package server

// Batch H1: agent identity and authorization on the per-agent token store.
// The WSTG-style authorization suite (RGT-223): IDOR between two agents,
// scope escalation, a spoofed agent field, expired / revoked tokens, audited
// authentication failures that never contain the token, operator-only
// routes, the lease scope, mass assignment, and concurrency.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/server/handlers"
	"rgt-vault-server/internal/vault"
)

// authzPolicy: alice and bob each own one namespace; nobody else gets
// anything. "*" in purpose so purposes do not matter here.
const authzPolicy = `rules:
  - effect: allow
    agent: alice
    namespace: alice-ns
    purpose: "*"
    action: "*"
  - effect: allow
    agent: bob
    namespace: bob-ns
    purpose: "*"
    action: "*"
`

type authzEnv struct {
	t     *testing.T
	stack *Stack
	store *auth.Store
	h     http.Handler
	now   time.Time
	mu    sync.Mutex

	alice, aliceLease, bob, auditor, operator, opOnly string
}

func newAuthzEnv(t *testing.T, approval bool) *authzEnv {
	t.Helper()
	dir := t.TempDir()
	stack, err := OpenStack(context.Background(), StackOptions{
		DBPath:          filepath.Join(dir, "vault", "vault.db"),
		PolicyFile:      writeFile(t, filepath.Join(dir, "policy.yaml"), authzPolicy),
		MasterProvider:  providerstest.NewMemory(),
		RequireApproval: approval,
		ApprovalTimeout: 30 * time.Second,
		KDFParams:       testKDF,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	e := &authzEnv{t: t, stack: stack, store: auth.OpenStore(filepath.Join(dir, "tokens.json")), now: time.Now()}
	e.store.SetClock(e.clock)
	e.alice = e.mint("alice", auth.ScopeAgent)
	e.aliceLease = e.mint("alice", auth.ScopeAgent, auth.ScopeLease)
	e.bob = e.mint("bob", auth.ScopeAgent, auth.ScopeLease)
	e.auditor = e.mint("auditor", auth.ScopeAudit)
	e.operator = e.mint("operator", auth.ScopeAgent, auth.ScopeOperator, auth.ScopeAudit, auth.ScopeLease)
	e.opOnly = e.mint("approver", auth.ScopeOperator)
	h, err := New(Config{
		Vault: stack.Vault, Tokens: e.store, Broker: stack.Broker,
		Actions: stack.Actions, Capabilities: stack.Capabilities,
		AuthFailureLimit: 5, AuthFailureWindow: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	// Seed one secret per agent, through the vault (not HTTP).
	for _, s := range []struct{ agent, ns, value string }{{"alice", "alice-ns", "ALICE-SECRET"}, {"bob", "bob-ns", "BOB-SECRET"}} {
		if err := stack.Vault.SetSecret(context.Background(), vault.SetSecretRequest{
			Name: "k", Namespace: s.ns, Agent: s.agent, Purpose: "seed", Value: []byte(s.value),
		}); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *authzEnv) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *authzEnv) advance(d time.Duration) {
	e.mu.Lock()
	e.now = e.now.Add(d)
	e.mu.Unlock()
}

func (e *authzEnv) mint(agent string, scopes ...auth.Scope) string {
	e.t.Helper()
	tok, _, err := e.store.Mint(auth.MintOptions{Agent: agent, Scopes: scopes})
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func (e *authzEnv) do(method, path, token string, body any, ip ...string) (int, string, http.Header) {
	e.t.Helper()
	var rd *strings.Reader
	switch b := body.(type) {
	case nil:
		rd = strings.NewReader("")
	case string:
		rd = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		rd = strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "127.0.0.1:4000"
	if len(ip) > 0 {
		req.RemoteAddr = ip[0] + ":4000"
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), rec.Header()
}

// rows returns audit rows straight from the vault (no HTTP, no extra rows).
func (e *authzEnv) rows(action string) []string {
	e.t.Helper()
	all, err := e.stack.Vault.AuditLog(context.Background(), -1)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, r := range all {
		if r.Action == action {
			out = append(out, r.Details.String+" agent="+r.AgentID.String)
		}
	}
	return out
}

func (e *authzEnv) allAudit() string {
	all, _ := e.stack.Vault.AuditLog(context.Background(), -1)
	var b strings.Builder
	for _, r := range all {
		fmt.Fprintf(&b, "%s|%s|%s|%s\n", r.Action, r.SecretName.String, r.Details.String, r.AgentID.String)
	}
	return b.String()
}

// IDOR (RGT-346): alice's token can never read, use, revoke or overwrite
// bob's secret, neither by naming bob nor through her own (ABAC) identity.
func TestAuthzIDORBetweenAgents(t *testing.T) {
	e := newAuthzEnv(t, false)
	attempts := []struct {
		name, method, path string
		body               any
	}{
		{"lease naming bob", "POST", "/v1/secrets/bob-ns/k/lease", map[string]any{"agent": "bob"}},
		{"lease as herself", "POST", "/v1/secrets/bob-ns/k/lease", map[string]any{}},
		{"use naming bob", "POST", "/v1/secrets/bob-ns/k/use", map[string]any{"action": "echo", "agent": "bob", "purpose": "p"}},
		{"use as herself", "POST", "/v1/secrets/bob-ns/k/use", map[string]any{"action": "echo", "purpose": "p"}},
		{"revoke naming bob", "POST", "/v1/secrets/bob-ns/k/revoke?agent=bob", nil},
		{"revoke as herself", "POST", "/v1/secrets/bob-ns/k/revoke", nil},
		{"overwrite naming bob", "POST", "/v1/secrets", map[string]any{"name": "k", "namespace": "bob-ns", "value": "pwned", "agent": "bob"}},
		{"overwrite as herself", "POST", "/v1/secrets", map[string]any{"name": "k", "namespace": "bob-ns", "value": "pwned"}},
		{"list naming bob", "GET", "/v1/secrets?namespace=bob-ns&agent=bob", nil},
		{"list as herself", "GET", "/v1/secrets?namespace=bob-ns", nil},
		{"simulate as bob", "POST", "/v1/policy/simulate", map[string]any{"agent": "bob", "namespace": "bob-ns"}},
		{"capabilities as bob", "GET", "/v1/capabilities/list?agent=bob", nil},
	}
	for _, a := range attempts {
		code, body, _ := e.do(a.method, a.path, e.aliceLease, a.body)
		if code != http.StatusForbidden || strings.Contains(body, "BOB-SECRET") {
			t.Errorf("%s: %d %s", a.name, code, body)
		}
	}
	// bob's secret is untouched and still his.
	code, body, _ := e.do("POST", "/v1/secrets/bob-ns/k/lease", e.bob, map[string]any{})
	if code != 200 || !strings.Contains(body, "BOB-SECRET") {
		t.Fatalf("bob after the attacks: %d %s", code, body)
	}
	// Each spoof wrote an AUTHZ_DENIED row naming alice (the real caller) and
	// the claimed agent; ABAC denials as alice are POLICY_DENIED rows.
	denied := e.rows(handlers.EventAuthzDenied)
	if len(denied) != 7 {
		t.Errorf("AUTHZ_DENIED rows = %d, want 7:\n%s", len(denied), strings.Join(denied, "\n"))
	}
	for _, d := range denied {
		if !strings.Contains(d, "agent=alice") || !strings.Contains(d, "claimed bob") || !strings.Contains(d, "ip=127.0.0.1") {
			t.Errorf("denied row = %q", d)
		}
	}
	if len(e.rows("POLICY_DENIED")) == 0 {
		t.Error("ABAC denials as alice were not audited")
	}
	// Her own secret works without naming herself, or naming herself.
	for _, b := range []map[string]any{{}, {"agent": "alice"}} {
		if code, body, _ := e.do("POST", "/v1/secrets/alice-ns/k/lease", e.aliceLease, b); code != 200 || !strings.Contains(body, "ALICE-SECRET") {
			t.Errorf("alice own lease %v: %d %s", b, code, body)
		}
	}
	if code, body, _ := e.do("POST", "/v1/secrets", e.alice, map[string]any{"name": "n", "namespace": "alice-ns", "value": "v2"}); code != 200 {
		t.Errorf("alice own set: %d %s", code, body)
	}
	if code, body, _ := e.do("POST", "/v1/secrets/alice-ns/k/use", e.alice, map[string]any{"action": "echo", "purpose": "p"}); code != 200 {
		t.Errorf("alice own use: %d %s", code, body)
	}
	if code, body, _ := e.do("GET", "/v1/secrets?namespace=alice-ns", e.alice, nil); code != 200 || !strings.Contains(body, `"k"`) {
		t.Errorf("alice own list: %d %s", code, body)
	}
	// The lease/set rows carry the token's agent, not a client value.
	for _, r := range e.rows("SECRET_READ") {
		if !strings.HasSuffix(r, "agent=alice") && !strings.HasSuffix(r, "agent=bob") {
			t.Errorf("SECRET_READ row subject = %q", r)
		}
	}
}

// Scope escalation (RGT-344, RGT-431): an agent token cannot rotate, read or
// verify the audit log, or touch the approval endpoints; an audit token only
// reads the audit log; plaintext needs the lease scope.
func TestAuthzScopes(t *testing.T) {
	e := newAuthzEnv(t, true)
	type want struct {
		token string
		code  int
	}
	routes := []struct {
		method, path string
		body         any
		cases        []want
	}{
		{"POST", "/v1/rotate", map[string]any{"target": "dek"}, []want{{e.alice, 403}, {e.auditor, 403}, {e.opOnly, 200}}},
		{"GET", "/v1/audit?limit=5", nil, []want{{e.alice, 403}, {e.bob, 403}, {e.auditor, 200}, {e.opOnly, 200}}},
		{"POST", "/v1/audit/verify", nil, []want{{e.alice, 403}, {e.auditor, 200}, {e.operator, 200}}},
		{"GET", "/v1/requests", nil, []want{{e.alice, 403}, {e.auditor, 403}, {e.opOnly, 200}}},
		{"POST", "/v1/requests/x/approve", map[string]any{}, []want{{e.alice, 403}, {e.auditor, 403}, {e.opOnly, 400}}},
		{"POST", "/v1/requests/x/deny", map[string]any{}, []want{{e.alice, 403}, {e.auditor, 403}, {e.opOnly, 400}}},
		{"POST", "/v1/secrets/alice-ns/k/lease", map[string]any{}, []want{{e.alice, 403}, {e.auditor, 403}, {e.opOnly, 403}}},
		{"GET", "/v1/secrets?namespace=alice-ns", nil, []want{{e.auditor, 403}, {e.opOnly, 403}, {e.alice, 200}}},
		{"GET", "/v1/actions", nil, []want{{e.auditor, 403}, {e.alice, 200}}},
		{"GET", "/v1/nope", nil, []want{{e.auditor, 403}, {e.alice, 404}}},
	}
	for _, r := range routes {
		for _, c := range r.cases {
			code, body, _ := e.do(r.method, r.path, c.token, r.body)
			if code != c.code {
				t.Errorf("%s %s with %s: %d, want %d (%s)", r.method, r.path, tokName(e, c.token), code, c.code, body)
			}
			if code == 403 && !strings.Contains(body, "AuthorizationError") {
				t.Errorf("%s %s: 403 body %s", r.method, r.path, body)
			}
		}
	}
	if n := len(e.rows(handlers.EventAuthzDenied)); n < 15 {
		t.Errorf("only %d AUTHZ_DENIED rows for the refused calls", n)
	}
	for _, d := range e.rows(handlers.EventAuthzDenied) {
		if !strings.Contains(d, "reason=missing scope") {
			t.Errorf("scope denial row = %q", d)
		}
	}
	// Audit rows never contain a token.
	all := e.allAudit()
	for _, tok := range []string{e.alice, e.aliceLease, e.bob, e.auditor, e.operator, e.opOnly} {
		if strings.Contains(all, tok) {
			t.Fatal("a token is in the audit log")
		}
	}
}

func tokName(e *authzEnv, tok string) string {
	for name, v := range map[string]string{"alice": e.alice, "aliceLease": e.aliceLease, "bob": e.bob, "auditor": e.auditor, "operator": e.operator, "opOnly": e.opOnly} {
		if v == tok {
			return name
		}
	}
	return "?"
}

// The operator decides approvals as itself: a spoofed operator name is
// refused, the decision records the token's agent, and an agent can never
// approve its own request.
func TestAuthzApprovalAsTokenOperator(t *testing.T) {
	e := newAuthzEnv(t, true)
	done := make(chan int, 1)
	go func() {
		code, _, _ := e.do("POST", "/v1/secrets/alice-ns/k/lease", e.aliceLease, map[string]any{"purpose": "deploy"})
		done <- code
	}()
	var id string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline) && id == ""; time.Sleep(10 * time.Millisecond) {
		_, body, _ := e.do("GET", "/v1/requests", e.opOnly, nil)
		var res struct {
			Requests []struct {
				ID    string `json:"request_id"`
				Agent string `json:"agent"`
			} `json:"requests"`
		}
		_ = json.Unmarshal([]byte(body), &res)
		if len(res.Requests) == 1 {
			id = res.Requests[0].ID
			if res.Requests[0].Agent != "alice" {
				t.Errorf("request agent = %q", res.Requests[0].Agent)
			}
		}
	}
	if id == "" {
		t.Fatal("no pending request")
	}
	if code, _, _ := e.do("POST", "/v1/requests/"+id+"/approve", e.aliceLease, map[string]any{}); code != 403 {
		t.Errorf("self-approval: %d", code)
	}
	if code, _, _ := e.do("POST", "/v1/requests/"+id+"/approve", e.opOnly, map[string]any{"operator": "someone-else"}); code != 403 {
		t.Errorf("spoofed operator name: %d", code)
	}
	if code, body, _ := e.do("POST", "/v1/requests/"+id+"/approve", e.opOnly, map[string]any{}); code != 200 {
		t.Fatalf("approve: %d %s", code, body)
	}
	if code := <-done; code != 200 {
		t.Fatalf("lease after approval: %d", code)
	}
	if !strings.Contains(e.allAudit(), "approver") {
		t.Errorf("the decision does not record the operator token's agent:\n%s", e.allAudit())
	}
}

// Failed authentication (RGT-413): generic 401, an AUTH_FAILED row with the
// reason, the client IP and at most a short id, never the token; expired and
// revoked tokens are 401 like unknown ones (no oracle).
func TestAuthzAuthenticationFailures(t *testing.T) {
	e := newAuthzEnv(t, false)
	expiring, info, err := e.store.Mint(auth.MintOptions{Agent: "alice", Scopes: []auth.Scope{auth.ScopeAgent}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if code, _, _ := e.do("GET", "/v1/actions", expiring, nil); code != 200 {
		t.Fatalf("fresh token: %d", code)
	}
	e.advance(time.Hour + time.Second)
	revoked := e.mint("alice", auth.ScopeAgent)
	infos, _ := e.store.List()
	if _, err := e.store.Revoke(infos[len(infos)-1].ID); err != nil {
		t.Fatal(err)
	}
	unknown, _ := auth.GenerateToken()

	bodies := map[string]string{}
	for name, tok := range map[string]string{"missing": "", "unknown": unknown, "expired": expiring, "revoked": revoked} {
		code, body, hdr := e.do("GET", "/v1/actions", tok, nil, "10.0.0."+fmt.Sprint(len(name)))
		if code != 401 || hdr.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: %d %s", name, code, body)
		}
		bodies[name] = strings.TrimSpace(body)
	}
	// Unknown, expired and revoked are indistinguishable to the client.
	if bodies["unknown"] != bodies["expired"] || bodies["unknown"] != bodies["revoked"] {
		t.Errorf("401 bodies differ: %v", bodies)
	}
	rows := e.rows(handlers.EventAuthFailed)
	if len(rows) != 4 {
		t.Fatalf("AUTH_FAILED rows = %d:\n%s", len(rows), strings.Join(rows, "\n"))
	}
	joined := strings.Join(rows, "\n")
	for _, want := range []string{"reason=missing token=-", "reason=invalid token=" + auth.TokenID(unknown), "reason=expired token=" + info.ID, "GET /v1/actions", "ip=10.0.0."} {
		if !strings.Contains(joined, want) {
			t.Errorf("AUTH_FAILED rows lack %q:\n%s", want, joined)
		}
	}
	all := e.allAudit()
	for _, tok := range []string{unknown, expiring, revoked} {
		if strings.Contains(all, tok) {
			t.Fatal("a presented token is in the audit log")
		}
	}
}

// Repeated failures from one source: 429 after the limit, ONE summary row,
// other sources and valid tokens from the same source are not affected.
func TestAuthzFailureRateLimit(t *testing.T) {
	e := newAuthzEnv(t, false)
	codes := []int{}
	for i := 0; i < 12; i++ {
		code, _, _ := e.do("GET", "/v1/actions", "bad-token", nil, "192.0.2.7")
		codes = append(codes, code)
	}
	want := []int{401, 401, 401, 401, 401, 429, 429, 429, 429, 429, 429, 429}
	if fmt.Sprint(codes) != fmt.Sprint(want) {
		t.Errorf("codes = %v, want %v", codes, want)
	}
	if n := len(e.rows(handlers.EventAuthFailed)); n != 5 {
		t.Errorf("AUTH_FAILED rows = %d, want 5", n)
	}
	if n := len(e.rows(handlers.EventAuthRateLimited)); n != 1 {
		t.Errorf("AUTH_RATE_LIMITED rows = %d, want 1", n)
	}
	// A valid token from the limited source still works.
	if code, _, _ := e.do("GET", "/v1/actions", e.alice, nil, "192.0.2.7"); code != 200 {
		t.Errorf("valid token from a limited source: %d", code)
	}
	if code, _, _ := e.do("GET", "/v1/actions", "bad-token", nil, "192.0.2.8"); code != 401 {
		t.Errorf("other source: %d", code)
	}
}

func TestFailureLimiterWindowAndTableBound(t *testing.T) {
	now := time.Unix(0, 0)
	l := newFailureLimiter(2, time.Minute)
	l.now = func() time.Time { return now }
	for i, want := range []bool{false, false, true, true} {
		lim, rep, full := l.failure("a")
		if lim != want || rep != (i == 2) || full {
			t.Errorf("attempt %d: limited=%v report=%v full=%v", i, lim, rep, full)
		}
	}
	now = now.Add(time.Minute)
	if lim, _, _ := l.failure("a"); lim {
		t.Error("window did not reset")
	}
	// The table is bounded; when full of live windows a newcomer is limited
	// and ONE summary row per window is reported (review L4).
	fullReports := 0
	for i := 0; i < maxTrackedSources+5; i++ {
		lim, rep, full := l.failure(fmt.Sprint("s", i))
		if full {
			if !lim {
				t.Fatal("full table: newcomer not limited")
			}
			if rep {
				fullReports++
			}
		}
	}
	if fullReports != 1 {
		t.Errorf("full-table summary rows in one window = %d, want 1", fullReports)
	}
	now = now.Add(2 * time.Minute)
	if lim, _, _ := l.failure("newcomer"); lim {
		t.Error("expired windows were not pruned")
	}
	if d := newFailureLimiter(0, 0); d.limit != DefaultAuthFailureLimit || d.window != DefaultAuthFailureWindow {
		t.Error("defaults")
	}
}

// A token revoked or rotated while the server runs stops working at the
// next request (another Store value = the `rgt-vault token` CLI process).
func TestAuthzRevokeAndRotateTakeEffectLive(t *testing.T) {
	e := newAuthzEnv(t, false)
	cli := auth.OpenStore(e.store.Path())
	tok, info, err := cli.Mint(auth.MintOptions{Agent: "alice", Scopes: []auth.Scope{auth.ScopeAgent}})
	if err != nil {
		t.Fatal(err)
	}
	if code, _, _ := e.do("GET", "/v1/actions", tok, nil); code != 200 {
		t.Fatalf("minted token: %d", code)
	}
	fresh, _, err := cli.Rotate(info.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if code, _, _ := e.do("GET", "/v1/actions", tok, nil); code != 401 {
		t.Errorf("rotated-out token: %d", code)
	}
	if code, _, _ := e.do("GET", "/v1/actions", fresh, nil); code != 200 {
		t.Errorf("rotated-in token: %d", code)
	}
	infos, _ := cli.List()
	for _, in := range infos {
		if in.Agent == "alice" {
			_, _ = cli.Revoke(in.ID)
		}
	}
	if code, _, _ := e.do("GET", "/v1/actions", fresh, nil); code != 401 {
		t.Errorf("revoked token: %d", code)
	}
	if code, _, _ := e.do("GET", "/v1/actions", e.alice, nil); code != 401 {
		t.Errorf("alice's other revoked token: %d", code)
	}
}

// Mass assignment (RGT-352): unknown fields are refused on every body,
// including the new lease route; a client cannot smuggle scopes or ids.
func TestAuthzStrictBodies(t *testing.T) {
	e := newAuthzEnv(t, false)
	for _, c := range []struct {
		path string
		body string
	}{
		{"/v1/secrets", `{"name":"x","namespace":"alice-ns","value":"v","scopes":["operator"]}`},
		{"/v1/secrets/alice-ns/k/lease", `{"agent_id":"bob"}`},
		{"/v1/secrets/alice-ns/k/use", `{"action":"echo","token_id":"tok_x"}`},
		{"/v1/policy/simulate", `{"namespace":"alice-ns","role":"admin"}`},
	} {
		if code, body, _ := e.do("POST", c.path, e.aliceLease, c.body); code != 400 {
			t.Errorf("%s %s: %d %s", c.path, c.body, code, body)
		}
	}
}

// No route but the lease route returns a "value" field (RGT-504).
func TestAuthzOnlyLeaseReturnsValues(t *testing.T) {
	e := newAuthzEnv(t, false)
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/v1/secrets?namespace=alice-ns", ""},
		{"GET", "/v1/secrets?namespace=alice-ns&name=k", ""},
		{"GET", "/v1/secrets/alice-ns/k", ""},
		{"POST", "/v1/secrets/alice-ns/k/use", `{"action":"echo","purpose":"p"}`},
		{"POST", "/v1/policy/simulate", `{"namespace":"alice-ns"}`},
		{"GET", "/v1/capabilities", ""},
		{"GET", "/v1/capabilities/list", ""},
		{"GET", "/v1/actions", ""},
	} {
		var body any
		if c.body != "" {
			body = c.body
		}
		_, out, _ := e.do(c.method, c.path, e.operator, body)
		if strings.Contains(out, "ALICE-SECRET") || strings.Contains(out, `"value"`) {
			t.Errorf("%s %s returned a value: %s", c.method, c.path, out)
		}
	}
	for _, p := range []string{"/v1/audit?limit=100", "/v1/requests"} {
		if _, out, _ := e.do("GET", p, e.operator, nil); strings.Contains(out, "ALICE-SECRET") {
			t.Errorf("%s leaks the value", p)
		}
	}
	code, out, hdr := e.do("POST", "/v1/secrets/alice-ns/k/lease", e.aliceLease, map[string]any{})
	if code != 200 || !strings.Contains(out, `"value":"ALICE-SECRET"`) || hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("lease: %d %s %v", code, out, hdr)
	}
	// Operators simulate / list capabilities for any agent; agents only for
	// themselves (checked in the IDOR test).
	if code, out, _ := e.do("POST", "/v1/policy/simulate", e.operator, map[string]any{"agent": "bob", "namespace": "bob-ns"}); code != 200 || !strings.Contains(out, `"allowed":true`) {
		t.Errorf("operator simulate for bob: %d %s", code, out)
	}
	if code, out, _ := e.do("GET", "/v1/capabilities/list?agent=bob", e.operator, nil); code != 200 || !strings.Contains(out, `"agent":"bob"`) {
		t.Errorf("operator capability list for bob: %d %s", code, out)
	}
	if code, out, _ := e.do("GET", "/v1/capabilities/list", e.alice, nil); code != 200 || !strings.Contains(out, `"agent":"alice"`) {
		t.Errorf("default capability list: %d %s", code, out)
	}
}

// Concurrent requests from two agents with a token rotated mid-way (-race).
func TestAuthzConcurrent(t *testing.T) {
	e := newAuthzEnv(t, false)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok, ns, other := e.aliceLease, "alice-ns", "bob-ns"
			if i%2 == 1 {
				tok, ns, other = e.bob, "bob-ns", "alice-ns"
			}
			if code, _, _ := e.do("POST", "/v1/secrets/"+ns+"/k/lease", tok, map[string]any{}); code != 200 {
				t.Errorf("own lease %d: %d", i, code)
			}
			if code, _, _ := e.do("POST", "/v1/secrets/"+other+"/k/lease", tok, map[string]any{}); code != 403 {
				t.Errorf("cross lease %d: %d", i, code)
			}
			if i == 5 {
				_, _, _ = e.store.Mint(auth.MintOptions{Agent: "late", Scopes: []auth.Scope{auth.ScopeAgent}})
			}
		}(i)
	}
	wg.Wait()
	if ok, err := e.stack.Vault.VerifyAuditChain(context.Background()); err != nil || !ok {
		t.Errorf("audit chain after concurrent requests: %v %v", ok, err)
	}
}

// Configuration errors of New.
func TestNewIdentityConfig(t *testing.T) {
	e := newAuthzEnv(t, false)
	if _, err := New(Config{Vault: e.stack.Vault}); err == nil {
		t.Error("no token source accepted")
	}
	legacy := auth.NewTokenStore(filepath.Join(t.TempDir(), "t"))
	if _, err := New(Config{Vault: e.stack.Vault, Tokens: e.store, AgentTokens: legacy}); err == nil {
		t.Error("both token sources accepted")
	}
	if _, err := New(Config{Vault: e.stack.Vault, Tokens: e.store, OperatorTokens: legacy}); err == nil {
		t.Error("legacy operator file with the store accepted")
	}
}

// A handler reached without the auth middleware fails closed.
func TestSubjectWithoutPrincipal(t *testing.T) {
	e := newAuthzEnv(t, false)
	h := &handlers.Handlers{Vault: e.stack.Vault}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/secrets", strings.NewReader(`{"name":"x","value":"v","namespace":"alice-ns"}`))
	h.SetSecret(rec, req)
	if rec.Code != 401 {
		t.Errorf("no principal: %d", rec.Code)
	}
}

// A corrupt token store is a 500, not an open door.
func TestAuthzStoreUnavailable(t *testing.T) {
	e := newAuthzEnv(t, false)
	if err := writeFileErr(e.store.Path(), "{garbage"); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := e.do("GET", "/v1/actions", e.alice, nil); code != 500 || strings.Contains(body, e.store.Path()) {
		t.Errorf("corrupt store: %d %s", code, body)
	}
}

func writeFileErr(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// WSTG authorization remainder (RGT-223): a revoked secret cannot be
// recovered over HTTP, and an older version cannot be leased back.
func TestAuthzDeletedSecretAndVersionRollback(t *testing.T) {
	e := newAuthzEnv(t, false)
	if code, body, _ := e.do("POST", "/v1/secrets", e.aliceLease, map[string]any{"name": "k", "namespace": "alice-ns", "value": "ALICE-V2"}); code != 200 {
		t.Fatalf("set v2: %d %s", code, body)
	}
	// Only the current version is leased; there is no version selector on
	// the lease route and an unknown field is refused.
	if code, body, _ := e.do("POST", "/v1/secrets/alice-ns/k/lease", e.aliceLease, map[string]any{}); code != 200 || !strings.Contains(body, "ALICE-V2") {
		t.Fatalf("lease current: %d %s", code, body)
	}
	if code, _, _ := e.do("POST", "/v1/secrets/alice-ns/k/lease?version=1", e.aliceLease, map[string]any{}); code == 200 {
		// the query is ignored: it must still be the current value
		if _, body, _ := e.do("POST", "/v1/secrets/alice-ns/k/lease?version=1", e.aliceLease, map[string]any{}); strings.Contains(body, "ALICE-SECRET") {
			t.Error("old version leased via ?version=")
		}
	}
	if code, _, _ := e.do("POST", "/v1/secrets/alice-ns/k/lease", e.aliceLease, map[string]any{"version": 1}); code != 400 {
		t.Errorf("version field accepted: %d", code)
	}
	// Revoke, then every way back is closed.
	if code, body, _ := e.do("POST", "/v1/secrets/alice-ns/k/revoke", e.aliceLease, nil); code != 200 {
		t.Fatalf("revoke: %d %s", code, body)
	}
	for _, c := range []struct{ method, path string }{
		{"POST", "/v1/secrets/alice-ns/k/lease"},
		{"POST", "/v1/secrets/alice-ns/k/use"},
	} {
		body := map[string]any{}
		if strings.HasSuffix(c.path, "/use") {
			body = map[string]any{"action": "echo", "purpose": "p"}
		}
		code, out, _ := e.do(c.method, c.path, e.aliceLease, body)
		if code != 404 || strings.Contains(out, "ALICE") {
			t.Errorf("%s after revoke: %d %s", c.path, code, out)
		}
	}
	if _, out, _ := e.do("GET", "/v1/secrets?namespace=alice-ns", e.aliceLease, nil); strings.Contains(out, `"name":"k"`) {
		t.Errorf("revoked secret still listed: %s", out)
	}
}

// Route classification is by method + exact segments on the router's own
// path (Kilo review on PR #53): a secret or namespace named "lease" is not
// the lease route, and an encoded "/" cannot move a request off it.
func TestAuthzLeaseRouteClassification(t *testing.T) {
	e := newAuthzEnv(t, false)
	for _, name := range []string{"lease", "my-lease", "lease-x"} {
		if err := e.stack.Vault.SetSecret(context.Background(), vault.SetSecretRequest{
			Name: name, Namespace: "alice-ns", Agent: "alice", Purpose: "seed", Value: []byte("V-" + name),
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Fingerprint GET of a secret named "lease": agent scope is enough.
	for _, name := range []string{"lease", "my-lease", "lease-x"} {
		code, body, _ := e.do("GET", "/v1/secrets/alice-ns/"+name, e.alice, nil)
		if code != 200 || !strings.Contains(body, `"fingerprint"`) || strings.Contains(body, "V-"+name) {
			t.Errorf("fingerprint of %q with an agent token: %d %s", name, code, body)
		}
	}
	// The lease POST of a secret named "lease": needs the lease scope.
	if code, body, _ := e.do("POST", "/v1/secrets/alice-ns/lease/lease", e.alice, map[string]any{}); code != 403 || strings.Contains(body, "V-lease") {
		t.Errorf("lease of 'lease' without the lease scope: %d %s", code, body)
	}
	if code, body, _ := e.do("POST", "/v1/secrets/alice-ns/lease/lease", e.aliceLease, map[string]any{}); code != 200 || !strings.Contains(body, `"V-lease"`) {
		t.Errorf("lease of 'lease' with the lease scope: %d %s", code, body)
	}
	// use/revoke of a secret named "lease" are agent routes.
	if code, body, _ := e.do("POST", "/v1/secrets/alice-ns/lease/use", e.alice, map[string]any{"action": "echo", "purpose": "p"}); code != 200 {
		t.Errorf("use of 'lease': %d %s", code, body)
	}
	// A namespace named "lease" is not the lease route either (ABAC then
	// denies alice there: 403 from POLICY, not from scope).
	if code, body, _ := e.do("GET", "/v1/secrets/lease/k", e.alice, nil); code == 403 && strings.Contains(body, "insufficient scope") {
		t.Errorf("namespace 'lease' mis-gated: %d %s", code, body)
	}
	// Encoded slashes: chi routes on the raw path, and so does the scope
	// check, so an agent-only token never reaches the lease handler.
	for _, p := range []string{"/v1/secrets/alice-ns/x%2Fy/lease", "/v1/secrets/a%2Fb/k/lease", "/v1/secrets/alice-ns/k%2Flease/lease"} {
		code, body, _ := e.do("POST", p, e.alice, map[string]any{})
		if code != 403 || !strings.Contains(body, "insufficient scope") {
			t.Errorf("POST %s with an agent-only token: %d %s", p, code, body)
		}
	}
	// Unit view of the classifier.
	for _, c := range []struct {
		method, path string
		want         bool
	}{
		{"POST", "/v1/secrets/ns/k/lease", true},
		{"POST", "/v1/secrets/ns/lease/lease", true},
		{"GET", "/v1/secrets/ns/k/lease", false},
		{"GET", "/v1/secrets/ns/lease", false},
		{"POST", "/v1/secrets/ns/lease", false},
		{"POST", "/v1/secrets/lease/k/use", false},
		{"POST", "/v1/secrets/ns/k/lease/x", false},
		{"POST", "/v1/secrets//k/lease", false},
		{"POST", "/v2/secrets/ns/k/lease", false},
	} {
		if got := isLeaseRoute(c.method, c.path); got != c.want {
			t.Errorf("isLeaseRoute(%s %s) = %v", c.method, c.path, got)
		}
	}
}
