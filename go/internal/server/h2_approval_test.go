package server

// Batch H2: approval and 2FA hardening through the real HTTP stack: attempt
// caps and lockout, TOTP replay audit + notification, separation of duties,
// require_2fa downgrade protection, optional approval for set/rotate/revoke,
// request expiry, and single-use capability tokens.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/approval"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/captoken"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers/providerstest"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/totp"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/vault"
)

const h2Policy = `rules:
  - effect: allow
    agent: "*"
    namespace: "*"
    purpose: "*"
    action: "*"
`

type recNotifier struct {
	mu     sync.Mutex
	events []approval.Event
}

func (n *recNotifier) Notify(_ context.Context, e approval.Event) {
	n.mu.Lock()
	n.events = append(n.events, e)
	n.mu.Unlock()
}

func (n *recNotifier) kinds() []approval.EventKind {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []approval.EventKind
	for _, e := range n.events {
		out = append(out, e.Kind)
	}
	return out
}

func (n *recNotifier) count(k approval.EventKind) int {
	c := 0
	for _, x := range n.kinds() {
		if x == k {
			c++
		}
	}
	return c
}

type h2Env struct {
	t          *testing.T
	stack      *Stack
	store      *auth.Store
	h          http.Handler
	notes      *recNotifier
	totpSecret string
	signer     *captoken.HMACTokenVerifier

	// tokens
	alice    string // agent alice: agent scope only
	aliceOp  string // agent alice: agent + operator (an operator who is also the agent)
	aliceOp2 string // a second token of agent alice with operator scope
	opA, opB string // operators ops1 / ops2 (operator scope only)
}

func newH2Env(t *testing.T, mod func(*StackOptions)) *h2Env {
	t.Helper()
	dir := t.TempDir()
	secret, err := totp.GenerateSecret(20)
	if err != nil {
		t.Fatal(err)
	}
	so := StackOptions{
		DBPath:          filepath.Join(dir, "vault", "vault.db"),
		PolicyFile:      writeFile(t, filepath.Join(dir, "policy.yaml"), h2Policy),
		MasterProvider:  providerstest.NewMemory(),
		RequireApproval: true,
		TOTPSecretFile:  writeFile(t, filepath.Join(dir, "totp.secret"), secret+"\n"),
		ApprovalTimeout: 30 * time.Second,
		KDFParams:       testKDF,
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	hexKey := hex.EncodeToString(key)
	so.HarnessKeyFile = writeFile(t, filepath.Join(dir, "harness.key"), hexKey+"\n")
	signer, err := captoken.NewHMACTokenVerifier([]byte(hexKey))
	if err != nil {
		t.Fatal(err)
	}
	if mod != nil {
		mod(&so)
	}
	stack, err := OpenStack(context.Background(), so)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	e := &h2Env{t: t, stack: stack, notes: &recNotifier{}, totpSecret: secret, signer: signer,
		store: auth.OpenStore(filepath.Join(dir, "tokens.json"))}
	mint := func(agent string, scopes ...auth.Scope) string {
		tok, _, err := e.store.Mint(auth.MintOptions{Agent: agent, Scopes: scopes})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	e.alice = mint("alice", auth.ScopeAgent)
	e.aliceOp = mint("alice", auth.ScopeAgent, auth.ScopeOperator)
	e.aliceOp2 = mint("alice", auth.ScopeOperator)
	e.opA = mint("ops1", auth.ScopeOperator)
	e.opB = mint("ops2", auth.ScopeOperator)
	e.h, err = New(Config{
		Vault: stack.Vault, Tokens: e.store, Broker: stack.Broker, GatedOps: stack.GatedOps,
		Notifier: e.notes, Actions: stack.Actions, Capabilities: stack.Capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *h2Env) do(method, path, token string, body any) (int, map[string]any, http.Header) {
	e.t.Helper()
	var rd *strings.Reader
	if body == nil {
		rd = strings.NewReader("")
	} else {
		raw, _ := json.Marshal(body)
		rd = strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "127.0.0.1:4000"
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m, rec.Header()
}

// seed stores a secret through the vault. flagged secrets need 2FA to lease.
func (e *h2Env) seed(ns, name, value string, flagged bool) {
	e.t.Helper()
	if err := e.stack.Vault.SetSecret(context.Background(), vault.SetSecretRequest{
		Name: name, Namespace: ns, Agent: "alice", Purpose: "seed", Value: []byte(value), Require2FA: flagged,
	}); err != nil {
		e.t.Fatal(err)
	}
}

type asyncResp struct {
	code int
	body map[string]any
}

func (e *h2Env) async(method, path, token string, body any) <-chan asyncResp {
	ch := make(chan asyncResp, 1)
	go func() {
		c, m, _ := e.do(method, path, token, body)
		ch <- asyncResp{c, m}
	}()
	return ch
}

// useAsync is alice leasing a secret through the approval gate.
func (e *h2Env) useAsync(ns, name string) <-chan asyncResp {
	return e.async("POST", "/v1/secrets/"+ns+"/"+name+"/use", e.alice,
		map[string]any{"action": "echo", "purpose": "p"})
}

// pending waits for n pending approval requests and returns them.
func (e *h2Env) pending(n int) []map[string]any {
	e.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		code, m, _ := e.do("GET", "/v1/requests", e.opA, nil)
		if code != 200 {
			e.t.Fatalf("list requests: %d %v", code, m)
		}
		raw, _ := m["requests"].([]any)
		if len(raw) >= n {
			out := make([]map[string]any, len(raw))
			for i, r := range raw {
				out[i] = r.(map[string]any)
			}
			return out
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.t.Fatalf("no %d pending request(s)", n)
	return nil
}

func (e *h2Env) approve(token, id string, code string) (int, map[string]any, http.Header) {
	body := map[string]any{}
	if code != "" {
		body["totp_code"] = code
	}
	return e.do("POST", "/v1/requests/"+id+"/approve", token, body)
}

func (e *h2Env) goodCode() string {
	e.t.Helper()
	c, err := totp.Generate(e.totpSecret, time.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

// wrongCode returns a 6-digit code that is not valid in the +/-1 window.
func (e *h2Env) wrongCode() string {
	e.t.Helper()
	for _, c := range []string{"000000", "111111", "222222", "333333", "444444"} {
		if !totp.Verify(e.totpSecret, c, time.Now()) {
			return c
		}
	}
	e.t.Skip("no wrong code found")
	return ""
}

func (e *h2Env) audit() []rowView {
	e.t.Helper()
	all, err := e.stack.Vault.AuditLog(context.Background(), -1)
	if err != nil {
		e.t.Fatal(err)
	}
	// AuditLog returns newest first; the tests read chronologically.
	out := make([]rowView, 0, len(all))
	for i := len(all) - 1; i >= 0; i-- {
		r := all[i]
		out = append(out, rowView{r.Action, r.SecretName.String, r.Details.String, r.AgentID.String})
	}
	return out
}

type rowView struct{ action, secret, details, agent string }

func (e *h2Env) rows(action string) []rowView {
	var out []rowView
	for _, r := range e.audit() {
		if r.action == action {
			out = append(out, r)
		}
	}
	return out
}

func (e *h2Env) assertNoCode(codes ...string) {
	e.t.Helper()
	for _, r := range e.audit() {
		for _, c := range codes {
			if strings.Contains(r.details, c) || strings.Contains(r.secret, c) {
				e.t.Fatalf("audit row %s contains a TOTP code: %q", r.action, r.details)
			}
		}
	}
	e.notes.mu.Lock()
	defer e.notes.mu.Unlock()
	for _, ev := range e.notes.events {
		for _, c := range codes {
			if strings.Contains(ev.Detail, c) {
				e.t.Fatalf("notification %s contains a TOTP code", ev.Kind)
			}
		}
	}
}

// --- (1) attempt cap + lockout --------------------------------------------

func TestH2BadCodesDenyRequestAndAreAudited(t *testing.T) {
	e := newH2Env(t, nil)
	e.seed("prod", "guarded", "SENTINEL", true)
	done := e.useAsync("prod", "guarded")
	id := e.pending(1)[0]["request_id"].(string)
	bad := e.wrongCode()

	for i := 1; i < approval.DefaultMaxCodeAttempts; i++ {
		code, m, _ := e.approve(e.opA, id, bad)
		if code != 400 || m["error"] != "ApprovalError" {
			t.Fatalf("bad code %d: %d %v", i, code, m)
		}
	}
	// The fifth bad code denies the request.
	code, m, _ := e.approve(e.opA, id, bad)
	if code != 403 || m["error"] != "ApprovalError" || !strings.Contains(fmt.Sprint(m["detail"]), "request denied") {
		t.Fatalf("capping bad code: %d %v", code, m)
	}
	res := <-done
	if res.code != 403 || !strings.Contains(fmt.Sprint(res.body["detail"]), "invalid 2FA codes") {
		t.Fatalf("agent after cap: %d %v", res.code, res.body)
	}
	// Even the right code is now useless.
	if code, _, _ := e.approve(e.opA, id, e.goodCode()); code != 400 {
		t.Fatalf("approve after denial: %d", code)
	}

	// Every bad code is one APPROVAL_BAD_CODE row, with token and attempt
	// number but never the code; the cap adds an auto-denial row.
	bc := e.rows("APPROVAL_BAD_CODE")
	if len(bc) != approval.DefaultMaxCodeAttempts {
		t.Fatalf("APPROVAL_BAD_CODE rows = %d, want %d", len(bc), approval.DefaultMaxCodeAttempts)
	}
	for i, r := range bc {
		if !strings.Contains(r.details, "request="+id) || !strings.Contains(r.details, "token=") ||
			!strings.Contains(r.details, fmt.Sprintf("attempt=%d/%d", i+1, approval.DefaultMaxCodeAttempts)) || r.agent != "ops1" {
			t.Fatalf("row %d = %+v", i, r)
		}
	}
	if len(e.rows("APPROVAL_AUTO_DENIED")) != 1 || len(e.rows("APPROVAL_DENIED")) != 1 {
		t.Fatalf("rows: auto=%d denied=%d", len(e.rows("APPROVAL_AUTO_DENIED")), len(e.rows("APPROVAL_DENIED")))
	}
	if e.notes.count(approval.EventBadCode) != approval.DefaultMaxCodeAttempts || e.notes.count(approval.EventAutoDenied) != 1 {
		t.Fatalf("notifications = %v", e.notes.kinds())
	}
	e.assertNoCode(bad, "SENTINEL")
}

func TestH2OperatorThrottledAcrossRequests(t *testing.T) {
	e := newH2Env(t, func(o *StackOptions) {
		o.ApprovalCodeAttempts = 100
		o.ApprovalOperatorFails = 3
		o.ApprovalLockout = time.Minute
	})
	e.seed("prod", "guarded", "SENTINEL", true)
	done := e.useAsync("prod", "guarded")
	id := e.pending(1)[0]["request_id"].(string)
	bad := e.wrongCode()
	for i := 0; i < 3; i++ {
		if code, _, _ := e.approve(e.opA, id, bad); code != 400 {
			t.Fatalf("bad code %d: %d", i, code)
		}
	}
	// Locked out: 429 with Retry-After, even for the correct code, which
	// must not be consumed.
	good := e.goodCode()
	code, m, hdr := e.approve(e.opA, id, good)
	if code != 429 || m["error"] != "ApprovalThrottled" || hdr.Get("Retry-After") == "" {
		t.Fatalf("throttled: %d %v %v", code, m, hdr)
	}
	if len(e.rows("APPROVAL_LOCKOUT")) != 1 || len(e.rows("APPROVAL_THROTTLED")) != 1 {
		t.Fatalf("rows: lockout=%d throttled=%d", len(e.rows("APPROVAL_LOCKOUT")), len(e.rows("APPROVAL_THROTTLED")))
	}
	if e.notes.count(approval.EventLockout) != 1 || e.notes.count(approval.EventThrottled) != 1 {
		t.Fatalf("notifications = %v", e.notes.kinds())
	}
	// Another operator is not locked, and the code is still unused.
	if code, m, _ := e.approve(e.opB, id, good); code != 200 {
		t.Fatalf("other operator: %d %v", code, m)
	}
	if res := <-done; res.code != 200 {
		t.Fatalf("agent: %d %v", res.code, res.body)
	}
	e.assertNoCode(bad, good)
}

func TestH2MissingCodeIsCountedAndDeniesTheRequest(t *testing.T) {
	e := newH2Env(t, nil)
	e.seed("prod", "guarded", "SENTINEL", true)
	done := e.useAsync("prod", "guarded")
	id := e.pending(1)[0]["request_id"].(string)
	for i := 1; i < approval.DefaultMaxCodeAttempts; i++ {
		if code, _, _ := e.approve(e.opA, id, ""); code != 400 {
			t.Fatalf("missing code %d: %d", i, code)
		}
	}
	if code, m, _ := e.approve(e.opA, id, ""); code != 403 {
		t.Fatalf("the capping missing code: %d %v", code, m)
	}
	if res := <-done; res.code != 403 {
		t.Fatalf("agent: %d %v", res.code, res.body)
	}
	rows := e.rows("APPROVAL_BAD_CODE")
	if len(rows) != approval.DefaultMaxCodeAttempts || !strings.Contains(rows[0].details, "attempt=1/5") {
		t.Fatalf("rows = %+v", rows)
	}
}

// A flood of code-less approve calls with one stolen operator token: the
// budget stops it, the audit log and the notifier stay small, and the lockout
// alert is among the events.
func TestH2NoCodeFloodIsBoundedAndTheLockoutIsReported(t *testing.T) {
	e := newH2Env(t, func(o *StackOptions) { o.ApprovalCodeAttempts = 1000 })
	e.seed("prod", "guarded", "SENTINEL", true)
	var dones []<-chan asyncResp
	for i := 0; i < 3; i++ {
		dones = append(dones, e.useAsync("prod", "guarded"))
	}
	reqs := e.pending(3)
	codes := map[int]int{}
	for i := 0; i < 400; i++ {
		c, _, _ := e.approve(e.opA, reqs[i%3]["request_id"].(string), "")
		codes[c]++
	}
	if codes[400] != approval.DefaultMaxOperatorFails || codes[429] != 400-approval.DefaultMaxOperatorFails {
		t.Fatalf("status codes = %v, want %d x 400 then 429", codes, approval.DefaultMaxOperatorFails)
	}
	// 10 counted rows, one lockout row, and the 390 throttled calls
	// coalesced into one row (not 390).
	if n := len(e.rows("APPROVAL_BAD_CODE")); n != approval.DefaultMaxOperatorFails {
		t.Fatalf("APPROVAL_BAD_CODE rows = %d", n)
	}
	if n := len(e.rows("APPROVAL_LOCKOUT")); n != 1 {
		t.Fatalf("APPROVAL_LOCKOUT rows = %d", n)
	}
	if n := len(e.rows("APPROVAL_THROTTLED")); n != 1 {
		t.Fatalf("APPROVAL_THROTTLED rows = %d, want the flood coalesced into 1", n)
	}
	if e.notes.count(approval.EventLockout) != 1 || e.notes.count(approval.EventThrottled) != 1 {
		t.Fatalf("notifications = %v", e.notes.kinds())
	}
	for _, r := range reqs {
		e.do("POST", "/v1/requests/"+r["request_id"].(string)+"/deny", e.opB, nil)
	}
	for _, d := range dones {
		<-d
	}
}

// Many self-approval attempts are coalesced too; the first one is reported.
func TestH2SelfApprovalFloodIsCoalesced(t *testing.T) {
	e := newH2Env(t, nil)
	e.seed("prod", "plain", "SENTINEL", false)
	done := e.useAsync("prod", "plain")
	id := e.pending(1)[0]["request_id"].(string)
	for i := 0; i < 50; i++ {
		if c, _, _ := e.approve(e.aliceOp, id, ""); c != 403 {
			t.Fatalf("self approval: %d", c)
		}
	}
	if n := len(e.rows("APPROVAL_SOD_DENIED")); n != 1 {
		t.Fatalf("APPROVAL_SOD_DENIED rows = %d, want 1 (coalesced)", n)
	}
	e.approve(e.opA, id, "")
	<-done
}

// The pending-request cap and the per-agent rate limit stop one agent token
// from burying the operator's queue with gated sets.
func TestH2GatedSetQueueIsCapped(t *testing.T) {
	e := newH2Env(t, func(o *StackOptions) {
		o.RequireApproval = false
		o.RequireApprovalFor = []approval.GatedOp{approval.OpSet}
		o.ApprovalMaxPendingPerAgent = 5
		o.RateLimit = 1000
	})
	var dones []<-chan asyncResp
	for i := 0; i < 5; i++ {
		dones = append(dones, e.async("POST", "/v1/secrets", e.alice,
			map[string]any{"name": fmt.Sprintf("k%d", i), "value": "v", "namespace": "prod", "purpose": "ci"}))
	}
	e.pending(5)
	codes := map[int]int{}
	for i := 0; i < 30; i++ {
		c, m, _ := e.do("POST", "/v1/secrets", e.alice, map[string]any{"name": fmt.Sprintf("x%d", i), "value": "v", "namespace": "prod", "purpose": "ci"})
		codes[c]++
		if c == 429 && m["error"] != "ApprovalQueueFull" {
			t.Fatalf("429 = %v", m)
		}
	}
	if codes[429] != 30 {
		t.Fatalf("over the cap: %v", codes)
	}
	if n := len(e.rows("APPROVAL_QUEUE_FULL")); n != 1 {
		t.Fatalf("APPROVAL_QUEUE_FULL rows = %d, want 1 (coalesced)", n)
	}
	if e.notes.count(approval.EventQueueFull) != 1 {
		t.Fatalf("notifications = %v", e.notes.kinds())
	}
	if _, m, _ := e.do("GET", "/v1/requests", e.opA, nil); len(m["requests"].([]any)) != 5 {
		t.Fatalf("queue = %v", m)
	}
	// Another agent is not affected by alice's cap.
	for _, r := range e.pending(5) {
		e.do("POST", "/v1/requests/"+r["request_id"].(string)+"/deny", e.opA, nil)
	}
	for _, d := range dones {
		<-d
	}
}

func TestH2GatedSetIsRateLimitedBeforeParking(t *testing.T) {
	e := newH2Env(t, func(o *StackOptions) {
		o.RequireApproval = false
		o.RequireApprovalFor = []approval.GatedOp{approval.OpSet}
		o.RateLimit = 3
		o.RateWindow = time.Hour
	})
	var dones []<-chan asyncResp
	for i := 0; i < 3; i++ {
		dones = append(dones, e.async("POST", "/v1/secrets", e.alice,
			map[string]any{"name": fmt.Sprintf("k%d", i), "value": "v", "namespace": "prod", "purpose": "ci"}))
	}
	e.pending(3)
	c, m, _ := e.do("POST", "/v1/secrets", e.alice, map[string]any{"name": "k9", "value": "v", "namespace": "prod", "purpose": "ci"})
	if c != 429 || !strings.Contains(fmt.Sprint(m["detail"]), "Rate limit") {
		t.Fatalf("4th gated set: %d %v", c, m)
	}
	if len(e.rows("RATE_LIMITED")) != 1 {
		t.Fatalf("RATE_LIMITED rows = %d", len(e.rows("RATE_LIMITED")))
	}
	for _, r := range e.pending(3) {
		e.do("POST", "/v1/requests/"+r["request_id"].(string)+"/deny", e.opA, nil)
	}
	for _, d := range dones {
		<-d
	}
}

// --- (2) TOTP replay: rejected, audited, notified --------------------------

func TestH2ReplayedCodeRejectedAuditedNotified(t *testing.T) {
	e := newH2Env(t, nil)
	e.seed("prod", "a", "A-SENTINEL", true)
	e.seed("prod", "b", "B-SENTINEL", true)

	doneA := e.useAsync("prod", "a")
	idA := e.pending(1)[0]["request_id"].(string)
	good := e.goodCode()
	if code, m, _ := e.approve(e.opA, idA, good); code != 200 {
		t.Fatalf("first use: %d %v", code, m)
	}
	<-doneA

	// Somebody who saw the code replays it on the next request.
	doneB := e.useAsync("prod", "b")
	var idB string
	for _, p := range e.pending(1) {
		idB = p["request_id"].(string)
	}
	code, m, _ := e.approve(e.opB, idB, good)
	if code != 400 || !strings.Contains(fmt.Sprint(m["detail"]), "already used") {
		t.Fatalf("replay: %d %v", code, m)
	}
	rep := e.rows("APPROVAL_CODE_REPLAY")
	if len(rep) != 1 || !strings.Contains(rep[0].details, "request="+idB) || rep[0].agent != "ops2" {
		t.Fatalf("replay rows = %+v", rep)
	}
	if e.notes.count(approval.EventCodeReplay) != 1 {
		t.Fatalf("notifications = %v", e.notes.kinds())
	}
	if len(e.rows("APPROVAL_BAD_CODE")) != 0 {
		t.Fatal("a replay was recorded as an ordinary bad code")
	}
	e.assertNoCode(good, "A-SENTINEL", "B-SENTINEL")
	// Deny so the goroutine ends.
	e.do("POST", "/v1/requests/"+idB+"/deny", e.opA, nil)
	<-doneB
}

// --- (7) separation of duties and expiry ----------------------------------

func TestH2AgentCannotApproveOwnRequest(t *testing.T) {
	e := newH2Env(t, nil)
	e.seed("prod", "plain", "SENTINEL", false)
	done := e.useAsync("prod", "plain")
	id := e.pending(1)[0]["request_id"].(string)
	_ = id

	// aliceOp is a token of the requesting agent. It is not the same token as
	// the requester (alice), it has the operator scope, and it still cannot
	// approve: same agent. Its own twin token fares no better.
	for name, tok := range map[string]string{"agent+operator token": e.aliceOp, "operator token of the same agent": e.aliceOp2} {
		code, m, _ := e.approve(tok, id, "")
		if code != 403 || m["error"] != "SeparationOfDutiesError" {
			t.Fatalf("%s: %d %v", name, code, m)
		}
	}
	if len(e.rows("APPROVAL_SOD_DENIED")) != 2 || e.notes.count(approval.EventSeparation) != 2 {
		t.Fatalf("sod rows=%d notes=%v", len(e.rows("APPROVAL_SOD_DENIED")), e.notes.kinds())
	}
	// The request is still pending; a different operator approves it.
	if len(e.pending(1)) != 1 {
		t.Fatal("request lost")
	}
	if code, m, _ := e.approve(e.opA, id, ""); code != 200 {
		t.Fatalf("honest approve: %d %v", code, m)
	}
	if res := <-done; res.code != 200 {
		t.Fatalf("agent: %d %v", res.code, res.body)
	}
	if len(e.rows("APPROVAL_APPROVED")) != 1 {
		t.Fatal("approval not audited")
	}
}

func TestH2SameTokenIDCannotApprove(t *testing.T) {
	// One token carrying both the agent and the operator scope: the request
	// it makes can never be approved with the same token id.
	e := newH2Env(t, nil)
	e.seed("prod", "plain", "SENTINEL", false)
	done := e.async("POST", "/v1/secrets/prod/plain/use", e.aliceOp, map[string]any{"action": "echo", "purpose": "p"})
	id := e.pending(1)[0]["request_id"].(string)
	if code, m, _ := e.approve(e.aliceOp, id, ""); code != 403 || m["error"] != "SeparationOfDutiesError" {
		t.Fatalf("self approval: %d %v", code, m)
	}
	if code, _, _ := e.approve(e.opB, id, ""); code != 200 {
		t.Fatalf("other operator: %d", code)
	}
	if res := <-done; res.code != 200 {
		t.Fatalf("agent: %d %v", res.code, res.body)
	}
}

func TestH2RequestExpiryFailsClosed(t *testing.T) {
	e := newH2Env(t, func(o *StackOptions) { o.ApprovalTimeout = 150 * time.Millisecond })
	e.seed("prod", "plain", "SENTINEL", false)
	done := e.useAsync("prod", "plain")
	id := e.pending(1)[0]["request_id"].(string)
	res := <-done
	if res.code != 403 || !strings.Contains(fmt.Sprint(res.body["detail"]), "timed out") {
		t.Fatalf("expired request: %d %v", res.code, res.body)
	}
	// Too late for an operator: nothing to approve.
	if code, m, _ := e.approve(e.opA, id, ""); code != 400 {
		t.Fatalf("late approve: %d %v", code, m)
	}
	if rows := e.rows("APPROVAL_DENIED"); len(rows) != 1 || !strings.Contains(rows[0].details, "timed out") {
		t.Fatalf("APPROVAL_DENIED rows = %+v", rows)
	}
	if len(e.rows("LEASE_GRANTED")) != 0 {
		t.Fatal("the value was leased although the approval expired")
	}
}

// --- (4) require_2fa downgrade over HTTP ----------------------------------

func TestH2DowngradeNeedsOperatorScope(t *testing.T) {
	e := newH2Env(t, nil)
	set := func(tok string, extra map[string]any) (int, map[string]any) {
		body := map[string]any{"name": "root", "value": "v", "namespace": "prod", "purpose": "ci"}
		for k, v := range extra {
			body[k] = v
		}
		c, m, _ := e.do("POST", "/v1/secrets", tok, body)
		return c, m
	}
	if c, m := set(e.alice, map[string]any{"require_2fa": true}); c != 200 {
		t.Fatalf("create: %d %v", c, m)
	}
	// Explicit false and an omitted flag both strip it: refused.
	for name, extra := range map[string]map[string]any{"explicit false": {"require_2fa": false}, "omitted": nil} {
		c, m := set(e.alice, extra)
		if c != 403 || !strings.Contains(fmt.Sprint(m["detail"]), "require_2fa") {
			t.Fatalf("%s: %d %v", name, c, m)
		}
	}
	if len(e.rows("REQUIRE_2FA_DOWNGRADE_DENIED")) != 2 {
		t.Fatalf("denial rows = %d", len(e.rows("REQUIRE_2FA_DOWNGRADE_DENIED")))
	}
	if on, _ := e.stack.Vault.Requires2FA(context.Background(), "prod", "root"); !on {
		t.Fatal("the flag was stripped")
	}
	// Keeping it is fine.
	if c, m := set(e.alice, map[string]any{"require_2fa": true}); c != 200 {
		t.Fatalf("keep: %d %v", c, m)
	}
	// An operator may drop it, and it is audited.
	if c, m := set(e.aliceOp, map[string]any{"require_2fa": false}); c != 200 {
		t.Fatalf("operator downgrade: %d %v", c, m)
	}
	if rows := e.rows("REQUIRE_2FA_DOWNGRADED"); len(rows) != 1 || !strings.Contains(rows[0].details, "Agent: alice") {
		t.Fatalf("downgrade rows = %+v", rows)
	}
	if on, _ := e.stack.Vault.Requires2FA(context.Background(), "prod", "root"); on {
		t.Fatal("operator downgrade did not apply")
	}
}

func TestH2LegacySharedTokenCannotDowngrade(t *testing.T) {
	// The legacy shared token holds every scope, so the scope proves nothing:
	// it can never drop require_2fa.
	e := newEnv(t, envOpts{})
	e.set("prod", "root", "v", map[string]any{"require_2fa": true})
	code, m, _ := e.call("POST", "/v1/secrets", e.agentTok, map[string]any{"name": "root", "value": "v2", "namespace": "prod", "agent": "bot", "purpose": "ci"})
	if code != 403 || !strings.Contains(fmt.Sprint(m["detail"]), "require_2fa") {
		t.Fatalf("legacy downgrade: %d %v", code, m)
	}
}

// --- (5) optional approval for set / revoke / rotate ----------------------

func TestH2GatedSetRevokeRotate(t *testing.T) {
	e := newH2Env(t, func(o *StackOptions) {
		o.RequireApproval = false // reads are NOT gated; only the listed operations
		o.RequireApprovalFor = []approval.GatedOp{approval.OpSet, approval.OpRevoke, approval.OpRotate}
	})
	// A read needs no approval.
	e.seed("prod", "plain", "SENTINEL", false)
	if c, m, _ := e.do("POST", "/v1/secrets/prod/plain/use", e.alice, map[string]any{"action": "echo", "purpose": "p"}); c != 200 {
		t.Fatalf("ungated read: %d %v", c, m)
	}

	// set waits for an operator.
	done := e.async("POST", "/v1/secrets", e.alice, map[string]any{"name": "newk", "value": "NEW-SENTINEL", "namespace": "prod", "purpose": "ci"})
	req := e.pending(1)[0]
	if req["action"] != "set" || req["agent"] != "alice" || req["secret_name"] != "newk" || req["require_2fa"] != false {
		t.Fatalf("set request = %v", req)
	}
	if strings.Contains(fmt.Sprint(req), "NEW-SENTINEL") {
		t.Fatal("the pending request carries the value")
	}
	if len(e.rows("SET_SECRET")) != 1 { // only the seed
		t.Fatal("secret written before approval")
	}
	if c, m, _ := e.approve(e.opA, req["request_id"].(string), ""); c != 200 {
		t.Fatalf("approve set: %d %v", c, m)
	}
	if res := <-done; res.code != 200 {
		t.Fatalf("set after approval: %d %v", res.code, res.body)
	}
	if len(e.rows("SET_SECRET")) != 2 {
		t.Fatal("approved set not written")
	}

	// A denied set is a 403 and nothing is written.
	done = e.async("POST", "/v1/secrets", e.alice, map[string]any{"name": "nope", "value": "v", "namespace": "prod", "purpose": "ci"})
	id := e.pending(1)[0]["request_id"].(string)
	e.do("POST", "/v1/requests/"+id+"/deny", e.opA, map[string]any{"reason": "no thanks"})
	if res := <-done; res.code != 403 || !strings.Contains(fmt.Sprint(res.body["detail"]), "no thanks") {
		t.Fatalf("denied set: %d %v", res.code, res.body)
	}
	if rows := e.rows("APPROVAL_DENIED"); len(rows) != 1 || !strings.Contains(rows[0].details, "Action: set") {
		t.Fatalf("APPROVAL_DENIED rows = %+v", rows)
	}
	if len(e.rows("SET_SECRET")) != 2 {
		t.Fatal("a denied set was written")
	}

	// revoke waits too.
	done = e.async("POST", "/v1/secrets/prod/newk/revoke", e.alice, nil)
	req = e.pending(1)[0]
	if req["action"] != "revoke" || req["secret_name"] != "newk" {
		t.Fatalf("revoke request = %v", req)
	}
	e.approve(e.opB, req["request_id"].(string), "")
	if res := <-done; res.code != 200 {
		t.Fatalf("revoke after approval: %d %v", res.code, res.body)
	}

	// rotate (operator route): the approver must be ANOTHER operator.
	done = e.async("POST", "/v1/rotate", e.opA, map[string]any{"target": "dek"})
	req = e.pending(1)[0]
	if req["action"] != "rotate" || req["namespace"] != "_admin" || req["secret_name"] != "dek" || req["require_2fa"] != true {
		t.Fatalf("rotate request = %v", req)
	}
	rid := req["request_id"].(string)
	if c, m, _ := e.approve(e.opA, rid, e.goodCode()); c != 403 || m["error"] != "SeparationOfDutiesError" {
		t.Fatalf("operator approves own rotation: %d %v", c, m)
	}
	if c, m, _ := e.approve(e.opB, rid, e.goodCode()); c != 200 {
		t.Fatalf("second operator: %d %v", c, m)
	}
	if res := <-done; res.code != 200 || res.body["target"] != "dek" {
		t.Fatalf("rotate after approval: %d %v", res.code, res.body)
	}
}

func TestH2GatedOpsSkipRequestsThePolicyDenies(t *testing.T) {
	e := newH2Env(t, func(o *StackOptions) {
		o.RequireApproval = false
		o.RequireApprovalFor = []approval.GatedOp{approval.OpSet, approval.OpRevoke}
		o.PolicyFile = writeFile(t, filepath.Join(t.TempDir(), "p.yaml"), `rules:
  - effect: allow
    agent: "*"
    namespace: open
    purpose: "*"
    action: "*"
`)
	})
	// The policy refuses prod: the operator is never bothered, the vault
	// denies (and audits) as usual.
	c, m, _ := e.do("POST", "/v1/secrets", e.alice, map[string]any{"name": "k", "value": "v", "namespace": "prod", "purpose": "ci"})
	if c != 403 || m["error"] != "PolicyDeniedError" {
		t.Fatalf("denied set: %d %v", c, m)
	}
	c, m, _ = e.do("POST", "/v1/secrets/prod/k/revoke", e.alice, nil)
	if c != 403 || m["error"] != "PolicyDeniedError" {
		t.Fatalf("denied revoke: %d %v", c, m)
	}
	if _, m2, _ := e.do("GET", "/v1/requests", e.opA, nil); len(m2["requests"].([]any)) != 0 {
		t.Fatalf("a policy-denied request reached the operator: %v", m2)
	}
	if len(e.rows("POLICY_DENIED")) != 2 {
		t.Fatalf("POLICY_DENIED rows = %d", len(e.rows("POLICY_DENIED")))
	}
}

func TestH2GatedSetNeeds2FAWhenSecretIsFlagged(t *testing.T) {
	e := newH2Env(t, func(o *StackOptions) {
		o.RequireApproval = false
		o.RequireApprovalFor = []approval.GatedOp{approval.OpSet}
	})
	e.seed("prod", "root", "v1", true)
	done := e.async("POST", "/v1/secrets", e.alice, map[string]any{"name": "root", "value": "v2", "namespace": "prod", "purpose": "ci", "require_2fa": true})
	req := e.pending(1)[0]
	if req["require_2fa"] != true {
		t.Fatalf("flagged secret set without 2FA: %v", req)
	}
	id := req["request_id"].(string)
	if c, _, _ := e.approve(e.opA, id, ""); c != 400 {
		t.Fatalf("approve without code: %d", c)
	}
	if c, _, _ := e.approve(e.opA, id, e.goodCode()); c != 200 {
		t.Fatalf("approve with code: %d", c)
	}
	if res := <-done; res.code != 200 {
		t.Fatalf("set: %d %v", res.code, res.body)
	}
}

func TestH2GatedOpsConfigErrors(t *testing.T) {
	e := newH2Env(t, nil)
	if _, err := New(Config{Vault: e.stack.Vault, Tokens: e.store, GatedOps: []approval.GatedOp{approval.OpSet}}); err == nil {
		t.Fatal("GatedOps without a Broker was accepted")
	}
}

// --- (6) capability tokens are single-use through the real server path -----

func TestH2CapabilityTokenIsSingleUse(t *testing.T) {
	e := newH2Env(t, nil)
	execute := func(tok string) (int, map[string]any) {
		c, m, _ := e.do("POST", "/v1/capabilities/execute", e.alice,
			map[string]any{"capability": "secrets.echo", "capability_token": tok, "payload": map[string]any{"message": "hi"}})
		return c, m
	}
	tok, err := e.signer.Sign("alice", "secrets.echo", 1, nil, 120)
	if err != nil {
		t.Fatal(err)
	}
	if c, m := execute(tok); c != 200 || m["ok"] != true {
		t.Fatalf("first use: %d %v", c, m)
	}
	for i := 0; i < 3; i++ {
		c, m := execute(tok)
		if c != 403 || !strings.Contains(fmt.Sprint(m["detail"]), "already used") {
			t.Fatalf("replay %d: %d %v", i, c, m)
		}
	}
	denied := e.rows("CAPABILITY_DENIED")
	if len(denied) != 3 || !strings.Contains(denied[0].details, "TokenReplayError") {
		t.Fatalf("CAPABILITY_DENIED rows = %+v", denied)
	}
	if len(e.rows("CAPABILITY_EXECUTED")) != 1 {
		t.Fatal("the replayed token executed")
	}
	// The replayed token is not echoed anywhere.
	for _, r := range e.audit() {
		if strings.Contains(r.details, tok) {
			t.Fatalf("audit row %s contains the token", r.action)
		}
	}
	// A fresh token works.
	tok2, _ := e.signer.Sign("alice", "secrets.echo", 1, nil, 121)
	if c, m, _ := e.do("POST", "/v1/capabilities/execute", e.alice,
		map[string]any{"capability": "secrets.echo", "capability_token": tok2, "payload": map[string]any{"message": "hi"}}); c != 200 {
		t.Fatalf("fresh token: %d %v", c, m)
	}
}

func TestH2CapabilityReplayConcurrent(t *testing.T) {
	e := newH2Env(t, nil)
	tok, _ := e.signer.Sign("alice", "secrets.echo", 1, nil, 120)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, _, _ := e.do("POST", "/v1/capabilities/execute", e.alice,
				map[string]any{"capability": "secrets.echo", "capability_token": tok, "payload": map[string]any{"message": "x"}})
			mu.Lock()
			codes[c]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[200] != 1 || codes[403] != 11 {
		t.Fatalf("status codes = %v, want exactly one 200", codes)
	}
}

// --- TOTP secret file ------------------------------------------------------

func TestH2TOTPSecretFileMustBePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes only")
	}
	dir := t.TempDir()
	path := writeFile(t, filepath.Join(dir, "totp.secret"), "JBSWY3DPEHPK3PXP\n")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := OpenStack(context.Background(), StackOptions{
		DBPath: filepath.Join(dir, "v", "vault.db"), MasterProvider: providerstest.NewMemory(),
		RequireApproval: true, TOTPSecretFile: path, KDFParams: testKDF,
	})
	if err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("group-readable secret accepted: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStack(context.Background(), StackOptions{
		DBPath: filepath.Join(dir, "v", "vault.db"), MasterProvider: providerstest.NewMemory(),
		RequireApproval: true, TOTPSecretFile: path, KDFParams: testKDF,
	})
	if err != nil {
		t.Fatalf("0600 secret: %v", err)
	}
	_ = s.Close()
	if _, err := OpenStack(context.Background(), StackOptions{
		DBPath: filepath.Join(dir, "v2", "vault.db"), MasterProvider: providerstest.NewMemory(),
		RequireApproval: true, TOTPSecretFile: filepath.Join(dir, "missing"), KDFParams: testKDF,
	}); err == nil {
		t.Fatal("missing secret file accepted")
	}
}

func TestH2GatedOpsValidateBeforeTheOperatorSees(t *testing.T) {
	e := newH2Env(t, func(o *StackOptions) {
		o.RequireApproval = false
		o.RequireApprovalFor = []approval.GatedOp{approval.OpSet}
	})
	// Control characters in the purpose must be refused with 400 before an
	// approval request (shown on the operator's screen) is created.
	c, m, _ := e.do("POST", "/v1/secrets", e.alice, map[string]any{
		"name": "k", "value": "v", "namespace": "prod", "purpose": "ok\x1b[2J\x1b[31mFAKE PROMPT"})
	if c != 400 {
		t.Fatalf("control characters in the purpose: %d %v", c, m)
	}
	c, m, _ = e.do("POST", "/v1/secrets", e.alice, map[string]any{"name": "bad name\n", "value": "v", "namespace": "prod"})
	if c != 400 {
		t.Fatalf("bad name: %d %v", c, m)
	}
	if _, m2, _ := e.do("GET", "/v1/requests", e.opA, nil); len(m2["requests"].([]any)) != 0 {
		t.Fatalf("an invalid request reached the operator: %v", m2)
	}
}

// A bystander who sees a capability token cannot burn it by presenting it as
// another agent: it is consumed only after the agent binding matched.
func TestH2CapabilityTokenNotBurnedByAWrongAgent(t *testing.T) {
	e := newH2Env(t, nil)
	tok, _ := e.signer.Sign("carol", "secrets.echo", 1, nil, 120)
	carol := func() string {
		tk, _, err := e.store.Mint(auth.MintOptions{Agent: "carol", Scopes: []auth.Scope{auth.ScopeAgent}})
		if err != nil {
			t.Fatal(err)
		}
		return tk
	}()
	body := map[string]any{"capability": "secrets.echo", "capability_token": tok, "payload": map[string]any{"message": "hi"}}
	// alice presents carol's token: refused (agent mismatch) and NOT consumed.
	for i := 0; i < 3; i++ {
		c, m, _ := e.do("POST", "/v1/capabilities/execute", e.alice, body)
		if c != 403 || !strings.Contains(fmt.Sprint(m["detail"]), "bound to agent") {
			t.Fatalf("bystander attempt %d: %d %v", i, c, m)
		}
	}
	if c, m, _ := e.do("POST", "/v1/capabilities/execute", carol, body); c != 200 {
		t.Fatalf("the rightful agent: %d %v", c, m)
	}
	if c, _, _ := e.do("POST", "/v1/capabilities/execute", carol, body); c != 403 {
		t.Fatalf("replay by the rightful agent: %d", c)
	}
}

// RGT-510: the last accepted TOTP step survives a restart.
func TestH2TOTPReplayWindowStaysClosedAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	secret, _ := totp.GenerateSecret(20)
	secretFile := writeFile(t, filepath.Join(dir, "totp.secret"), secret+"\n")
	open := func(db string) *Stack {
		s, err := OpenStack(context.Background(), StackOptions{
			DBPath: filepath.Join(dir, db, "vault.db"), MasterProvider: providerstest.NewMemory(),
			RequireApproval: true, TOTPSecretFile: secretFile, ApprovalTimeout: 30 * time.Second, KDFParams: testKDF,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	approveWith := func(s *Stack, code string) error {
		tk, err := s.Broker.Submit(approval.Request{RequestID: fmt.Sprintf("r-%d", time.Now().UnixNano()), Require2FA: true})
		if err != nil {
			t.Fatal(err)
		}
		defer tk.Wait(context.Background())
		err = s.Broker.Approve(tk.ID(), code, "op")
		if err != nil {
			_ = s.Broker.Deny(tk.ID(), "cleanup", "op")
		}
		return err
	}
	code, _ := totp.Generate(secret, time.Now())
	s1 := open("v1")
	if err := approveWith(s1, code); err != nil {
		t.Fatal(err)
	}
	_ = s1.Close()
	// The server restarts: the used code is still refused, as a replay.
	s2 := open("v2")
	if err := approveWith(s2, code); !errors.Is(err, approval.ErrCodeReplayed) {
		t.Fatalf("code reused after a restart = %v, want a replay", err)
	}
	if _, err := os.Stat(secretFile + ".state"); err != nil {
		t.Fatalf("state file: %v", err)
	}
}

func TestH2TOTPSecretFileChecks(t *testing.T) {
	dir := t.TempDir()
	o := StackOptions{DBPath: filepath.Join(dir, "v", "vault.db"), MasterProvider: providerstest.NewMemory(), RequireApproval: true, KDFParams: testKDF}
	o.TOTPSecretFile = dir // not a regular file
	if _, err := OpenStack(context.Background(), o); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory: %v", err)
	}
	o.TOTPSecretFile = writeFile(t, filepath.Join(dir, "big"), strings.Repeat("A", 5000))
	if _, err := OpenStack(context.Background(), o); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized: %v", err)
	}
	o.TOTPSecretFile = writeFile(t, filepath.Join(dir, "empty"), "\n")
	if _, err := OpenStack(context.Background(), o); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty: %v", err)
	}
}

// Review of PR #56: 64 goroutines guessing across 6 requests with one
// operator token hold the operator budget exactly, and a correct code sent
// while locked out is refused and NOT consumed.
func TestH2ConcurrentGuessingHoldsTheOperatorBudget(t *testing.T) {
	e := newH2Env(t, func(o *StackOptions) {
		o.ApprovalCodeAttempts = 1000
		o.ApprovalOperatorFails = 10
		o.ApprovalLockout = time.Second
	})
	e.seed("prod", "guarded", "SENTINEL", true)
	const nReq = 6
	var dones []<-chan asyncResp
	for i := 0; i < nReq; i++ {
		dones = append(dones, e.useAsync("prod", "guarded"))
	}
	reqs := e.pending(nReq)
	bad := e.wrongCode()
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			c, _, _ := e.approve(e.opA, reqs[g%nReq]["request_id"].(string), bad)
			mu.Lock()
			codes[c]++
			mu.Unlock()
		}(g)
	}
	wg.Wait()
	if codes[400] != 10 || codes[429] != 54 || len(codes) != 2 {
		t.Fatalf("status codes = %v, want 10 x 400 and 54 x 429", codes)
	}
	good := e.goodCode()
	id := reqs[0]["request_id"].(string)
	if c, _, _ := e.approve(e.opA, id, good); c != 429 {
		t.Fatalf("correct code while locked out: %d", c)
	}
	time.Sleep(1200 * time.Millisecond)
	// Same code, same time step: it was not consumed by the refused call.
	if c, m, _ := e.approve(e.opA, id, good); c != 200 {
		t.Fatalf("correct code after the lockout: %d %v", c, m)
	}
	for _, r := range reqs[1:] {
		e.do("POST", "/v1/requests/"+r["request_id"].(string)+"/deny", e.opB, nil)
	}
	for _, d := range dones {
		<-d
	}
}

// A second token of the same operator shares the budget.
func TestH2SecondTokenOfTheSameOperatorSharesTheBudget(t *testing.T) {
	e := newH2Env(t, func(o *StackOptions) {
		o.ApprovalCodeAttempts = 1000
		o.ApprovalOperatorFails = 3
	})
	second, _, err := e.store.Mint(auth.MintOptions{Agent: "ops1", Scopes: []auth.Scope{auth.ScopeOperator}})
	if err != nil {
		t.Fatal(err)
	}
	e.seed("prod", "guarded", "SENTINEL", true)
	done := e.useAsync("prod", "guarded")
	id := e.pending(1)[0]["request_id"].(string)
	bad := e.wrongCode()
	counted := 0
	for i := 0; i < 8; i++ {
		tok := e.opA
		if i%2 == 1 {
			tok = second
		}
		if c, _, _ := e.approve(tok, id, bad); c == 400 {
			counted++
		}
	}
	if counted != 3 {
		t.Fatalf("%d guesses counted with two tokens of one operator, want 3", counted)
	}
	e.do("POST", "/v1/requests/"+id+"/deny", e.opB, nil)
	<-done
}
