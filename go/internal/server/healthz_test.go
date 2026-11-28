package server

// RGT-531: GET /healthz is a public liveness probe whose detail (vault id,
// key epoch, action list, version) is for callers holding the audit or
// operator scope. These tests pin the optional-authentication path in
// AuthMiddleware: what each kind of token sees, that junk on /healthz never
// feeds the failed-authentication limiter or the audit log, and that a
// lockout or a token-store fault never changes what /healthz answers.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/buildinfo"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/server/handlers"
)

const minimalHealthBody = `{"status":"ok"}` + "\n"

// healthGet performs GET /healthz with a raw Authorization header ("" = none).
func healthGet(h http.Handler, authz string, ip string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/healthz", nil)
	req.RemoteAddr = ip + ":4000"
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func bearer(tok string) string { return "Bearer " + tok }

// wantDetailed asserts the FULL detailed body: exactly status, vault_id,
// key_epoch, actions and version, with the right values.
func wantDetailed(t *testing.T, name string, rec *httptest.ResponseRecorder, e *healthWant) {
	t.Helper()
	if rec.Code != 200 {
		t.Fatalf("%s: status %d, body %s", name, rec.Code, rec.Body.String())
	}
	m := decodeObject(t, rec.Body.String())
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if want := []string{"actions", "key_epoch", "status", "vault_id", "version"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("%s: body keys %v, want %v (%s)", name, keys, want, rec.Body.String())
	}
	if m["status"] != "ok" || m["vault_id"] != e.vaultID || m["version"] != buildinfo.Version() {
		t.Errorf("%s: body %v", name, m)
	}
	if m["key_epoch"].(float64) != float64(e.keyEpoch) {
		t.Errorf("%s: key_epoch %v, want %d", name, m["key_epoch"], e.keyEpoch)
	}
	acts, _ := m["actions"].([]any)
	got := make([]string, 0, len(acts))
	for _, a := range acts {
		got = append(got, a.(string))
	}
	if !reflect.DeepEqual(got, e.actions) {
		t.Errorf("%s: actions %v, want %v", name, got, e.actions)
	}
	if len(e.actions) == 0 || !contains(e.actions, "echo") {
		t.Fatalf("test setup: expected the echo action, have %v", e.actions)
	}
}

func decodeObject(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("body is not a JSON object: %q (%v)", body, err)
	}
	return m
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func wantMinimal(t *testing.T, name string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != 200 || rec.Body.String() != minimalHealthBody {
		t.Errorf("%s: %d %q, want 200 %q", name, rec.Code, rec.Body.String(), minimalHealthBody)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("%s: content-type %q", name, ct)
	}
}

// healthWant carries the values a detailed body must contain.
type healthWant struct {
	vaultID  string
	keyEpoch int
	actions  []string
}

func healthExpect(t *testing.T, e *authzEnv) *healthWant {
	t.Helper()
	var names []string
	for _, s := range e.stack.Actions.List() {
		names = append(names, s.Name)
	}
	return &healthWant{vaultID: e.stack.Vault.VaultID(), keyEpoch: int(e.stack.Vault.KeyEpoch()), actions: names}
}

func auditCount(t *testing.T, e *authzEnv) int {
	t.Helper()
	all, err := e.stack.Vault.AuditLog(context.Background(), -1)
	if err != nil {
		t.Fatal(err)
	}
	return len(all)
}

// Every token state in per-agent mode.
func TestHealthzPerAgentTokenMatrix(t *testing.T) {
	e := newAuthzEnv(t, false)
	want := healthExpect(t, e)

	expired := func() string {
		tok, _, err := e.store.Mint(auth.MintOptions{Agent: "shortlived", Scopes: []auth.Scope{auth.ScopeAudit, auth.ScopeOperator}, TTL: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}()
	revoked := func() string {
		tok, info, err := e.store.Mint(auth.MintOptions{Agent: "gone", Scopes: []auth.Scope{auth.ScopeAudit, auth.ScopeOperator}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.store.Revoke(info.ID); err != nil {
			t.Fatal(err)
		}
		return tok
	}()
	e.advance(time.Hour) // expires `expired`; the other tokens have no expiry

	for _, c := range []struct {
		name     string
		authz    string
		detailed bool
	}{
		{"no header", "", false},
		{"empty bearer", "Bearer ", false},
		{"garbage token", bearer("definitely-not-a-token"), false},
		{"wrong scheme", "Basic dXNlcjpwYXNz", false},
		{"header without scheme", "justatoken", false},
		{"agent token without audit scope", bearer(e.alice), false},
		{"agent+lease token", bearer(e.aliceLease), false},
		{"expired audit+operator token", bearer(expired), false},
		{"revoked audit+operator token", bearer(revoked), false},
		{"audit-scope token", bearer(e.auditor), true},
		{"operator-only token", bearer(e.opOnly), true},
		{"full operator token", bearer(e.operator), true},
	} {
		rec := healthGet(e.h, c.authz, "10.0.0.1")
		if c.detailed {
			wantDetailed(t, c.name, rec, want)
		} else {
			wantMinimal(t, c.name, rec)
		}
	}
}

// The unauthenticated body is byte-identical whatever junk is presented, so
// it is no oracle for token existence, expiry or revocation.
func TestHealthzUnauthenticatedResponsesAreIdentical(t *testing.T) {
	e := newAuthzEnv(t, false)
	base := healthGet(e.h, "", "10.0.0.2")
	for _, authz := range []string{bearer("x"), bearer(strings.Repeat("a", 5000)), bearer(e.alice), "Bearer\x01"} {
		rec := healthGet(e.h, authz, "10.0.0.2")
		if rec.Code != base.Code || rec.Body.String() != base.Body.String() {
			t.Errorf("%.20q: %d %q differs from no-token %d %q", authz, rec.Code, rec.Body.String(), base.Code, base.Body.String())
		}
		for _, h := range []string{"Content-Type", "Retry-After", "WWW-Authenticate"} {
			if rec.Header().Get(h) != base.Header().Get(h) {
				t.Errorf("%.20q: header %s = %q, want %q", authz, h, rec.Header().Get(h), base.Header().Get(h))
			}
		}
	}
	if base.Body.String() != minimalHealthBody {
		t.Fatalf("base body %q", base.Body.String())
	}
}

// Junk on /healthz must not count toward the failed-authentication limit
// (5 per minute in this env), or a scanner could lock out real agents that
// share the source address; and it writes no AUTH_FAILED / audit rows.
func TestHealthzJunkDoesNotFeedLimiterOrAudit(t *testing.T) {
	e := newAuthzEnv(t, false)
	before := auditCount(t, e)
	for i := 0; i < 60; i++ {
		authz := ""
		if i%2 == 1 {
			authz = bearer("garbage-token-value")
		}
		wantMinimal(t, "junk", healthGet(e.h, authz, "127.0.0.1"))
	}
	if n := auditCount(t, e); n != before {
		t.Fatalf("junk /healthz wrote %d audit rows, want 0:\n%s", n-before, e.allAudit())
	}
	// The same source now fails ONE authentication on a real route: a plain
	// 401 (not 429), recorded once.
	if code, _, _ := e.do("GET", "/v1/secrets", "garbage-token-value", nil); code != http.StatusUnauthorized {
		t.Fatalf("first real failure = %d, want 401 (healthz junk was counted)", code)
	}
	if n := len(e.rows("AUTH_FAILED")); n != 1 {
		t.Errorf("AUTH_FAILED rows = %d, want 1", n)
	}
	if n := len(e.rows("AUTH_RATE_LIMITED")); n != 0 {
		t.Errorf("AUTH_RATE_LIMITED rows = %d, want 0", n)
	}
	if code, _, _ := e.do("GET", "/v1/secrets?namespace=alice-ns", e.alice, nil); code != 200 {
		t.Errorf("a real agent from the same address = %d, want 200", code)
	}
}

// And the reverse: a source locked out on the real routes gets the same
// /healthz answers as anybody (never a 429), and a valid token still works.
func TestHealthzUnaffectedByLockout(t *testing.T) {
	e := newAuthzEnv(t, false)
	want := healthExpect(t, e)
	locked := false
	for i := 0; i < 12; i++ {
		if code, _, _ := e.do("GET", "/v1/secrets", "bad-token", nil, "10.9.9.9"); code == http.StatusTooManyRequests {
			locked = true
		}
	}
	if !locked {
		t.Fatal("test setup: the source never hit the limiter")
	}
	if code, _, _ := e.do("GET", "/v1/secrets", "bad-token", nil, "10.9.9.9"); code != http.StatusTooManyRequests {
		t.Fatalf("setup: source not locked out, got %d", code)
	}
	wantMinimal(t, "locked-out no token", healthGet(e.h, "", "10.9.9.9"))
	wantMinimal(t, "locked-out garbage token", healthGet(e.h, bearer("bad-token"), "10.9.9.9"))
	wantDetailed(t, "locked-out valid audit token", healthGet(e.h, bearer(e.auditor), "10.9.9.9"), want)
	// healthz traffic adds nothing to the lockout bookkeeping.
	rows := len(e.rows("AUTH_RATE_LIMITED"))
	for i := 0; i < 20; i++ {
		healthGet(e.h, bearer("bad-token"), "10.9.9.9")
	}
	if n := len(e.rows("AUTH_RATE_LIMITED")); n != rows {
		t.Errorf("AUTH_RATE_LIMITED rows grew from %d to %d through /healthz", rows, n)
	}
}

// An authenticated /healthz is audited like any authenticated route
// (HTTP_API, token id, method and path); an unauthenticated one is not (it
// has no caller to record, and publicRequest lets it through AuditHTTP).
func TestHealthzAuditRows(t *testing.T) {
	e := newAuthzEnv(t, false)
	healthGet(e.h, "", "10.0.0.3")
	healthGet(e.h, bearer("junk"), "10.0.0.3")
	if rows := e.rows("HTTP_API"); len(rows) != 0 {
		t.Fatalf("unauthenticated healthz wrote HTTP_API rows: %v", rows)
	}
	healthGet(e.h, bearer(e.auditor), "10.0.0.3")
	healthGet(e.h, bearer(e.alice), "10.0.0.3") // authenticated without detail: still a caller
	rows := e.rows("HTTP_API")
	if len(rows) != 2 {
		t.Fatalf("HTTP_API rows = %d, want 2: %v", len(rows), rows)
	}
	// The audit log lists the newest row first.
	for i, wantAgent := range []string{"alice", "auditor"} {
		if !strings.Contains(rows[i], "GET /healthz") || !strings.HasSuffix(rows[i], "agent="+wantAgent) {
			t.Errorf("row %d = %q", i, rows[i])
		}
	}
	if rows := e.rows("HTTP_OPERATOR"); len(rows) != 0 {
		t.Errorf("healthz wrote HTTP_OPERATOR rows: %v", rows)
	}
}

// A token-store fault is logged but never changes the /healthz answer (the
// other routes answer 500 for it).
func TestHealthzTokenStoreFaultStillMinimal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	logs := captureLog(t)
	h := NewRouter(&handlers.Handlers{}, NewStoreMiddleware(auth.OpenStore(path)))
	wantMinimal(t, "per-agent store fault", healthGet(h, bearer("whatever"), "10.0.0.4"))
	if !strings.Contains(logs.String(), "token verification unavailable on /healthz") {
		t.Errorf("store fault not logged: %q", logs.String())
	}
	if strings.Contains(logs.String(), path) {
		t.Errorf("log leaked the token store path: %q", logs.String())
	}
	// Same route table, other path: the real routes still report the fault.
	if rec := doReq(h, "GET", "/v1/secrets", bearer("whatever")); rec.Code != 500 {
		t.Errorf("/v1/secrets with a broken token store = %d, want 500", rec.Code)
	}
}

func doReq(h http.Handler, method, path, authz string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", authz)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Legacy shared-token mode: an operator-file token sees the detail; an
// agent-file token sees it only where it could read /v1/audit anyway
// (LegacyPrivilegedRoutes); junk never counts toward the limiter.
func TestHealthzLegacySharedTokens(t *testing.T) {
	for _, privileged := range []bool{false, true} {
		for _, withOperatorFile := range []bool{true, false} {
			name := map[bool]string{false: "unprivileged", true: "privileged"}[privileged]
			if !withOperatorFile {
				name += "/no-operator-file"
			}
			t.Run(name, func(t *testing.T) {
				e := newEnv(t, envOpts{})
				dir := t.TempDir()
				agentStore, agentTok := newToken(t, filepath.Join(dir, "agent.token"))
				cfg := Config{
					Vault: e.stack.Vault, AgentTokens: agentStore, LegacyPrivilegedRoutes: privileged,
					Broker: e.stack.Broker, Actions: e.stack.Actions, Capabilities: e.stack.Capabilities,
					AuthFailureLimit: 3, AuthFailureWindow: time.Minute,
				}
				var opTok string
				if withOperatorFile {
					var opStore *auth.TokenStore
					opStore, opTok = newToken(t, filepath.Join(dir, "operator.token"))
					cfg.OperatorTokens = opStore
				}
				h, err := New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				var names []string
				for _, s := range e.stack.Actions.List() {
					names = append(names, s.Name)
				}
				want := &healthWant{vaultID: e.stack.Vault.VaultID(), keyEpoch: int(e.stack.Vault.KeyEpoch()), actions: names}

				wantMinimal(t, "no token", healthGet(h, "", "10.1.1.1"))
				wantMinimal(t, "garbage", healthGet(h, bearer("garbage"), "10.1.1.1"))
				rec := healthGet(h, bearer(agentTok), "10.1.1.1")
				if privileged {
					wantDetailed(t, "agent file token (privileged)", rec, want)
				} else {
					wantMinimal(t, "agent file token (unprivileged)", rec)
				}
				if withOperatorFile {
					wantDetailed(t, "operator file token", healthGet(h, bearer(opTok), "10.1.1.1"), want)
				}
				// Junk beyond the limit of 3 never produces a 429 here...
				for i := 0; i < 10; i++ {
					wantMinimal(t, "junk", healthGet(h, bearer("garbage"), "10.1.1.1"))
				}
				// ...nor counts toward the real routes' limit.
				if rec := doReq(h, "GET", "/v1/secrets", bearer("garbage")); rec.Code != http.StatusUnauthorized {
					t.Errorf("first real failure = %d, want 401", rec.Code)
				}
			})
		}
	}
}

// Legacy tokens: an agent-file token must never be mistaken for the
// operator on the approval routes because /healthz accepts either file.
func TestHealthzLegacyFallbackDoesNotWidenOtherRoutes(t *testing.T) {
	e := newEnv(t, envOpts{operator: true})
	// The operator token is not an agent token, and vice versa, on their routes.
	if code, _, _ := e.call("GET", "/v1/secrets", e.opTok, nil); code != http.StatusUnauthorized {
		t.Errorf("operator token on an agent route = %d, want 401", code)
	}
	if code, _, _ := e.call("GET", "/v1/requests", e.agentTok, nil); code != http.StatusUnauthorized {
		t.Errorf("agent token on an operator route = %d, want 401", code)
	}
}
