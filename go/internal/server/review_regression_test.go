package server

// Regression tests from the independent security review of PR #53 (batch
// H1): adversarial route x token matrix, path tricks, the fingerprint IDOR /
// existence oracle (MEDIUM-1), audit-log injection (L1), the limiter's
// X-Forwarded-For handling, and legacy-mode privileged routes (MEDIUM-3).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/server/handlers"
)

type rt struct{ method, path, body string }

// need: which tokens must be allowed past the scope gate (not 401, not
// "insufficient scope"). Every other token must be refused at the gate.
func TestReviewRouteTokenMatrix(t *testing.T) {
	e := newAuthzEnv(t, false)
	expired, _, _ := e.store.Mint(auth.MintOptions{Agent: "alice", Scopes: []auth.Scope{auth.ScopeAgent, auth.ScopeOperator}, TTL: time.Second})
	revoked, info, _ := e.store.Mint(auth.MintOptions{Agent: "alice", Scopes: []auth.Scope{auth.ScopeAgent, auth.ScopeOperator}})
	if _, err := e.store.Revoke(info.ID); err != nil {
		t.Fatal(err)
	}
	e.advance(5 * time.Second)

	tokens := map[string]string{
		"none": "", "garbage": "Zm9vYmFy", "expired": expired, "revoked": revoked,
		"agent": e.alice, "agent+lease": e.aliceLease, "audit": e.auditor, "operator": e.operator, "opOnly": e.opOnly,
	}
	// allowed[route] = set of token names that pass the gate
	type row struct {
		r       rt
		allowed []string
	}
	rows := []row{
		{rt{"GET", "/v1/secrets?namespace=alice-ns", ""}, []string{"agent", "agent+lease", "operator"}},
		{rt{"POST", "/v1/secrets", `{"name":"x","namespace":"alice-ns","value":"v"}`}, []string{"agent", "agent+lease", "operator"}},
		{rt{"GET", "/v1/secrets/alice-ns/k", ""}, []string{"agent", "agent+lease", "operator"}},
		{rt{"POST", "/v1/secrets/alice-ns/k/use", `{"action":"echo","purpose":"p"}`}, []string{"agent", "agent+lease", "operator"}},
		{rt{"POST", "/v1/secrets/alice-ns/k/revoke", ""}, []string{"agent", "agent+lease", "operator"}},
		{rt{"POST", "/v1/secrets/alice-ns/k/lease", `{}`}, []string{"agent+lease", "operator"}},
		{rt{"POST", "/v1/policy/simulate", `{"namespace":"alice-ns"}`}, []string{"agent", "agent+lease", "operator"}},
		{rt{"GET", "/v1/capabilities", ""}, []string{"agent", "agent+lease", "operator"}},
		{rt{"GET", "/v1/capabilities/list", ""}, []string{"agent", "agent+lease", "operator"}},
		{rt{"GET", "/v1/actions", ""}, []string{"agent", "agent+lease", "operator"}},
		{rt{"POST", "/v1/capabilities/execute", `{"capability":"x","capability_token":"y"}`}, []string{"agent", "agent+lease", "operator"}},
		{rt{"POST", "/v1/rotate", `{"target":"dek"}`}, []string{"operator", "opOnly"}},
		{rt{"GET", "/v1/requests", ""}, []string{"operator", "opOnly"}},
		{rt{"POST", "/v1/requests/x/approve", `{}`}, []string{"operator", "opOnly"}},
		{rt{"POST", "/v1/requests/x/deny", `{}`}, []string{"operator", "opOnly"}},
		{rt{"GET", "/v1/audit", ""}, []string{"audit", "operator", "opOnly"}},
		{rt{"POST", "/v1/audit/verify", ""}, []string{"audit", "operator", "opOnly"}},
	}
	in := func(l []string, s string) bool {
		for _, x := range l {
			if x == s {
				return true
			}
		}
		return false
	}
	for _, rw := range rows {
		for name, tok := range tokens {
			code, body, _ := e.do(rw.r.method, rw.r.path, tok, nilIfEmpty(rw.r.body))
			gate := code == 401 || (code == 403 && strings.Contains(body, "insufficient scope")) || code == 429
			if in(rw.allowed, name) == gate {
				t.Errorf("%s %s as %s: %d %s (allowed=%v)", rw.r.method, rw.r.path, name, code, strings.TrimSpace(body), in(rw.allowed, name))
			}
		}
	}
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Path / method tricks against operator-only and audit-only routes with an
// agent-only token: nothing may reach the handler (2xx) and nothing may be
// answered by the operator handler.
func TestReviewPathTricks(t *testing.T) {
	e := newAuthzEnv(t, false)
	paths := []string{
		"/v1/rotate/", "/v1/Rotate", "/v1/ROTATE", "/v1/%72otate", "/v1/rotate%2F", "/v1/rotate%00", "/v1/./rotate",
		"/v1/rotate;x=1", "/v1/rotate?x=1", "//v1/rotate", "/v1//rotate", "/v1/%2e%2e/v1/rotate", "/v1/rotate%20",
		"/v1/audit/", "/v1/AUDIT", "/v1/audit%2Fverify", "/v1/audit/verify/", "/v1/%61udit", "/v1/audit;x",
		"/v1/requests/", "/v1/Requests", "/v1/%72equests", "/v1/requests%2Fx%2Fapprove", "/v1/requests/x/approve/",
		"/v1/requests/x%2Fapprove", "/v1/requests/%2e/approve", "/v1/requests/x/APPROVE",
		"/v1/secrets/../rotate", "/v1/secrets/%2e%2e/rotate", "/v1/secrets/ns/k/%6cease", "/v1/secrets/ns/k/lease/",
		"/v1/secrets/ns/k/LEASE", "/v1/secrets/ns%2Fk/lease", "/v1/secrets/ns/k%2Flease", "/v1/secrets/ns/k/lease%2F",
		"/V1/rotate", "/v1/secrets/lease/lease", "/v1/secrets/a/lease/lease",
	}
	for _, p := range paths {
		for _, m := range []string{"GET", "POST", "OPTIONS", "HEAD", "PUT", "DELETE", "TRACE", "PATCH"} {
			var req *http.Request
			func() {
				defer func() { _ = recover() }()
				req = httptest.NewRequest(m, p, strings.NewReader(`{}`))
			}()
			if req == nil {
				continue
			}
			req.RemoteAddr = "127.0.0.1:1"
			req.Header.Set("Authorization", "Bearer "+e.alice)
			rec := httptest.NewRecorder()
			e.h.ServeHTTP(rec, req)
			body := rec.Body.String()
			opHandlers := strings.Contains(body, `"rows"`) || strings.Contains(body, `"requests"`) || strings.Contains(body, "key_epoch") || strings.Contains(body, "rotated") || strings.Contains(body, "chain")
			if rec.Code/100 == 2 || opHandlers {
				t.Errorf("%s %s with an agent-only token: %d %s", m, p, rec.Code, body)
			}
			if testing.Verbose() && m == "GET" {
				t.Logf("%-7s %-34s %d", m, p, rec.Code)
			}
		}
	}
}

// RGT-346 / review MEDIUM-1: the fingerprint route is ABAC-gated and gives
// ONE answer for "not yours", "does not exist", another agent's versions and
// an unknown namespace, so it is no existence or version oracle.
func TestReviewFingerprintCrossAgent(t *testing.T) {
	e := newAuthzEnv(t, false)
	strip := func(body string) string { // incident ids differ per request
		var m map[string]any
		_ = json.Unmarshal([]byte(body), &m)
		delete(m, "incident_id")
		b, _ := json.Marshal(m)
		return string(b)
	}
	var first string
	for _, p := range []string{"/v1/secrets/bob-ns/k", "/v1/secrets/bob-ns/k?version=1", "/v1/secrets/bob-ns/does-not-exist",
		"/v1/secrets/nonexistent-ns/k", "/v1/secrets/alice-ns/does-not-exist", "/v1/secrets/alice-ns/k?version=9",
		"/v1/secrets/bob-ns/k?agent=alice"} {
		code, body, _ := e.do("GET", p, e.alice, nil)
		if code != 404 || strings.Contains(body, "fingerprint") {
			t.Errorf("alice GET %s: %d %s", p, code, body)
		}
		if first == "" {
			first = strip(body)
		} else if strip(body) != first {
			t.Errorf("GET %s answers differently (%s vs %s): an oracle", p, strip(body), first)
		}
	}
	// Naming bob is the usual spoof refusal.
	if code, _, _ := e.do("GET", "/v1/secrets/bob-ns/k?agent=bob", e.alice, nil); code != 403 {
		t.Errorf("?agent=bob: %d", code)
	}
	// Bob reads his own; alice hers.
	if code, body, _ := e.do("GET", "/v1/secrets/bob-ns/k", e.bob, nil); code != 200 || !strings.Contains(body, "fingerprint") {
		t.Errorf("bob own fingerprint: %d %s", code, body)
	}
	if code, _, _ := e.do("GET", "/v1/secrets/alice-ns/k?version=1", e.alice, nil); code != 200 {
		t.Errorf("alice own version 1: %d", code)
	}
	// Denials are audited.
	found := false
	for _, r := range e.rows(handlers.EventAuthzDenied) {
		if strings.Contains(r, "policy denies fingerprint of bob-ns/k") && strings.Contains(r, "agent=alice") {
			found = true
		}
	}
	if !found {
		t.Error("fingerprint denial not audited")
	}
}

// Audit log injection (review L1): request-derived path text is recorded
// percent-encoded, so it can neither add fields (" reason=", " token=") nor
// split lines (CR, LF, U+0085, U+2028).
func TestReviewAuditInjection(t *testing.T) {
	e := newAuthzEnv(t, false)
	for _, p := range []string{
		"/v1/x%20reason=expired%20token=tok_0123456789abcdef",
		"/v1/x%C2%85FAKE-ROW",
		"/v1/x%E2%80%A8FAKE-ROW",
		"/v1/x%0d%0aFAKE-ROW",
	} {
		req := httptest.NewRequest("GET", p, nil)
		req.RemoteAddr = "10.0.0.9:1"
		req.Header.Set("Authorization", "Bearer nope")
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
	}
	// Authenticated rows too (HTTP_API, AUTHZ_DENIED).
	e.do("GET", "/v1/x%20reason=forged", e.alice, nil)
	e.do("GET", "/v1/audit%20reason=forged", e.alice, nil)
	all, err := e.stack.Vault.AuditLog(context.Background(), -1)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range all {
		d := r.Details.String
		if strings.Count(d, " reason=") > 1 || strings.Count(d, " token=") > 1 || strings.Contains(d, " token=tok_0123456789abcdef") ||
			strings.ContainsAny(d, "\r\n\u0085\u2028") || strings.Contains(d, " reason=forged") {
			t.Errorf("%s row forged by the path: %q", r.Action, d)
		}
	}
	if !strings.Contains(e.allAudit(), "/v1/x%20reason=expired%20token=tok_0123456789abcdef") {
		t.Error("the encoded path is not recorded (investigation metadata lost)")
	}
}

// Rate limiter: X-Forwarded-For is ignored (good); RemoteAddr is the key.
func TestReviewLimiterXFF(t *testing.T) {
	e := newAuthzEnv(t, false)
	var last int
	for i := 0; i < 8; i++ {
		req := httptest.NewRequest("GET", "/v1/actions", nil)
		req.RemoteAddr = "127.0.0.1:1"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("1.2.3.%d", i))
		req.Header.Set("Authorization", "Bearer nope")
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		last = rec.Code
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("XFF rotation evaded the limiter: last=%d", last)
	}
	// A valid token from the same address still works while limited.
	if code, _, _ := e.do("GET", "/v1/actions", e.alice, nil); code != 200 {
		t.Errorf("valid token from a limited source: %d", code)
	}
}

// Legacy mode (review MEDIUM-3): the shared token cannot reach the lease
// route, rotation or the audit log unless LegacyPrivilegedRoutes; refusals
// are audited.
func TestLegacyPrivilegedRoutesRefused(t *testing.T) {
	for _, privileged := range []bool{false, true} {
		e := newEnv(t, envOpts{})
		e.set("ns", "k", "LEGACY-VALUE", nil)
		h, err := New(Config{
			Vault: e.stack.Vault, AgentTokens: auth.NewTokenStore(filepath.Join(e.dir, "agent.token")),
			LegacyPrivilegedRoutes: privileged, Actions: e.stack.Actions, Capabilities: e.stack.Capabilities,
		})
		if err != nil {
			t.Fatal(err)
		}
		e.h = h
		for _, c := range []struct {
			method, path string
			body         any
		}{
			{"POST", "/v1/secrets/ns/k/lease", map[string]any{"agent": "bot"}},
			{"POST", "/v1/rotate", map[string]any{"target": "dek"}},
			{"GET", "/v1/audit", nil},
			{"POST", "/v1/audit/verify", nil},
		} {
			code, m, rec := e.call(c.method, c.path, e.agentTok, c.body)
			refused := code == 403 && strings.Contains(fmt.Sprint(m["detail"]), "legacy shared-token mode")
			if refused == privileged || (!privileged && strings.Contains(rec.Body.String(), "LEGACY-VALUE")) {
				t.Errorf("privileged=%v %s %s: %d %v", privileged, c.method, c.path, code, m)
			}
		}
		if code, _, _ := e.call("GET", "/v1/actions", e.agentTok, nil); code != 200 {
			t.Errorf("legacy agent route: %d", code)
		}
	}
	if _, err := New(Config{Vault: newAuthzEnv(t, false).stack.Vault, Tokens: auth.OpenStore(filepath.Join(t.TempDir(), "s")), LegacyPrivilegedRoutes: true}); err == nil {
		t.Error("LegacyPrivilegedRoutes with the per-agent store accepted")
	}
}
