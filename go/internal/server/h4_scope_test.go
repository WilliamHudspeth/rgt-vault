package server

// Batch H4 (RGT-345): the handlers authorize on their own, behind the auth
// middleware's route table. A handler reached without a principal answers
// 401 and one reached with too few scopes 403, each with an incident id.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/server/handlers"
)

func TestHandlersFailClosedWithoutPrincipalOrScope(t *testing.T) {
	e := newAuthzEnv(t, true)
	captureLog(t)
	h := &handlers.Handlers{Vault: e.stack.Vault, Actions: e.stack.Actions, Capabilities: e.stack.Capabilities, Broker: e.stack.Broker}

	type route struct {
		name   string
		fn     http.HandlerFunc
		method string
		body   string
		// scopes that are NOT enough: a principal holding only these gets 403.
		tooFew []auth.Scope
	}
	routes := []route{
		{"SetSecret", h.SetSecret, "POST", `{"name":"a","value":"b"}`, []auth.Scope{auth.ScopeAudit}},
		{"ListSecrets", h.ListSecrets, "GET", "", []auth.Scope{auth.ScopeAudit}},
		{"LeaseSecret", h.LeaseSecret, "POST", `{}`, []auth.Scope{auth.ScopeAgent}}, // agent without lease
		{"GetSecret", h.GetSecret, "GET", "", []auth.Scope{auth.ScopeAudit}},
		{"UseSecret", h.UseSecret, "POST", `{"action":"x"}`, []auth.Scope{auth.ScopeAudit}},
		{"RevokeSecret", h.RevokeSecret, "POST", "", []auth.Scope{auth.ScopeAudit}},
		{"Rotate", h.Rotate, "POST", `{"target":"dek"}`, []auth.Scope{auth.ScopeAgent, auth.ScopeAudit}},
		{"Audit", h.Audit, "GET", "", []auth.Scope{auth.ScopeAgent}},
		{"AuditVerify", h.AuditVerify, "POST", "", []auth.Scope{auth.ScopeAgent}},
		{"PolicySimulate", h.PolicySimulate, "POST", `{"namespace":"n"}`, []auth.Scope{auth.ScopeAudit}},
		{"ExecuteCapability", h.ExecuteCapability, "POST", `{"capability":"c","capability_token":"t"}`, []auth.Scope{auth.ScopeAudit}},
		{"ListCapabilities", h.ListCapabilities, "GET", "", []auth.Scope{auth.ScopeAudit}},
		{"ListAuthorizedCapabilities", h.ListAuthorizedCapabilities, "GET", "", []auth.Scope{auth.ScopeAudit}},
		{"ListActions", h.ListActions, "GET", "", []auth.Scope{auth.ScopeAudit}},
		{"ListRequests", h.ListRequests, "GET", "", []auth.Scope{auth.ScopeAgent, auth.ScopeAudit}},
		{"Approve", h.Approve, "POST", `{}`, []auth.Scope{auth.ScopeAgent, auth.ScopeAudit}},
		{"Deny", h.Deny, "POST", `{}`, []auth.Scope{auth.ScopeAgent, auth.ScopeAudit}},
	}
	for _, rt := range routes {
		call := func(ctx context.Context) *httptest.ResponseRecorder {
			var body *strings.Reader
			if rt.body != "" {
				body = strings.NewReader(rt.body)
			}
			var r *http.Request
			if body != nil {
				r = httptest.NewRequest(rt.method, "/v1/x", body)
			} else {
				r = httptest.NewRequest(rt.method, "/v1/x", nil)
			}
			rec := httptest.NewRecorder()
			rt.fn(rec, r.WithContext(ctx))
			return rec
		}
		rec := call(context.Background())
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a principal: %d, want 401 (%s)", rt.name, rec.Code, rec.Body.String())
		} else {
			errorBody(t, rt.name+" no principal", rec)
		}
		weak := handlers.WithPrincipal(context.Background(), auth.Principal{TokenID: "t", Agent: "weak", Scopes: rt.tooFew})
		rec = call(weak)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s with scopes %v: %d, want 403 (%s)", rt.name, rt.tooFew, rec.Code, rec.Body.String())
		} else {
			errorBody(t, rt.name+" too few scopes", rec)
		}
	}
}

// AuditHTTP no longer waves a request through when the auth middleware did
// not set a principal; the public routes still pass.
func TestAuditHTTPDeniesWithoutPrincipal(t *testing.T) {
	e := newAuthzEnv(t, false)
	captureLog(t)
	h := &handlers.Handlers{Vault: e.stack.Vault}
	reached := false
	next := h.AuditHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/actions", nil))
	if reached || rec.Code != http.StatusUnauthorized {
		t.Fatalf("no principal: reached=%v status=%d", reached, rec.Code)
	}
	errorBody(t, "AuditHTTP", rec)

	for _, p := range []string{"/healthz", "/crossdomain.xml", "/clientaccesspolicy.xml"} {
		reached = false
		next.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", p, nil))
		if !reached {
			t.Errorf("public route %s blocked", p)
		}
	}
	// Not public: same path with another verb, or a look-alike.
	for _, rq := range []*http.Request{httptest.NewRequest("POST", "/healthz", nil), httptest.NewRequest("GET", "/healthz/x", nil)} {
		reached = false
		next.ServeHTTP(httptest.NewRecorder(), rq)
		if reached {
			t.Errorf("%s %s reached the handler without a principal", rq.Method, rq.URL.Path)
		}
	}
}

// An operator may deny with a multi-line reason; other control
// characters are still refused (RGT-357). Operator names follow the agent-id
// allow-list.
func TestDenyReasonAllowsLineBreaksOnly(t *testing.T) {
	e := newAuthzEnv(t, true)
	for body, wantValidation := range map[string]bool{
		`{"reason":"too broad\nask again\twith a narrower scope"}`: false,
		`{"reason":"bad\u0001char"}`:                               true,
		`{"reason":"ok","operator":"Alice Smith"}`:                 true,
		`{"reason":"ok","operator":""}`:                            true,
		`{"reason":"ok","operator":"approver"}`:                    false,
	} {
		code, out, _ := e.do("POST", "/v1/requests/nope/deny", e.opOnly, body)
		isValidation := code == http.StatusBadRequest && strings.Contains(out, `"ValidationError"`)
		if isValidation != wantValidation {
			t.Errorf("%s: %d %s (validation error wanted=%v)", body, code, out, wantValidation)
		}
	}
}
