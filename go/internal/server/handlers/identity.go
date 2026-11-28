package handlers

import (
	"context"
	"database/sql"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/validation"
)

// Identity (batch H1).
//
// The auth middleware authenticates every /v1 request and stores the caller
// (an auth.Principal) in the request context. With the per-agent token store
// the ABAC subject is the token's agent_id: a request that names a different
// agent (body "agent"/"agent_id"/"operator" or query ?agent=) is refused with
// 403 and an AUTHZ_DENIED audit row, so one agent's token can never act as
// another agent (IDOR). Only with the deprecated --legacy-shared-token mode
// is the self-asserted field still the subject, as in Python.

// Audit event names written by the identity layer.
const (
	// EventAuthFailed: a request without valid credentials (401).
	EventAuthFailed = "AUTH_FAILED"
	// EventAuthRateLimited: further failures from the same source in the
	// same window are answered 429 and summarised by one row.
	EventAuthRateLimited = "AUTH_RATE_LIMITED"
	// EventAuthzDenied: an authenticated request refused for its scope or
	// for naming another agent (403).
	EventAuthzDenied = "AUTHZ_DENIED"
)

type principalKey struct{}

// WithPrincipal returns ctx carrying the authenticated caller.
func WithPrincipal(ctx context.Context, p auth.Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFromContext returns the caller stored by WithPrincipal.
func PrincipalFromContext(ctx context.Context) (auth.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(auth.Principal)
	return p, ok
}

// AuditPath is the request path as it may appear in an audit row or log:
// percent-encoded (url.URL.EscapedPath), so a client cannot forge fields
// with spaces ("%20reason=expired") or split lines with CR/LF, U+0085 or
// U+2028: those are always escaped there. Never write r.URL.Path (the
// DECODED path) into audit details.
func AuditPath(r *http.Request) string { return r.URL.EscapedPath() }

// RoutePath is the path the router (chi) matches: r.URL.RawPath when set,
// else r.URL.Path. Route-dependent decisions classify this string.
func RoutePath(r *http.Request) string {
	if r.URL.RawPath != "" {
		return r.URL.RawPath
	}
	return r.URL.Path
}

// ClientIP is the request's peer address without the port ("?" if unknown).
func ClientIP(r *http.Request) string {
	client, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || client == "" {
		return "?"
	}
	return client
}

// safeAgentLabel returns a for an audit row if it is a valid agent id, else
// a fixed placeholder (the claimed value is attacker-controlled).
func safeAgentLabel(a string) string {
	if v, err := validation.ValidateAgent(a); err == nil {
		return v
	}
	return "<invalid>"
}

// AuditDenied writes an AUTHZ_DENIED row: who (token id + agent), from where,
// what (method, path) and why. It never records a token or a secret value.
func (h *Handlers) AuditDenied(r *http.Request, p auth.Principal, reason string) {
	if h.Vault == nil {
		return
	}
	details := "token=" + p.TokenID + " ip=" + ClientIP(r) + " " + r.Method + " " + AuditPath(r) + " reason=" + reason
	agent := sql.NullString{}
	if p.Agent != "" {
		agent = sql.NullString{String: p.Agent, Valid: true}
	}
	if err := h.Vault.Audit(r.Context(), EventAuthzDenied, sql.NullString{}, details, agent); err != nil {
		log.Printf("ERROR: writing %s audit row: %s", EventAuthzDenied, LogSafe(err.Error()))
	}
}

var errAgentMismatch = newAppError(http.StatusForbidden, "AuthorizationError", "agent does not match the authenticated token")

// subject resolves the ABAC subject of a request.
//
//   - legacy shared token: the claimed value, else def (Python's behaviour);
//   - per-agent token: the token's agent. A claimed value that differs is
//     refused (403 + AUTHZ_DENIED). With allowOperator, a token carrying
//     the operator scope may name another agent (read-only policy queries).
//
// A request with no principal in its context (a handler called without the
// auth middleware) is refused: fail closed.
func (h *Handlers) subject(w http.ResponseWriter, r *http.Request, claimed *string, def string, allowOperator bool) (string, bool) {
	p, ok := PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, r, newAppError(http.StatusUnauthorized, "ServerAuthError", "invalid credentials"))
		return "", false
	}
	if p.Legacy {
		if claimed != nil {
			return *claimed, true
		}
		return def, true
	}
	if claimed == nil || *claimed == p.Agent {
		return p.Agent, true
	}
	if allowOperator && p.Has(auth.ScopeOperator) {
		return *claimed, true
	}
	h.AuditDenied(r, p, "agent mismatch (claimed "+safeAgentLabel(*claimed)+")")
	writeError(w, r, errAgentMismatch)
	return "", false
}

// querySubject is subject for an optional query parameter.
func (h *Handlers) querySubject(w http.ResponseWriter, r *http.Request, name, def string, allowOperator bool) (string, bool) {
	if v, ok := r.URL.Query()[name]; ok && len(v) > 0 {
		return h.subject(w, r, &v[0], def, allowOperator)
	}
	return h.subject(w, r, nil, def, allowOperator)
}

// isOperatorRoute reports whether path is an approval endpoint.
func isOperatorRoute(path string) bool {
	return path == "/v1/requests" || strings.HasPrefix(path, "/v1/requests/")
}

// AuditAuthFailure writes an AUTH_FAILED / AUTH_RATE_LIMITED row (the auth
// middleware's AuthAuditor). details never contain a token: at most the
// short id auth.PresentedID or a store record id.
func (h *Handlers) AuditAuthFailure(r *http.Request, event, details string) {
	if h.Vault == nil {
		return
	}
	if err := h.Vault.Audit(r.Context(), event, sql.NullString{}, details, sql.NullString{}); err != nil {
		log.Printf("ERROR: writing %s audit row: %s", event, LogSafe(err.Error()))
	}
}
