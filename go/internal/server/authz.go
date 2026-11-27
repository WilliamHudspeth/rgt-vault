package server

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/server/handlers"
)

// Route authorization (batch H1). Every authenticated route requires a
// scope; the table is the single place access is decided (ASVS 1.4.4 /
// 4.1.3), before any handler runs. Handlers then derive the ABAC subject
// from the token (handlers/identity.go) and the vault applies ABAC.
//
//	/v1/requests*                   operator          approve / deny / list pending
//	/v1/rotate                      operator          master / DEK rotation
//	/v1/audit, /v1/audit/verify     audit or operator read / verify the audit log
//	/v1/secrets/{ns}/{name}/lease   agent AND lease   plaintext read (RGT-504)
//	every other path                agent             secrets, simulate, capabilities, actions
//
// There is no policy-changing endpoint: the policy is a file read at
// startup, changed by whoever can write it (the operator), not over HTTP.

// requirement is the scope set a route needs: all of allOf, plus at least
// one of anyOf when anyOf is non-empty.
type requirement struct {
	allOf []auth.Scope
	anyOf []auth.Scope
	name  string
}

func (q requirement) satisfiedBy(p auth.Principal) bool {
	for _, s := range q.allOf {
		if !p.Has(s) {
			return false
		}
	}
	if len(q.anyOf) == 0 {
		return true
	}
	for _, s := range q.anyOf {
		if p.Has(s) {
			return true
		}
	}
	return false
}

var (
	reqOperator = requirement{allOf: []auth.Scope{auth.ScopeOperator}, name: "operator"}
	reqAudit    = requirement{anyOf: []auth.Scope{auth.ScopeAudit, auth.ScopeOperator}, name: "audit"}
	reqLease    = requirement{allOf: []auth.Scope{auth.ScopeAgent, auth.ScopeLease}, name: "agent+lease"}
	reqAgent    = requirement{allOf: []auth.Scope{auth.ScopeAgent}, name: "agent"}
)

// routePath is the path the router matches: chi routes on r.URL.RawPath
// when it is set (the request used escapes such as %2F) and on r.URL.Path
// otherwise. Authorization MUST classify the same string, or a request
// could reach a handler under a different route's requirement (e.g. an
// encoded "/" in a secret name changing the segment count).
func routePath(r *http.Request) string { return handlers.RoutePath(r) }

// isLeaseRoute reports whether method + path is exactly
// POST /v1/secrets/{namespace}/{name}/lease: six "/"-separated parts
// (leading empty one included) with non-empty namespace and name. A secret
// or namespace merely NAMED "lease" (GET /v1/secrets/{ns}/lease, the
// fingerprint route) is not the lease route.
func isLeaseRoute(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	seg := strings.Split(path, "/")
	return len(seg) == 6 && seg[0] == "" && seg[1] == "v1" && seg[2] == "secrets" &&
		seg[3] != "" && seg[4] != "" && seg[5] == "lease"
}

// routeRequirement returns the scopes a request needs, classified on the
// router's own path (routePath) by method and exact segments. The path has
// already passed PathMiddleware (no "..", "//" or backslashes).
func routeRequirement(r *http.Request) requirement {
	path := routePath(r)
	switch {
	case operatorPath(path), path == "/v1/rotate":
		return reqOperator
	case path == "/v1/audit", path == "/v1/audit/verify":
		return reqAudit
	case isLeaseRoute(r.Method, path):
		return reqLease
	default:
		return reqAgent
	}
}

// legacyPrivileged reports whether a legacy shared-token request targets a
// route that the shared token reaches only with LegacyPrivilegedRoutes: the
// plaintext lease, key rotation and the audit log (review of PR #53,
// MEDIUM-3). /v1/requests* keeps its legacy operator-file rule.
func legacyPrivileged(r *http.Request) bool {
	path := routePath(r)
	return path == "/v1/rotate" || path == "/v1/audit" || path == "/v1/audit/verify" || isLeaseRoute(r.Method, path)
}

// Defaults of the per-source authentication-failure limiter.
const (
	DefaultAuthFailureLimit  = 10
	DefaultAuthFailureWindow = time.Minute
	maxTrackedSources        = 4096
)

// failureLimiter counts failed authentications per source address. It only
// ever affects requests WITHOUT valid credentials, so one misbehaving local
// client (all of them share 127.0.0.1) cannot lock out the others: a valid
// token is always served.
type failureLimiter struct {
	limit  int
	window time.Duration
	now    func() time.Time

	mu      sync.Mutex
	sources map[string]*failureWindow
	// fullSince is when a "table full" summary row was last reported.
	fullSince time.Time
}

type failureWindow struct {
	start    time.Time
	count    int
	reported bool // the AUTH_RATE_LIMITED row for this window was written
}

func newFailureLimiter(limit int, window time.Duration) *failureLimiter {
	if limit <= 0 {
		limit = DefaultAuthFailureLimit
	}
	if window <= 0 {
		window = DefaultAuthFailureWindow
	}
	return &failureLimiter{limit: limit, window: window, now: time.Now, sources: map[string]*failureWindow{}}
}

// failure records one failed attempt from source. It returns limited when
// the source is over the limit in the current window, and report when this
// is the first over-limit attempt of the window (write one summary row).
// When the source table is full of live windows, newcomers are limited and
// one summary row per window is reported for all of them (full = true).
func (l *failureLimiter) failure(source string) (limited, report, full bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	fw, ok := l.sources[source]
	if !ok || now.Sub(fw.start) >= l.window {
		if !ok && len(l.sources) >= maxTrackedSources {
			l.prune(now)
			if len(l.sources) >= maxTrackedSources {
				// Table full of live windows: treat the newcomer as limited
				// rather than grow without bound; one summary row per window
				// so the flood is still visible in the audit log.
				if l.fullSince.IsZero() || now.Sub(l.fullSince) >= l.window {
					l.fullSince = now
					return true, true, true
				}
				return true, false, true
			}
		}
		fw = &failureWindow{start: now}
		l.sources[source] = fw
	}
	fw.count++
	if fw.count <= l.limit {
		return false, false, false
	}
	if !fw.reported {
		fw.reported = true
		return true, true, false
	}
	return true, false, false
}

func (l *failureLimiter) prune(now time.Time) {
	for k, fw := range l.sources {
		if now.Sub(fw.start) >= l.window {
			delete(l.sources, k)
		}
	}
}

// writeAuthError answers 401 with the generic message.
func writeUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="rgt-vault"`)
	WriteJSONError(w, http.StatusUnauthorized, "ServerAuthError", msg)
}
