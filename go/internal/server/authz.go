package server

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"rgt-vault-server/internal/auth"
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

// routeRequirement returns the scopes path needs. The path has already
// passed PathMiddleware (no "..", "//" or backslashes).
func routeRequirement(path string) requirement {
	switch {
	case operatorPath(path), path == "/v1/rotate":
		return reqOperator
	case path == "/v1/audit", path == "/v1/audit/verify":
		return reqAudit
	case strings.HasPrefix(path, "/v1/secrets/") && strings.HasSuffix(path, "/lease"):
		return reqLease
	default:
		return reqAgent
	}
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
func (l *failureLimiter) failure(source string) (limited, report bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	fw, ok := l.sources[source]
	if !ok || now.Sub(fw.start) >= l.window {
		if !ok && len(l.sources) >= maxTrackedSources {
			l.prune(now)
			if len(l.sources) >= maxTrackedSources {
				// Table full of live windows: treat the newcomer as limited
				// (no audit row) rather than grow without bound.
				return true, false
			}
		}
		fw = &failureWindow{start: now}
		l.sources[source] = fw
	}
	fw.count++
	if fw.count <= l.limit {
		return false, false
	}
	if !fw.reported {
		fw.reported = true
		return true, true
	}
	return true, false
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
