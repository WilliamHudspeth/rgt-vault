// Package server provides HTTP middleware for the rgt-vault server.
//
// Middleware stack (outermost first):
//  1. Security headers
//  2. Request logging (method, path, status, duration; never the query or any header)
//  3. Recover - a panic becomes a generic 500 with an incident id (inside the
//     logger so the 500 is logged)
//  4. CORS - deny by default, exact-match allow-list, preflight answered only
//     for allowed origins
//  5. Method allow-list - unknown verbs and TRACE get 405 before authentication
//  6. Strict path check - "..", "//", "\\" and control characters get 400
//  7. Bearer token authentication (skipped for the XML policy stubs; optional
//     for /healthz, see AuthMiddleware) against the per-agent token store, then the route's scope
//     (authz.go). Failures are audited (AUTH_FAILED / AUTHZ_DENIED) and
//     repeated failures from one source are rate-limited (429). With the
//     deprecated legacy shared token, /v1/requests* takes the operator token
//     file and everything else the agent token file, as before H1.
//  8. Request body size limit (413)
package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/server/handlers"
)

// DefaultMaxBodyBytes is the default request-body limit (1 MiB).
const DefaultMaxBodyBytes int64 = 1 << 20

// allowedMethods is the complete verb allow-list (Python's). OPTIONS is only
// ever served as a CORS preflight to an allowed origin; elsewhere it falls
// through to authentication and the router. TRACE, CONNECT, PUT, PATCH,
// DELETE, HEAD and unknown verbs are refused with 405. (The Go-only DELETE
// route of the stub store was dropped with it, decision D5: revoke is
// POST .../revoke.)
var allowedMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodPost:    true,
	http.MethodOptions: true,
}

const allowHeaderValue = "GET, POST, OPTIONS"

// AuthAuditor receives the audit events of the auth middleware.
// *handlers.Handlers implements it.
type AuthAuditor interface {
	// AuditAuthFailure records a failed authentication (never the token).
	AuditAuthFailure(r *http.Request, event, details string)
	// AuditDenied records an authenticated request refused for its scope.
	AuditDenied(r *http.Request, p auth.Principal, reason string)
}

// Middleware holds the server middleware components.
type Middleware struct {
	// Tokens is the per-agent token store (the default since H1). When set,
	// TokenStore and OperatorTokenStore are ignored.
	Tokens *auth.Store

	// TokenStore holds the DEPRECATED legacy shared agent bearer token
	// (--legacy-shared-token). Used only when Tokens is nil.
	TokenStore *auth.TokenStore

	// OperatorTokenStore holds the legacy operator token required by the
	// approval endpoints (/v1/requests*) in legacy mode. Nil means those
	// endpoints accept the agent token, as Python does without
	// --operator-token-file: an agent holding it could then approve its own
	// requests.
	OperatorTokenStore *auth.TokenStore

	// LegacyPrivilegedRoutes lets the legacy shared token reach the lease
	// route, /v1/rotate and the audit log, as before H1. Off by default:
	// legacy mode then refuses them (403) and the operator uses the offline
	// commands (get --offline, verify-audit --offline).
	LegacyPrivilegedRoutes bool

	// Auditor receives AUTH_FAILED / AUTH_RATE_LIMITED / AUTHZ_DENIED rows.
	// Nil: not audited (tests of the bare middleware).
	Auditor AuthAuditor

	failures     *failureLimiter
	failuresOnce sync.Once

	// AllowedOrigins is the exact-match CORS allow-list. Empty means CORS is
	// denied for every origin (the default). "*" is never honoured.
	AllowedOrigins []string

	// MaxBodyBytes caps request bodies; <= 0 selects DefaultMaxBodyBytes.
	MaxBodyBytes int64
}

// NewMiddleware creates a legacy shared-token Middleware with CORS denied and
// the default body limit. Use NewStoreMiddleware for per-agent tokens.
func NewMiddleware(tokenStore *auth.TokenStore) *Middleware {
	return &Middleware{TokenStore: tokenStore, MaxBodyBytes: DefaultMaxBodyBytes}
}

// NewStoreMiddleware creates a Middleware authenticating against the
// per-agent token store.
func NewStoreMiddleware(tokens *auth.Store) *Middleware {
	return &Middleware{Tokens: tokens, MaxBodyBytes: DefaultMaxBodyBytes}
}

// SetAuthFailureLimit configures the per-source failed-authentication
// limiter (<= 0 keeps the defaults). Call before serving.
func (mw *Middleware) SetAuthFailureLimit(limit int, window time.Duration) {
	mw.failures = newFailureLimiter(limit, window)
}

func (mw *Middleware) limiter() *failureLimiter {
	mw.failuresOnce.Do(func() {
		if mw.failures == nil {
			mw.failures = newFailureLimiter(0, 0)
		}
	})
	return mw.failures
}

// ParseAllowedOrigins turns a comma-separated list into an allow-list. Blank
// entries and "*" are dropped (a wildcard is not accepted; list origins
// explicitly). The second return value lists the rejected entries so callers
// can warn about them.
func ParseAllowedOrigins(csv string) (origins, rejected []string) {
	for _, part := range strings.Split(csv, ",") {
		p := strings.TrimSpace(part)
		switch {
		case p == "":
		case p == "*" || strings.EqualFold(p, "null") || strings.Contains(p, "*"):
			rejected = append(rejected, p)
		default:
			origins = append(origins, p)
		}
	}
	return origins, rejected
}

func (mw *Middleware) maxBody() int64 {
	if mw.MaxBodyBytes > 0 {
		return mw.MaxBodyBytes
	}
	return DefaultMaxBodyBytes
}

// matchOrigin returns the allow-list entry equal to origin, or "". The value
// returned is the configured entry, never the request header itself.
func (mw *Middleware) matchOrigin(origin string) string {
	if origin == "" {
		return ""
	}
	for _, allowed := range mw.AllowedOrigins {
		if allowed == origin {
			return allowed
		}
	}
	return ""
}

// WriteJSONError writes the standard error envelope {"error", "detail",
// "incident_id"} (handlers.ErrorBody) with a fresh incident id and logs one
// line with the same id. Every error the middleware answers (400, 401, 403,
// 404, 405, 413, 429, 500) goes through it, so no error response lacks an id
// (RGT-418/419). It returns the id.
func WriteJSONError(w http.ResponseWriter, r *http.Request, status int, errType, detail string) string {
	return handlers.WriteAppError(w, r, status, errType, detail)
}

// RecoverMiddleware converts a handler panic into a generic 500 carrying an
// incident id. The panic value and stack go to the server log only; the
// client never sees them.
func (mw *Middleware) RecoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			id := handlers.NewIncidentID()
			committed := false
			if rw, ok := w.(*responseWriter); ok {
				committed = rw.wrote
			}
			// Log the panic's type, not its value: the value may embed request
			// data. The stack is enough to locate the fault.
			log.Printf("PANIC incident=%s method=%s path=%s panic_type=%T\n%s",
				id, handlers.LogSafe(r.Method), handlers.LogSafe(r.URL.Path), rec, debug.Stack())
			if committed {
				// Headers already sent: appending a JSON body would corrupt
				// the response. Abort the connection instead.
				panic(http.ErrAbortHandler)
			}
			handlers.WriteErrorWithID(w, id, http.StatusInternalServerError, "InternalError", "internal server error")
		}()
		next.ServeHTTP(w, r)
	})
}

// MethodMiddleware returns 405 for every verb outside the allow-list, before
// authentication, so TRACE and friends are never reachable.
func (mw *Middleware) MethodMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowedMethods[r.Method] {
			w.Header().Set("Allow", allowHeaderValue)
			WriteJSONError(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "method not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CORSMiddleware implements deny-by-default CORS.
//
//   - No allow-list configured: no CORS header is ever emitted.
//   - An origin is accepted only on an exact match with a configured entry;
//     the configured entry (not the request header) is what is echoed back.
//   - A preflight (OPTIONS + Origin + Access-Control-Request-Method) from an
//     allowed origin is answered here with 204, before authentication
//     because browsers cannot attach credentials to preflights. Every other
//     OPTIONS request falls through to authentication and the router.
func (mw *Middleware) CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(mw.AllowedOrigins) > 0 {
			w.Header().Add("Vary", "Origin")
		}
		origin := mw.matchOrigin(r.Header.Get("Origin"))

		if origin != "" {
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				reqMethod := r.Header.Get("Access-Control-Request-Method")
				if !allowedMethods[reqMethod] || reqMethod == http.MethodOptions {
					// Allowed origin, but asking for a verb we do not serve.
					w.Header().Set("Allow", allowHeaderValue)
					WriteJSONError(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "method not allowed")
					return
				}
				h := w.Header()
				h.Add("Vary", "Access-Control-Request-Method")
				h.Add("Vary", "Access-Control-Request-Headers")
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Methods", "GET, POST")
				h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				h.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		next.ServeHTTP(w, r)
	})
}

// SecurityHeadersMiddleware strips sensitive headers and adds standard secure headers.
func (mw *Middleware) SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Del("Server")
		w.Header().Del("X-Powered-By")

		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")

		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware logs each request with method, path, status, and duration.
// Query strings and headers are deliberately not logged.
func (mw *Middleware) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		log.Printf("HTTP %s %s -> %d (%s)",
			handlers.LogSafe(r.Method), handlers.LogSafe(r.URL.Path), wrapped.statusCode, duration.Round(time.Microsecond))
	})
}

// BodyLimitMiddleware caps request bodies with http.MaxBytesReader. A declared
// Content-Length over the limit is refused with 413 immediately; undeclared or
// understated bodies are cut off while being read (handlers map the resulting
// *http.MaxBytesError to 413).
func (mw *Middleware) BodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := mw.maxBody()
		if r.ContentLength > limit {
			w.Header().Set("Connection", "close")
			WriteJSONError(w, r, http.StatusRequestEntityTooLarge, "RequestTooLarge", "request body too large")
			return
		}
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

// authFailure maps an auth error to a status, a fixed non-echoing message
// and the reason recorded in the audit row. Missing, unknown, revoked and
// expired tokens all get the same 401 body, so the response is no oracle for
// whether a token exists. Error text from the token stores can contain a
// file path, so it is never copied into the response.
func authFailure(err error) (status int, msg, reason string) {
	switch {
	case errors.Is(err, auth.ErrMissingAuth):
		return http.StatusUnauthorized, "missing credentials", "missing"
	case errors.Is(err, auth.ErrEmptyToken):
		return http.StatusUnauthorized, "invalid credentials", "empty"
	case errors.Is(err, auth.ErrExpiredToken):
		return http.StatusUnauthorized, "invalid credentials", "expired"
	case errors.Is(err, auth.ErrInvalidToken):
		return http.StatusUnauthorized, "invalid credentials", "invalid"
	default:
		// Token store unreadable: a server-side fault, not a client one. The
		// caller logs the error under the response's incident id.
		return http.StatusInternalServerError, "authentication unavailable", ""
	}
}

// operatorPath reports whether path is an approval endpoint.
func operatorPath(path string) bool {
	return path == "/v1/requests" || strings.HasPrefix(path, "/v1/requests/")
}

func publicRoute(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		(r.URL.Path == "/crossdomain.xml" || r.URL.Path == "/clientaccesspolicy.xml")
}

// healthzRoute reports whether the request is GET /healthz.
func healthzRoute(r *http.Request) bool {
	return r.Method == http.MethodGet && r.URL.Path == "/healthz"
}

// authenticate identifies the caller of r.
func (mw *Middleware) authenticate(r *http.Request) (auth.Principal, error) {
	header := r.Header.Get("Authorization")
	if mw.Tokens != nil {
		return mw.Tokens.Authenticate(header)
	}
	if healthzRoute(r) {
		return mw.authenticateLegacyHealthz(header)
	}
	// Legacy shared token files: the route picks the file, as before H1.
	ts := mw.TokenStore
	if operatorPath(handlers.RoutePath(r)) && mw.OperatorTokenStore != nil {
		ts = mw.OperatorTokenStore
	}
	if ts == nil {
		return auth.Principal{}, errors.New("no token store configured")
	}
	tokenID, err := ts.Verify(header)
	if err != nil {
		return auth.Principal{}, err
	}
	return auth.Principal{TokenID: tokenID, Legacy: true, Scopes: append([]auth.Scope(nil), auth.AllScopes...)}, nil
}

// authenticateLegacyHealthz identifies a /healthz caller in legacy
// shared-token mode, where /healthz has no route-to-file rule of its own. It
// accepts either file, because the detailed body is for the operator: a token
// from the operator file holds every scope (as it does on /v1/requests*),
// while one from the agent file holds the audit scope only when
// LegacyPrivilegedRoutes already lets that shared token read the audit log,
// so /healthz never shows an agent token more than /v1/audit would.
func (mw *Middleware) authenticateLegacyHealthz(header string) (auth.Principal, error) {
	all := func(id string) auth.Principal {
		return auth.Principal{TokenID: id, Legacy: true, Scopes: append([]auth.Scope(nil), auth.AllScopes...)}
	}
	var firstErr error
	if mw.OperatorTokenStore != nil {
		id, err := mw.OperatorTokenStore.Verify(header)
		if err == nil {
			return all(id), nil
		}
		firstErr = err
	}
	if mw.TokenStore != nil {
		id, err := mw.TokenStore.Verify(header)
		if err == nil {
			p := all(id)
			if !mw.LegacyPrivilegedRoutes {
				p.Scopes = []auth.Scope{auth.ScopeAgent}
			}
			return p, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("no token store configured")
	}
	return auth.Principal{}, firstErr
}

// serveHealthz runs /healthz authentication, which is optional: a valid
// token attaches its principal (so the handler can add detail for audit and
// operator scopes), and anything else (no header, malformed, unknown,
// expired, revoked) simply proceeds without one and gets the minimal body.
//
// By design this path does not feed the failed-authentication limiter, write
// AUTH_FAILED rows, or enforce the route table: /healthz is a public
// liveness probe, so a monitor or scanner hitting it with junk can neither
// lock out real agents sharing the source address nor flood the audit log,
// and every caller sees the same status and body whatever the token state.
// A token-store fault is logged under an incident id and never changes the
// response.
func (mw *Middleware) serveHealthz(next http.Handler, w http.ResponseWriter, r *http.Request) {
	p, err := mw.authenticate(r)
	if err == nil {
		next.ServeHTTP(w, r.WithContext(handlers.WithPrincipal(r.Context(), p)))
		return
	}
	if status, _, _ := authFailure(err); status != http.StatusUnauthorized {
		log.Printf("ERROR incident=%s status=%d token verification unavailable on /healthz: %s",
			handlers.NewIncidentID(), status, handlers.LogSafe(err.Error()))
	}
	next.ServeHTTP(w, r)
}

// AuthMiddleware authenticates every route except the public ones (and
// /healthz, whose authentication is optional: serveHealthz) and enforces the route's scope (authz.go). It does NOT exempt OPTIONS: a
// legitimate preflight is answered earlier by CORSMiddleware, and any other
// OPTIONS request must authenticate like everything else.
//
// A failed authentication is audited (AUTH_FAILED with the client IP, the
// route, the reason and at most a short token id: never the token) and
// answered with a generic 401. More than the limiter allows from one source
// in one window are answered 429 and summarised by a single
// AUTH_RATE_LIMITED row, so an attacker cannot flood the audit log. A token
// without the route's scope gets 403 and an AUTHZ_DENIED row. On success the
// caller is stored in the request context (handlers.WithPrincipal).
func (mw *Middleware) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicRoute(r) {
			next.ServeHTTP(w, r)
			return
		}
		if healthzRoute(r) {
			mw.serveHealthz(next, w, r)
			return
		}
		p, err := mw.authenticate(r)
		if err != nil {
			status, msg, reason := authFailure(err)
			if status != http.StatusUnauthorized {
				// The cause (a token-store path or parse error) is logged
				// under the incident id and never sent to the client.
				id := handlers.NewIncidentID()
				log.Printf("ERROR incident=%s status=%d token verification unavailable: %s", id, status, handlers.LogSafe(err.Error()))
				handlers.WriteErrorWithID(w, id, status, "ServerAuthError", msg)
				return
			}
			limited, report, full := mw.limiter().failure(handlers.ClientIP(r))
			if mw.Auditor != nil && (!limited || report) {
				id := p.TokenID // the record id of an expired token
				if id == "" {
					id = auth.PresentedID(r.Header.Get("Authorization"))
				}
				if id == "" {
					id = "-"
				}
				event := handlers.EventAuthFailed
				details := "ip=" + handlers.ClientIP(r) + " " + r.Method + " " + handlers.AuditPath(r) + " reason=" + reason + " token=" + id
				switch {
				case full:
					event = handlers.EventAuthRateLimited
					details += fmt.Sprintf(" (failure table full: %d sources tracked; failures from new sources get 429 and are not logged until the window ends)", maxTrackedSources)
				case limited:
					event = handlers.EventAuthRateLimited
					details += " (further failures from this source are not logged until the window ends)"
				}
				mw.Auditor.AuditAuthFailure(r, event, details)
			}
			if limited {
				w.Header().Set("Retry-After", strconv.Itoa(int(mw.limiter().window/time.Second)))
				WriteJSONError(w, r, http.StatusTooManyRequests, "ServerAuthError", "too many failed authentication attempts")
				return
			}
			writeUnauthorized(w, r, msg)
			return
		}
		if p.Legacy && !mw.LegacyPrivilegedRoutes && legacyPrivileged(r) {
			if mw.Auditor != nil {
				mw.Auditor.AuditDenied(r, p, "route disabled in legacy shared-token mode")
			}
			WriteJSONError(w, r, http.StatusForbidden, "AuthorizationError",
				"this route is disabled in legacy shared-token mode: use a per-agent token (or the offline command)")
			return
		}
		if !p.Legacy {
			if need := routeRequirement(r); !need.satisfiedBy(p) {
				if mw.Auditor != nil {
					mw.Auditor.AuditDenied(r, p, "missing scope "+need.name)
				}
				WriteJSONError(w, r, http.StatusForbidden, "AuthorizationError", "insufficient scope for this route")
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(handlers.WithPrincipal(r.Context(), p)))
	})
}

// PathMiddleware refuses ambiguous request paths with 400 before
// authentication (python StrictURLNormalizationMiddleware): "..", a
// backslash, "//" or a control character, in the decoded path or in the
// percent-decoded raw path.
func (mw *Middleware) PathMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.EscapedPath()
		if dec, err := url.PathUnescape(raw); err == nil {
			raw = dec
		}
		for _, p := range []string{r.URL.Path, raw} {
			if badPath(p) {
				WriteJSONError(w, r, http.StatusBadRequest, "BadRequest", "Invalid URI path")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func badPath(p string) bool {
	if strings.Contains(p, "..") || strings.Contains(p, "\\") || strings.Contains(p, "//") {
		return true
	}
	for _, c := range p {
		if c < 32 || c == 127 {
			return true
		}
	}
	return false
}

// TokenIDFromContext extracts the token ID from the request context.
func TokenIDFromContext(ctx context.Context) string {
	p, _ := handlers.PrincipalFromContext(ctx)
	return p.TokenID
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	wrote      bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wrote {
		rw.statusCode = code
		rw.wrote = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.wrote = true
	return rw.ResponseWriter.Write(b)
}

// Unwrap returns the underlying ResponseWriter for middleware that needs it.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}
