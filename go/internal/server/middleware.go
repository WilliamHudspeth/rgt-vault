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
//  7. Bearer token authentication (skipped for /healthz and the XML policy
//     stubs). /v1/requests* takes the operator token, everything else the
//     agent token.
//  8. Request body size limit (413)
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/server/handlers"
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

// Middleware holds the server middleware components.
type Middleware struct {
	// TokenStore holds the agent bearer token.
	TokenStore *auth.TokenStore

	// OperatorTokenStore holds the operator token required by the approval
	// endpoints (/v1/requests*). Nil means those endpoints accept the agent
	// token, as Python does without --operator-token-file: an agent holding
	// it could then approve its own requests.
	OperatorTokenStore *auth.TokenStore

	// AllowedOrigins is the exact-match CORS allow-list. Empty means CORS is
	// denied for every origin (the default). "*" is never honoured.
	AllowedOrigins []string

	// MaxBodyBytes caps request bodies; <= 0 selects DefaultMaxBodyBytes.
	MaxBodyBytes int64
}

// NewMiddleware creates a Middleware with CORS denied and the default body limit.
func NewMiddleware(tokenStore *auth.TokenStore) *Middleware {
	return &Middleware{TokenStore: tokenStore, MaxBodyBytes: DefaultMaxBodyBytes}
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

// WriteJSONError writes {"error": errType, "detail": detail} using encoding/json.
func WriteJSONError(w http.ResponseWriter, status int, errType, detail string) {
	writeJSONErrorBody(w, status, map[string]string{"error": errType, "detail": detail})
}

func writeJSONErrorBody(w http.ResponseWriter, status int, body map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("ERROR: failed to write JSON error response: %v", err)
	}
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
			id := newIncidentID()
			committed := false
			if rw, ok := w.(*responseWriter); ok {
				committed = rw.wrote
			}
			// Log the panic's type, not its value: the value may embed request
			// data. The stack is enough to locate the fault.
			log.Printf("PANIC incident=%s method=%s path=%s panic_type=%T\n%s",
				id, r.Method, r.URL.Path, rec, debug.Stack())
			if committed {
				// Headers already sent: appending a JSON body would corrupt
				// the response. Abort the connection instead.
				panic(http.ErrAbortHandler)
			}
			writeJSONErrorBody(w, http.StatusInternalServerError, map[string]string{
				"error":       "InternalError",
				"detail":      "internal server error",
				"incident_id": id,
			})
		}()
		next.ServeHTTP(w, r)
	})
}

func newIncidentID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

// MethodMiddleware returns 405 for every verb outside the allow-list, before
// authentication, so TRACE and friends are never reachable.
func (mw *Middleware) MethodMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowedMethods[r.Method] {
			w.Header().Set("Allow", allowHeaderValue)
			WriteJSONError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "method not allowed")
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
					WriteJSONError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "method not allowed")
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
			r.Method, r.URL.Path, wrapped.statusCode, duration.Round(time.Microsecond))
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
			WriteJSONError(w, http.StatusRequestEntityTooLarge, "RequestTooLarge", "request body too large")
			return
		}
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

// authFailure maps an auth error to a status and a fixed, non-echoing message.
// Error text from the token store can contain the token file path, so it is
// never copied into the response.
func authFailure(err error) (int, string) {
	switch {
	case errors.Is(err, auth.ErrMissingAuth):
		return http.StatusUnauthorized, "missing credentials"
	case errors.Is(err, auth.ErrEmptyToken), errors.Is(err, auth.ErrInvalidToken):
		return http.StatusUnauthorized, "invalid credentials"
	default:
		// Token file unreadable: a server-side fault, not a client one.
		log.Printf("ERROR: token verification unavailable: %v", err)
		return http.StatusInternalServerError, "authentication unavailable"
	}
}

// operatorPath reports whether path is an operator endpoint.
func operatorPath(path string) bool {
	return path == "/v1/requests" || strings.HasPrefix(path, "/v1/requests/")
}

// AuthMiddleware verifies the bearer token for all routes except the public
// ones. Unlike earlier versions it does NOT exempt OPTIONS: a legitimate
// preflight is answered earlier by CORSMiddleware, and any other OPTIONS
// request must authenticate like everything else.
//
// /v1/requests* (approve/deny) verifies against OperatorTokenStore when one
// is configured, and every other route against TokenStore only, so neither
// token works in the other's scope. On success it stores the token id and
// scope in the request context.
func (mw *Middleware) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet &&
			(r.URL.Path == "/healthz" || r.URL.Path == "/crossdomain.xml" || r.URL.Path == "/clientaccesspolicy.xml") {
			next.ServeHTTP(w, r)
			return
		}

		ts, scope := mw.TokenStore, handlers.ScopeAgent
		if operatorPath(r.URL.Path) {
			scope = handlers.ScopeOperator
			if mw.OperatorTokenStore != nil {
				ts = mw.OperatorTokenStore
			}
		}
		tokenID, err := ts.Verify(r.Header.Get("Authorization"))
		if err != nil {
			status, msg := authFailure(err)
			if status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", `Bearer realm="rgt-vault"`)
			}
			WriteJSONError(w, status, "ServerAuthError", msg)
			return
		}

		next.ServeHTTP(w, r.WithContext(handlers.WithAuth(r.Context(), tokenID, scope)))
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
				WriteJSONError(w, http.StatusBadRequest, "BadRequest", "Invalid URI path")
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
	id, _ := handlers.AuthFromContext(ctx)
	return id
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
