// Package gateway implements a reverse proxy gateway with cutover capabilities.
//
// This is created as part of ticket RGT-162 (cutover gateway). It functions
// as a tiny reverse proxy fronting the Python rgt-vault server (acting as the safe
// backend) and gradually routes a percentage of traffic to the new Go server.
//
// Key Design Properties:
//   - Starts at 0% Go (100% Python).
//   - Rollback is simple: setting go_percent to 0 immediately redirects all traffic to Python.
//   - Canary safety: Go-backend transport failures transparently fall back to the Python backend.
//   - No global state or init() side effects.
//   - The admin API (/__cutover*) requires an operator bearer token
//     (internal/auth TokenStore, constant-time compare) and fails closed: a
//     gateway without a configured token store rejects every admin call.
//     Admin paths are never proxied to a backend.
package gateway

import (
	"encoding/json"
	"errors"
	"log"
	"math/rand/v2"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync/atomic"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/logging"
)

// adminPrefix is the path prefix reserved for the gateway's admin API.
const adminPrefix = "/__cutover"

// Gateway manages routing traffic between a legacy Python backend and a new Go backend.
type Gateway struct {
	pythonProxy *httputil.ReverseProxy
	goProxy     *httputil.ReverseProxy
	goPercent   atomic.Int64 // 0..100, percent of traffic sent to Go
	pythonReqs  atomic.Int64
	goReqs      atomic.Int64
	goFails     atomic.Int64
	operator    atomic.Pointer[auth.TokenStore] // nil => admin API disabled
}

// SetOperatorTokenStore configures the token store that authenticates the
// admin API. Passing nil disables the admin API (every call gets 403).
func (g *Gateway) SetOperatorTokenStore(ts *auth.TokenStore) {
	g.operator.Store(ts)
}

// authorizeAdmin reports whether r carries a valid operator token, writing
// the error response itself when it does not.
func (g *Gateway) authorizeAdmin(w http.ResponseWriter, r *http.Request) bool {
	ts := g.operator.Load()
	if ts == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin API disabled: no operator token configured"})
		return false
	}
	id, err := ts.Verify(r.Header.Get("Authorization"))
	if err != nil {
		// Never echo the presented token; log only the failure class and sanitize
		// request-derived fields so CR/LF/control bytes cannot forge log lines.
		log.Printf("gateway: admin auth failed for %s %s from %s: %s",
			logging.SanitizeText(r.Method),
			logging.SanitizeText(r.URL.Path),
			logging.SanitizeText(r.RemoteAddr),
			authFailure(err),
		)
		w.Header().Set("WWW-Authenticate", `Bearer realm="rgt-vault-gateway"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "operator token required"})
		return false
	}
	log.Printf("gateway: admin %s %s go=%q by token %s",
		logging.SanitizeText(r.Method),
		logging.SanitizeText(path.Clean(r.URL.Path)),
		r.URL.Query().Get("go"),
		logging.SanitizeText(id),
	)
	return true
}

// authFailure maps auth errors to a fixed vocabulary so file paths from
// TokenStore.Read never reach logs at a client's prompting.
func authFailure(err error) string {
	switch {
	case errors.Is(err, auth.ErrMissingAuth):
		return "missing"
	case errors.Is(err, auth.ErrEmptyToken):
		return "empty"
	case errors.Is(err, auth.ErrInvalidToken):
		return "invalid"
	default:
		return "token store unavailable"
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// NewGateway creates a new Gateway instance routing traffic to pythonURL and goURL.
// goPercent is clamped to [0, 100]. The Go proxy's ErrorHandler increments goFails,
// logs the error, and transparently re-serves the request via the Python proxy (canary fallback).
func NewGateway(pythonURL, goURL string, goPercent int) (*Gateway, error) {
	pURL, err := url.Parse(pythonURL)
	if err != nil {
		return nil, err
	}
	gURL, err := url.Parse(goURL)
	if err != nil {
		return nil, err
	}

	g := &Gateway{
		pythonProxy: httputil.NewSingleHostReverseProxy(pURL),
		goProxy:     httputil.NewSingleHostReverseProxy(gURL),
	}
	g.goPercent.Store(clamp(goPercent))

	// ErrorHandler is assigned AFTER goProxy is built so that g.pythonProxy is
	// already set in the Gateway struct. The closure captures g (the *Gateway),
	// ensuring it always references the live pythonProxy — never a nil or stale copy.
	g.goProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		g.goFails.Add(1)
		errMsg := "<nil>"
		if err != nil {
			errMsg = logging.SanitizeText(err.Error())
		}
		log.Printf("gateway: Go backend failure: %s; falling back to Python backend", errMsg)
		g.pythonProxy.ServeHTTP(w, r)
	}

	return g, nil
}

// SetGoPercent updates the percentage of traffic routed to the Go backend.
// The value is clamped to [0, 100].
func (g *Gateway) SetGoPercent(p int) {
	g.goPercent.Store(clamp(p))
}

// GoPercent returns the current Go routing percentage as an int.
func (g *Gateway) GoPercent() int {
	return int(g.goPercent.Load())
}

// Stats returns a snapshot of the internal counters.
func (g *Gateway) Stats() map[string]int64 {
	return map[string]int64{
		"go_percent":  g.goPercent.Load(),
		"python_reqs": g.pythonReqs.Load(),
		"go_reqs":     g.goReqs.Load(),
		"go_fails":    g.goFails.Load(),
	}
}

// ServeHTTP satisfies http.Handler. Admin paths (operator token required)
// are handled first and never proxied:
//
//	PUT/POST /__cutover?go=N   — set Go percent; 400 on missing/invalid N
//	GET /__cutover/stats       — JSON snapshot of Stats()
//	anything else under /__cutover — 404/405
//
// All other requests are probabilistically routed: rand.IntN(100) < goPercent
// sends to the Go proxy; otherwise the Python proxy handles it.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Match on the cleaned path so //__cutover, /x/../__cutover etc. are
	// treated as admin requests (authenticated, never proxied).
	if p := path.Clean("/" + r.URL.Path); p == adminPrefix || strings.HasPrefix(p, adminPrefix+"/") {
		g.serveAdmin(w, r, p)
		return
	}
	// Probabilistic routing: n is uniform in [0, 100).
	// When goPercent==100 all n < 100 are true (100% Go).
	// When goPercent==0  no  n < 0   is true (100% Python).
	n := rand.IntN(100)
	if int64(n) < g.goPercent.Load() {
		g.goReqs.Add(1)
		g.goProxy.ServeHTTP(w, r)
	} else {
		g.pythonReqs.Add(1)
		g.pythonProxy.ServeHTTP(w, r)
	}
}

func (g *Gateway) serveAdmin(w http.ResponseWriter, r *http.Request, cleanPath string) {
	if !g.authorizeAdmin(w, r) {
		return
	}
	switch cleanPath {
	case adminPrefix:
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			w.Header().Set("Allow", "PUT, POST")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		goStr := r.URL.Query().Get("go")
		if goStr == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing query parameter 'go'"})
			return
		}
		p, err := strconv.Atoi(goStr)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid 'go' value, must be an integer"})
			return
		}
		g.SetGoPercent(p)
		writeJSON(w, http.StatusOK, map[string]int{"go_percent": g.GoPercent()})

	case adminPrefix + "/stats":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, g.Stats())

	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown admin endpoint"})
	}
}

// clamp bounds p to the inclusive range [0, 100].
func clamp(p int) int64 {
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return int64(p)
}

// Compile-time assertion: Gateway implements http.Handler.
var _ http.Handler = (*Gateway)(nil)
