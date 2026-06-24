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
package gateway

import (
	"encoding/json"
	"log"
	"math/rand/v2"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync/atomic"
)

// Gateway manages routing traffic between a legacy Python backend and a new Go backend.
type Gateway struct {
	pythonProxy *httputil.ReverseProxy
	goProxy     *httputil.ReverseProxy
	goPercent   atomic.Int64 // 0..100, percent of traffic sent to Go
	pythonReqs  atomic.Int64
	goReqs      atomic.Int64
	goFails     atomic.Int64
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
		log.Printf("gateway: Go backend failure: %v; falling back to Python backend", err)
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

// ServeHTTP satisfies http.Handler. Admin paths are handled first:
//
//	PUT/POST /__cutover?go=N   — set Go percent; 400 on missing/invalid N
//	GET /__cutover/stats       — JSON snapshot of Stats()
//
// All other requests are probabilistically routed: rand.IntN(100) < goPercent
// sends to the Go proxy; otherwise the Python proxy handles it.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/__cutover" && (r.Method == http.MethodPut || r.Method == http.MethodPost):
		goStr := r.URL.Query().Get("go")
		if goStr == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing query parameter 'go'"})
			return
		}
		p, err := strconv.Atoi(goStr)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid 'go' value, must be an integer"})
			return
		}
		g.SetGoPercent(p)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]int{"go_percent": g.GoPercent()})

	case r.URL.Path == "/__cutover/stats" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(g.Stats())

	default:
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
