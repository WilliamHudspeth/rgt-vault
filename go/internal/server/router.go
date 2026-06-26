// Package server provides the HTTP router for the rgt-vault server.
//
// The router uses chi for clean route grouping and middleware composition.
// All 12+ route groups mirror the Python FastAPI app.py endpoints.
package server

import (
	"github.com/go-chi/chi/v5"
	"rgt-vault-server/internal/server/handlers"
)

// NewRouter creates and configures the chi router with all routes and middleware.
//
// Route groups:
//
//	Public (no auth):
//	  GET  /healthz                   - Health check
//
//	Authenticated (Bearer token required):
//	  POST /v1/secrets                        - Set a secret
//	  GET  /v1/secrets                        - List secrets by namespace
//	  GET  /v1/secrets/{namespace}/{name}     - Get a single secret
//	  POST /v1/secrets/{namespace}/{name}/use - Use (lease) a secret
//	  POST /v1/secrets/{namespace}/{name}/revoke - Revoke a secret
//	  DELETE /v1/secrets/{namespace}/{name}   - Delete a secret
//	  POST /v1/rotate                         - Rotate keys (master/dek)
//	  GET  /v1/audit                          - Get audit log entries
//	  POST /v1/audit/verify                   - Verify audit chain integrity
//	  POST /v1/policy/simulate                - Simulate a policy decision
//	  GET  /v1/actions                        - List registered actions
func NewRouter(h *handlers.Handlers, mw *Middleware) chi.Router {
	r := chi.NewRouter()

	// Global middleware stack (applied to all routes)
	r.Use(mw.CORSMiddleware)
	r.Use(mw.SecurityHeadersMiddleware)
	r.Use(mw.LoggingMiddleware)
	r.Use(mw.AuthMiddleware)

	// -----------------------------------------------------------------------
	// Public routes (auth skipped by AuthMiddleware for /healthz)
	// -----------------------------------------------------------------------
	r.Get("/healthz", h.HealthCheck)
	r.Get("/crossdomain.xml", h.BlockXMLPolicy)
	r.Get("/clientaccesspolicy.xml", h.BlockXMLPolicy)

	// -----------------------------------------------------------------------
	// API v1 routes (all authenticated)
	// -----------------------------------------------------------------------
	r.Route("/v1", func(r chi.Router) {
		// Secrets collection
		r.Post("/secrets", h.SetSecret)
		r.Get("/secrets", h.ListSecrets)

		// Secret operations (by namespace and name)
		r.Route("/secrets/{namespace}/{name}", func(r chi.Router) {
			r.Get("/", h.GetSecret)
			r.Delete("/", h.DeleteSecret)
			r.Post("/use", h.UseSecret)
			r.Post("/revoke", h.RevokeSecret)
		})

		// Key rotation
		r.Post("/rotate", h.Rotate)

		// Audit
		r.Get("/audit", h.Audit)
		r.Post("/audit/verify", h.AuditVerify)

		// Policy simulation
		r.Post("/policy/simulate", h.PolicySimulate)

		// Action listing
		r.Get("/actions", h.ListActions)
	})

	return r
}
