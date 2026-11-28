// Package server provides the HTTP router, middleware and constructor of
// the rgt-vault server: the Go port of python/server/app.py on the real
// vault (internal/vault).
package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"rgt-vault-server/internal/server/handlers"
)

// NewRouter creates the chi router with all routes and middleware. Most
// callers want New, which also builds the Handlers and Middleware.
//
// Routes (python/server/app.py, plus the Go-only extras marked *):
//
//	Public (no auth):
//	  GET  /healthz
//	  GET  /crossdomain.xml, /clientaccesspolicy.xml   (restrictive 404)
//
//	Scope agent (the subject is the token's agent; see authz.go):
//	  POST /v1/secrets                              set a secret
//	  GET  /v1/secrets?namespace=                   list (never values)
//	* GET  /v1/secrets/{namespace}/{name}           ciphertext fingerprint (RGT-502)
//	  POST /v1/secrets/{namespace}/{name}/use       lease + run an action
//	  POST /v1/secrets/{namespace}/{name}/revoke    revoke
//	* POST /v1/secrets/{namespace}/{name}/lease     plaintext value (agent AND lease scope; RGT-504)
//	  POST /v1/policy/simulate                      ABAC decision
//	  POST /v1/capabilities/execute                 run a capability (v2 token)
//	  GET  /v1/capabilities                         registered capabilities
//	  GET  /v1/capabilities/list?agent=             capabilities the agent may run
//	* GET  /v1/actions                              registered actions
//
//	Scope audit (or operator):
//	  GET  /v1/audit?limit=&capability=             audit rows (RGT-166 filter)
//	  POST /v1/audit/verify                         verify the hash chain
//
//	Scope operator:
//	  POST /v1/rotate                               {"target": "master"|"dek"}
//	  GET  /v1/requests                             pending approvals
//	  POST /v1/requests/{id}/approve                {"totp_code", "operator"}
//	  POST /v1/requests/{id}/deny                   {"reason", "operator"}
func NewRouter(h *handlers.Handlers, mw *Middleware) chi.Router {
	r := chi.NewRouter()

	// Global middleware stack (applied to all routes, outermost first).
	// Recover sits just inside the logger so a panic anywhere below becomes a
	// generic, logged 500; CORS answers preflights for allowed origins only
	// and tags allowed-origin responses (including 405s); the method
	// allow-list then refuses TRACE and unknown verbs, and the path check
	// ambiguous paths, before authentication; auth guards everything else
	// (including any OPTIONS request that was not a legitimate preflight)
	// and every authenticated request is audited before its handler runs.
	r.Use(mw.SecurityHeadersMiddleware)
	r.Use(mw.LoggingMiddleware)
	r.Use(mw.RecoverMiddleware)
	r.Use(mw.CORSMiddleware)
	r.Use(mw.MethodMiddleware)
	r.Use(mw.PathMiddleware)
	r.Use(mw.AuthMiddleware)
	r.Use(h.AuditHTTP)
	r.Use(mw.BodyLimitMiddleware)

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		WriteJSONError(w, r, http.StatusNotFound, "NotFound", "not found")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allowHeaderValue)
		WriteJSONError(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "method not allowed")
	})

	r.Get("/healthz", h.HealthCheck)
	r.Get("/crossdomain.xml", h.BlockXMLPolicy)
	r.Get("/clientaccesspolicy.xml", h.BlockXMLPolicy)

	r.Route("/v1", func(r chi.Router) {
		r.Post("/secrets", h.SetSecret)
		r.Get("/secrets", h.ListSecrets)
		r.Route("/secrets/{namespace}/{name}", func(r chi.Router) {
			r.Get("/", h.GetSecret)
			r.Post("/use", h.UseSecret)
			r.Post("/revoke", h.RevokeSecret)
			r.Post("/lease", h.LeaseSecret)
		})

		r.Post("/rotate", h.Rotate)

		r.Get("/audit", h.Audit)
		r.Post("/audit/verify", h.AuditVerify)

		r.Post("/policy/simulate", h.PolicySimulate)

		r.Get("/requests", h.ListRequests)
		r.Post("/requests/{id}/approve", h.Approve)
		r.Post("/requests/{id}/deny", h.Deny)

		r.Post("/capabilities/execute", h.ExecuteCapability)
		r.Get("/capabilities", h.ListCapabilities)
		r.Get("/capabilities/list", h.ListAuthorizedCapabilities)

		r.Get("/actions", h.ListActions)
	})

	return r
}
