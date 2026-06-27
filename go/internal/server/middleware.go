// Package server provides HTTP middleware for the rgt-vault server.
//
// Middleware stack:
//  1. CORS headers (permissive for local development)
//  2. Request logging (method, path, status, duration)
//  3. Bearer token authentication (skipped for /healthz)
package server

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"rgt-vault-server/internal/auth"
)

// Middleware holds the server middleware components.
type Middleware struct {
	TokenStore *auth.TokenStore
}

// NewMiddleware creates a new Middleware instance.
func NewMiddleware(tokenStore *auth.TokenStore) *Middleware {
	return &Middleware{TokenStore: tokenStore}
}

// CORSMiddleware adds permissive CORS headers for local development or restricted origins in production.
func (mw *Middleware) CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			allowedOriginsStr := os.Getenv("CORS_ALLOWED_ORIGINS")
			isAllowed := false

			if allowedOriginsStr == "*" {
				isAllowed = true
			} else if allowedOriginsStr != "" {
				allowedOrigins := strings.Split(allowedOriginsStr, ",")
				for _, allowed := range allowedOrigins {
					if strings.TrimSpace(allowed) == origin {
						isAllowed = true
						break
					}
				}
			} else {
				// If not configured, default to allowing all in non-production, and reject in production.
				if os.Getenv("APP_ENV") != "production" {
					isAllowed = true
				}
			}

			if isAllowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
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

// AuthMiddleware verifies the bearer token for all routes except /healthz.
// On success, it sets the token ID in the request context.
func (mw *Middleware) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health check and XML policy endpoints
		if r.URL.Path == "/healthz" || r.URL.Path == "/crossdomain.xml" || r.URL.Path == "/clientaccesspolicy.xml" || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		tokenID, err := mw.TokenStore.Verify(authHeader)
		if err != nil {
			// Map auth errors to HTTP status codes
			status := http.StatusUnauthorized
			msg := err.Error()
			switch {
			case strings.Contains(msg, "missing"):
				status = http.StatusUnauthorized
			case strings.Contains(msg, "Empty") || strings.Contains(msg, "empty"):
				status = http.StatusUnauthorized
			case strings.Contains(msg, "Invalid") || strings.Contains(msg, "invalid"):
				status = http.StatusUnauthorized
			case strings.Contains(msg, "not found"):
				status = http.StatusInternalServerError
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			w.Write([]byte(`{"error":"ServerAuthError","detail":"` + msg + `"}`))
			return
		}

		// Store token ID in context for handlers that need it
		ctx := context.WithValue(r.Context(), contextKeyTokenID, tokenID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// contextKey is a private type for context keys to avoid collisions.
type contextKey string

const contextKeyTokenID contextKey = "tokenID"

// TokenIDFromContext extracts the token ID from the request context.
func TokenIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(contextKeyTokenID).(string); ok {
		return v
	}
	return ""
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Unwrap returns the underlying ResponseWriter for middleware that needs it.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}
