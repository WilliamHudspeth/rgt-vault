package logging

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ctxKey struct{}

// WithContext stores logger in ctx so request-scoped fields (incident_id,
// request_id, token_id, agent) can flow across middleware and handlers.
func WithContext(ctx context.Context, logger *slog.Logger) context.Context {
	if logger == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, logger)
}

// FromContext extracts the *slog.Logger stored by WithContext, falling back to
// Default() when none is present.
func FromContext(ctx context.Context) *slog.Logger {
	if ctx != nil {
		if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok && l != nil {
			return l
		}
	}
	return Default()
}

// TokenHashID returns the irreversible 8-character hex SHA-256 prefix of token
// (matching internal/auth.TokenID), or "" if token is empty/whitespace.
func TokenHashID(token string) string {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(sum[:])[:8]
}

// NewIncidentID generates a 16-character lowercase hex correlation identifier
// from crypto/rand (matching internal/server.RecoverMiddleware).
func NewIncidentID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UTC().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// HTTPMiddleware returns a standard net/http middleware that emits one
// structured JSON access record per request with method, path, status, and
// duration_ms. Query strings, headers, cookies, client IPs, and bodies are
// deliberately excluded (RGT-409, RGT-410, RGT-432).
func HTTPMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			durMS := float64(time.Since(start).Microseconds()) / 1000.0

			lvl := slog.LevelInfo
			if rec.status >= http.StatusInternalServerError {
				lvl = slog.LevelError
			} else if rec.status >= http.StatusBadRequest {
				lvl = slog.LevelWarn
			}

			logger.LogAttrs(r.Context(), lvl, "http_request",
				slog.String(FieldHTTPMethod, SanitizeText(r.Method)),
				slog.String(FieldHTTPPath, SanitizeText(r.URL.Path)),
				slog.Int(FieldHTTPStatus, rec.status),
				slog.Float64(FieldDurationMS, durMS),
			)
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (sr *statusRecorder) WriteHeader(code int) {
	if !sr.wrote {
		sr.status = code
		sr.wrote = true
	}
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(b []byte) (int, error) {
	if !sr.wrote {
		sr.wrote = true
	}
	return sr.ResponseWriter.Write(b)
}

func (sr *statusRecorder) Unwrap() http.ResponseWriter {
	return sr.ResponseWriter
}
