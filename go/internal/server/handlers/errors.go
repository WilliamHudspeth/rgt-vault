package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"rgt-vault-server/internal/actions"
	"rgt-vault-server/internal/approval"
	"rgt-vault-server/internal/audit"
	"rgt-vault-server/internal/capabilities"
	"rgt-vault-server/internal/vault"
)

// AppError is an HTTP error response: {"error": Type, "detail": Message}
// (plus "incident_id" when one was assigned).
type AppError struct {
	Code    int
	Type    string
	Message string
}

func (e *AppError) Error() string { return e.Message }

func newAppError(code int, typ, msg string) *AppError {
	return &AppError{Code: code, Type: typ, Message: msg}
}

func badRequest(msg string) *AppError {
	return newAppError(http.StatusBadRequest, "ValidationError", msg)
}

// unprocessable is FastAPI's 422 for a request that is well-formed JSON (or a
// well-formed query string) but misses a required field or has a field of
// the wrong type.
func unprocessable(msg string) *AppError {
	return newAppError(http.StatusUnprocessableEntity, "RequestValidationError", msg)
}

// statusRule maps one error kind to a status and the Python exception class
// name used as the "error" field (python/server/app.py _STATUS_MAP, plus the
// separate PermissionError handler).
type statusRule struct {
	kind   error
	status int
	class  string
}

// statusRules is checked in order; the first kind the error matches
// (errors.Is) wins. More specific kinds come first: ErrRateLimited before
// ErrPermission, and the "server fault" kinds before the client ones so a
// wrapped handler failure is never reported with its inner message.
//
// Deliberate differences from Python:
//   - a rate-limit refusal is 429 (Python: 403 PermissionError), so clients
//     can tell "slow down" from "never" (RGT-154);
//   - ErrClosed / ErrInconsistent are 503 (Python has no equivalent state).
var statusRules = []statusRule{
	{vault.ErrClosed, http.StatusServiceUnavailable, "VaultUnavailable"},
	{vault.ErrInconsistent, http.StatusServiceUnavailable, "VaultUnavailable"},
	{vault.ErrRateLimited, http.StatusTooManyRequests, "PermissionError"},
	{vault.ErrPermission, http.StatusForbidden, "PermissionError"},
	{vault.ErrPolicyDenied, http.StatusForbidden, "PolicyDeniedError"},
	{vault.ErrNotFound, http.StatusNotFound, "SecretNotFoundError"},
	{vault.ErrCapabilityNotFound, http.StatusNotFound, "CapabilityNotFoundError"},
	{capabilities.ErrActionNotFound, http.StatusNotFound, "ActionNotFoundError"},
	{actions.ErrActionNotFound, http.StatusNotFound, "ActionNotFoundError"},
	{vault.ErrCapabilityVersion, http.StatusBadRequest, "CapabilityVersionError"},
	{vault.ErrRotateNotSupported, http.StatusBadRequest, "RotateNotSupportedError"},
	{vault.ErrLegacyVault, http.StatusBadRequest, "VaultError"},
	{vault.ErrValidation, http.StatusBadRequest, "ValidationError"},
	{capabilities.ErrActionExecution, http.StatusInternalServerError, "ActionExecutionError"},
	{actions.ErrActionExecution, http.StatusInternalServerError, "ActionExecutionError"},
	{approval.ErrApproval, http.StatusBadRequest, "ApprovalError"},
}

// classify maps err to an AppError. Errors of a known kind keep their
// message (vault, actions and capability errors carry Python's message,
// which never contains a secret value); anything else becomes a generic 500
// whose text is only logged.
func classify(err error) (*AppError, bool) {
	var ae *AppError
	if errors.As(err, &ae) {
		return ae, true
	}
	for _, r := range statusRules {
		if errors.Is(err, r.kind) {
			return newAppError(r.status, r.class, err.Error()), true
		}
	}
	return nil, false
}

func newIncidentID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

// writeError writes err as a JSON error with an incident id. The status,
// class and path are logged with the id; the error text is logged only for
// unexpected (500) errors, never echoed to the client for those.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	id := newIncidentID()
	path := ""
	if r != nil {
		path = LogSafe(r.URL.Path)
	}
	ae, known := classify(err)
	if !known {
		log.Printf("ERROR incident=%s path=%s unexpected handler error: %s", id, path, LogSafe(err.Error()))
		ae = newAppError(http.StatusInternalServerError, "InternalError", "internal server error")
	} else {
		log.Printf("WARNING incident=%s status=%d error=%s path=%s", id, ae.Code, ae.Type, path)
	}
	writeJSON(w, ae.Code, map[string]string{
		"error":       ae.Type,
		"detail":      ae.Message,
		"incident_id": id,
	})
}

// maxLogField caps a request-derived value in a log line.
const maxLogField = 256

// LogSafe encodes a request-derived string for a single log line: CR, LF
// and TAB become \r, \n, \t (internal/audit.Sanitize), every other control
// character (C0, DEL, C1) and invalid UTF-8 becomes \xNN, and the result is
// capped at maxLogField bytes (marked with "..."). A client can therefore
// never forge or split log entries.
func LogSafe(s string) string {
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = audit.Sanitize(s)
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			for _, c := range []byte(s[i : i+size]) {
				fmt.Fprintf(&b, `\x%02x`, c)
			}
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
		if b.Len() > maxLogField {
			out := b.String()
			for len(out) > maxLogField || !utf8.ValidString(out) {
				out = out[:len(out)-1]
			}
			return out + "..."
		}
	}
	return b.String()
}
