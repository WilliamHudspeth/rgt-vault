package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"rgt-vault-server/internal/actions"
	"rgt-vault-server/internal/approval"
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
		path = r.URL.Path
	}
	ae, known := classify(err)
	if !known {
		log.Printf("ERROR incident=%s path=%s unexpected handler error: %v", id, path, err)
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
