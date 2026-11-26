// Package handlers implements the HTTP request handlers for the rgt-vault server.
//
// The handlers provide a thin translation layer over an in-memory secret store,
// mirroring the Python FastAPI app.py endpoints. All handlers (except health)
// require bearer-token authentication via middleware.
package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"rgt-vault-server/internal/auth"
)

// ---------------------------------------------------------------------------
// In-memory secret store (stand-in for VaultManager)
// ---------------------------------------------------------------------------

// Secret represents a stored secret.
type Secret struct {
	Name      string `json:"name"`
	Value     string `json:"-"` // never serialised by accident; see ListSecrets
	Namespace string `json:"namespace"`
	Agent     string `json:"agent"`
	Purpose   string `json:"purpose"`
	CreatedAt string `json:"created_at"`
}

// SecretMeta is the list/metadata view of a secret. It has no value field.
type SecretMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Agent     string `json:"agent"`
	Purpose   string `json:"purpose"`
	CreatedAt string `json:"created_at"`
}

func metaOf(s Secret) SecretMeta {
	return SecretMeta{Name: s.Name, Namespace: s.Namespace, Agent: s.Agent, Purpose: s.Purpose, CreatedAt: s.CreatedAt}
}

// AuditEntry represents a single audit log line.
type AuditEntry struct {
	Timestamp string `json:"timestamp"`
	Event     string `json:"event"`
	Principal string `json:"principal"`
	Detail    string `json:"detail"`
	Hash      string `json:"hash"`
}

// Store is an in-memory secret store with audit logging.
type Store struct {
	mu       sync.RWMutex
	secrets  map[string]*Secret // key: "namespace/name"
	auditLog []AuditEntry
	auditSeq int
	keyEpoch int
	vaultID  string
}

// NewStore creates a new in-memory store.
func NewStore() *Store {
	return &Store{
		secrets:  make(map[string]*Secret),
		auditLog: make([]AuditEntry, 0),
		auditSeq: 0,
		keyEpoch: 1,
		vaultID:  "rgt-vault-go-001",
	}
}

func (s *Store) secretKey(namespace, name string) string {
	return namespace + "/" + name
}

// SetSecret stores a secret.
func (s *Store) SetSecret(name, value, namespace, agent, purpose string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.secretKey(namespace, name)
	s.secrets[key] = &Secret{
		Name:      name,
		Value:     value,
		Namespace: namespace,
		Agent:     agent,
		Purpose:   purpose,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	return nil
}

// GetSecret retrieves a single secret.
func (s *Store) GetSecret(namespace, name string) (*Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := s.secretKey(namespace, name)
	sec, ok := s.secrets[key]
	if !ok {
		return nil, ErrSecretNotFound
	}
	return sec, nil
}

// ListSecrets returns all secrets in a namespace.
func (s *Store) ListSecrets(namespace string) []Secret {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []Secret
	prefix := namespace + "/"
	for key, sec := range s.secrets {
		if strings.HasPrefix(key, prefix) {
			result = append(result, *sec)
		}
	}
	if result == nil {
		result = []Secret{}
	}
	return result
}

// DeleteSecret removes a secret.
func (s *Store) DeleteSecret(namespace, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.secretKey(namespace, name)
	if _, ok := s.secrets[key]; !ok {
		return ErrSecretNotFound
	}
	delete(s.secrets, key)
	return nil
}

// RevokeSecret is an alias for DeleteSecret (matches Python API).
func (s *Store) RevokeSecret(namespace, name string) error {
	return s.DeleteSecret(namespace, name)
}

// AddAuditEntry adds an entry to the audit log.
func (s *Store) AddAuditEntry(event, principal, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditSeq++

	prevHash := ""
	if len(s.auditLog) > 0 {
		prevHash = s.auditLog[len(s.auditLog)-1].Hash
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)
	raw := fmt.Sprintf("%s|%s|%s|%s|%s", prevHash, timestamp, event, principal, detail)
	hasher := sha256.New()
	hasher.Write([]byte(raw))
	hash := hex.EncodeToString(hasher.Sum(nil))

	s.auditLog = append(s.auditLog, AuditEntry{
		Timestamp: timestamp,
		Event:     event,
		Principal: principal,
		Detail:    detail,
		Hash:      hash,
	})
}

// GetAuditLog returns the last `limit` audit entries.
func (s *Store) GetAuditLog(limit int) []AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.auditLog) {
		limit = len(s.auditLog)
	}
	start := len(s.auditLog) - limit
	if start < 0 {
		start = 0
	}
	result := make([]AuditEntry, limit)
	copy(result, s.auditLog[start:])
	return result
}

// VerifyAuditChain walks every entry in the in-memory audit log and recomputes the SHA-256 chain hash.
func (s *Store) VerifyAuditChain() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.auditLog) == 0 {
		return true
	}

	prevHash := ""
	for _, entry := range s.auditLog {
		raw := fmt.Sprintf("%s|%s|%s|%s|%s", prevHash, entry.Timestamp, entry.Event, entry.Principal, entry.Detail)
		hasher := sha256.New()
		hasher.Write([]byte(raw))
		expectedHash := hex.EncodeToString(hasher.Sum(nil))

		if subtle.ConstantTimeCompare([]byte(entry.Hash), []byte(expectedHash)) != 1 {
			return false
		}
		prevHash = entry.Hash
	}
	return true
}

// RotateMasterKey increments the key epoch.
func (s *Store) RotateMasterKey() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyEpoch++
}

// RotateDEK increments the key epoch (same as master in stub).
func (s *Store) RotateDEK() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyEpoch++
}

// KeyEpoch returns the current key epoch.
func (s *Store) KeyEpoch() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keyEpoch
}

// VaultID returns the vault identifier.
func (s *Store) VaultID() string {
	return s.vaultID
}

// SimulatePolicy returns a simulated policy decision.
func (s *Store) SimulatePolicy(agent, namespace, purpose, action string) map[string]interface{} {
	return map[string]interface{}{
		"allowed":   true,
		"agent":     agent,
		"namespace": namespace,
		"purpose":   purpose,
		"action":    action,
		"reason":    "simulated - all access granted in stub",
	}
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

var (
	ErrSecretNotFound = &AppError{Code: http.StatusNotFound, Type: "SecretNotFoundError", Message: "secret not found"}
	ErrBadRequest     = &AppError{Code: http.StatusBadRequest, Type: "ValidationError", Message: "bad request"}
	ErrUnauthorized   = &AppError{Code: http.StatusUnauthorized, Type: "ServerAuthError", Message: "unauthorized"}
	ErrForbidden      = &AppError{Code: http.StatusForbidden, Type: "PolicyDeniedError", Message: "forbidden"}
	ErrInternal       = &AppError{Code: http.StatusInternalServerError, Type: "ActionExecutionError", Message: "internal server error"}
)

// AppError is an application error with an HTTP status code.
type AppError struct {
	Code    int    `json:"-"`
	Type    string `json:"error"`
	Message string `json:"detail"`
}

func (e *AppError) Error() string {
	return e.Message
}

func newAppError(code int, typ, msg string) *AppError {
	return &AppError{Code: code, Type: typ, Message: msg}
}

// ---------------------------------------------------------------------------
// Handlers struct
// ---------------------------------------------------------------------------

// Handlers holds all HTTP handler methods and their dependencies.
type Handlers struct {
	Store      *Store
	TokenStore *auth.TokenStore
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(store *Store, tokenStore *auth.TokenStore) *Handlers {
	return &Handlers{Store: store, TokenStore: tokenStore}
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("ERROR: failed to write JSON response: %v", err)
	}
}

// maxBodyMsg is returned when the request body exceeds the configured limit.
const maxBodyMsg = "request body too large"

// decodeJSON decodes exactly one JSON value from the request body into dst.
// Unknown fields and trailing data are rejected (400); a body larger than the
// limit installed by the server's body-limit middleware is rejected with 413.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	if r.Body == nil {
		writeError(w, newAppError(http.StatusBadRequest, "ValidationError", "invalid JSON body"))
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(dst)
	if err == nil {
		// Reject trailing garbage / a second JSON value.
		if _, terr := dec.Token(); terr != io.EOF {
			err = terr
			if err == nil {
				err = errors.New("trailing data after JSON body")
			}
		}
	}
	if err == nil {
		return true
	}
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		w.Header().Set("Connection", "close")
		writeError(w, newAppError(http.StatusRequestEntityTooLarge, "RequestTooLarge", maxBodyMsg))
		return false
	}
	// Deliberately generic: the decoder's message can quote request content.
	writeError(w, newAppError(http.StatusBadRequest, "ValidationError", "invalid JSON body"))
	return false
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, err error) {
	appErr, ok := err.(*AppError)
	if !ok {
		// Never echo an unexpected error's text to the client.
		log.Printf("ERROR: unexpected handler error: %v", err)
		appErr = &AppError{Code: http.StatusInternalServerError, Type: "InternalError", Message: "internal server error"}
	}
	writeJSON(w, appErr.Code, map[string]string{
		"error":  appErr.Type,
		"detail": appErr.Message,
	})
}

// ---------------------------------------------------------------------------
// Handler: GET /healthz
// ---------------------------------------------------------------------------

// HealthCheck returns server health information. No auth required.
func (h *Handlers) HealthCheck(w http.ResponseWriter, r *http.Request) {
	version := "0.3.0"
	if os.Getenv("APP_ENV") == "production" {
		version = ""
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "ok",
		"vault_id":  h.Store.VaultID(),
		"key_epoch": h.Store.KeyEpoch(),
		"version":   version,
	})
}

// BlockXMLPolicy serves restrictive policies with a 404 status and disables caching.
func (h *Handlers) BlockXMLPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
  <site-control permitted-cross-domain-policies="none"/>
</cross-domain-policy>`))
}

// ---------------------------------------------------------------------------
// Handler: POST /v1/secrets
// ---------------------------------------------------------------------------

// SetSecretRequest is the JSON body for setting a secret.
type SetSecretRequest struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Namespace string `json:"namespace"`
	Agent     string `json:"agent"`
	Purpose   string `json:"purpose"`
}

// SetSecret handles POST /v1/secrets.
func (h *Handlers) SetSecret(w http.ResponseWriter, r *http.Request) {
	var req SetSecretRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		writeError(w, newAppError(http.StatusBadRequest, "ValidationError", "'name' is required"))
		return
	}
	if req.Value == "" {
		writeError(w, newAppError(http.StatusBadRequest, "ValidationError", "'value' is required"))
		return
	}
	if req.Namespace == "" {
		req.Namespace = "default"
	}
	if req.Agent == "" {
		req.Agent = "cli"
	}

	if err := h.Store.SetSecret(req.Name, req.Value, req.Namespace, req.Agent, req.Purpose); err != nil {
		writeError(w, err)
		return
	}

	h.Store.AddAuditEntry("SECRET_SET", req.Agent, req.Namespace+"/"+req.Name)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":        true,
		"namespace": req.Namespace,
		"name":      req.Name,
	})
}

// ---------------------------------------------------------------------------
// Handler: GET /v1/secrets/{namespace}/{name}
// ---------------------------------------------------------------------------

// GetSecret handles GET /v1/secrets/{namespace}/{name}.
func (h *Handlers) GetSecret(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	name := r.PathValue("name")

	secret, err := h.Store.GetSecret(namespace, name)
	if err != nil {
		writeError(w, err)
		return
	}

	// Return the secret metadata without the raw value for safety
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":       secret.Name,
		"namespace":  secret.Namespace,
		"agent":      secret.Agent,
		"purpose":    secret.Purpose,
		"created_at": secret.CreatedAt,
	})
}

// ---------------------------------------------------------------------------
// Handler: GET /v1/secrets (list)
// ---------------------------------------------------------------------------

// ListSecrets handles GET /v1/secrets.
//
// The list never contains secret values: each entry is a SecretMeta.
//
// TODO(D5/G9): transitional plaintext path. The Go CLI `get` and the MCP
// `lease_secret` tool still fetch plaintext with GET /v1/secrets?name=<exact>
// (go/cmd/rgt-vault/commands.go runGet, go/internal/mcp/mcp.go lease_secret).
// To avoid breaking them before B12/G10 move them off this route, an EXACT
// `name` filter returns that one secret INCLUDING its value, and the read is
// audited. An unfiltered list, and every other route, never returns a value.
// This path is removed when the server moves onto the real vault (G9) and the
// CLI `get` becomes an offline, operator-only operation.
func (h *Handlers) ListSecrets(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		namespace = "default"
	}

	if name := r.URL.Query().Get("name"); name != "" {
		h.listSecretWithValue(w, namespace, name)
		return
	}

	secrets := h.Store.ListSecrets(namespace)
	metas := make([]SecretMeta, 0, len(secrets))
	for _, s := range secrets {
		metas = append(metas, metaOf(s))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"namespace": namespace,
		"secrets":   metas,
	})
}

// transitionalSecret is the one response shape that carries a value.
// TODO(D5/G9): delete together with the plaintext-by-name path.
type transitionalSecret struct {
	SecretMeta
	Value string `json:"value"`
}

func (h *Handlers) listSecretWithValue(w http.ResponseWriter, namespace, name string) {
	out := []transitionalSecret{}
	if sec, err := h.Store.GetSecret(namespace, name); err == nil {
		out = append(out, transitionalSecret{SecretMeta: metaOf(*sec), Value: sec.Value})
		h.Store.AddAuditEntry("SECRET_READ", "api", namespace+"/"+name)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"namespace": namespace,
		"secrets":   out,
	})
}

// ---------------------------------------------------------------------------
// Handler: POST /v1/secrets/{namespace}/{name}/use
// ---------------------------------------------------------------------------

// UseSecretRequest is the JSON body for using a secret.
type UseSecretRequest struct {
	Action  string                 `json:"action"`
	Agent   string                 `json:"agent"`
	Purpose string                 `json:"purpose"`
	Params  map[string]interface{} `json:"params"`
}

// UseSecret handles POST /v1/secrets/{namespace}/{name}/use.
func (h *Handlers) UseSecret(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	name := r.PathValue("name")

	var req UseSecretRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Action == "" {
		writeError(w, newAppError(http.StatusBadRequest, "ValidationError", "'action' is required"))
		return
	}
	if req.Agent == "" {
		writeError(w, newAppError(http.StatusBadRequest, "ValidationError", "'agent' is required"))
		return
	}

	secret, err := h.Store.GetSecret(namespace, name)
	if err != nil {
		writeError(w, err)
		return
	}

	// Execute the action (stub - in production this would run real actions)
	result := map[string]interface{}{
		"action":        req.Action,
		"status":        "completed",
		"secret_leased": true,
		"secret_len":    len(secret.Value),
		"message":       "action executed; secret NOT returned in response",
	}

	h.Store.AddAuditEntry("SECRET_USE", req.Agent, namespace+"/"+name+" action="+req.Action)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":     true,
		"action": req.Action,
		"result": result,
	})
}

// ---------------------------------------------------------------------------
// Handler: POST /v1/secrets/{namespace}/{name}/revoke
// ---------------------------------------------------------------------------

// RevokeSecret handles POST /v1/secrets/{namespace}/{name}/revoke.
func (h *Handlers) RevokeSecret(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	name := r.PathValue("name")

	if err := h.Store.RevokeSecret(namespace, name); err != nil {
		writeError(w, err)
		return
	}

	h.Store.AddAuditEntry("SECRET_REVOKE", "api", namespace+"/"+name)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":        true,
		"namespace": namespace,
		"name":      name,
	})
}

// ---------------------------------------------------------------------------
// Handler: DELETE /v1/secrets/{namespace}/{name}
// ---------------------------------------------------------------------------

// DeleteSecret handles DELETE /v1/secrets/{namespace}/{name}.
func (h *Handlers) DeleteSecret(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	name := r.PathValue("name")

	if err := h.Store.DeleteSecret(namespace, name); err != nil {
		writeError(w, err)
		return
	}

	h.Store.AddAuditEntry("SECRET_DELETE", "api", namespace+"/"+name)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":        true,
		"namespace": namespace,
		"name":      name,
	})
}

// ---------------------------------------------------------------------------
// Handler: POST /v1/rotate
// ---------------------------------------------------------------------------

// RotateRequest is the JSON body for key rotation.
type RotateRequest struct {
	Target string `json:"target"` // "master" or "dek"
}

// Rotate handles POST /v1/rotate.
func (h *Handlers) Rotate(w http.ResponseWriter, r *http.Request) {
	var req RotateRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	switch req.Target {
	case "master":
		h.Store.RotateMasterKey()
	case "dek":
		h.Store.RotateDEK()
	default:
		writeError(w, newAppError(http.StatusBadRequest, "ValidationError", "target must be 'master' or 'dek'"))
		return
	}

	h.Store.AddAuditEntry("KEY_ROTATE", "api", "target="+req.Target)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":        true,
		"target":    req.Target,
		"key_epoch": h.Store.KeyEpoch(),
	})
}

// ---------------------------------------------------------------------------
// Handler: GET /v1/audit
// ---------------------------------------------------------------------------

// Audit handles GET /v1/audit.
func (h *Handlers) Audit(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil {
			limit = parsed
		}
	}
	if limit < 1 {
		writeError(w, newAppError(http.StatusBadRequest, "ValidationError", "'limit' must be >= 1"))
		return
	}
	if limit > 1000 {
		writeError(w, newAppError(http.StatusBadRequest, "ValidationError", "'limit' must be <= 1000"))
		return
	}

	entries := h.Store.GetAuditLog(limit)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
	})
}

// ---------------------------------------------------------------------------
// Handler: POST /v1/audit/verify
// ---------------------------------------------------------------------------

// AuditVerify handles POST /v1/audit/verify.
func (h *Handlers) AuditVerify(w http.ResponseWriter, r *http.Request) {
	ok := h.Store.VerifyAuditChain()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok": ok,
	})
}

// ---------------------------------------------------------------------------
// Handler: POST /v1/policy/simulate
// ---------------------------------------------------------------------------

// SimulateRequest is the JSON body for policy simulation.
type SimulateRequest struct {
	Agent     string `json:"agent"`
	Namespace string `json:"namespace"`
	Purpose   string `json:"purpose"`
	Action    string `json:"action"`
}

// PolicySimulate handles POST /v1/policy/simulate.
func (h *Handlers) PolicySimulate(w http.ResponseWriter, r *http.Request) {
	var req SimulateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Agent == "" {
		writeError(w, newAppError(http.StatusBadRequest, "ValidationError", "'agent' is required"))
		return
	}
	if req.Namespace == "" {
		writeError(w, newAppError(http.StatusBadRequest, "ValidationError", "'namespace' is required"))
		return
	}
	if req.Action == "" {
		req.Action = "read"
	}

	result := h.Store.SimulatePolicy(req.Agent, req.Namespace, req.Purpose, req.Action)
	writeJSON(w, http.StatusOK, result)
}

// ---------------------------------------------------------------------------
// Handler: GET /v1/actions (list registered actions)
// ---------------------------------------------------------------------------

// ListActions handles GET /v1/actions.
func (h *Handlers) ListActions(w http.ResponseWriter, r *http.Request) {
	actions := []map[string]interface{}{
		{"name": "echo", "description": "Diagnostic action. Confirms lease worked; secret NEVER returned."},
		{"name": "http_get_with_auth", "description": "GET a URL with the leased secret as a Bearer token."},
		{"name": "http_post_with_auth", "description": "POST to a URL with the leased secret as a Bearer token."},
		{"name": "openai_chat", "description": "POST to an OpenAI-compatible /v1/chat/completions endpoint."},
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"actions": actions,
	})
}
