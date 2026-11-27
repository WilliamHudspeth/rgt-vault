// Package handlers implements the HTTP request handlers of the rgt-vault
// server on top of the real vault (internal/vault): the Go port of the
// routes in python/server/app.py.
//
// Every endpoint maps an HTTP request onto a vault method, so the ABAC
// policy, the rate limiter, honeytokens, the approval gate and the
// hash-chained audit log apply exactly as they do for in-process callers.
// Secret values never cross the HTTP boundary, with ONE documented
// exception: the transitional exact-name lookup on GET /v1/secrets
// (decision D5, see listSecretWithValue).
//
// Identity is still the shared bearer token plus a self-asserted "agent"
// field, as in Python. Per-agent identity is batch H1.
package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"rgt-vault-server/internal/actions"
	"rgt-vault-server/internal/approval"
	"rgt-vault-server/internal/capabilities"
	"rgt-vault-server/internal/hooks/pyfmt"
	"rgt-vault-server/internal/store"
	"rgt-vault-server/internal/vault"
)

// Version is reported by /healthz outside production.
const Version = "0.3.0"

// Handlers holds the HTTP handlers and their dependencies.
type Handlers struct {
	// Vault is the open vault. Required.
	Vault *vault.Vault
	// Actions backs POST /v1/secrets/{ns}/{name}/use and GET /v1/actions.
	// Nil means no action is registered.
	Actions *actions.Registry
	// Capabilities is listed by /v1/capabilities*. Nil means the vault's
	// registry if it is a *capabilities.Registry, else none.
	Capabilities *capabilities.Registry
	// Broker serves /v1/requests*. Nil means no live approval: those
	// endpoints answer 409, as in Python.
	Broker *approval.Broker
}

func (h *Handlers) capabilityList() []*capabilities.Spec {
	reg := h.Capabilities
	if reg == nil && h.Vault != nil {
		reg, _ = h.Vault.Capabilities().(*capabilities.Registry)
	}
	if reg == nil {
		return nil
	}
	return reg.List()
}

// ---------------------------------------------------------------------------
// Authentication context (set by the server's auth middleware)
// ---------------------------------------------------------------------------

// Scope is the token scope a request authenticated with.
type Scope int

const (
	// ScopeNone: the request did not authenticate (public route).
	ScopeNone Scope = iota
	// ScopeAgent: the agent bearer token (every /v1 route but /v1/requests*).
	ScopeAgent
	// ScopeOperator: the operator token (/v1/requests* only).
	ScopeOperator
)

type authKey struct{}

type authInfo struct {
	tokenID string
	scope   Scope
}

// WithAuth returns ctx carrying the authenticated token id and scope.
func WithAuth(ctx context.Context, tokenID string, scope Scope) context.Context {
	return context.WithValue(ctx, authKey{}, authInfo{tokenID: tokenID, scope: scope})
}

// AuthFromContext returns the token id and scope stored by WithAuth.
func AuthFromContext(ctx context.Context) (tokenID string, scope Scope) {
	a, _ := ctx.Value(authKey{}).(authInfo)
	return a.tokenID, a.scope
}

// AuditHTTP writes one HTTP_API (agent scope) or HTTP_OPERATOR (operator
// scope) row per authenticated request, before the handler runs: token id,
// client IP, method and path (python require_token / require_operator_token).
// The token itself is never recorded. A failed audit write fails the request
// closed with a 500.
func (h *Handlers) AuditHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenID, scope := AuthFromContext(r.Context())
		if scope == ScopeNone || h.Vault == nil {
			next.ServeHTTP(w, r)
			return
		}
		event := "HTTP_API"
		if scope == ScopeOperator {
			event = "HTTP_OPERATOR"
		}
		client, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || client == "" {
			client = "?"
		}
		details := "token=" + tokenID + " ip=" + client + " " + r.Method + " " + r.URL.Path
		if err := h.Vault.Audit(r.Context(), event, sql.NullString{}, details, sql.NullString{}); err != nil {
			writeError(w, r, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("ERROR: failed to write JSON response: %v", err)
	}
}

const maxBodyMsg = "request body too large"

// decodeJSON decodes exactly one JSON object from the body into dst.
//
//   - malformed JSON, unknown fields or trailing data: 400 (B3 hardening;
//     the message never quotes the request);
//   - a field of the wrong type: 422, naming only the (known) field;
//   - a body over the server limit: 413.
//
// Numbers are decoded as json.Number so integer payloads keep their exact
// form (the capability audit context_hash depends on it).
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil {
		writeError(w, r, badRequest("invalid JSON body"))
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	dec.UseNumber()
	err := dec.Decode(dst)
	if err == nil {
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
		writeError(w, r, newAppError(http.StatusRequestEntityTooLarge, "RequestTooLarge", maxBodyMsg))
		return false
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) && typeErr.Field != "" && knownField(dst, typeErr.Field) {
		writeError(w, r, unprocessable("invalid type for field '"+typeErr.Field+"'"))
		return false
	}
	writeError(w, r, badRequest("invalid JSON body"))
	return false
}

// knownField reports whether name is a top-level JSON field of *dst, so a
// 422 message only ever names a field from our own schema.
func knownField(dst any, name string) bool {
	t := reflect.TypeOf(dst)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return false
	}
	for i := 0; i < t.NumField(); i++ {
		tag := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if tag == name {
			return true
		}
	}
	return false
}

// required returns a 422 naming the first missing field, or nil.
func required(fields ...namedField) *AppError {
	for _, f := range fields {
		if f.missing {
			return unprocessable("field '" + f.name + "' is required")
		}
	}
	return nil
}

type namedField struct {
	name    string
	missing bool
}

func field[T any](name string, p *T) namedField { return namedField{name: name, missing: p == nil} }

func deref[T any](p *T, def T) T {
	if p == nil {
		return def
	}
	return *p
}

// queryInt parses an optional integer query parameter (FastAPI: 422 when
// it is not an integer).
func queryInt(r *http.Request, name string, def int) (int, *AppError) {
	s := r.URL.Query().Get(name)
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, unprocessable("query parameter '" + name + "' must be an integer")
	}
	return n, nil
}

func queryDefault(r *http.Request, name, def string) string {
	if v, ok := r.URL.Query()[name]; ok && len(v) > 0 {
		return v[0]
	}
	return def
}

// ---------------------------------------------------------------------------
// GET /healthz, XML policy stubs
// ---------------------------------------------------------------------------

// HealthCheck returns server health information. No auth required.
func (h *Handlers) HealthCheck(w http.ResponseWriter, r *http.Request) {
	version := Version
	if os.Getenv("APP_ENV") == "production" {
		version = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"vault_id":  h.Vault.VaultID(),
		"key_epoch": h.Vault.KeyEpoch(),
		"actions":   h.actionNames(),
		"version":   version,
	})
}

func (h *Handlers) actionNames() []string {
	out := []string{}
	if h.Actions != nil {
		for _, s := range h.Actions.List() {
			out = append(out, s.Name)
		}
	}
	return out
}

// BlockXMLPolicy serves restrictive policies with a 404 status and disables caching.
func (h *Handlers) BlockXMLPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
  <site-control permitted-cross-domain-policies="none"/>
</cross-domain-policy>`))
}

// ---------------------------------------------------------------------------
// POST /v1/secrets
// ---------------------------------------------------------------------------

// SetSecretRequest is the JSON body of POST /v1/secrets (python
// SetSecretBody). Absent optional fields take Python's defaults.
type SetSecretRequest struct {
	Name       *string `json:"name"`
	Value      *string `json:"value"`
	Namespace  *string `json:"namespace"`
	Agent      *string `json:"agent"`
	Purpose    *string `json:"purpose"`
	Note       *string `json:"note"`
	Require2FA *bool   `json:"require_2fa"`
}

// SetSecret handles POST /v1/secrets.
func (h *Handlers) SetSecret(w http.ResponseWriter, r *http.Request) {
	var req SetSecretRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if e := required(field("name", req.Name), field("value", req.Value)); e != nil {
		writeError(w, r, e)
		return
	}
	ns := deref(req.Namespace, vault.DefaultNamespace)
	value := []byte(*req.Value)
	err := h.Vault.SetSecret(r.Context(), vault.SetSecretRequest{
		Name:       *req.Name,
		Namespace:  ns,
		Agent:      deref(req.Agent, "cli"),
		Purpose:    deref(req.Purpose, ""),
		Value:      value,
		Note:       deref(req.Note, ""),
		Require2FA: deref(req.Require2FA, false),
	})
	for i := range value {
		value[i] = 0
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "namespace": ns, "name": *req.Name})
}

// ---------------------------------------------------------------------------
// GET /v1/secrets (list)
// ---------------------------------------------------------------------------

// ListSecrets handles GET /v1/secrets?namespace=&agent=&purpose=&limit=&offset=
// (python list_secrets). The list never contains secret values.
//
// Go clients (CLI list, TUI, MCP) do not send agent; it defaults to "cli",
// the Python CLI's default agent, and namespace defaults to "default".
// Both are still subject to the ABAC policy.
func (h *Handlers) ListSecrets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	namespace := queryDefault(r, "namespace", vault.DefaultNamespace)
	agent := queryDefault(r, "agent", "cli")

	if _, ok := q["name"]; ok {
		h.listSecretWithValue(w, r, namespace, q.Get("name"), agent)
		return
	}

	limit, e := queryInt(r, "limit", vault.DefaultListSize)
	if e == nil {
		var offset int
		if offset, e = queryInt(r, "offset", 0); e == nil {
			switch {
			case limit < 1 || limit > 1000:
				e = badRequest("'limit' must be between 1 and 1000.")
			case offset < 0:
				e = badRequest("'offset' must be >= 0.")
			default:
				items, err := h.Vault.ListSecrets(r.Context(), vault.ListRequest{
					Namespace: namespace, Agent: agent, Purpose: q.Get("purpose"),
					Limit: limit, Offset: offset,
				})
				if err != nil {
					writeError(w, r, err)
					return
				}
				if items == nil {
					items = []store.SecretInfo{}
				}
				writeJSON(w, http.StatusOK, map[string]any{"namespace": namespace, "secrets": items})
				return
			}
		}
	}
	writeError(w, r, e)
}

// D5PurposeDefault is the purpose recorded for the transitional plaintext
// lookup when the caller gives none.
const D5PurposeDefault = "cli get"

// listSecretWithValue serves GET /v1/secrets?name=<exact>.
//
// TODO(D5/H1): transitional plaintext path. The Go CLI `get` and the MCP
// `lease_secret` tool read a value through this route (go/cmd/rgt-vault
// commands.go runGet, go/internal/mcp lease_secret). It is NOT a raw read:
// it goes through vault.Lease, so the hook, rate limit, honeytokens, ABAC
// "read" for (agent, namespace, purpose), the approval gate (and its 2FA)
// and the LEASE_GRANTED/LEASE_RETURNED audit rows all apply, and a
// SECRET_READ row records that the value left the process over HTTP. It is
// still a plaintext-returning route behind the shared agent token, so it is
// removed once an operator scope exists (H1) and `get` becomes an offline,
// operator-only read (G10).
//
// A secret that does not exist (or was revoked) is an empty list, not an
// error, so the CLI prints its own "not found".
func (h *Handlers) listSecretWithValue(w http.ResponseWriter, r *http.Request, namespace, name, agent string) {
	purpose := queryDefault(r, "purpose", D5PurposeDefault)
	var value string
	var notUTF8 bool
	err := h.Vault.Lease(r.Context(), vault.LeaseRequest{
		Name: name, Namespace: namespace, Agent: agent, Purpose: purpose,
	}, func(secret []byte) error {
		if !utf8.Valid(secret) {
			notUTF8 = true
			return nil
		}
		value = string(secret)
		return nil
	})
	if errors.Is(err, vault.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"namespace": namespace, "secrets": []any{}})
		return
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	if notUTF8 {
		writeError(w, r, badRequest("secret value is not valid UTF-8 and cannot be returned as JSON"))
		return
	}
	tokenID, _ := AuthFromContext(r.Context())
	details := "Agent: " + agent + ", Namespace: " + namespace + ", Purpose: " + purpose +
		", Route: GET /v1/secrets?name= (D5 plaintext), token=" + tokenID
	if err := h.Vault.Audit(r.Context(), "SECRET_READ", store.Name(name), details, sql.NullString{String: agent, Valid: true}); err != nil {
		writeError(w, r, err) // fail closed: no audit row, no value
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"namespace": namespace,
		"secrets":   []map[string]string{{"name": name, "namespace": namespace, "value": value}},
	})
}

// ---------------------------------------------------------------------------
// GET /v1/secrets/{namespace}/{name}  (fingerprint; Go-only, RGT-502)
// ---------------------------------------------------------------------------

// GetSecret handles GET /v1/secrets/{namespace}/{name}[?version=N]: the
// ciphertext fingerprint (python get_fingerprint, sha256(ciphertext)[:8]).
// It never returns the value and, as in Python, is not policy-gated (a
// fingerprint leaks no plaintext); honeytokens still trigger.
func (h *Handlers) GetSecret(w http.ResponseWriter, r *http.Request) {
	namespace, name := r.PathValue("namespace"), r.PathValue("name")
	version, e := queryInt(r, "version", 0)
	if e == nil && r.URL.Query().Has("version") && version < 1 {
		e = badRequest("'version' must be >= 1.")
	}
	if e != nil {
		writeError(w, r, e)
		return
	}
	fp, err := h.Vault.Fingerprint(r.Context(), namespace, name, int64(version))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"namespace": namespace, "name": name, "fingerprint": fp})
}

// ---------------------------------------------------------------------------
// POST /v1/secrets/{namespace}/{name}/use
// ---------------------------------------------------------------------------

// UseSecretRequest is the JSON body of the use endpoint (python UseBody).
type UseSecretRequest struct {
	Action  *string        `json:"action"`
	Agent   *string        `json:"agent"`
	Purpose *string        `json:"purpose"`
	Params  map[string]any `json:"params"`
}

// UseSecret handles POST /v1/secrets/{namespace}/{name}/use: lease the
// secret server-side, run a registered action on it, return only the
// action's result (python use_secret).
func (h *Handlers) UseSecret(w http.ResponseWriter, r *http.Request) {
	namespace, name := r.PathValue("namespace"), r.PathValue("name")
	var req UseSecretRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if e := required(field("action", req.Action), field("agent", req.Agent)); e != nil {
		writeError(w, r, e)
		return
	}
	if h.Actions == nil {
		writeError(w, r, capabilities.ActionNotFound(*req.Action, nil))
		return
	}
	spec, err := h.Actions.Get(*req.Action)
	if err != nil {
		writeError(w, r, err) // 404
		return
	}
	if req.Params == nil {
		req.Params = map[string]any{}
	}
	if err := spec.ValidateParams(req.Params); err != nil {
		// A malformed param set is a client error, not a server fault.
		writeError(w, r, badRequest(err.Error()))
		return
	}
	var result map[string]any
	err = h.Vault.Lease(r.Context(), vault.LeaseRequest{
		Name: name, Namespace: namespace, Agent: *req.Agent, Purpose: deref(req.Purpose, ""),
	}, func(secret []byte) error {
		var aerr error
		result, aerr = h.Actions.Execute(r.Context(), *req.Action, secret, req.Params)
		return aerr
	})
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "action": *req.Action, "result": result})
}

// ---------------------------------------------------------------------------
// POST /v1/secrets/{namespace}/{name}/revoke
// ---------------------------------------------------------------------------

// RevokeSecret handles POST /v1/secrets/{namespace}/{name}/revoke?agent=
// (python revoke; agent defaults to "system"). Any request body is ignored.
func (h *Handlers) RevokeSecret(w http.ResponseWriter, r *http.Request) {
	namespace, name := r.PathValue("namespace"), r.PathValue("name")
	agent := queryDefault(r, "agent", vault.SystemAgent)
	if err := h.Vault.RevokeSecret(r.Context(), namespace, name, agent); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "namespace": namespace, "name": name})
}

// ---------------------------------------------------------------------------
// POST /v1/rotate
// ---------------------------------------------------------------------------

// RotateRequest is the JSON body for key rotation.
type RotateRequest struct {
	Target *string `json:"target"` // "master" or "dek"
}

// Rotate handles POST /v1/rotate (python rotate).
func (h *Handlers) Rotate(w http.ResponseWriter, r *http.Request) {
	var req RotateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if e := required(field("target", req.Target)); e != nil {
		writeError(w, r, e)
		return
	}
	var err error
	switch *req.Target {
	case "master":
		err = h.Vault.RotateMaster(r.Context())
	case "dek":
		err = h.Vault.RotateDEK(r.Context())
	default:
		err = badRequest("target must be 'master' or 'dek'")
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "target": *req.Target, "key_epoch": h.Vault.KeyEpoch()})
}

// ---------------------------------------------------------------------------
// GET /v1/audit, POST /v1/audit/verify
// ---------------------------------------------------------------------------

// AuditEntry is one audit_logs row as Python's dict(sqlite3.Row) renders it
// (NULL columns are JSON null).
type AuditEntry struct {
	ID         int64   `json:"id"`
	Action     string  `json:"action"`
	SecretName *string `json:"secret_name"`
	Timestamp  string  `json:"timestamp"`
	Details    *string `json:"details"`
	PrevHash   *string `json:"prev_hash"`
	EntryHash  string  `json:"entry_hash"`
	PolicyHash *string `json:"policy_hash"`
	AgentID    *string `json:"agent_id"`
}

func nullable(s sql.NullString) *string {
	if !s.Valid {
		return nil
	}
	v := s.String
	return &v
}

func entryOf(r store.AuditRow) AuditEntry {
	return AuditEntry{
		ID: r.ID, Action: r.Action, SecretName: nullable(r.SecretName), Timestamp: r.Timestamp,
		Details: nullable(r.Details), PrevHash: nullable(r.PrevHash), EntryHash: r.EntryHash,
		PolicyHash: nullable(r.PolicyHash), AgentID: nullable(r.AgentID),
	}
}

// rowCapability returns the "capability" field of a row whose details are a
// JSON object (the CAPABILITY_EXECUTED / _DENIED / _FAILED and
// HOOK_CAPABILITY rows written by vault.ExecuteCapability).
func rowCapability(r store.AuditRow) (string, bool) {
	if !r.Details.Valid || !strings.HasPrefix(r.Details.String, "{") {
		return "", false
	}
	var d struct {
		Capability *string `json:"capability"`
	}
	if json.Unmarshal([]byte(r.Details.String), &d) != nil || d.Capability == nil {
		return "", false
	}
	return *d.Capability, true
}

// Audit handles GET /v1/audit?limit=50[&capability=NAME], newest first
// (python audit). capability= (RGT-166) keeps only the capability rows
// that name that capability; limit then counts matching rows.
func (h *Handlers) Audit(w http.ResponseWriter, r *http.Request) {
	limit, e := queryInt(r, "limit", 50)
	switch {
	case e != nil:
	case limit < 1:
		e = badRequest("'limit' must be >= 1.")
	case limit > 1000:
		e = badRequest("'limit' must be <= 1000. Use /v1/audit/verify and a tail query tool to walk larger histories.")
	}
	if e != nil {
		writeError(w, r, e)
		return
	}
	capFilter, filtered := r.URL.Query()["capability"]
	fetch := limit
	if filtered {
		fetch = -1 // filter over the whole log
	}
	rows, err := h.Vault.AuditLog(r.Context(), fetch)
	if err != nil {
		writeError(w, r, err)
		return
	}
	entries := make([]AuditEntry, 0, min(len(rows), limit))
	for _, row := range rows {
		if len(entries) == limit {
			break
		}
		if filtered {
			if c, ok := rowCapability(row); !ok || c != capFilter[0] {
				continue
			}
		}
		entries = append(entries, entryOf(row))
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// AuditVerify handles POST /v1/audit/verify.
func (h *Handlers) AuditVerify(w http.ResponseWriter, r *http.Request) {
	ok, err := h.Vault.VerifyAuditChain(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok})
}

// ---------------------------------------------------------------------------
// POST /v1/policy/simulate
// ---------------------------------------------------------------------------

// SimulateRequest is the JSON body for policy simulation (python SimulateBody).
type SimulateRequest struct {
	Agent     *string `json:"agent"`
	Namespace *string `json:"namespace"`
	Purpose   *string `json:"purpose"`
	Action    *string `json:"action"`
}

// PolicySimulate handles POST /v1/policy/simulate: the ABAC decision
// {"allowed", "reason", "matched_rule"} (python simulate).
func (h *Handlers) PolicySimulate(w http.ResponseWriter, r *http.Request) {
	var req SimulateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if e := required(field("agent", req.Agent), field("namespace", req.Namespace)); e != nil {
		writeError(w, r, e)
		return
	}
	d, err := h.Vault.Simulate(r.Context(), *req.Agent, *req.Namespace, deref(req.Purpose, ""), deref(req.Action, "read"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// ---------------------------------------------------------------------------
// /v1/requests (operator approval endpoints; operator token)
// ---------------------------------------------------------------------------

// requireOperator refuses a request that did not authenticate with the
// operator scope (defence in depth behind the auth middleware) and one made
// while no broker is active (409, as in Python).
func (h *Handlers) requireOperator(w http.ResponseWriter, r *http.Request) bool {
	if _, scope := AuthFromContext(r.Context()); scope != ScopeOperator {
		writeError(w, r, newAppError(http.StatusForbidden, "ServerAuthError", "operator token required"))
		return false
	}
	if h.Broker == nil {
		writeError(w, r, newAppError(http.StatusConflict, "Conflict", "No approval broker is active on this server."))
		return false
	}
	return true
}

// ListRequests handles GET /v1/requests: the pending approval requests,
// oldest first. A request carries no secret value.
func (h *Handlers) ListRequests(w http.ResponseWriter, r *http.Request) {
	if !h.requireOperator(w, r) {
		return
	}
	pending := h.Broker.List()
	out := make([]map[string]any, 0, len(pending))
	for _, p := range pending {
		out = append(out, map[string]any{
			"request_id":  p.RequestID,
			"agent":       p.Agent,
			"namespace":   p.Namespace,
			"secret_name": p.SecretName,
			"purpose":     p.Purpose,
			"action":      p.Action,
			"require_2fa": p.Require2FA,
			// Python: time.time() float seconds.
			"created_at": float64(p.CreatedAt.UnixNano()) / 1e9,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

// ApproveRequest is the JSON body of the approve endpoint (python ApproveBody).
type ApproveRequest struct {
	TOTPCode *string `json:"totp_code"`
	Operator *string `json:"operator"`
}

// DenyRequest is the JSON body of the deny endpoint (python DenyBody).
type DenyRequest struct {
	Reason   *string `json:"reason"`
	Operator *string `json:"operator"`
}

// decodeOptionalJSON accepts an empty body as {} (every field optional).
func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return true
	}
	return decodeJSON(w, r, dst)
}

// Approve handles POST /v1/requests/{id}/approve. A request flagged
// require_2fa needs a valid, unused TOTP code (the broker's verifier).
func (h *Handlers) Approve(w http.ResponseWriter, r *http.Request) {
	if !h.requireOperator(w, r) {
		return
	}
	var req ApproveRequest
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	if err := h.Broker.Approve(id, deref(req.TOTPCode, ""), deref(req.Operator, "operator")); err != nil {
		writeError(w, r, err) // ApprovalError -> 400
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request_id": id, "decision": "approved"})
}

// Deny handles POST /v1/requests/{id}/deny.
func (h *Handlers) Deny(w http.ResponseWriter, r *http.Request) {
	if !h.requireOperator(w, r) {
		return
	}
	var req DenyRequest
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	if err := h.Broker.Deny(id, deref(req.Reason, "denied by operator"), deref(req.Operator, "operator")); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "request_id": id, "decision": "denied"})
}

// ---------------------------------------------------------------------------
// /v1/capabilities*
// ---------------------------------------------------------------------------

// ExecuteCapabilityRequest is the JSON body of /v1/capabilities/execute
// (python ExecuteCapabilityBody).
type ExecuteCapabilityRequest struct {
	Capability        *string        `json:"capability"`
	AgentID           *string        `json:"agent_id"`
	CapabilityToken   *string        `json:"capability_token"`
	Payload           map[string]any `json:"payload"`
	CapabilityVersion *int           `json:"capability_version"`
}

// ExecuteCapability handles POST /v1/capabilities/execute (python
// execute_capability): every check of vault.ExecuteCapability, in Python's
// order, with Python's audit rows.
//
// As in Python only validation (400), version (400), policy (403) and
// not-found (404) errors keep their message; every other failure, including
// a handler error, is a sanitized 500 so a handler's error text can never
// leak a secret. A rate-limit refusal is 429 (Python: a sanitized 500).
func (h *Handlers) ExecuteCapability(w http.ResponseWriter, r *http.Request) {
	var req ExecuteCapabilityRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if e := required(field("capability", req.Capability), field("agent_id", req.AgentID),
		field("capability_token", req.CapabilityToken)); e != nil {
		writeError(w, r, e)
		return
	}
	version := deref(req.CapabilityVersion, 1)
	if version < 1 {
		// Version 0 would silently mean 1 inside the vault.
		writeError(w, r, badRequest("capability_version must be >= 1"))
		return
	}
	result, err := h.Vault.ExecuteCapability(r.Context(), vault.CapabilityRequest{
		Capability: *req.Capability,
		Version:    version,
		Agent:      *req.AgentID,
		Token:      *req.CapabilityToken,
		Payload:    req.Payload,
	})
	if err != nil {
		writeError(w, r, executeError(*req.Capability, err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "capability": *req.Capability, "result": result})
}

func executeError(capability string, err error) error {
	if errors.Is(err, vault.ErrCapabilityFailed) {
		// The handler's own error: never echoed.
		log.Printf("ERROR: capability %q failed; details suppressed from response: %v", capability, err)
		return newAppError(http.StatusInternalServerError, "ActionExecutionError",
			"capability "+pyfmt.Repr(capability)+" failed; see server logs for details")
	}
	for _, kind := range []error{vault.ErrValidation, vault.ErrCapabilityVersion, vault.ErrPolicyDenied,
		vault.ErrCapabilityNotFound, vault.ErrRateLimited} {
		if errors.Is(err, kind) {
			return err
		}
	}
	log.Printf("ERROR: capability %q raised an unhandled error; details suppressed from response: %v", capability, err)
	return newAppError(http.StatusInternalServerError, "ActionExecutionError",
		"capability "+pyfmt.Repr(capability)+" failed; see server logs for details")
}

type capabilityView struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	SupportedVersions []int    `json:"supported_versions"`
	ParamsSchema      []string `json:"params_schema"`
}

func viewOf(s *capabilities.Spec) capabilityView {
	versions := s.SupportedVersions()
	sort.Ints(versions)
	return capabilityView{Name: s.Name, Description: s.Description, SupportedVersions: versions, ParamsSchema: schemaKeys(s.Schema)}
}

// schemaKeys is python list(spec.params_schema): the parameter names of a
// ParamList, or the top-level keys of a JSON-schema dict (sorted; Go maps
// have no insertion order).
func schemaKeys(s capabilities.Schema) []string {
	switch v := s.(type) {
	case capabilities.ParamList:
		return append([]string{}, v...)
	case capabilities.JSONSchema:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys
	default:
		return []string{}
	}
}

// ListCapabilities handles GET /v1/capabilities: every registered
// capability and the versions it supports (no handler bodies, no secrets).
func (h *Handlers) ListCapabilities(w http.ResponseWriter, r *http.Request) {
	out := []capabilityView{}
	for _, s := range h.capabilityList() {
		out = append(out, viewOf(s))
	}
	writeJSON(w, http.StatusOK, map[string]any{"capabilities": out})
}

// ListAuthorizedCapabilities handles GET /v1/capabilities/list?agent=
// [&namespace=*][&purpose=*]: the capabilities the ABAC policy allows the
// agent to execute (action = capability name).
func (h *Handlers) ListAuthorizedCapabilities(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if !q.Has("agent") {
		writeError(w, r, unprocessable("query parameter 'agent' is required"))
		return
	}
	agent := q.Get("agent")
	namespace := queryDefault(r, "namespace", "*")
	purpose := queryDefault(r, "purpose", "*")
	engine := h.Vault.Policy()
	out := []capabilityView{}
	for _, s := range h.capabilityList() {
		if engine.Evaluate(agent, namespace, purpose, s.Name).Allowed {
			out = append(out, viewOf(s))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent": agent, "capabilities": out})
}

// ---------------------------------------------------------------------------
// GET /v1/actions (Go-only)
// ---------------------------------------------------------------------------

// ListActions handles GET /v1/actions: the registered actions for /use.
func (h *Handlers) ListActions(w http.ResponseWriter, r *http.Request) {
	out := []map[string]any{}
	if h.Actions != nil {
		for _, s := range h.Actions.List() {
			schema := append([]string{}, s.ParamsSchema...)
			out = append(out, map[string]any{"name": s.Name, "description": s.Description, "params_schema": schema})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": out})
}
