// Package handlers implements the HTTP request handlers of the rgt-vault
// server on top of the real vault (internal/vault): the Go port of the
// routes in python/server/app.py.
//
// Every endpoint maps an HTTP request onto a vault method, so the ABAC
// policy, the rate limiter, honeytokens, the approval gate and the
// hash-chained audit log apply exactly as they do for in-process callers.
// Secret values never cross the HTTP boundary, with ONE documented
// exception: POST /v1/secrets/{ns}/{name}/lease, which needs a token with
// both the agent and the lease scope (RGT-504; see LeaseSecret).
//
// Identity (batch H1, identity.go): the ABAC subject is the agent bound to
// the caller's token in the per-agent token store; a request naming another
// agent is refused. Only the deprecated --legacy-shared-token mode keeps
// Python's self-asserted "agent" field.
package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"rgt-vault-server/internal/actions"
	"rgt-vault-server/internal/approval"
	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/capabilities"
	"rgt-vault-server/internal/hooks/pyfmt"
	"rgt-vault-server/internal/store"
	"rgt-vault-server/internal/validation"
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
	// AuditScanLimit overrides MaxAuditScan, the number of newest audit rows
	// a filtered GET /v1/audit examines (tests). Zero means MaxAuditScan.
	AuditScanLimit int
	// Notifier receives approval security events (bad and replayed TOTP
	// codes, lockouts, separation-of-duties refusals). Nil logs a warning.
	Notifier approval.Notifier

	// gated is the set of operations that wait for approval (SetGatedOps).
	gated gatedOps
	// events coalesces repeated security events (approvalflow.go).
	events eventLimiter
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

// publicRequest reports whether r is one of the unauthenticated routes
// (the auth middleware lets exactly these through without a principal).
func publicRequest(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		(r.URL.Path == "/healthz" || r.URL.Path == "/crossdomain.xml" || r.URL.Path == "/clientaccesspolicy.xml")
}

// requireScope is the handler's own authorization check, behind the auth
// middleware's route table (defence in depth, RGT-345): no authenticated
// principal is 401, a principal without ALL the scopes is 403 (and audited),
// each with an incident id. A handler reached without the middleware, or a
// route whose table entry went missing, therefore fails closed. The scopes
// match what the middleware requires for the route today; a legacy shared
// token holds every scope, so authenticated callers see no change.
func (h *Handlers) requireScope(w http.ResponseWriter, r *http.Request, need ...auth.Scope) bool {
	p, ok := PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, r, newAppError(http.StatusUnauthorized, "ServerAuthError", "invalid credentials"))
		return false
	}
	for _, sc := range need {
		if !p.Has(sc) {
			h.AuditDenied(r, p, "missing scope "+string(sc))
			writeError(w, r, newAppError(http.StatusForbidden, "AuthorizationError", "insufficient scope for this route"))
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// HTTP audit row (set by the server's auth middleware)
// ---------------------------------------------------------------------------

// AuditHTTP writes one HTTP_API (or HTTP_OPERATOR for /v1/requests*) row per
// authenticated request, before the handler runs: token id, client IP,
// method and path, with the token's agent in the agent_id column (python
// require_token / require_operator_token). The token itself is never
// recorded. A failed audit write fails the request closed with a 500.
func (h *Handlers) AuditHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFromContext(r.Context())
		if !ok {
			// Only the public routes have no caller. Anything else reaching
			// here without one means the auth middleware did not run: fail
			// closed rather than serve it unaudited.
			if publicRequest(r) {
				next.ServeHTTP(w, r)
				return
			}
			writeError(w, r, newAppError(http.StatusUnauthorized, "ServerAuthError", "invalid credentials"))
			return
		}
		if h.Vault == nil {
			next.ServeHTTP(w, r)
			return
		}
		event := "HTTP_API"
		if isOperatorRoute(RoutePath(r)) {
			event = "HTTP_OPERATOR"
		}
		agent := sql.NullString{}
		if p.Agent != "" {
			agent = sql.NullString{String: p.Agent, Valid: true}
		}
		details := "token=" + p.TokenID + " ip=" + ClientIP(r) + " " + r.Method + " " + AuditPath(r)
		if err := h.Vault.Audit(r.Context(), event, sql.NullString{}, details, agent); err != nil {
			writeError(w, r, err)
			return
		}
		// Pin the caller for the approval broker: a request made with this
		// token can never be approved with it (separation of duties).
		ctx := approval.WithRequester(r.Context(), approval.Identity{TokenID: p.TokenID, Agent: p.Agent})
		next.ServeHTTP(w, r.WithContext(ctx))
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

// Bounds on list endpoints and free-text request fields (H4: RGT-376,
// RGT-353, RGT-357). A client may not make the server walk or hold an
// arbitrarily large window, nor feed unbounded text to the policy engine,
// the audit log or the operator's screen.
const (
	// MaxListLimit is the largest page of GET /v1/secrets and /v1/audit.
	MaxListLimit = 1000
	// MaxListOffset is the largest offset of GET /v1/secrets. A deeper
	// window is refused (400) rather than scanned.
	MaxListOffset = 1_000_000
	// MaxAuditScan bounds how many of the NEWEST audit rows GET /v1/audit
	// examines when it filters (?capability=): the filter never reads the
	// whole log into memory.
	MaxAuditScan = 10_000
	// maxTextField is the cap of a free-text request field (purpose,
	// reason): the vault's purpose length.
	maxTextField = vault.MaxPurposeChars
	// maxTOTPCodeLen caps the totp_code of an approval (real codes have 6-8
	// digits). A longer value is refused before it reaches the verifier.
	maxTOTPCodeLen = 32
)

// queryPage parses limit and offset (FastAPI-style 422 for a non-integer, an
// integer too large for int included) and enforces the bounds above.
func queryPage(r *http.Request, defLimit int) (limit, offset int, e *AppError) {
	if limit, e = queryInt(r, "limit", defLimit); e != nil {
		return 0, 0, e
	}
	if offset, e = queryInt(r, "offset", 0); e != nil {
		return 0, 0, e
	}
	switch {
	case limit < 1 || limit > MaxListLimit:
		return 0, 0, badRequest("'limit' must be between 1 and " + strconv.Itoa(MaxListLimit) + ".")
	case offset < 0:
		return 0, 0, badRequest("'offset' must be >= 0.")
	case offset > MaxListOffset:
		return 0, 0, badRequest("'offset' must be <= " + strconv.Itoa(MaxListOffset) + ".")
	}
	return limit, offset, nil
}

// freeText validates a request-supplied free-text field (purpose, reason,
// filter): valid UTF-8, at most maxTextField characters, then the same
// allow-list as the vault's own purpose check (NFC, no control or format
// characters). The length is checked first so an oversized value is never
// normalised. The error never quotes the value.
func freeText(field, value string) *AppError { return freeTextIn(field, value, false) }

// multilineText is freeText for a field an operator writes by hand (the
// denial reason): line breaks and tabs are allowed (Python never validated
// the reason); every other control character is still refused.
func multilineText(field, value string) *AppError { return freeTextIn(field, value, true) }

func freeTextIn(field, value string, whitespace bool) *AppError {
	if !utf8.ValidString(value) {
		return badRequest("'" + field + "' must be valid UTF-8.")
	}
	if utf8.RuneCountInString(value) > maxTextField {
		return badRequest("'" + field + "' exceeds the maximum allowed length of " + strconv.Itoa(maxTextField) + " characters.")
	}
	check := value
	if whitespace {
		check = strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(value)
	}
	if _, err := validation.ValidateFreeText(check, maxTextField); err != nil {
		return badRequest("'" + field + "' contains characters that are not allowed.")
	}
	return nil
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
	if !h.requireScope(w, r, auth.ScopeAgent) {
		return
	}
	var req SetSecretRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if e := required(field("name", req.Name), field("value", req.Value)); e != nil {
		writeError(w, r, e)
		return
	}
	agent, ok := h.subject(w, r, req.Agent, "cli", false)
	if !ok {
		return
	}
	ns := deref(req.Namespace, vault.DefaultNamespace)
	p, _ := PrincipalFromContext(r.Context())
	if h.gated[approval.OpSet] {
		// The operator approves with a TOTP code when the secret already
		// requires 2FA or this version asks for it.
		need2FA := deref(req.Require2FA, false)
		if cur, err := h.Vault.Requires2FA(r.Context(), ns, *req.Name); err != nil {
			writeError(w, r, err)
			return
		} else if cur {
			need2FA = true
		}
		if !h.gate(w, r, approval.OpSet, agent, ns, *req.Name, deref(req.Purpose, ""), need2FA, deref(req.Purpose, ""), "write") {
			return
		}
	}
	value := []byte(*req.Value)
	err := h.Vault.SetSecret(r.Context(), vault.SetSecretRequest{
		Name:       *req.Name,
		Namespace:  ns,
		Agent:      agent,
		Purpose:    deref(req.Purpose, ""),
		Value:      value,
		Note:       deref(req.Note, ""),
		Require2FA: deref(req.Require2FA, false),
		// Only a per-agent token that carries the operator scope may drop
		// require_2fa from a secret. The legacy shared token never can: it
		// holds every scope, so the scope proves nothing there.
		AllowRequire2FADowngrade: p.Has(auth.ScopeOperator) && !p.Legacy,
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
// The subject is the token's agent (?agent= may only repeat it); with the
// legacy shared token it is ?agent=, default "cli" (the Python CLI's
// default). namespace defaults to "default". ABAC "list" applies.
//
// The transitional ?name= plaintext lookup (decision D5) is gone (RGT-504):
// it answers 400 and points at the lease endpoint.
func (h *Handlers) ListSecrets(w http.ResponseWriter, r *http.Request) {
	if !h.requireScope(w, r, auth.ScopeAgent) {
		return
	}
	q := r.URL.Query()
	namespace := queryDefault(r, "namespace", vault.DefaultNamespace)
	if _, ok := q["name"]; ok {
		writeError(w, r, badRequest("the name= filter was removed: read a value with POST /v1/secrets/{namespace}/{name}/lease (lease scope)"))
		return
	}
	agent, ok := h.querySubject(w, r, "agent", "cli", false)
	if !ok {
		return
	}

	limit, offset, e := queryPage(r, vault.DefaultListSize)
	if e != nil {
		writeError(w, r, e)
		return
	}
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
}

// ---------------------------------------------------------------------------
// POST /v1/secrets/{namespace}/{name}/lease  (plaintext; lease scope)
// ---------------------------------------------------------------------------

// LeasePurposeDefault is the purpose recorded for a lease when the caller
// gives none.
const LeasePurposeDefault = "cli get"

// LeaseRequest is the JSON body of the lease endpoint (all optional).
type LeaseRequest struct {
	Agent   *string `json:"agent"`
	Purpose *string `json:"purpose"`
}

// LeaseSecret handles POST /v1/secrets/{namespace}/{name}/lease: the one
// route that returns a secret value (Go CLI `get`, MCP `lease_secret`).
//
// It replaces the transitional GET /v1/secrets?name= (RGT-504): a POST, so
// the value is never tied to a cacheable or logged URL; it requires a token
// with BOTH the agent and the lease scope (enforced by the auth
// middleware), so an ordinary agent token can use secrets server-side but
// never read them; the subject is the token's agent. It goes through
// vault.Lease, so the hook, rate limit, honeytokens, ABAC "read", the
// approval gate (and its 2FA) and the LEASE_* audit rows all apply, and a
// SECRET_READ row records that the value left the process over HTTP.
//
// A secret that does not exist (or was revoked) is a 404.
func (h *Handlers) LeaseSecret(w http.ResponseWriter, r *http.Request) {
	if !h.requireScope(w, r, auth.ScopeAgent, auth.ScopeLease) {
		return
	}
	namespace, name := r.PathValue("namespace"), r.PathValue("name")
	var req LeaseRequest
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	agent, ok := h.subject(w, r, req.Agent, "cli", false)
	if !ok {
		return
	}
	purpose := deref(req.Purpose, LeasePurposeDefault)
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
	if err != nil {
		writeError(w, r, err)
		return
	}
	if notUTF8 {
		writeError(w, r, badRequest("secret value is not valid UTF-8 and cannot be returned as JSON"))
		return
	}
	p, _ := PrincipalFromContext(r.Context())
	details := "Agent: " + agent + ", Namespace: " + namespace + ", Purpose: " + purpose +
		", Route: POST /v1/secrets/{ns}/{name}/lease, token=" + p.TokenID
	if err := h.Vault.Audit(r.Context(), "SECRET_READ", store.Name(name), details, sql.NullString{String: agent, Valid: true}); err != nil {
		writeError(w, r, err) // fail closed: no audit row, no value
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]any{"namespace": namespace, "name": name, "value": value})
}

// ---------------------------------------------------------------------------
// GET /v1/secrets/{namespace}/{name}  (fingerprint; Go-only, RGT-502)
// ---------------------------------------------------------------------------

// errSecretNotFound is the ONE answer of the fingerprint route for a secret
// the caller may not see, one that does not exist, a revoked one and a
// missing version: no existence or version oracle across agents.
var errSecretNotFound = newAppError(http.StatusNotFound, "SecretNotFoundError", "secret not found")

// GetSecret handles GET /v1/secrets/{namespace}/{name}[?version=N][&purpose=]:
// the ciphertext fingerprint (python get_fingerprint, sha256(ciphertext)[:8]).
// It never returns the value.
//
// With per-agent tokens it is ABAC-gated like a list (action "read" for the
// token's agent, the namespace and ?purpose=), because a fingerprint still
// reveals that a secret and its versions exist (review of PR #53,
// MEDIUM-1). A denied request and a missing secret get the same 404; the
// denial is audited (AUTHZ_DENIED). The legacy shared-token mode keeps
// Python's ungated fingerprint.
func (h *Handlers) GetSecret(w http.ResponseWriter, r *http.Request) {
	if !h.requireScope(w, r, auth.ScopeAgent) {
		return
	}
	namespace, name := r.PathValue("namespace"), r.PathValue("name")
	version, e := queryInt(r, "version", 0)
	if e == nil && r.URL.Query().Has("version") && version < 1 {
		e = badRequest("'version' must be >= 1.")
	}
	if e != nil {
		writeError(w, r, e)
		return
	}
	if _, err := validation.ValidateNamespace(namespace); err != nil {
		writeError(w, r, err)
		return
	}
	if _, err := validation.ValidateName(name); err != nil {
		writeError(w, r, err)
		return
	}
	p, ok := PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, r, newAppError(http.StatusUnauthorized, "ServerAuthError", "invalid credentials"))
		return
	}
	if !p.Legacy {
		if _, ok := r.URL.Query()["agent"]; ok {
			if _, ok := h.querySubject(w, r, "agent", "", false); !ok {
				return
			}
		}
		purpose := r.URL.Query().Get("purpose")
		if e := freeText("purpose", purpose); e != nil {
			writeError(w, r, e)
			return
		}
		if d := h.Vault.Policy().Evaluate(p.Agent, namespace, purpose, "read"); !d.Allowed {
			h.AuditDenied(r, p, "policy denies fingerprint of "+namespace+"/"+name)
			writeError(w, r, errSecretNotFound)
			return
		}
	}
	fp, err := h.Vault.Fingerprint(r.Context(), namespace, name, int64(version))
	if errors.Is(err, vault.ErrNotFound) {
		writeError(w, r, errSecretNotFound)
		return
	}
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
	if !h.requireScope(w, r, auth.ScopeAgent) {
		return
	}
	namespace, name := r.PathValue("namespace"), r.PathValue("name")
	var req UseSecretRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if e := required(field("action", req.Action)); e != nil {
		writeError(w, r, e)
		return
	}
	// Python requires "agent"; the legacy mode keeps that. With per-agent
	// tokens it is optional and may only repeat the token's agent.
	if p, _ := PrincipalFromContext(r.Context()); p.Legacy && req.Agent == nil {
		writeError(w, r, required(field("agent", req.Agent)))
		return
	}
	agent, ok := h.subject(w, r, req.Agent, "", false)
	if !ok {
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
		Name: name, Namespace: namespace, Agent: agent, Purpose: deref(req.Purpose, ""),
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
	if !h.requireScope(w, r, auth.ScopeAgent) {
		return
	}
	namespace, name := r.PathValue("namespace"), r.PathValue("name")
	agent, ok := h.querySubject(w, r, "agent", vault.SystemAgent, false)
	if !ok {
		return
	}
	if h.gated[approval.OpRevoke] {
		cur, err := h.Vault.Requires2FA(r.Context(), namespace, name)
		if err != nil {
			writeError(w, r, err)
			return
		}
		if !h.gate(w, r, approval.OpRevoke, agent, namespace, name, "", cur, "*", "revoke") {
			return
		}
	}
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
	if !h.requireScope(w, r, auth.ScopeOperator) {
		return
	}
	var req RotateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if e := required(field("target", req.Target)); e != nil {
		writeError(w, r, e)
		return
	}
	if *req.Target == "master" || *req.Target == "dek" {
		p, _ := PrincipalFromContext(r.Context())
		agent := p.Agent
		if agent == "" {
			agent = vault.SystemAgent
		}
		// Rotation is operator-only; the approver must be a DIFFERENT
		// operator token. 2FA applies when a TOTP verifier is configured.
		need2FA := h.Broker != nil && h.Broker.HasTOTP()
		if !h.gate(w, r, approval.OpRotate, agent, "_admin", *req.Target, "rotate_"+*req.Target, need2FA, "", "") {
			return
		}
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
// that name that capability; limit then counts matching rows among the
// newest MaxAuditScan rows; when that window is exhausted before limit
// matches were found the answer adds "truncated": true and "scanned": N.
func (h *Handlers) Audit(w http.ResponseWriter, r *http.Request) {
	if !h.requireScope(w, r, auth.ScopeAudit) {
		return
	}
	limit, e := queryInt(r, "limit", 50)
	switch {
	case e != nil:
	case limit < 1:
		e = badRequest("'limit' must be >= 1.")
	case limit > MaxListLimit:
		e = badRequest("'limit' must be <= " + strconv.Itoa(MaxListLimit) + ". Use /v1/audit/verify and a tail query tool to walk larger histories.")
	}
	if e != nil {
		writeError(w, r, e)
		return
	}
	capFilter, filtered := r.URL.Query()["capability"]
	fetch := limit
	if filtered {
		if e := freeText("capability", capFilter[0]); e != nil {
			writeError(w, r, e)
			return
		}
		// Filter over the newest MaxAuditScan rows, never the whole log:
		// the read is bounded however long the history is.
		fetch = MaxAuditScan
		if h.AuditScanLimit > 0 {
			fetch = h.AuditScanLimit
		}
	}
	rows, err := h.Vault.AuditLog(r.Context(), fetch)
	if err != nil {
		writeError(w, r, err)
		return
	}
	// No pre-allocation sized by the request: limit is bounded above, but
	// the slice only ever grows to the rows actually returned.
	entries := []AuditEntry{}
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
	out := map[string]any{"entries": entries}
	// A filtered read that examined its whole scan window and still found
	// fewer than limit matches may have missed older rows: say so, so an
	// empty answer is never mistaken for "no such event" (RGT-376). The
	// fields are additive; Python's {"entries"} shape is unchanged
	// otherwise.
	if filtered && len(rows) >= fetch && len(entries) < limit {
		out["truncated"] = true
		out["scanned"] = len(rows)
	}
	writeJSON(w, http.StatusOK, out)
}

// AuditVerify handles POST /v1/audit/verify.
func (h *Handlers) AuditVerify(w http.ResponseWriter, r *http.Request) {
	if !h.requireScope(w, r, auth.ScopeAudit) {
		return
	}
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
	if !h.requireScope(w, r, auth.ScopeAgent) {
		return
	}
	var req SimulateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if p, _ := PrincipalFromContext(r.Context()); p.Legacy && req.Agent == nil {
		writeError(w, r, required(field("agent", req.Agent)))
		return
	}
	if e := required(field("namespace", req.Namespace)); e != nil {
		writeError(w, r, e)
		return
	}
	// An operator may simulate any agent; an agent only itself.
	agent, ok := h.subject(w, r, req.Agent, "", true)
	if !ok {
		return
	}
	d, err := h.Vault.Simulate(r.Context(), agent, *req.Namespace, deref(req.Purpose, ""), deref(req.Action, "read"))
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
	p, ok := PrincipalFromContext(r.Context())
	if !ok {
		writeError(w, r, newAppError(http.StatusUnauthorized, "ServerAuthError", "invalid credentials"))
		return false
	}
	if !p.Has(auth.ScopeOperator) {
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

// validateOperatorFields validates the operator name and the denial reason
// of an approval decision. Both are stored in the decision, shown to the
// requester and used in log lines, so they get the same allow-list as an
// agent id and a purpose (RGT-353, RGT-357). Nil fields are absent.
func validateOperatorFields(operator, reason *string) *AppError {
	if operator != nil {
		if _, err := validation.ValidateAgent(*operator); err != nil {
			return badRequest("'operator' is not a valid operator name.")
		}
	}
	if reason != nil {
		return multilineText("reason", *reason)
	}
	return nil
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
	if e := validateOperatorFields(req.Operator, nil); e != nil {
		writeError(w, r, e)
		return
	}
	if code := deref(req.TOTPCode, ""); len(code) > maxTOTPCodeLen {
		writeError(w, r, badRequest("'totp_code' is too long."))
		return
	}
	operator, ok := h.subject(w, r, req.Operator, "operator", false)
	if !ok {
		return
	}
	id := r.PathValue("id")
	p, _ := PrincipalFromContext(r.Context())
	who := approval.Approver{Name: operator, Identity: approval.Identity{TokenID: p.TokenID, Agent: p.Agent}}
	if err := h.Broker.ApproveBy(id, deref(req.TOTPCode, ""), who); err != nil {
		writeError(w, r, h.reportApprovalFailure(w, r, p, id, err)) // ApprovalError -> 400/403/429
		return
	}
	h.auditEvent(r, EventApprovalApproved, sql.NullString{},
		"request="+safeID(id)+" token="+p.TokenID+" ip="+ClientIP(r), agentCol(p))
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
	if e := validateOperatorFields(req.Operator, req.Reason); e != nil {
		writeError(w, r, e)
		return
	}
	operator, ok := h.subject(w, r, req.Operator, "operator", false)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := h.Broker.Deny(id, deref(req.Reason, "denied by operator"), operator); err != nil {
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
	if !h.requireScope(w, r, auth.ScopeAgent) {
		return
	}
	var req ExecuteCapabilityRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if p, _ := PrincipalFromContext(r.Context()); p.Legacy && req.AgentID == nil {
		writeError(w, r, required(field("agent_id", req.AgentID)))
		return
	}
	if e := required(field("capability", req.Capability), field("capability_token", req.CapabilityToken)); e != nil {
		writeError(w, r, e)
		return
	}
	// The capability token is also bound to an agent; the vault checks it
	// against this subject.
	agent, ok := h.subject(w, r, req.AgentID, "", false)
	if !ok {
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
		Agent:      agent,
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
		log.Printf("ERROR: capability %s failed; details suppressed from response: %s", LogSafe(capability), LogSafe(err.Error()))
		return newAppError(http.StatusInternalServerError, "ActionExecutionError",
			"capability "+pyfmt.Repr(capability)+" failed; see server logs for details")
	}
	for _, kind := range []error{vault.ErrValidation, vault.ErrCapabilityVersion, vault.ErrPolicyDenied,
		vault.ErrCapabilityNotFound, vault.ErrRateLimited} {
		if errors.Is(err, kind) {
			return err
		}
	}
	log.Printf("ERROR: capability %s raised an unhandled error; details suppressed from response: %s", LogSafe(capability), LogSafe(err.Error()))
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
	if !h.requireScope(w, r, auth.ScopeAgent) {
		return
	}
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
	if !h.requireScope(w, r, auth.ScopeAgent) {
		return
	}
	q := r.URL.Query()
	if p, _ := PrincipalFromContext(r.Context()); p.Legacy && !q.Has("agent") {
		writeError(w, r, unprocessable("query parameter 'agent' is required"))
		return
	}
	agent, ok := h.querySubject(w, r, "agent", "", true)
	if !ok {
		return
	}
	namespace := queryDefault(r, "namespace", "*")
	purpose := queryDefault(r, "purpose", "*")
	// "*" (the default) asks "for any namespace / purpose"; anything else
	// is validated like the same field of a secret request.
	if namespace != "*" {
		if _, err := validation.ValidateNamespace(namespace); err != nil {
			writeError(w, r, err)
			return
		}
	}
	if purpose != "*" {
		if e := freeText("purpose", purpose); e != nil {
			writeError(w, r, e)
			return
		}
	}
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
	if !h.requireScope(w, r, auth.ScopeAgent) {
		return
	}
	out := []map[string]any{}
	if h.Actions != nil {
		for _, s := range h.Actions.List() {
			schema := append([]string{}, s.ParamsSchema...)
			out = append(out, map[string]any{"name": s.Name, "description": s.Description, "params_schema": schema})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": out})
}
