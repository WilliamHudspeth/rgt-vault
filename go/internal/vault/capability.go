package vault

// Capability execution: the Go port of VaultManager.execute_capability
// (python/vault.py:423-783) and _hook_consult_capability. The registry and
// the built-in capabilities live in internal/capabilities, which implements
// CapabilityRegistry structurally; the real hooks live in internal/hooks.
//
// Python's bypass_verification flag is NOT ported: there is no way to run a
// capability without a verified token (RGT-423). TestExecuteCapabilityNoBypass
// guards this.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"rgt-vault-server/internal/captoken"
	"rgt-vault-server/internal/hooks/pyfmt"
)

var (
	// ErrCapabilityNotFound is Python's CapabilityNotFoundError: the
	// capability name is not registered (HTTP 404).
	ErrCapabilityNotFound = errors.New("vault: capability not found")
	// ErrCapabilityVersion is Python's CapabilityVersionError: the
	// registered handler does not support the requested version (HTTP 400).
	ErrCapabilityVersion = errors.New("vault: capability version not supported")
	// ErrNoTokenVerifier means Config.TokenVerifier is nil, so capability
	// execution fails closed. It also matches ErrValidation (Python raises
	// ValidationError).
	ErrNoTokenVerifier = errors.New("vault: no token verifier configured")
	// ErrTokenVerifier means the configured TokenVerifier misbehaved: it
	// returned neither a token nor an error. The call is denied (it also
	// matches ErrPolicyDenied) and audited as "token: TokenVerifierError";
	// the agent's failed-credential count is NOT incremented, because the
	// fault is the server's, not the presented token's.
	ErrTokenVerifier = errors.New("vault: token verifier returned no token")
	// ErrCapabilityFailed wraps an error returned (or a panic raised) by a
	// capability handler: a server fault, not an authorization failure.
	ErrCapabilityFailed = errors.New("vault: capability handler failed")
)

// CapabilityContext is the read-only context passed to a capability handler
// (python CapabilityContext). It never carries the raw token or any secret;
// a handler that needs a secret leases it through Vault itself.
type CapabilityContext struct {
	Vault             *Vault
	AgentID           string
	TokenID           string
	Capability        string
	CapabilityVersion int
	// TokenMetadata is {"token_id", "exp", "context_bindings"}.
	TokenMetadata map[string]any
}

// CapabilitySpec is one registered capability (python CapabilitySpec).
type CapabilitySpec interface {
	// SupportsVersion reports whether the handler accepts version.
	SupportsVersion(version int) bool
	// SupportedVersions returns the accepted versions, sorted.
	SupportedVersions() []int
	// ValidatePayload is the schema gate at the vault boundary. Its error
	// should match ErrValidation and carry Python's message.
	ValidatePayload(payload map[string]any) error
	// Invoke runs the handler.
	Invoke(ctx context.Context, payload map[string]any, cctx CapabilityContext) (any, error)
}

// CapabilityRegistry resolves capability names (python CapabilityRegistry).
// internal/capabilities.Registry implements it.
type CapabilityRegistry interface {
	// Lookup returns the spec, or an error matching ErrCapabilityNotFound.
	Lookup(name string) (CapabilitySpec, error)
}

// CapabilityRequest are the arguments of ExecuteCapability. There is
// deliberately no field that skips token verification.
type CapabilityRequest struct {
	// Capability is the registered capability name, e.g. "secrets.echo".
	Capability string
	// Version is the capability_version; 0 means 1 (Python's default).
	Version int
	// Agent is the calling agent id; the token must be bound to it.
	Agent string
	// Token is the v2 capability token minted by the harness. Required.
	Token string
	// Payload are the capability arguments; nil means {}. Decode request
	// JSON with json.Decoder.UseNumber so integers keep their Python form
	// in the audit context_hash.
	Payload map[string]any
}

// pyRepr is Python's repr() for the strings embedded in error messages.
func pyRepr(v any) string { return pyfmt.Repr(v) }

// capDetails is the common prefix of every capability audit row.
func capDetails(agent, capability string, version int, rest ...pyKV) string {
	d := pyObject{{"agent", agent}, {"capability", capability}, {"capability_version", version}}
	return pyDumps(append(d, rest...))
}

// ExecuteCapability runs a registered capability on behalf of an agent:
// the v0.3 enforcement point. The checks run in exactly Python's order and
// every failure writes Python's audit row:
//
//  1. freeze check                      -> CAPABILITY_DENIED "vault frozen"
//  2. token verifier configured         -> CAPABILITY_DENIED "no token verifier configured"
//  3. failed-credential cap (RGT-277)   -> CAPABILITY_DENIED "too many failed credential verifications"
//  4. token signature/expiry            -> CAPABILITY_DENIED "token: <TokenErrorClass>"
//  5. agent / capability / version      -> CAPABILITY_DENIED "... mismatch"
//  6. context bindings                  -> CAPABILITY_DENIED "context binding: <msg>"
//  7. hook                              -> HOOK_CAPABILITY (always)
//  8. registry lookup                   -> (no row, as in Python)
//  9. version supported                 -> CAPABILITY_DENIED "version not supported by registered handler"
//  10. payload schema                   -> CAPABILITY_DENIED "payload: <msg>"
//  11. rate limit                       -> CAPABILITY_DENIED "rate limited"
//  12. handler                          -> CAPABILITY_FAILED "handler: <class>" or CAPABILITY_EXECUTED
func (v *Vault) ExecuteCapability(ctx context.Context, req CapabilityRequest) (any, error) {
	name, agent, token := req.Capability, req.Agent, req.Token
	version := req.Version
	if version == 0 {
		version = 1
	}
	payload := req.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	if strings.TrimFunc(name, isPySpace) == "" {
		return nil, validationErr("capability_name must be a non-empty string")
	}
	if strings.TrimFunc(agent, isPySpace) == "" {
		return nil, validationErr("agent_id must be a non-empty string")
	}
	if token == "" {
		return nil, validationErr("capability_token is required")
	}
	// No hook or verifier side effects on a closed or broken vault.
	if err := v.withR(func() error { return nil }); err != nil {
		return nil, err
	}
	// deny writes the CAPABILITY_DENIED row and returns result (or the
	// audit write's error: an unrecorded denial is still a denial).
	deny := func(result error, reason string, rest ...pyKV) error {
		if err := v.withR(func() error {
			return v.logAudit(ctx, "CAPABILITY_DENIED", sql.NullString{},
				capDetails(agent, name, version, append([]pyKV{{"reason", reason}}, rest...)...))
		}); err != nil {
			return err
		}
		return result
	}

	// 1. Freeze check, before any token work.
	if v.hook.Frozen() {
		return nil, deny(deniedErr("vault frozen"), "vault frozen")
	}

	// 2. The verifier is the trust anchor; without one, refuse to run.
	if v.tokenVerifier == nil {
		return nil, deny(newErr([]error{ErrNoTokenVerifier, ErrValidation}, nil,
			"execute_capability requires a configured token_verifier; set vault.Config.TokenVerifier"), "no token verifier configured")
	}

	// 3. RGT-277 failed-credential cap, checked before verifying another
	// guess. Same boundary as Python (`count(agent) >= max_requests`): with
	// AuthFailureLimit = 100, 100 failed verifications are allowed in the
	// window and the 101st attempt is refused without verifying.
	// Count-then-Record is not atomic (see python/vault.py): the cap can
	// overshoot by the concurrency level, then self-corrects.
	if v.authFailureLimiter.Count(agent) >= v.authFailureLimiter.max {
		return nil, deny(deniedErr("agent '%s' locked out: too many failed credential attempts", agent), "too many failed credential verifications")
	}

	// 4. Signature, envelope and expiry.
	// A verifier that can split "authentic" from "consumed" (the replay
	// guard) is consumed only after the request matched the token (step 6),
	// so presenting someone else's token cannot burn it.
	dc, deferred := v.tokenVerifier.(captoken.DeferredConsumer)
	var tok *captoken.CapabilityV2Token
	var verr error
	if deferred {
		tok, verr = dc.VerifyUnconsumed(token)
	} else {
		tok, verr = v.tokenVerifier.Verify(token)
	}
	if verr == nil && tok == nil {
		return nil, deny(newErr([]error{ErrTokenVerifier, ErrPolicyDenied}, nil,
			"capability token rejected: token verifier returned no token"), "token: TokenVerifierError")
	}
	if verr != nil {
		v.authFailureLimiter.Record(agent)
		class := "TokenError"
		if errors.Is(verr, captoken.ErrToken) {
			class = pyfmt.TokenErrorClass(verr)
		} else if errors.Is(verr, captoken.ErrNotImplemented) {
			class = "NotImplementedError"
		}
		return nil, deny(newErr([]error{ErrPolicyDenied}, nil, "capability token rejected: %s", pyfmt.TokenErrorMessage(verr)), "token: "+class)
	}

	// 5. Token -> request consistency.
	if tok.AgentID != agent {
		return nil, deny(deniedErr("token bound to agent %s, caller claimed %s", pyRepr(tok.AgentID), pyRepr(agent)), "agent mismatch")
	}
	if tok.Capability != name {
		return nil, deny(deniedErr("token authorizes %s, request asked for %s", pyRepr(tok.Capability), pyRepr(name)), "capability mismatch", pyKV{"token_capability", tok.Capability})
	}
	if tok.CapabilityVersion != version {
		return nil, deny(deniedErr("token capability_version=%d, request asked for %d", tok.CapabilityVersion, version), "version mismatch", pyKV{"token_version", tok.CapabilityVersion})
	}

	// 6. Context bindings: every key the token pins must be in the payload
	// with the same value.
	bindings := make(map[string]any, len(tok.ContextBindings))
	for k, b := range tok.ContextBindings {
		bindings[k] = b
	}
	tokenMetadata := map[string]any{
		"token_id":         tok.TokenID,
		"exp":              tok.ExpiresAt,
		"context_bindings": bindings,
	}
	if berr := pyfmt.CheckContext(tok, payload); berr != nil {
		// Python re-raises the TokenBindingError (which its server turns
		// into a 500); Go classifies it as a policy denial (403).
		return nil, deny(newErr([]error{ErrPolicyDenied}, berr, "%s", berr.Error()), "context binding: "+berr.Error())
	}

	// 6b. One-time use: consume the token now that it is known to be this
	// agent's, for this capability, version and payload. A replay is not a
	// failed credential (a harness may legitimately retry a lost response),
	// so it is not counted against the agent's failure limit.
	if deferred {
		if cerr := dc.Consume(tok); cerr != nil {
			class := "TokenError"
			if errors.Is(cerr, captoken.ErrToken) {
				class = pyfmt.TokenErrorClass(cerr)
			}
			return nil, deny(newErr([]error{ErrPolicyDenied}, nil, "capability token rejected: %s", pyfmt.TokenErrorMessage(cerr)), "token: "+class)
		}
	}

	// 7. Hook on the capability path.
	if err := v.hookConsultCapability(ctx, agent, name, version, payload, tokenMetadata, token); err != nil {
		return nil, err
	}

	// 8. Registry lookup (no audit row, as in Python).
	if v.capabilities == nil {
		return nil, newErr([]error{ErrCapabilityNotFound}, nil, "unknown capability %s. Registered: []", pyRepr(name))
	}
	spec, err := v.capabilities.Lookup(name)
	if err == nil && spec == nil {
		err = newErr([]error{ErrCapabilityNotFound}, nil, "unknown capability %s", pyRepr(name))
	}
	if err != nil {
		if !errors.Is(err, ErrCapabilityNotFound) {
			err = newErr([]error{ErrCapabilityNotFound}, err, "%s", err.Error())
		}
		return nil, err
	}

	// 9. Version check.
	if !spec.SupportsVersion(version) {
		sv := append([]int(nil), spec.SupportedVersions()...)
		sort.Ints(sv)
		list := make([]any, len(sv))
		for i, x := range sv {
			list[i] = x
		}
		return nil, deny(newErr([]error{ErrCapabilityVersion}, nil,
			"capability %s does not support version %d; supported: %s", pyRepr(name), version, pyfmt.SortedIntsRepr(sv)),
			"version not supported by registered handler", pyKV{"supported_versions", list})
	}

	// 10. Payload schema.
	if perr := spec.ValidatePayload(payload); perr != nil {
		if !errors.Is(perr, ErrValidation) {
			perr = newErr([]error{ErrValidation}, perr, "%s", perr.Error())
		}
		return nil, deny(perr, "payload: "+perr.Error())
	}

	// 11. Rate limit (the same per-agent limiter as leases).
	if !v.rateLimiter.Allow(agent) {
		return nil, deny(newErr([]error{ErrRateLimited, ErrPermission}, nil, "Rate limit exceeded for agent %s", pyRepr(agent)), "rate limited")
	}

	// 12. Execute.
	cctx := CapabilityContext{
		Vault:             v,
		AgentID:           agent,
		TokenID:           tok.TokenID,
		Capability:        name,
		CapabilityVersion: version,
		TokenMetadata:     tokenMetadata,
	}
	contextHash := ContextHash(payload)
	result, herr := invokeHandler(ctx, spec, payload, cctx)
	if herr != nil {
		if err := v.withR(func() error {
			return v.logAudit(ctx, "CAPABILITY_FAILED", sql.NullString{},
				capDetails(agent, name, version, pyKV{"reason", "handler: " + errorClass(herr)}, pyKV{"context_hash", contextHash}))
		}); err != nil {
			return nil, err
		}
		return nil, newErr([]error{ErrCapabilityFailed}, herr, "%s", herr.Error())
	}
	if err := v.withR(func() error {
		return v.logAudit(ctx, "CAPABILITY_EXECUTED", sql.NullString{},
			capDetails(agent, name, version,
				pyKV{"hook", v.hook.ID()}, pyKV{"allowed", true}, pyKV{"context_hash", contextHash}))
	}); err != nil {
		return nil, err
	}
	return result, nil
}

// hookConsultCapability is VaultManager._hook_consult_capability.
func (v *Vault) hookConsultCapability(ctx context.Context, agent, capability string, version int,
	payload, tokenMetadata map[string]any, token string) error {
	if v.hook.Frozen() {
		details := pyDumps(pyObject{
			{"hook_id", v.hook.ID()}, {"decision", string(HookFreeze)}, {"reason", "vault frozen by hook"},
			{"agent", agent}, {"capability", capability}, {"capability_version", version},
		})
		if err := v.withR(func() error {
			return v.logAudit(ctx, "HOOK_CAPABILITY", sql.NullString{}, details)
		}); err != nil {
			return err
		}
		return deniedErr("vault frozen by hook")
	}
	resp := v.preOpCheck(ctx, HookRequest{
		Operation:         OpCapability,
		Agent:             agent,
		Capability:        capability,
		CapabilityVersion: version,
		Payload:           payload,
		TokenMetadata:     tokenMetadata,
		CapabilityToken:   token,
		RequestID:         newRequestID(),
	})
	details := pyObject{{"hook_id", v.hook.ID()}, {"agent", agent}, {"capability", capability}, {"capability_version", version}}
	details = append(details, resp.auditFields()...)
	if err := v.withR(func() error {
		return v.logAudit(ctx, "HOOK_CAPABILITY", sql.NullString{}, pyDumps(details))
	}); err != nil {
		return err
	}
	if resp.Decision != HookAllow {
		reason := resp.Reason
		if reason == "" {
			reason = "no reason given"
		}
		return deniedErr("hook %s denied capability %s for agent %s: %s",
			pyRepr(v.hook.ID()), pyRepr(capability), pyRepr(agent), reason)
	}
	return nil
}

// invokeHandler runs the handler, turning a panic into an error.
func invokeHandler(ctx context.Context, spec CapabilitySpec, payload map[string]any, cctx CapabilityContext) (res any, err error) {
	defer func() {
		if p := recover(); p != nil {
			res, err = nil, &handlerPanic{value: p}
		}
	}()
	return spec.Invoke(ctx, payload, cctx)
}

type handlerPanic struct{ value any }

// Error never includes the panic value: it may contain secret material.
func (p *handlerPanic) Error() string {
	return "capability handler panicked; see server logs for details"
}
func (*handlerPanic) PyClass() string { return "panic" }
func (p *handlerPanic) Unwrap() error { e, _ := p.value.(error); return e }

// errorClass is type(e).__name__ for the audit reason: never the message,
// which could contain secret material. An error may name its class with a
// PyClass() string method; otherwise the Go type name is used.
func errorClass(err error) string {
	var pc interface{ PyClass() string }
	if errors.As(err, &pc) && pc.PyClass() != "" {
		return pc.PyClass()
	}
	switch {
	case errors.Is(err, ErrValidation):
		return "ValidationError"
	case errors.Is(err, ErrPolicyDenied):
		return "PolicyDeniedError"
	case errors.Is(err, ErrNotFound):
		return "SecretNotFoundError"
	case errors.Is(err, ErrPermission):
		return "PermissionError"
	}
	t := reflect.TypeOf(err)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Name() == "" {
		return "error"
	}
	return t.Name()
}

// ContextHash is the audit context_hash of a payload:
// sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"),
// default=str))[:16], with Python's ensure_ascii escaping.
//
// The 16-hex-character (64-bit) truncation is a frozen cross-implementation
// format: the value is part of the CAPABILITY_EXECUTED / CAPABILITY_FAILED
// details, which are hashed into the audit chain, and Python writes exactly
// this width (python/vault.py execute_capability). Widening it would make
// Go-written rows differ from Python's (TestPythonExecuteCapabilityParity)
// and is an audit-format change (RGT-489). It is a correlation aid, not a
// security control: nothing is authorized by matching it, so a birthday
// collision (~2^32 payloads) only makes two rows look alike.
func ContextHash(payload map[string]any) string {
	var b strings.Builder
	pyCompactSorted(&b, payload)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])[:16]
}

// pyCompactSorted is json.dumps(v, sort_keys=True, separators=(",", ":"),
// default=str).
func pyCompactSorted(b *strings.Builder, v any) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			pyQuote(b, k)
			b.WriteByte(':')
			pyCompactSorted(b, x[k])
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, it := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			pyCompactSorted(b, it)
		}
		b.WriteByte(']')
	case []string:
		items := make([]any, len(x))
		for i := range x {
			items[i] = x[i]
		}
		pyCompactSorted(b, items)
	case map[string]string:
		m := make(map[string]any, len(x))
		for k, s := range x {
			m[k] = s
		}
		pyCompactSorted(b, m)
	case json.Number:
		if jsonNumber.MatchString(x.String()) {
			b.WriteString(x.String())
		} else {
			pyQuote(b, x.String())
		}
	case int:
		b.WriteString(strconv.Itoa(x))
	default:
		// Scalars render identically in both separator styles.
		pyEncode(b, x, -1, 0)
	}
}

// TokenVerifier returns the configured capability-token verifier (nil when
// capability execution is disabled).
func (v *Vault) TokenVerifier() captoken.TokenVerifier { return v.tokenVerifier }

// Capabilities returns the configured capability registry (may be nil).
func (v *Vault) Capabilities() CapabilityRegistry { return v.capabilities }
