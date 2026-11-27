package vault

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

// HookDecision is a hook's verdict (python/hook.py HookDecision).
type HookDecision string

// Hook decisions. The string values are written to the audit chain.
const (
	HookAllow  HookDecision = "allow"
	HookDeny   HookDecision = "deny"
	HookFreeze HookDecision = "freeze" // denied because the hook is frozen
)

// Hook operations on the secret-access path, and the capability path.
const (
	OpRead       = "read"
	OpWrite      = "write"
	OpRotate     = "rotate"
	OpRevoke     = "revoke"
	OpList       = "list"
	OpSimulate   = "simulate"
	OpCapability = "capability"
)

// HookRequest is what a hook sees for one sensitive operation
// (python/hook.py HookRequest). It never carries plaintext.
//
// On the secret-access path Operation is one of read/write/rotate/revoke/
// list/simulate and SecretName is the requested name (nil for list,
// simulate and rotate). On the capability path (batch G8a) Operation is
// "capability" and the Capability* / Payload / TokenMetadata fields are set.
type HookRequest struct {
	Operation       string
	Agent           string
	Namespace       string
	Purpose         string
	SecretName      *string
	CapabilityToken string

	Capability        string
	CapabilityVersion int
	Payload           any
	TokenMetadata     any

	RequestID string
}

// IsCapability reports whether req is on the capability path.
func (r HookRequest) IsCapability() bool {
	return r.Operation == OpCapability && r.Capability != ""
}

// HookResponse is a hook's answer (python/hook.py HookResponse).
type HookResponse struct {
	Decision HookDecision
	Reason   string
	// CapabilityToken is an optional refreshed token from the harness. It is
	// a credential and is never written to the audit chain.
	CapabilityToken string
	// Extra is free-form data recorded in the audit row (as a JSON string,
	// keys sorted, without any "capability_token" key).
	Extra map[string]any
}

// auditFields returns HookResponse.to_audit_dict() as ordered fields.
func (r HookResponse) auditFields() pyObject {
	d := pyObject{{"decision", string(r.Decision)}, {"reason", r.Reason}}
	if len(r.Extra) > 0 {
		safe := make(map[string]any, len(r.Extra))
		for k, v := range r.Extra {
			if k != "capability_token" {
				safe[k] = v
			}
		}
		if len(safe) > 0 {
			d = append(d, pyKV{"extra", pyDumps(safe)})
		}
	}
	return d
}

// Hook is the audit-hook seam (python/hook.py AuditHook). The vault calls
// Consult on every sensitive operation BEFORE the rate limiter and the ABAC
// policy; the decision is recorded in the audit chain either way.
//
// Implementations must be fast and safe for concurrent use. A Consult that
// returns an error (or panics) is treated as a deny, never as an allow.
// Frozen reports the kill switch: while true, every operation is denied
// without calling Consult. Batch G8a provides the real hooks (log,
// two-factor, webhook, freeze file); this package ships only OffHook.
type Hook interface {
	ID() string
	Frozen() bool
	Consult(ctx context.Context, req HookRequest) (HookResponse, error)
}

// OffHook is the default no-op hook: it always allows (python OffHook).
type OffHook struct{}

// ID returns "off".
func (OffHook) ID() string { return "off" }

// Frozen is always false.
func (OffHook) Frozen() bool { return false }

// Consult always allows with the reason "hook disabled".
func (OffHook) Consult(context.Context, HookRequest) (HookResponse, error) {
	return HookResponse{Decision: HookAllow, Reason: "hook disabled"}, nil
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// preOpCheck is AuditHook.pre_op_check: frozen -> FREEZE; an error or a
// panic from Consult -> DENY; an unknown decision -> DENY (fail closed).
func (v *Vault) preOpCheck(ctx context.Context, req HookRequest) (resp HookResponse) {
	defer func() {
		if p := recover(); p != nil {
			resp = HookResponse{Decision: HookDeny, Reason: fmt.Sprintf("hook raised panic: %v", p)}
		}
	}()
	if v.hook.Frozen() {
		return HookResponse{Decision: HookFreeze, Reason: "vault frozen by hook"}
	}
	r, err := v.hook.Consult(ctx, req)
	if err != nil {
		return HookResponse{Decision: HookDeny, Reason: fmt.Sprintf("hook raised error: %v", err)}
	}
	switch r.Decision {
	case HookAllow, HookDeny, HookFreeze:
		return r
	default:
		return HookResponse{Decision: HookDeny, Reason: fmt.Sprintf("hook returned unknown decision %q", string(r.Decision))}
	}
}

// hookConsult is VaultManager._hook_consult: consult the hook, record
// HOOK_<OP> in the audit chain, and return ErrPolicyDenied unless allowed.
// The caller must NOT hold v.mu: the hook runs unlocked (it may be slow or
// call back into the vault) and only the audit write takes the lock.
func (v *Vault) hookConsult(ctx context.Context, operation, agent, namespace, purpose string, secretName *string) error {
	// No external hook side effects on a closed or broken vault.
	if err := v.withR(func() error { return nil }); err != nil {
		return err
	}
	req := HookRequest{
		Operation:  operation,
		Agent:      agent,
		Namespace:  namespace,
		Purpose:    purpose,
		SecretName: secretName,
		RequestID:  newRequestID(),
	}
	resp := v.preOpCheck(ctx, req)
	details := append(pyObject{{"hook_id", v.hook.ID()}}, resp.auditFields()...)
	name := sql.NullString{}
	if secretName != nil {
		name = sql.NullString{String: *secretName, Valid: true}
	}
	if err := v.withR(func() error {
		return v.logAudit(ctx, "HOOK_"+strings.ToUpper(operation), name, pyDumps(details))
	}); err != nil {
		return err
	}
	if resp.Decision != HookAllow {
		reason := resp.Reason
		if reason == "" {
			reason = "no reason given"
		}
		return deniedErr("hook '%s' denied %s for agent '%s': %s", v.hook.ID(), operation, agent, reason)
	}
	return nil
}
