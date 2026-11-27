package hooks

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"

	"golang.org/x/crypto/blake2b"

	"rgt-vault-server/internal/hooks/pyfmt"
	"rgt-vault-server/internal/vault"
)

// SensitiveKeys matches map keys whose values are always redacted
// (python/hooks/log_redaction.py SENSITIVE_KEYS, RGT-28).
var SensitiveKeys = regexp.MustCompile(`(?i)(pass|passwd|password|secret|token|api_key|apikey|access_key|` +
	`private|privkey|seed|mnemonic|credential|auth|bearer|jwt|key)`)

var highEntropy = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{24,}$`)

// Redacted is the replacement for a sensitive value.
const Redacted = "[REDACTED]"

// IsHighEntropy is the heuristic for long base64/hex-looking strings.
func IsHighEntropy(s string) bool { return len(s) > 24 && highEntropy.MatchString(s) }

// Redact returns a copy of v with sensitive keys, high-entropy strings and
// byte slices redacted (python redact). It never mutates v. Unlike Python,
// a high-entropy string is replaced entirely by [REDACTED], with no prefix.
func Redact(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if SensitiveKeys.MatchString(k) {
				out[k] = Redacted
			} else {
				out[k] = Redact(val)
			}
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if SensitiveKeys.MatchString(k) {
				out[k] = Redacted
			} else {
				out[k] = Redact(val)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = Redact(val)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = Redact(val)
		}
		return out
	case string:
		if IsHighEntropy(x) {
			// Deliberate difference from Python, which keeps the first four
			// characters (x[:4] + "...[REDACTED]"): any prefix of a key
			// narrows it (key type, issuer, brute-force space).
			return Redacted
		}
		return x
	case []byte:
		return fmt.Sprintf("<%d bytes redacted>", len(x))
	}
	return v
}

// RequestContext identifies one capability request in redacted logs
// (python hooks/audit.py RequestContext).
type RequestContext struct {
	AgentID      string
	CapabilityID string
	Version      string
	TimestampNS  int64
	Nonce        []byte
}

// ContextHash is blake2b-256(agent || capability || version ||
// str(timestamp_ns) || nonce) in hex, as in Python.
func (c RequestContext) ContextHash() string {
	h, _ := blake2b.New256(nil)
	h.Write([]byte(c.AgentID))
	h.Write([]byte(c.CapabilityID))
	h.Write([]byte(c.Version))
	h.Write([]byte(strconv.FormatInt(c.TimestampNS, 10)))
	h.Write(c.Nonce)
	return hex.EncodeToString(h.Sum(nil))
}

// LogRedactionHook logs request metadata with every sensitive value
// redacted and never logs a secret value (python LogRedactionHook, RGT-28).
// It is also a vault.Hook that always allows, so it can be installed as the
// vault's hook to get redacted request logs.
type LogRedactionHook struct {
	*Base
	log *slog.Logger
}

// NewLogRedactionHook logs to logger (nil means slog.Default()).
func NewLogRedactionHook(logger *slog.Logger) *LogRedactionHook {
	if logger == nil {
		logger = slog.Default()
	}
	return &LogRedactionHook{Base: NewBase("log_redaction"), log: logger}
}

// OnCapabilityRequest logs a capability request with redacted parameters.
func (h *LogRedactionHook) OnCapabilityRequest(c RequestContext, parameters map[string]any) {
	h.log.Info(fmt.Sprintf("capability_request: agent=%s cap=%s ver=%s ctx_hash=%s params=%s",
		c.AgentID, c.CapabilityID, c.Version, c.ContextHash(), pyfmt.Repr(Redact(parameters))))
}

// OnCapabilityGrant logs a granted capability lease.
func (h *LogRedactionHook) OnCapabilityGrant(c RequestContext, leaseTTLSeconds int) {
	h.log.Info(fmt.Sprintf("capability_grant: agent=%s cap=%s ttl=%d ctx_hash=%s",
		c.AgentID, c.CapabilityID, leaseTTLSeconds, c.ContextHash()))
}

// OnSecretAccess logs secret metadata only, never the value.
func (h *LogRedactionHook) OnSecretAccess(c RequestContext, secretID, operation string) {
	h.log.Info(fmt.Sprintf("secret_access: agent=%s secret_id=%s op=%s ctx_hash=%s",
		c.AgentID, secretID, operation, c.ContextHash()))
}

// OnCapabilityComplete logs the outcome; an error mentioning a sensitive
// word is replaced by [REDACTED].
func (h *LogRedactionHook) OnCapabilityComplete(c RequestContext, success bool, errMsg *string) {
	safe := "None"
	if errMsg != nil {
		safe = *errMsg
		if SensitiveKeys.MatchString(safe) {
			safe = Redacted
		}
	}
	h.log.Info(fmt.Sprintf("capability_complete: agent=%s cap=%s success=%s error=%s ctx_hash=%s",
		c.AgentID, c.CapabilityID, pyfmt.Repr(success), safe, c.ContextHash()))
}

// Consult logs the operation (capability requests with redacted payload,
// secret-path operations as secret_access) and allows. Tokens are never
// logged.
func (h *LogRedactionHook) Consult(_ context.Context, req vault.HookRequest) (vault.HookResponse, error) {
	c := RequestContext{AgentID: req.Agent, CapabilityID: req.Capability,
		Version: strconv.Itoa(req.CapabilityVersion), Nonce: []byte(req.RequestID)}
	if req.IsCapability() {
		params, _ := req.Payload.(map[string]any)
		h.OnCapabilityRequest(c, params)
	} else {
		name := ""
		if req.SecretName != nil {
			name = *req.SecretName
		}
		h.OnSecretAccess(c, name, req.Operation)
	}
	return allow("log redaction: not enforced"), nil
}
