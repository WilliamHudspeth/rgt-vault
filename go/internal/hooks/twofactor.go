package hooks

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"rgt-vault-server/internal/captoken"
	"rgt-vault-server/internal/hooks/pyfmt"
	"rgt-vault-server/internal/vault"
)

// DefaultReplayCacheSize is TwoFactorHook's replay-cache bound (Python
// _max_cache).
const DefaultReplayCacheSize = 4096

// TwoFactorHook verifies HMAC-signed tokens minted by the harness (python
// TwoFactorHook). The format is chosen by peeking at the payload: v2
// capability tokens ({"v":2,...}) on the capability path, v1 namespace
// tokens otherwise. Every failure is a deny (fail closed); an accepted
// token id is remembered until the cache fills, so a token is accepted at
// most once per process (replay protection).
type TwoFactorHook struct {
	*Base
	secret []byte
	maxTTL int
	now    func() time.Time
	v2     *captoken.HMACTokenVerifier

	seenMu   sync.Mutex
	seen     map[string]int64 // token id -> expires_at
	maxCache int
}

// TwoFactorOption configures NewTwoFactorHook.
type TwoFactorOption func(*TwoFactorHook)

// WithMaxTTL sets max_ttl_seconds for Issue (default 3600).
func WithMaxTTL(seconds int) TwoFactorOption { return func(h *TwoFactorHook) { h.maxTTL = seconds } }

// WithClock overrides the time source (tests and vectors).
func WithClock(now func() time.Time) TwoFactorOption { return func(h *TwoFactorHook) { h.now = now } }

// WithReplayCacheSize overrides the replay-cache bound (minimum 2).
func WithReplayCacheSize(n int) TwoFactorOption {
	return func(h *TwoFactorHook) {
		if n < 2 {
			n = 2
		}
		h.maxCache = n
	}
}

// NewTwoFactorHook returns a hook for the shared secret (at least 32 bytes;
// copied).
func NewTwoFactorHook(sharedSecret []byte, opts ...TwoFactorOption) (*TwoFactorHook, error) {
	if len(sharedSecret) < captoken.MinSecretLen {
		return nil, validationErr("shared_secret must be at least 32 bytes of random material.")
	}
	h := &TwoFactorHook{
		Base:     NewBase("two_factor"),
		secret:   append([]byte(nil), sharedSecret...),
		maxTTL:   captoken.DefaultMaxTTLSeconds,
		now:      time.Now,
		seen:     map[string]int64{},
		maxCache: DefaultReplayCacheSize,
	}
	for _, o := range opts {
		o(h)
	}
	v2, err := captoken.NewHMACTokenVerifier(h.secret, captoken.WithClock(func() time.Time { return h.now() }))
	if err != nil {
		return nil, err
	}
	h.v2 = v2
	return h, nil
}

// Issue mints a v1 token for agent/namespace/capabilities valid for
// ttlSeconds (1..max TTL) and returns it in compact form, SIGNED WITH THE
// SHARED SECRET. (Python's issue().to_compact() signs with an empty key and
// so produces tokens its own consult rejects; that bug is not ported.)
func (h *TwoFactorHook) Issue(agent, namespace string, capabilities []string, ttlSeconds int) (string, *captoken.CapabilityToken, error) {
	tok, err := captoken.IssueCapabilityToken(agent, namespace, capabilities, ttlSeconds, h.maxTTL, h.now())
	if err != nil {
		return "", nil, err
	}
	s, err := tok.ToCompact(h.secret)
	if err != nil {
		return "", nil, err
	}
	return s, tok, nil
}

// IssueV2 mints a v2 capability token with the same shared secret (the
// harness side of HMACTokenVerifier.sign).
func (h *TwoFactorHook) IssueV2(agentID, capability string, capabilityVersion int, bindings map[string]any, ttlSeconds int) (string, error) {
	return h.v2.Sign(agentID, capability, capabilityVersion, bindings, ttlSeconds)
}

// Verifier returns the hook's v2 verifier, so the vault can share the trust
// anchor (vault.Config.TokenVerifier).
func (h *TwoFactorHook) Verifier() captoken.TokenVerifier { return h.v2 }

// Consult verifies the presented token (python TwoFactorHook.consult).
func (h *TwoFactorHook) Consult(_ context.Context, req vault.HookRequest) (vault.HookResponse, error) {
	if req.CapabilityToken == "" {
		return deny("no capability_token presented"), nil
	}
	format, err := captoken.TokenFormat(req.CapabilityToken)
	if err != nil {
		return deny("malformed capability_token"), nil
	}
	if format == 2 {
		return h.consultV2(req), nil
	}
	return h.consultV1(req), nil
}

func (h *TwoFactorHook) consultV1(req vault.HookRequest) vault.HookResponse {
	tok, err := captoken.ParseV1(req.CapabilityToken, h.secret)
	if err != nil {
		// captoken carries Python's reason strings ("malformed
		// capability_token", "capability_token base64 decode failed",
		// "capability_token signature invalid", "capability_token payload
		// invalid: ...").
		return deny(pyfmt.TokenErrorMessage(err))
	}
	if tok.Agent != req.Agent {
		return deny(fmt.Sprintf("capability_token bound to agent %s, caller claimed %s", pyfmt.Repr(tok.Agent), pyfmt.Repr(req.Agent)))
	}
	if !tok.Covers(req.Operation, req.Namespace, h.now()) {
		return deny(fmt.Sprintf("capability_token does not cover %s on %s", req.Operation, req.Namespace))
	}
	return h.accept(tok.TokenID, tok.ExpiresAt, "v1 token valid")
}

func (h *TwoFactorHook) consultV2(req vault.HookRequest) vault.HookResponse {
	if !req.IsCapability() {
		return deny("v2 capability_token presented on a non-capability op; v2 tokens only authorize capability execution")
	}
	tok, err := h.v2.Verify(req.CapabilityToken)
	if err != nil {
		switch {
		case errors.Is(err, captoken.ErrExpired):
			return deny("v2 token expired")
		case errors.Is(err, captoken.ErrSignature):
			return deny("v2 token signature invalid")
		case errors.Is(err, captoken.ErrMalformed), errors.Is(err, captoken.ErrVersion):
			return deny("v2 token malformed: " + pyfmt.TokenErrorClass(err))
		default:
			return deny("v2 token rejected: " + pyfmt.TokenErrorClass(err) + ": " + pyfmt.TokenErrorMessage(err))
		}
	}
	if tok.AgentID != req.Agent {
		return deny(fmt.Sprintf("v2 token bound to agent %s, caller claimed %s", pyfmt.Repr(tok.AgentID), pyfmt.Repr(req.Agent)))
	}
	if tok.Capability != req.Capability {
		return deny(fmt.Sprintf("v2 token authorizes %s, request asked for %s", pyfmt.Repr(tok.Capability), pyfmt.Repr(req.Capability)))
	}
	if tok.CapabilityVersion != req.CapabilityVersion {
		return deny(fmt.Sprintf("v2 token capability_version=%d, request asked for %d", tok.CapabilityVersion, req.CapabilityVersion))
	}
	payload, _ := req.Payload.(map[string]any)
	if payload == nil {
		payload = map[string]any{}
	}
	if err := pyfmt.CheckContext(tok, payload); err != nil {
		return deny("v2 token context binding failed: " + err.Error())
	}
	return h.accept(tok.TokenID, tok.ExpiresAt, "v2 token valid")
}

// accept is the bounded replay cache shared by v1 and v2 (python
// _accept_token): when full, the half with the earliest expiry is dropped
// first (an evicted id can then be replayed: the documented trade-off of an
// in-process cache; the signature check stays authoritative).
func (h *TwoFactorHook) accept(tokenID string, expiresAt int64, reason string) vault.HookResponse {
	h.seenMu.Lock()
	defer h.seenMu.Unlock()
	if len(h.seen) >= h.maxCache {
		ids := make([]string, 0, len(h.seen))
		for id := range h.seen {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool {
			if h.seen[ids[i]] != h.seen[ids[j]] {
				return h.seen[ids[i]] < h.seen[ids[j]]
			}
			return ids[i] < ids[j]
		})
		for _, id := range ids[:h.maxCache/2] {
			delete(h.seen, id)
		}
	}
	if _, dup := h.seen[tokenID]; dup {
		return deny("capability_token replay detected")
	}
	h.seen[tokenID] = expiresAt
	return vault.HookResponse{Decision: vault.HookAllow, Reason: reason, Extra: map[string]any{"token_id": tokenID}}
}
