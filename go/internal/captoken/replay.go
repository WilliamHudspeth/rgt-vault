package captoken

import (
	"sync"
	"time"
)

// DefaultReplayCacheSize bounds how many live token ids a ReplayGuard keeps.
const DefaultReplayCacheSize = 4096

// ReplayGuard wraps a TokenVerifier so every v2 capability token is
// accepted at most once per process (ASVS 3.5.x / RGT-338). A token's id
// (its jti: sha256 of the signed payload, see CapabilityV2Token.TokenID) is
// remembered until the token's own expiry; presenting the same token again
// is ErrReplay.
//
// Semantics, chosen to fail closed:
//   - the token is consumed atomically (Consume), before the hook, policy,
//     rate limit and handler run. A request that is then refused or fails
//     has still used the token: the harness mints a new one. This leaves no
//     window in which two concurrent requests both pass.
//   - expired ids are purged on every accept, so the cache never keeps a
//     dead id. An expired token is refused by the inner verifier before it
//     reaches the cache, so forgetting it cannot enable a replay.
//   - the cache is bounded. When it is full of live ids a NEW token is
//     refused (ErrReplay, "replay cache full") rather than evicting a live
//     id, because eviction would re-open exactly the replay this guards.
//     Only holders of the signing key can fill it, with tokens that expire
//     on their own.
//   - the identical token string within the same second for the same
//     claims has the same id (the id is a content hash): the second use is
//     refused as a replay. Mint a token per call.
//   - state is in memory: a restart forgets it (a token is then valid
//     again until its expiry; keep TTLs short).
//
// A caller that wants to consume the token LATER (the vault does: only after
// the token's agent, capability, version and context bindings matched the
// request, so a bystander who merely sees a token cannot burn it by
// presenting it as someone else) uses the DeferredConsumer methods:
// VerifyUnconsumed checks without recording, Consume then records. Verify is
// both in one step.
//
// Do not combine it with hooks.TwoFactorHook on the same tokens: both
// remember ids, so the second would see the first's entry as a replay.
type ReplayGuard struct {
	inner TokenVerifier
	max   int
	now   func() time.Time

	mu   sync.Mutex
	seen map[string]int64 // token id -> expires_at (unix seconds)
}

var _ TokenVerifier = (*ReplayGuard)(nil)
var _ DeferredConsumer = (*ReplayGuard)(nil)

// DeferredConsumer is implemented by verifiers that can split "is this token
// authentic" from "mark it used". A caller that sees it should call
// VerifyUnconsumed first and Consume once the request is known to match the
// token; a refusal from Consume is an ErrReplay.
type DeferredConsumer interface {
	VerifyUnconsumed(token string) (*CapabilityV2Token, error)
	Consume(tok *CapabilityV2Token) error
}

// ReplayGuardOption configures NewReplayGuard.
type ReplayGuardOption func(*ReplayGuard)

// WithReplayCacheSize sets the cache bound (minimum 1).
func WithReplayCacheSize(n int) ReplayGuardOption {
	return func(g *ReplayGuard) {
		if n < 1 {
			n = 1
		}
		g.max = n
	}
}

// WithReplayClock overrides the clock used to purge expired ids.
func WithReplayClock(now func() time.Time) ReplayGuardOption {
	return func(g *ReplayGuard) { g.now = now }
}

// NewReplayGuard wraps inner. A nil inner returns nil.
func NewReplayGuard(inner TokenVerifier, opts ...ReplayGuardOption) *ReplayGuard {
	if inner == nil {
		return nil
	}
	g := &ReplayGuard{inner: inner, max: DefaultReplayCacheSize, now: time.Now, seen: map[string]int64{}}
	for _, o := range opts {
		o(g)
	}
	return g
}

// Sign implements TokenVerifier (delegates; signing records nothing).
func (g *ReplayGuard) Sign(agentID, capability string, capabilityVersion int, contextBindings map[string]any, ttlSeconds int) (string, error) {
	return g.inner.Sign(agentID, capability, capabilityVersion, contextBindings, ttlSeconds)
}

// Verify implements TokenVerifier: the inner verification first (signature,
// envelope, expiry), then the one-time check.
func (g *ReplayGuard) Verify(token string) (*CapabilityV2Token, error) {
	tok, err := g.VerifyUnconsumed(token)
	if err != nil || tok == nil {
		return tok, err
	}
	if err := g.Consume(tok); err != nil {
		return nil, err
	}
	return tok, nil
}

// VerifyUnconsumed is the inner verification only; nothing is recorded.
func (g *ReplayGuard) VerifyUnconsumed(token string) (*CapabilityV2Token, error) {
	return g.inner.Verify(token)
}

// Consume records tok as used. A token that was already consumed, or a
// cache full of live ids, is ErrReplay.
func (g *ReplayGuard) Consume(tok *CapabilityV2Token) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, dup := g.seen[tok.TokenID]; dup {
		return newErr(kindReplay, "capability token already used")
	}
	now := g.now().Unix()
	for id, exp := range g.seen {
		if exp < now {
			delete(g.seen, id)
		}
	}
	if len(g.seen) >= g.max {
		return newErr(kindReplay, "replay cache full; refusing a new token")
	}
	g.seen[tok.TokenID] = tok.ExpiresAt
	return nil
}

// Len returns the number of remembered token ids (tests, metrics).
func (g *ReplayGuard) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.seen)
}
