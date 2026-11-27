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
//   - the token is consumed when it is VERIFIED, before any later check
//     (agent binding, policy, rate limit, handler). A request that is then
//     refused or fails has still used the token: the harness mints a new one.
//     This leaves no window in which two concurrent requests both pass.
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
	tok, err := g.inner.Verify(token)
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, nil // the caller reports "verifier returned no token"
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, dup := g.seen[tok.TokenID]; dup {
		return nil, newErr(kindReplay, "capability token already used")
	}
	now := g.now().Unix()
	for id, exp := range g.seen {
		if exp < now {
			delete(g.seen, id)
		}
	}
	if len(g.seen) >= g.max {
		return nil, newErr(kindReplay, "replay cache full; refusing a new token")
	}
	g.seen[tok.TokenID] = tok.ExpiresAt
	return tok, nil
}

// Len returns the number of remembered token ids (tests, metrics).
func (g *ReplayGuard) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.seen)
}
