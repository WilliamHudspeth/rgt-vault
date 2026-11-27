package captoken

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func guardFixture(t *testing.T, opts ...ReplayGuardOption) (*ReplayGuard, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	hv, err := NewHMACTokenVerifier([]byte(strings.Repeat("k", 32)), WithClock(clk.now))
	if err != nil {
		t.Fatal(err)
	}
	return NewReplayGuard(hv, append([]ReplayGuardOption{WithReplayClock(clk.now)}, opts...)...), clk
}

func TestReplayGuardSingleUse(t *testing.T) {
	g, _ := guardFixture(t)
	tok, err := g.Sign("agent", "cap", 1, map[string]any{"a": 1}, 60)
	if err != nil {
		t.Fatal(err)
	}
	got, err := g.Verify(tok)
	if err != nil || got.AgentID != "agent" {
		t.Fatalf("first verify: %v %+v", err, got)
	}
	for i := 0; i < 3; i++ {
		_, err = g.Verify(tok)
		if !errors.Is(err, ErrReplay) || !errors.Is(err, ErrToken) {
			t.Fatalf("replay %d = %v", i, err)
		}
		if strings.Contains(err.Error(), tok) {
			t.Fatal("the error carries the token")
		}
	}
	// A different token (other claims) is independent.
	other, _ := g.Sign("agent", "cap", 1, map[string]any{"a": 2}, 60)
	if _, err := g.Verify(other); err != nil {
		t.Fatalf("other token: %v", err)
	}
	if g.Len() != 2 {
		t.Fatalf("Len = %d", g.Len())
	}
}

func TestReplayGuardPassesInnerErrorsThroughWithoutRecording(t *testing.T) {
	g, clk := guardFixture(t)
	if _, err := g.Verify("garbage"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("malformed = %v", err)
	}
	tok, _ := g.Sign("agent", "cap", 1, nil, 5)
	clk.add(10 * time.Second)
	if _, err := g.Verify(tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired = %v", err)
	}
	// A forged token (bad signature) must not poison the cache either.
	hv2, _ := NewHMACTokenVerifier([]byte(strings.Repeat("z", 32)), WithClock(clk.now))
	forged, _ := hv2.Sign("agent", "cap", 1, nil, 60)
	if _, err := g.Verify(forged); !errors.Is(err, ErrSignature) {
		t.Fatalf("forged = %v", err)
	}
	if g.Len() != 0 {
		t.Fatalf("a refused token was remembered: Len = %d", g.Len())
	}
}

func TestReplayGuardPurgesExpiredOnEveryAccept(t *testing.T) {
	g, clk := guardFixture(t, WithReplayCacheSize(3))
	var toks []string
	for i := 0; i < 3; i++ {
		tk, _ := g.Sign("agent", "cap", 1, map[string]any{"i": i}, 10)
		toks = append(toks, tk)
		if _, err := g.Verify(tk); err != nil {
			t.Fatal(err)
		}
	}
	// Full of live ids: a new token fails closed instead of evicting one.
	fresh, _ := g.Sign("agent", "cap", 1, map[string]any{"i": 99}, 10)
	if _, err := g.Verify(fresh); !errors.Is(err, ErrReplay) || !strings.Contains(err.Error(), "cache full") {
		t.Fatalf("full cache = %v", err)
	}
	// The ids that were accepted stay replay-protected while the cache is full.
	for _, tk := range toks {
		if _, err := g.Verify(tk); !errors.Is(err, ErrReplay) {
			t.Fatalf("accepted id replayed on a full cache: %v", err)
		}
	}
	// Once they expire, the next accept purges them and takes the new token.
	clk.add(11 * time.Second)
	fresh2, _ := g.Sign("agent", "cap", 1, map[string]any{"i": 100}, 10)
	if _, err := g.Verify(fresh2); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
	if g.Len() != 1 {
		t.Fatalf("expired ids were not purged: Len = %d", g.Len())
	}
	// And the expired tokens themselves are refused by their own expiry.
	if _, err := g.Verify(toks[0]); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired token = %v", err)
	}
}

func TestReplayGuardConcurrentExactlyOne(t *testing.T) {
	g, _ := guardFixture(t)
	tok, _ := g.Sign("agent", "cap", 1, nil, 60)
	var ok, replay atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := g.Verify(tok); err == nil {
				ok.Add(1)
			} else if errors.Is(err, ErrReplay) {
				replay.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 || replay.Load() != 63 {
		t.Fatalf("ok=%d replay=%d, want 1 and 63", ok.Load(), replay.Load())
	}
}

func TestReplayGuardOptionsAndNil(t *testing.T) {
	if NewReplayGuard(nil) != nil {
		t.Fatal("nil inner must give nil")
	}
	g, _ := guardFixture(t, WithReplayCacheSize(-5))
	if g.max != 1 {
		t.Fatalf("size clamp = %d", g.max)
	}
	if NewReplayGuard(&Ed25519Verifier{}).Len() != 0 {
		t.Fatal("fresh guard not empty")
	}
	// Verifier errors of the inner placeholder pass through.
	if _, err := NewReplayGuard(&Ed25519Verifier{}).Verify("x"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("inner error = %v", err)
	}
	if _, err := NewReplayGuard(&Ed25519Verifier{}).Sign("a", "c", 1, nil, 1); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("sign passthrough = %v", err)
	}
}

type nilVerifier struct{}

func (nilVerifier) Sign(string, string, int, map[string]any, int) (string, error) { return "", nil }
func (nilVerifier) Verify(string) (*CapabilityV2Token, error)                     { return nil, nil }

func TestReplayGuardNilTokenFromInner(t *testing.T) {
	tok, err := NewReplayGuard(nilVerifier{}).Verify("x")
	if tok != nil || err != nil {
		t.Fatalf("got %v %v", tok, err)
	}
}

func TestReplayErrorKind(t *testing.T) {
	err := newErr(kindReplay, "x")
	if !errors.Is(err, ErrReplay) || !errors.Is(err, ErrToken) || errors.Is(err, ErrExpired) {
		t.Fatal("kind matching wrong")
	}
	if got := err.Error(); !strings.Contains(got, "token replay") {
		t.Fatalf("Error() = %q", got)
	}
}

func TestReplayGuardDeferredConsume(t *testing.T) {
	g, _ := guardFixture(t)
	tok, _ := g.Sign("agent", "cap", 1, nil, 60)
	// VerifyUnconsumed any number of times: nothing is recorded.
	var claims *CapabilityV2Token
	for i := 0; i < 3; i++ {
		c, err := g.VerifyUnconsumed(tok)
		if err != nil {
			t.Fatal(err)
		}
		claims = c
	}
	if g.Len() != 0 {
		t.Fatalf("VerifyUnconsumed recorded the token: Len = %d", g.Len())
	}
	if err := g.Consume(claims); err != nil {
		t.Fatal(err)
	}
	if err := g.Consume(claims); !errors.Is(err, ErrReplay) {
		t.Fatalf("second Consume = %v", err)
	}
	// Verify is both steps, and sees the consumed token as a replay.
	if _, err := g.Verify(tok); !errors.Is(err, ErrReplay) {
		t.Fatalf("Verify of a consumed token = %v", err)
	}
	// Consume refuses a new token when the cache is full of live ids.
	g2, _ := guardFixture(t, WithReplayCacheSize(1))
	a, _ := g2.Sign("agent", "cap", 1, map[string]any{"i": 1}, 60)
	b, _ := g2.Sign("agent", "cap", 1, map[string]any{"i": 2}, 60)
	ca, _ := g2.VerifyUnconsumed(a)
	cb, _ := g2.VerifyUnconsumed(b)
	if err := g2.Consume(ca); err != nil {
		t.Fatal(err)
	}
	if err := g2.Consume(cb); !errors.Is(err, ErrReplay) || !strings.Contains(err.Error(), "cache full") {
		t.Fatalf("Consume on a full cache = %v", err)
	}
	// Inner errors pass through VerifyUnconsumed.
	if _, err := g.VerifyUnconsumed("garbage"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("garbage = %v", err)
	}
}
