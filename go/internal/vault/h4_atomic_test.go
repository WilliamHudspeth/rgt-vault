package vault

// Batch H4 (RGT-256, RGT-257): the check-and-record of the rate limiters is
// one atomic step. Run with -race.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"rgt-vault-server/internal/captoken"
)

func TestReserveIsAtomicUnderContention(t *testing.T) {
	const max, workers = 10, 200
	r := NewRateLimiter(max, time.Hour)
	var admitted atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if slot, ok := r.Reserve("agent"); ok {
				admitted.Add(1)
				slot.Commit()
			}
		}()
	}
	close(start)
	wg.Wait()
	if n := admitted.Load(); n != max {
		t.Fatalf("admitted %d reservations, want exactly %d (cap overshoot)", n, max)
	}
	if n := r.Count("agent"); n != max {
		t.Fatalf("recorded %d events, want %d", n, max)
	}
	if _, ok := r.Reserve("agent"); ok {
		t.Fatal("a full key must refuse")
	}
}

func TestReserveCommitAndRelease(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	r := NewRateLimiter(2, time.Minute)
	r.now = func() time.Time { return now }

	a, ok := r.Reserve("k")
	if !ok {
		t.Fatal("first reserve")
	}
	b, ok := r.Reserve("k")
	if !ok {
		t.Fatal("second reserve")
	}
	if _, ok := r.Reserve("k"); ok {
		t.Fatal("third reserve must be refused at the cap")
	}
	a.Release() // takes exactly its own event back
	if r.Count("k") != 1 {
		t.Fatalf("count after release = %d, want 1", r.Count("k"))
	}
	a.Release() // idempotent: must not take b's event
	if r.Count("k") != 1 {
		t.Fatalf("a second Release removed another event: %d", r.Count("k"))
	}
	b.Commit()
	b.Release() // no-op after Commit
	if r.Count("k") != 1 {
		t.Fatalf("Release after Commit removed the event: %d", r.Count("k"))
	}
	if c, ok := r.Reserve("k"); !ok {
		t.Fatal("room again after the release")
	} else {
		c.Release()
	}
	b2, _ := r.Reserve("k")
	b2.Release()
	if _, kept := r.windows["k"]; !kept {
		t.Fatal("key with a committed event must stay")
	}
	// An emptied key is dropped, so the map does not grow per agent.
	r2 := NewRateLimiter(1, time.Minute)
	s, _ := r2.Reserve("only")
	s.Release()
	if _, kept := r2.windows["only"]; kept {
		t.Fatal("released-empty key must be deleted")
	}
}

// slowVerifier delays every verification so concurrent requests overlap
// inside the check-then-verify window, then rejects the token.
type slowVerifier struct {
	captoken.TokenVerifier
	calls atomic.Int64
}

func (s *slowVerifier) Verify(token string) (*captoken.CapabilityV2Token, error) {
	s.calls.Add(1)
	time.Sleep(60 * time.Millisecond)
	return s.TokenVerifier.Verify(token)
}

// TestAuthFailureCapHoldsUnderConcurrency: AuthFailureLimit+100 simultaneous
// bad-credential guesses for one agent; with Python's count-then-record all
// of them pass the check before any is recorded and all are verified. The
// atomic reserve admits exactly AuthFailureLimit of them.
func TestAuthFailureCapHoldsUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	ver := &slowVerifier{TokenVerifier: verifierAt(t, time.Unix(1_900_000_000, 0))}
	v := newCapVault(t, nil, fakeRegistry{"secrets.echo": echoSpec()}, ver)
	const workers = AuthFailureLimit + 100
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _ = v.ExecuteCapability(ctx, CapabilityRequest{Capability: "secrets.echo", Agent: "a", Token: "x.y"})
		}()
	}
	close(start)
	wg.Wait()
	if n := ver.calls.Load(); n != AuthFailureLimit {
		t.Fatalf("verifier ran %d times, want exactly %d: the lockout cap was overshot", n, AuthFailureLimit)
	}
	if n := v.AuthFailureLimiter().Count("a"); n != AuthFailureLimit {
		t.Fatalf("recorded failures = %d, want %d", n, AuthFailureLimit)
	}
}

// TestSuccessfulVerificationsDoNotConsumeTheCap: valid tokens give their
// slot back, so any number of them leaves the failure count at zero.
func TestSuccessfulVerificationsDoNotConsumeTheCap(t *testing.T) {
	ctx := context.Background()
	ver := verifierAt(t, time.Unix(1_900_000_000, 0))
	v := newCapVault(t, nil, fakeRegistry{"secrets.echo": echoSpec()}, ver)
	for i := 0; i < AuthFailureLimit+20; i++ {
		tok, err := ver.Sign("a", "secrets.echo", 1, nil, 60+i)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.ExecuteCapability(ctx, CapabilityRequest{Capability: "secrets.echo", Agent: "a", Token: tok}); err != nil {
			t.Fatalf("valid request %d: %v", i, err)
		}
	}
	if n := v.AuthFailureLimiter().Count("a"); n != 0 {
		t.Fatalf("successful verifications left %d recorded failures", n)
	}
}
