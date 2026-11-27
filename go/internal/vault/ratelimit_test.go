package vault

import (
	"sync"
	"testing"
	"time"
)

func TestRateLimiterSlidingWindow(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	r := NewRateLimiter(2, time.Minute)
	r.now = func() time.Time { return now }

	for i, want := range []bool{true, true, false} {
		if got := r.Allow("a"); got != want {
			t.Fatalf("Allow #%d = %v, want %v (cap of 2)", i+1, got, want)
		}
	}
	if r.Count("a") != 2 || !r.Allow("b") {
		t.Fatal("keys must be independent")
	}
	now = now.Add(59 * time.Second)
	if r.Allow("a") {
		t.Fatal("events inside the window still count")
	}
	now = now.Add(time.Second) // exactly window seconds later: expired (now - t < window)
	if r.Count("a") != 0 || !r.Allow("a") {
		t.Fatal("events at the window edge must expire")
	}

	// Record ignores the cap; Count sees it (RGT-277 auth-failure use).
	for i := 0; i < 5; i++ {
		r.Record("f")
	}
	if r.Count("f") != 5 || r.Allow("f") {
		t.Fatal("Record/Count")
	}
	now = now.Add(time.Hour)
	n := r.Count("f")
	if _, kept := r.windows["f"]; n != 0 || kept {
		t.Fatalf("expired keys not dropped: %v", r.windows)
	}
}

func TestRateLimiterConcurrent(t *testing.T) {
	r := NewRateLimiter(100, time.Hour)
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if r.Allow("x") {
					mu.Lock()
					allowed++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if allowed != 100 {
		t.Fatalf("allowed %d, want exactly 100", allowed)
	}
}
