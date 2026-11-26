package vault

import (
	"sync"
	"time"
)

// RateLimiter is the in-memory sliding-window limiter of python/vault.py
// (RateLimiter): at most max events per key within window. It is safe for
// concurrent use.
type RateLimiter struct {
	max    int
	window time.Duration
	now    func() time.Time

	mu      sync.Mutex
	windows map[string][]time.Time
}

// NewRateLimiter returns a limiter allowing max events per key per window.
func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	return &RateLimiter{max: max, window: window, now: time.Now, windows: map[string][]time.Time{}}
}

// prune drops events outside the window; the caller holds mu. Empty keys are
// deleted so the map does not grow with every agent ever seen.
func (r *RateLimiter) prune(key string, now time.Time) []time.Time {
	old := r.windows[key]
	kept := old[:0]
	for _, t := range old {
		if now.Sub(t) < r.window {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(r.windows, key)
		return nil
	}
	r.windows[key] = kept
	return kept
}

// Allow records one event for key and reports true, or reports false
// without recording when key is already at the cap (Python allow()).
func (r *RateLimiter) Allow(key string) bool {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	w := r.prune(key, now)
	if len(w) >= r.max {
		return false
	}
	r.windows[key] = append(w, now)
	return true
}

// Count returns the number of events for key in the current window without
// recording anything (Python count(), RGT-277).
func (r *RateLimiter) Count(key string) int {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.prune(key, now))
}

// Record unconditionally records one event for key, with no cap check
// (Python record(), RGT-277).
func (r *RateLimiter) Record(key string) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.windows[key] = append(r.windows[key], now)
}
