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
	windows map[string][]rateEvent
	seq     uint64
}

// rateEvent is one recorded event. seq identifies it so a reservation can
// be taken back (RateSlot.Release) without disturbing other events.
type rateEvent struct {
	at  time.Time
	seq uint64
}

// NewRateLimiter returns a limiter allowing max events per key per window.
// A non-positive window means DefaultRateWindow (a zero window would let
// every event expire at once, i.e. fail open); a negative max allows nothing.
func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	if window <= 0 {
		window = DefaultRateWindow
	}
	return &RateLimiter{max: max, window: window, now: time.Now, windows: map[string][]rateEvent{}}
}

// prune drops events outside the window; the caller holds mu. Empty keys are
// deleted so the map does not grow with every agent ever seen.
func (r *RateLimiter) prune(key string, now time.Time) []rateEvent {
	old := r.windows[key]
	kept := old[:0]
	for _, e := range old {
		if now.Sub(e.at) < r.window {
			kept = append(kept, e)
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
	r.windows[key] = append(w, r.event(now))
	return true
}

// event makes a new event stamped now; the caller holds mu.
func (r *RateLimiter) event(now time.Time) rateEvent {
	r.seq++
	return rateEvent{at: now, seq: r.seq}
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
	r.windows[key] = append(r.prune(key, now), r.event(now))
}

// RateSlot is one event taken by Reserve. It stays recorded after Commit and
// is taken back by Release; both are idempotent and the first call wins.
type RateSlot struct {
	r    *RateLimiter
	key  string
	seq  uint64
	done bool // guarded by r.mu
}

// Reserve is the race-free "check the cap, then record" step (RGT-256,
// RGT-257): under ONE lock it refuses (nil, false) when key already has max
// events in the window and otherwise records an event and returns it as a
// slot. The caller does its work, then Commits the slot (the event counts,
// for example a failed credential check) or Releases it (it does not).
//
// This replaces Count followed by Record, where N concurrent callers could
// all pass the check before any of them recorded, overshooting the cap by
// N-1. While a slot is held it counts against the cap, so a burst of
// concurrent attempts sees at most max of them admitted.
func (r *RateLimiter) Reserve(key string) (*RateSlot, bool) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	w := r.prune(key, now)
	if len(w) >= r.max {
		return nil, false
	}
	e := r.event(now)
	r.windows[key] = append(w, e)
	return &RateSlot{r: r, key: key, seq: e.seq}, true
}

// Commit keeps the slot's event recorded.
func (s *RateSlot) Commit() {
	s.r.mu.Lock()
	s.done = true
	s.r.mu.Unlock()
}

// Release takes the slot's event back, unless Commit or Release already ran.
func (s *RateSlot) Release() {
	s.r.mu.Lock()
	defer s.r.mu.Unlock()
	if s.done {
		return
	}
	s.done = true
	w := s.r.windows[s.key]
	for i, e := range w {
		if e.seq == s.seq {
			w = append(w[:i], w[i+1:]...)
			break
		}
	}
	if len(w) == 0 {
		delete(s.r.windows, s.key)
		return
	}
	s.r.windows[s.key] = w
}
