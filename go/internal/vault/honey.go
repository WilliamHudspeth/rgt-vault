package vault

// Honey capabilities (RGT-30): decoy capability names that are never
// granted. ExecuteCapability records every attempt on one as a
// HONEY_CAPABILITY_TRIGGERED audit row and raises an alert through the
// detector, then carries on down the ordinary path, so the caller gets
// exactly the answer any other unregistered capability would give: there is
// no response that tells a prober it hit a trap. The detector itself lives
// in internal/honeycap.

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"
)

// Honey audit flood limits (RGT-30 review MED-1). Within one window an agent
// gets a HONEY_CAPABILITY_TRIGGERED row for each of its first
// HoneyAuditPerAgent probes; after that only for the probes whose running
// count is a power of two (64, 128, 256, ...). Every row carries
// "probes_in_window", so the log still says how many probes there were
// while a flood adds only O(log n) rows. The alert side has its own
// de-duplication (internal/honeycap).
const (
	HoneyAuditPerAgent = 32
	HoneyAuditWindow   = time.Minute
	// honeyMaxAgents bounds the limiter; past it, agents share one bucket.
	honeyMaxAgents = 4096
	// HoneyNameClip is how many bytes of a probed name reach an audit row
	// or an alert; the rest is replaced by a "(+N bytes)" marker.
	HoneyNameClip = 128
)

// ClipHoneyName cuts s to at most HoneyNameClip bytes on a rune boundary
// and appends "(+N bytes)" naming what was cut.
func ClipHoneyName(s string) string {
	if len(s) <= HoneyNameClip {
		return s
	}
	cut := HoneyNameClip
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "(+" + strconv.Itoa(len(s)-cut) + " bytes)"
}

type honeyWindow struct {
	start time.Time
	n     uint64
}

// honeyLimiter decides which probes get an audit row.
type honeyLimiter struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]*honeyWindow
}

func newHoneyLimiter() *honeyLimiter {
	return &honeyLimiter{now: time.Now, m: map[string]*honeyWindow{}}
}

// admit counts a probe by agent and reports the running count in the
// window and whether to write a row for it.
func (l *honeyLimiter) admit(agent string) (uint64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if _, known := l.m[agent]; !known && len(l.m) >= honeyMaxAgents {
		for k, old := range l.m {
			if now.Sub(old.start) >= HoneyAuditWindow {
				delete(l.m, k)
			}
		}
		if len(l.m) >= honeyMaxAgents {
			agent = honeyOverflowKey // every further agent shares one bucket
		}
	}
	w := l.m[agent]
	if w == nil || now.Sub(w.start) >= HoneyAuditWindow {
		w = &honeyWindow{start: now}
		l.m[agent] = w
	}
	w.n++
	return w.n, w.n <= HoneyAuditPerAgent || w.n&(w.n-1) == 0
}

// honeyOverflowKey cannot be an agent id (agent ids are validated text).
const honeyOverflowKey = "\x00overflow"

// HoneyCapabilityEvent is the audit action of a honey-capability probe.
// It is a new, additive event name; no existing row format changes.
const HoneyCapabilityEvent = "HONEY_CAPABILITY_TRIGGERED"

// HoneyProbe describes one attempt on a honey capability. It never carries
// the presented token or the payload values (they may hold secrets).
type HoneyProbe struct {
	// Agent is the calling agent id as the server resolved it.
	Agent string
	// Capability is the requested name exactly as sent.
	Capability string
	// Version is the requested capability_version.
	Version int
	// Source names the entry point ("capability.execute").
	Source string
	// TokenPresented reports whether a non-empty token came with the call.
	TokenPresented bool
	// PayloadKeys is the number of top-level payload keys (not the values).
	PayloadKeys int
}

// HoneyDetector decides which capability names are traps and raises the
// alert for a probe. internal/honeycap.Set implements it.
type HoneyDetector interface {
	// IsHoney reports whether name is a honey capability.
	IsHoney(name string) bool
	// Names lists the configured honey names (used to refuse a registry
	// that registers one of them).
	Names() []string
	// Tripped raises the alert. It must not block for long or panic.
	Tripped(ctx context.Context, p HoneyProbe)
}

// ReservingRegistry is a CapabilityRegistry that can atomically check its
// names against a matcher and refuse matching registrations from then on
// (internal/capabilities.Registry implements it).
type ReservingRegistry interface {
	ReserveNames(reserved func(name string) bool) error
}

// checkHoneyRegistry refuses a configuration in which a registered
// capability is a honey name under the detector's own matching (case and
// surrounding whitespace ignored): a trap that could be granted is not a
// trap, and a real capability shadowed by a trap would be silently
// disabled. A ReservingRegistry also refuses such names from then on.
// Another registry is checked by exact Lookup of the configured names.
func checkHoneyRegistry(h HoneyDetector, reg CapabilityRegistry) error {
	if h == nil || reg == nil {
		return nil
	}
	if rr, ok := reg.(ReservingRegistry); ok {
		if err := rr.ReserveNames(h.IsHoney); err != nil {
			return fmt.Errorf("vault: %w", err)
		}
		return nil
	}
	for _, n := range h.Names() {
		if spec, err := reg.Lookup(n); err == nil && spec != nil {
			return fmt.Errorf("vault: registered capability %q matches a honey capability name; rename one of them", n)
		}
	}
	return nil
}

// honeyProbe records and alerts on a probe of a honey capability. It reports
// whether name is a honey capability. A failed audit write does not change
// the caller's answer (that would be an oracle); the alert still fires.
func (v *Vault) honeyProbe(ctx context.Context, p HoneyProbe) bool {
	if v.honey == nil || !v.honey.IsHoney(p.Capability) {
		return false
	}
	count, write := v.honeyLimit.admit(p.Agent)
	if write {
		v.writeHoneyRow(ctx, p, count)
	}
	v.honey.Tripped(ctx, p)
	return true
}

func (v *Vault) writeHoneyRow(ctx context.Context, p HoneyProbe, count uint64) {
	details := pyDumps(pyObject{
		{"agent", ClipHoneyName(p.Agent)},
		{"capability", ClipHoneyName(p.Capability)},
		{"capability_version", p.Version},
		{"severity", "critical"},
		{"source", p.Source},
		{"token_presented", p.TokenPresented},
		{"payload_keys", p.PayloadKeys},
		{"probes_in_window", int(count)},
	})
	_ = v.withR(func() error {
		return v.logAudit(ctx, HoneyCapabilityEvent, sql.NullString{}, details)
	})
}
