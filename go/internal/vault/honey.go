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
)

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

// checkHoneyRegistry refuses a configuration in which a honey name is
// actually registered: a trap that could be granted is not a trap.
func checkHoneyRegistry(h HoneyDetector, reg CapabilityRegistry) error {
	if h == nil || reg == nil {
		return nil
	}
	for _, n := range h.Names() {
		if spec, err := reg.Lookup(n); err == nil && spec != nil {
			return fmt.Errorf("vault: honey capability %q is also a registered capability", n)
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
	details := pyDumps(pyObject{
		{"agent", p.Agent},
		{"capability", p.Capability},
		{"capability_version", p.Version},
		{"severity", "critical"},
		{"source", p.Source},
		{"token_presented", p.TokenPresented},
		{"payload_keys", p.PayloadKeys},
	})
	_ = v.withR(func() error {
		return v.logAudit(ctx, HoneyCapabilityEvent, sql.NullString{}, details)
	})
	v.honey.Tripped(ctx, p)
	return true
}
