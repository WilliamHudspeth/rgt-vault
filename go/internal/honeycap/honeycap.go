// Package honeycap implements honey capabilities (RGT-30): decoy capability
// names that look like real, high-value capabilities ("aws.admin.full"),
// are never registered or granted, and whose every invocation is a
// detection signal for lateral movement or unauthorized exploration.
//
// A Set plugs into vault.Config.HoneyCapabilities. vault.ExecuteCapability
// then, for a honey name:
//
//   - writes a HONEY_CAPABILITY_TRIGGERED audit row (agent, name, version,
//     entry point, whether a token came with the call, the number of payload
//     keys; never the token or payload values);
//   - raises an approval.EventHoneyCapability security event through the
//     configured approval.Notifier (log line, and the --security-webhook
//     when one is set). The event kind is Critical, so the webhook keeps
//     capacity for it under an event flood;
//   - and otherwise answers exactly as it would for any unregistered
//     capability name (same status, same body), so a prober cannot tell
//     that it hit a trap.
//
// Names match case-insensitively after trimming surrounding whitespace, so
// "AWS.Admin.Full " trips the same trap. vault.Open refuses a registry in
// which a registered capability matches a honey name under that same
// matching, and the registry then refuses such names.
//
// Flood limits: audit rows per agent are capped (vault.HoneyAuditPerAgent,
// then powers of two), alerts are de-duplicated per (agent, name) per
// AlertWindow, names are clipped to vault.HoneyNameClip bytes, and the
// security webhook gives honey events their own delivery budget.
//
// Configuration: DefaultNames are always active. A policy file that is a
// mapping may add more under a top-level "honey_capabilities" list; the ABAC
// engine (Go and Python) ignores that key:
//
//	honey_capabilities:
//	  - payments.wire.unrestricted
//	rules:
//	  - {agent: "*", effect: deny}
//
// The default names are public (they are in this source file), so operators
// should add names that fit their own deployment.
package honeycap

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"

	"rgt-vault-server/internal/approval"
	"rgt-vault-server/internal/vault"
)

// Event is the audit action and security-event kind of a honey probe.
const Event = vault.HoneyCapabilityEvent

// PolicyKey is the top-level policy-file key that lists extra honey names.
const PolicyKey = "honey_capabilities"

// MaxNameLen bounds a configured honey name, in bytes.
const MaxNameLen = 128

// AlertWindow is the default per-(agent, name) alert de-duplication window.
const AlertWindow = time.Minute

// maxAlertKeys bounds the de-duplication state; past it, agents share one
// window per honey name.
const maxAlertKeys = 4096

// DefaultNames are the honey capabilities registered by default. They are
// named like the most tempting capabilities an attacker could hope for.
var DefaultNames = []string{
	"aws.admin.full",
	"iam.root.assume",
	"secrets.export_all",
	"vault.master_key.read",
	"db.prod.superuser",
}

// ErrConfig is an invalid honey-capability configuration.
var ErrConfig = errors.New("honeycap: invalid configuration")

var _ vault.HoneyDetector = (*Set)(nil)

// Set is an immutable set of honey capability names plus the alert channel.
// It is safe for concurrent use.
type Set struct {
	names    map[string]string // normalized -> configured spelling
	notifier approval.Notifier
	now      func() time.Time
	window   time.Duration
	trips    atomic.Uint64

	suppressed atomic.Uint64
	mu         sync.Mutex
	alerts     map[string]*alertWindow
}

// Option configures a Set.
type Option func(*Set)

// WithNotifier sets where alerts go. Nil (the default) means
// approval.LogNotifier, so a probe always reaches the log.
func WithNotifier(n approval.Notifier) Option {
	return func(s *Set) {
		if n != nil {
			s.notifier = n
		}
	}
}

// WithAlertWindow sets the alert de-duplication window (default
// AlertWindow; d <= 0 keeps the default).
func WithAlertWindow(d time.Duration) Option {
	return func(s *Set) {
		if d > 0 {
			s.window = d
		}
	}
}

// WithClock overrides the event time source (tests).
func WithClock(now func() time.Time) Option { return func(s *Set) { s.now = now } }

func normalize(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

func validName(n string) bool {
	if n == "" || len(n) > MaxNameLen {
		return false
	}
	for _, c := range n {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-', c == ':', c == '/':
		default:
			return false
		}
	}
	return true
}

// New returns a Set of DefaultNames plus extra. Every name must be 1 to
// MaxNameLen bytes of [A-Za-z0-9._:/-]; duplicates (after normalization)
// are merged.
func New(extra []string, opts ...Option) (*Set, error) {
	s := &Set{names: map[string]string{}, notifier: approval.LogNotifier{}, now: time.Now,
		window: AlertWindow, alerts: map[string]*alertWindow{}}
	for _, o := range opts {
		o(s)
	}
	for _, n := range append(append([]string(nil), DefaultNames...), extra...) {
		if !validName(n) {
			return nil, fmt.Errorf("%w: honey capability name %s must be 1-%d characters of [A-Za-z0-9._:/-]",
				ErrConfig, strconv.Quote(vault.ClipHoneyName(n)), MaxNameLen)
		}
		if _, dup := s.names[normalize(n)]; !dup {
			s.names[normalize(n)] = n
		}
	}
	return s, nil
}

// Default returns a Set of DefaultNames only.
func Default(opts ...Option) *Set {
	s, err := New(nil, opts...)
	if err != nil { // DefaultNames are valid; TestDefaultNamesValid pins it
		panic(err)
	}
	return s
}

// FromPolicyYAML returns DefaultNames plus the names listed under the
// policy's top-level "honey_capabilities" key. A policy that is empty, a
// bare rule list, or a mapping without the key yields the defaults. A key
// whose value is not a list of strings is an error (fail loud: a typo must
// not silently disable a trap).
func FromPolicyYAML(policyYAML string, opts ...Option) (*Set, error) {
	extra, err := policyNames(policyYAML)
	if err != nil {
		return nil, err
	}
	return New(extra, opts...)
}

func policyNames(src string) ([]string, error) {
	if strings.TrimSpace(src) == "" {
		return nil, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		// The policy engine reports malformed YAML; nothing to add here.
		return nil, nil
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil
	}
	root := doc.Content[0]
	var val *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if k := root.Content[i]; k.Kind == yaml.ScalarNode && k.Value == PolicyKey {
			val = root.Content[i+1]
		}
	}
	if val == nil {
		return nil, nil
	}
	if val.Kind == yaml.ScalarNode && val.Tag == "!!null" {
		return nil, nil
	}
	if val.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%w: %q must be a list of capability names", ErrConfig, PolicyKey)
	}
	out := make([]string, 0, len(val.Content))
	for _, it := range val.Content {
		if it.Kind != yaml.ScalarNode || it.Tag != "!!str" {
			return nil, fmt.Errorf("%w: %q entries must be strings", ErrConfig, PolicyKey)
		}
		out = append(out, it.Value)
	}
	return out, nil
}

// IsHoney implements vault.HoneyDetector.
func (s *Set) IsHoney(name string) bool {
	_, ok := s.names[normalize(name)]
	return ok
}

// Names implements vault.HoneyDetector: the configured names, sorted.
func (s *Set) Names() []string {
	out := make([]string, 0, len(s.names))
	for _, n := range s.names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Trips is the number of probes seen since the Set was created.
func (s *Set) Trips() uint64 { return s.trips.Load() }

// Tripped implements vault.HoneyDetector: it raises a Critical
// HONEY_CAPABILITY_TRIGGERED security event. The event carries the agent,
// the (clipped, quoted) name, the version and the entry point; never a token
// or payload value. A panicking notifier is contained.
//
// Alerts are de-duplicated per (agent, honey name): the first probe alerts
// at once; further probes within AlertWindow are only counted, and the next
// alert after the window says how many were suppressed. (The audit log
// records the probes themselves; see vault.HoneyAuditPerAgent.)
func (s *Set) Tripped(ctx context.Context, p vault.HoneyProbe) {
	s.trips.Add(1)
	suppressed, send := s.admitAlert(p.Agent, p.Capability)
	if !send {
		return
	}
	detail := fmt.Sprintf("honey capability %s probed via %s (version %d, token presented: %t)",
		strconv.Quote(vault.ClipHoneyName(p.Capability)), p.Source, p.Version, p.TokenPresented)
	if suppressed > 0 {
		detail += fmt.Sprintf("; %d earlier alerts for this agent and name suppressed", suppressed)
	}
	e := approval.Event{
		Kind:   approval.EventHoneyCapability,
		Agent:  vault.ClipHoneyName(p.Agent),
		Detail: detail,
		Time:   s.now(),
	}
	defer func() { _ = recover() }()
	s.notifier.Notify(ctx, e)
}

// Suppressed returns how many alerts de-duplication has dropped so far.
func (s *Set) Suppressed() uint64 { return s.suppressed.Load() }

type alertWindow struct {
	start      time.Time
	suppressed uint64
}

// admitAlert applies the per-(agent, name) alert window. The key uses the
// normalized honey name, so spelling variants share one window.
func (s *Set) admitAlert(agent, name string) (uint64, bool) {
	key := vault.ClipHoneyName(agent) + "\x00" + normalize(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if _, known := s.alerts[key]; !known && len(s.alerts) >= maxAlertKeys {
		for k, w := range s.alerts {
			if now.Sub(w.start) >= s.window {
				delete(s.alerts, k)
			}
		}
		if len(s.alerts) >= maxAlertKeys {
			key = "\x00overflow\x00" + normalize(name)
		}
	}
	w := s.alerts[key]
	if w != nil && now.Sub(w.start) < s.window {
		w.suppressed++
		s.suppressed.Add(1)
		return 0, false
	}
	var prev uint64
	if w != nil {
		prev = w.suppressed
	}
	s.alerts[key] = &alertWindow{start: now}
	return prev, true
}
