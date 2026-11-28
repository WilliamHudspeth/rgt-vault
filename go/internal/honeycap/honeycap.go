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
// "AWS.Admin.Full " trips the same trap. vault.Open refuses a configuration
// in which a honey name is also a registered capability.
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

// maxDetailName bounds how much of a probed name reaches an alert.
const maxDetailName = 128

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
	trips    atomic.Uint64
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
	s := &Set{names: map[string]string{}, notifier: approval.LogNotifier{}, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	for _, n := range append(append([]string(nil), DefaultNames...), extra...) {
		if !validName(n) {
			return nil, fmt.Errorf("%w: honey capability name %s must be 1-%d characters of [A-Za-z0-9._:/-]",
				ErrConfig, strconv.Quote(clip(n)), MaxNameLen)
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
func (s *Set) Tripped(ctx context.Context, p vault.HoneyProbe) {
	s.trips.Add(1)
	e := approval.Event{
		Kind:  approval.EventHoneyCapability,
		Agent: clip(p.Agent),
		Detail: fmt.Sprintf("honey capability %s probed via %s (version %d, token presented: %t)",
			strconv.Quote(clip(p.Capability)), p.Source, p.Version, p.TokenPresented),
		Time: s.now(),
	}
	defer func() { _ = recover() }()
	s.notifier.Notify(ctx, e)
}

func clip(v string) string {
	if len(v) <= maxDetailName {
		return v
	}
	// Cut on a rune boundary.
	cut := maxDetailName
	for cut > 0 && !utf8RuneStart(v[cut]) {
		cut--
	}
	return v[:cut] + "..."
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }
