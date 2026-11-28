package actions

// Destination allow-list (RGT-523, docs/design/destinations.md): each secret
// is bound to the hosts it may be sent to, and the HTTP actions refuse any
// other destination before a connection is made.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/netguard"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/policy"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/validation"
)

// ErrDestinationRefused is the kind of a destination refusal (HTTP 403).
var ErrDestinationRefused = errors.New("destination refused")

// Refusal reason codes (audit rows and alerts).
const (
	ReasonNoList              = "NO_LIST"
	ReasonHostNotListed       = "HOST_NOT_LISTED"
	ReasonPortMismatch        = "PORT_MISMATCH"
	ReasonIPLiteral           = "IP_LITERAL"
	ReasonNonASCIIHost        = "NON_ASCII_HOST" // load-time only: netguard refuses such URLs first
	ReasonRedirectOffList     = "REDIRECT_OFF_LIST"
	ReasonRedirectCrossOrigin = "REDIRECT_CROSS_ORIGIN"
)

// DestinationMode is the serve --destinations switch.
type DestinationMode int

const (
	// DestinationsEnforce refuses every destination that is not allowed.
	DestinationsEnforce DestinationMode = iota
	// DestinationsWarn relaxes ONLY secrets that have no entry at all
	// (NO_LIST): they are sent after a DESTINATION_REFUSED row (mode=warn)
	// was written. A secret that has an entry is always enforced. Temporary,
	// for migration to v0.4.0.
	DestinationsWarn
)

func (m DestinationMode) String() string {
	if m == DestinationsWarn {
		return "warn"
	}
	return "enforce"
}

// ParseDestinationMode parses "enforce" (or "") and "warn".
func ParseDestinationMode(s string) (DestinationMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "enforce":
		return DestinationsEnforce, nil
	case "warn":
		return DestinationsWarn, nil
	}
	return 0, fmt.Errorf("--destinations must be enforce or warn, not %q", s)
}

// ---------------------------------------------------------------------------
// Secret identity on the context
// ---------------------------------------------------------------------------

// SecretUse names the secret an action runs with. Callers that lease a
// secret for an action put it on the context (WithSecretUse) with exactly
// the values they passed to vault.Lease.
type SecretUse struct {
	Agent     string
	Namespace string
	Name      string
	Purpose   string
}

type secretUseKey struct{}

// WithSecretUse returns ctx carrying u.
func WithSecretUse(ctx context.Context, u SecretUse) context.Context {
	return context.WithValue(ctx, secretUseKey{}, u)
}

// SecretUseFrom returns the SecretUse on ctx, if any.
func SecretUseFrom(ctx context.Context) (SecretUse, bool) {
	u, ok := ctx.Value(secretUseKey{}).(SecretUse)
	return u, ok
}

// ---------------------------------------------------------------------------
// Entries and normalisation
// ---------------------------------------------------------------------------

// Destination is one parsed allow-list entry. Only https matches.
type Destination struct {
	host     string // canonical: lower-case, no trailing dot; IPs in netip form
	wildcard bool   // "*.base": exactly one extra label, never the base itself
	ip       bool
	port     int // always set (443 by default)
}

// String renders the entry in canonical form.
func (d Destination) String() string {
	h := d.host
	if d.wildcard {
		h = "*." + h
	}
	return net.JoinHostPort(h, strconv.Itoa(d.port))
}

// Suffix lists used to refuse wildcards over public or shared bases. They
// are a guard against obvious mistakes, not a public-suffix list.
var (
	publicLabels = setOf("com", "net", "org", "io", "dev", "app", "co", "uk", "de", "eu",
		"info", "biz", "cloud", "ai", "me", "us")
	secondLevel = setOf("co", "com", "net", "org", "ac", "gov", "edu", "ne", "or", "go",
		"gob", "mil", "ltd", "plc", "sch", "nhs")
	sharedHosting = setOf("vercel.app", "netlify.app", "workers.dev", "pages.dev",
		"herokuapp.com", "azurewebsites.net", "ngrok-free.app", "ngrok.io",
		"trycloudflare.com", "firebaseapp.com", "web.app", "appspot.com")
	warnHosting = setOf("github.io", "s3.amazonaws.com")
)

func setOf(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// destError is a load-time entry error; Reason is NON_ASCII_HOST for
// non-ASCII input, empty otherwise.
type destError struct {
	Entry, Why, Reason string
}

func (e *destError) Error() string { return fmt.Sprintf("%q: %s", e.Entry, e.Why) }

// ParseDestination parses one entry: "https://host[:port]", "host[:port]"
// or "*.example.com[:port]" (IPv6 in brackets). See the design note for the
// rules.
func ParseDestination(entry string) (Destination, error) {
	d, _, err := parseDestination(entry)
	return d, err
}

// parseDestination also returns a load warning (a wildcard over a base
// where third parties can get names, such as *.github.io).
func parseDestination(entry string) (Destination, string, error) {
	bad := func(why string) (Destination, string, error) {
		return Destination{}, "", &destError{Entry: entry, Why: why}
	}
	for i := 0; i < len(entry); i++ {
		if c := entry[i]; c >= 0x80 {
			return Destination{}, "", &destError{Entry: entry, Reason: ReasonNonASCIIHost,
				Why: "non-ASCII host names are not allowed; write IDNs in punycode (xn--...)"}
		} else if c <= 0x20 || c == 0x7f {
			return bad("contains whitespace or control characters")
		}
	}
	if entry == "" {
		return bad("empty entry")
	}
	hostport := entry
	if i := strings.Index(entry, "://"); i >= 0 {
		scheme := strings.ToLower(entry[:i])
		if scheme != "https" {
			return bad("only https:// destinations are allowed")
		}
		u, err := url.Parse(entry)
		if err != nil || u.Opaque != "" {
			return bad("not a valid URL")
		}
		if u.User != nil {
			return bad("credentials (user@) are not allowed")
		}
		if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(entry[i+3:], "?#") {
			return bad("a destination is scheme://host[:port] only: no path, query or fragment")
		}
		hostport = u.Host
	} else {
		if strings.Contains(entry, "@") {
			return bad("credentials (user@) are not allowed")
		}
		if strings.ContainsAny(entry, "/?#") {
			return bad("a destination is host[:port] only: no path, query or fragment")
		}
	}
	if strings.Contains(hostport, "@") {
		return bad("credentials (user@) are not allowed")
	}
	host, port := hostport, 443
	switch {
	case strings.HasPrefix(hostport, "["):
		end := strings.Index(hostport, "]")
		if end < 0 {
			return bad("unterminated IPv6 literal")
		}
		host = hostport[1:end]
		rest := hostport[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return bad("bad port")
			}
			p, err := parseDestPort(rest[1:])
			if err != nil {
				return bad(err.Error())
			}
			port = p
		}
		a, err := netip.ParseAddr(host)
		if err != nil || !a.Is6() {
			return bad("brackets hold an IPv6 literal only")
		}
	case strings.Count(hostport, ":") > 1:
		return bad("IPv6 literals need brackets: [2001:db8::1]:443")
	case strings.Contains(hostport, ":"):
		h, p, err := net.SplitHostPort(hostport)
		if err != nil {
			return bad("bad host:port")
		}
		pp, err := parseDestPort(p)
		if err != nil {
			return bad(err.Error())
		}
		host, port = h, pp
	}
	d := Destination{port: port}
	if strings.HasPrefix(host, "*.") {
		d.wildcard = true
		host = host[2:]
	}
	if strings.Contains(host, "*") {
		return bad("a wildcard is allowed only as the whole leftmost label (*.example.com)")
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return bad("empty host")
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if d.wildcard {
			return bad("wildcards cannot apply to an IP address")
		}
		if a.Zone() != "" {
			return bad("IPv6 zone identifiers are not allowed")
		}
		if a.Is4In6() {
			return bad("IPv4-mapped IPv6 literals are not allowed; write the IPv4 address")
		}
		d.host, d.ip = a.String(), true
		return d, "", nil
	}
	if why := checkLabels(host); why != "" {
		return bad(why)
	}
	labels := strings.Split(host, ".")
	allNumeric := true
	for _, l := range labels {
		if strings.Trim(l, "0123456789") != "" {
			allNumeric = false
		}
	}
	if allNumeric {
		return bad("ambiguous numeric host; write IP addresses in dotted-decimal form")
	}
	d.host = host
	if !d.wildcard {
		return d, "", nil
	}
	if why := wildcardBaseRefused(labels); why != "" {
		return bad(why)
	}
	if warnHosting[host] {
		return d, fmt.Sprintf("%q: anyone can get a name under %s; prefer the exact host", entry, host), nil
	}
	return d, "", nil
}

func parseDestPort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("port must be 1-65535, not %q", s)
	}
	return p, nil
}

// checkLabels validates a host name (ASCII, already lower-cased).
func checkLabels(host string) string {
	if len(host) > 253 {
		return "host name is longer than 253 characters"
	}
	for _, l := range strings.Split(host, ".") {
		if l == "" {
			return "host name has an empty label"
		}
		if len(l) > 63 {
			return "host name label is longer than 63 characters"
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "host name contains an invalid character"
			}
		}
	}
	return ""
}

func wildcardBaseRefused(labels []string) string {
	base := strings.Join(labels, ".")
	n := len(labels)
	switch {
	case n == 1:
		return "is a wildcard over a public suffix"
	case n == 2 && publicLabels[labels[0]] && publicLabels[labels[1]]:
		return "is a wildcard over a public suffix"
	case n == 2 && len(labels[1]) == 2 && secondLevel[labels[0]]:
		return "is a wildcard over a public suffix"
	case sharedHosting[base]:
		return "is a wildcard over a shared-hosting domain where anyone can get a name; list the exact host"
	case n == 4 && labels[0] == "execute-api" && labels[2] == "amazonaws" && labels[3] == "com",
		n == 4 && labels[0] == "lambda-url" && labels[2] == "on" && labels[3] == "aws":
		return "is a wildcard over a shared-hosting domain where anyone can get a name; list the exact host"
	}
	return ""
}

// target is a request destination, canonicalised like an entry.
type target struct {
	host  string
	port  int
	ip    bool
	https bool
}

func (t target) String() string { return net.JoinHostPort(t.host, strconv.Itoa(t.port)) }

func targetOf(u *url.URL) target {
	t := targetHost(u.Hostname())
	t.https = strings.EqualFold(u.Scheme, "https")
	t.port = 443
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			t.port = n
		} else {
			t.port = -1
		}
	}
	return t
}

func targetHost(h string) target {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if a, err := netip.ParseAddr(h); err == nil {
		return target{host: a.String(), ip: true}
	}
	return target{host: h}
}

func (d Destination) hostMatches(t target) bool {
	if d.ip || t.ip {
		return d.ip && t.ip && d.host == t.host
	}
	if !d.wildcard {
		return d.host == t.host
	}
	prefix, ok := strings.CutSuffix(t.host, "."+d.host)
	return ok && prefix != "" && !strings.Contains(prefix, ".")
}

// refuse returns "" when t is allowed by list, else the reason code.
func refuseBy(list []Destination, t target) string {
	if !t.https {
		return ReasonHostNotListed
	}
	hostSeen := false
	for _, d := range list {
		if d.hostMatches(t) {
			if d.port == t.port {
				return ""
			}
			hostSeen = true
		}
	}
	switch {
	case hostSeen:
		return ReasonPortMismatch
	case t.ip:
		return ReasonIPLiteral
	}
	return ReasonHostNotListed
}

// effective is the decision for one request: the secret's list and every
// narrowing rule list. A destination must pass all of them.
type effective struct {
	lists [][]Destination
}

func (e *effective) refuse(t target) string {
	for _, l := range e.lists {
		if r := refuseBy(l, t); r != "" {
			return r
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

// DestinationRefusal describes one refused (or, in warn mode, relaxed)
// destination. It never holds a path, query, header or body.
type DestinationRefusal struct {
	Use         SecretUse
	Action      string
	Destination string // host:port
	Reason      string
	Mode        DestinationMode
}

// AuditDetails is the details text of the DESTINATION_REFUSED row.
func (r DestinationRefusal) AuditDetails() string {
	return fmt.Sprintf("namespace=%s action=%s destination=%s reason=%s mode=%s",
		r.Use.Namespace, r.Action, r.Destination, r.Reason, r.Mode)
}

// AlertDetail is the security-event text; suppressed is how many identical
// alerts were dropped since the last one.
func (r DestinationRefusal) AlertDetail(suppressed int) string {
	s := fmt.Sprintf("secret=%s/%s %s", r.Use.Namespace, r.Use.Name, r.AuditDetails())
	if suppressed > 0 {
		s += fmt.Sprintf(" suppressed=%d", suppressed)
	}
	return s
}

// DestinationOptions configure NewDestinationPolicy.
type DestinationOptions struct {
	// PolicyYAML is the policy text (the same string the vault parses).
	PolicyYAML string
	Mode       DestinationMode
	// Audit writes the DESTINATION_REFUSED row. In warn mode a relaxed
	// request is sent only if Audit returned nil. Nil means no audit.
	Audit func(ctx context.Context, r DestinationRefusal) error
	// Alert raises the security event (after de-duplication). Nil: none.
	Alert func(ctx context.Context, r DestinationRefusal, suppressed int)
	// AlertWindow is the de-duplication window (default one minute).
	AlertWindow time.Duration
	// Now is the clock for de-duplication (tests).
	Now func() time.Time
}

// DestinationPolicy is the parsed destination allow-list plus the per-rule
// narrowing lists. It is immutable after NewDestinationPolicy and safe for
// concurrent use.
type DestinationPolicy struct {
	mode      DestinationMode
	secrets   map[string][]Destination // "ns/name"
	spaces    map[string][]Destination // "ns" (from "ns/*")
	engine    *policy.Engine
	ruleHosts map[int][]Destination // rule index -> allowed_hosts
	listForm  bool
	present   bool
	warnings  []string
	audit     func(context.Context, DestinationRefusal) error
	alert     func(context.Context, DestinationRefusal, int)
	limiter   *alertLimiter
}

// NewDestinationPolicy parses the destinations section and the rules'
// allowed_hosts of policyYAML. Any malformed key or entry is an error that
// names it. A policy without a destinations section yields an empty policy:
// every secret is NO_LIST.
func NewDestinationPolicy(o DestinationOptions) (*DestinationPolicy, error) {
	doc, err := policy.DestinationsFromYAML(o.PolicyYAML)
	if err != nil {
		return nil, err
	}
	eng, err := policy.Parse(o.PolicyYAML)
	if err != nil {
		return nil, err
	}
	p := &DestinationPolicy{
		mode: o.Mode, secrets: map[string][]Destination{}, spaces: map[string][]Destination{},
		engine: eng, ruleHosts: map[int][]Destination{}, listForm: doc.ListForm, present: doc.Present,
		audit: o.Audit, alert: o.Alert, limiter: newAlertLimiter(o.AlertWindow, o.Now),
	}
	for _, key := range doc.Keys {
		ns, name, ok := strings.Cut(key, "/")
		if !ok {
			return nil, keyErr(key, `a key is "namespace/name" or "namespace/*"`)
		}
		if _, err := validation.ValidateNamespace(ns); err != nil {
			return nil, keyErr(key, err.Error())
		}
		if name != "*" {
			if _, err := validation.ValidateName(name); err != nil {
				return nil, keyErr(key, err.Error())
			}
		}
		list, warns, err := parseList(doc.Entries[key])
		if err != nil {
			return nil, keyErr(key, err.Error())
		}
		for _, w := range warns {
			p.warnings = append(p.warnings, fmt.Sprintf("destinations: %q: %s", key, w))
		}
		if name == "*" {
			p.spaces[ns] = list
		} else {
			p.secrets[key] = list
		}
	}
	for i, r := range eng.Rules() {
		v, ok := r.Get(policy.AllowedHostsKey)
		if !ok {
			continue
		}
		raw, isList := v.([]any)
		if !isList {
			return nil, fmt.Errorf("%w: rule %d: %q must be a list of hosts (use [] to allow none)", policy.ErrInvalid, i, policy.AllowedHostsKey)
		}
		strs := make([]string, 0, len(raw))
		for _, it := range raw {
			s, isStr := it.(string)
			if !isStr {
				return nil, fmt.Errorf("%w: rule %d: %q entries must be strings", policy.ErrInvalid, i, policy.AllowedHostsKey)
			}
			strs = append(strs, s)
		}
		list, warns, err := parseList(strs)
		if err != nil {
			return nil, fmt.Errorf("%w: rule %d: %q: %v", policy.ErrInvalid, i, policy.AllowedHostsKey, err)
		}
		for _, w := range warns {
			p.warnings = append(p.warnings, fmt.Sprintf("destinations: rule %d allowed_hosts: %s", i, w))
		}
		p.ruleHosts[i] = list
	}
	return p, nil
}

func parseList(entries []string) ([]Destination, []string, error) {
	out := make([]Destination, 0, len(entries))
	var warns []string
	for _, e := range entries {
		d, w, err := parseDestination(e)
		if err != nil {
			return nil, nil, err
		}
		if w != "" {
			warns = append(warns, w)
		}
		out = append(out, d)
	}
	return out, warns, nil
}

func keyErr(key, why string) error {
	return fmt.Errorf("%w: destinations: %q: %s", policy.ErrInvalid, key, why)
}

// Mode returns the configured mode.
func (p *DestinationPolicy) Mode() DestinationMode { return p.mode }

// lookup returns the secret's list: the exact entry, else the namespace
// entry. ok is false when there is neither (NO_LIST).
func (p *DestinationPolicy) lookup(ns, name string) ([]Destination, bool) {
	if l, ok := p.secrets[ns+"/"+name]; ok {
		return l, true
	}
	l, ok := p.spaces[ns]
	return l, ok
}

// decide builds the effective lists for u.
func (p *DestinationPolicy) decide(u SecretUse) (*effective, bool) {
	l, ok := p.lookup(u.Namespace, u.Name)
	if !ok {
		return nil, false
	}
	e := &effective{lists: [][]Destination{l}}
	for _, i := range p.engine.MatchingAllowRules(u.Agent, u.Namespace, u.Purpose, "read") {
		if rl, has := p.ruleHosts[i]; has {
			e.lists = append(e.lists, rl)
		}
	}
	return e, true
}

// record audits and alerts one refusal. It returns the audit error.
func (p *DestinationPolicy) record(ctx context.Context, r DestinationRefusal) error {
	var err error
	if p.audit != nil {
		err = p.audit(ctx, r)
	}
	if p.alert != nil {
		key := r.Use.Agent + "\x00" + r.Use.Namespace + "/" + r.Use.Name + "\x00" + r.Destination + "\x00" + r.Reason
		if send, suppressed := p.limiter.admit(key); send {
			p.alert(ctx, r, suppressed)
		}
	}
	return err
}

func noListErr(u SecretUse) error {
	return &Error{kind: ErrDestinationRefused, msg: fmt.Sprintf(
		`no destination is allowed for secret %s/%s: add it under "destinations:" in the policy file`, u.Namespace, u.Name)}
}

func refusedErr(u SecretUse, t target, reason string) error {
	return &Error{kind: ErrDestinationRefused, msg: fmt.Sprintf(
		"destination %s is not allowed for secret %s/%s (%s)", t, u.Namespace, u.Name, reason)}
}

var errNoIdentity = &Error{kind: ErrDestinationRefused,
	msg: "no destination is allowed: the request does not name the secret it uses"}

var errNoPolicy = &Error{kind: ErrDestinationRefused,
	msg: `no destination is allowed: no destination policy is configured (add "destinations:" to the policy file)`}

// authorize is the check in endpoint.send. It returns the context to send
// with (carrying the netguard backstop) or the refusal.
func (p *DestinationPolicy) authorize(ctx context.Context, action string, u *url.URL) (context.Context, error) {
	use, ok := SecretUseFrom(ctx)
	if !ok {
		return ctx, errNoIdentity
	}
	t := targetOf(u)
	eff, has := p.decide(use)
	if !has {
		r := DestinationRefusal{Use: use, Action: action, Destination: t.String(), Reason: ReasonNoList, Mode: p.mode}
		aerr := p.record(ctx, r)
		if p.mode == DestinationsWarn {
			if aerr != nil {
				return ctx, execErr("Request not sent: the destination audit row could not be written.")
			}
			return ctx, nil
		}
		return ctx, noListErr(use)
	}
	if reason := eff.refuse(t); reason != "" {
		_ = p.record(ctx, DestinationRefusal{Use: use, Action: action, Destination: t.String(), Reason: reason, Mode: p.mode})
		return ctx, refusedErr(use, t, reason)
	}
	return netguard.WithHostCheck(ctx, &destCheck{p: p, eff: eff, use: use, action: action}), nil
}

// destCheck is the netguard backstop: the dial and every redirect hop are
// re-checked against the same effective lists.
type destCheck struct {
	p      *DestinationPolicy
	eff    *effective
	use    SecretUse
	action string
}

func (c *destCheck) refuse(ctx context.Context, t target, reason string) error {
	_ = c.p.record(ctx, DestinationRefusal{Use: c.use, Action: c.action, Destination: t.String(), Reason: reason, Mode: c.p.mode})
	return refusedErr(c.use, t, reason)
}

func (c *destCheck) CheckDial(ctx context.Context, host string, port int) error {
	t := targetHost(host)
	t.port, t.https = port, true // the scheme was checked on the URL
	if reason := c.eff.refuse(t); reason != "" {
		return c.refuse(ctx, t, reason)
	}
	return nil
}

func (c *destCheck) CheckRedirect(ctx context.Context, first, next *url.URL) error {
	t := targetOf(next)
	if reason := c.eff.refuse(t); reason != "" {
		return c.refuse(ctx, t, ReasonRedirectOffList)
	}
	f := targetOf(first)
	if f.host != t.host || f.port != t.port || f.https != t.https {
		return c.refuse(ctx, t, ReasonRedirectCrossOrigin)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Start-up warnings
// ---------------------------------------------------------------------------

// SecretRef names a stored secret (namespace and name only).
type SecretRef struct{ Namespace, Name string }

// StartupWarnings returns the lines serve logs at start: the mode, load
// warnings, and per-namespace coverage gaps for the stored secrets. They
// name namespaces only, never secret names.
func (p *DestinationPolicy) StartupWarnings(stored []SecretRef) []string {
	var out []string
	if p.mode == DestinationsWarn {
		out = append(out, "destinations: WARN mode: secrets without an entry may be sent to any host (--destinations=warn is temporary and will be removed in the next release)")
	}
	switch {
	case p.listForm:
		out = append(out, `destinations: the policy file is a bare list of rules, so it cannot hold a "destinations:" section: convert it to a mapping with "rules:" and "destinations:"`)
	case !p.present:
		out = append(out, `destinations: the policy has no "destinations:" section: HTTP actions (http_get_with_auth, http_post_with_auth, openai_chat) are refused for every secret`)
	}
	out = append(out, p.warnings...)
	missing := map[string]int{}
	have := map[string]bool{}
	for _, s := range stored {
		have[s.Namespace+"/"+s.Name] = true
		if _, ok := p.lookup(s.Namespace, s.Name); !ok {
			missing[s.Namespace]++
		}
	}
	consequence := "HTTP actions with them are refused"
	if p.mode == DestinationsWarn {
		consequence = "HTTP actions with them are sent to any host (warn mode)"
	}
	for _, ns := range sortedKeys(missing) {
		out = append(out, fmt.Sprintf("destinations: namespace %q has %d secret(s) with no destinations entry; %s", ns, missing[ns], consequence))
	}
	unknown := map[string]int{}
	for key := range p.secrets {
		if !have[key] {
			ns, _, _ := strings.Cut(key, "/")
			unknown[ns]++
		}
	}
	for _, ns := range sortedKeys(unknown) {
		out = append(out, fmt.Sprintf("destinations: namespace %q has %d destinations entr%s naming no stored secret (a typo leaves the real secret on the namespace entry or none)", ns, unknown[ns], plural(unknown[ns], "y", "ies")))
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Alert de-duplication
// ---------------------------------------------------------------------------

const alertMaxKeys = 4096

type alertWindow struct {
	start      time.Time
	suppressed int
}

// alertLimiter lets one alert per key per window through and counts the
// rest; the next alert for the key reports that count.
type alertLimiter struct {
	mu     sync.Mutex
	window time.Duration
	now    func() time.Time
	m      map[string]*alertWindow
}

func newAlertLimiter(window time.Duration, now func() time.Time) *alertLimiter {
	if window <= 0 {
		window = time.Minute
	}
	if now == nil {
		now = time.Now
	}
	return &alertLimiter{window: window, now: now, m: map[string]*alertWindow{}}
}

func (l *alertLimiter) admit(key string) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	w := l.m[key]
	if w == nil && len(l.m) >= alertMaxKeys {
		for k, old := range l.m {
			if now.Sub(old.start) >= l.window && old.suppressed == 0 {
				delete(l.m, k)
			}
		}
		if len(l.m) >= alertMaxKeys {
			key = "\x00overflow"
			w = l.m[key]
		}
	}
	if w == nil || now.Sub(w.start) >= l.window {
		sup := 0
		if w != nil {
			sup = w.suppressed
		}
		l.m[key] = &alertWindow{start: now}
		return true, sup
	}
	w.suppressed++
	return false, 0
}
