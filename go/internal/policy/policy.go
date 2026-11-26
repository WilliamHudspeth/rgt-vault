// Package policy is the Go port of python/auth.py (ABACPolicyEngine): a YAML
// attribute-based access-control policy with explicit-deny precedence,
// default deny, fnmatchcase-style matching and per-rule lease TTLs.
//
// Behaviour that is deliberately the same as Python:
//   - the policy is a top-level YAML list of rules or a mapping with a
//     "rules" list; anything else yields an empty rule set (default deny);
//   - missing agent/namespace/purpose/action default to "*";
//   - `effect` is compared case-insensitively; any other effect value is
//     ignored; an explicit "deny" wins over any "allow", regardless of order;
//   - matching is fnmatch.fnmatchcase (see Match): case-sensitive, `*`
//     crosses '/', plus `?`, `[seq]`, `[!seq]`;
//   - the policy hash is sha256(policy text)[:16] hex ("" for empty text);
//   - the default lease TTL is 300 seconds.
//
// Deliberate differences (all fail closed; Python would instead raise on
// the first evaluation that reaches the offending rule):
//   - a malformed policy is rejected when it is loaded: a "rules" value that
//     is not a list (including `rules:` with no value), a rule that is not a mapping, an agent/namespace/
//     purpose/action that is not a string, or a pattern fnmatch cannot
//     translate;
//   - YAML is parsed with yaml.v3 (YAML 1.2 core schema) where PyYAML uses
//     YAML 1.1. The differences that could change a decision are closed (an
//     unquoted yes/no/on/off in agent/namespace/purpose/action is rejected,
//     as Python's evaluation would fail; a ttl like 1e3 or 0o10 is a string
//     as in PyYAML, giving the default TTL); sexagesimal ints (1:30) and
//     duplicate keys inside nested mappings (yaml.v3 rejects them) differ;
//   - int(ttl) of a non-ASCII-digit string falls back to the default TTL.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	// MaxPolicyChars is the policy size cap, in characters (Python len()).
	MaxPolicyChars = 1024 * 1024
	// DefaultLeaseTTL is the lease lifetime, in seconds, when no rule sets one.
	DefaultLeaseTTL = 300
)

var (
	// ErrTooLarge: the policy text exceeds MaxPolicyChars.
	ErrTooLarge = errors.New("policy_yaml exceeds the maximum allowed size of 1MB")
	// ErrInvalid: the policy could not be parsed or is malformed.
	ErrInvalid = errors.New("invalid policy")
)

// Decision is the result of evaluating the policy (Python's evaluate dict).
type Decision struct {
	Allowed     bool   `json:"allowed"`
	Reason      string `json:"reason"`
	MatchedRule *Rule  `json:"matched_rule"`
}

// Explain renders the decision as Python's VaultManager.explain does.
func (d Decision) Explain() string {
	res := "DENIED"
	if d.Allowed {
		res = "ALLOWED"
	}
	rule := "None"
	if d.MatchedRule != nil && d.MatchedRule.Len() > 0 {
		rule = d.MatchedRule.PythonJSON()
	}
	return fmt.Sprintf("Access: %s\nReason: %s\nMatched Rule: %s", res, d.Reason, rule)
}

type attrPattern struct {
	pat *Pattern
}

type engineRule struct {
	rule  *Rule
	attrs [4]attrPattern // agent, namespace, purpose, action
}

var attrNames = [4]string{"agent", "namespace", "purpose", "action"}

// Engine evaluates a parsed policy. It is immutable and safe for concurrent
// use.
type Engine struct {
	rules []engineRule
	hash  string
}

// Parse builds an Engine from policy YAML text (ABACPolicyEngine.__init__).
func Parse(policyYAML string) (*Engine, error) {
	if !utf8.ValidString(policyYAML) {
		return nil, fmt.Errorf("%w: policy is not valid UTF-8", ErrInvalid)
	}
	if len(policyYAML) > MaxPolicyChars && utf8.RuneCountInString(policyYAML) > MaxPolicyChars {
		return nil, ErrTooLarge
	}
	e := &Engine{hash: HashPolicy(policyYAML)}
	if isBlank(policyYAML) {
		return e, nil
	}
	rules, err := parseRules(policyYAML)
	if err != nil {
		return nil, err
	}
	for i, r := range rules {
		er := engineRule{rule: r}
		for a, name := range attrNames {
			pattern := "*"
			if v, ok := r.Get(name); ok {
				s, isStr := v.(string)
				if !isStr {
					return nil, fmt.Errorf("%w: rule %d: %q must be a string", ErrInvalid, i, name)
				}
				pattern = s
			}
			p, err := CompilePattern(pattern)
			if err != nil {
				return nil, fmt.Errorf("%w: rule %d: %q: %w", ErrInvalid, i, name, err)
			}
			er.attrs[a] = attrPattern{pat: p}
		}
		e.rules = append(e.rules, er)
	}
	return e, nil
}

// Load reads and parses a policy file (the Python CLI does read_text).
func Load(path string) (*Engine, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied policy path
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// MaxPolicyChars characters are at most 4 bytes each.
	data, err := io.ReadAll(io.LimitReader(f, 4*MaxPolicyChars+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 4*MaxPolicyChars {
		return nil, ErrTooLarge
	}
	// Python's Path.read_text() translates "\r\n" and "\r" to "\n" (universal
	// newlines) before the size check and the hash; do the same so the
	// audit policy_hash and the size cap agree with Python.
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return Parse(text)
}

// HashPolicy is the vault's policy_hash: sha256 of the UTF-8 policy text,
// hex, first 16 characters; empty for an empty policy.
func HashPolicy(policyYAML string) string {
	if policyYAML == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(policyYAML))
	return hex.EncodeToString(sum[:])[:16]
}

// Hash returns the policy hash recorded in audit rows.
func (e *Engine) Hash() string { return e.hash }

// RuleCount returns the number of rules (len(vault.auth.rules)).
func (e *Engine) RuleCount() int { return len(e.rules) }

// Rules returns the parsed rules in policy order.
func (e *Engine) Rules() []Rule {
	out := make([]Rule, len(e.rules))
	for i, r := range e.rules {
		out[i] = r.rule.clone()
	}
	return out
}

func (r *engineRule) matches(agent, namespace, purpose, action string) bool {
	vals := [4]string{agent, namespace, purpose, action}
	for i := range vals {
		if !r.attrs[i].pat.Match(vals[i]) {
			return false
		}
	}
	return true
}

// Evaluate decides whether agent may perform action on namespace for
// purpose. An explicit deny always wins; no matching allow means default
// deny.
func (e *Engine) Evaluate(agent, namespace, purpose, action string) Decision {
	var allowRule *Rule
	for i := range e.rules {
		er := &e.rules[i]
		if !er.matches(agent, namespace, purpose, action) {
			continue
		}
		switch effectOf(er.rule) {
		case "deny":
			return Decision{Allowed: false, Reason: "Explicit deny rule matched", MatchedRule: copyRule(er.rule)}
		case "allow":
			allowRule = er.rule
		}
	}
	if allowRule != nil {
		return Decision{Allowed: true, Reason: "Allow rule matched", MatchedRule: copyRule(allowRule)}
	}
	return Decision{Allowed: false, Reason: "No matching allow rule (default deny)"}
}

// copyRule hands callers their own copy, so a Decision can never alter the
// engine's rules.
func copyRule(r *Rule) *Rule {
	c := r.clone()
	return &c
}

// Simulate is Evaluate; the validation, hook consultation and audit row that
// Python's VaultManager.simulate adds belong to the vault layer.
func (e *Engine) Simulate(agent, namespace, purpose, action string) Decision {
	return e.Evaluate(agent, namespace, purpose, action)
}

// Explain returns the human-readable simulation text.
func (e *Engine) Explain(agent, namespace, purpose, action string) string {
	return e.Evaluate(agent, namespace, purpose, action).Explain()
}

// effectOf is str(rule.get("effect", "")).lower() restricted to the values
// that matter: any non-string effect cannot equal "allow" or "deny".
func effectOf(r *Rule) string {
	v, ok := r.Get("effect")
	if !ok {
		return ""
	}
	s, isStr := v.(string)
	if !isStr {
		return ""
	}
	return strings.ToLower(s)
}

// LeaseTTL implements get_lease_ttl: among rules whose action equals
// capability (or is "*") and whose agent is the agent, "*" or absent, the
// most specific (exact agent first, then exact action; ties keep policy
// order) decides; a ttl that does not convert with int() or a missing ttl
// yields DefaultLeaseTTL; the result is at least 1.
func (e *Engine) LeaseTTL(agent, capability string) int {
	bestRank := 4
	var best *Rule
	for i := range e.rules {
		r := e.rules[i].rule
		act, ok := r.Get("action")
		if !ok { // r.get("action") is None, which is neither capability nor "*"
			continue
		}
		actS, _ := act.(string)
		if actS != capability && actS != "*" {
			continue
		}
		agentMismatch := true
		if av, ok := r.Get("agent"); !ok {
			agentMismatch = true // None: allowed, but not an exact match
		} else if s, _ := av.(string); s == agent {
			agentMismatch = false
		} else if s != "*" {
			continue
		}
		rank := 0
		if agentMismatch {
			rank += 2
		}
		if actS != capability {
			rank++
		}
		if rank < bestRank {
			bestRank, best = rank, r
		}
	}
	if best != nil {
		if tv, ok := best.Get("ttl"); ok {
			if n, ok := pyIntOf(tv); ok {
				if n < 1 {
					n = 1
				}
				const maxInt = int64(^uint(0) >> 1)
				if n > maxInt {
					n = maxInt
				}
				return int(n)
			}
		}
	}
	return DefaultLeaseTTL
}

// ---------------------------------------------------------------------------
// YAML decoding
// ---------------------------------------------------------------------------

func parseRules(src string) ([]*Rule, error) {
	dec := yaml.NewDecoder(strings.NewReader(src))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) { // only comments/directives: Python parsed None
			return nil, nil
		}
		return nil, fmt.Errorf("%w: Failed to parse policy YAML: %v", ErrInvalid, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: Failed to parse policy YAML: expected a single document", ErrInvalid)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, nil
	}
	if err := checkDocument(doc.Content[0]); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	root := deref(doc.Content[0])
	var rulesNode *yaml.Node
	switch root.Kind {
	case yaml.SequenceNode:
		rulesNode = root
	case yaml.MappingNode:
		pairs, err := flatten(root, 0)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		for _, p := range pairs { // last duplicate wins, as in PyYAML
			if p.key.Tag == "!!str" && p.key.Value == "rules" {
				rulesNode = deref(p.val)
			}
		}
	}
	if rulesNode == nil {
		return nil, nil
	}
	if rulesNode.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%w: \"rules\" must be a list", ErrInvalid)
	}
	var out []*Rule
	for i, item := range rulesNode.Content {
		item = deref(item)
		if item.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%w: rule %d is not a mapping", ErrInvalid, i)
		}
		r, err := ruleFromNode(item)
		if err != nil {
			return nil, fmt.Errorf("%w: rule %d: %v", ErrInvalid, i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// Limits for checkDocument. PyYAML shares aliased subtrees, while yaml.v3
// decoding copies them, so an alias "bomb" is cheap in Python but explodes
// here; the expanded node count is therefore bounded.
const maxExpandedNodes = 100_000

// safeTags are the tags yaml.safe_load can construct; anything else makes
// PyYAML raise ConstructorError, so it is rejected here too.
var safeTags = map[string]bool{
	"!!str": true, "!!int": true, "!!float": true, "!!bool": true, "!!null": true,
	"!!seq": true, "!!map": true, "!!merge": true, "!!binary": true, "!!timestamp": true,
	"!!set": true, "!!omap": true, "!!pairs": true, "!!value": true,
}

// checkDocument rejects unknown tags anywhere in the document and bounds the
// alias-expanded size.
func checkDocument(root *yaml.Node) error {
	sizes := map[*yaml.Node]int{}
	var walk func(n *yaml.Node, depth int) (int, error)
	walk = func(n *yaml.Node, depth int) (int, error) {
		if n.Kind == yaml.AliasNode {
			if n.Alias == nil {
				return 0, errors.New("dangling alias")
			}
			sz, ok := sizes[n.Alias]
			if !ok {
				return 0, errors.New("alias used before its anchor")
			}
			return sz, nil
		}
		if sz, ok := sizes[n]; ok {
			return sz, nil
		}
		if n.Tag != "" && !safeTags[n.Tag] {
			return 0, fmt.Errorf("could not determine a constructor for the tag %q", n.Tag)
		}
		total := 1
		for _, c := range n.Content {
			cs, err := walk(c, depth+1)
			if err != nil {
				return 0, err
			}
			total += cs
			if total > maxExpandedNodes {
				return 0, errors.New("policy expands to too many YAML nodes (alias bomb?)")
			}
		}
		sizes[n] = total
		return total, nil
	}
	_, err := walk(root, 0)
	return err
}

type pair struct{ key, val *yaml.Node }

// flatten returns a mapping's effective key/value pairs in PyYAML order:
// merged (<<) entries first, later merges overriding earlier ones, then the
// mapping's own keys. Duplicate keys are left for the caller (last wins).
func flatten(m *yaml.Node, depth int) ([]pair, error) {
	if depth > 16 {
		return nil, errors.New("merge keys nested too deeply")
	}
	var merged, own []pair
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := deref(m.Content[i]), m.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			return nil, errors.New("complex mapping keys are not supported")
		}
		if k.Tag != "!!merge" {
			own = append(own, pair{k, v})
			continue
		}
		v = deref(v)
		targets := []*yaml.Node{v}
		if v.Kind == yaml.SequenceNode {
			targets = nil
			for _, c := range v.Content {
				targets = append(targets, deref(c))
			}
		}
		for _, t := range targets {
			if t.Kind != yaml.MappingNode {
				return nil, errors.New("expected a mapping or list of mappings for merging")
			}
			sub, err := flatten(t, depth+1)
			if err != nil {
				return nil, err
			}
			merged = append(merged, sub...)
		}
	}
	return append(merged, own...), nil
}

// isBlank is Python's str.strip() == "": Unicode white space plus U+001C..U+001F.
func isBlank(s string) bool {
	for _, r := range s {
		if !unicode.IsSpace(r) && !(r >= 0x1c && r <= 0x1f) {
			return false
		}
	}
	return true
}

func deref(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

func ruleFromNode(m *yaml.Node) (*Rule, error) {
	pairs, err := flatten(m, 0)
	if err != nil {
		return nil, err
	}
	r := &Rule{vals: map[string]any{}}
	for _, p := range pairs {
		var val any
		if err := p.val.Decode(&val); err != nil {
			return nil, err
		}
		val, err := yaml11Compat(p.key.Value, deref(p.val), val)
		if err != nil {
			return nil, err
		}
		if _, dup := r.vals[p.key.Value]; !dup {
			r.keys = append(r.keys, p.key.Value)
		}
		r.vals[p.key.Value] = val
	}
	return r, nil
}

// yaml11Compat closes the two YAML 1.1 (PyYAML) vs 1.2 (yaml.v3) differences
// that could change a policy decision:
//   - an unquoted yes/no/on/off in agent/namespace/purpose/action is a
//     boolean in PyYAML (so Python rejects the rule when it is evaluated);
//     yaml.v3 would read it as the literal string. It is rejected here;
//   - a ttl such as 1e3 or 0o10 is a string in PyYAML (so int() fails and the
//     default TTL applies) but a number in yaml.v3; it is kept as a string.
func yaml11Compat(key string, n *yaml.Node, val any) (any, error) {
	if n == nil || n.Kind != yaml.ScalarNode || n.Style != 0 { // quoted/block scalars are always strings
		return val, nil
	}
	switch key {
	case "agent", "namespace", "purpose", "action":
		switch strings.ToLower(n.Value) {
		case "yes", "no", "on", "off":
			return nil, fmt.Errorf("%q must be a string; quote the unquoted boolean %q", key, n.Value)
		}
	case "ttl":
		if (n.Tag == "!!int" && !yaml11Int.MatchString(n.Value)) || (n.Tag == "!!float" && !yaml11Float.MatchString(n.Value)) {
			return n.Value, nil
		}
	}
	return val, nil
}

var (
	yaml11Int   = regexp.MustCompile(`^(?:[-+]?0b[01_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+)$`)
	yaml11Float = regexp.MustCompile(`^(?:[-+]?[0-9][0-9_]*\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$`)
)
