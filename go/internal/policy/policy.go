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
//     YAML 1.1, so 1.1-only spellings (yes/no/on/off booleans, sexagesimal
//     ints) are not interpreted as such;
//   - int(ttl) of a non-ASCII-digit string falls back to the default TTL.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
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
	if strings.TrimSpace(policyYAML) == "" {
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
	return Parse(string(data))
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
		out[i] = *r.rule
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
			return Decision{Allowed: false, Reason: "Explicit deny rule matched", MatchedRule: er.rule}
		case "allow":
			allowRule = er.rule
		}
	}
	if allowRule != nil {
		return Decision{Allowed: true, Reason: "Allow rule matched", MatchedRule: allowRule}
	}
	return Decision{Allowed: false, Reason: "No matching allow rule (default deny)"}
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
	root := deref(doc.Content[0])
	var rulesNode *yaml.Node
	switch root.Kind {
	case yaml.SequenceNode:
		rulesNode = root
	case yaml.MappingNode:
		for i := 0; i+1 < len(root.Content); i += 2 {
			k := deref(root.Content[i])
			if k.Kind == yaml.ScalarNode && k.Tag == "!!str" && k.Value == "rules" {
				rulesNode = deref(root.Content[i+1]) // last duplicate wins, as in PyYAML
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

func deref(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

func ruleFromNode(m *yaml.Node) (*Rule, error) {
	r := &Rule{vals: map[string]any{}}
	set := func(k string, v any) {
		if _, dup := r.vals[k]; !dup {
			r.keys = append(r.keys, k)
		}
		r.vals[k] = v
	}
	var merged []*yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := deref(m.Content[i]), m.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			return nil, errors.New("complex mapping keys are not supported")
		}
		if k.Tag == "!!merge" {
			merged = append(merged, deref(v))
			continue
		}
		var val any
		if err := v.Decode(&val); err != nil {
			return nil, err
		}
		set(k.Value, val)
	}
	// Merge keys: explicit keys win over merged ones.
	var extra []map[string]any
	for _, mn := range merged {
		nodes := []*yaml.Node{mn}
		if mn.Kind == yaml.SequenceNode {
			nodes = mn.Content
		}
		for _, n := range nodes {
			var mv map[string]any
			if err := deref(n).Decode(&mv); err != nil {
				return nil, err
			}
			extra = append(extra, mv)
		}
	}
	for _, mv := range extra {
		keys := make([]string, 0, len(mv))
		for k := range mv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, ok := r.vals[k]; !ok {
				set(k, mv[k])
			}
		}
	}
	return r, nil
}
