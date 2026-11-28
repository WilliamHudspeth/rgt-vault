package policy

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// DestinationsKey is the top-level policy key holding the destination
// allow-list (RGT-523). Python's policy engine ignores it.
const DestinationsKey = "destinations"

// AllowedHostsKey is the optional per-rule key that narrows the destination
// allow-list for requests the rule allows. Python ignores it.
const AllowedHostsKey = "allowed_hosts"

// DestinationsDoc is the raw "destinations:" section of a policy file:
// key ("namespace/name" or "namespace/*") to the entry strings, unparsed.
// Interpreting the entries is internal/actions' job.
type DestinationsDoc struct {
	// Present reports whether the policy had a destinations key.
	Present bool
	// ListForm reports a policy that is a bare list of rules: it has
	// nowhere to put a destinations section.
	ListForm bool
	// Keys holds the keys in file order; Entries the value of each key.
	Keys    []string
	Entries map[string][]string
}

// DestinationsFromYAML extracts the destinations section. It is stricter
// than the rule parser on purpose, because a silently shadowed entry widens
// or narrows where a credential may be sent: duplicate keys (inside the map,
// or a second top-level destinations key), aliases and merge keys are
// errors, and every value must be a list of strings (null or a scalar is an
// error, not "no entry"). The usual document checks (safe tags, size) apply.
func DestinationsFromYAML(src string) (DestinationsDoc, error) {
	doc := DestinationsDoc{Entries: map[string][]string{}}
	if isBlank(src) {
		return doc, nil
	}
	dec := yaml.NewDecoder(strings.NewReader(src))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			return doc, nil
		}
		return doc, fmt.Errorf("%w: Failed to parse policy YAML: %v", ErrInvalid, err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return doc, nil
	}
	if err := checkDocument(root.Content[0]); err != nil {
		return doc, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	top := root.Content[0]
	if top.Kind == yaml.AliasNode {
		top = deref(top)
	}
	switch top.Kind {
	case yaml.SequenceNode:
		doc.ListForm = true
		return doc, nil
	case yaml.MappingNode:
	default:
		return doc, nil
	}
	var val *yaml.Node
	for i := 0; i+1 < len(top.Content); i += 2 {
		k := top.Content[i]
		if k.Kind == yaml.ScalarNode && k.Tag == "!!merge" {
			if m := deref(top.Content[i+1]); m != nil && hasKey(m, DestinationsKey) {
				return doc, destErr("%q must not come from a merge key (<<)", DestinationsKey)
			}
			continue
		}
		if k.Kind != yaml.ScalarNode || k.Value != DestinationsKey {
			continue
		}
		if val != nil {
			return doc, destErr("duplicate top-level %q key", DestinationsKey)
		}
		val = top.Content[i+1]
	}
	if val == nil {
		return doc, nil
	}
	doc.Present = true
	if val.Kind == yaml.AliasNode || val.Anchor != "" {
		return doc, destErr("YAML aliases and anchors are not allowed under %q", DestinationsKey)
	}
	if val.Kind != yaml.MappingNode {
		return doc, destErr("%q must be a mapping of \"namespace/name\" or \"namespace/*\" to a list of hosts", DestinationsKey)
	}
	for i := 0; i+1 < len(val.Content); i += 2 {
		k, v := val.Content[i], val.Content[i+1]
		if k.Kind != yaml.ScalarNode || k.Tag == "!!merge" {
			return doc, destErr("merge keys (<<) and complex keys are not allowed under %q", DestinationsKey)
		}
		key := k.Value
		if _, dup := doc.Entries[key]; dup {
			return doc, destErr("duplicate key %q", key)
		}
		list, err := StringList(v)
		if err != nil {
			return doc, destErr("%q: %v", key, err)
		}
		doc.Keys = append(doc.Keys, key)
		doc.Entries[key] = list
	}
	return doc, nil
}

// StringList decodes a YAML sequence of plain strings, refusing null, a
// scalar, aliases and non-string items.
func StringList(n *yaml.Node) ([]string, error) {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return nil, errors.New("YAML aliases and anchors are not allowed")
	}
	if n.Kind != yaml.SequenceNode {
		return nil, errors.New("must be a list of hosts (use [] to allow none)")
	}
	out := make([]string, 0, len(n.Content))
	for _, it := range n.Content {
		if it.Kind != yaml.ScalarNode || it.Tag != "!!str" || it.Anchor != "" {
			return nil, errors.New("every entry must be a string")
		}
		out = append(out, it.Value)
	}
	return out, nil
}

func hasKey(m *yaml.Node, key string) bool {
	if m.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return true
		}
	}
	return false
}

func destErr(format string, a ...any) error {
	return fmt.Errorf("%w: destinations: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// MatchingAllowRules returns the indexes (into Rules()) of EVERY allow rule
// that matches, in policy order, or nil when an explicit deny matches or
// nothing allows. Evaluate reports only the last matching allow rule; the
// destination check needs all of them so that narrowing by allowed_hosts
// does not depend on rule order.
func (e *Engine) MatchingAllowRules(agent, namespace, purpose, action string) []int {
	var out []int
	for i := range e.rules {
		er := &e.rules[i]
		if !er.matches(agent, namespace, purpose, action) {
			continue
		}
		switch effectOf(er.rule) {
		case "deny":
			return nil
		case "allow":
			out = append(out, i)
		}
	}
	return out
}
