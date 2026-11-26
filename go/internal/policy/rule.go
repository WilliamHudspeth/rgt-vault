package policy

import (
	"bytes"
	"encoding/json"
)

// Rule is one policy rule: an ordered YAML mapping. The top-level key order
// of the YAML document is preserved so that explain output and JSON match
// Python's dict ordering.
type Rule struct {
	keys []string
	vals map[string]any
}

// Get returns the value of a field and whether it is present.
func (r Rule) Get(key string) (any, bool) {
	v, ok := r.vals[key]
	return v, ok
}

// Keys returns the field names in document order.
func (r Rule) Keys() []string { return append([]string(nil), r.keys...) }

// Len returns the number of fields.
func (r Rule) Len() int { return len(r.keys) }

// PythonJSON renders the rule exactly like Python's json.dumps(rule)
// (", " / ": " separators, ensure_ascii). Explain output uses it.
func (r Rule) PythonJSON() string {
	var sb []byte
	sb = append(sb, '{')
	for i, k := range r.keys {
		if i > 0 {
			sb = append(sb, ", "...)
		}
		sb = append(sb, pyJSON(k)...)
		sb = append(sb, ": "...)
		sb = append(sb, pyJSON(r.vals[k])...)
	}
	sb = append(sb, '}')
	return string(sb)
}

// MarshalJSON emits the rule as a compact JSON object in document order.
func (r Rule) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range r.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		vb, err := json.Marshal(jsonSafe(r.vals[k]))
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// jsonSafe converts map[any]any (yaml.v3 for non-string keys) into a form
// encoding/json accepts.
func jsonSafe(v any) any {
	switch x := v.(type) {
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			ks := pyJSON(k)
			if s, ok := k.(string); ok {
				ks = s
			}
			m[ks] = jsonSafe(e)
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = jsonSafe(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = jsonSafe(e)
		}
		return out
	}
	return v
}
