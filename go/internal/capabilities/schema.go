package capabilities

import (
	"bytes"
	"encoding/json"
	"math"
	"sort"
	"strings"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/hooks/pyfmt"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/vault"
)

// Schema validates a capability payload at the vault boundary. Errors match
// vault.ErrValidation and carry Python's message.
type Schema interface {
	Validate(capability string, payload map[string]any) error
}

func payloadErr(format string, a ...any) error {
	return newError("ValidationError", nil, []error{vault.ErrValidation}, format, a...)
}

// ParamList is Python's list-of-names params_schema: payload keys outside
// the list are rejected; none is required. An empty list accepts anything.
type ParamList []string

// Validate implements Schema.
func (p ParamList) Validate(capability string, payload map[string]any) error {
	if len(p) == 0 {
		return nil
	}
	allowed := map[string]bool{}
	for _, n := range p {
		allowed[n] = true
	}
	var unknown []string
	for k := range payload {
		if !allowed[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		return payloadErr("capability %s got unknown param(s): %s. Allowed: %s",
			pyfmt.Repr(capability), pyfmt.SortedStringsRepr(unknown), pyfmt.SortedStringsRepr(dedupe(p)))
	}
	return nil
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(s))
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// JSONSchema is a JSON-Schema-like dict validated the way Python's fallback
// validator (no jsonschema installed) does: "required" fields must be
// present; with "additionalProperties": false unknown keys are rejected;
// a property's "type" of string / integer / boolean / object / array is
// checked (other types and keywords are not enforced).
//
// Deliberate difference: payload keys are checked in sorted order. Python
// checks them in payload (insertion) order, which a Go map does not keep.
// The outcome is the same (any violation rejects the payload with a
// ValidationError, and "required" is still checked first in schema order);
// only WHICH violation the message names can differ when a payload breaks
// several rules. Sorting makes that choice deterministic.
type JSONSchema map[string]any

// Validate implements Schema.
func (s JSONSchema) Validate(_ string, payload map[string]any) error {
	for _, f := range stringList(s["required"]) {
		if _, ok := payload[f]; !ok {
			return payloadErr("Payload validation failed: Missing required field '%s'", f)
		}
	}
	props := asMap(s["properties"])
	noExtra := false
	if b, ok := s["additionalProperties"].(bool); ok && !b {
		noExtra = true
	}
	keys := make([]string, 0, len(payload))
	for k := range payload {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ps, known := props[k]
		if !known {
			if noExtra {
				return payloadErr("Payload validation failed: Additional properties not allowed '%s'", k)
			}
			continue
		}
		t, _ := asMap(ps)["type"].(string)
		v := payload[k]
		switch t {
		case "string":
			if _, ok := v.(string); !ok {
				return payloadErr("Payload validation failed: '%s' must be a string", k)
			}
		case "integer":
			if !isPyInt(v) {
				return payloadErr("Payload validation failed: '%s' must be an integer", k)
			}
		case "boolean":
			if _, ok := v.(bool); !ok {
				return payloadErr("Payload validation failed: '%s' must be a boolean", k)
			}
		case "object":
			if !isObject(v) {
				return payloadErr("Payload validation failed: '%s' must be a dict", k)
			}
		case "array":
			if !isArray(v) {
				return payloadErr("Payload validation failed: '%s' must be a list", k)
			}
		}
	}
	return nil
}

// asMap accepts both map[string]any and a nested JSONSchema.
func asMap(v any) map[string]any {
	switch x := v.(type) {
	case map[string]any:
		return x
	case JSONSchema:
		return x
	}
	return nil
}

func stringList(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// isPyInt is isinstance(v, int) for a JSON-decoded value. As in Python, a
// bool is an int. A float64 counts when integral, because Go's default JSON
// decoding turns 1 into float64(1); a json.Number must be an integer
// literal ("1.0" is a float in Python).
func isPyInt(v any) bool {
	switch x := v.(type) {
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case float64:
		return !math.IsInf(x, 0) && x == math.Trunc(x)
	case json.Number:
		s := strings.TrimPrefix(x.String(), "-")
		if s == "" {
			return false
		}
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
		return true
	}
	return false
}

func isObject(v any) bool {
	switch v.(type) {
	case map[string]any, map[string]string:
		return true
	}
	return false
}

func isArray(v any) bool {
	switch v.(type) {
	case []any, []string:
		return true
	}
	return false
}

// StructSchema validates a payload by decoding it into a Go struct (the
// counterpart of Python's pydantic params_schema): unknown fields are
// rejected, JSON types must match the struct, and if *T implements
// interface{ Validate() error } that runs last.
type StructSchema[T any] struct{}

// Struct returns a StructSchema for T.
func Struct[T any]() StructSchema[T] { return StructSchema[T]{} }

// Validate implements Schema.
func (StructSchema[T]) Validate(_ string, payload map[string]any) error {
	_, err := DecodePayload[T](payload)
	return err
}

// DecodePayload decodes payload into a T with StructSchema's rules, for
// handlers that want typed arguments.
func DecodePayload[T any](payload map[string]any) (*T, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, payloadErr("Payload validation failed: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	var out T
	if err := dec.Decode(&out); err != nil {
		return nil, payloadErr("Payload validation failed: %s", strings.TrimPrefix(err.Error(), "json: "))
	}
	if vd, ok := any(&out).(interface{ Validate() error }); ok {
		if err := vd.Validate(); err != nil {
			return nil, payloadErr("Payload validation failed: %v", err)
		}
	}
	return &out, nil
}
