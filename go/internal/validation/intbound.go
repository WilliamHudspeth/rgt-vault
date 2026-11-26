package validation

import (
	"encoding/json"
	"fmt"
	"math/big"
)

// Bound is an optional integer limit for ValidateIntBound.
type Bound struct {
	set bool
	val int64
}

// Limit returns a set Bound.
func Limit(v int64) Bound { return Bound{set: true, val: v} }

// NoLimit is the unset Bound.
var NoLimit = Bound{}

// pyTypeName maps a Go value to the Python type name used in messages.
func pyTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case string:
		return "str"
	case float32, float64:
		return "float"
	case []byte:
		return "bytes"
	case []any:
		return "list"
	case map[string]any, map[any]any:
		return "dict"
	case json.Number:
		return "float"
	}
	return fmt.Sprintf("%T", v)
}

// intOf converts v to a big integer if it is an integer in Python's sense
// (bool is not).
func intOf(v any) (*big.Int, bool) {
	switch x := v.(type) {
	case int:
		return big.NewInt(int64(x)), true
	case int8:
		return big.NewInt(int64(x)), true
	case int16:
		return big.NewInt(int64(x)), true
	case int32:
		return big.NewInt(int64(x)), true
	case int64:
		return big.NewInt(x), true
	case uint:
		return new(big.Int).SetUint64(uint64(x)), true
	case uint8:
		return big.NewInt(int64(x)), true
	case uint16:
		return big.NewInt(int64(x)), true
	case uint32:
		return big.NewInt(int64(x)), true
	case uint64:
		return new(big.Int).SetUint64(x), true
	case *big.Int:
		if x == nil {
			return nil, false
		}
		return x, true
	case json.Number:
		// A JSON number is an int only if it has no fraction/exponent.
		if b, ok := new(big.Int).SetString(x.String(), 10); ok {
			return b, true
		}
	}
	return nil, false
}

// ValidateIntBound validates that value is an integer within [min, max]
// (python: validate_int_bound). bool, float, string, nil etc. are rejected
// with the Python message ("must be an integer; got <type>."). Integers
// outside the int64 range are rejected with the same range messages when a
// bound is violated, and with an overflow error otherwise.
func ValidateIntBound(paramName string, value any, min, max Bound) (int64, error) {
	b, ok := intOf(value)
	if !ok {
		return 0, fail("'%s' must be an integer; got %s.", paramName, pyTypeName(value))
	}
	if min.set && b.Cmp(big.NewInt(min.val)) < 0 {
		return 0, fail("'%s' must be >= %d; got %s.", paramName, min.val, b.String())
	}
	if max.set && b.Cmp(big.NewInt(max.val)) > 0 {
		return 0, fail("'%s' must be <= %d; got %s.", paramName, max.val, b.String())
	}
	if !b.IsInt64() {
		return 0, fail("'%s' is outside the supported integer range; got %s.", paramName, b.String())
	}
	return b.Int64(), nil
}
