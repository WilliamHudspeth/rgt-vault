package validation

import (
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
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
	switch x := v.(type) {
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
		if _, err := strconv.ParseFloat(string(x), 64); err != nil {
			return "str"
		}
		return "float"
	}
	return fmt.Sprintf("%T", v)
}

var jsonInt = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)$`)

const maxIntDigits = 4300

// showInt renders an integer for an error message without amplifying a huge
// untrusted value into the message.
func showInt(b *big.Int) string {
	if b.BitLen() > 128 {
		return "a very large integer"
	}
	return b.String()
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
		// A JSON number is an int only if it is written as one (no
		// fraction, exponent, sign other than '-', or leading zeros), and
		// Python 3.11+ refuses ints of more than 4300 digits.
		if jsonInt.MatchString(string(x)) && len(x) <= maxIntDigits+1 {
			if b, ok := new(big.Int).SetString(string(x), 10); ok {
				return b, true
			}
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
		return 0, fail("'%s' must be >= %d; got %s.", paramName, min.val, showInt(b))
	}
	if max.set && b.Cmp(big.NewInt(max.val)) > 0 {
		return 0, fail("'%s' must be <= %d; got %s.", paramName, max.val, showInt(b))
	}
	if !b.IsInt64() {
		return 0, fail("'%s' is outside the supported integer range; got %s.", paramName, showInt(b))
	}
	return b.Int64(), nil
}
