package policy

import (
	"math"
	"math/big"
	"strings"
)

// pyIntOf mirrors Python's int(v) for the value types a YAML scalar can
// decode to. ok is false where Python raises ValueError/TypeError
// (get_lease_ttl catches those and falls back to the default). Values outside
// the int64 range are clamped, which is indistinguishable here because the
// caller only needs max(1, n).
func pyIntOf(v any) (n int64, ok bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case int:
		return int64(x), true
	case int64:
		return x, true
	case uint64:
		if x > math.MaxInt64 {
			return math.MaxInt64, true
		}
		return int64(x), true
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return 0, false // Python: ValueError / OverflowError
		}
		t := math.Trunc(x)
		if t >= math.MaxInt64 {
			return math.MaxInt64, true
		}
		if t <= math.MinInt64 {
			return math.MinInt64, true
		}
		return int64(t), true
	case string:
		return pyIntFromString(x)
	}
	return 0, false
}

// pyIntFromString mirrors int(str) in base 10 for ASCII digits: surrounding
// whitespace is stripped, an optional sign is allowed, single underscores are
// allowed between digits. (Non-ASCII decimal digits, which Python also
// accepts, are not supported and fall back to the default TTL.)
func pyIntFromString(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	if s == "" {
		return 0, false
	}
	var digits strings.Builder
	prevUnderscore := true // forbids a leading underscore
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			digits.WriteByte(c)
			prevUnderscore = false
		case c == '_' && !prevUnderscore:
			prevUnderscore = true
		default:
			return 0, false
		}
	}
	if prevUnderscore { // trailing underscore
		return 0, false
	}
	b, ok := new(big.Int).SetString(digits.String(), 10)
	if !ok {
		return 0, false
	}
	if neg {
		b.Neg(b)
	}
	if !b.IsInt64() {
		if neg {
			return math.MinInt64, true
		}
		return math.MaxInt64, true
	}
	return b.Int64(), true
}
