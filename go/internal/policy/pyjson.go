package policy

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// pyJSON renders v exactly like Python's json.dumps(v) with default
// arguments: ", " and ": " separators and ensure_ascii=True. Mapping keys
// below the top level of a rule have no meaningful order in YAML, so nested
// maps are emitted with sorted keys (Rule keeps the top-level YAML order).
func pyJSON(v any) string {
	var sb strings.Builder
	writePyJSON(&sb, v)
	return sb.String()
}

func writePyJSON(sb *strings.Builder, v any) {
	switch x := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if x {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case string:
		writePyString(sb, x)
	case int:
		sb.WriteString(strconv.FormatInt(int64(x), 10))
	case int64:
		sb.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		sb.WriteString(strconv.FormatUint(x, 10))
	case float64:
		sb.WriteString(pyFloatJSON(x))
	case []any:
		sb.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				sb.WriteString(", ")
			}
			writePyJSON(sb, e)
		}
		sb.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteString(", ")
			}
			writePyString(sb, k)
			sb.WriteString(": ")
			writePyJSON(sb, x[k])
		}
		sb.WriteByte('}')
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[fmt.Sprint(k)] = e
		}
		writePyJSON(sb, m)
	default:
		writePyString(sb, fmt.Sprint(x))
	}
}

func writePyString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			sb.WriteString(`\"`)
		case r == '\\':
			sb.WriteString(`\\`)
		case r == '\n':
			sb.WriteString(`\n`)
		case r == '\r':
			sb.WriteString(`\r`)
		case r == '\t':
			sb.WriteString(`\t`)
		case r == '\b':
			sb.WriteString(`\b`)
		case r == '\f':
			sb.WriteString(`\f`)
		case r >= ' ' && r <= '~':
			sb.WriteRune(r)
		case r > 0xFFFF:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(sb, `\u%04x\u%04x`, hi, lo)
		default:
			fmt.Fprintf(sb, `\u%04x`, r)
		}
	}
	sb.WriteByte('"')
}

// pyFloatJSON mirrors float.__repr__ (as used by json.dumps).
func pyFloatJSON(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	s := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±XX, shortest digits
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	mant, expStr, _ := strings.Cut(s, "e")
	exp, _ := strconv.Atoi(expStr)
	digits := strings.Replace(mant, ".", "", 1)
	var out string
	if exp < -4 || exp >= 16 {
		out = digits[:1]
		if len(digits) > 1 {
			out += "." + digits[1:]
		}
		sign := "+"
		if exp < 0 {
			sign = "-"
			exp = -exp
		}
		out += fmt.Sprintf("e%s%02d", sign, exp)
	} else if exp >= 0 {
		if len(digits) <= exp+1 {
			out = digits + strings.Repeat("0", exp+1-len(digits)) + ".0"
		} else {
			out = digits[:exp+1] + "." + digits[exp+1:]
		}
	} else {
		out = "0." + strings.Repeat("0", -exp-1) + digits
	}
	if neg {
		out = "-" + out
	}
	return out
}
