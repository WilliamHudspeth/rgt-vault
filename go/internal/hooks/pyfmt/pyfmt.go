// Package pyfmt renders Go values the way Python's repr() and str() render
// the equivalent JSON-decoded Python values. The hook and capability ports
// use it to reproduce Python's reason and error strings (which embed values
// with !r) byte for byte, so audit rows written by Go match Python's.
//
// It covers the shapes a JSON payload decodes to: nil, bool, string, the Go
// integer types, float64/float32, json.Number, []any, []string and
// map[string]any. Go maps have no insertion order, so map keys are rendered
// sorted; that matches Python whenever the dict came from a canonical
// (sort_keys=True) JSON document such as a capability token payload.
package pyfmt

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Repr returns Python's repr(v) for a JSON-shaped value.
func Repr(v any) string {
	var b strings.Builder
	writeRepr(&b, v)
	return b.String()
}

// Str returns Python's str(v): strings are returned as-is, everything else
// is rendered as Repr (which is what str() does for the JSON value types).
func Str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return Repr(v)
}

// SortedIntsRepr renders a sorted list of ints as Python prints
// sorted(set_of_ints), e.g. "[1, 2]".
func SortedIntsRepr(vs []int) string {
	c := append([]int(nil), vs...)
	sort.Ints(c)
	items := make([]any, len(c))
	for i, x := range c {
		items[i] = x
	}
	return Repr(items)
}

// SortedStringsRepr renders sorted(strings) as Python prints it,
// e.g. "['a', 'b']".
func SortedStringsRepr(vs []string) string {
	c := append([]string(nil), vs...)
	sort.Strings(c)
	items := make([]any, len(c))
	for i, x := range c {
		items[i] = x
	}
	return Repr(items)
}

func writeRepr(b *strings.Builder, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("None")
	case bool:
		if x {
			b.WriteString("True")
		} else {
			b.WriteString("False")
		}
	case string:
		writeStr(b, x)
	case int:
		b.WriteString(strconv.Itoa(x))
	case int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		fmt.Fprintf(b, "%d", x)
	case float32:
		b.WriteString(FloatRepr(float64(x)))
	case float64:
		b.WriteString(FloatRepr(x))
	case json.Number:
		s := x.String()
		if isIntLiteral(s) {
			// Python int() of the literal drops a leading "-0" sign only for
			// zero; json never emits "+", so the literal is the repr.
			if s == "-0" {
				s = "0"
			}
			b.WriteString(s)
		} else if f, err := strconv.ParseFloat(s, 64); err == nil {
			b.WriteString(FloatRepr(f))
		} else {
			writeStr(b, s)
		}
	case []any:
		b.WriteByte('[')
		for i, it := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			writeRepr(b, it)
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, it := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			writeStr(b, it)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			writeStr(b, k)
			b.WriteString(": ")
			writeRepr(b, x[k])
		}
		b.WriteByte('}')
	default:
		// Not a JSON shape; fall back to a quoted Go rendering so the output
		// is still a single, unambiguous token.
		writeStr(b, fmt.Sprint(x))
	}
}

func isIntLiteral(s string) bool {
	s = strings.TrimPrefix(s, "-")
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

// writeStr is str.__repr__: single quotes unless the string contains a
// single quote and no double quote; backslash, the quote, \t \n \r escaped;
// other non-printable characters as \xhh, \uhhhh or \Uhhhhhhhh; printable
// non-ASCII characters kept as-is.
func writeStr(b *strings.Builder, s string) {
	quote := byte('\'')
	if strings.IndexByte(s, '\'') >= 0 && strings.IndexByte(s, '"') < 0 {
		quote = '"'
	}
	b.WriteByte(quote)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Not reachable from a Python str; render the byte like a
			// surrogate-escaped byte would print.
			fmt.Fprintf(b, `\udc%02x`, s[i])
			i++
			continue
		}
		i += size
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == rune(quote):
			b.WriteByte('\\')
			b.WriteByte(quote)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(b, `\x%02x`, r)
		case r < 0x7f:
			b.WriteRune(r)
		case isPrintable(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(b, `\u%04x`, r)
		default:
			fmt.Fprintf(b, `\U%08x`, r)
		}
	}
	b.WriteByte(quote)
}

// isPrintable approximates Python's str.isprintable for one non-ASCII
// character: letters, marks, numbers, punctuation and symbols are printable;
// separators other than the ASCII space, controls, format characters,
// surrogates, private-use and unassigned code points are not.
func isPrintable(r rune) bool {
	if unicode.In(r, unicode.Zs, unicode.Zl, unicode.Zp, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs) {
		return false
	}
	return unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S)
}

// FloatRepr is float.__repr__: the shortest round-tripping digits, in
// positional notation when the decimal exponent is in [-4, 16), otherwise
// as d.ddde+XX; integral values keep a ".0"; inf, -inf and nan.
func FloatRepr(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	case math.IsNaN(f):
		return "nan"
	}
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // e.g. -1.2345e+06
	neg := strings.HasPrefix(e, "-")
	if neg {
		e = e[1:]
	}
	mant, expStr, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expStr)
	digits := strings.Replace(mant, ".", "", 1)
	var out string
	if exp >= -5 && exp < 16 {
		// Python switches to exponent form when exp < -4.
		if exp < -4 {
			out = sciRepr(digits, exp)
		} else if exp < 0 {
			out = "0." + strings.Repeat("0", -exp-1) + digits
		} else if len(digits) <= exp+1 {
			out = digits + strings.Repeat("0", exp+1-len(digits)) + ".0"
		} else {
			out = digits[:exp+1] + "." + digits[exp+1:]
		}
	} else {
		out = sciRepr(digits, exp)
	}
	if neg {
		return "-" + out
	}
	return out
}

func sciRepr(digits string, exp int) string {
	m := digits[:1]
	if len(digits) > 1 {
		m += "." + digits[1:]
	}
	sign := "+"
	if exp < 0 {
		sign = "-"
		exp = -exp
	}
	return fmt.Sprintf("%se%s%02d", m, sign, exp)
}
