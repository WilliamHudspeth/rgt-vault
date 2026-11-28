package vault

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/store"
)

// This file reproduces Python's json.dumps output byte for byte for the
// values the vault serialises: audit detail strings (json.dumps(d), default
// separators ", " and ": ") and the export document (json.dumps(d,
// indent=2)). Both use ensure_ascii=True. Go's encoding/json differs
// (no spaces, HTML escaping, raw UTF-8), so it cannot be used here.

// jsonNumber is the RFC 8259 number grammar.
var jsonNumber = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// pyKV is one key/value of an ordered JSON object (Python dict insertion
// order).
type pyKV struct {
	k string
	v any
}

// pyObject is an ordered JSON object.
type pyObject []pyKV

// pyDumps is json.dumps(v) with Python's default separators.
func pyDumps(v any) string {
	var b strings.Builder
	pyEncode(&b, v, -1, 0)
	return b.String()
}

// pyDumpsIndent is json.dumps(v, indent=indent).
func pyDumpsIndent(v any, indent int) string {
	var b strings.Builder
	pyEncode(&b, v, indent, 0)
	return b.String()
}

// pyEncode writes v. indent < 0 means single-line with ", " / ": ".
func pyEncode(b *strings.Builder, v any, indent, level int) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		pyQuote(b, x)
	case []byte:
		pyQuote(b, string(x))
	case int:
		b.WriteString(strconv.Itoa(x))
	case int8:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int16:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case uint:
		b.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint8:
		b.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint16:
		b.WriteString(strconv.FormatUint(uint64(x), 10))
	case float32:
		b.WriteString(pyFloat(float64(x)))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case int32:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case uint32:
		b.WriteString(strconv.FormatUint(uint64(x), 10))
	case uint64:
		b.WriteString(strconv.FormatUint(x, 10))
	case json.Number:
		if jsonNumber.MatchString(x.String()) {
			b.WriteString(x.String())
		} else {
			pyQuote(b, x.String())
		}
	case float64:
		b.WriteString(pyFloat(x))
	case pyObject:
		pyEncodeObject(b, x, indent, level)
	case map[string]any:
		// A Go map has no insertion order; sort the keys (deterministic,
		// and what json.dumps(sort_keys=True) does).
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		obj := make(pyObject, 0, len(keys))
		for _, k := range keys {
			obj = append(obj, pyKV{k, x[k]})
		}
		pyEncodeObject(b, obj, indent, level)
	case store.OrderedRow:
		obj := make(pyObject, len(x))
		for i, c := range x {
			obj[i] = pyKV{c.Key, c.Value}
		}
		pyEncodeObject(b, obj, indent, level)
	case []store.OrderedRow:
		items := make([]any, len(x))
		for i := range x {
			items[i] = x[i]
		}
		pyEncodeList(b, items, indent, level)
	case []string:
		items := make([]any, len(x))
		for i := range x {
			items[i] = x[i]
		}
		pyEncodeList(b, items, indent, level)
	case []any:
		pyEncodeList(b, x, indent, level)
	case map[string]string:
		m := make(map[string]any, len(x))
		for k, s := range x {
			m[k] = s
		}
		pyEncode(b, m, indent, level)
	default:
		// json.dumps(default=str). fmt.Sprint also handles a nil-pointer
		// fmt.Stringer without panicking.
		pyQuote(b, fmt.Sprint(x))
	}
}

func pyNewline(b *strings.Builder, indent, level int) {
	b.WriteByte('\n')
	b.WriteString(strings.Repeat(" ", indent*level))
}

func pyEncodeObject(b *strings.Builder, obj pyObject, indent, level int) {
	if len(obj) == 0 {
		b.WriteString("{}")
		return
	}
	b.WriteByte('{')
	for i, kv := range obj {
		if i > 0 {
			b.WriteByte(',')
			if indent < 0 {
				b.WriteByte(' ')
			}
		}
		if indent >= 0 {
			pyNewline(b, indent, level+1)
		}
		pyQuote(b, kv.k)
		b.WriteString(": ")
		pyEncode(b, kv.v, indent, level+1)
	}
	if indent >= 0 {
		pyNewline(b, indent, level)
	}
	b.WriteByte('}')
}

func pyEncodeList(b *strings.Builder, items []any, indent, level int) {
	if len(items) == 0 {
		b.WriteString("[]")
		return
	}
	b.WriteByte('[')
	for i, it := range items {
		if i > 0 {
			b.WriteByte(',')
			if indent < 0 {
				b.WriteByte(' ')
			}
		}
		if indent >= 0 {
			pyNewline(b, indent, level+1)
		}
		pyEncode(b, it, indent, level+1)
	}
	if indent >= 0 {
		pyNewline(b, indent, level)
	}
	b.WriteByte(']')
}

const hexDigits = "0123456789abcdef"

func pyU(b *strings.Builder, r rune) {
	b.WriteString(`\u`)
	b.WriteByte(hexDigits[(r>>12)&0xf])
	b.WriteByte(hexDigits[(r>>8)&0xf])
	b.WriteByte(hexDigits[(r>>4)&0xf])
	b.WriteByte(hexDigits[r&0xf])
}

// pyQuote writes s as json.encoder.py_encode_basestring_ascii does: every
// character outside ' '..'~' is escaped, non-BMP characters as a surrogate
// pair, hex digits in lower case. Invalid UTF-8 (impossible in a Python
// str) is written as U+FFFD.
func pyQuote(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r >= ' ' && r <= '~':
				b.WriteRune(r)
			case r > 0xffff:
				r -= 0x10000
				pyU(b, 0xd800|((r>>10)&0x3ff))
				pyU(b, 0xdc00|(r&0x3ff))
			default:
				pyU(b, r)
			}
		}
	}
	b.WriteByte('"')
}

// pyFloat is float.__repr__ as json.dumps writes it.
func pyFloat(f float64) string {
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
	// Shortest round-trip digits, then Python's repr layout: scientific
	// notation when the decimal exponent is < -4 or >= 16.
	digits := strconv.FormatFloat(math.Abs(f), 'e', -1, 64) // d.ddde±XX
	mant, expStr, _ := strings.Cut(digits, "e")
	exp, _ := strconv.Atoi(expStr)
	sign := ""
	if f < 0 {
		sign = "-"
	}
	if exp < -4 || exp >= 16 {
		return sign + mant + "e" + fmt.Sprintf("%+03d", exp)
	}
	s := strconv.FormatFloat(math.Abs(f), 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return sign + s
}
