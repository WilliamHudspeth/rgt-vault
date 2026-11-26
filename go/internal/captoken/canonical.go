package captoken

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// canonicalJSON renders v exactly as Python's
//
//	json.dumps(v, sort_keys=True, separators=(",", ":"))   # ensure_ascii=True
//
// would. This matters because the HMAC is computed over these bytes:
//   - object keys are sorted (by code point, which equals UTF-8 byte order);
//   - no whitespace;
//   - every non-ASCII code point, DEL (0x7f) and every control character is
//     escaped as \uXXXX (lower-case hex; astral code points as surrogate pairs);
//   - <, > and & are NOT escaped (Go's encoding/json would escape them);
//   - floats use Python's repr (1.0, 1e-05, 1e+16);
//   - NaN and +/-Inf are rejected (Python would emit NaN / Infinity).
//
// Supported value types: nil, bool, string, all int/uint kinds, float32/64,
// json.Number, slices/arrays, and maps with string keys (recursively).
func canonicalJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := encodeValue(&b, reflect.ValueOf(v)); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

var jsonNumberType = reflect.TypeOf(json.Number(""))

func encodeValue(b *bytes.Buffer, rv reflect.Value) error {
	if !rv.IsValid() {
		b.WriteString("null")
		return nil
	}
	if rv.Type() == jsonNumberType {
		return encodeJSONNumber(b, rv.String())
	}
	switch rv.Kind() {
	case reflect.Interface, reflect.Pointer:
		if rv.IsNil() {
			b.WriteString("null")
			return nil
		}
		return encodeValue(b, rv.Elem())
	case reflect.Bool:
		if rv.Bool() {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case reflect.String:
		return encodeString(b, rv.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		b.WriteString(strconv.FormatInt(rv.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		b.WriteString(strconv.FormatUint(rv.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		s, err := pyFloatRepr(rv.Float())
		if err != nil {
			return err
		}
		b.WriteString(s)
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			b.WriteString("[]") // Python: an empty list; callers never pass nil lists meaning null
			return nil
		}
		b.WriteByte('[')
		for i := 0; i < rv.Len(); i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encodeValue(b, rv.Index(i)); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return newErr(kindValidation, "map keys must be strings, got %s", rv.Type().Key())
		}
		keys := rv.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encodeString(b, k.String()); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := encodeValue(b, rv.MapIndex(k)); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return newErr(kindValidation, "unsupported value type %s", rv.Type())
	}
	return nil
}

// encodeJSONNumber normalises a json.Number the way Python would re-serialise
// the parsed value: integer text stays an integer, anything else becomes a
// Python float repr.
func encodeJSONNumber(b *bytes.Buffer, s string) error {
	if !strings.ContainsAny(s, ".eE") {
		if isDigits(strings.TrimPrefix(s, "-")) {
			b.WriteString(s)
			return nil
		}
		return newErr(kindValidation, "invalid number %q", s)
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return newErr(kindValidation, "invalid number %q", s)
	}
	r, err := pyFloatRepr(f)
	if err != nil {
		return err
	}
	b.WriteString(r)
	return nil
}

func isDigits(s string) bool {
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

const hexLower = "0123456789abcdef"

func writeU(b *bytes.Buffer, r rune) {
	b.WriteString(`\u`)
	b.WriteByte(hexLower[(r>>12)&0xf])
	b.WriteByte(hexLower[(r>>8)&0xf])
	b.WriteByte(hexLower[(r>>4)&0xf])
	b.WriteByte(hexLower[r&0xf])
}

// encodeString reproduces Python's py_encode_basestring_ascii.
func encodeString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return newErr(kindValidation, "string is not valid UTF-8")
	}
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r >= ' ' && r <= '~':
			b.WriteByte(byte(r))
		case r < 0x10000:
			writeU(b, r)
		default:
			r -= 0x10000
			writeU(b, 0xd800|((r>>10)&0x3ff))
			writeU(b, 0xdc00|(r&0x3ff))
		}
	}
	b.WriteByte('"')
	return nil
}

// pyFloatRepr formats f like Python's repr(float).
func pyFloatRepr(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", newErr(kindValidation, "NaN and Infinity are not allowed in tokens")
	}
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0", nil
		}
		return "0.0", nil
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	// Shortest round-trip digits, as d.ddde±XX.
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expStr)
	digits := strings.Replace(mant, ".", "", 1)
	decpt := exp + 1 // position of the decimal point relative to digits
	var out string
	switch {
	case decpt > 16 || decpt < -3:
		out = digits[:1]
		if len(digits) > 1 {
			out += "." + digits[1:]
		}
		es := "+"
		x := decpt - 1
		if x < 0 {
			es = "-"
			x = -x
		}
		out += fmt.Sprintf("e%s%02d", es, x)
	case decpt <= 0:
		out = "0." + strings.Repeat("0", -decpt) + digits
	case decpt >= len(digits):
		out = digits + strings.Repeat("0", decpt-len(digits)) + ".0"
	default:
		out = digits[:decpt] + "." + digits[decpt:]
	}
	return sign + out, nil
}
