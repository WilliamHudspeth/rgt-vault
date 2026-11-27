package actions

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
)

func asError(err error, target **Error) bool { return errors.As(err, target) }

func loggerOrDiscard(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Header limits.
const (
	MaxHeaderCount      = 32
	MaxHeaderNameBytes  = 128
	MaxHeaderValueBytes = 4096
	MaxHeadersTotal     = 16 << 10
)

// deniedHeaders can never be set by the caller. Host is handled separately
// (silently dropped, as in Python). Authorization is owned by the action.
var deniedHeaders = map[string]string{
	"authorization":       "is set by the action from the leased secret",
	"proxy-authorization": "is not allowed",
	"proxy-connection":    "is a hop-by-hop header",
	"connection":          "is a hop-by-hop header",
	"keep-alive":          "is a hop-by-hop header",
	"te":                  "is a hop-by-hop header",
	"trailer":             "is a hop-by-hop header",
	"transfer-encoding":   "controls message framing",
	"content-length":      "controls message framing",
	"upgrade":             "is a hop-by-hop header",
	"expect":              "is not allowed",
	"forwarded":           "could spoof the client address",
	"x-forwarded-for":     "could spoof the client address",
	"x-forwarded-host":    "could spoof the client address",
	"x-forwarded-proto":   "could spoof the client address",
	"x-real-ip":           "could spoof the client address",
}

func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// ValidateHeaders is the port of _validate_headers. headers is the decoded
// JSON "headers" param (nil = none). It returns the sanitised header map
// (canonical names) or an error. allowed, when non-empty, is a lower-case
// allow-list of header names; anything else is refused.
func ValidateHeaders(headers any, allowed map[string]struct{}) (map[string]string, error) {
	out := map[string]string{}
	if headers == nil {
		return out, nil
	}
	var m map[string]any
	switch h := headers.(type) {
	case map[string]any:
		m = h
	case map[string]string:
		m = make(map[string]any, len(h))
		for k, v := range h {
			m[k] = v
		}
	default:
		return nil, execErr("'headers' must be a JSON object if provided.")
	}
	if len(m) > MaxHeaderCount {
		return nil, execErr("'headers' has too many entries (max %d).", MaxHeaderCount)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	total := 0
	for _, k := range keys {
		if k == "" || len(k) > MaxHeaderNameBytes {
			return nil, execErr("Header names must be 1-%d bytes.", MaxHeaderNameBytes)
		}
		for i := 0; i < len(k); i++ {
			if !isTokenChar(k[i]) {
				return nil, execErr("Header name %s contains an invalid character.", strconv.Quote(sanitizeForMsg(k)))
			}
		}
		lower := strings.ToLower(k)
		if lower == "host" {
			// Python parity: the caller cannot pin Host; it is dropped, not an error.
			continue
		}
		if why, bad := deniedHeaders[lower]; bad {
			return nil, execErr("Header %q %s.", k, why)
		}
		if len(allowed) > 0 {
			if _, ok := allowed[lower]; !ok {
				return nil, execErr("Header %q is not on the allow-list.", k)
			}
		}
		val, ok := headerString(m[k])
		if !ok {
			return nil, execErr("Header %q must be a string, number or boolean.", k)
		}
		if len(val) > MaxHeaderValueBytes {
			return nil, execErr("Header %q value is too long (max %d bytes).", k, MaxHeaderValueBytes)
		}
		for i := 0; i < len(val); i++ {
			c := val[i]
			if c == '\r' || c == '\n' || c == 0 {
				return nil, execErr("Header %q value contains a forbidden control character.", k)
			}
			if (c < 0x20 && c != '\t') || c >= 0x7f {
				return nil, execErr("Header %q value must be printable ASCII.", k)
			}
		}
		canon := textproto.CanonicalMIMEHeaderKey(k)
		if _, dup := out[canon]; dup {
			return nil, execErr("Header %q is given more than once.", k)
		}
		total += len(canon) + len(val)
		if total > MaxHeadersTotal {
			return nil, execErr("'headers' is too large (max %d bytes in total).", MaxHeadersTotal)
		}
		out[canon] = val
	}
	return out, nil
}

// sanitizeForMsg keeps a caller-supplied name printable and short before it is
// echoed in an error.
func sanitizeForMsg(s string) string {
	if len(s) > 40 {
		s = s[:40]
	}
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c >= 0x7f {
			b[i] = '?'
		}
	}
	return string(b)
}

// headerString stringifies a header value the way Python's str(v) would for
// JSON scalars (bool -> "True"/"False"); null, arrays and objects are refused.
func headerString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		if x {
			return "True", true
		}
		return "False", true
	case json.Number:
		return x.String(), true
	case int:
		return strconv.Itoa(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return "", false
		}
		if x == math.Trunc(x) && math.Abs(x) < 1e15 {
			return strconv.FormatFloat(x, 'f', 1, 64), true // Python: str(5.0) == "5.0"
		}
		return strconv.FormatFloat(x, 'g', -1, 64), true
	}
	return "", false
}

// asInt64 accepts the integer forms a decoded JSON number can take. A float is
// accepted only when integral and exactly representable (Python rejects 5.0;
// Go's default decoder cannot tell 5 from 5.0, so this is the tolerant side).
func asInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int32:
		return int64(x), true
	case int64:
		return x, true
	case float64:
		if x != math.Trunc(x) || math.Abs(x) > 1<<53 {
			return 0, false
		}
		return int64(x), true
	case json.Number:
		n, err := strconv.ParseInt(x.String(), 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

func asFloat64(v any) (float64, bool) {
	var f float64
	switch x := v.(type) {
	case int:
		f = float64(x)
	case int32:
		f = float64(x)
	case int64:
		f = float64(x)
	case float64:
		f = x
	case json.Number:
		p, err := strconv.ParseFloat(x.String(), 64)
		if err != nil {
			return 0, false
		}
		f = p
	default:
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}
