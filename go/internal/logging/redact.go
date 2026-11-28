package logging

import (
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// RedactedPlaceholder replaces scrubbed credential and secret values.
const RedactedPlaceholder = "[REDACTED]"

// maxScrubDepth bounds recursion through nested groups, maps, slices, structs,
// and LogValuers so cyclic or pathological structures never overflow the stack.
const maxScrubDepth = 16

// safeExactKeys are vault metadata identifiers whose names contain words like
// "secret", "token", or "key" but hold non-secret identifiers or counters.
// Their string values still undergo inline credential scrubbing and control
// character encoding.
var safeExactKeys = map[string]bool{
	"secret_name":   true,
	"secret_id":     true,
	"token_id":      true,
	"key_epoch":     true,
	"policy_hash":   true,
	"entry_hash":    true,
	"prev_hash":     true,
	"dek_version":   true,
	"vault_id":      true,
	"request_id":    true,
	"incident_id":   true,
	"require_2fa":   true,
	"secret_leased": true,
	"secret_len":    true,
	"public_key":    true,
	"honeytoken":    true,
}

// defaultSensitiveExact matches normalized (lowercase, '-' -> '_') key names.
var defaultSensitiveExact = map[string]bool{
	"value":               true,
	"secret":              true,
	"secret_value":        true,
	"password":            true,
	"passwd":              true,
	"passphrase":          true,
	"pwd":                 true,
	"token":               true,
	"bearer":              true,
	"bearer_token":        true,
	"access_token":        true,
	"refresh_token":       true,
	"operator_token":      true,
	"capability_token":    true,
	"session_token":       true,
	"authorization":       true,
	"proxy_authorization": true,
	"cookie":              true,
	"set_cookie":          true,
	"api_key":             true,
	"apikey":              true,
	"x_api_key":           true,
	"access_key":          true,
	"secret_key":          true,
	"private_key":         true,
	"privkey":             true,
	"master_key":          true,
	"master_secret":       true,
	"dek":                 true,
	"wrapped_dek":         true,
	"harness_key":         true,
	"signing_key":         true,
	"client_secret":       true,
	"totp":                true,
	"totp_code":           true,
	"totp_secret":         true,
	"otp":                 true,
	"otp_code":            true,
	"passcode":            true,
	"mfa_code":            true,
	"two_factor_code":     true,
	"seed":                true,
	"mnemonic":            true,
	"credential":          true,
	"credentials":         true,
	"dsn":                 true,
	"connection_string":   true,
	"database_url":        true,
}

// defaultSensitiveSubstrings catches compound attribute names (e.g.
// "aws_secret_access_key", "github_token", "totp_seed", "db_password").
var defaultSensitiveSubstrings = []string{
	"password",
	"passwd",
	"passphrase",
	"secret",
	"token",
	"apikey",
	"api_key",
	"access_key",
	"private_key",
	"privkey",
	"master_key",
	"wrapped_dek",
	"authorization",
	"cookie",
	"totp",
	"passcode",
	"mnemonic",
	"credential",
	"connection_string",
}

// Inline value scrubbers for free-form strings, log messages, and error text.
var (
	// Authorization / Cookie header lines in formatted text.
	reAuthHeader = regexp.MustCompile(`(?i)\b((?:proxy-)?authorization|cookie|set-cookie|x-api-key)\s*:\s*([^\r\n,;]+)`)
	// "Bearer <tok>" or "Basic <b64>" credentials.
	reAuthScheme = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{4,}`)
	// otpauth://totp/...?secret=BASE32...
	reOTPAuthURI = regexp.MustCompile(`(?i)(otpauth://[^\s"']*?[?&]secret=)([A-Za-z2-7=]+)`)
	// URL userinfo credentials: scheme://user:password@host
	reURLUserInfo = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:)([^@\s/]+)(@)`)
	// Inline key=value or "key":"value" assignments in free text.
	reInlineKV = regexp.MustCompile(
		`(?i)("?(?:password|passwd|passphrase|secret|secret_value|api[_-]?key|access[_-]?key|private[_-]?key|` +
			`client[_-]?secret|master[_-]?secret|master[_-]?key|wrapped[_-]?dek|bearer[_-]?token|` +
			`capability[_-]?token|operator[_-]?token|access[_-]?token|refresh[_-]?token|` +
			`totp(?:[_-]?(?:code|secret))?|otp[_-]?code|passcode)"?\s*[:=]\s*)` +
			`("[^"]*"|'[^']*'|[^\s,;}\]]+)`,
	)
	// Common high-confidence token formats (OpenAI/API sk-*, GitHub ghp_*, AWS AKIA*, JWT / v2 token a.b).
	reKnownTokens = regexp.MustCompile(
		`\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{4,})?)\b`,
	)
	// Standalone 6-8 digit numeric OTP code (used when key is "code" or under 2fa context).
	reDigitsOTP = regexp.MustCompile(`^\d{6,8}$`)
)

// Redactor scrubs credentials from slog attributes and encodes control
// characters in strings to prevent log injection. It is immutable after
// construction and safe for concurrent use.
type Redactor struct {
	extraSubstrings []string
}

// NewRedactor creates a Redactor with optional extra case-insensitive sensitive
// key substrings.
func NewRedactor(extraSensitiveKeys ...string) *Redactor {
	var extras []string
	for _, k := range extraSensitiveKeys {
		norm := normalizeKey(k)
		if norm != "" {
			extras = append(extras, norm)
		}
	}
	return &Redactor{extraSubstrings: extras}
}

func normalizeKey(k string) string {
	k = strings.ToLower(strings.TrimSpace(k))
	k = strings.ReplaceAll(k, "-", "_")
	k = strings.ReplaceAll(k, ".", "_")
	return k
}

// IsSensitiveKey reports whether key names a credential, secret, TOTP, or
// sensitive header attribute.
func (r *Redactor) IsSensitiveKey(key string) bool {
	norm := normalizeKey(key)
	if norm == "" {
		return false
	}
	if safeExactKeys[norm] {
		return false
	}
	if defaultSensitiveExact[norm] {
		return true
	}
	for _, sub := range defaultSensitiveSubstrings {
		if strings.Contains(norm, sub) {
			return true
		}
	}
	for _, sub := range r.extraSubstrings {
		if strings.Contains(norm, sub) {
			return true
		}
	}
	return false
}

func (r *Redactor) anySensitiveInPath(groups []string, key string) bool {
	if r.IsSensitiveKey(key) {
		return true
	}
	for _, g := range groups {
		if r.IsSensitiveKey(g) {
			return true
		}
	}
	return false
}

// ReplaceAttr implements slog.HandlerOptions.ReplaceAttr: it normalizes top
// timestamps to UTC, scrubs sensitive attributes, and encodes control
// characters in keys and string values.
func (r *Redactor) ReplaceAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 {
		switch a.Key {
		case slog.TimeKey:
			if a.Value.Kind() == slog.KindTime {
				return slog.Time(FieldTime, a.Value.Time().UTC())
			}
		case slog.LevelKey:
			return a
		case slog.MessageKey:
			return slog.String(FieldMessage, r.ScrubString(a.Value.String()))
		case slog.SourceKey:
			return a
		}
	}
	return r.scrubAttr(groups, a, 0)
}

func (r *Redactor) scrubAttr(groups []string, a slog.Attr, depth int) slog.Attr {
	if a.Equal(slog.Attr{}) {
		return a
	}
	cleanKey := SanitizeText(a.Key)
	if depth > maxScrubDepth {
		return slog.String(cleanKey, RedactedPlaceholder)
	}

	val := resolveBounded(a.Value)

	// Group attributes: recurse into members so sensitive group names (e.g.
	// slog.Group("credentials", ...)) redact all children and nested keys/vals
	// are sanitized.
	if val.Kind() == slog.KindGroup {
		attrs := val.Group()
		nextGroups := make([]string, len(groups)+1)
		copy(nextGroups, groups)
		nextGroups[len(groups)] = cleanKey
		out := make([]any, len(attrs))
		for i, child := range attrs {
			out[i] = r.scrubAttr(nextGroups, child, depth+1)
		}
		return slog.Group(cleanKey, out...)
	}

	if r.anySensitiveInPath(groups, cleanKey) {
		return slog.String(cleanKey, RedactedPlaceholder)
	}

	// Special case: key "code" holding a 6-8 digit string is treated as an OTP
	// code, while integer HTTP/exit codes (slog.Int("code", 200)) stay intact.
	if normalizeKey(cleanKey) == "code" && val.Kind() == slog.KindString && reDigitsOTP.MatchString(strings.TrimSpace(val.String())) {
		return slog.String(cleanKey, RedactedPlaceholder)
	}

	return slog.Attr{Key: cleanKey, Value: r.scrubValue(groups, cleanKey, val, depth)}
}

func resolveBounded(v slog.Value) slog.Value {
	for i := 0; i < maxScrubDepth && v.Kind() == slog.KindLogValuer; i++ {
		v = v.LogValuer().LogValue()
	}
	if v.Kind() == slog.KindLogValuer {
		return slog.StringValue(RedactedPlaceholder)
	}
	return v
}

func (r *Redactor) scrubValue(groups []string, key string, v slog.Value, depth int) slog.Value {
	switch v.Kind() {
	case slog.KindString:
		return slog.StringValue(r.ScrubString(v.String()))
	case slog.KindTime:
		return slog.TimeValue(v.Time().UTC())
	case slog.KindBool, slog.KindInt64, slog.KindUint64, slog.KindFloat64, slog.KindDuration:
		return v
	case slog.KindAny:
		return slog.AnyValue(r.scrubAny(appendKey(groups, key), v.Any(), depth+1))
	default:
		return v
	}
}

func appendKey(groups []string, key string) []string {
	if key == "" {
		return groups
	}
	out := make([]string, len(groups)+1)
	copy(out, groups)
	out[len(groups)] = key
	return out
}

func (r *Redactor) scrubAny(keyPath []string, x any, depth int) any {
	if x == nil {
		return nil
	}
	if depth > maxScrubDepth {
		return RedactedPlaceholder
	}

	switch v := x.(type) {
	case string:
		if len(keyPath) > 0 && normalizeKey(keyPath[len(keyPath)-1]) == "code" && reDigitsOTP.MatchString(strings.TrimSpace(v)) {
			return RedactedPlaceholder
		}
		return r.ScrubString(v)
	case []byte:
		// Raw byte slices in vault code hold secret plaintexts, DEKs, or master
		// secrets; never serialize raw byte contents to operational logs.
		return fmt.Sprintf("<%d bytes redacted>", len(v))
	case http.Header:
		out := make(map[string]any, len(v))
		for hk, hv := range v {
			ck := SanitizeText(hk)
			if r.IsSensitiveKey(ck) {
				out[ck] = RedactedPlaceholder
				continue
			}
			vals := make([]string, len(hv))
			for i, item := range hv {
				vals[i] = r.ScrubString(item)
			}
			if len(vals) == 1 {
				out[ck] = vals[0]
			} else {
				out[ck] = vals
			}
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(v))
		for mk, mv := range v {
			ck := SanitizeText(mk)
			if r.IsSensitiveKey(ck) || (normalizeKey(ck) == "code" && reDigitsOTP.MatchString(strings.TrimSpace(mv))) {
				out[ck] = RedactedPlaceholder
			} else {
				out[ck] = r.ScrubString(mv)
			}
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for mk, mv := range v {
			ck := SanitizeText(mk)
			if r.IsSensitiveKey(ck) {
				out[ck] = RedactedPlaceholder
			} else {
				out[ck] = r.scrubAny(appendKey(keyPath, ck), mv, depth+1)
			}
		}
		return out
	case []string:
		out := make([]string, len(v))
		for i, item := range v {
			out[i] = r.ScrubString(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = r.scrubAny(keyPath, item, depth+1)
		}
		return out
	case time.Time:
		return v.UTC()
	case error:
		return r.ScrubString(v.Error())
	case slog.LogValuer:
		resolved := resolveBounded(slog.AnyValue(v))
		if resolved.Kind() == slog.KindGroup {
			m := make(map[string]any, len(resolved.Group()))
			for _, ga := range resolved.Group() {
				sa := r.scrubAttr(keyPath, ga, depth+1)
				m[sa.Key] = sa.Value.Any()
			}
			return m
		}
		if resolved.Kind() == slog.KindString {
			return r.ScrubString(resolved.String())
		}
		return resolved.Any()
	}

	return r.scrubReflect(keyPath, reflect.ValueOf(x), depth)
}

func (r *Redactor) scrubReflect(keyPath []string, rv reflect.Value, depth int) any {
	if !rv.IsValid() {
		return nil
	}
	if depth > maxScrubDepth {
		return RedactedPlaceholder
	}

	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		return r.scrubAny(keyPath, rv.Elem().Interface(), depth+1)

	case reflect.String:
		return r.ScrubString(rv.String())

	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		return rv.Interface()

	case reflect.Slice, reflect.Array:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			return fmt.Sprintf("<%d bytes redacted>", rv.Len())
		}
		n := rv.Len()
		out := make([]any, n)
		for i := 0; i < n; i++ {
			out[i] = r.scrubAny(keyPath, rv.Index(i).Interface(), depth+1)
		}
		return out

	case reflect.Map:
		if rv.IsNil() {
			return nil
		}
		out := make(map[string]any, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			mk := SanitizeText(fmt.Sprint(iter.Key().Interface()))
			if r.IsSensitiveKey(mk) {
				out[mk] = RedactedPlaceholder
			} else {
				out[mk] = r.scrubAny(appendKey(keyPath, mk), iter.Value().Interface(), depth+1)
			}
		}
		return out

	case reflect.Struct:
		rt := rv.Type()
		out := make(map[string]any, rt.NumField())
		for i := 0; i < rt.NumField(); i++ {
			sf := rt.Field(i)
			if !sf.IsExported() {
				continue
			}
			tag := sf.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name := sf.Name
			if tag != "" {
				if tagName, _, _ := strings.Cut(tag, ","); tagName != "" {
					name = tagName
				}
			}
			cleanName := SanitizeText(name)
			if r.IsSensitiveKey(cleanName) || r.IsSensitiveKey(sf.Name) {
				out[cleanName] = RedactedPlaceholder
			} else {
				out[cleanName] = r.scrubAny(appendKey(keyPath, cleanName), rv.Field(i).Interface(), depth+1)
			}
		}
		return out

	default:
		return r.ScrubString(fmt.Sprint(rv.Interface()))
	}
}

// ScrubString scrubs inline credentials (Authorization headers, Bearer/Basic
// schemes, otpauth secrets, URL userinfo passwords, sensitive key=value pairs,
// and known token prefixes) and encodes all control characters.
func (r *Redactor) ScrubString(s string) string {
	if s == "" {
		return ""
	}
	scrubbed := scrubInlineCredentials(s)
	return SanitizeText(scrubbed)
}

func scrubInlineCredentials(s string) string {
	// Fast check: skip regex work when none of the trigger characters or
	// prefixes can match.
	lower := strings.ToLower(s)
	mayHaveCreds := strings.Contains(s, ":") ||
		strings.Contains(s, "=") ||
		strings.Contains(lower, "bearer") ||
		strings.Contains(lower, "basic") ||
		strings.Contains(s, "sk-") ||
		strings.Contains(s, "gh") ||
		strings.Contains(s, "AKIA") ||
		strings.Contains(s, "eyJ")
	if !mayHaveCreds {
		return s
	}

	s = reOTPAuthURI.ReplaceAllString(s, "${1}"+RedactedPlaceholder)
	s = reURLUserInfo.ReplaceAllString(s, "${1}"+RedactedPlaceholder+"${3}")
	s = reAuthHeader.ReplaceAllString(s, "${1}: "+RedactedPlaceholder)
	s = reAuthScheme.ReplaceAllString(s, "${1} "+RedactedPlaceholder)
	s = reInlineKV.ReplaceAllString(s, "${1}"+RedactedPlaceholder)
	s = reKnownTokens.ReplaceAllString(s, RedactedPlaceholder)
	return s
}

// SanitizeText encodes CR (\r), LF (\n), TAB (\t), ESC/ANSI (\x1b), ASCII C0
// control characters (0x00..0x1f), DEL (0x7f), invalid UTF-8 bytes, Unicode C1
// controls (U+0080..U+009F), Unicode line/paragraph separators (U+2028/U+2029),
// and BiDi override code points into visible escape sequences (RGT-415).
func SanitizeText(s string) string {
	if isCleanASCII(s) {
		return s
	}

	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\n", `\n`)

	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c == '\t' {
				b.WriteString(`\t`)
			} else if c < 0x20 || c == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, c)
			} else {
				b.WriteByte(c)
			}
			i++
			continue
		}

		r, width := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && width == 1 {
			fmt.Fprintf(&b, `\x%02x`, c)
			i++
			continue
		}
		if isUnsafeUnicodeControl(r) {
			fmt.Fprintf(&b, `\u%04x`, r)
		} else {
			b.WriteRune(r)
		}
		i += width
	}
	return b.String()
}

func isCleanASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

func isUnsafeUnicodeControl(r rune) bool {
	switch {
	case r >= 0x0080 && r <= 0x009f: // C1 controls (including CSI U+009B)
		return true
	case r == 0x2028 || r == 0x2029: // Unicode line / paragraph separator
		return true
	case r >= 0x202a && r <= 0x202e: // BiDi embedding / override
		return true
	case r >= 0x2066 && r <= 0x2069: // BiDi isolate controls
		return true
	default:
		return false
	}
}
