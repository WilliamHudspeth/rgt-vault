package logging

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Placeholders emitted for scrubbed credentials, panicking formatters, and
// oversized/cyclic attribute graphs.
const (
	RedactedPlaceholder      = "[REDACTED]"
	RedactedPanicPlaceholder = "[REDACTED:panic]"
	TruncatedPlaceholder     = "[TRUNCATED]"
)

// Bounds preventing stack overflow and exponential DAG/cycle memory blowup.
const (
	maxScrubDepth = 16
	maxScrubNodes = 10_000
	// maxScrubStringBytes caps how much of one string ScrubString inspects.
	maxScrubStringBytes = 64 << 10
)

type scrubState struct {
	budget int
}

func newScrubState() *scrubState {
	return &scrubState{budget: maxScrubNodes}
}

func (s *scrubState) take() bool {
	if s.budget <= 0 {
		return false
	}
	s.budget--
	return true
}

// safeExactKeys are vault metadata identifiers whose names contain words like
// "secret", "token", or "key" but hold non-secret identifiers or counters.
// Their values are still scanned for inline credentials/tokens and control
// characters, and a long string passed as "token_id" is still redacted.
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

// defaultSensitiveExact matches camelCase-split, snake_case-normalized keys.
var defaultSensitiveExact = map[string]bool{
	"value":               true,
	"pin":                 true,
	"pw":                  true,
	"secret":              true,
	"secret_value":        true,
	"pass":                true,
	"password":            true,
	"passwd":              true,
	"passphrase":          true,
	"pwd":                 true,
	"auth":                true,
	"auth_token":          true,
	"auth_header":         true,
	"auth_key":            true,
	"auth_secret":         true,
	"session":             true,
	"session_id":          true,
	"session_key":         true,
	"session_secret":      true,
	"session_token":       true,
	"session_cookie":      true,
	"jwt":                 true,
	"token":               true,
	"bearer":              true,
	"bearer_token":        true,
	"access_token":        true,
	"refresh_token":       true,
	"operator_token":      true,
	"capability_token":    true,
	"id_token":            true,
	"csrf_token":          true,
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
	"kek":                 true,
	"wrapped_dek":         true,
	"hmac_key":            true,
	"harness_key":         true,
	"signing_key":         true,
	"client_secret":       true,
	"totp":                true,
	"totp_code":           true,
	"totp_secret":         true,
	"otp":                 true,
	"otp_code":            true,
	"otp_seed":            true,
	"passcode":            true,
	"mfa_code":            true,
	"two_factor_code":     true,
	"verification_code":   true,
	"recovery_code":       true,
	"seed":                true,
	"mnemonic":            true,
	"credential":          true,
	"credentials":         true,
	"dsn":                 true,
	"connection_string":   true,
	"database_url":        true,
}

// sensitiveWordSegments matches individual underscore-delimited segments after
// camelCase splitting (so PrivateKey -> ["private","key"], WrappedDEK ->
// ["wrapped","dek"], SigningKey -> ["signing","key"]).
var sensitiveWordSegments = map[string]bool{
	"pass":        true,
	"passwd":      true,
	"password":    true,
	"passphrase":  true,
	"pwd":         true,
	"secret":      true,
	"token":       true,
	"bearer":      true,
	"jwt":         true,
	"dek":         true,
	"kek":         true,
	"totp":        true,
	"otp":         true,
	"passcode":    true,
	"mnemonic":    true,
	"privkey":     true,
	"credential":  true,
	"credentials": true,
	"cookie":      true,
	"apikey":      true,
}

// defaultSensitiveSubstrings catches compound names after normalization.
var defaultSensitiveSubstrings = []string{
	"password",
	"passwd",
	"passphrase",
	"secret",
	"token",
	"api_key",
	"apikey",
	"access_key",
	"private_key",
	"privkey",
	"master_key",
	"signing_key",
	"harness_key",
	"hmac_key",
	"wrapped_dek",
	"authorization",
	"cookie",
	"totp",
	"otp_seed",
	"recovery_code",
	"verification_code",
	"passcode",
	"mnemonic",
	"credential",
	"connection_string",
}

// Inline value scrubbers for free-form strings, log messages, map keys, and error text.
var (
	// PEM private key blocks (single-line or multi-line).
	rePEMPrivateKey = regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[^\r\n]*`)
	// Authorization, Cookie, Set-Cookie, and X-Api-Key header lines (entire header value to EOL).
	reAuthHeader = regexp.MustCompile(`(?i)\b((?:proxy-)?authorization|cookie|set-cookie|x-api-key)\s*:\s*([^\r\n]+)`)
	// Bearer and Basic auth schemes, including Unicode whitespace (NBSP U+00A0, etc.).
	reBearerScheme = regexp.MustCompile(`(?i)\b(bearer)((?:[\s\p{Z}]|%20)+)([^\s\p{Z},;)"'\]]+)`)
	reBasicScheme  = regexp.MustCompile(`(?i)\b(basic)([\s\p{Z}]+)([A-Za-z0-9+/=_-]{4,})`)
	// "token <val>" in prose/errors such as fmt.Errorf("bad token %s", tok).
	reTokenProse = regexp.MustCompile(`(?i)\b(token)([\s\p{Z}]+)([A-Za-z0-9._~+/=-]{12,})`)
	// otpauth://totp/...?secret=BASE32...
	reOTPAuthURI = regexp.MustCompile(`(?i)(otpauth://[^\s"']*?[?&]secret=)([A-Za-z2-7=]+)`)
	// URL userinfo credentials: scheme://[user]:password@host (supports empty user
	// like redis://:pw@host and greedy match up to the LAST '@' in authority so
	// passwords containing '@' are scrubbed completely).
	reURLUserInfo = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@?#]*:)([^\s/?#]+)(@[^@\s/?#]+)`)
	// Inline key=value, ?key=value, or "key":"value" assignments in free text
	// (excludes short safe metadata IDs like token_id, secret_name, secret_id, dek_version).
	reInlineKV = regexp.MustCompile(
		`(?i)([?&"']?\b(?:password|passwd|passphrase|pass|pwd|pw|auth|bearer|secret|secret[_-]?value|` +
			`(?:[a-z0-9]+[_-])?token|authorization|proxy[_-]authorization|cookie|set[_-]cookie|` +
			`api[_-]?key|x[_-]api[_-]key|access[_-]?key|secret[_-]?key|private[_-]?key|privkey|` +
			`signing[_-]?key|harness[_-]?key|hmac[_-]?key|master[_-]?key|master[_-]?secret|` +
			`client[_-]?secret|wrapped[_-]?dek|dek|kek|jwt|session|` +
			`totp(?:[_-]?(?:code|secret|seed))?|otp(?:[_-]?(?:code|seed))?|` +
			`verification[_-]?code|recovery[_-]?code|passcode|pin)"?\s*[:=]\s*)` +
			`(\[REDACTED(?::panic)?\]|"[^"]*"|'[^']*'|[^\s&?,;}\]]+)`,
	)
	// Common prefixed token formats (vault vlt_*/rgt_*, OpenAI sk-*, GitHub ghp_*/github_pat_*,
	// GitLab glpat-*, Slack xox*, AWS AKIA*, JWT / v2 capability token eyJ...).
	reKnownTokens = regexp.MustCompile(
		`\b(?:(?:vlt|rgt)_[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{12,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{4,})?)\b`,
	)
	// Candidate bare 43-char base64url or 44-char '='-padded base64/base64url tokens
	// (matching auth.GenerateToken 44-char and RawURLEncoding 43-char vault tokens).
	reBareTokenCandidate = regexp.MustCompile(`[A-Za-z0-9+/=_-]{43,44}`)
	// Standalone 6-8 digit numeric OTP code.
	reDigitsOTP = regexp.MustCompile(`^\d{6,8}$`)
)

// nonSecretBearerWords prevents redacting English prose like "Bearer token" or "bearer auth".
var nonSecretBearerWords = map[string]bool{
	"token":          true,
	"tokens":         true,
	"auth":           true,
	"authentication": true,
	"header":         true,
	"headers":        true,
	"scheme":         true,
	"credential":     true,
	"credentials":    true,
	"format":         true,
	"mode":           true,
	"realm":          true,
}

// Redactor scrubs credentials from slog attributes and encodes control
// characters in strings to prevent log injection. It is immutable after
// construction and safe for concurrent use.
type Redactor struct {
	extraSubstrings []string
}

// NewRedactor creates a Redactor with optional extra case-insensitive sensitive
// key names or substrings.
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

// normalizeKey splits camelCase and uppercase acronyms (e.g. "PrivateKey" ->
// "private_key", "WrappedDEK" -> "wrapped_dek", "wrappedDek" -> "wrapped_dek")
// and normalizes separators ('-', '.', '/', ' ') to single underscores.
func normalizeKey(k string) string {
	k = strings.TrimSpace(k)
	if k == "" {
		return ""
	}
	runes := []rune(k)
	var b strings.Builder
	b.Grow(len(k) + 4)
	prevUnderscore := true
	for i, r := range runes {
		if r == '-' || r == '_' || r == '.' || r == '/' || unicode.IsSpace(r) {
			if !prevUnderscore {
				b.WriteByte('_')
				prevUnderscore = true
			}
			continue
		}
		if i > 0 && unicode.IsUpper(r) && !prevUnderscore {
			prev := runes[i-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToLower(r))
		prevUnderscore = false
	}
	return strings.Trim(b.String(), "_")
}

// IsSensitiveKey reports whether key names a credential, secret, key, TOTP, or
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
	for _, seg := range strings.Split(norm, "_") {
		if sensitiveWordSegments[seg] {
			return true
		}
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

func isConditionalStringSecretKey(normKey string, val string) bool {
	switch normKey {
	case "code":
		return reDigitsOTP.MatchString(strings.TrimSpace(val))
	case "pin":
		return strings.TrimSpace(val) != ""
	case "token_id":
		return !looksLikeSafeTokenID(val)
	default:
		return false
	}
}

// looksLikeSafeTokenID accepts short token identifiers used in rgt-vault
// (8-hex auth.TokenID, 16-hex captoken.TokenID, "tok_<hex>" auth.Store IDs,
// 32-hex captoken v1 IDs, and 36-char UUIDs), while flagging raw tokens
// mistakenly logged under "token_id".
func looksLikeSafeTokenID(val string) bool {
	s := strings.TrimSpace(val)
	if s == "" || s == RedactedPlaceholder || s == RedactedPanicPlaceholder {
		return true
	}
	body := strings.TrimPrefix(s, "tok_")
	if len(s) <= 36 && isHexOrHyphen(body) {
		return true
	}
	return len(s) <= 20 && !looksLikeBareVaultToken(s)
}

func isHexOrHyphen(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-') {
			return false
		}
	}
	return true
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
	return r.scrubAttr(newScrubState(), groups, a, 0)
}

func (r *Redactor) scrubAttr(st *scrubState, groups []string, a slog.Attr, depth int) slog.Attr {
	if a.Equal(slog.Attr{}) {
		return a
	}
	rawKey := a.Key
	cleanKey := r.ScrubString(rawKey)
	if !st.take() {
		return slog.String(cleanKey, TruncatedPlaceholder)
	}
	if depth > maxScrubDepth {
		return slog.String(cleanKey, RedactedPlaceholder)
	}

	val := resolveBounded(st, a.Value)

	if val.Kind() == slog.KindGroup {
		attrs := val.Group()
		nextGroups := make([]string, len(groups)+1)
		copy(nextGroups, groups)
		nextGroups[len(groups)] = rawKey
		out := make([]any, 0, len(attrs))
		for _, child := range attrs {
			if !st.take() {
				out = append(out, slog.String(TruncatedPlaceholder, TruncatedPlaceholder))
				break
			}
			out = append(out, r.scrubAttr(st, nextGroups, child, depth+1))
		}
		return slog.Group(cleanKey, out...)
	}

	if r.anySensitiveInPath(groups, rawKey) {
		return slog.String(cleanKey, RedactedPlaceholder)
	}

	normKey := normalizeKey(rawKey)
	if val.Kind() == slog.KindString && isConditionalStringSecretKey(normKey, val.String()) {
		return slog.String(cleanKey, RedactedPlaceholder)
	}

	return slog.Attr{Key: cleanKey, Value: r.scrubValue(st, groups, rawKey, val, depth)}
}

func resolveBounded(st *scrubState, v slog.Value) (out slog.Value) {
	defer func() {
		if recover() != nil {
			out = slog.StringValue(RedactedPanicPlaceholder)
		}
	}()
	for i := 0; i < maxScrubDepth && v.Kind() == slog.KindLogValuer; i++ {
		if !st.take() {
			return slog.StringValue(TruncatedPlaceholder)
		}
		lv := v.LogValuer()
		if lv == nil {
			return slog.AnyValue(nil)
		}
		rv := reflect.ValueOf(lv)
		if rv.Kind() == reflect.Pointer && rv.IsNil() {
			return slog.AnyValue(nil)
		}
		v = lv.LogValue()
	}
	if v.Kind() == slog.KindLogValuer {
		return slog.StringValue(RedactedPlaceholder)
	}
	return v
}

func (r *Redactor) scrubValue(st *scrubState, groups []string, key string, v slog.Value, depth int) slog.Value {
	switch v.Kind() {
	case slog.KindString:
		return slog.StringValue(r.ScrubString(v.String()))
	case slog.KindTime:
		return slog.TimeValue(v.Time().UTC())
	case slog.KindBool, slog.KindInt64, slog.KindUint64, slog.KindFloat64, slog.KindDuration:
		return v
	case slog.KindAny:
		return slog.AnyValue(r.scrubAny(st, appendKey(groups, key), v.Any(), depth+1))
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

func (r *Redactor) scrubAny(st *scrubState, keyPath []string, x any, depth int) any {
	if x == nil {
		return nil
	}
	if !st.take() {
		return TruncatedPlaceholder
	}
	if depth > maxScrubDepth {
		return RedactedPlaceholder
	}

	lastNormKey := ""
	if len(keyPath) > 0 {
		lastNormKey = normalizeKey(keyPath[len(keyPath)-1])
	}

	switch v := x.(type) {
	case string:
		if isConditionalStringSecretKey(lastNormKey, v) {
			return RedactedPlaceholder
		}
		return r.ScrubString(v)

	case []byte:
		return fmt.Sprintf("<%d bytes redacted>", len(v))

	case http.Header:
		out := make(map[string]any, len(v))
		for hk, hv := range v {
			if !st.take() {
				out[TruncatedPlaceholder] = TruncatedPlaceholder
				break
			}
			ck := r.ScrubString(hk)
			if r.IsSensitiveKey(hk) {
				out[ck] = RedactedPlaceholder
				continue
			}
			vals := make([]string, 0, len(hv))
			for _, item := range hv {
				if !st.take() {
					vals = append(vals, TruncatedPlaceholder)
					break
				}
				vals = append(vals, r.ScrubString(item))
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
			if !st.take() {
				out[TruncatedPlaceholder] = TruncatedPlaceholder
				break
			}
			ck := r.ScrubString(mk)
			normMK := normalizeKey(mk)
			if r.IsSensitiveKey(mk) || isConditionalStringSecretKey(normMK, mv) {
				out[ck] = RedactedPlaceholder
			} else {
				out[ck] = r.ScrubString(mv)
			}
		}
		return out

	case map[string]any:
		out := make(map[string]any, len(v))
		for mk, mv := range v {
			if !st.take() {
				out[TruncatedPlaceholder] = TruncatedPlaceholder
				break
			}
			ck := r.ScrubString(mk)
			if r.IsSensitiveKey(mk) {
				out[ck] = RedactedPlaceholder
			} else {
				out[ck] = r.scrubAny(st, appendKey(keyPath, mk), mv, depth+1)
			}
		}
		return out

	case []string:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if !st.take() {
				out = append(out, TruncatedPlaceholder)
				break
			}
			out = append(out, r.ScrubString(item))
		}
		return out

	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			if !st.take() {
				out = append(out, TruncatedPlaceholder)
				break
			}
			out = append(out, r.scrubAny(st, keyPath, item, depth+1))
		}
		return out

	case time.Time:
		return v.UTC()

	case error:
		s, isNil := safeErrorString(v)
		if isNil {
			return nil
		}
		return r.ScrubString(s)

	case slog.LogValuer:
		resolved := resolveBounded(st, slog.AnyValue(v))
		switch resolved.Kind() {
		case slog.KindGroup:
			m := make(map[string]any, len(resolved.Group()))
			for _, ga := range resolved.Group() {
				if !st.take() {
					m[TruncatedPlaceholder] = TruncatedPlaceholder
					break
				}
				sa := r.scrubAttr(st, keyPath, ga, depth+1)
				m[sa.Key] = sa.Value.Any()
			}
			return m
		case slog.KindString:
			return r.ScrubString(resolved.String())
		case slog.KindTime:
			return resolved.Time().UTC()
		default:
			return r.scrubAny(st, keyPath, resolved.Any(), depth+1)
		}
	}

	return r.scrubReflect(st, keyPath, reflect.ValueOf(x), depth)
}

func safeErrorString(err error) (s string, isTypedNil bool) {
	rv := reflect.ValueOf(err)
	if !rv.IsValid() || (rv.Kind() == reflect.Pointer && rv.IsNil()) {
		return "", true
	}
	defer func() {
		if recover() != nil {
			s = RedactedPanicPlaceholder
		}
	}()
	return err.Error(), false
}

func safeSprint(x any) (s string) {
	if x == nil {
		return ""
	}
	defer func() {
		if recover() != nil {
			s = RedactedPanicPlaceholder
		}
	}()
	if str, ok := x.(fmt.Stringer); ok {
		rv := reflect.ValueOf(x)
		if !rv.IsValid() || (rv.Kind() == reflect.Pointer && rv.IsNil()) {
			return "<nil>"
		}
		return str.String()
	}
	out := fmt.Sprint(x)
	if strings.Contains(out, "(PANIC=") {
		return RedactedPanicPlaceholder
	}
	return out
}

func (r *Redactor) scrubReflect(st *scrubState, keyPath []string, rv reflect.Value, depth int) any {
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
		return r.scrubAny(st, keyPath, rv.Elem().Interface(), depth+1)

	case reflect.String:
		s := rv.String()
		if len(keyPath) > 0 && isConditionalStringSecretKey(normalizeKey(keyPath[len(keyPath)-1]), s) {
			return RedactedPlaceholder
		}
		return r.ScrubString(s)

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
		out := make([]any, 0, min(n, 64))
		for i := 0; i < n; i++ {
			if !st.take() {
				out = append(out, TruncatedPlaceholder)
				break
			}
			out = append(out, r.scrubAny(st, keyPath, rv.Index(i).Interface(), depth+1))
		}
		return out

	case reflect.Map:
		if rv.IsNil() {
			return nil
		}
		out := make(map[string]any, min(rv.Len(), 64))
		iter := rv.MapRange()
		for iter.Next() {
			if !st.take() {
				out[TruncatedPlaceholder] = TruncatedPlaceholder
				break
			}
			rawMK := safeSprint(iter.Key().Interface())
			ck := r.ScrubString(rawMK)
			if r.IsSensitiveKey(rawMK) {
				out[ck] = RedactedPlaceholder
			} else {
				out[ck] = r.scrubAny(st, appendKey(keyPath, rawMK), iter.Value().Interface(), depth+1)
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
			if !st.take() {
				out[TruncatedPlaceholder] = TruncatedPlaceholder
				break
			}
			name := sf.Name
			if tag != "" {
				if tagName, _, _ := strings.Cut(tag, ","); tagName != "" {
					name = tagName
				}
			}
			cleanName := r.ScrubString(name)
			if r.IsSensitiveKey(name) || r.IsSensitiveKey(sf.Name) {
				out[cleanName] = RedactedPlaceholder
			} else {
				out[cleanName] = r.scrubAny(st, appendKey(keyPath, name), rv.Field(i).Interface(), depth+1)
			}
		}
		return out

	default:
		return r.ScrubString(safeSprint(rv.Interface()))
	}
}

// ScrubString scrubs inline credentials (PEM private keys, Authorization/Cookie
// headers, Bearer/Basic schemes, otpauth secrets, URL userinfo passwords,
// sensitive key=value pairs, known token prefixes, and bare 43/44-char vault
// tokens) and encodes all control and BiDi override characters.
func (r *Redactor) ScrubString(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > maxScrubStringBytes {
		// Bound the work per string (the regex passes are far from linear on
		// adversarial 50 MB inputs). Only the scrubbed prefix is kept, so a
		// credential cut by the limit can never leave a partial copy behind.
		cut := maxScrubStringBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		omitted := len(s) - cut
		return SanitizeText(scrubInlineCredentials(s[:cut])) + fmt.Sprintf("[TRUNCATED %d bytes]", omitted)
	}
	return SanitizeText(scrubInlineCredentials(s))
}

func scrubInlineCredentials(s string) string {
	s = rePEMPrivateKey.ReplaceAllString(s, RedactedPlaceholder)
	s = reOTPAuthURI.ReplaceAllString(s, "${1}"+RedactedPlaceholder)
	s = reURLUserInfo.ReplaceAllString(s, "${1}"+RedactedPlaceholder+"${3}")
	s = reAuthHeader.ReplaceAllStringFunc(s, func(m string) string {
		parts := reAuthHeader.FindStringSubmatch(m)
		if len(parts) == 3 {
			trimmed := strings.TrimSpace(parts[2])
			if trimmed == RedactedPlaceholder || trimmed == RedactedPanicPlaceholder {
				return m
			}
		}
		return parts[1] + ": " + RedactedPlaceholder
	})

	s = reBearerScheme.ReplaceAllStringFunc(s, func(m string) string {
		parts := reBearerScheme.FindStringSubmatch(m)
		if len(parts) != 4 {
			return m
		}
		kw, tok := parts[1], parts[3]
		if strings.HasPrefix(tok, "[REDACTED") || nonSecretBearerWords[strings.ToLower(strings.Trim(tok, ".,:;!?"))] {
			return m
		}
		// Capitalized "Bearer <tok>" is standard HTTP syntax; lowercase "bearer <x>"
		// requires a non-word token shape to avoid redacting prose.
		if kw[0] == 'B' || !isPlainLowerWord(tok) || len(tok) >= 16 {
			return kw + " " + RedactedPlaceholder
		}
		return m
	})

	s = reBasicScheme.ReplaceAllStringFunc(s, func(m string) string {
		parts := reBasicScheme.FindStringSubmatch(m)
		if len(parts) != 4 {
			return m
		}
		kw, tok := parts[1], parts[3]
		if strings.HasPrefix(tok, "[REDACTED") {
			return m
		}
		if looksLikeBasicPayload(kw, tok) {
			return kw + " " + RedactedPlaceholder
		}
		return m
	})

	s = reInlineKV.ReplaceAllStringFunc(s, func(m string) string {
		parts := reInlineKV.FindStringSubmatch(m)
		if len(parts) != 3 {
			return m
		}
		prefix, val := parts[1], parts[2]
		if val == RedactedPlaceholder || val == RedactedPanicPlaceholder {
			return m
		}
		// Extract the matched key name before ':' or '=' and skip safe metadata keys
		// when their value is a short identifier rather than a raw token.
		keyPart := strings.TrimLeft(prefix, `?&"'`)
		if idx := strings.IndexAny(keyPart, `":= `); idx > 0 {
			keyPart = keyPart[:idx]
		}
		norm := normalizeKey(keyPart)
		unquoted := strings.Trim(val, `"'`)
		if safeExactKeys[norm] {
			if norm == "token_id" && looksLikeSafeTokenID(unquoted) {
				return m
			}
			if norm != "token_id" && len(unquoted) <= 36 && !looksLikeBareVaultToken(unquoted) {
				return m
			}
		}
		return prefix + RedactedPlaceholder
	})

	s = reTokenProse.ReplaceAllStringFunc(s, func(m string) string {
		parts := reTokenProse.FindStringSubmatch(m)
		if len(parts) != 4 {
			return m
		}
		kw, tok := parts[1], parts[3]
		if strings.HasPrefix(tok, "[REDACTED") || isPlainLowerWord(tok) {
			return m
		}
		return kw + " " + RedactedPlaceholder
	})

	s = reKnownTokens.ReplaceAllString(s, RedactedPlaceholder)
	s = scrubAssignedBareTokens(s)
	s = scrubBareVaultTokens(s)
	return s
}

func isPlainLowerWord(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return len(s) > 0
}

func looksLikeBasicPayload(kw, tok string) bool {
	if isPlainLowerWord(tok) {
		return false
	}
	// Standard HTTP Basic payload is base64("user:pass").
	if len(tok)%4 == 0 {
		if decoded, err := base64.StdEncoding.DecodeString(tok); err == nil && bytes.IndexByte(decoded, ':') >= 0 {
			return true
		}
	}
	// Capitalized "Basic <b64>" with base64 padding, digits, or mixed-case/symbols.
	return kw[0] == 'B' && !isPlainAlphaWord(tok)
}

func isPlainAlphaWord(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return len(s) > 0
}

func isTokenBoundaryByte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '_' || c == '-' || c == '/' || c == '.' || c == '+' || c == '='
}

// scrubBareVaultTokens redacts standalone 43-char base64url or 44-char '='-padded
// base64/base64url strings matching auth.GenerateToken / auth.Store.Mint output,
// while leaving file paths, URLs, Go test/symbol identifiers, and prose intact.
func scrubBareVaultTokens(s string) string {
	if len(s) < 43 {
		return s
	}
	idxs := reBareTokenCandidate.FindAllStringIndex(s, -1)
	if len(idxs) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	replaced := false
	for _, loc := range idxs {
		start, end := loc[0], loc[1]
		if start > 0 && isTokenBoundaryByte(s[start-1]) {
			continue
		}
		if end < len(s) && isTokenBoundaryByte(s[end]) {
			continue
		}
		cand := s[start:end]
		if !looksLikeBareVaultToken(cand) {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString(RedactedPlaceholder)
		last = end
		replaced = true
	}
	if !replaced {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// reAssignedBareToken finds `<anything>=<43/44-char token>` or `: <token>`, the
// shape `token_id=<raw token>` takes: the key is not in the credential key
// list (token_id is normally a short public id) but the value is a full token.
var reAssignedBareToken = regexp.MustCompile(`([=:]\s*["']?)([A-Za-z0-9_-]{43}=?)`)

func scrubAssignedBareTokens(s string) string {
	if len(s) < 44 {
		return s
	}
	return reAssignedBareToken.ReplaceAllStringFunc(s, func(m string) string {
		parts := reAssignedBareToken.FindStringSubmatch(m)
		if len(parts) != 3 || !looksLikeBareVaultToken(parts[2]) {
			return m
		}
		return parts[1] + RedactedPlaceholder
	})
}

func looksLikeBareVaultToken(cand string) bool {
	if len(cand) == 44 {
		// 32-byte standard or URL-safe base64 always has a single trailing '='.
		if cand[43] != '=' || strings.Contains(cand[:43], "=") {
			return false
		}
	} else if len(cand) == 43 {
		if strings.Contains(cand, "=") || strings.ContainsAny(cand, "+/") {
			return false
		}
	} else {
		return false
	}

	var hasUpper, hasLower, hasDigit bool
	var underscores int
	var freq [128]int
	for i := 0; i < len(cand); i++ {
		c := cand[i]
		if c >= 128 {
			return false
		}
		freq[c]++
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == '_':
			underscores++
		}
	}
	// Reject snake_case identifiers (e.g. a_long_configuration_variable_identifier_ok).
	if underscores > 6 {
		return false
	}
	// Require character-class diversity (digits + letters, or '=' padded base64 with
	// mixed classes) and realistic base64 entropy so CamelCase function names without
	// digits (e.g. TestVaultBoundaryRejectsHostileNamesAndAgen) are never flagged.
	if !hasDigit && !strings.HasSuffix(cand, "=") {
		return false
	}
	if !(hasUpper || hasLower) {
		return false
	}
	return shannonEntropyASCII(cand, &freq) >= 3.5
}

func shannonEntropyASCII(s string, freq *[128]int) float64 {
	n := float64(len(s))
	if n == 0 {
		return 0
	}
	var h float64
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// SanitizeText encodes CR (\r), LF (\n), TAB (\t), ESC/ANSI (\x1b), ASCII C0
// control characters (0x00..0x1f), DEL (0x7f), invalid UTF-8 bytes, Unicode C1
// controls (U+0080..U+009F), Unicode line/paragraph separators (U+2028/U+2029),
// and BiDi mark/override/isolate code points (including U+200E/U+200F LRM/RLM,
// U+061C ALM, U+202A..U+202E, U+2066..U+2069, zero-width U+200B..U+200D, and
// U+FEFF), soft hyphen, word joiner, annotation anchors, U+180E, tag characters
// and private-use code points into visible escape sequences (RGT-415).
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

// IsUnsafeRune reports whether r is a non-ASCII code point that SanitizeText
// encodes as \uXXXX: C1 controls, invisible/format characters and BiDi
// controls that can reorder or hide text in a terminal or log viewer. It is
// exported so other log sanitizers (handlers.LogSafe) encode the same set.
func IsUnsafeRune(r rune) bool { return isUnsafeUnicodeControl(r) }

func isUnsafeUnicodeControl(r rune) bool {
	switch {
	case r >= 0x0080 && r <= 0x009f: // C1 controls (including CSI U+009B)
		return true
	case r == 0x00ad: // soft hyphen
		return true
	case r == 0x061c: // Arabic Letter Mark
		return true
	case r == 0x180e: // Mongolian vowel separator
		return true
	case r >= 0x200b && r <= 0x200f: // ZWSP, ZWNJ, ZWJ, LRM (U+200E), RLM (U+200F)
		return true
	case r == 0x2028 || r == 0x2029: // Unicode line / paragraph separator
		return true
	case r >= 0x202a && r <= 0x202e: // BiDi embedding / override
		return true
	case r == 0x2060: // word joiner
		return true
	case r >= 0x2066 && r <= 0x2069: // BiDi isolate controls
		return true
	case r == 0xfeff: // ZWNBSP / BOM
		return true
	case r >= 0xfff9 && r <= 0xfffb: // interlinear annotation anchors
		return true
	case r >= 0xe0000 && r <= 0xe007f: // tag characters
		return true
	case unicode.Is(unicode.Co, r): // private use areas
		return true
	default:
		return false
	}
}
