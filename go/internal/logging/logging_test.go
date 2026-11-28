package logging

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func parseJSONLine(t *testing.T, line string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &m); err != nil {
		t.Fatalf("invalid JSON log line %q: %v", line, err)
	}
	return m
}

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in      string
		want    slog.Level
		wantErr bool
	}{
		{"", slog.LevelInfo, false},
		{"info", slog.LevelInfo, false},
		{"  DEBUG ", slog.LevelDebug, false},
		{"warn", slog.LevelWarn, false},
		{"WARNING", slog.LevelWarn, false},
		{"error", slog.LevelError, false},
		{"trace", slog.LevelInfo, true},
	}
	for _, tc := range cases {
		got, err := ParseLevel(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseLevel(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}

	if _, err := New(WithLevelString("bogus")); err == nil {
		t.Fatal("New(WithLevelString(\"bogus\")) succeeded, want error")
	}
}

func TestJSONStructureLevelsAndUTCTimestamp(t *testing.T) {
	var buf bytes.Buffer
	fixedLocal := time.FixedZone("EST-5", -5*3600)
	fixedTime := time.Date(2026, 11, 26, 15, 4, 5, 123456000, fixedLocal)
	attrLocal := time.Date(2026, 11, 27, 12, 0, 0, 0, time.FixedZone("UTC+2", 2*3600))

	lvl := new(slog.LevelVar)
	lvl.Set(slog.LevelInfo)

	logger, closer, err := NewWithCloser(
		WithWriter(&buf),
		WithLevel(lvl),
		WithComponent("vault-server"),
		WithAddSource(true),
		WithClock(func() time.Time { return fixedTime }),
	)
	if err != nil {
		t.Fatalf("NewWithCloser: %v", err)
	}
	defer func() { _ = closer.Close() }()

	logger.Debug("debug suppressed")
	if buf.Len() != 0 {
		t.Fatalf("debug message emitted at INFO level: %s", buf.String())
	}

	lvl.Set(slog.LevelDebug)
	logger.Info("vault ready",
		slog.String(FieldEvent, "SERVER_START"),
		slog.String(FieldTokenID, "a1b2c3d4"),
		slog.String(FieldSecretName, "prod-db"),
		slog.Time("checked_at", attrLocal),
		slog.Any("any_time", attrLocal),
	)

	m := parseJSONLine(t, buf.String())
	if m[FieldTime] != "2026-11-26T20:04:05.123456Z" {
		t.Errorf("time = %v, want UTC 2026-11-26T20:04:05.123456Z", m[FieldTime])
	}
	// Mutant check (#14): dropping .UTC() on slog.KindTime or time.Time in scrubAny must fail.
	if m["checked_at"] != "2026-11-27T10:00:00Z" {
		t.Errorf("checked_at = %v, want UTC 2026-11-27T10:00:00Z", m["checked_at"])
	}
	if m["any_time"] != "2026-11-27T10:00:00Z" {
		t.Errorf("any_time = %v, want UTC 2026-11-27T10:00:00Z", m["any_time"])
	}
	if m[FieldLevel] != "INFO" {
		t.Errorf("level = %v, want INFO", m[FieldLevel])
	}
	if m[FieldMessage] != "vault ready" {
		t.Errorf("msg = %v, want 'vault ready'", m[FieldMessage])
	}
	if m[FieldComponent] != "vault-server" {
		t.Errorf("component = %v, want vault-server", m[FieldComponent])
	}
	if m[FieldTokenID] != "a1b2c3d4" {
		t.Errorf("token_id was wrongly redacted: %v", m[FieldTokenID])
	}
	if m[FieldSecretName] != "prod-db" {
		t.Errorf("secret_name was wrongly redacted: %v", m[FieldSecretName])
	}
	if m[FieldSource] == nil {
		t.Error("expected source object when WithAddSource(true)")
	}

	// Mutant check (#14): direct ReplaceAttr usage without sanitizingHandler
	// still normalizes top-level record timestamps to UTC, scrubs msg, preserves
	// level/source, and scrubs sensitive attributes.
	var rawBuf bytes.Buffer
	rawHandler := slog.NewJSONHandler(&rawBuf, &slog.HandlerOptions{
		AddSource:   true,
		ReplaceAttr: NewRedactor().ReplaceAttr,
	})
	rec := slog.NewRecord(fixedTime, slog.LevelInfo, "direct Bearer TOP_SECRET_DIRECT_TOK", 0)
	rec.AddAttrs(slog.String("password", "DIRECT_PW_99"), slog.String("region", "us-west-2"), slog.Attr{})
	if err := rawHandler.Handle(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rawBuf.String(), "TOP_SECRET_DIRECT_TOK") || strings.Contains(rawBuf.String(), "DIRECT_PW_99") {
		t.Fatalf("ReplaceAttr direct leaked secret: %s", rawBuf.String())
	}
	rm := parseJSONLine(t, rawBuf.String())
	if rm[FieldTime] != "2026-11-26T20:04:05.123456Z" {
		t.Errorf("ReplaceAttr direct time = %v, want UTC", rm[FieldTime])
	}
	if rm["region"] != "us-west-2" {
		t.Errorf("ReplaceAttr direct region = %v, want us-west-2", rm["region"])
	}
	if Default() == nil {
		t.Error("Default() returned nil")
	}
}

// sampleCredStruct exercises:
//   - sensitive Go struct field name with non-sensitive json tag (MasterKey `json:"mk"`),
//   - non-sensitive Go field name with sensitive json tag (Opaque `json:"client_secret"`),
//   - untagged CamelCase fields (PrivateKey, WrappedDEK, PublicLabel),
//   - json:"-" and unexported fields (#4, #14).
type sampleCredStruct struct {
	Agent         string `json:"agent"`
	MasterKey     string `json:"mk"`
	Opaque        string `json:"client_secret"`
	PrivateKey    string
	WrappedDEK    string
	PublicLabel   string
	InternalNotes string `json:"-"`
	unexported    string
}

type customLogValuer struct {
	token string
	agent string
}

func (c customLogValuer) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("agent", c.agent),
		slog.String("token", c.token),
	)
}

type stringTokenValuer struct{ line string }

func (s stringTokenValuer) LogValue() slog.Value {
	return slog.StringValue(s.line)
}

type recursiveValuer struct{}

func (recursiveValuer) LogValue() slog.Value {
	return slog.AnyValue(recursiveValuer{})
}

type panickingValuer struct{ secret string }

func (p panickingValuer) LogValue() slog.Value {
	panic("valuer boom " + p.secret)
}

type typedNilError struct{ msg string }

func (e *typedNilError) Error() string { return e.msg } // dereferences nil if called on (*typedNilError)(nil)

type panickingError struct{ secret string }

func (p panickingError) Error() string { panic("error boom " + p.secret) }

type panickingStringer struct{ secret string }

func (p panickingStringer) String() string { panic("stringer boom " + p.secret) }

type timeLogValuer struct{ t time.Time }

func (tv timeLogValuer) LogValue() slog.Value { return slog.TimeValue(tv.t) }

type intLogValuer struct{ n int }

func (iv intLogValuer) LogValue() slog.Value { return slog.IntValue(iv.n) }

type cyclicNode struct {
	Name string
	Next *cyclicNode
}

func TestRedactionAcrossTypesAndNesting(t *testing.T) {
	const (
		rawBearer = "vlt_live_9876543210abcdef_DO_NOT_LOG"
		rawSecret = "SUPER_SECRET_DB_PASSWORD_9911!"
		rawTOTP   = "482910"
		rawDEK    = "0123456789abcdef0123456789abcdef"
		rawCustom = "CUSTOM_INTERNAL_CRED_XYZ"
	)

	var buf bytes.Buffer
	logger, err := New(
		WithWriter(&buf),
		WithLevelString("debug"),
		WithExtraSensitiveKeys("custom_cred"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	hdr := http.Header{
		"Authorization": {"Bearer " + rawBearer},
		"Cookie":        {"a=1; sid=" + rawSecret},
		"X-Request-Id":  {"req-123"},
		"Accept":        {"application/json", "text/plain"},
	}

	nestedMap := map[string]any{
		"level1": map[string]any{
			"password":            rawSecret,
			"totp_code":           rawTOTP,
			"wrappedDek":          rawDEK,
			"SigningKey":          rawSecret,
			"HarnessKey":          rawSecret,
			"AccessKey":           rawSecret,
			"safe_list":           []any{"ok", map[string]string{"api_key": rawSecret, "code": rawTOTP, "pin": "7391", "region": "us-east-1"}},
			rawBearer:             "secret-used-as-map-key",
			"Bearer " + rawSecret: "bearer-map-key",
		},
		"raw_bytes": []byte(rawSecret),
	}

	cs := &sampleCredStruct{
		Agent:         "agent-alpha",
		MasterKey:     rawSecret,
		Opaque:        rawSecret,
		PrivateKey:    rawSecret,
		WrappedDEK:    rawDEK,
		PublicLabel:   "public-metadata-ok",
		InternalNotes: rawSecret,
		unexported:    rawSecret,
	}

	child := logger.
		With(slog.String("operator_token", rawBearer), slog.Int("code", 200), slog.Int("pin", 7), slog.String("code", rawTOTP)).
		WithGroup("").
		WithGroup("req_ctx")

	var nilStructPtr *sampleCredStruct
	var nilCustomMap map[int]string
	customMap := map[int]string{1: "Bearer " + rawBearer, 2: "safe"}
	cyc := &cyclicNode{Name: "cycle"}
	cyc.Next = cyc

	errVal := errors.New("connect postgres://admin:" + rawSecret + "@db.internal:5432/vault failed")

	child.Info("operation failed: Authorization: Bearer "+rawBearer,
		slog.String("empty", ""),
		slog.Bool("flag", true),
		slog.Float64("ratio", 0.5),
		slog.Duration("elapsed", 5*time.Millisecond),
		slog.String("value", rawSecret),
		slog.String("totp", rawTOTP),
		slog.String("my_custom_cred_field", rawCustom),
		slog.Group("credentials",
			slog.String("anything_inside_sensitive_group", rawSecret),
		),
		slog.Group("request",
			slog.Any("headers", hdr),
			slog.Any("payload", nestedMap),
			slog.Any("struct_ptr", cs),
			slog.Any("cyclic", cyc),
			slog.Any("nil_ptr", nilStructPtr),
			slog.Any("nil_any", nil),
			slog.Any("nil_map", nilCustomMap),
			slog.Any("int_map", customMap),
			slog.Any("int_slice", []int{10, 20}),
			slog.Any("str_slice", []string{"Bearer " + rawBearer, "plain"}),
			slog.Any("valuer", customLogValuer{token: rawBearer, agent: "bot-1"}),
			slog.Any("str_valuer", stringTokenValuer{line: "token=" + rawBearer}),
			slog.Any("loop_valuer", recursiveValuer{}),
			slog.Any("err", errVal),
		),
	)

	out := buf.String()
	for _, forbidden := range []string{rawBearer, rawSecret, rawTOTP, rawDEK, rawCustom, "7391"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("log output leaked sensitive value %q:\n%s", forbidden, out)
		}
	}

	// Positive assertions including mutant checks (#14):
	//   - non-sensitive struct field PublicLabel stays intact while mk, client_secret,
	//     PrivateKey, and WrappedDEK are redacted;
	//   - integer code=200 and pin=7 stay intact;
	//   - case error: produces the scrubbed error string (not an empty struct {}).
	for _, expected := range []string{
		"agent-alpha",
		"public-metadata-ok",
		"req-123",
		"us-east-1",
		"bot-1",
		`"code":200`,
		`"pin":7`,
		`"mk":"[REDACTED]"`,
		`"client_secret":"[REDACTED]"`,
		`"PrivateKey":"[REDACTED]"`,
		`"WrappedDEK":"[REDACTED]"`,
		`connect postgres://admin:[REDACTED]@db.internal:5432/vault failed`,
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("log output missing expected output %q:\n%s", expected, out)
		}
	}
}

// TestReviewerLeakProbesAndEdgeCases covers every leak vector identified in the
// security review (#3, #4, #5, #6, #7, #10, #12, #14).
func TestReviewerLeakProbesAndEdgeCases(t *testing.T) {
	// Real 43-char RawURLEncoding and 44-char URLEncoding 32-byte tokens.
	raw32 := []byte("0123456789abcdef0123456789ABCDEF")
	bareTok43 := base64.RawURLEncoding.EncodeToString(raw32) // 43 chars, no '='
	bareTok44 := base64.URLEncoding.EncodeToString(raw32)    // 44 chars, trailing '='
	basicUserPass := base64.StdEncoding.EncodeToString([]byte("admin:s3cr3tPass!"))

	t.Run("camelCase_and_expanded_sensitive_keys", func(t *testing.T) {
		r := NewRedactor()
		mustSensitive := []string{
			"PrivateKey", "MasterKey", "AccessKey", "SigningKey", "HarnessKey",
			"WrappedDEK", "wrappedDek", "HMACKey", "hmac_key", "APIKey",
			"pass", "auth", "session", "jwt", "dek", "kek",
			"recovery_code", "otp_seed", "verification_code",
			"session_token", "authorization",
		}
		for _, k := range mustSensitive {
			if !r.IsSensitiveKey(k) {
				t.Errorf("IsSensitiveKey(%q) = false, want true (normalized=%q)", k, normalizeKey(k))
			}
		}
		mustSafe := []string{"secret_name", "SecretName", "token_id", "TokenID", "public_key", "PublicKey", "secret_len"}
		for _, k := range mustSafe {
			if r.IsSensitiveKey(k) {
				t.Errorf("IsSensitiveKey(%q) = true, want false", k)
			}
		}

		// Conditional string keys: "pin" (string redacted, int kept) and "safe" keys
		// carrying real tokens/keys in their values (#4).
		var buf bytes.Buffer
		l, _ := New(WithWriter(&buf))
		l.Info("safe-key-value-scan",
			slog.String("pin", "0451"),
			slog.Int("pin_num", 4),
			slog.String("token_id", bareTok43),
			slog.String("valid_v1_token_id", "ok"),
			slog.Any("map_with_bare_token_key", map[string]string{bareTok43: "val1", bareTok44: "val2"}),
			slog.String("secret_len", "Bearer "+bareTok43),
			slog.String("public_key", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC\n-----END PRIVATE KEY-----"),
		)
		out := buf.String()
		for _, bad := range []string{"0451", bareTok43, bareTok44, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC"} {
			if strings.Contains(out, bad) {
				t.Errorf("leaked %q under conditional/safe key:\n%s", bad, out)
			}
		}

		// Legitimate 8-hex, 16-hex, tok_<hex>, and 32-hex v1 token_id values stay unredacted.
		buf.Reset()
		l.Info("safe-token-ids",
			slog.String("token_id", "550e8400e29b41d4a716446655440000"),
			slog.String("msg_kv", "token_id=tok_0123456789abcdef"),
		)
		if !strings.Contains(buf.String(), "550e8400e29b41d4a716446655440000") || !strings.Contains(buf.String(), "tok_0123456789abcdef") {
			t.Errorf("falsely redacted legitimate token_id:\n%s", buf.String())
		}

		// ScrubString idempotence check: double-scrubbing never mangles [REDACTED].
		for _, sample := range []string{
			"Authorization: Bearer " + bareTok43,
			"Bearer " + bareTok43,
			"Basic " + basicUserPass,
			"token=" + bareTok43,
			"Cookie: a=1; sid=secret",
		} {
			once := r.ScrubString(sample)
			twice := r.ScrubString(once)
			if once != twice {
				t.Errorf("ScrubString not idempotent for %q: once=%q twice=%q", sample, once, twice)
			}
		}
	})

	t.Run("inline_token_kv_and_bare_43_44_char_tokens", func(t *testing.T) {
		var buf bytes.Buffer
		l, _ := New(WithWriter(&buf))
		errText := fmt.Errorf("bad token %s or %s", bareTok43, bareTok44)
		l.Error("auth probe ?token="+bareTok43+"&session_token=sess_secret_999 authorization=raw_auth_999 token: inline_tok_999",
			slog.Any("err", errText),
			slog.Any("valuer", stringTokenValuer{line: "failed with " + bareTok43}),
			slog.String("token_id", "a1b2c3d4"),
			slog.String("func_name", "TestVaultBoundaryRejectsHostileNamesAndAgen"), // 43-char CamelCase, no digits -> must NOT false-positive
		)
		out := buf.String()
		for _, bad := range []string{bareTok43, bareTok44, "sess_secret_999", "raw_auth_999", "inline_tok_999"} {
			if strings.Contains(out, bad) {
				t.Errorf("leaked %q:\n%s", bad, out)
			}
		}
		for _, keep := range []string{"a1b2c3d4", "TestVaultBoundaryRejectsHostileNamesAndAgen"} {
			if !strings.Contains(out, keep) {
				t.Errorf("falsely redacted %q:\n%s", keep, out)
			}
		}
	})

	t.Run("cookie_semicolon_header_and_auth_header_mutant", func(t *testing.T) {
		// Mutant check (#5, #14): neither Digest, X-Api-Key, nor multi-cookie values
		// match Bearer/Basic/reKnownTokens; only reAuthHeader catches them.
		var buf bytes.Buffer
		l, _ := New(WithWriter(&buf))
		l.Warn("headers\nCookie: a=1; sid=COOKIE_SID_SECRET_77; theme=dark\nAuthorization: Digest username=\"op\", response=\"DIGEST_RESP_88\"\nX-Api-Key: XAPI_RAW_99")
		out := buf.String()
		for _, bad := range []string{"COOKIE_SID_SECRET_77", "theme=dark", "DIGEST_RESP_88", "XAPI_RAW_99"} {
			if strings.Contains(out, bad) {
				t.Errorf("header value leaked %q:\n%s", bad, out)
			}
		}
	})

	t.Run("basic_prose_preserved_nbsp_bearer_and_complex_url_passwords", func(t *testing.T) {
		var buf bytes.Buffer
		l, _ := New(WithWriter(&buf))
		l.Info("loaded basic configuration and Basic configuration",
			slog.String("auth1", "Basic "+basicUserPass),
			slog.String("auth2", "Bearer\u00a0NBSP_SECRET_TOK"),
			slog.String("redis_empty_user", "redis://:REDIS_PW_123@cache.internal:6379/0"),
			slog.String("pw_with_at", "postgres://vault:p@ss@w0rd!@db.internal:5432/vault"),
		)
		out := buf.String()
		for _, bad := range []string{basicUserPass, "NBSP_SECRET_TOK", "REDIS_PW_123", "p@ss", "w0rd!"} {
			if strings.Contains(out, bad) {
				t.Errorf("leaked %q:\n%s", bad, out)
			}
		}
		for _, keep := range []string{"basic configuration", "Basic configuration", "@cache.internal:6379", "@db.internal:5432"} {
			if !strings.Contains(out, keep) {
				t.Errorf("unexpectedly mangled %q:\n%s", keep, out)
			}
		}
	})

	t.Run("panicking_logvaluer_and_typed_nil_error_never_panic", func(t *testing.T) {
		var buf bytes.Buffer
		l, _ := New(WithWriter(&buf))
		var nilTypedErr error = (*typedNilError)(nil)
		var nilValuer slog.LogValuer = (*panickingValuer)(nil)

		l.Error("resilience check",
			slog.Any("panic_attr", panickingValuer{secret: "PANIC_SECRET_1"}),
			slog.Any("panic_any", []any{panickingValuer{secret: "PANIC_SECRET_2"}}),
			slog.Any("typed_nil_err", nilTypedErr),
			slog.Any("panic_err", panickingError{secret: "PANIC_SECRET_3"}),
			slog.Any("nil_valuer", nilValuer),
			slog.Any("func_val", func() {}),
			slog.Any("map_panic_key", map[any]string{panickingStringer{secret: "PANIC_SECRET_4"}: "v"}),
			slog.Any("time_valuer", []any{timeLogValuer{t: time.Date(2026, 11, 27, 12, 0, 0, 0, time.FixedZone("UTC+3", 3*3600))}, intLogValuer{n: 42}}),
		)
		out := buf.String()
		for _, bad := range []string{"PANIC_SECRET_1", "PANIC_SECRET_2", "PANIC_SECRET_3", "PANIC_SECRET_4"} {
			if strings.Contains(out, bad) {
				t.Errorf("panic value leaked %q:\n%s", bad, out)
			}
		}
		if !strings.Contains(out, RedactedPanicPlaceholder) {
			t.Errorf("expected %q placeholder in %s", RedactedPanicPlaceholder, out)
		}
	})

	t.Run("breadth_cycle_map_finishes_fast_and_bounded", func(t *testing.T) {
		// Exact reviewer DoS probe: 4 self-edges at depth 16 = 4^16 nodes without a node budget.
		m := map[string]any{}
		for i := 0; i < 4; i++ {
			m[fmt.Sprintf("k_%d", i)] = m
		}

		var buf bytes.Buffer
		l, _ := New(WithWriter(&buf))
		start := time.Now()
		l.Info(" cyclic-breadth-dos", slog.Any("graph", m))
		elapsed := time.Since(start)

		if elapsed > 2*time.Second {
			t.Fatalf("breadth DoS took %s (want < 2s)", elapsed)
		}
		if buf.Len() > 2*1024*1024 {
			t.Fatalf("output size = %d bytes, want bounded (< 2 MiB)", buf.Len())
		}
		if !strings.Contains(buf.String(), TruncatedPlaceholder) {
			t.Errorf("expected %q marker in truncated graph output", TruncatedPlaceholder)
		}
	})

	t.Run("lrm_rlm_and_bidi_controls_encoded", func(t *testing.T) {
		got := SanitizeText("safe\u200elrm\u200frlm\u061calm\u200bzwsp\ufeffbom")
		for _, raw := range []string{"\u200e", "\u200f", "\u061c", "\u200b", "\ufeff"} {
			if strings.Contains(got, raw) {
				t.Errorf("SanitizeText left raw Unicode control %+q in %q", raw, got)
			}
		}
		for _, want := range []string{`\u200e`, `\u200f`, `\u061c`, `\u200b`, `\ufeff`} {
			if !strings.Contains(got, want) {
				t.Errorf("SanitizeText missing %q in %q", want, got)
			}
		}
	})
}

func TestHostileInputsNoSecretAndInjectionEncoded(t *testing.T) {
	const sentinel = "SENTINEL_CRED_8842_NEVER_APPEAR"

	cases := []struct {
		name      string
		msg       string
		attrs     []slog.Attr
		forbidden []string
		mustHave  []string
	}{
		{
			name: "crlf_log_forging_in_message_and_fields",
			msg:  "user login\r\n{\"level\":\"INFO\",\"msg\":\"FORGED_ADMIN_GRANT\"}",
			attrs: []slog.Attr{
				slog.String(FieldAgent, "agent-1\r\nFAKE_LINE\tTAB"),
				slog.String(FieldSecretName, "db\nname\rwith\tcrlf"),
			},
			mustHave: []string{`\r\n`, `\t`},
		},
		{
			name: "ansi_osc_and_control_chars_encoded",
			msg:  "alert \x1b[31mRED\x1b[0m \x1b]52;c;YWJj\x07 bell\x00nul\x7fdel\u2028linesep\u202erlo\u009bcsi",
			attrs: []slog.Attr{
				slog.String("note", "esc=\x1b[2J nul=\x00 sep=\u2029"),
			},
			forbidden: []string{"\x1b", "\x00", "\x07", "\x7f", "\u2028", "\u2029", "\u202e", "\u009b"},
			mustHave:  []string{`\x1b[31m`, `\x00`, `\x07`, `\x7f`, `\u2028`, `\u202e`, `\u009b`},
		},
		{
			name:      "bearer_and_basic_schemes_in_free_text",
			msg:       "upstream rejected Bearer " + sentinel + " and Basic " + base64.StdEncoding.EncodeToString([]byte("u:"+sentinel)),
			forbidden: []string{sentinel, base64.StdEncoding.EncodeToString([]byte("u:" + sentinel))},
			mustHave:  []string{"Bearer [REDACTED]", "Basic [REDACTED]"},
		},
		{
			name: "otpauth_uri_and_totp_codes",
			msg:  "enrolled otpauth://totp/rgt-vault:operator?secret=JBSWY3DPEHPK3PXP&issuer=rgt-vault",
			attrs: []slog.Attr{
				slog.String("totp_code", "654321"),
				slog.String("totp_secret", "JBSWY3DPEHPK3PXP"),
			},
			forbidden: []string{"JBSWY3DPEHPK3PXP", "654321"},
			mustHave:  []string{"secret=[REDACTED]"},
		},
		{
			name: "inline_kv_and_known_token_shapes",
			msg:  `error client_secret=` + sentinel + ` token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZ2VudCJ9.c2lnbmF0dXJl"`,
			attrs: []slog.Attr{
				slog.String("detail", "key=sk-test1234567890abcdef and password='"+sentinel+"'"),
			},
			forbidden: []string{sentinel, "sk-test1234567890abcdef", "eyJhbGciOiJIUzI1NiJ9"},
		},
		{
			name: "raw_byte_slices_and_arrays_never_dumped",
			msg:  "buffer diagnostic",
			attrs: []slog.Attr{
				slog.Any("buf", []byte(sentinel)),
				slog.Any("arr", [4]byte{'S', 'E', 'C', 'R'}),
			},
			forbidden: []string{sentinel, "SECR"},
			mustHave:  []string{"bytes redacted>"},
		},
		{
			name: "invalid_utf8_and_hostile_key_names",
			msg:  "bad utf8 " + string([]byte{0xff, 0xfe}),
			attrs: []slog.Attr{
				slog.String("bad\nkey\x1b", "ok"),
			},
			mustHave: []string{`\xff\xfe`, `bad\\nkey\\x1b`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger, err := New(WithWriter(&buf), WithLevelString("debug"))
			if err != nil {
				t.Fatal(err)
			}
			logger.LogAttrs(context.Background(), slog.LevelWarn, tc.msg, tc.attrs...)

			raw := buf.String()
			trimmed := strings.TrimSuffix(raw, "\n")
			if strings.ContainsRune(trimmed, '\n') || strings.ContainsRune(trimmed, '\r') {
				t.Fatalf("log output contains unencoded CR/LF across lines: %q", raw)
			}
			m := parseJSONLine(t, raw)

			decodedMsg, _ := m[FieldMessage].(string)
			if strings.ContainsAny(decodedMsg, "\r\n\t\x1b\x00\x7f") {
				t.Errorf("decoded msg still contains raw control characters: %q", decodedMsg)
			}

			for _, bad := range tc.forbidden {
				if strings.Contains(raw, bad) || strings.Contains(decodedMsg, bad) {
					t.Errorf("output contains forbidden substring %q:\nraw=%s", bad, raw)
				}
			}
			for _, want := range tc.mustHave {
				if !strings.Contains(raw, want) && !strings.Contains(decodedMsg, want) {
					t.Errorf("output missing %q:\nraw=%s\ndecodedMsg=%s", want, raw, decodedMsg)
				}
			}
		})
	}
}

func TestFileWriterLifecyclePermissionsSymlinkAndReopen(t *testing.T) {
	if _, _, err := NewWithCloser(WithFile("   ")); err == nil {
		t.Fatal("expected error for blank file path")
	}

	base := t.TempDir()
	logDir := filepath.Join(base, "sub")
	logPath := filepath.Join(logDir, "vault.log")

	logger, closer, err := NewWithCloser(WithFile(logPath), WithComponent("daemon"))
	if err != nil {
		t.Fatalf("NewWithCloser(WithFile): %v", err)
	}

	fw, ok := closer.(*FileWriter)
	if !ok {
		t.Fatalf("closer = %T, want *FileWriter", closer)
	}
	if fw.Path() != logPath {
		t.Errorf("Path() = %q, want %q", fw.Path(), logPath)
	}

	logger.Info("before rotate", slog.String("secret", "TOP_SECRET_1"))

	if runtime.GOOS != "windows" {
		// Mutant check (#13, #14): new directory MUST be 0700 (not 0755) and file 0600.
		dInfo, err := os.Stat(logDir)
		if err != nil {
			t.Fatal(err)
		}
		if dMode := dInfo.Mode().Perm(); dMode != 0o700 {
			t.Errorf("new log dir mode = %04o, want 0700", dMode)
		}
		info, err := os.Stat(logPath)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("file mode = %04o, want 0600", mode)
		}
	}

	rotatedPath := logPath + ".1"
	if runtime.GOOS != "windows" {
		if err := os.Rename(logPath, rotatedPath); err != nil {
			t.Fatalf("rename: %v", err)
		}
	}
	if err := fw.Reopen(); err != nil {
		t.Fatalf("Reopen: %v", err)
	}
	logger.Info("after rotate", slog.String("token", "TOP_SECRET_2"))

	if err := fw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := fw.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if _, err := fw.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Write after Close = %v, want os.ErrClosed", err)
	}
	if err := fw.Reopen(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Reopen after Close = %v, want os.ErrClosed", err)
	}

	activeBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read active log: %v", err)
	}
	if !strings.Contains(string(activeBytes), "after rotate") || strings.Contains(string(activeBytes), "TOP_SECRET_2") {
		t.Errorf("unexpected active log contents: %s", string(activeBytes))
	}

	if runtime.GOOS != "windows" {
		rotBytes, err := os.ReadFile(rotatedPath)
		if err != nil {
			t.Fatalf("read rotated log: %v", err)
		}
		if !strings.Contains(string(rotBytes), "before rotate") || strings.Contains(string(rotBytes), "TOP_SECRET_1") {
			t.Errorf("unexpected rotated log contents: %s", string(rotBytes))
		}

		// Mutant check (#13, #14): pre-existing loose dir (0755) and loose file
		// (0644 / 0640) MUST be tightened to 0700 and 0600 on open, and symlinks
		// MUST be refused (O_NOFOLLOW).
		looseDir := filepath.Join(base, "loosedir")
		if err := os.MkdirAll(looseDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(looseDir, 0o755); err != nil {
			t.Fatal(err)
		}
		looseFile := filepath.Join(looseDir, "existing.log")
		if err := os.WriteFile(looseFile, []byte{}, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(looseFile, 0o644); err != nil {
			t.Fatal(err)
		}
		fwLoose, err := OpenFileWriter(looseFile)
		if err != nil {
			t.Fatalf("OpenFileWriter on loose file: %v", err)
		}
		_ = fwLoose.Close()

		if dInfo, err := os.Stat(looseDir); err != nil || dInfo.Mode().Perm() != 0o700 {
			t.Errorf("tightened dir mode = %04o (err=%v), want 0700", dInfo.Mode().Perm(), err)
		}
		if fInfo, err := os.Stat(looseFile); err != nil || fInfo.Mode().Perm() != 0o600 {
			t.Errorf("tightened file mode = %04o (err=%v), want 0600", fInfo.Mode().Perm(), err)
		}

		// Symlink target refusal (O_NOFOLLOW) and symlink dir refusal.
		symFile := filepath.Join(base, "symlink.log")
		if err := os.Symlink(looseFile, symFile); err != nil {
			t.Fatal(err)
		}
		if badFW, err := OpenFileWriter(symFile); err == nil {
			_ = badFW.Close()
			t.Fatal("OpenFileWriter followed a file symlink, want error")
		}

		symDir := filepath.Join(base, "symdir")
		if err := os.Symlink(looseDir, symDir); err != nil {
			t.Fatal(err)
		}
		if badFW, err := OpenFileWriter(filepath.Join(symDir, "inner.log")); err == nil {
			_ = badFW.Close()
			t.Fatal("OpenFileWriter accepted a symlinked parent directory, want error")
		}
		if badFW, err := OpenFileWriter(looseDir); err == nil {
			_ = badFW.Close()
			t.Fatal("OpenFileWriter accepted a directory target, want error")
		}
		if badFW, err := OpenFileWriter(filepath.Join(looseFile, "child.log")); err == nil {
			_ = badFW.Close()
			t.Fatal("OpenFileWriter accepted a non-directory parent, want error")
		}
	}
}

func TestHelpersContextTokenHashIncidentIDAndHTTPMiddleware(t *testing.T) {
	if got := TokenHashID(""); got != "" {
		t.Errorf("TokenHashID(\"\") = %q, want empty", got)
	}
	id1 := TokenHashID("my-bearer-token")
	id2 := TokenHashID("  my-bearer-token\n")
	if len(id1) != 8 || id1 != id2 || id1 == "my-beare" {
		t.Errorf("TokenHashID unexpected: id1=%q id2=%q", id1, id2)
	}

	incA, incB := NewIncidentID(), NewIncidentID()
	if len(incA) != 16 || incA == incB {
		t.Errorf("NewIncidentID = %q, %q", incA, incB)
	}

	var buf bytes.Buffer
	l, err := New(WithWriter(&buf), WithStdout(), WithStderr(), WithWriter(nil), WithWriter(&buf))
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithContext(context.Background(), nil)
	if FromContext(ctx) == nil {
		t.Error("FromContext fallback returned nil")
	}
	ctx = WithContext(ctx, l)
	if FromContext(ctx) != l {
		t.Error("FromContext did not return stored logger")
	}

	mw := HTTPMiddleware(l)
	_ = HTTPMiddleware(nil)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, ok := w.(interface{ Unwrap() http.ResponseWriter }); ok {
			_ = u.Unwrap()
		}
		switch r.URL.Path {
		case "/fail500":
			w.WriteHeader(http.StatusInternalServerError)
		case "/deny401":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))

	for _, tc := range []struct {
		target    string
		wantCode  float64
		wantLevel string
	}{
		{"/v1/secrets?token=DO_NOT_LOG_QUERY&secret=VAL", 200, "INFO"},
		{"/deny401?secret=NOPE", 401, "WARN"},
		{"/fail500", 500, "ERROR"},
	} {
		buf.Reset()
		req := httptest.NewRequest("GET", tc.target, nil)
		req.Header.Set("Authorization", "Bearer SECRET_HEADER_TOKEN")
		req.RemoteAddr = "198.51.100.42:55123"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		raw := buf.String()
		for _, forbidden := range []string{"DO_NOT_LOG_QUERY", "SECRET_HEADER_TOKEN", "198.51.100.42"} {
			if strings.Contains(raw, forbidden) {
				t.Errorf("HTTPMiddleware leaked %q in %s", forbidden, raw)
			}
		}
		m := parseJSONLine(t, raw)
		if m[FieldHTTPStatus] != tc.wantCode || m[FieldLevel] != tc.wantLevel {
			t.Errorf("target %s: got status=%v level=%v, want %v/%s", tc.target, m[FieldHTTPStatus], m[FieldLevel], tc.wantCode, tc.wantLevel)
		}
	}
}

func TestConcurrentLoggingAndReopenUnderRace(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "concurrent.log")
	logger, closer, err := NewWithCloser(WithFile(logPath), WithLevelString("debug"))
	if err != nil {
		t.Fatal(err)
	}
	fw := closer.(*FileWriter)
	defer func() { _ = fw.Close() }()

	const workers = 12
	const iters = 40
	var wg sync.WaitGroup
	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			sub := logger.With(slog.Int("worker", id)).WithGroup("job")
			for i := 0; i < iters; i++ {
				if id == 0 && i%10 == 0 {
					_ = fw.Reopen()
				}
				sub.Info("step\r\ninject",
					slog.String("token", fmt.Sprintf("tok-%d-%d", id, i)),
					slog.Any("meta", map[string]any{
						"iter":     i,
						"password": "pw-secret",
						"note":     "line1\nline2\x1b[31m",
					}),
				)
			}
		}(g)
	}
	wg.Wait()
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != workers*iters {
		t.Fatalf("got %d lines, want %d", len(lines), workers*iters)
	}
	for idx, ln := range lines {
		if strings.Contains(ln, "tok-") || strings.Contains(ln, "pw-secret") {
			t.Fatalf("line %d leaked secret: %s", idx, ln)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("line %d corrupted JSON under concurrency: %v (%q)", idx, err, ln)
		}
	}
}
