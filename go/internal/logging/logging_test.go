package logging

import (
	"bytes"
	"context"
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

	// Below threshold -> suppressed.
	logger.Debug("debug suppressed")
	if buf.Len() != 0 {
		t.Fatalf("debug message emitted at INFO level: %s", buf.String())
	}

	// Dynamic level change to DEBUG.
	lvl.Set(slog.LevelDebug)
	logger.Info("vault ready",
		slog.String(FieldEvent, "SERVER_START"),
		slog.String(FieldTokenID, "a1b2c3d4"),
		slog.String(FieldSecretName, "prod-db"),
	)

	m := parseJSONLine(t, buf.String())
	if m[FieldTime] != "2026-11-26T20:04:05.123456Z" {
		t.Errorf("time = %v, want UTC 2026-11-26T20:04:05.123456Z", m[FieldTime])
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
}

type sampleCredStruct struct {
	Agent         string `json:"agent"`
	BearerToken   string `json:"bearer_token"`
	SecretValue   string `json:"value"`
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

type recursiveValuer struct{}

func (recursiveValuer) LogValue() slog.Value {
	return slog.AnyValue(recursiveValuer{})
}

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
		"Cookie":        {"session=" + rawSecret},
		"X-Request-Id":  {"req-123"},
		"Accept":        {"application/json", "text/plain"},
	}

	nestedMap := map[string]any{
		"level1": map[string]any{
			"password":    rawSecret,
			"totp_code":   rawTOTP,
			"wrapped_dek": rawDEK,
			"safe_list":   []any{"ok", map[string]string{"api_key": rawSecret, "code": rawTOTP, "region": "us-east-1"}},
		},
		"raw_bytes": []byte(rawSecret),
	}

	cs := &sampleCredStruct{
		Agent:         "agent-alpha",
		BearerToken:   rawBearer,
		SecretValue:   rawSecret,
		InternalNotes: rawSecret,
		unexported:    rawSecret,
	}

	child := logger.
		With(slog.String("operator_token", rawBearer), slog.Int("code", 200), slog.String("code", rawTOTP)).
		WithGroup("").
		WithGroup("auth_ctx")

	var nilStructPtr *sampleCredStruct
	var nilCustomMap map[int]string
	customMap := map[int]string{1: "Bearer " + rawBearer, 2: "safe"}
	cyc := &cyclicNode{Name: "cycle"}
	cyc.Next = cyc

	child.Info("operation failed: Authorization: Bearer "+rawBearer,
		slog.String("empty", ""),
		slog.Time("checked_at", time.Date(2026, 11, 27, 12, 0, 0, 0, time.FixedZone("UTC+2", 7200))),
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
			slog.Any("time_any", time.Now()),
			slog.Any("valuer", customLogValuer{token: rawBearer, agent: "bot-1"}),
			slog.Any("loop_valuer", recursiveValuer{}),
			slog.Any("err", errors.New("connect postgres://admin:"+rawSecret+"@db.internal:5432/vault failed")),
		),
	)

	out := buf.String()
	for _, forbidden := range []string{rawBearer, rawSecret, rawTOTP, rawDEK, rawCustom} {
		if strings.Contains(out, forbidden) {
			t.Errorf("log output leaked sensitive value %q:\n%s", forbidden, out)
		}
	}

	// Positive assertions: non-sensitive metadata and integer status code remain intact.
	for _, expected := range []string{"agent-alpha", "req-123", "us-east-1", "bot-1", `"code":200`, RedactedPlaceholder} {
		if !strings.Contains(out, expected) {
			t.Errorf("log output missing expected safe value %q:\n%s", expected, out)
		}
	}
}

func TestHostileInputsNoSecretAndInjectionEncoded(t *testing.T) {
	// Sentinel values are synthetic strings that never match real credentials
	// while exercising every redaction and injection vector.
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
			msg:       "upstream rejected Bearer " + sentinel + " and Basic " + sentinel,
			forbidden: []string{sentinel},
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
			// Must be exactly one newline-terminated JSON object (no injected lines).
			trimmed := strings.TrimSuffix(raw, "\n")
			if strings.ContainsRune(trimmed, '\n') || strings.ContainsRune(trimmed, '\r') {
				t.Fatalf("log output contains unencoded CR/LF across lines: %q", raw)
			}
			m := parseJSONLine(t, raw)

			// Decoded JSON strings must also contain no raw control/newline chars,
			// so downstream consumers that extract .msg cannot be tricked.
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

func TestFileWriterLifecyclePermissionsAndReopen(t *testing.T) {
	if _, _, err := NewWithCloser(WithFile("   ")); err == nil {
		t.Fatal("expected error for blank file path")
	}

	logPath := filepath.Join(t.TempDir(), "sub", "vault.log")
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
		info, err := os.Stat(logPath)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("file mode = %04o, want 0600", mode)
		}
	}

	// Simulate logrotate moving the active file and signaling Reopen.
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
	// Idempotent Close; Write/Reopen after Close fail cleanly.
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
