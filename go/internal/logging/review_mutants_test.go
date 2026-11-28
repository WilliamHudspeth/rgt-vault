package logging

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Tests in this file pin behaviour that mutation testing showed was not
// otherwise covered (PR #58 review, finding 14), plus a few review leak
// repros. Each asserts the exact output so removing the guarded code fails it.

const testTok43 = "Zq3vK9xT2mLpR7sYw1BnC8dFh5JkA0eGu4iOa6VbXyE" // 43 chars, mixed case + digits

func logLine(t *testing.T, opts []Option, msg string, args ...any) string {
	t.Helper()
	var buf bytes.Buffer
	l, err := New(append([]Option{WithWriter(&buf)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	l.Info(msg, args...)
	return buf.String()
}

func TestNestedTimesAreUTC(t *testing.T) {
	if len(testTok43) != 43 {
		t.Fatalf("fixture token length = %d, want 43", len(testTok43))
	}
	zone := time.FixedZone("UTC+5", 5*3600)
	at := time.Date(2026, 11, 27, 10, 0, 0, 0, zone) // 05:00:00Z

	// time.Time nested in a map / slice / struct goes through scrubAny.
	out := logLine(t, nil, "m", "nested", map[string]any{"at": at, "list": []any{at}},
		"strct", struct{ At time.Time }{At: at})
	if strings.Contains(out, "+05:00") || strings.Count(out, "2026-11-27T05:00:00Z") != 3 {
		t.Errorf("nested time.Time not converted to UTC: %s", out)
	}

	// A LogValuer that resolves to a time, nested inside a map.
	out = logLine(t, nil, "v", "nested", map[string]any{"at": timeValuer{at}})
	if strings.Contains(out, "+05:00") || !strings.Contains(out, "2026-11-27T05:00:00Z") {
		t.Errorf("LogValuer time not converted to UTC: %s", out)
	}
}

type timeValuer struct{ t time.Time }

func (v timeValuer) LogValue() slog.Value { return slog.TimeValue(v.t) }

// The record timestamp must be UTC even when the process-local zone is not
// and no injected clock is set.
func TestDefaultClockTimestampIsUTCWhenLocalZoneIsNot(t *testing.T) {
	saved := time.Local
	time.Local = time.FixedZone("UTC+9", 9*3600)
	defer func() { time.Local = saved }()

	m := parseJSONLine(t, logLine(t, nil, "tick"))
	ts, _ := m[FieldTime].(string)
	if !strings.HasSuffix(ts, "Z") || strings.Contains(ts, "+09:00") {
		t.Errorf("time = %q, want a UTC (Z) timestamp", ts)
	}
}

func TestXAPIKeyHeaderAndHeaderMapKeysAreScrubbed(t *testing.T) {
	out := logLine(t, nil, "upstream said X-Api-Key: "+testTok43+" rejected")
	if strings.Contains(out, testTok43) || !strings.Contains(out, "X-Api-Key: [REDACTED]") {
		t.Errorf("X-Api-Key value leaked: %s", out)
	}

	// A credential used as an http.Header / map KEY must not be printed.
	h := http.Header{"Bearer " + testTok43: {"x"}}
	out = logLine(t, nil, "h", "headers", h,
		"m1", map[string]string{"Bearer " + testTok43: "x"},
		"m2", map[string]any{"token=" + testTok43: 1})
	if strings.Contains(out, testTok43) {
		t.Errorf("secret used as map key was printed: %s", out)
	}
}

func TestBareTokenHeuristicHasNoFalsePositives(t *testing.T) {
	benign := []string{
		"basic configuration loaded",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // sha256 hex
		"3f786850e387550fdab836ed7e6dc881de23001b",                         // git sha
		"550e8400-e29b-41d4-a716-446655440000",                             // uuid
		"TestVaultBoundaryRejectsHostileNamesAndAgentsBeforeAudit",         // identifier
		"/var/lib/rgt-vault/sealed/master_secret.priv",
		"the quick brown fox jumps over the lazy dog today",
	}
	for _, s := range benign {
		if got := NewRedactor().ScrubString(s); got != s {
			t.Errorf("ScrubString(%q) = %q, want unchanged", s, got)
		}
	}
	// ...while the same-length random token on its own is redacted.
	if got := NewRedactor().ScrubString("x " + testTok43 + " y"); got != "x [REDACTED] y" {
		t.Errorf("bare 43-char token = %q, want redacted", got)
	}
}

func TestStructSensitiveFieldNameWinsOverBenignJSONTag(t *testing.T) {
	type creds struct {
		Password string `json:"p"`
		Note     string `json:"private_key"` // benign Go name, sensitive tag
		Plain    string `json:"plain"`
	}
	out := logLine(t, nil, "s", "c", creds{Password: "hunter2hunter2", Note: "n0t-a-real-one", Plain: "visible"})
	if strings.Contains(out, "hunter2hunter2") || strings.Contains(out, "n0t-a-real-one") || !strings.Contains(out, "visible") {
		t.Errorf("struct redaction wrong: %s", out)
	}
}

// A short (non-43-char) credential after the word "token" in prose or error
// text is caught by the prose rule alone (bare-token heuristic cannot match).
func TestTokenProseRuleCatchesShortCredentialInErrorText(t *testing.T) {
	const short = "Qw3rTy9uIo2pAs5d"
	out := logLine(t, nil, "auth failed", "err", errString("bad token "+short+" for agent"))
	if strings.Contains(out, short) || !strings.Contains(out, "bad token [REDACTED] for agent") {
		t.Errorf("short token after 'token' leaked: %s", out)
	}
	// Prose without a credential is untouched.
	if got := NewRedactor().ScrubString("the token expired yesterday"); got != "the token expired yesterday" {
		t.Errorf("prose over-redacted: %q", got)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestRedactorClosesReviewGaps(t *testing.T) {
	r := NewRedactor()
	for _, in := range []string{
		"auth=SECRETX1", "pw=SECRETX1", "pin=123456",
		"token_id=" + testTok43, "bearer=" + testTok43, "Bearer%20" + testTok43,
		"cfg {token_id: " + testTok43 + "}",
	} {
		got := r.ScrubString(in)
		if strings.Contains(got, "SECRETX1") || strings.Contains(got, "123456") || strings.Contains(got, testTok43) {
			t.Errorf("ScrubString(%q) = %q leaked", in, got)
		}
	}
	// A short, public token_id is still allowed through as an assignment.
	if got := r.ScrubString("token_id=a1b2c3d4"); got != "token_id=a1b2c3d4" {
		t.Errorf("short token id over-redacted: %q", got)
	}

	// Integer and struct-field PIN / pw values, which a string-only rule misses.
	out := logLine(t, nil, "m", "pin", 123456, "pw", "SECRETX1",
		"s", struct {
			Pin int
			PW  string
		}{123456, "SECRETX1"})
	if strings.Contains(out, "123456") || strings.Contains(out, "SECRETX1") {
		t.Errorf("pin/pw leaked: %s", out)
	}
}

func TestScrubStringIsBoundedOnHugeInput(t *testing.T) {
	big := strings.Repeat("a b ", 5_000_000) // 20 MB
	start := time.Now()
	got := NewRedactor().ScrubString(big + " token=" + testTok43)
	// Capped work is ~1 s even under -race on a slow runner; uncapped it is minutes.
	if d := time.Since(start); d > 30*time.Second {
		t.Fatalf("ScrubString on 20 MB took %v", d)
	}
	if !strings.Contains(got, "[TRUNCATED ") || len(got) > 70<<10 {
		t.Errorf("huge string not truncated (len %d, tail %q)", len(got), got[len(got)-40:])
	}
	if strings.Contains(got, testTok43) {
		t.Error("token beyond the cap must not appear")
	}
	// A credential straddling the cap is never partially emitted.
	edge := strings.Repeat("x ", (maxScrubStringBytes-10)/2) + "token=" + testTok43 + " tail"
	if out := NewRedactor().ScrubString(edge); strings.Contains(out, testTok43[:12]) {
		t.Errorf("credential cut by the cap leaked a prefix: %q", out[len(out)-60:])
	}
}

func TestSanitizeTextEncodesInvisibleAndPrivateUseCodePoints(t *testing.T) {
	for _, r := range []rune{0x00ad, 0x180e, 0x2060, 0xfff9, 0xfffa, 0xfffb, 0xe000, 0xf8ff, 0xe0041, 0xf0000, 0x2028, 0x200e} {
		in := "a" + string(r) + "b"
		got := SanitizeText(in)
		if strings.ContainsRune(got, r) || !strings.Contains(got, `\u`) {
			t.Errorf("SanitizeText(U+%04X) = %q, want encoded", r, got)
		}
	}
	if got := SanitizeText("café 世界 \U0001F600"); got != "café 世界 \U0001F600" {
		t.Errorf("ordinary non-ASCII altered: %q", got)
	}
}
