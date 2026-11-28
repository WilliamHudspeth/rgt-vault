package logging

import (
	"bytes"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
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

func TestFileWriterDirectoryAndFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}

	// Existing owned directory that is group/other accessible is tightened to 0700
	// and a pre-existing 0640 file is tightened to 0600.
	base := t.TempDir()
	dir := filepath.Join(base, "logs")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "a.log")
	if err := os.WriteFile(path, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	fw, err := OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = fw.Close()
	assertMode(t, dir, 0o700)
	assertMode(t, path, 0o600)

	// A sticky shared directory (like /tmp) is never chmodded.
	shared := filepath.Join(base, "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	fw, err = OpenFileWriter(filepath.Join(shared, "b.log"))
	if err != nil {
		t.Fatal(err)
	}
	_ = fw.Close()
	st, err := os.Stat(shared)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSticky == 0 || st.Mode().Perm() != 0o777 {
		t.Errorf("sticky shared dir was modified: %v", st.Mode())
	}

	// A symlinked log FILE is refused (O_NOFOLLOW).
	target := filepath.Join(base, "target.log")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if fw, err := OpenFileWriter(link); err == nil {
		_ = fw.Close()
		t.Error("OpenFileWriter followed a symlinked log file")
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != want {
		t.Errorf("%s mode = %04o, want %04o", path, got, want)
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
