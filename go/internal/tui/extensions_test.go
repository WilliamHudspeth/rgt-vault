package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
)

// ---------------------------------------------------------------------------
// Pure unit tests
// ---------------------------------------------------------------------------

// TestBuildTree checks that BuildTree produces the expected pre-order flattened
// rows for a set of slash-separated secret names.
func TestBuildTree(t *testing.T) {
	secrets := []SecretInfo{
		{Name: "api/key", Fingerprint: "aaa11111"},
		{Name: "db/host", Fingerprint: "bbb22222"},
		{Name: "db/pass", Fingerprint: "ccc33333"},
	}

	rows := BuildTree(secrets)

	// Expected pre-order (sorted alphabetically at each level):
	//   api      indent=0, isLeaf=false
	//     key    indent=1, isLeaf=true
	//   db       indent=0, isLeaf=false
	//     host   indent=1, isLeaf=true
	//     pass   indent=1, isLeaf=true
	type expected struct {
		indent int
		label  string
		isLeaf bool
	}
	want := []expected{
		{0, "api", false},
		{1, "key", true},
		{0, "db", false},
		{1, "host", true},
		{1, "pass", true},
	}

	if len(rows) != len(want) {
		t.Fatalf("BuildTree: got %d rows, want %d; rows=%+v", len(rows), len(want), rows)
	}
	for i, w := range want {
		r := rows[i]
		if r.Indent != w.indent || r.Label != w.label || r.IsLeaf != w.isLeaf {
			t.Errorf("row[%d]: got {Indent:%d Label:%q IsLeaf:%v}, want {Indent:%d Label:%q IsLeaf:%v}",
				i, r.Indent, r.Label, r.IsLeaf, w.indent, w.label, w.isLeaf)
		}
		if w.isLeaf && r.Secret == nil {
			t.Errorf("row[%d]: IsLeaf=true but Secret is nil", i)
		}
		if !w.isLeaf && r.Secret != nil {
			t.Errorf("row[%d]: IsLeaf=false but Secret is non-nil", i)
		}
	}
}

// TestTOTPRemaining verifies that TOTPRemaining returns a value in [1, 30] and
// computes correctly for a known timestamp.
func TestTOTPRemaining(t *testing.T) {
	// Unix timestamp 1_000_000_000 % 30 == 10, so remaining == 20.
	knownTime := time.Unix(1_000_000_000, 0)
	got := TOTPRemaining(knownTime, 30)
	if got != 20 {
		t.Errorf("TOTPRemaining(1_000_000_000, 30): got %d, want 20", got)
	}

	// Result must always be in [1, 30] for arbitrary times.
	for offset := 0; offset < 60; offset++ {
		rem := TOTPRemaining(time.Unix(int64(offset), 0), 30)
		if rem < 1 || rem > 30 {
			t.Errorf("TOTPRemaining(offset=%d): %d out of [1,30]", offset, rem)
		}
	}
}

// TestIsTOTP checks the heuristic that identifies TOTP secrets by name.
func TestIsTOTP(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"github-totp", true},
		{"vpn-otp", true},
		{"TOTP-service", true},
		{"api-key", false},
		{"db-pass", false},
		{"totp", true},
	}
	for _, tc := range cases {
		got := IsTOTP(SecretInfo{Name: tc.name})
		if got != tc.want {
			t.Errorf("IsTOTP(%q): got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestMemoryClipboard verifies the in-memory clipboard Write/Content/Clear cycle.
func TestMemoryClipboard(t *testing.T) {
	clip := &MemoryClipboard{}

	// Initially empty.
	if got := clip.Content(); got != "" {
		t.Errorf("initial content: got %q, want %q", got, "")
	}

	// Write sets content.
	if err := clip.Write("abc12345"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := clip.Content(); got != "abc12345" {
		t.Errorf("after Write: got %q, want %q", got, "abc12345")
	}

	// Clear empties content.
	if err := clip.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if got := clip.Content(); got != "" {
		t.Errorf("after Clear: got %q, want %q", got, "")
	}
}

// ---------------------------------------------------------------------------
// fakeClientTOTP — returns one TOTP secret for teatest scenarios
// ---------------------------------------------------------------------------

type fakeClientTOTP struct{}

func (f *fakeClientTOTP) Health() bool      { return true }
func (f *fakeClientTOTP) VerifyAudit() bool { return true }
func (f *fakeClientTOTP) ListSecrets(namespace string) ([]SecretInfo, error) {
	return []SecretInfo{
		{Name: "vpn-totp", Fingerprint: "ff001122"},
	}, nil
}
func (f *fakeClientTOTP) Rotate(target string) error { return nil }
func (f *fakeClientTOTP) GetAuditLog(limit int) ([]AuditEntry, error) { return nil, nil }

// ---------------------------------------------------------------------------
// fakeClientTree — returns three secrets with path-like names
// ---------------------------------------------------------------------------

type fakeClientTree struct{}

func (f *fakeClientTree) Health() bool      { return true }
func (f *fakeClientTree) VerifyAudit() bool { return true }
func (f *fakeClientTree) ListSecrets(namespace string) ([]SecretInfo, error) {
	return []SecretInfo{
		{Name: "db/host", Fingerprint: "aaa11111"},
		{Name: "db/pass", Fingerprint: "bbb22222"},
		{Name: "api/key", Fingerprint: "ccc33333"},
	}, nil
}
func (f *fakeClientTree) Rotate(target string) error { return nil }
func (f *fakeClientTree) GetAuditLog(limit int) ([]AuditEntry, error) { return nil, nil }

// ---------------------------------------------------------------------------
// teatest: TOTP countdown appears in output
// ---------------------------------------------------------------------------

// TestTOTPCountdownRendered verifies that when showTOTP is true (the default)
// and the loaded secrets include a TOTP secret, the output contains "TOTP".
func TestTOTPCountdownRendered(t *testing.T) {
	tm := teatest.NewTestModel(
		t,
		New(&fakeClientTOTP{}, "default"),
		teatest.WithInitialTermSize(80, 24),
	)

	teatest.WaitFor(
		t,
		tm.Output(),
		func(bts []byte) bool {
			return strings.Contains(string(bts), "TOTP")
		},
		teatest.WithDuration(3*time.Second),
		teatest.WithCheckInterval(50*time.Millisecond),
	)

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
}

// ---------------------------------------------------------------------------
// teatest: tree view toggle with "t" key
// ---------------------------------------------------------------------------

// TestTreeViewToggle verifies that pressing "t" in dashboard mode switches to
// the tree view which renders parent nodes ("db") and indented leaves.
func TestTreeViewToggle(t *testing.T) {
	tm := teatest.NewTestModel(
		t,
		New(&fakeClientTree{}, "default"),
		teatest.WithInitialTermSize(80, 24),
	)

	// Wait for the flat list to appear.
	teatest.WaitFor(
		t,
		tm.Output(),
		func(bts []byte) bool {
			return strings.Contains(string(bts), "db/host")
		},
		teatest.WithDuration(3*time.Second),
		teatest.WithCheckInterval(50*time.Millisecond),
	)

	// Toggle tree view.
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("t")})

	// In tree mode the parent node "db" renders without the slash; the
	// leaves "host" and "pass" should appear indented beneath it.
	teatest.WaitFor(
		t,
		tm.Output(),
		func(bts []byte) bool {
			out := string(bts)
			// Parent node "db" must appear, and at least one of the children
			// must appear indented (two spaces + label).
			return strings.Contains(out, "db") &&
				(strings.Contains(out, "  host") || strings.Contains(out, "  pass"))
		},
		teatest.WithDuration(3*time.Second),
		teatest.WithCheckInterval(50*time.Millisecond),
	)

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
}

// ---------------------------------------------------------------------------
// teatest: clipboard copy and auto-clear
// ---------------------------------------------------------------------------

// TestClipboardCopyAndClear verifies that:
//  1. Pressing "c" writes the selected secret's fingerprint to the clipboard.
//  2. Sending clipboardClearMsg{} (the auto-clear message) empties the clipboard.
func TestClipboardCopyAndClear(t *testing.T) {
	clip := &MemoryClipboard{}
	tm := teatest.NewTestModel(
		t,
		NewWithClipboard(&fakeClientTOTP{}, "default", clip),
		teatest.WithInitialTermSize(80, 24),
	)

	// Wait for secrets to load so the cursor sits on the first secret.
	teatest.WaitFor(
		t,
		tm.Output(),
		func(bts []byte) bool {
			return strings.Contains(string(bts), "vpn-totp")
		},
		teatest.WithDuration(3*time.Second),
		teatest.WithCheckInterval(50*time.Millisecond),
	)

	// Press "c" — should copy fingerprint "ff001122" to clipboard.
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("c")})

	// Wait for the status message confirming the copy.
	teatest.WaitFor(
		t,
		tm.Output(),
		func(bts []byte) bool {
			return strings.Contains(string(bts), "copied fingerprint")
		},
		teatest.WithDuration(3*time.Second),
		teatest.WithCheckInterval(50*time.Millisecond),
	)

	// Verify clipboard content matches the secret's fingerprint.
	if got := clip.Content(); got != "ff001122" {
		t.Errorf("clipboard after 'c': got %q, want %q", got, "ff001122")
	}

	// Simulate the auto-clear timer firing by sending clipboardClearMsg directly.
	tm.Send(clipboardClearMsg{})

	// Wait for the "clipboard cleared" status to appear.
	teatest.WaitFor(
		t,
		tm.Output(),
		func(bts []byte) bool {
			return strings.Contains(string(bts), "clipboard cleared")
		},
		teatest.WithDuration(3*time.Second),
		teatest.WithCheckInterval(50*time.Millisecond),
	)

	// Clipboard must now be empty.
	if got := clip.Content(); got != "" {
		t.Errorf("clipboard after clear: got %q, want %q", got, "")
	}

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t, teatest.WithFinalTimeout(2*time.Second))
}
