package tui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// pasteMsg builds a key message like the one Bubble Tea delivers for text
// typed or pasted in one chunk. bracketed marks a bracketed paste (its String()
// form is wrapped in '[...]').
func pasteMsg(s string, bracketed bool) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s), Paste: bracketed}
}

// totpPromptModel drives a model into the TOTP prompt for the require_2fa
// request (id-2).
func totpPromptModel(t *testing.T) (Model, *fakeApprover) {
	t.Helper()
	f := &fakeApprover{reqs: twoRequests()}
	m := loadedModel(t, f)
	m, _ = step(m, key("j"))
	m, _ = step(m, key("a"))
	if m.mode != modeTOTPPrompt {
		t.Fatalf("mode = %v, want TOTP prompt", m.mode)
	}
	return m, f
}

func TestTOTPPrompt_AcceptsPastedCode(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		bracketed bool
		want      string
	}{
		{"six digit bracketed paste", "123456", true, "123456"},
		{"multi rune key message", "123456", false, "123456"},
		{"non digits are dropped", "12 34-56", true, "123456"},
		{"paste longer than the cap", "123456789012", true, "12345678"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := totpPromptModel(t)
			m, _ = step(m, pasteMsg(tc.input, tc.bracketed))
			if m.totpInput != tc.want {
				t.Fatalf("totpInput = %q, want %q", m.totpInput, tc.want)
			}
			// The code stays masked, never echoed.
			if tc.want != "" && strings.Contains(m.View(), tc.want) {
				t.Errorf("view renders the code:\n%s", m.View())
			}
			if !strings.Contains(m.View(), strings.Repeat("*", len(tc.want))+"_") {
				t.Errorf("view does not mask the code:\n%s", m.View())
			}
		})
	}
}

func TestTOTPPrompt_PastedCodeCanBeSubmitted(t *testing.T) {
	m, f := totpPromptModel(t)
	m, _ = step(m, pasteMsg("987654", true))
	m, cmd := step(m, key("enter"))
	if cmd == nil {
		t.Fatal("enter after paste did not issue an approve command")
	}
	m, _ = step(m, runCmd(t, cmd))
	if got := f.approvals(); len(got) != 1 || got[0] != [2]string{"id-2", "987654"} {
		t.Fatalf("approvals = %v, want id-2 with 987654", got)
	}
	if m.totpInput != "" {
		t.Errorf("code kept after submit: %q", m.totpInput)
	}
}

func TestTOTPPrompt_PasteRespectsExistingLength(t *testing.T) {
	m, _ := totpPromptModel(t)
	m, _ = step(m, key("1"))
	m, _ = step(m, key("2"))
	m, _ = step(m, pasteMsg("3456789", true))
	if m.totpInput != "12345678" {
		t.Fatalf("totpInput = %q, want the 8-digit cap", m.totpInput)
	}
}

func TestPanicKeyIsClearScreenQuit(t *testing.T) {
	m := New(&fakeClient{}, "default")
	m, _ = step(m, loadedMsg{serverOK: true, auditValid: true})

	footer := m.View()
	if strings.Contains(strings.ToLower(footer), "lock") {
		t.Errorf("footer still claims a lock:\n%s", footer)
	}
	if !strings.Contains(footer, "[P] clear screen & quit") {
		t.Errorf("footer lacks the renamed P key:\n%s", footer)
	}

	m, _ = step(m, key("?"))
	help := m.View()
	if strings.Contains(strings.ToLower(help), "lock") {
		t.Errorf("help still claims a lock:\n%s", help)
	}
	if !strings.Contains(help, "Clear screen & quit") {
		t.Errorf("help lacks the renamed P key:\n%s", help)
	}

	// P still quits, but the status no longer claims the vault is locked.
	d := New(&fakeClient{}, "default")
	d, _ = step(d, loadedMsg{serverOK: true, auditValid: true})
	d, cmd := step(d, key("P"))
	if cmd == nil {
		t.Fatal("P did not quit")
	}
	if strings.Contains(strings.ToLower(d.status), "lock") {
		t.Errorf("status = %q, still claims a lock", d.status)
	}
}

func TestDashboardPendingBadgeUpdates(t *testing.T) {
	f := &fakeApprover{reqs: twoRequests()}
	m := New(f, "prod")
	m, _ = step(m, loadedMsg{serverOK: true, auditValid: true})

	m, cmd := step(m, pendingTickMsg{})
	if cmd == nil {
		t.Fatal("poll tick did not issue a load command")
	}
	m, _ = step(m, runCmd(t, cmd))
	if v := m.View(); !strings.Contains(v, "requests: 2") {
		t.Fatalf("header lacks requests: 2:\n%s", v)
	}

	f.mu.Lock()
	f.reqs = append(f.reqs, PendingRequest{RequestID: "id-3", Agent: "late", Namespace: "dev", SecretName: "new", Action: "read"})
	f.mu.Unlock()

	m, cmd = step(m, pendingTickMsg{})
	m, _ = step(m, runCmd(t, cmd))
	if v := m.View(); !strings.Contains(v, "requests: 3") {
		t.Fatalf("header did not update after the poll:\n%s", v)
	}
}

func TestDashboardPendingBadgeOnlyWithApprovals(t *testing.T) {
	m := New(&fakeClient{}, "default")
	m, _ = step(m, loadedMsg{serverOK: true, auditValid: true})
	if v := m.View(); strings.Contains(v, "requests:") {
		t.Errorf("plain client should not show a requests badge:\n%s", v)
	}
}

func TestBellOffByDefaultAndToggle(t *testing.T) {
	m := New(&fakeApprover{}, "prod")
	if m.bellOn {
		t.Fatal("bell must be off by default")
	}
	m, _ = step(m, loadedMsg{serverOK: true, auditValid: true})

	m, _ = step(m, key("b"))
	if !m.bellOn {
		t.Fatal("b did not enable the bell")
	}
	if v := m.View(); !strings.Contains(v, "bell on") {
		t.Errorf("status does not report the bell on:\n%s", v)
	}

	m, _ = step(m, key("b"))
	if m.bellOn {
		t.Fatal("b did not disable the bell")
	}
	if v := m.View(); !strings.Contains(v, "bell off") {
		t.Errorf("status does not report the bell off:\n%s", v)
	}

	m, _ = step(m, key("?"))
	if help := m.View(); !strings.Contains(strings.ToLower(help), "bell") {
		t.Errorf("help does not document the bell key:\n%s", help)
	}
}

func TestBellRingsOnlyOnIncreaseWhenEnabled(t *testing.T) {
	var buf bytes.Buffer
	m := New(&fakeApprover{}, "prod").WithRequestPollInterval(time.Millisecond)
	m.bell = &buf
	m.bellOn = true
	m, _ = step(m, loadedMsg{serverOK: true, auditValid: true})

	// First observation establishes the baseline: no ring.
	m, cmd := step(m, pendingMsg{count: 2})
	if _, ok := cmd().(tea.BatchMsg); ok {
		t.Fatal("bell rang on the first observation")
	}

	// An increase rings (the batch carries the bell command alongside the tick).
	m, cmd = step(m, pendingMsg{count: 3})
	batch, ok := cmd().(tea.BatchMsg)
	if !ok || len(batch) != 2 {
		t.Fatalf("expected a batch with the tick and the bell, got %T", cmd())
	}
	for _, c := range batch {
		c()
	}
	if buf.String() != "\a" {
		t.Fatalf("bell output = %q, want BEL", buf.String())
	}

	// No increase, no ring.
	buf.Reset()
	m, cmd = step(m, pendingMsg{count: 3})
	if _, ok := cmd().(tea.BatchMsg); ok {
		t.Fatal("bell rang without an increase")
	}
}

func TestRequestsHeaderSaysAllNamespaces(t *testing.T) {
	f := &fakeApprover{reqs: twoRequests()}
	m := loadedModel(t, f)
	v := m.View()
	if !strings.Contains(v, "all namespaces") {
		t.Errorf("requests header does not say what is listed:\n%s", v)
	}
	if strings.Contains(v, "Namespace: prod") {
		t.Errorf("requests header still claims one namespace:\n%s", v)
	}
}
