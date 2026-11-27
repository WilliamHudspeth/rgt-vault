package tui

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"
)

// fakeApprover is a Client that can also approve/deny.
type fakeApprover struct {
	fakeClient
	mu         sync.Mutex
	reqs       []PendingRequest
	listErr    error
	approveErr error
	denyErr    error
	approved   [][2]string // {id, code}
	denied     []string
}

func (f *fakeApprover) ListRequests() ([]PendingRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]PendingRequest(nil), f.reqs...), nil
}

func (f *fakeApprover) remove(id string) {
	for i, r := range f.reqs {
		if r.RequestID == id {
			f.reqs = append(f.reqs[:i], f.reqs[i+1:]...)
			return
		}
	}
}

func (f *fakeApprover) Approve(id, code string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.approved = append(f.approved, [2]string{id, code})
	if f.approveErr == nil {
		f.remove(id)
	}
	return f.approveErr
}

func (f *fakeApprover) Deny(id, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denied = append(f.denied, id)
	if f.denyErr == nil {
		f.remove(id)
	}
	return f.denyErr
}

func (f *fakeApprover) approvals() [][2]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][2]string(nil), f.approved...)
}

func twoRequests() []PendingRequest {
	return []PendingRequest{
		{RequestID: "id-1", Agent: "bot-one", Namespace: "prod", SecretName: "plain-secret", Purpose: "deploy", Action: "read"},
		{RequestID: "id-2", Agent: "bot-two", Namespace: "prod", SecretName: "guarded", Purpose: "backup", Action: "read", Require2FA: true},
	}
}

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// step feeds one message to the model.
func step(m Model, msg tea.Msg) (Model, tea.Cmd) {
	nm, cmd := m.Update(msg)
	return nm.(Model), cmd
}

// runCmd executes a command that is not a timer and returns its message.
func runCmd(t *testing.T, cmd tea.Cmd) tea.Msg {
	t.Helper()
	if cmd == nil {
		t.Fatal("expected a command")
	}
	return cmd()
}

// loadedModel returns a model in the requests view with reqs loaded.
func loadedModel(t *testing.T, f *fakeApprover) Model {
	t.Helper()
	m := New(f, "prod")
	m, _ = step(m, loadedMsg{serverOK: true, auditValid: true})
	m, _ = step(m, key("tab"))
	if m.mode != modeRequests {
		t.Fatalf("mode = %v after tab", m.mode)
	}
	m, _ = step(m, requestsLoadedMsg{gen: m.reqGen, reqs: f.reqs})
	return m
}

func TestApprovalsUnavailableWithPlainClient(t *testing.T) {
	m := New(&fakeClient{}, "default")
	m, _ = step(m, loadedMsg{serverOK: true})
	m, cmd := step(m, key("tab"))
	if cmd != nil || m.mode != modeDashboard || !strings.Contains(m.status, "not available") {
		t.Fatalf("mode=%v status=%q cmd=%v", m.mode, m.status, cmd != nil)
	}
	if !strings.Contains(m.View(), "not available") {
		t.Error("status not rendered")
	}
}

func TestRequestsView_RendersColumnsAndCursor(t *testing.T) {
	f := &fakeApprover{reqs: twoRequests()}
	m := loadedModel(t, f)
	v := m.View()
	for _, want := range []string{"2 pending request(s)", "AGENT", "bot-one", "plain-secret", "guarded", "deploy", "ACTION", "2FA", "yes", "no", "[a] approve | [d] deny"} {
		if !strings.Contains(v, want) {
			t.Errorf("view lacks %q:\n%s", want, v)
		}
	}
	m, _ = step(m, key("j"))
	if m.reqCursor != 1 {
		t.Fatalf("cursor = %d", m.reqCursor)
	}
	m, _ = step(m, key("down")) // clamped
	if m.reqCursor != 1 {
		t.Fatalf("cursor past end = %d", m.reqCursor)
	}
	m, _ = step(m, key("k"))
	m, _ = step(m, key("up"))
	if m.reqCursor != 0 {
		t.Fatalf("cursor = %d", m.reqCursor)
	}
}

func TestRequestsView_EmptyAndError(t *testing.T) {
	f := &fakeApprover{}
	m := loadedModel(t, f)
	if v := m.View(); !strings.Contains(v, "0 pending request(s)") || !strings.Contains(v, "(no pending requests)") {
		t.Errorf("empty view:\n%s", v)
	}
	if _, cmd := step(m, key("a")); cmd != nil {
		t.Error("approve with nothing selected issued a command")
	}
	m2, _ := step(m, key("a"))
	if m2.status != "No request selected." || m2.mode != modeRequests {
		t.Errorf("status=%q mode=%v", m2.status, m2.mode)
	}
	m2, cmd := step(m, key("d"))
	if cmd != nil || m2.status != "No request selected." {
		t.Errorf("deny with nothing selected: %q", m2.status)
	}

	m, _ = step(m, requestsLoadedMsg{gen: m.reqGen, err: errors.New("dial tcp: boom\x1b[2J")})
	v := m.View()
	if !strings.Contains(v, "Could not reach daemon: dial tcp: boom") || strings.Contains(v, "\x1b[2J") {
		t.Errorf("error rendering:\n%q", v)
	}
	// A later successful load clears the error.
	m, _ = step(m, requestsLoadedMsg{gen: m.reqGen, reqs: twoRequests()})
	if strings.Contains(m.View(), "Could not reach") {
		t.Error("error not cleared")
	}
}

func TestApprove_WithoutTOTP_NeedsConfirmation(t *testing.T) {
	f := &fakeApprover{reqs: twoRequests()}
	m := loadedModel(t, f)
	m, cmd := step(m, key("a"))
	if m.mode != modeApproveConfirm || cmd != nil || len(f.approvals()) != 0 {
		t.Fatalf("mode=%v approvals=%v", m.mode, f.approvals())
	}
	if v := m.View(); !strings.Contains(v, "Approve bot-one's request for prod/plain-secret") || !strings.Contains(v, "(y/n)") {
		t.Errorf("confirm view:\n%s", v)
	}
	// n cancels without a call.
	m2, _ := step(m, key("n"))
	if m2.mode != modeRequests || m2.status != "Approval cancelled." || len(f.approvals()) != 0 {
		t.Fatalf("cancel: mode=%v status=%q", m2.mode, m2.status)
	}
	// y approves with no code.
	m, cmd = step(m, key("y"))
	if m.mode != modeRequests || m.target != nil {
		t.Fatalf("after y: mode=%v target=%v", m.mode, m.target)
	}
	msg := runCmd(t, cmd)
	if got := f.approvals(); len(got) != 1 || got[0] != [2]string{"id-1", ""} {
		t.Fatalf("approvals = %v", got)
	}
	m, cmd = step(m, msg)
	if m.status != "Approved." {
		t.Errorf("status = %q", m.status)
	}
	refreshed := runCmd(t, cmd) // reload after the decision
	m, _ = step(m, refreshed)
	if len(m.requests) != 1 || m.requests[0].RequestID != "id-2" {
		t.Errorf("requests after approval = %+v", m.requests)
	}
}

func TestApprove_2FA_PromptMaskedAndBounded(t *testing.T) {
	f := &fakeApprover{reqs: twoRequests()}
	m := loadedModel(t, f)
	m, _ = step(m, key("j"))
	m, _ = step(m, key("a"))
	if m.mode != modeTOTPPrompt {
		t.Fatalf("mode = %v", m.mode)
	}
	if v := m.View(); !strings.Contains(v, "2FA required to approve 'guarded'") || !strings.Contains(v, "2FA code: _") {
		t.Errorf("prompt view:\n%s", v)
	}
	// Letters and shortcuts are ignored; digits are bounded to 8.
	for _, k := range []string{"q", "a", "x", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0"} {
		m, _ = step(m, key(k))
	}
	if m.totpInput != "12345678" {
		t.Fatalf("input = %q", m.totpInput)
	}
	m, _ = step(m, key("backspace"))
	m, _ = step(m, key("backspace"))
	if m.totpInput != "123456" {
		t.Fatalf("after backspace = %q", m.totpInput)
	}
	v := m.View()
	if strings.Contains(v, "123456") || !strings.Contains(v, "2FA code: ******_") {
		t.Errorf("code must be masked:\n%s", v)
	}
	m, cmd := step(m, key("enter"))
	if m.totpInput != "" || m.mode != modeRequests || m.target != nil {
		t.Fatalf("input not cleared: %q mode=%v", m.totpInput, m.mode)
	}
	msg := runCmd(t, cmd)
	if got := f.approvals(); len(got) != 1 || got[0] != [2]string{"id-2", "123456"} {
		t.Fatalf("approvals = %v", got)
	}
	m, _ = step(m, msg)
	if m.status != "Approved." {
		t.Errorf("status = %q", m.status)
	}
}

func TestApprove_2FA_EmptyCancelAndRejected(t *testing.T) {
	f := &fakeApprover{reqs: twoRequests(), approveErr: ErrRejected}
	m := loadedModel(t, f)
	m, _ = step(m, key("j"))
	m, _ = step(m, key("a"))
	m, cmd := step(m, key("enter")) // no digits
	if cmd != nil || m.mode != modeTOTPPrompt || !strings.Contains(m.status, "Enter the 2FA code") {
		t.Fatalf("empty submit: mode=%v status=%q", m.mode, m.status)
	}
	m, _ = step(m, key("esc"))
	if m.mode != modeRequests || m.totpInput != "" || m.target != nil || !strings.Contains(m.status, "cancelled") || len(f.approvals()) != 0 {
		t.Fatalf("cancel: mode=%v input=%q status=%q", m.mode, m.totpInput, m.status)
	}
	// Server rejects a wrong code.
	m, _ = step(m, key("a"))
	for _, k := range "000000" {
		m, _ = step(m, key(string(k)))
	}
	m, cmd = step(m, key("enter"))
	m, _ = step(m, runCmd(t, cmd))
	if !strings.HasPrefix(m.status, "Rejected (bad/missing 2FA code") || strings.Contains(m.View(), "000000") {
		t.Errorf("status = %q", m.status)
	}
}

func TestApprove_TargetIsPinnedWhileListMoves(t *testing.T) {
	f := &fakeApprover{reqs: twoRequests()}
	m := loadedModel(t, f)
	m, _ = step(m, key("a")) // confirm for id-1
	// id-1 is decided elsewhere and a new request takes the top row.
	m, _ = step(m, requestsLoadedMsg{gen: m.reqGen, reqs: []PendingRequest{
		{RequestID: "id-9", Agent: "evil", SecretName: "other"}, twoRequests()[1],
	}})
	m, cmd := step(m, key("y"))
	runCmd(t, cmd)
	if got := f.approvals(); len(got) != 1 || got[0][0] != "id-1" {
		t.Fatalf("approved %v, want the request shown when the prompt opened (id-1)", got)
	}
	_ = m
}

func TestDeny_Flow(t *testing.T) {
	f := &fakeApprover{reqs: twoRequests()}
	m := loadedModel(t, f)
	m, _ = step(m, key("j"))
	m, cmd := step(m, key("d"))
	if m.status != "Denying..." {
		t.Errorf("status = %q", m.status)
	}
	m, _ = step(m, runCmd(t, cmd))
	if len(f.denied) != 1 || f.denied[0] != "id-2" || m.status != "Denied." {
		t.Fatalf("denied=%v status=%q", f.denied, m.status)
	}

	f.denyErr = ErrRejected
	m, cmd = step(m, key("d"))
	m, _ = step(m, runCmd(t, cmd))
	if !strings.HasPrefix(m.status, "Deny rejected") {
		t.Errorf("status = %q", m.status)
	}
	f.denyErr = errors.New("list requests: HTTP 500 Internal Server Error")
	m, cmd = step(m, key("d"))
	m, _ = step(m, runCmd(t, cmd))
	if m.status != "Decision failed: list requests: HTTP 500 Internal Server Error" {
		t.Errorf("status = %q", m.status)
	}
}

func TestDecisionFailure_NeverRendersTokenOrCode(t *testing.T) {
	f := &fakeApprover{reqs: twoRequests()}
	f.approveErr = &StatusError{Op: "approve", Code: 401}
	m := loadedModel(t, f)
	m, _ = step(m, key("j"))
	m, _ = step(m, key("a"))
	for _, k := range "424242" {
		m, _ = step(m, key(string(k)))
	}
	m, cmd := step(m, key("enter"))
	m, _ = step(m, runCmd(t, cmd))
	v := m.View()
	if !strings.Contains(v, "Decision failed: approve: HTTP 401 Unauthorized") {
		t.Errorf("view:\n%s", v)
	}
	if strings.Contains(v, "424242") {
		t.Error("TOTP code rendered")
	}
}

func TestRequestsLoop_StaleMessagesAndLeaving(t *testing.T) {
	f := &fakeApprover{reqs: twoRequests()}
	m := New(f, "prod").WithRequestPollInterval(time.Millisecond)
	m, _ = step(m, loadedMsg{serverOK: true})
	m, cmd := step(m, key("i"))
	if cmd == nil || m.reqGen != 1 {
		t.Fatalf("enter: gen=%d", m.reqGen)
	}
	// A tick of the current generation re-arms; a stale one stops.
	if _, c := step(m, requestsTickMsg{gen: m.reqGen}); c == nil {
		t.Error("current tick did not continue")
	}
	if _, c := step(m, requestsTickMsg{gen: m.reqGen - 1}); c != nil {
		t.Error("stale tick continued")
	}
	// Leaving (tab) bumps the generation: the old loop and answers are dropped.
	oldGen := m.reqGen
	m2, _ := step(m, key("tab"))
	if m2.mode != modeDashboard || m2.reqGen == oldGen {
		t.Fatalf("leave: mode=%v gen=%d", m2.mode, m2.reqGen)
	}
	if _, c := step(m2, requestsTickMsg{gen: oldGen}); c != nil {
		t.Error("tick after leaving continued")
	}
	m3, _ := step(m2, requestsLoadedMsg{gen: oldGen, reqs: twoRequests()})
	if len(m3.requests) != 0 {
		t.Error("stale load applied")
	}
	// Re-entering starts a fresh generation.
	m4, _ := step(m2, key("tab"))
	if m4.reqGen != m2.reqGen+1 {
		t.Errorf("re-enter gen = %d", m4.reqGen)
	}
	// A decision result after leaving does not reload.
	if _, c := step(m2, decisionMsg{approve: true}); c != nil {
		t.Error("decision while on the dashboard reloaded")
	}
	// Esc also leaves; quit keys work.
	m5, _ := step(m4, key("esc"))
	if m5.mode != modeDashboard {
		t.Error("esc did not leave")
	}
	if _, c := step(m4, key("q")); c == nil {
		t.Error("q did not quit")
	}
	m6, _ := step(m4, key("r"))
	if _, c := step(m6, key("ctrl+c")); c == nil {
		t.Error("ctrl+c did not quit")
	}
	if _, c := step(m4, key("r")); c == nil {
		t.Error("r did not refresh")
	}
	// ctrl+c quits even inside the TOTP prompt.
	mp := loadedModel(t, &fakeApprover{reqs: twoRequests()})
	mp, _ = step(mp, key("j"))
	mp, _ = step(mp, key("a"))
	if _, c := step(mp, key("ctrl+c")); c == nil {
		t.Error("ctrl+c did not quit from the prompt")
	}
}

func TestRequestsView_EscapeSequencesAreNeutralised(t *testing.T) {
	evil := "\x1b[31mEVIL\x1b[2J\u202e\u2028x\r\ny"
	f := &fakeApprover{reqs: []PendingRequest{{RequestID: "e", Agent: evil, Namespace: evil, SecretName: evil, Purpose: evil, Action: evil, Require2FA: true}}}
	m := loadedModel(t, f)
	m, _ = step(m, key("a"))
	for _, v := range []string{m.View()} {
		for _, bad := range []string{"\x1b", "\u202e", "\u2028", "\r"} {
			if strings.Contains(v, bad) {
				t.Errorf("view contains %q:\n%q", bad, v)
			}
		}
	}
	// Secrets list and audit stream too.
	d := New(&fakeClient{}, "ns\x1b[2J")
	d, _ = step(d, loadedMsg{serverOK: true, secrets: []SecretInfo{{Name: evil, Fingerprint: evil, Note: evil}}, err: errors.New(evil)})
	d, _ = step(d, tea.WindowSizeMsg{Width: 100, Height: 30})
	if v := d.View(); strings.Contains(v, "\x1b") || strings.Contains(v, "\u202e") {
		t.Errorf("dashboard view contains control sequences: %q", v)
	}
	d, _ = step(d, key("a"))
	d, _ = step(d, auditLoadMsg{entries: []AuditEntry{{Timestamp: evil, Event: evil, Principal: evil, Detail: evil}}})
	if v := d.View(); strings.Contains(v, "\x1b") {
		t.Errorf("audit view contains ESC: %q", v)
	}
}

func TestSafeTextAndErrText(t *testing.T) {
	if got := safeText("a\x00b\x7fc\u0085d\xffe", 50); got != "a?b?c?d?e" {
		t.Errorf("safeText = %q", got)
	}
	if got := safeText("héllo wörld", 5); got != "héllo…" {
		t.Errorf("truncation = %q", got)
	}
	if got := errText(nil); got != "" {
		t.Errorf("errText(nil) = %q", got)
	}
	if got := errText(errors.New(strings.Repeat("x", 500))); len([]rune(got)) != maxErrorRunes+1 {
		t.Errorf("errText length = %d", len([]rune(got)))
	}
}

func TestDashboardShowsNoteAnd2FAColumns(t *testing.T) {
	m := New(&fakeClient{}, "default")
	m, _ = step(m, loadedMsg{serverOK: true, auditValid: true, secrets: []SecretInfo{
		{Name: "plain", Fingerprint: "11111111", Note: "just a note"},
		{Name: "guarded", Fingerprint: "22222222", Require2FA: true, Note: "needs 2fa"},
		{Name: "nofp"},
	}})
	v := m.View()
	for _, want := range []string{"NAME", "FINGERPRINT", "2FA", "NOTE", "11111111", "just a note", "22222222", "needs 2fa", "yes", "no"} {
		if !strings.Contains(v, want) {
			t.Errorf("dashboard lacks %q:\n%s", want, v)
		}
	}
	if !strings.Contains(v, "nofp") || !strings.Contains(v, "-  ") {
		t.Errorf("missing fingerprint should render '-':\n%s", v)
	}
	// Distinct fingerprints are shown per secret, never one shared value.
	if strings.Count(v, "11111111") != 1 || strings.Count(v, "22222222") != 1 {
		t.Errorf("fingerprints:\n%s", v)
	}
}

func TestDashboardShowsLoadError(t *testing.T) {
	m := New(&fakeClient{}, "default")
	m, _ = step(m, loadedMsg{err: errors.New("list secrets: HTTP 403 Forbidden")})
	if v := m.View(); !strings.Contains(v, "error: list secrets: HTTP 403 Forbidden") {
		t.Errorf("view:\n%s", v)
	}
}

func TestHelpMentionsRequests(t *testing.T) {
	m := New(&fakeClient{}, "default")
	m, _ = step(m, loadedMsg{serverOK: true})
	m, _ = step(m, key("?"))
	if !strings.Contains(m.View(), "Pending approval requests") {
		t.Error("help lacks the requests key")
	}
}

// --- teatest end-to-end flows ------------------------------------------------

func waitFor(t *testing.T, tm *teatest.TestModel, cond func(string) bool) {
	t.Helper()
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool { return cond(string(b)) },
		teatest.WithDuration(5*time.Second), teatest.WithCheckInterval(20*time.Millisecond))
}

func typeKeys(tm *teatest.TestModel, s string) {
	for _, r := range s {
		tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}

func TestTeatest_ApprovalFlow_TwoFactor(t *testing.T) {
	f := &fakeApprover{reqs: twoRequests()}
	tm := teatest.NewTestModel(t, New(f, "prod").WithRequestPollInterval(20*time.Millisecond), teatest.WithInitialTermSize(120, 30))
	waitFor(t, tm, func(s string) bool { return strings.Contains(s, "online") })
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	waitFor(t, tm, func(s string) bool { return strings.Contains(s, "guarded") && strings.Contains(s, "bot-two") })

	tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	waitFor(t, tm, func(s string) bool { return strings.Contains(s, "2FA required to approve 'guarded'") })
	typeKeys(tm, "987654")
	waitFor(t, tm, func(s string) bool { return strings.Contains(s, "******_") })
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor(t, tm, func(s string) bool { return strings.Contains(s, "Approved.") })
	if got := f.approvals(); len(got) != 1 || got[0] != [2]string{"id-2", "987654"} {
		t.Fatalf("approvals = %v", got)
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	final := tm.FinalModel(t, teatest.WithFinalTimeout(3*time.Second)).(Model)
	if final.totpInput != "" {
		t.Error("TOTP digits kept after submit")
	}
	if strings.Contains(final.View(), "987654") {
		t.Error("TOTP code rendered")
	}
}

func TestTeatest_ApprovalFlow_DenyAndPolling(t *testing.T) {
	f := &fakeApprover{reqs: twoRequests()[:1]}
	tm := teatest.NewTestModel(t, New(f, "prod").WithRequestPollInterval(20*time.Millisecond), teatest.WithInitialTermSize(120, 30))
	waitFor(t, tm, func(s string) bool { return strings.Contains(s, "online") })
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	waitFor(t, tm, func(s string) bool { return strings.Contains(s, "plain-secret") })

	// A new request arrives while the view is open: the poll picks it up.
	f.mu.Lock()
	f.reqs = append(f.reqs, PendingRequest{RequestID: "id-late", Agent: "late-agent", Namespace: "prod", SecretName: "arrived", Purpose: "p", Action: "read"})
	f.mu.Unlock()
	waitFor(t, tm, func(s string) bool { return strings.Contains(s, "arrived") })

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	waitFor(t, tm, func(s string) bool { return strings.Contains(s, "Denied.") })
	f.mu.Lock()
	denied := append([]string(nil), f.denied...)
	f.mu.Unlock()
	if len(denied) != 1 || denied[0] != "id-1" {
		t.Fatalf("denied = %v", denied)
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestTeatest_ListErrorRendered(t *testing.T) {
	f := &fakeApprover{listErr: errors.New("connection refused"), reqs: nil}
	tm := teatest.NewTestModel(t, New(f, "prod").WithRequestPollInterval(20*time.Millisecond), teatest.WithInitialTermSize(120, 30))
	waitFor(t, tm, func(s string) bool { return strings.Contains(s, "online") })
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	waitFor(t, tm, func(s string) bool { return strings.Contains(s, "Could not reach daemon: connection refused") })
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}
