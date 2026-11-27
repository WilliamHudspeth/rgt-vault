package tui

// The pending-requests view: the operator approves or denies agent requests
// that the server holds behind its approval gate (python tui.py "Requests"
// tab). A request flagged require_2fa asks for a TOTP code first. The view
// only ever sees request metadata (agent, secret name, namespace, purpose);
// no secret value and no token ever reaches it.

import (
	"errors"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ApprovalClient is the approval half of the server API. A Client that also
// implements it enables the requests view; HTTPClient does.
type ApprovalClient interface {
	ListRequests() ([]PendingRequest, error)
	// Approve approves a request; totpCode is "" unless the request needs 2FA.
	// A server refusal (bad/missing/replayed code, request gone) is ErrRejected.
	Approve(requestID, totpCode string) error
	Deny(requestID, reason string) error
}

// DefaultRequestPoll is how often the requests view refreshes (python: 2 s).
const DefaultRequestPoll = 2 * time.Second

// maxTOTPDigits bounds the TOTP entry (python: max_length=8).
const maxTOTPDigits = 8

type requestsLoadedMsg struct {
	gen  int
	reqs []PendingRequest
	err  error
}

type requestsTickMsg struct{ gen int }

type decisionMsg struct {
	approve bool
	err     error
}

func requestsTickCmd(gen int, d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return requestsTickMsg{gen: gen} })
}

func (m Model) loadRequestsCmd() tea.Cmd {
	gen, ap := m.reqGen, m.approver
	return func() tea.Msg {
		reqs, err := ap.ListRequests()
		return requestsLoadedMsg{gen: gen, reqs: reqs, err: err}
	}
}

func (m Model) decideCmd(target PendingRequest, approve bool, code string) tea.Cmd {
	ap := m.approver
	return func() tea.Msg {
		if approve {
			return decisionMsg{approve: true, err: ap.Approve(target.RequestID, code)}
		}
		return decisionMsg{err: ap.Deny(target.RequestID, "denied by operator")}
	}
}

// inRequests reports whether one of the requests-view modes is active.
func (m Model) inRequests() bool {
	return m.mode == modeRequests || m.mode == modeApproveConfirm || m.mode == modeTOTPPrompt
}

// enterRequests switches to the requests view and starts its refresh loop.
func (m Model) enterRequests() (Model, tea.Cmd) {
	if m.approver == nil {
		m.status = "approvals are not available with this client"
		return m, nil
	}
	m.mode = modeRequests
	m.status = ""
	m.reqGen++ // ticks of an earlier visit are now stale and stop themselves
	return m, tea.Batch(m.loadRequestsCmd(), requestsTickCmd(m.reqGen, m.requestPoll))
}

func (m Model) leaveRequests() Model {
	m.mode = modeDashboard
	m.status = ""
	m.target = nil
	m.totpInput = ""
	m.reqGen++
	return m
}

func (m Model) selectedRequest() (PendingRequest, bool) {
	if m.reqCursor < 0 || m.reqCursor >= len(m.requests) {
		return PendingRequest{}, false
	}
	return m.requests[m.reqCursor], true
}

func (m *Model) clampRequestCursor() {
	if m.reqCursor >= len(m.requests) {
		m.reqCursor = len(m.requests) - 1
	}
	if m.reqCursor < 0 {
		m.reqCursor = 0
	}
}

// updateRequestsMsg handles the non-key messages of the requests view.
func (m Model) updateRequestsMsg(msg tea.Msg) (Model, tea.Cmd, bool) {
	switch msg := msg.(type) {
	case requestsLoadedMsg:
		if msg.gen != m.reqGen || !m.inRequests() {
			return m, nil, true // a stale answer from an earlier visit
		}
		m.reqErr = msg.err
		if msg.err == nil {
			m.requests = msg.reqs
			m.clampRequestCursor()
		}
		return m, nil, true

	case requestsTickMsg:
		if msg.gen != m.reqGen || !m.inRequests() {
			return m, nil, true // stop this loop
		}
		return m, tea.Batch(m.loadRequestsCmd(), requestsTickCmd(m.reqGen, m.requestPoll)), true

	case decisionMsg:
		switch {
		case errors.Is(msg.err, ErrRejected) && msg.approve:
			m.status = "Rejected (bad/missing 2FA code, or the request is gone)."
		case errors.Is(msg.err, ErrRejected):
			m.status = "Deny rejected (the request is already decided or gone)."
		case msg.err != nil:
			m.status = "Decision failed: " + errText(msg.err)
		case msg.approve:
			m.status = "Approved."
		default:
			m.status = "Denied."
		}
		if m.approver == nil || !m.inRequests() {
			return m, nil, true
		}
		return m, m.loadRequestsCmd(), true
	}
	return m, nil, false
}

// updateRequestsKey handles keys in the three requests-view modes.
func (m Model) updateRequestsKey(msg tea.KeyMsg) (Model, tea.Cmd) {
	key := msg.String()
	if key == "ctrl+c" {
		return m, tea.Quit
	}
	switch m.mode {
	case modeRequests:
		switch key {
		case "q":
			return m, tea.Quit
		case "esc", "tab", "i":
			return m.leaveRequests(), nil
		case "up", "k":
			if m.reqCursor > 0 {
				m.reqCursor--
			}
		case "down", "j":
			if m.reqCursor < len(m.requests)-1 {
				m.reqCursor++
			}
		case "r":
			return m, m.loadRequestsCmd()
		case "a", "enter":
			req, ok := m.selectedRequest()
			if !ok {
				m.status = "No request selected."
				return m, nil
			}
			m.target = &req // the decision is about THIS request, even if the list moves
			m.status = ""
			if req.Require2FA {
				m.totpInput = ""
				m.mode = modeTOTPPrompt
			} else {
				m.mode = modeApproveConfirm
			}
		case "d":
			req, ok := m.selectedRequest()
			if !ok {
				m.status = "No request selected."
				return m, nil
			}
			m.status = "Denying..."
			return m, m.decideCmd(req, false, "")
		}

	case modeApproveConfirm:
		switch key {
		case "y":
			target := *m.target
			m.mode, m.target, m.status = modeRequests, nil, "Approving..."
			return m, m.decideCmd(target, true, "")
		case "n", "esc":
			m.mode, m.target = modeRequests, nil
			m.status = "Approval cancelled."
		}

	case modeTOTPPrompt:
		switch key {
		case "esc":
			m.mode, m.target, m.totpInput = modeRequests, nil, ""
			m.status = "Approval cancelled (no 2FA code)."
		case "backspace":
			if n := len(m.totpInput); n > 0 {
				m.totpInput = m.totpInput[:n-1]
			}
		case "enter":
			if m.totpInput == "" {
				m.status = "Enter the 2FA code, or esc to cancel."
				return m, nil
			}
			target, code := *m.target, m.totpInput
			m.mode, m.target, m.totpInput, m.status = modeRequests, nil, "", "Approving..."
			return m, m.decideCmd(target, true, code)
		default:
			// Digits only, bounded: a code can never grow without limit and
			// stray keys cannot trigger the dashboard's shortcuts.
			if len(key) == 1 && key[0] >= '0' && key[0] <= '9' && len(m.totpInput) < maxTOTPDigits {
				m.totpInput += key
			}
		}
	}
	return m, nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// viewRequests renders the requests view (all three modes).
func (m Model) viewRequests() string {
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	selectedStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))
	var sb strings.Builder
	sb.WriteString(headerStyle.Render("Pending approval requests - Namespace: "+safeText(m.namespace, maxFieldRunes)) + "\n\n")

	switch {
	case m.reqErr != nil:
		sb.WriteString("Could not reach daemon: " + errText(m.reqErr) + "\n\n")
	default:
		sb.WriteString(fmt.Sprintf("%d pending request(s)\n\n", len(m.requests)))
	}

	if len(m.requests) == 0 {
		sb.WriteString("  (no pending requests)\n")
	} else {
		sb.WriteString(fmt.Sprintf("  %-14s %-20s %-12s %-24s %-8s %s\n", "AGENT", "SECRET", "NAMESPACE", "PURPOSE", "ACTION", "2FA"))
		for i, r := range m.requests {
			line := fmt.Sprintf("%-14s %-20s %-12s %-24s %-8s %s",
				safeText(r.Agent, 14), safeText(r.SecretName, 20), safeText(r.Namespace, 12),
				safeText(r.Purpose, 24), safeText(r.Action, 8), yesNo(r.Require2FA))
			if i == m.reqCursor {
				sb.WriteString(selectedStyle.Render("> "+line) + "\n")
			} else {
				sb.WriteString("  " + line + "\n")
			}
		}
	}
	sb.WriteString("\n")

	switch m.mode {
	case modeApproveConfirm:
		if m.target != nil {
			sb.WriteString(fmt.Sprintf("Approve %s's request for %s/%s (purpose: %s)? (y/n)\n\n",
				safeText(m.target.Agent, maxFieldRunes), safeText(m.target.Namespace, maxFieldRunes),
				safeText(m.target.SecretName, maxNameRunes), safeText(m.target.Purpose, maxFieldRunes)))
		}
		sb.WriteString("[y] approve | [n/esc] cancel")
	case modeTOTPPrompt:
		if m.target != nil {
			sb.WriteString(fmt.Sprintf("2FA required to approve '%s' (%s, namespace %s)\n",
				safeText(m.target.SecretName, maxNameRunes), safeText(m.target.Agent, maxFieldRunes),
				safeText(m.target.Namespace, maxFieldRunes)))
		}
		// The code is masked: it is a live credential for one more window.
		sb.WriteString("2FA code: " + strings.Repeat("*", len(m.totpInput)) + "_\n\n")
		sb.WriteString("[enter] approve | [esc] cancel")
	default:
		sb.WriteString("[a] approve | [d] deny | [r] refresh | [tab] secrets | [q] quit")
	}
	if m.status != "" {
		sb.WriteString("\n\n" + safeText(m.status, 200))
	}
	return sb.String()
}
