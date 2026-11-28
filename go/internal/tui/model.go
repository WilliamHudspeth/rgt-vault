// Package tui provides a Bubble Tea TUI dashboard for rgt-vault.
// This implementation addresses tickets RGT-158 and RGT-160.
package tui

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// SecretInfo stores metadata about a secret. It has no field for a value: the
// TUI never receives or holds one.
type SecretInfo struct {
	Name        string
	Fingerprint string // sha256(ciphertext)[:8] from the server; "" if unavailable
	Note        string // free-text note (the server's "note" metadata)
	Require2FA  bool   // leasing this secret needs a TOTP second factor
	Type        string // optional server-supplied kind, e.g. "totp"
}

// Client is implemented elsewhere in the package (an HTTP client).
type Client interface {
	Health() bool
	VerifyAudit() bool
	ListSecrets(namespace string) ([]SecretInfo, error)
	Rotate(target string) error
	GetAuditLog(limit int) ([]AuditEntry, error)
}

type loadedMsg struct {
	serverOK   bool
	auditValid bool
	secrets    []SecretInfo
	err        error
}

type rotatedMsg struct {
	err error
}

// totpTickMsg is emitted once per second to update the TOTP countdown.
type totpTickMsg time.Time

// clipboardClearMsg is emitted when the clipboard auto-clear timer fires.
type clipboardClearMsg struct{}

type mode int

const (
	modeDashboard mode = iota
	modeHelp
	modeSearch
	modeConfirm
	modeAudit
	modeRequests       // pending approval requests (approve / deny)
	modeApproveConfirm // y/n before approving a request without 2FA
	modeTOTPPrompt     // TOTP entry before approving a require_2fa request
)

// Model holds the TUI state.
type Model struct {
	client        Client
	namespace     string
	secrets       []SecretInfo // full set
	filtered      []SecretInfo // after search filter
	cursor        int
	serverOK      bool
	auditValid    bool
	loaded        bool
	mode          mode
	search        string
	status        string // last action status line
	err           error
	width, height int

	// RGT-160: TOTP countdown
	showTOTP      bool
	totpRemaining int

	// RGT-160: namespace tree view
	treeView bool

	// RGT-160: clipboard auto-clear.
	// We copy the FINGERPRINT, not plaintext — the TUI never holds the secret value.
	clipboard        Clipboard
	clipboardTimeout time.Duration

	// RGT-41: Live Audit Log Streamer
	auditEntries []AuditEntry

	// RGT-160/497: pending approval requests (operator view).
	approver    ApprovalClient // nil when the client cannot approve
	requests    []PendingRequest
	reqCursor   int
	reqErr      error
	reqGen      int           // bumped on every enter/leave; stale loads and ticks are dropped
	requestPoll time.Duration // refresh interval of the requests view
	target      *PendingRequest
	totpInput   string // digits typed so far; masked in the view, cleared on submit

	// RGT-528: dashboard pending-request badge and optional bell.
	pending      int       // last observed number of pending requests
	pendingKnown bool      // a poll has answered at least once
	bellOn       bool      // off by default; "b" toggles it
	bell         io.Writer // where the terminal bell goes (os.Stdout by default)
}

// pendingMsg carries the number of pending requests for the dashboard badge.
// A negative count means the poll failed; the last known count is kept.
type pendingMsg struct{ count int }

// pendingTickMsg asks for another pending-requests poll.
type pendingTickMsg struct{}

func pendingTickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return pendingTickMsg{} })
}

func (m Model) loadPendingCmd() tea.Cmd {
	ap := m.approver
	if ap == nil {
		return nil
	}
	return func() tea.Msg {
		reqs, err := ap.ListRequests()
		if err != nil {
			return pendingMsg{count: -1}
		}
		return pendingMsg{count: len(reqs)}
	}
}

func bellCmd(w io.Writer) tea.Cmd {
	return func() tea.Msg {
		if w != nil {
			_, _ = io.WriteString(w, "\a")
		}
		return nil
	}
}

// totpTickCmd arms a one-second tick that emits totpTickMsg.

type auditTickMsg time.Time

type auditLoadMsg struct {
	entries []AuditEntry
	err     error
}

func auditTickCmd() tea.Cmd {
	return tea.Tick(time.Second*2, func(t time.Time) tea.Msg {
		return auditTickMsg(t)
	})
}

func (m Model) loadAuditCmd() tea.Cmd {
	return func() tea.Msg {
		entries, err := m.client.GetAuditLog(100)
		return auditLoadMsg{entries: entries, err: err}
	}
}

func totpTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return totpTickMsg(t)
	})
}

// New constructs a new TUI Model.
func New(client Client, namespace string) Model {
	approver, _ := client.(ApprovalClient)
	return Model{
		client:           client,
		approver:         approver,
		requestPoll:      DefaultRequestPoll,
		namespace:        namespace,
		mode:             modeDashboard,
		showTOTP:         true,
		totpRemaining:    TOTPRemaining(time.Now(), TOTPPeriod),
		clipboard:        &MemoryClipboard{},
		clipboardTimeout: 30 * time.Second,
		bell:             os.Stdout,
	}
}

// NewWithClipboard is a test seam that constructs a Model with a custom Clipboard
// so tests can inject a *MemoryClipboard and observe its contents.
func NewWithClipboard(client Client, namespace string, clip Clipboard) Model {
	m := New(client, namespace)
	m.clipboard = clip
	return m
}

// WithRequestPollInterval sets how often the requests view refreshes (test
// seam; the default is DefaultRequestPoll).
func (m Model) WithRequestPollInterval(d time.Duration) Model {
	if d > 0 {
		m.requestPoll = d
	}
	return m
}

// Init initializes the Model by triggering the loading command and starting the
// TOTP tick.
func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{m.loadCmd(), totpTickCmd()}
	if m.approver != nil {
		cmds = append(cmds, m.loadPendingCmd(), pendingTickCmd(m.requestPoll))
	}
	return tea.Batch(cmds...)
}

func (m Model) loadCmd() tea.Cmd {
	return func() tea.Msg {
		ok := m.client.Health()
		valid := m.client.VerifyAudit()
		secrets, err := m.client.ListSecrets(m.namespace)
		return loadedMsg{
			serverOK:   ok,
			auditValid: valid,
			secrets:    secrets,
			err:        err,
		}
	}
}

func (m Model) rotateCmd() tea.Cmd {
	return func() tea.Msg {
		return rotatedMsg{err: m.client.Rotate("master")}
	}
}

// Update processes incoming messages and updates the Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case loadedMsg:
		m.serverOK = msg.serverOK
		m.auditValid = msg.auditValid
		m.secrets = msg.secrets
		m.err = msg.err
		m.loaded = true
		m.applyFilter()
		return m, nil

	case rotatedMsg:
		if msg.err != nil {
			m.status = "rotate failed: " + errText(msg.err)
		} else {
			m.status = "rotate complete"
		}
		return m, m.loadCmd()

	case totpTickMsg:
		// Re-compute the remaining seconds and re-arm the ticker.
		m.totpRemaining = TOTPRemaining(time.Now(), TOTPPeriod)
		return m, totpTickCmd()

	case clipboardClearMsg:
		// Auto-clear fires: wipe clipboard and update status.
		_ = m.clipboard.Clear()
		m.status = "clipboard cleared"
		return m, nil

	case auditTickMsg:
		if m.mode == modeAudit {
			return m, tea.Batch(m.loadAuditCmd(), auditTickCmd())
		}
		return m, nil

	case auditLoadMsg:
		m.auditEntries = msg.entries
		if msg.err != nil {
			m.status = "audit error: " + errText(msg.err)
		}
		return m, nil

	case requestsLoadedMsg, requestsTickMsg, decisionMsg:
		nm, cmd, _ := m.updateRequestsMsg(msg)
		return nm, cmd

	case pendingMsg:
		if msg.count < 0 {
			// Poll failed: keep the last known badge and try again next tick.
			return m, pendingTickCmd(m.requestPoll)
		}
		ring := m.bellOn && m.pendingKnown && msg.count > m.pending
		m.pending = msg.count
		m.pendingKnown = true
		if ring {
			return m, tea.Batch(pendingTickCmd(m.requestPoll), bellCmd(m.bell))
		}
		return m, pendingTickCmd(m.requestPoll)

	case pendingTickMsg:
		if m.approver == nil {
			return m, nil
		}
		return m, m.loadPendingCmd()

	case tea.KeyMsg:
		if m.inRequests() {
			return m.updateRequestsKey(msg)
		}
		switch m.mode {
		case modeDashboard:
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "?":
				m.mode = modeHelp
			case "/":
				m.mode = modeSearch
				m.search = ""
				m.applyFilter()
			case "r":
				m.mode = modeConfirm
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				}
			case "down", "j":
				if m.cursor < len(m.filtered)-1 {
					m.cursor++
				}
			case "P":
				// Clears the local view and quits; the server keeps running.
				m.secrets = nil
				m.filtered = nil
				m.search = ""
				m.status = "screen cleared; quitting"
				return m, tea.Quit

			case "b":
				m.bellOn = !m.bellOn
				if m.bellOn {
					m.status = "bell on: rings when new requests arrive"
				} else {
					m.status = "bell off"
				}

			case "tab", "i":
				return m.enterRequests()
			case "a":
				m.mode = modeAudit
				m.status = "streaming audit log..."
				return m, tea.Batch(m.loadAuditCmd(), auditTickCmd())
			case "t":
				// Toggle the namespace tree view.
				m.treeView = !m.treeView

			case "c":
				// Copy selected secret's FINGERPRINT to clipboard.
				// We copy the fingerprint only — the TUI never holds the plaintext secret value.
				if len(m.filtered) > 0 {
					selected := m.filtered[m.cursor]
					_ = m.clipboard.Write(selected.Fingerprint)
					m.status = "copied fingerprint (clears in 30s)"
					if m.clipboardTimeout > 0 {
						return m, tea.Tick(m.clipboardTimeout, func(time.Time) tea.Msg {
							return clipboardClearMsg{}
						})
					}
				}
			}

		case modeAudit:
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "esc", "a":
				m.mode = modeDashboard
				m.status = ""
				return m, nil
			}

		case modeHelp:
			m.mode = modeDashboard

		case modeSearch:
			switch msg.String() {
			case "esc":
				m.mode = modeDashboard
				m.search = ""
				m.applyFilter()
			case "enter":
				m.mode = modeDashboard
			case "backspace":
				runes := []rune(m.search)
				if len(runes) > 0 {
					m.search = string(runes[:len(runes)-1])
				}
				m.applyFilter()
			default:
				if len(msg.String()) == 1 {
					m.search += msg.String()
					m.applyFilter()
				}
			}

		case modeConfirm:
			switch msg.String() {
			case "y":
				m.mode = modeDashboard
				return m, m.rotateCmd()
			case "n", "esc":
				m.mode = modeDashboard
				m.status = "rotate cancelled"
			}
		}
	}

	return m, nil
}

func (m *Model) applyFilter() {
	if m.search == "" {
		m.filtered = make([]SecretInfo, len(m.secrets))
		copy(m.filtered, m.secrets)
	} else {
		m.filtered = nil
		searchLower := strings.ToLower(m.search)
		for _, s := range m.secrets {
			if strings.Contains(strings.ToLower(s.Name), searchLower) {
				m.filtered = append(m.filtered, s)
			}
		}
	}

	sort.Slice(m.filtered, func(i, j int) bool {
		return m.filtered[i].Name < m.filtered[j].Name
	})

	if len(m.filtered) == 0 {
		m.cursor = 0
	} else {
		if m.cursor < 0 {
			m.cursor = 0
		}
		if m.cursor >= len(m.filtered) {
			m.cursor = len(m.filtered) - 1
		}
	}
}

// totpSuffix returns the TOTP countdown string for a secret, or "" if not applicable.
func (m Model) totpSuffix(secret SecretInfo) string {
	if m.showTOTP && IsTOTP(secret) {
		return fmt.Sprintf(" (TOTP %ds)", m.totpRemaining)
	}
	return ""
}

// View renders the TUI layout.
func (m Model) View() string {
	if !m.loaded {
		return "Loading rgt-vault dashboard...\n"
	}

	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	selectedStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))
	normalStyle := lipgloss.NewStyle()

	if m.mode == modeHelp {
		var sb strings.Builder
		sb.WriteString("RGT-Vault Dashboard Help\n")
		sb.WriteString("========================\n\n")
		sb.WriteString("  /        Search secrets\n")
		sb.WriteString("  r        Rotate master key\n")
		sb.WriteString("  P        Clear screen & quit\n")
		sb.WriteString("  b        Toggle terminal bell on new requests (off by default)\n")
		sb.WriteString("  t        Toggle tree view\n")
		sb.WriteString("  a        Live audit log stream\n")
		sb.WriteString("  tab/i    Pending approval requests (approve/deny)\n")
		sb.WriteString("  c        Copy fingerprint to clipboard\n")
		sb.WriteString("  ?        Show help\n")
		sb.WriteString("  q/ctrl+c Quit\n")
		sb.WriteString("  up/k     Move cursor up\n")
		sb.WriteString("  down/j   Move cursor down\n\n")
		sb.WriteString("Press any key to return...\n")
		return sb.String()
	}

	if m.mode == modeAudit {
		var sb strings.Builder
		sb.WriteString(headerStyle.Render("Live Audit Log Stream") + "\n\n")
		if len(m.auditEntries) == 0 {
			sb.WriteString("  (no audit entries)\n")
		} else {
			displayCount := m.height - 10
			if displayCount < 5 {
				displayCount = 5
			}
			start := len(m.auditEntries) - displayCount
			if start < 0 {
				start = 0
			}
			for _, entry := range m.auditEntries[start:] {
				// Trim long details
				detail := safeText(entry.Detail, maxDetailRunes)
				// Format: HH:MM:SS | EVENT | PRINCIPAL | DETAIL
				tStr := safeText(entry.Timestamp, 32)
				if len(tStr) >= 19 {
					tStr = tStr[11:19] // Extract HH:MM:SS from RFC3339
				}
				line := fmt.Sprintf("%-8s | %-15s | %-10s | %s", tStr, safeText(entry.Event, 15), safeText(entry.Principal, 10), detail)
				sb.WriteString(normalStyle.Render(line) + "\n")
			}
		}
		sb.WriteString("\n[a/esc] back | [q] quit\n")
		if m.status != "" {
			sb.WriteString("\n" + safeText(m.status, 200))
		}
		return sb.String()
	}

	if m.inRequests() {
		return m.viewRequests()
	}

	var sb strings.Builder

	healthStr := "○ offline"
	if m.serverOK {
		healthStr = "● online"
	}
	auditStr := "audit: INVALID"
	if m.auditValid {
		auditStr = "audit: OK"
	}
	headerText := fmt.Sprintf("[%s] [%s] Namespace: %s", healthStr, auditStr, safeText(m.namespace, maxFieldRunes))
	if m.approver != nil {
		headerText = fmt.Sprintf("[%s] [%s] requests: %d Namespace: %s",
			healthStr, auditStr, m.pending, safeText(m.namespace, maxFieldRunes))
	}
	sb.WriteString(headerStyle.Render(headerText) + "\n\n")

	if m.err != nil {
		sb.WriteString("  error: " + errText(m.err) + "\n\n")
	}

	if m.mode == modeSearch {
		sb.WriteString(fmt.Sprintf("/%s\n\n", safeText(m.search, maxFieldRunes)))
	}

	if len(m.filtered) == 0 {
		sb.WriteString("  (no secrets)\n")
	} else if m.treeView {
		// Tree view: render BuildTree output as indented rows.
		// Cursor selection stays indexed over m.filtered (flat); tree is for visual navigation.
		rows := BuildTree(m.filtered)
		for _, row := range rows {
			indent := strings.Repeat("  ", row.Indent)
			if row.IsLeaf && row.Secret != nil {
				suffix := m.totpSuffix(*row.Secret)
				line := fmt.Sprintf("%s%s  %s%s", indent, safeText(row.Label, maxNameRunes), secretColumns(*row.Secret), suffix)
				sb.WriteString(normalStyle.Render(line) + "\n")
			} else {
				sb.WriteString(normalStyle.Render(indent+safeText(row.Label, maxNameRunes)) + "\n")
			}
		}
	} else {
		// Flat list view: NAME FINGERPRINT 2FA NOTE.
		sb.WriteString(normalStyle.Render(fmt.Sprintf("  %-20s  %-11s  %-3s  %s", "NAME", "FINGERPRINT", "2FA", "NOTE")) + "\n")
		for i, secret := range m.filtered {
			suffix := m.totpSuffix(secret)
			line := fmt.Sprintf("%-20s  %s%s", safeText(secret.Name, maxNameRunes), secretColumns(secret), suffix)
			if i == m.cursor {
				sb.WriteString(selectedStyle.Render("> "+line) + "\n")
			} else {
				sb.WriteString(normalStyle.Render("  "+line) + "\n")
			}
		}
	}

	sb.WriteString("\n")

	if m.mode == modeConfirm {
		sb.WriteString("Rotate master key? (y/n)\n\n")
	}

	var footerParts []string
	if m.mode == modeDashboard {
		footerParts = append(footerParts, "[/] search", "[r] rotate", "[a] audit", "[P] clear screen & quit", "[t] tree", "[c] copy", "[b] bell", "[tab] requests", "[?] help", "[q] quit")
	} else if m.mode == modeSearch {
		footerParts = append(footerParts, "[esc] cancel search", "[enter] keep filter")
	} else if m.mode == modeConfirm {
		footerParts = append(footerParts, "[y] confirm rotate", "[n/esc] cancel")
	}
	sb.WriteString(strings.Join(footerParts, " | "))

	if m.status != "" {
		sb.WriteString("\n\n" + safeText(m.status, 200))
	}

	return sb.String()
}

// secretColumns renders the metadata columns of a secret row: fingerprint,
// 2FA flag and note. Every server-supplied field is made terminal-safe.
func secretColumns(s SecretInfo) string {
	fp := safeText(s.Fingerprint, 16)
	if fp == "" {
		fp = "-"
	}
	line := fmt.Sprintf("%-11s  %-3s", fp, yesNo(s.Require2FA))
	if note := safeText(s.Note, maxNoteRunes); note != "" {
		line += "  " + note
	}
	return line
}
