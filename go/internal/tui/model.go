// Package tui provides a Bubble Tea TUI dashboard for rgt-vault.
// This implementation addresses tickets RGT-158 and RGT-160.
package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// SecretInfo stores metadata about a secret.
type SecretInfo struct {
	Name        string
	Fingerprint string // short hash; NEVER the plaintext value
}

// Client is implemented elsewhere in the package (an HTTP client).
type Client interface {
	Health() bool
	VerifyAudit() bool
	ListSecrets(namespace string) ([]SecretInfo, error)
	Rotate(target string) error
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
)

// Model holds the TUI state.
type Model struct {
	client    Client
	namespace string
	secrets   []SecretInfo // full set
	filtered  []SecretInfo // after search filter
	cursor    int
	serverOK  bool
	auditValid bool
	loaded     bool
	mode       mode
	search     string
	status     string // last action status line
	err        error
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
}

// totpTickCmd arms a one-second tick that emits totpTickMsg.
func totpTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return totpTickMsg(t)
	})
}

// New constructs a new TUI Model.
func New(client Client, namespace string) Model {
	return Model{
		client:           client,
		namespace:        namespace,
		mode:             modeDashboard,
		showTOTP:         true,
		totpRemaining:    TOTPRemaining(time.Now(), TOTPPeriod),
		clipboard:        &MemoryClipboard{},
		clipboardTimeout: 30 * time.Second,
	}
}

// NewWithClipboard is a test seam that constructs a Model with a custom Clipboard
// so tests can inject a *MemoryClipboard and observe its contents.
func NewWithClipboard(client Client, namespace string, clip Clipboard) Model {
	m := New(client, namespace)
	m.clipboard = clip
	return m
}

// Init initializes the Model by triggering the loading command and starting the
// TOTP tick.
func (m Model) Init() tea.Cmd {
	return tea.Batch(m.loadCmd(), totpTickCmd())
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
			m.status = "rotate failed: " + msg.err.Error()
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

	case tea.KeyMsg:
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
				m.secrets = nil
				m.filtered = nil
				m.search = ""
				m.status = "vault locked"
				return m, tea.Quit

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
		sb.WriteString("  P        Panic lock & exit\n")
		sb.WriteString("  t        Toggle tree view\n")
		sb.WriteString("  c        Copy fingerprint to clipboard\n")
		sb.WriteString("  ?        Show help\n")
		sb.WriteString("  q/ctrl+c Quit\n")
		sb.WriteString("  up/k     Move cursor up\n")
		sb.WriteString("  down/j   Move cursor down\n\n")
		sb.WriteString("Press any key to return...\n")
		return sb.String()
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
	headerText := fmt.Sprintf("[%s] [%s] Namespace: %s", healthStr, auditStr, m.namespace)
	sb.WriteString(headerStyle.Render(headerText) + "\n\n")

	if m.mode == modeSearch {
		sb.WriteString(fmt.Sprintf("/%s\n\n", m.search))
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
				line := fmt.Sprintf("%s%s  %s%s", indent, row.Label, row.Secret.Fingerprint, suffix)
				sb.WriteString(normalStyle.Render(line) + "\n")
			} else {
				sb.WriteString(normalStyle.Render(indent+row.Label) + "\n")
			}
		}
	} else {
		// Flat list view.
		for i, secret := range m.filtered {
			suffix := m.totpSuffix(secret)
			line := fmt.Sprintf("%-20s  %s%s", secret.Name, secret.Fingerprint, suffix)
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
		footerParts = append(footerParts, "[/] search", "[r] rotate", "[P] panic-lock", "[t] tree", "[c] copy", "[?] help", "[q] quit")
	} else if m.mode == modeSearch {
		footerParts = append(footerParts, "[esc] cancel search", "[enter] keep filter")
	} else if m.mode == modeConfirm {
		footerParts = append(footerParts, "[y] confirm rotate", "[n/esc] cancel")
	}
	sb.WriteString(strings.Join(footerParts, " | "))

	if m.status != "" {
		sb.WriteString("\n\n" + m.status)
	}

	return sb.String()
}
