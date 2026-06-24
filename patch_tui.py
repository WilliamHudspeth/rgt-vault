
# 1. Update client.go
with open("go/internal/tui/client.go", "r") as f:
    client_code = f.read()

audit_structs = """
type AuditEntry struct {
	Timestamp string `json:"timestamp"`
	Event     string `json:"event"`
	Principal string `json:"principal"`
	Detail    string `json:"detail"`
	Hash      string `json:"hash"`
}

type auditLogResponse struct {
	Entries []AuditEntry `json:"entries"`
}

func (c *HTTPClient) GetAuditLog(limit int) ([]AuditEntry, error) {
	u := fmt.Sprintf("%s/v1/audit?limit=%d", c.baseURL, limit)
	req, err := c.newReq(http.MethodGet, u, "")
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get audit: unexpected status %d", resp.StatusCode)
	}
	var res auditLogResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return res.Entries, nil
}
"""
# Insert before "func (c *HTTPClient) Rotate"
client_code = client_code.replace(
    "func (c *HTTPClient) Rotate(target string) error {",
    audit_structs + "\nfunc (c *HTTPClient) Rotate(target string) error {",
)

with open("go/internal/tui/client.go", "w") as f:
    f.write(client_code)


# 2. Update model.go
with open("go/internal/tui/model.go", "r") as f:
    model_code = f.read()

# Add to Client interface
model_code = model_code.replace(
    "Rotate(target string) error\n}", "Rotate(target string) error\n\tGetAuditLog(limit int) ([]AuditEntry, error)\n}"
)

# Add modeAudit
model_code = model_code.replace("modeConfirm\n)", "modeConfirm\n\tmodeAudit\n)")

# Add fields to Model
model_code = model_code.replace(
    "clipboardTimeout time.Duration\n}",
    "clipboardTimeout time.Duration\n\n\t// RGT-41: Live Audit Log Streamer\n\tauditEntries []AuditEntry\n}",
)

# Add messages and commands
msgs_and_cmds = """
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
"""
model_code = model_code.replace("func totpTickCmd() tea.Cmd {", msgs_and_cmds + "\nfunc totpTickCmd() tea.Cmd {")

# Add update logic
update_logic = """	case auditTickMsg:
		if m.mode == modeAudit {
			return m, tea.Batch(m.loadAuditCmd(), auditTickCmd())
		}
		return m, nil

	case auditLoadMsg:
		m.auditEntries = msg.entries
		if msg.err != nil {
			m.status = "audit error: " + msg.err.Error()
		}
		return m, nil

	case tea.KeyMsg:"""
model_code = model_code.replace("	case tea.KeyMsg:", update_logic)

# Add keys to modeDashboard
dash_keys = """			case "a":
				m.mode = modeAudit
				m.status = "streaming audit log..."
				return m, tea.Batch(m.loadAuditCmd(), auditTickCmd())
			case "t":"""
model_code = model_code.replace('			case "t":', dash_keys)

# Add modeAudit handler
audit_handler = """		case modeAudit:
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "esc", "a":
				m.mode = modeDashboard
				m.status = ""
				return m, nil
			}

		case modeHelp:"""
model_code = model_code.replace("		case modeHelp:", audit_handler)

# Add audit help
model_code = model_code.replace(
    'sb.WriteString("  t        Toggle tree view\\n")',
    'sb.WriteString("  t        Toggle tree view\\n")\n\t\tsb.WriteString("  a        Live audit log stream\\n")',
)

# Add audit view
audit_view = """	if m.mode == modeAudit {
		var sb strings.Builder
		sb.WriteString(headerStyle.Render("Live Audit Log Stream") + "\\n\\n")
		if len(m.auditEntries) == 0 {
			sb.WriteString("  (no audit entries)\\n")
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
				detail := entry.Detail
				if len(detail) > 40 {
					detail = detail[:37] + "..."
				}
				// Format: HH:MM:SS | EVENT | PRINCIPAL | DETAIL
				tStr := entry.Timestamp
				if len(tStr) >= 19 {
					tStr = tStr[11:19] // Extract HH:MM:SS from RFC3339
				}
				line := fmt.Sprintf("%-8s | %-15s | %-10s | %s", tStr, entry.Event, entry.Principal, detail)
				sb.WriteString(normalStyle.Render(line) + "\\n")
			}
		}
		sb.WriteString("\\n[a/esc] back | [q] quit\\n")
		if m.status != "" {
			sb.WriteString("\\n" + m.status)
		}
		return sb.String()
	}

	var sb strings.Builder"""
model_code = model_code.replace(
    '\tvar sb strings.Builder\n\n\thealthStr := "○ offline"', audit_view + '\n\n\thealthStr := "○ offline"'
)

# Add footer
model_code = model_code.replace(
    'footerParts = append(footerParts, "[/] search", "[r] rotate", "[P] panic-lock", "[t] tree", "[c] copy", "[?] help", "[q] quit")',
    'footerParts = append(footerParts, "[/] search", "[r] rotate", "[a] audit", "[P] panic-lock", "[t] tree", "[c] copy", "[?] help", "[q] quit")',
)

with open("go/internal/tui/model.go", "w") as f:
    f.write(model_code)

print("Patching complete!")
