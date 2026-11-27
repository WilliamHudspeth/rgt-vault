package mcp

// Capability tools and the policy-summary resource: the Go port of
// python/server/mcp_server.py (vault_execute, vault_list_capabilities and the
// vault://policy resource). They bridge to the backend routes
//
//	POST /v1/capabilities/execute
//	GET  /v1/capabilities/list?agent=
//
// A v2 capability token is a credential. It is forwarded to the backend in
// the request body and nowhere else: not in logs, not in tool results, not in
// error text (every string that leaves the process goes through redact).

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"rgt-vault-server/internal/policy"
	"rgt-vault-server/internal/validation"
)

const (
	// maxCapabilityTokenBytes bounds a capability token read from a file or a
	// tool argument. A v2 token is base64url(JSON payload).base64url(HMAC);
	// real ones are well under 4 KiB.
	maxCapabilityTokenBytes = 16 << 10
	// maxErrorDetailRunes bounds a backend validation message relayed to the
	// client.
	maxErrorDetailRunes = 200
	// maxCapabilityVersion bounds the version argument (the backend ignores
	// anything but small integers anyway).
	maxCapabilityVersion = 1 << 20
)

// SetCapabilityToken sets the default capability token used by
// execute_capability when the caller supplies none. An empty token clears it.
func (s *Server) SetCapabilityToken(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		s.capToken = ""
		return nil
	}
	if err := checkTokenShape(token); err != nil {
		return err
	}
	s.capToken = token
	return nil
}

// LoadCapabilityTokenFile reads the default capability token from path (one
// token, surrounding whitespace ignored). The file is read with a size cap
// and its contents are never included in an error.
func (s *Server) LoadCapabilityTokenFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("capability token file: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxCapabilityTokenBytes+1))
	if err != nil {
		return fmt.Errorf("capability token file: %w", err)
	}
	if len(raw) > maxCapabilityTokenBytes {
		return fmt.Errorf("capability token file: larger than %d bytes", maxCapabilityTokenBytes)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return errors.New("capability token file: empty")
	}
	if err := checkTokenShape(tok); err != nil {
		return fmt.Errorf("capability token file: %w", err)
	}
	s.capToken = tok
	return nil
}

// SetPolicyFile names the ABAC policy file the policy summary counts rules
// in (read at resources/read time; only the count is exposed).
func (s *Server) SetPolicyFile(path string) { s.policyFile = path }

// checkTokenShape rejects tokens that cannot be a capability token: oversized
// or containing whitespace/control characters (header or log injection).
func checkTokenShape(tok string) error {
	if len(tok) > maxCapabilityTokenBytes {
		return fmt.Errorf("capability token is larger than %d bytes", maxCapabilityTokenBytes)
	}
	for _, r := range tok {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return errors.New("capability token contains whitespace or control characters")
		}
	}
	return nil
}

// redact removes every credential this server holds (agent token, default
// capability token) from text that is about to be logged or returned.
func (s *Server) redact(text string, extra ...string) string {
	for _, secret := range append([]string{s.token, s.capToken}, extra...) {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, "[redacted]")
		}
	}
	return text
}

// cleanText makes backend-supplied text safe for a tool result: control
// characters become spaces and the length is bounded.
func cleanText(text string, maxRunes int) string {
	var b strings.Builder
	n := 0
	for _, r := range text {
		if n >= maxRunes {
			b.WriteString("...")
			break
		}
		if unicode.IsControl(r) || r == utf8.RuneError {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// stringArg returns args[key] as a string. A missing key is ("", true); a
// present non-string is ("", false).
func stringArg(args map[string]any, key string) (string, bool) {
	v, present := args[key]
	if !present || v == nil {
		return "", true
	}
	str, ok := v.(string)
	return str, ok
}

// versionArg parses the optional version argument: an integer >= 1, as a JSON
// number or a numeric string ("2", or Python's "1.0"). The default is 1.
func versionArg(args map[string]any) (int, error) {
	v, present := args["version"]
	if !present || v == nil {
		return 1, nil
	}
	var n int
	switch t := v.(type) {
	case float64:
		if t != math.Trunc(t) || t < 1 || t > maxCapabilityVersion {
			return 0, errors.New("invalid version: must be an integer >= 1")
		}
		n = int(t)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(t), ".0"))
		if err != nil || parsed < 1 || parsed > maxCapabilityVersion {
			return 0, errors.New("invalid version: must be an integer >= 1")
		}
		n = parsed
	default:
		return 0, errors.New("invalid version: must be an integer >= 1")
	}
	return n, nil
}

// executeCapability implements the execute_capability tool.
func (s *Server) executeCapability(args map[string]any) (string, bool) {
	const tool = "execute_capability"
	capability, _ := stringArg(args, "capability")
	agent, ok := stringArg(args, "agent_id")
	if !ok {
		return "invalid agent_id: must be a string", true
	}
	if agent == "" {
		agent = s.agent
	}
	agent, err := validation.ValidateAgent(agent)
	if err != nil {
		return "invalid agent_id: " + cleanText(err.Error(), maxErrorDetailRunes), true
	}
	token, ok := stringArg(args, "capability_token")
	if !ok {
		return "invalid capability_token: must be a string", true
	}
	token = strings.TrimSpace(token)
	if token == "" {
		token = s.capToken
	}
	if token == "" {
		return "missing capability token: pass capability_token or start the MCP server with a capability token file", true
	}
	if err := checkTokenShape(token); err != nil {
		return "invalid capability_token", true
	}
	version, err := versionArg(args)
	if err != nil {
		return err.Error(), true
	}
	var payload map[string]any
	if raw, present := args["payload"]; present && raw != nil {
		pm, isMap := raw.(map[string]any)
		if !isMap {
			return "invalid payload: must be an object", true
		}
		payload = pm
	}

	body, err := json.Marshal(map[string]any{
		"capability":         capability,
		"agent_id":           agent,
		"capability_token":   token,
		"capability_version": version,
		"payload":            payload,
	})
	if err != nil {
		return "encode error", true
	}
	resp, respBody, err := s.do("POST", s.backendURL+"/v1/capabilities/execute", body)
	if err != nil {
		return s.unreachable(tool, err)
	}
	if resp.StatusCode != http.StatusOK {
		return s.capabilityError(resp, respBody, token)
	}
	var res struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(respBody, &res); err != nil {
		return "backend returned an invalid response", true
	}
	if len(res.Result) == 0 {
		res.Result = json.RawMessage("null")
	}
	out, err := json.Marshal(map[string]any{"ok": true, "result": res.Result})
	if err != nil {
		return "encode error", true
	}
	return s.redact(string(out), token), false
}

// capabilityError maps a failed execute response to a fixed client message,
// as python/server/mcp_server.py does (PermissionError -> "unauthorized",
// anything else -> "execution_failed"). Only the backend's validation message
// (HTTP 400: bad payload, unknown version) is relayed, cleaned and bounded.
// The full body is logged on stderr with credentials redacted.
func (s *Server) capabilityError(resp *http.Response, body []byte, token string) (string, bool) {
	logged := s.redact(string(body), token)
	if len(logged) > maxLoggedErrorBody {
		logged = logged[:maxLoggedErrorBody]
	}
	s.logf("execute_capability backend error: %s - %q", resp.Status, logged)
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return "unauthorized", true
	case http.StatusTooManyRequests:
		return "rate limited", true
	case http.StatusNotFound:
		return "capability not found", true
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		var e struct {
			Detail string `json:"detail"`
		}
		if json.Unmarshal(body, &e) == nil && e.Detail != "" {
			return "invalid request: " + cleanText(s.redact(e.Detail, token), maxErrorDetailRunes), true
		}
		return "invalid request", true
	default:
		return "execution_failed", true
	}
}

// capabilityView is the metadata of one capability (no handler, no secrets).
type capabilityView struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	SupportedVersions []int    `json:"supported_versions"`
	ParamsSchema      []string `json:"params_schema"`
}

// listCapabilities implements the list_capabilities tool: the capabilities the
// ABAC policy allows an agent to execute.
func (s *Server) listCapabilities(args map[string]any) (string, bool) {
	const tool = "list_capabilities"
	agent, ok := stringArg(args, "agent")
	if !ok {
		return "invalid agent: must be a string", true
	}
	if agent == "" {
		agent = s.agent
	}
	agent, err := validation.ValidateAgent(agent)
	if err != nil {
		return "invalid agent: " + cleanText(err.Error(), maxErrorDetailRunes), true
	}
	resp, body, err := s.do("GET", s.backendURL+"/v1/capabilities/list?agent="+url.QueryEscape(agent), nil)
	if err != nil {
		return s.unreachable(tool, err)
	}
	if resp.StatusCode != http.StatusOK {
		return s.backendError(tool, resp, body)
	}
	// Re-encode with a fixed shape so nothing else the backend sends leaves.
	var res struct {
		Agent        string           `json:"agent"`
		Capabilities []capabilityView `json:"capabilities"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "backend returned an invalid response", true
	}
	if res.Capabilities == nil {
		res.Capabilities = []capabilityView{}
	}
	out, err := json.Marshal(res)
	if err != nil {
		return "encode error", true
	}
	return string(out), false
}

// policySummary is the vault://policy resource body (python get_policy_summary
// returns {"rules": N, "default_ttl": 300}). "rules" is the number of ABAC
// rules, or null when this server was not told where the policy file is (the
// backend has no policy-summary route); it never includes rule contents.
func (s *Server) policySummary() map[string]any {
	summary := map[string]any{"rules": nil, "default_ttl": policy.DefaultLeaseTTL}
	if s.policyFile == "" {
		return summary
	}
	eng, err := policy.Load(s.policyFile)
	if err != nil {
		// The error names the path and may quote policy text: log it only.
		s.logf("policy summary: cannot load the policy file: %v", err)
		return summary
	}
	summary["rules"] = eng.RuleCount()
	return summary
}
