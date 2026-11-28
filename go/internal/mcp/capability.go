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

	"github.com/WilliamHudspeth/rgt-vault/go/internal/apierr"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/validation"
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
	if agent != "" { // "" = the token's agent (server-side)
		var err error
		if agent, err = validation.ValidateAgent(agent); err != nil {
			return "invalid agent_id: " + cleanText(err.Error(), maxErrorDetailRunes), true
		}
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

	req := map[string]any{
		"capability":         capability,
		"capability_token":   token,
		"capability_version": version,
		"payload":            payload,
	}
	if agent != "" {
		req["agent_id"] = agent
	}
	body, err := json.Marshal(req)
	if err != nil {
		return "encode error", true
	}
	resp, respBody, err := s.do(tool, "POST", s.backendURL+"/v1/capabilities/execute", body)
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

// capabilityError turns a failed execute response into the tool error. A
// standard error envelope is relayed like every other tool's (class, detail,
// HTTP code, incident id; errorText); a body without one (a proxy page, an
// older backend) falls back to the fixed messages python/server/mcp_server.py
// used (PermissionError -> "unauthorized", anything else -> "execution_failed").
// The full body is logged on stderr with credentials redacted.
func (s *Server) capabilityError(resp *http.Response, body []byte, token string) (string, bool) {
	text, isErr := s.backendError("execute_capability", resp, body, token)
	if _, ok := apierr.Parse(body); ok {
		return text, isErr
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return "unauthorized", true
	case http.StatusTooManyRequests:
		return "rate limited", true
	case http.StatusNotFound:
		return "capability not found", true
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
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
	listURL := s.backendURL + "/v1/capabilities/list"
	if agent != "" { // "" = the token's agent (server-side)
		var err error
		if agent, err = validation.ValidateAgent(agent); err != nil {
			return "invalid agent: " + cleanText(err.Error(), maxErrorDetailRunes), true
		}
		listURL += "?agent=" + url.QueryEscape(agent)
	}
	resp, body, err := s.do(tool, "GET", listURL, nil)
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
