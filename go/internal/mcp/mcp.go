// Package mcp implements a local stdio MCP (Model Context Protocol) server that
// bridges an MCP client to the rgt-vault HTTP backend (Ticket RGT-159).
// It speaks newline-delimited JSON-RPC 2.0 over stdio; bridges to the rgt-vault HTTP backend.
package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"rgt-vault-server/internal/netguard"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Server holds the configuration and client for communicating with the vault backend.
type Server struct {
	backendURL    string
	token         string
	httpClient    *http.Client
	serverName    string
	serverVersion string
	// logger receives backend error details; stdout is the protocol channel,
	// so it must never point there. Defaults to the standard logger (stderr).
	logger *log.Logger
}

// NewServer initializes a new Server with trimmed backendURL, default client timeout,
// and preset server info metadata.
func NewServer(backendURL, token string) *Server {
	return &Server{
		backendURL: strings.TrimSuffix(backendURL, "/"),
		token:      token,
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{DialContext: netguard.NewDialer(true).DialContext},
		},
		serverName:    "rgt-vault-mcp",
		serverVersion: "0.3.0",
		logger:        log.Default(),
	}
}

type flusher interface {
	Flush() error
}

func (s *Server) writeResponse(out io.Writer, resp *rpcResponse) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	if _, err := out.Write(data); err != nil {
		return err
	}
	if _, err := out.Write([]byte("\n")); err != nil {
		return err
	}
	if f, ok := out.(flusher); ok {
		return f.Flush()
	}
	return nil
}

// Serve handles incoming JSON-RPC messages from the in reader and writes responses to the out writer.
func (s *Server) Serve(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			resp := &rpcResponse{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error: &rpcError{
					Code:    -32700,
					Message: err.Error(),
				},
			}
			if err := s.writeResponse(out, resp); err != nil {
				return err
			}
			continue
		}

		resp := s.handle(req)
		if resp != nil {
			if err := s.writeResponse(out, resp); err != nil {
				return err
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

// supportedProtocolVersions lists the MCP protocol revisions this server can
// speak, newest first. The tool surface is identical across all of them, so
// the server echoes the client's requested revision when it is listed and
// otherwise answers with the newest one (per the MCP lifecycle spec).
var supportedProtocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

func negotiateProtocolVersion(raw json.RawMessage) string {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(raw, &p)
	for _, v := range supportedProtocolVersions {
		if v == p.ProtocolVersion {
			return v
		}
	}
	return supportedProtocolVersions[0]
}

// isNotification reports whether req is a JSON-RPC notification (no id). A
// server must never reply to a notification.
func isNotification(req rpcRequest) bool {
	id := strings.TrimSpace(string(req.ID))
	return id == ""
}

func (s *Server) handle(req rpcRequest) *rpcResponse {
	if isNotification(req) {
		return nil
	}
	// MCP: request ids must not be null; JSON-RPC: jsonrpc must be "2.0" and
	// method must be present.
	if strings.TrimSpace(string(req.ID)) == "null" || req.JSONRPC != "2.0" || req.Method == "" {
		id := req.ID
		if strings.TrimSpace(string(id)) == "null" {
			id = json.RawMessage("null")
		}
		return &rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: -32600, Message: "invalid request"}}
	}
	switch req.Method {
	case "ping":
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}}

	case "initialize":
		result := map[string]any{
			"protocolVersion": negotiateProtocolVersion(req.Params),
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    s.serverName,
				"version": s.serverVersion,
			},
		}
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  result,
		}

	case "tools/list":
		result := map[string]any{
			"tools": []any{
				map[string]any{
					"name":        "list_secrets",
					"description": "List secret names in a namespace (no plaintext).",
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"namespace": map[string]any{
								"type": "string",
							},
						},
						"required": []any{"namespace"},
					},
				},
				map[string]any{
					"name":        "lease_secret",
					"description": "Lease a secret: return its plaintext value for use by the agent.",
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"namespace": map[string]any{
								"type": "string",
							},
							"name": map[string]any{
								"type": "string",
							},
						},
						"required": []any{"namespace", "name"},
					},
				},
				map[string]any{
					"name":        "revoke_secret",
					"description": "Revoke (soft-delete) a secret.",
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"namespace": map[string]any{
								"type": "string",
							},
							"name": map[string]any{
								"type": "string",
							},
						},
						"required": []any{"namespace", "name"},
					},
				},
				map[string]any{
					"name":        "execute_secret",
					"description": "Execute a bounded action using a secret without returning the plaintext.",
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"namespace": map[string]any{
								"type": "string",
							},
							"name": map[string]any{
								"type": "string",
							},
							"action": map[string]any{
								"type": "string",
							},
							"params": map[string]any{
								"type":                 "object",
								"additionalProperties": true,
							},
						},
						"required": []any{"namespace", "name", "action"},
					},
				},
			},
		}
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  result,
		}

	case "tools/call":
		var params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return &rpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &rpcError{
					Code:    -32602,
					Message: "invalid params: " + err.Error(),
				},
			}
		}

		text, isError := s.callTool(params.Name, params.Arguments)
		result := map[string]any{
			"content": []any{
				map[string]any{
					"type": "text",
					"text": text,
				},
			},
			"isError": isError,
		}
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  result,
		}

	default:
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &rpcError{
				Code:    -32601,
				Message: "method not found: " + req.Method,
			},
		}
	}
}

func (s *Server) callTool(name string, args map[string]any) (string, bool) {
	getStr := func(key string) string {
		val, ok := args[key]
		if !ok {
			return ""
		}
		str, ok := val.(string)
		if !ok {
			return ""
		}
		return str
	}

	// Every tool needs a namespace; all but list_secrets need a name, and
	// execute_secret an action. Reject early rather than build "//" paths.
	required := map[string][]string{
		"list_secrets":   {"namespace"},
		"lease_secret":   {"namespace", "name"},
		"revoke_secret":  {"namespace", "name"},
		"execute_secret": {"namespace", "name", "action"},
	}
	for _, key := range required[name] {
		if getStr(key) == "" {
			return "missing required string argument: " + key, true
		}
	}

	switch name {
	case "list_secrets":
		ns := getStr("namespace")
		reqURL := s.backendURL + "/v1/secrets?namespace=" + url.QueryEscape(ns)
		resp, body, err := s.do("GET", reqURL, nil)
		if err != nil {
			return s.unreachable(name, err)
		}
		if resp.StatusCode != http.StatusOK {
			return s.backendError("list_secrets", resp, body)
		}
		// Re-encode with a metadata-only shape: whatever the backend sends
		// (the stub list route still includes "value"), plaintext never
		// leaves through list_secrets.
		var res struct {
			Namespace string `json:"namespace"`
			Secrets   []struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace,omitempty"`
				CreatedAt string `json:"created_at,omitempty"`
			} `json:"secrets"`
		}
		if err := json.Unmarshal(body, &res); err != nil {
			return "backend returned an invalid response", true
		}
		out, err := json.Marshal(res)
		if err != nil {
			return "encode error", true
		}
		return string(out), false

	case "lease_secret":
		ns := getStr("namespace")
		nm := getStr("name")
		// Single-secret route; the list route is not a plaintext source (it is
		// being changed to return metadata only).
		reqURL := s.backendURL + "/v1/secrets/" + url.PathEscape(ns) + "/" + url.PathEscape(nm)
		resp, body, err := s.do("GET", reqURL, nil)
		if err != nil {
			return s.unreachable(name, err)
		}
		if resp.StatusCode != http.StatusOK {
			return s.backendError("lease_secret", resp, body)
		}
		var res struct {
			Value *string `json:"value"`
		}
		if err := json.Unmarshal(body, &res); err != nil {
			return "backend returned an invalid response", true
		}
		if res.Value == nil {
			return "backend did not return a secret value", true
		}
		return *res.Value, false

	case "revoke_secret":
		ns := getStr("namespace")
		nm := getStr("name")
		reqURL := s.backendURL + "/v1/secrets/" + url.PathEscape(ns) + "/" + url.PathEscape(nm) + "/revoke"
		resp, body, err := s.do("POST", reqURL, nil)
		if err != nil {
			return s.unreachable(name, err)
		}
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
			return "revoked " + ns + "/" + nm, false
		}
		return s.backendError("revoke_secret", resp, body)

	case "execute_secret":
		ns := getStr("namespace")
		nm := getStr("name")
		act := getStr("action")

		var actionParams map[string]any
		if p, ok := args["params"]; ok {
			if pm, ok := p.(map[string]any); ok {
				actionParams = pm
			}
		}

		reqURL := s.backendURL + "/v1/secrets/" + url.PathEscape(ns) + "/" + url.PathEscape(nm) + "/use"
		reqBody := map[string]any{
			"action":  act,
			"agent":   "mcp-client",
			"purpose": "execute_secret tool call",
			"params":  actionParams,
		}
		bodyBytes, err := json.Marshal(reqBody)
		if err != nil {
			return "encode error: " + err.Error(), true
		}

		resp, body, err := s.do("POST", reqURL, bodyBytes)
		if err != nil {
			return s.unreachable(name, err)
		}
		if resp.StatusCode == http.StatusOK {
			return string(body), false
		}
		return s.backendError("execute_secret", resp, body)

	default:
		return "unknown tool: " + name, true
	}
}

// maxLoggedErrorBody caps how much of a backend error body reaches the log.
const maxLoggedErrorBody = 512

// maxBackendBody bounds how much of any backend response is read.
const maxBackendBody = 4 << 20

// backendError turns a non-success backend response into a tool error. The
// backend's error body may contain internal details (paths, stack context,
// policy internals) it was never meant to hand to an arbitrary MCP client, so
// the body is only logged (stderr, truncated) and the client gets the status.
func (s *Server) backendError(tool string, resp *http.Response, body []byte) (string, bool) {
	logged := body
	if len(logged) > maxLoggedErrorBody {
		logged = logged[:maxLoggedErrorBody]
	}
	s.logf("%s backend error: %s - %q", tool, resp.Status, logged)
	return "backend error: " + resp.Status, true
}

// SetLogger redirects backend error logging (nil disables it). Never pass a
// logger that writes to the protocol stream (stdout).
func (s *Server) SetLogger(l *log.Logger) { s.logger = l }

// unreachable logs the transport error (it names the backend URL) and gives
// the client a fixed message.
func (s *Server) unreachable(tool string, err error) (string, bool) {
	s.logf("%s backend unreachable: %v", tool, err)
	return "backend unreachable", true
}

func (s *Server) logf(format string, args ...any) {
	if s.logger != nil {
		s.logger.Printf(format, args...)
	}
}

func (s *Server) do(method, reqURL string, body []byte) (*http.Response, []byte, error) {
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, reqURL, bodyReader)
	if err != nil {
		return nil, nil, err
	}

	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBackendBody))
	if err != nil {
		return nil, nil, err
	}

	return resp, respBody, nil
}
