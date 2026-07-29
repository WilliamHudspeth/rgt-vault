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

func (s *Server) handle(req rpcRequest) *rpcResponse {
	switch req.Method {
	case "initialize":
		result := map[string]any{
			"protocolVersion": "2024-11-05",
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

	case "notifications/initialized":
		return nil

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
					"description": "Retrieve a secret value for use by the agent.",
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
								"type": "object",
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

	switch name {
	case "list_secrets":
		ns := getStr("namespace")
		reqURL := s.backendURL + "/v1/secrets?namespace=" + url.QueryEscape(ns)
		resp, body, err := s.do("GET", reqURL, nil)
		if err != nil {
			return "backend unreachable: " + err.Error(), true
		}
		if resp.StatusCode == 200 {
			return string(body), false
		}
		return "backend error: " + resp.Status, true

	case "lease_secret":
		ns := getStr("namespace")
		nm := getStr("name")
		reqURL := s.backendURL + "/v1/secrets?namespace=" + url.QueryEscape(ns) + "&name=" + url.QueryEscape(nm)
		resp, body, err := s.do("GET", reqURL, nil)
		if err != nil {
			return "backend unreachable: " + err.Error(), true
		}
		if resp.StatusCode == 200 {
			var res struct {
				Secrets []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"secrets"`
			}
			if err := json.Unmarshal(body, &res); err != nil {
				return "unmarshal error: " + err.Error(), true
			}
			for _, sec := range res.Secrets {
				if sec.Name == nm {
					return sec.Value, false
				}
			}
			return "secret not found", true
		}
		return "backend error: " + resp.Status, true

	case "revoke_secret":
		ns := getStr("namespace")
		nm := getStr("name")
		reqURL := s.backendURL + "/v1/secrets/" + url.PathEscape(ns) + "/" + url.PathEscape(nm) + "/revoke"
		resp, _, err := s.do("POST", reqURL, nil)
		if err != nil {
			return "backend unreachable: " + err.Error(), true
		}
		if resp.StatusCode == 200 || resp.StatusCode == 204 {
			return "revoked " + ns + "/" + nm, false
		}
		return "backend error: " + resp.Status, true

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
			return "backend unreachable: " + err.Error(), true
		}
		if resp.StatusCode == 200 {
			return string(body), false
		}
		// The backend's error body may contain internal details (paths, stack
		// context) it was never meant to hand to an arbitrary MCP client;
		// log it server-side and return only the status to the caller.
		log.Printf("execute_secret backend error: %s - %s", resp.Status, string(body))
		return "backend error: " + resp.Status, true

	default:
		return "unknown tool: " + name, true
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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	return resp, respBody, nil
}
