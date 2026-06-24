package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestServer returns an MCP Server pointed at the given httptest server.
func newTestServer(ts *httptest.Server) *Server {
	return NewServer(ts.URL, "test-token")
}

// makeReq builds a rpcRequest with a numeric JSON id.
func makeReq(id int, method string, params any) rpcRequest {
	rawID, _ := json.Marshal(id)
	var rawParams json.RawMessage
	if params != nil {
		rawParams, _ = json.Marshal(params)
	}
	return rpcRequest{
		JSONRPC: "2.0",
		ID:      rawID,
		Method:  method,
		Params:  rawParams,
	}
}

// resultMap re-encodes resp.Result to JSON and back into map[string]any.
func resultMap(t *testing.T, resp *rpcResponse) map[string]any {
	t.Helper()
	b, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return m
}

// ---- initialize -------------------------------------------------------

func TestHandle_Initialize(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	s := newTestServer(ts)

	resp := s.handle(makeReq(1, "initialize", nil))
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	// Echo the ID back.
	var gotID int
	if err := json.Unmarshal(resp.ID, &gotID); err != nil || gotID != 1 {
		t.Fatalf("id not echoed: raw=%s err=%v", resp.ID, err)
	}

	m := resultMap(t, resp)

	// protocolVersion must be present.
	if _, ok := m["protocolVersion"]; !ok {
		t.Error("missing protocolVersion")
	}

	// serverInfo.name must equal "rgt-vault-mcp".
	si, ok := m["serverInfo"].(map[string]any)
	if !ok {
		t.Fatalf("serverInfo missing or wrong type: %v", m["serverInfo"])
	}
	if si["name"] != "rgt-vault-mcp" {
		t.Errorf("serverInfo.name = %q, want rgt-vault-mcp", si["name"])
	}
}

// ---- notifications/initialized ----------------------------------------

func TestHandle_NotificationsInitialized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	s := newTestServer(ts)

	resp := s.handle(makeReq(2, "notifications/initialized", nil))
	if resp != nil {
		t.Errorf("expected nil response for notification, got %+v", resp)
	}
}

// ---- tools/list -------------------------------------------------------

func TestHandle_ToolsList(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	s := newTestServer(ts)

	resp := s.handle(makeReq(3, "tools/list", nil))
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	m := resultMap(t, resp)
	toolsRaw, ok := m["tools"]
	if !ok {
		t.Fatal("missing tools key")
	}
	tools, ok := toolsRaw.([]any)
	if !ok {
		t.Fatalf("tools is not an array: %T", toolsRaw)
	}
	if len(tools) != 3 {
		t.Fatalf("expected 3 tools, got %d", len(tools))
	}

	wantNames := map[string]bool{
		"list_secrets":  true,
		"lease_secret":  true,
		"revoke_secret": true,
	}
	for _, tv := range tools {
		tool, ok := tv.(map[string]any)
		if !ok {
			t.Fatalf("tool entry is not an object: %T", tv)
		}
		name, _ := tool["name"].(string)
		if !wantNames[name] {
			t.Errorf("unexpected tool name: %q", name)
		}
		delete(wantNames, name)
	}
	for missing := range wantNames {
		t.Errorf("missing tool: %q", missing)
	}
}

// ---- tools/call list_secrets ------------------------------------------

func TestCallTool_ListSecrets_OK(t *testing.T) {
	const fakeBody = `{"namespace":"ns1","secrets":[{"name":"k","value":"v"}]}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %s", r.Method)
		}
		if r.URL.Path != "/v1/secrets" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.URL.Query().Get("namespace") != "ns1" {
			t.Errorf("unexpected namespace %s", r.URL.Query().Get("namespace"))
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("auth header missing/wrong: %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, fakeBody)
	}))
	defer ts.Close()
	s := newTestServer(ts)

	text, isError := s.callTool("list_secrets", map[string]any{"namespace": "ns1"})
	if isError {
		t.Fatalf("expected isError=false, got true; text=%s", text)
	}
	if !strings.Contains(text, fakeBody) && text != fakeBody {
		t.Errorf("response text does not contain backend body; got %q", text)
	}
}

// ---- tools/call lease_secret (found) ----------------------------------

func TestCallTool_LeaseSecret_Found(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"namespace":"ns1","secrets":[{"name":"mykey","value":"s3cr3t"}]}`)
	}))
	defer ts.Close()
	s := newTestServer(ts)

	text, isError := s.callTool("lease_secret", map[string]any{"namespace": "ns1", "name": "mykey"})
	if isError {
		t.Fatalf("expected isError=false; text=%s", text)
	}
	if text != "s3cr3t" {
		t.Errorf("expected value s3cr3t, got %q", text)
	}
}

// ---- tools/call lease_secret (NOT found) ------------------------------

func TestCallTool_LeaseSecret_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return a response with no matching secret name.
		fmt.Fprint(w, `{"namespace":"ns1","secrets":[{"name":"other","value":"x"}]}`)
	}))
	defer ts.Close()
	s := newTestServer(ts)

	text, isError := s.callTool("lease_secret", map[string]any{"namespace": "ns1", "name": "missing"})
	if !isError {
		t.Fatalf("expected isError=true; text=%s", text)
	}
	if !strings.Contains(text, "not found") {
		t.Errorf("expected 'not found' message, got %q", text)
	}
}

// ---- tools/call revoke_secret -----------------------------------------

func TestCallTool_RevokeSecret_OK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method %s", r.Method)
		}
		wantPath := "/v1/secrets/ns1/mykey/revoke"
		if r.URL.Path != wantPath {
			t.Errorf("unexpected path %s, want %s", r.URL.Path, wantPath)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	s := newTestServer(ts)

	text, isError := s.callTool("revoke_secret", map[string]any{"namespace": "ns1", "name": "mykey"})
	if isError {
		t.Fatalf("expected isError=false; text=%s", text)
	}
	if !strings.Contains(text, "revoked") {
		t.Errorf("expected 'revoked' in text, got %q", text)
	}
}

// ---- unknown method ---------------------------------------------------

func TestHandle_UnknownMethod(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	s := newTestServer(ts)

	resp := s.handle(makeReq(9, "bogus/method", nil))
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Error == nil {
		t.Fatal("expected error, got nil")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("expected error code -32601, got %d", resp.Error.Code)
	}
	// ID must be echoed even for error responses.
	var gotID int
	if err := json.Unmarshal(resp.ID, &gotID); err != nil || gotID != 9 {
		t.Errorf("id not echoed: raw=%s err=%v", resp.ID, err)
	}
}

// ---- Serve() loop: two requests, two responses ------------------------

func TestServe_TwoRequests(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	s := newTestServer(ts)

	// Build two newline-delimited JSON-RPC requests.
	req1, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
	})
	req2, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	})
	input := string(req1) + "\n" + string(req2) + "\n"

	var out bytes.Buffer
	err := s.Serve(strings.NewReader(input), &out)
	if err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 response lines, got %d: %q", len(lines), out.String())
	}

	for i, line := range lines {
		var resp rpcResponse
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Errorf("line %d is not valid JSON: %v — %q", i+1, err, line)
			continue
		}
		var id int
		if err := json.Unmarshal(resp.ID, &id); err != nil {
			t.Errorf("line %d: cannot parse id: %v", i+1, err)
			continue
		}
		wantID := i + 1
		if id != wantID {
			t.Errorf("line %d: id = %d, want %d", i+1, id, wantID)
		}
	}
}

// ---- tools/call via handle() — verify full content shape --------------

func TestHandle_ToolsCall_ContentShape(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"namespace":"n","secrets":[]}`)
	}))
	defer ts.Close()
	s := newTestServer(ts)

	params := map[string]any{
		"name":      "list_secrets",
		"arguments": map[string]any{"namespace": "n"},
	}
	resp := s.handle(makeReq(10, "tools/call", params))
	if resp == nil || resp.Error != nil {
		t.Fatalf("unexpected response: %+v", resp)
	}

	m := resultMap(t, resp)

	// Must have "isError" key.
	if _, ok := m["isError"]; !ok {
		t.Error("missing isError key in result")
	}

	// Must have "content" as an array with at least one entry having type=text.
	contentRaw, ok := m["content"].([]any)
	if !ok || len(contentRaw) == 0 {
		t.Fatalf("content missing or empty: %v", m["content"])
	}
	entry, ok := contentRaw[0].(map[string]any)
	if !ok {
		t.Fatalf("content[0] not an object: %T", contentRaw[0])
	}
	if entry["type"] != "text" {
		t.Errorf("content[0].type = %q, want text", entry["type"])
	}
	if _, ok := entry["text"]; !ok {
		t.Error("content[0].text missing")
	}
}
