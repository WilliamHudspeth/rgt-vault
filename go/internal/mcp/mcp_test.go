package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
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
	if len(tools) != 4 {
		t.Fatalf("expected 4 tools, got %d", len(tools))
	}

	wantNames := map[string]bool{
		"list_secrets":   true,
		"lease_secret":   true,
		"revoke_secret":  true,
		"execute_secret": true,
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
		if r.Method != http.MethodGet || r.URL.Path != "/v1/secrets/ns1/mykey" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"namespace":"ns1","name":"mykey","value":"s3cr3t"}`)
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

// ---- tools/call lease_secret (NOT found / no value / bad JSON) ---------

func TestCallTool_LeaseSecret_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"NotFound","detail":"secret ns1/missing not found at /var/lib/vault"}`)
	}))
	defer ts.Close()
	s := newTestServer(ts)

	text, isError := s.callTool("lease_secret", map[string]any{"namespace": "ns1", "name": "missing"})
	if !isError {
		t.Fatalf("expected isError=true; text=%s", text)
	}
	if text != "backend error: 404 Not Found" {
		t.Errorf("expected sanitized 404, got %q", text)
	}
}

func TestCallTool_LeaseSecret_NoValueOrBadJSON(t *testing.T) {
	for body, want := range map[string]string{
		`{"name":"k","namespace":"ns1"}`: "backend did not return a secret value",
		`not json`:                       "backend returned an invalid response",
	} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, body)
		}))
		s := newTestServer(ts)
		text, isError := s.callTool("lease_secret", map[string]any{"namespace": "ns1", "name": "k"})
		ts.Close()
		if !isError || text != want {
			t.Errorf("body %q: got (%q, %v), want (%q, true)", body, text, isError, want)
		}
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

// ---- tools/call execute_secret ----------------------------------------

func TestCallTool_ExecuteSecret_OK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method %s", r.Method)
		}
		wantPath := "/v1/secrets/ns1/mykey/use"
		if r.URL.Path != wantPath {
			t.Errorf("unexpected path %s, want %s", r.URL.Path, wantPath)
		}

		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode body: %v", err)
		}

		if body["action"] != "echo" {
			t.Errorf("expected action 'echo', got %v", body["action"])
		}
		if body["agent"] != "mcp-client" {
			t.Errorf("expected agent 'mcp-client', got %v", body["agent"])
		}

		params, ok := body["params"].(map[string]any)
		if !ok || params["message"] != "hello" {
			t.Errorf("expected params.message 'hello', got %v", body["params"])
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true,"result":{"status":"completed"}}`)
	}))
	defer ts.Close()
	s := newTestServer(ts)

	args := map[string]any{
		"namespace": "ns1",
		"name":      "mykey",
		"action":    "echo",
		"params":    map[string]any{"message": "hello"},
	}
	text, isError := s.callTool("execute_secret", args)
	if isError {
		t.Fatalf("expected isError=false; text=%s", text)
	}
	if !strings.Contains(text, `"status":"completed"`) {
		t.Errorf("expected 'status: completed' in text, got %q", text)
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

// ---- protocol edge cases (spec compliance for real MCP clients) --------

func TestHandle_PingAndVersionNegotiation(t *testing.T) {
	s := NewServer("http://127.0.0.1:1", "")
	if r := s.handle(makeReq(1, "ping", nil)); r == nil || r.Error != nil {
		t.Fatalf("ping: %+v", r)
	}
	for req, want := range map[string]string{
		"2025-06-18": "2025-06-18",
		"2024-11-05": "2024-11-05",
		"1999-01-01": supportedProtocolVersions[0],
		"":           supportedProtocolVersions[0],
	} {
		r := s.handle(makeReq(1, "initialize", map[string]any{"protocolVersion": req}))
		got := r.Result.(map[string]any)["protocolVersion"]
		if got != want {
			t.Errorf("initialize(%q) negotiated %v, want %s", req, got, want)
		}
	}
	// A request without an id is a notification: never answered.
	if r := s.handle(rpcRequest{JSONRPC: "2.0", Method: "tools/list"}); r != nil {
		t.Errorf("notification answered: %+v", r)
	}
}

func TestHandle_ToolsCallInvalidParams(t *testing.T) {
	s := NewServer("http://127.0.0.1:1", "")
	r := s.handle(rpcRequest{JSONRPC: "2.0", ID: json.RawMessage("3"), Method: "tools/call", Params: json.RawMessage(`[1]`)})
	if r == nil || r.Error == nil || r.Error.Code != -32602 {
		t.Fatalf("want -32602, got %+v", r)
	}
}

func TestServe_ParseErrorAndBlankLines(t *testing.T) {
	s := NewServer("http://127.0.0.1:1", "")
	var out strings.Builder
	in := strings.NewReader("\n   \n{not json\n" + `{"jsonrpc":"2.0","id":9,"method":"ping"}` + "\n")
	if err := s.Serve(in, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "-32700") || !strings.Contains(lines[1], `"id":9`) {
		t.Fatalf("unexpected output %q", out.String())
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("closed") }

func TestServe_WriteErrorStops(t *testing.T) {
	s := NewServer("http://127.0.0.1:1", "")
	for _, in := range []string{"{bad\n", `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n"} {
		if err := s.Serve(strings.NewReader(in), failWriter{}); err == nil {
			t.Errorf("input %q: expected write error", in)
		}
	}
}

func TestCallTool_BackendErrorsSanitizedAndUnreachable(t *testing.T) {
	const leak = "/var/lib/rgt/state.db stack trace"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, strings.Repeat(leak, 100))
	}))
	defer ts.Close()
	s := newTestServer(ts)
	var logBuf strings.Builder
	s.SetLogger(log.New(&logBuf, "", 0))

	args := map[string]any{"namespace": "ns", "name": "n", "action": "a"}
	for _, tool := range []string{"list_secrets", "lease_secret", "revoke_secret", "execute_secret"} {
		text, isErr := s.callTool(tool, args)
		if !isErr || text != "backend error: 403 Forbidden" {
			t.Errorf("%s: got (%q, %v)", tool, text, isErr)
		}
	}
	if !strings.Contains(logBuf.String(), leak) {
		t.Error("backend body not logged")
	}
	if len(logBuf.String()) > 4*(maxLoggedErrorBody+200) {
		t.Errorf("log not truncated: %d bytes", len(logBuf.String()))
	}

	// Unreachable backend (closed port) for every tool.
	dead := NewServer("http://127.0.0.1:1", "")
	dead.SetLogger(nil)
	for _, tool := range []string{"list_secrets", "lease_secret", "revoke_secret", "execute_secret"} {
		if text, isErr := dead.callTool(tool, args); !isErr || !strings.HasPrefix(text, "backend unreachable") {
			t.Errorf("%s unreachable: got (%q, %v)", tool, text, isErr)
		}
	}
	// Bad backend URL makes request construction fail.
	bad := NewServer("http://[::1", "")
	if _, isErr := bad.callTool("list_secrets", args); !isErr {
		t.Error("bad URL: expected error")
	}
	// Non-string argument is treated as empty.
	if _, isErr := s.callTool("list_secrets", map[string]any{"namespace": 7}); !isErr {
		t.Error("expected backend error")
	}
}
