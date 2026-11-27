package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

	resp := s.handle(rpcRequest{JSONRPC: "2.0", Method: "notifications/initialized"})
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
	if text != `{"namespace":"ns1","secrets":[{"name":"k"}]}` {
		t.Errorf("unexpected list output %q", text)
	}
}

// list_secrets must never pass plaintext through, even if the backend's list
// route still includes values (the current stub store does).
func TestCallTool_ListSecrets_StripsValues(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"namespace":"ns1","secrets":[{"name":"k","value":"PLAINTEXT","namespace":"ns1","created_at":"t"}]}`)
	}))
	defer ts.Close()
	s := newTestServer(ts)
	text, isError := s.callTool("list_secrets", map[string]any{"namespace": "ns1"})
	if isError || strings.Contains(text, "PLAINTEXT") || !strings.Contains(text, `"created_at":"t"`) {
		t.Fatalf("got (%q, %v)", text, isError)
	}
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "nope") }))
	defer ts2.Close()
	if text, isError := newTestServer(ts2).callTool("list_secrets", map[string]any{"namespace": "ns1"}); !isError || text != "backend returned an invalid response" {
		t.Fatalf("bad JSON: got (%q, %v)", text, isError)
	}
}

func TestCallTool_RequiredArgs(t *testing.T) {
	hit := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer ts.Close()
	s := newTestServer(ts)
	for tool, args := range map[string]map[string]any{
		"list_secrets":   {},
		"lease_secret":   {"namespace": "ns"},
		"revoke_secret":  {"name": "n"},
		"execute_secret": {"namespace": "ns", "name": "n"},
	} {
		text, isError := s.callTool(tool, args)
		if !isError || !strings.HasPrefix(text, "missing required string argument") {
			t.Errorf("%s: got (%q, %v)", tool, text, isError)
		}
	}
	if hit {
		t.Error("backend was called despite missing arguments")
	}
}

func TestHandle_InvalidRequests(t *testing.T) {
	s := NewServer("http://127.0.0.1:1", "")
	for _, req := range []rpcRequest{
		{JSONRPC: "2.0", ID: json.RawMessage("null"), Method: "ping"},
		{JSONRPC: "1.0", ID: json.RawMessage("1"), Method: "ping"},
		{JSONRPC: "2.0", ID: json.RawMessage("1")},
	} {
		r := s.handle(req)
		if r == nil || r.Error == nil || r.Error.Code != -32600 {
			t.Errorf("%+v: want -32600, got %+v", req, r)
		}
	}
	// A notifications/* method sent WITH an id is a request and gets an answer.
	if r := s.handle(makeReq(4, "notifications/initialized", nil)); r == nil || r.Error == nil {
		t.Errorf("request with id must be answered, got %+v", r)
	}
}

// ---- tools/call lease_secret (found) ----------------------------------

func TestCallTool_LeaseSecret_Found(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.Method != http.MethodGet || r.URL.Path != "/v1/secrets" || q.Get("namespace") != "ns1" || q.Get("name") != "mykey" {
			t.Errorf("unexpected request %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
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

// ---- tools/call lease_secret (NOT found / no value / bad JSON / errors) --

func TestCallTool_LeaseSecret_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The server answers an unknown exact name with an empty list.
		fmt.Fprint(w, `{"namespace":"ns1","secrets":[]}`)
	}))
	defer ts.Close()
	s := newTestServer(ts)

	text, isError := s.callTool("lease_secret", map[string]any{"namespace": "ns1", "name": "missing"})
	if !isError || text != "secret not found" {
		t.Fatalf("got (%q, %v)", text, isError)
	}
}

func TestCallTool_LeaseSecret_BackendErrorSanitized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"NotFound","detail":"secret ns1/missing not found at /var/lib/vault"}`)
	}))
	defer ts.Close()
	text, isError := newTestServer(ts).callTool("lease_secret", map[string]any{"namespace": "ns1", "name": "missing"})
	if !isError || text != "backend error: 404 Not Found" {
		t.Errorf("expected sanitized 404, got (%q, %v)", text, isError)
	}
}

func TestCallTool_LeaseSecret_NoValueOrBadJSON(t *testing.T) {
	for body, want := range map[string]string{
		`{"secrets":[{"name":"k"}]}`:                 "backend did not return a secret value",
		`{"secrets":[{"name":"other","value":"x"}]}`: "secret not found",
		`not json`: "backend returned an invalid response",
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
		if text, isErr := dead.callTool(tool, args); !isErr || text != "backend unreachable" {
			t.Errorf("%s unreachable: got (%q, %v)", tool, text, isErr)
		}
	}
	// Bad backend URL makes request construction fail.
	bad := NewServer("http://[::1", "")
	if _, isErr := bad.callTool("list_secrets", args); !isErr {
		t.Error("bad URL: expected error")
	}
	// Non-string argument is treated as missing.
	if text, isErr := s.callTool("list_secrets", map[string]any{"namespace": 7}); !isErr || !strings.HasPrefix(text, "missing required") {
		t.Errorf("non-string arg: got (%q, %v)", text, isErr)
	}
}

// ---- tool table: tools/list schema and callTool enforcement agree ------

func TestToolsListRequiredMatchesCallToolEnforcement(t *testing.T) {
	var hits atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, `{"namespace":"x","secrets":[]}`)
	}))
	defer ts.Close()
	s := newTestServer(ts)

	raw, _ := json.Marshal(s.handle(makeReq(1, "tools/list", nil)).Result)
	var listed struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Properties map[string]any `json:"properties"`
				Required   []string       `json:"required"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) != len(toolSpecs) {
		t.Fatalf("tools/list has %d tools, table has %d", len(listed.Tools), len(toolSpecs))
	}
	for _, tool := range listed.Tools {
		spec, ok := lookupTool(tool.Name)
		if !ok {
			t.Fatalf("listed tool %q is not callable", tool.Name)
		}
		full := map[string]any{}
		for _, k := range tool.InputSchema.Required {
			full[k] = "x"
		}
		if text, _ := s.callTool(tool.Name, full); strings.HasPrefix(text, "unknown tool") || strings.HasPrefix(text, "missing required") {
			t.Errorf("%s with all required args: got %q (no handler?)", tool.Name, text)
		}
		if fmt.Sprint(tool.InputSchema.Required) != fmt.Sprint(spec.Required) {
			t.Errorf("%s: listed required %v != enforced %v", tool.Name, tool.InputSchema.Required, spec.Required)
		}
		// Enforcement: dropping any one required arg is rejected, naming it,
		// without a backend call.
		before := hits.Load()
		for _, drop := range tool.InputSchema.Required {
			if _, ok := tool.InputSchema.Properties[drop]; !ok {
				t.Errorf("%s: required %q missing from properties", tool.Name, drop)
			}
			args := map[string]any{}
			for _, k := range tool.InputSchema.Required {
				if k != drop {
					args[k] = "x"
				}
			}
			text, isErr := s.callTool(tool.Name, args)
			if !isErr || text != "missing required string argument: "+drop {
				t.Errorf("%s without %s: got (%q, %v)", tool.Name, drop, text, isErr)
			}
		}
		if hits.Load() != before {
			t.Errorf("%s: backend called despite missing required args", tool.Name)
		}
	}
}

// ---- execute_secret agent / purpose ------------------------------------

func TestExecuteSecret_AgentAndPurpose(t *testing.T) {
	var got []map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		got = append(got, b)
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer ts.Close()
	s := newTestServer(ts)
	base := map[string]any{"namespace": "ns", "name": "n", "action": "a"}
	with := func(extra map[string]any) map[string]any {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// Defaults.
	if _, isErr := s.callTool("execute_secret", base); isErr {
		t.Fatal("default call failed")
	}
	// Whitespace-only purpose falls back to the default.
	if _, isErr := s.callTool("execute_secret", with(map[string]any{"purpose": "   "})); isErr {
		t.Fatal("blank purpose failed")
	}
	// Configured agent + custom purpose (NFC-normalised by validation).
	if err := s.SetAgent("deploy-bot@ci"); err != nil {
		t.Fatal(err)
	}
	if _, isErr := s.callTool("execute_secret", with(map[string]any{"purpose": "rotate cafe\u0301 creds"})); isErr {
		t.Fatal("custom purpose failed")
	}
	want := [][2]string{
		{DefaultAgent, defaultPurpose},
		{DefaultAgent, defaultPurpose},
		{"deploy-bot@ci", "rotate caf\u00e9 creds"}, // NFD in, NFC out
	}
	if len(got) != len(want) {
		t.Fatalf("backend saw %d calls", len(got))
	}
	for i, w := range want {
		if got[i]["agent"] != w[0] || got[i]["purpose"] != w[1] {
			t.Errorf("call %d: agent=%v purpose=%v, want %v", i, got[i]["agent"], got[i]["purpose"], w)
		}
	}

	// Invalid purposes are rejected before any backend call.
	n := len(got)
	for _, bad := range []any{7, nil, true, []any{"x"}, strings.Repeat("p", maxPurposeLen+1),
		"bad\x00purpose", "\n", "\r\n", "\u2028", strings.Repeat(" ", maxPurposeLen+1)} {
		text, isErr := s.callTool("execute_secret", with(map[string]any{"purpose": bad}))
		if !isErr || !strings.HasPrefix(text, "invalid purpose") {
			t.Errorf("purpose %q: got (%q, %v)", bad, text, isErr)
		}
	}
	if len(got) != n {
		t.Error("invalid purpose reached the backend")
	}

	// Invalid agent labels are refused and leave the current one in place.
	for _, bad := range []string{"", "has space", strings.Repeat("a", 129), "semi;colon"} {
		if err := s.SetAgent(bad); err == nil {
			t.Errorf("SetAgent(%q) accepted", bad)
		}
	}
	if s.agent != "deploy-bot@ci" {
		t.Errorf("agent changed to %q", s.agent)
	}
}

func TestToolsListAdvertisesPurposeBound(t *testing.T) {
	s := NewServer("http://127.0.0.1:1", "")
	raw, _ := json.Marshal(s.handle(makeReq(1, "tools/list", nil)).Result)
	var listed struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Properties map[string]map[string]any `json:"properties"`
				Required   []string                  `json:"required"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &listed); err != nil {
		t.Fatal(err)
	}
	for _, tool := range listed.Tools {
		if tool.Name != "execute_secret" {
			continue
		}
		p := tool.InputSchema.Properties["purpose"]
		if p["type"] != "string" || p["maxLength"] != float64(256) {
			t.Errorf("purpose schema = %v", p)
		}
		for _, r := range tool.InputSchema.Required {
			if r == "purpose" {
				t.Error("purpose must stay optional")
			}
		}
		return
	}
	t.Fatal("execute_secret not listed")
}
