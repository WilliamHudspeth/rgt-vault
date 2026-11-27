package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const testCapToken = "eyJhIjoiYiJ9.c2lnbmF0dXJl-CAPTOKEN-MARKER"

// recordingBackend records every request and answers with a canned response.
type recordingBackend struct {
	mu     sync.Mutex
	status int
	body   string
	reqs   []recordedReq
}

type recordedReq struct {
	Method, URI, Auth string
	Body              map[string]any
}

func (b *recordingBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	rec := recordedReq{Method: r.Method, URI: r.URL.RequestURI(), Auth: r.Header.Get("Authorization")}
	_ = json.Unmarshal(raw, &rec.Body)
	b.mu.Lock()
	b.reqs = append(b.reqs, rec)
	status, body := b.status, b.body
	b.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (b *recordingBackend) set(status int, body string) {
	b.mu.Lock()
	b.status, b.body = status, body
	b.mu.Unlock()
}

func (b *recordingBackend) last(t *testing.T) recordedReq {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.reqs) == 0 {
		t.Fatal("backend was not called")
	}
	return b.reqs[len(b.reqs)-1]
}

func (b *recordingBackend) calls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.reqs)
}

// capServer builds a Server over a recording backend with a captured log.
func capServer(t *testing.T) (*Server, *recordingBackend, *bytes.Buffer) {
	t.Helper()
	b := &recordingBackend{}
	ts := httptest.NewServer(b)
	t.Cleanup(ts.Close)
	s := NewServer(ts.URL, "agent-bearer-SECRET")
	logs := &bytes.Buffer{}
	s.SetLogger(log.New(logs, "", 0))
	return s, b, logs
}

func TestNewServer_DefaultBackendURL(t *testing.T) {
	for _, in := range []string{"", "   "} {
		if got := NewServer(in, "t").backendURL; got != "http://127.0.0.1:8765" {
			t.Errorf("NewServer(%q) backend = %q, want the 8765 default", in, got)
		}
	}
	if DefaultBackendURL != "http://127.0.0.1:8765" {
		t.Errorf("DefaultBackendURL = %q", DefaultBackendURL)
	}
	if got := NewServer("http://example.test:1/", "t").backendURL; got != "http://example.test:1" {
		t.Errorf("trailing slash kept: %q", got)
	}
}

func TestExecuteCapability_RequestAndResult(t *testing.T) {
	s, b, _ := capServer(t)
	b.set(200, `{"ok":true,"capability":"secrets.echo","result":{"echo":{"msg":"hi"},"agent":"bot"}}`)

	text, isErr := s.callTool("execute_capability", map[string]any{
		"capability": "secrets.echo", "agent_id": "bot", "capability_token": testCapToken,
		"version": float64(2), "payload": map[string]any{"msg": "hi"},
	})
	if isErr {
		t.Fatalf("unexpected tool error: %s", text)
	}
	var out struct {
		OK     bool           `json:"ok"`
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil || !out.OK || out.Result["agent"] != "bot" {
		t.Fatalf("result = %q (%v)", text, err)
	}
	if strings.Contains(text, testCapToken) {
		t.Fatal("capability token echoed in the result")
	}
	req := b.last(t)
	if req.Method != "POST" || req.URI != "/v1/capabilities/execute" || req.Auth != "Bearer agent-bearer-SECRET" {
		t.Fatalf("request = %+v", req)
	}
	for k, want := range map[string]any{
		"capability": "secrets.echo", "agent_id": "bot", "capability_token": testCapToken, "capability_version": float64(2),
	} {
		if req.Body[k] != want {
			t.Errorf("body[%s] = %v, want %v", k, req.Body[k], want)
		}
	}
	if p, _ := req.Body["payload"].(map[string]any); p["msg"] != "hi" {
		t.Errorf("payload = %v", req.Body["payload"])
	}
}

func TestExecuteCapability_Defaults(t *testing.T) {
	s, b, _ := capServer(t)
	b.set(200, `{"ok":true}`) // no result key: null
	if err := s.SetAgent("mcp-bot"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCapabilityToken("  " + testCapToken + "\n"); err != nil {
		t.Fatal(err)
	}
	text, isErr := s.callTool("execute_capability", map[string]any{"capability": "secrets.echo"})
	if isErr || text != `{"ok":true,"result":null}` {
		t.Fatalf("got (%q, %v)", text, isErr)
	}
	req := b.last(t)
	if req.Body["agent_id"] != "mcp-bot" || req.Body["capability_token"] != testCapToken || req.Body["capability_version"] != float64(1) {
		t.Errorf("defaults not applied: %v", req.Body)
	}
	if p, present := req.Body["payload"]; !present || p != nil {
		t.Errorf("payload = %v, want JSON null", p)
	}

	// A tool argument overrides the configured token.
	s.callTool("execute_capability", map[string]any{"capability": "c", "capability_token": "other.token"})
	if got := b.last(t).Body["capability_token"]; got != "other.token" {
		t.Errorf("argument token not used: %v", got)
	}
	// Clearing the default.
	if err := s.SetCapabilityToken(""); err != nil {
		t.Fatal(err)
	}
	if text, isErr := s.callTool("execute_capability", map[string]any{"capability": "c"}); !isErr || !strings.HasPrefix(text, "missing capability token") {
		t.Errorf("after clearing: (%q, %v)", text, isErr)
	}
}

func TestExecuteCapability_ArgumentValidation(t *testing.T) {
	s, b, _ := capServer(t)
	base := func(over map[string]any) map[string]any {
		a := map[string]any{"capability": "secrets.echo", "agent_id": "bot", "capability_token": testCapToken}
		for k, v := range over {
			if v == nil {
				delete(a, k)
			} else {
				a[k] = v
			}
		}
		return a
	}
	cases := []struct {
		name string
		args map[string]any
		want string // prefix of the error
	}{
		{"agent not string", base(map[string]any{"agent_id": 5}), "invalid agent_id: must be a string"},
		{"agent bad chars", base(map[string]any{"agent_id": "bo t/../"}), "invalid agent_id:"},
		{"token not string", base(map[string]any{"capability_token": 7}), "invalid capability_token: must be a string"},
		{"token whitespace", base(map[string]any{"capability_token": "a b"}), "invalid capability_token"},
		{"token control", base(map[string]any{"capability_token": "a\x00b"}), "invalid capability_token"},
		{"token too long", base(map[string]any{"capability_token": strings.Repeat("a", maxCapabilityTokenBytes+1)}), "invalid capability_token"},
		{"token missing", base(map[string]any{"capability_token": nil}), "missing capability token"},
		{"version zero", base(map[string]any{"version": float64(0)}), "invalid version"},
		{"version fraction", base(map[string]any{"version": 1.5}), "invalid version"},
		{"version huge", base(map[string]any{"version": float64(1 << 40)}), "invalid version"},
		{"version string junk", base(map[string]any{"version": "v2"}), "invalid version"},
		{"version string zero", base(map[string]any{"version": "0"}), "invalid version"},
		{"version bool", base(map[string]any{"version": true}), "invalid version"},
		{"payload not object", base(map[string]any{"payload": []any{1}}), "invalid payload: must be an object"},
		{"capability missing", base(map[string]any{"capability": nil}), "missing required string argument: capability"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := b.calls()
			text, isErr := s.callTool("execute_capability", c.args)
			if !isErr || !strings.HasPrefix(text, c.want) {
				t.Fatalf("got (%q, %v), want error prefix %q", text, isErr, c.want)
			}
			if strings.Contains(text, testCapToken) {
				t.Fatal("token echoed")
			}
			if b.calls() != before {
				t.Fatal("backend called for an invalid request")
			}
		})
	}

	// Accepted version spellings.
	for in, want := range map[any]float64{float64(3): 3, "2": 2, "1.0": 1, " 4 ": 4} {
		b.set(200, `{"result":1}`)
		if text, isErr := s.callTool("execute_capability", base(map[string]any{"version": in})); isErr {
			t.Fatalf("version %v rejected: %s", in, text)
		}
		if got := b.last(t).Body["capability_version"]; got != want {
			t.Errorf("version %v sent as %v, want %v", in, got, want)
		}
	}
}

func TestExecuteCapability_ErrorMapping(t *testing.T) {
	longDetail := strings.Repeat("x", 500)
	cases := []struct {
		name   string
		status int
		body   string
		want   string // exact, or prefix when ending in "…"
	}{
		{"401", 401, `{"error":"ServerAuthError","detail":"bad bearer"}`, "unauthorized"},
		{"403 policy", 403, `{"error":"PolicyDeniedError","detail":"rule 3 (internal) denied"}`, "unauthorized"},
		{"429", 429, `{"error":"PermissionError","detail":"rate limit"}`, "rate limited"},
		{"404", 404, `{"error":"CapabilityNotFoundError","detail":"no such capability at /srv/x"}`, "capability not found"},
		{"400 detail", 400, `{"error":"CapabilityVersionError","detail":"capability 'a' has no version 9"}`, "invalid request: capability 'a' has no version 9"},
		{"400 control chars", 400, "{\"detail\":\"line1\\nline2\\u001b[31m\"}", "invalid request: line1 line2 [31m"},
		{"400 token in detail", 400, `{"detail":"bad token ` + testCapToken + ` or ` + "agent-bearer-SECRET" + `"}`, "invalid request: bad token [redacted] or [redacted]"},
		{"400 bounded", 400, `{"detail":"` + longDetail + `"}`, "invalid request: " + strings.Repeat("x", maxErrorDetailRunes) + "..."},
		{"400 no detail", 400, `{}`, "invalid request"},
		{"400 not json", 400, `<html>`, "invalid request"},
		{"422", 422, `{"detail":"field required"}`, "invalid request: field required"},
		{"500", 500, `{"error":"ActionExecutionError","detail":"capability 'a' failed; see server logs"}`, "execution_failed"},
		{"503", 503, ``, "execution_failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, b, logs := capServer(t)
			b.set(c.status, c.body)
			text, isErr := s.callTool("execute_capability", map[string]any{
				"capability": "a", "agent_id": "bot", "capability_token": testCapToken,
			})
			if !isErr || text != c.want {
				t.Fatalf("got (%q, %v), want %q", text, isErr, c.want)
			}
			for _, secret := range []string{testCapToken, "agent-bearer-SECRET"} {
				if strings.Contains(text, secret) || strings.Contains(logs.String(), secret) {
					t.Fatalf("credential %q leaked (result %q, log %q)", secret, text, logs.String())
				}
			}
			if !strings.Contains(logs.String(), "execute_capability backend error") {
				t.Errorf("backend error not logged: %q", logs.String())
			}
		})
	}
}

func TestExecuteCapability_Unreachable_BadResponse(t *testing.T) {
	s, b, logs := capServer(t)
	b.set(200, `not json`)
	if text, isErr := s.callTool("execute_capability", map[string]any{"capability": "a", "capability_token": testCapToken}); !isErr || text != "backend returned an invalid response" {
		t.Fatalf("bad JSON: (%q, %v)", text, isErr)
	}

	dead := NewServer("http://127.0.0.1:1", "agent-bearer-SECRET")
	dead.SetLogger(log.New(logs, "", 0))
	for _, tool := range []string{"execute_capability", "list_capabilities"} {
		text, isErr := dead.callTool(tool, map[string]any{"capability": "a", "capability_token": testCapToken})
		if !isErr || text != "backend unreachable" {
			t.Errorf("%s unreachable: (%q, %v)", tool, text, isErr)
		}
	}
	if strings.Contains(logs.String(), testCapToken) || strings.Contains(logs.String(), "agent-bearer-SECRET") {
		t.Fatalf("credentials in the log: %q", logs.String())
	}
}

func TestExecuteCapability_RedactsResult(t *testing.T) {
	// Defence in depth: a backend result that contains the token is redacted.
	s, b, _ := capServer(t)
	b.set(200, `{"result":{"echo":"`+testCapToken+`"}}`)
	text, isErr := s.callTool("execute_capability", map[string]any{"capability": "a", "capability_token": testCapToken})
	if isErr || strings.Contains(text, testCapToken) || !strings.Contains(text, "[redacted]") {
		t.Fatalf("got (%q, %v)", text, isErr)
	}
}

func TestSetCapabilityToken_Validation(t *testing.T) {
	s := NewServer("http://x", "t")
	for _, bad := range []string{"a b", "a\tb", "a\nb", "a\x00b", strings.Repeat("a", maxCapabilityTokenBytes+1)} {
		if err := s.SetCapabilityToken(bad); err == nil {
			t.Errorf("SetCapabilityToken(%q) accepted", bad)
		}
	}
	if s.capToken != "" {
		t.Fatal("rejected token was stored")
	}
}

func TestLoadCapabilityTokenFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	s := NewServer("http://x", "t")
	if err := s.LoadCapabilityTokenFile(write("ok", "\n  "+testCapToken+"  \r\n")); err != nil || s.capToken != testCapToken {
		t.Fatalf("load: %v (token %q)", err, s.capToken)
	}
	for name, content := range map[string]string{
		"empty":    " \n",
		"inner-ws": "abc def\n",
		"huge":     strings.Repeat("a", maxCapabilityTokenBytes+1),
	} {
		s2 := NewServer("http://x", "t")
		err := s2.LoadCapabilityTokenFile(write(name, content))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "abc") {
			t.Errorf("%s: token content in error %q", name, err)
		}
		if s2.capToken != "" {
			t.Errorf("%s: token stored", name)
		}
	}
	if err := s.LoadCapabilityTokenFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file accepted")
	}
	if err := s.LoadCapabilityTokenFile(dir); err == nil {
		t.Error("directory accepted")
	}
}

func TestListCapabilities(t *testing.T) {
	s, b, _ := capServer(t)
	b.set(200, `{"agent":"bot","capabilities":[
		{"name":"secrets.echo","description":"d","supported_versions":[1],"params_schema":["msg"],"handler":"LEAK","extra":1}],
		"internal":"LEAK"}`)
	text, isErr := s.callTool("list_capabilities", map[string]any{"agent": "bot"})
	if isErr || strings.Contains(text, "LEAK") {
		t.Fatalf("got (%q, %v)", text, isErr)
	}
	want := `{"agent":"bot","capabilities":[{"name":"secrets.echo","description":"d","supported_versions":[1],"params_schema":["msg"]}]}`
	if text != want {
		t.Fatalf("got %s\nwant %s", text, want)
	}
	if r := b.last(t); r.Method != "GET" || r.URI != "/v1/capabilities/list?agent=bot" || r.Auth != "Bearer agent-bearer-SECRET" {
		t.Fatalf("request = %+v", r)
	}

	// Default agent is the configured label.
	if err := s.SetAgent("label.1"); err != nil {
		t.Fatal(err)
	}
	b.set(200, `{"agent":"label.1"}`)
	text, isErr = s.callTool("list_capabilities", nil)
	if isErr || text != `{"agent":"label.1","capabilities":[]}` {
		t.Fatalf("empty list: (%q, %v)", text, isErr)
	}
	if b.last(t).URI != "/v1/capabilities/list?agent=label.1" {
		t.Errorf("default agent not used: %s", b.last(t).URI)
	}
}

func TestListCapabilities_Errors(t *testing.T) {
	s, b, logs := capServer(t)
	before := b.calls()
	for _, args := range []map[string]any{{"agent": 5}, {"agent": "a b"}, {"agent": "x/../y"}} {
		if text, isErr := s.callTool("list_capabilities", args); !isErr || !strings.HasPrefix(text, "invalid agent") {
			t.Errorf("%v: (%q, %v)", args, text, isErr)
		}
	}
	if b.calls() != before {
		t.Fatal("backend called for invalid agent")
	}
	b.set(403, `{"error":"PolicyDeniedError","detail":"INTERNAL-POLICY-DETAIL"}`)
	if text, isErr := s.callTool("list_capabilities", map[string]any{"agent": "bot"}); !isErr || text != "backend error: 403 Forbidden" {
		t.Errorf("403: (%q, %v)", text, isErr)
	}
	if strings.Contains(fmt.Sprint(logs), "agent-bearer-SECRET") {
		t.Error("bearer token in log")
	}
	b.set(200, `[1]`)
	if text, isErr := s.callTool("list_capabilities", map[string]any{"agent": "bot"}); !isErr || text != "backend returned an invalid response" {
		t.Errorf("bad json: (%q, %v)", text, isErr)
	}
}

func rpc(t *testing.T, s *Server, method string, params any) *rpcResponse {
	t.Helper()
	resp := s.handle(makeReq(1, method, params))
	if resp == nil {
		t.Fatalf("%s: nil response", method)
	}
	return resp
}

func TestResources_ListAndInitialize(t *testing.T) {
	s, _, _ := capServer(t)
	init := resultMap(t, rpc(t, s, "initialize", map[string]any{"protocolVersion": "2025-06-18"}))
	caps, _ := init["capabilities"].(map[string]any)
	if _, ok := caps["resources"]; !ok {
		t.Fatalf("initialize does not advertise resources: %v", caps)
	}
	list := resultMap(t, rpc(t, s, "resources/list", nil))
	res, _ := list["resources"].([]any)
	if len(res) != 1 {
		t.Fatalf("resources = %v", res)
	}
	r0 := res[0].(map[string]any)
	if r0["uri"] != "vault://policy" || r0["mimeType"] != "application/json" || r0["name"] != "policy" {
		t.Fatalf("resource = %v", r0)
	}
	tpl := resultMap(t, rpc(t, s, "resources/templates/list", nil))
	if v, ok := tpl["resourceTemplates"].([]any); !ok || len(v) != 0 {
		t.Fatalf("templates = %v", tpl)
	}
}

func readPolicy(t *testing.T, s *Server) map[string]any {
	t.Helper()
	resp := rpc(t, s, "resources/read", map[string]any{"uri": "vault://policy"})
	if resp.Error != nil {
		t.Fatalf("read: %+v", resp.Error)
	}
	contents, _ := resultMap(t, resp)["contents"].([]any)
	if len(contents) != 1 {
		t.Fatalf("contents = %v", contents)
	}
	c := contents[0].(map[string]any)
	if c["uri"] != "vault://policy" || c["mimeType"] != "application/json" {
		t.Fatalf("content = %v", c)
	}
	var summary map[string]any
	if err := json.Unmarshal([]byte(c["text"].(string)), &summary); err != nil {
		t.Fatal(err)
	}
	return summary
}

func TestResources_PolicySummary(t *testing.T) {
	s, b, logs := capServer(t)

	sum := readPolicy(t, s)
	if v, present := sum["rules"]; !present || v != nil || sum["default_ttl"] != float64(300) || len(sum) != 2 {
		t.Fatalf("no policy file: %v", sum)
	}

	dir := t.TempDir()
	policyFile := filepath.Join(dir, "policy.yaml")
	secretRule := "SECRET-AGENT-NAME"
	yaml := "rules:\n  - effect: allow\n    agent: " + secretRule + "\n    action: read\n  - effect: deny\n    agent: \"*\"\n    action: write\n"
	if err := os.WriteFile(policyFile, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	s.SetPolicyFile(policyFile)
	resp := rpc(t, s, "resources/read", map[string]any{"uri": "vault://policy"})
	raw, _ := json.Marshal(resp.Result)
	if strings.Contains(string(raw), secretRule) {
		t.Fatalf("rule contents leaked: %s", raw)
	}
	if sum := readPolicy(t, s); sum["rules"] != float64(2) || sum["default_ttl"] != float64(300) || len(sum) != 2 {
		t.Fatalf("with policy file: %v", sum)
	}

	// An unreadable/invalid policy yields null and a log line, never the text.
	if err := os.WriteFile(policyFile, []byte("rules: [unclosed SECRET-TEXT"), 0o600); err != nil {
		t.Fatal(err)
	}
	if sum := readPolicy(t, s); sum["rules"] != nil {
		t.Fatalf("invalid policy: %v", sum)
	}
	s.SetPolicyFile(filepath.Join(dir, "missing.yaml"))
	if sum := readPolicy(t, s); sum["rules"] != nil {
		t.Fatalf("missing policy: %v", sum)
	}
	if !strings.Contains(logs.String(), "policy summary") {
		t.Errorf("policy load failure not logged: %q", logs.String())
	}
	if b.calls() != 0 {
		t.Error("policy summary must not call the backend")
	}
}

func TestResources_ReadErrors(t *testing.T) {
	s, _, _ := capServer(t)
	resp := rpc(t, s, "resources/read", map[string]any{"uri": "vault://secrets"})
	if resp.Error == nil || resp.Error.Code != -32002 {
		t.Fatalf("unknown uri: %+v", resp)
	}
	for _, uri := range []string{"file:///etc/passwd", "vault://policy/../x", ""} {
		if resp := rpc(t, s, "resources/read", map[string]any{"uri": uri}); resp.Error == nil || resp.Error.Code != -32002 {
			t.Errorf("uri %q: %+v", uri, resp)
		}
	}
	bad := s.handle(rpcRequest{JSONRPC: "2.0", ID: json.RawMessage("2"), Method: "resources/read", Params: json.RawMessage(`[1]`)})
	if bad.Error == nil || bad.Error.Code != -32602 {
		t.Fatalf("bad params: %+v", bad)
	}
}

func TestCleanText(t *testing.T) {
	if got := cleanText("  a\tb\x00c\u0085d�e  ", 50); got != "a b c d e" {
		t.Errorf("cleanText = %q", got)
	}
	if got := cleanText("abcdef", 3); got != "abc..." {
		t.Errorf("cleanText cap = %q", got)
	}
}
