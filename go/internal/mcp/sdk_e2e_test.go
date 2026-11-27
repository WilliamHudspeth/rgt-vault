package mcp_test

// End-to-end contract test (RGT-159): the official MCP Go SDK client drives
// the rgt-vault stdio MCP server against an httptest vault backend, both over
// in-process pipes and as a real child process speaking over stdin/stdout.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	rgtmcp "rgt-vault-server/internal/mcp"
)

const (
	testToken = "e2e-test-token"
	// leakMarker appears only in backend error bodies; it must never reach
	// the MCP client.
	leakMarker = "INTERNAL-DETAIL /srv/vault/state.db goroutine 7 [running]"
)

// TestMain lets this test binary double as the stdio MCP server process for
// the CommandTransport test.
func TestMain(m *testing.M) {
	if os.Getenv("RGT_MCP_E2E_CHILD") == "1" {
		s := rgtmcp.NewServer(os.Getenv("RGT_MCP_E2E_BACKEND"), os.Getenv("RGT_MCP_E2E_TOKEN"))
		s.SetLogger(log.New(os.Stderr, "", 0))
		if err := s.Serve(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type call struct {
	Method, Path, Auth string
	Body               map[string]any
}

// fakeVault is a minimal stand-in for the rgt-vault HTTP API.
type fakeVault struct {
	mu      sync.Mutex
	secrets map[string]string // "ns/name" -> value
	revoked map[string]bool
	calls   []call
}

func newFakeVault() *fakeVault {
	return &fakeVault{
		secrets: map[string]string{"prod/api-key": "s3cr3t-value", "prod/broken": "x"},
		revoked: map[string]bool{},
	}
}

func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := call{Method: r.Method, Path: r.URL.RequestURI(), Auth: r.Header.Get("Authorization")}
	if r.Body != nil {
		raw, _ := io.ReadAll(r.Body)
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &c.Body)
		}
	}
	f.calls = append(f.calls, c)

	fail := func(code int) {
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"error":"boom","detail":%q}`, leakMarker)
	}
	if c.Auth != "Bearer "+testToken {
		fail(http.StatusUnauthorized)
		return
	}
	// Transitional plaintext path (D5): GET /v1/secrets?namespace=&name=.
	if r.Method == http.MethodGet && r.URL.Path == "/v1/secrets" {
		ns, nm := r.URL.Query().Get("namespace"), r.URL.Query().Get("name")
		out := []map[string]any{}
		if v, ok := f.secrets[ns+"/"+nm]; ok && !f.revoked[ns+"/"+nm] {
			out = append(out, map[string]any{"name": nm, "namespace": ns, "value": v})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"namespace": ns, "secrets": out})
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/secrets/"), "/")
	if len(parts) < 2 {
		fail(http.StatusNotFound)
		return
	}
	key := parts[0] + "/" + parts[1]
	val, ok := f.secrets[key]
	if !ok || f.revoked[key] {
		fail(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && len(parts) == 3 && parts[2] == "use":
		if parts[1] == "broken" {
			fail(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "action": c.Body["action"],
			"result": map[string]any{"status": "completed", "secret_len": len(val)}})
	case r.Method == http.MethodPost && len(parts) == 3 && parts[2] == "revoke":
		f.revoked[key] = true
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	default:
		fail(http.StatusMethodNotAllowed)
	}
}

func (f *fakeVault) snapshot() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func toolText(t *testing.T, res *sdk.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("want 1 content item, got %d", len(res.Content))
	}
	tc, ok := res.Content[0].(*sdk.TextContent)
	if !ok {
		t.Fatalf("content is %T, want *TextContent", res.Content[0])
	}
	return tc.Text
}

// runLifecycle performs initialize -> tools/list -> lease_secret ->
// execute_secret -> revoke_secret plus the error-sanitisation checks.
func runLifecycle(t *testing.T, transport sdk.Transport, fv *fakeVault) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client := sdk.NewClient(&sdk.Implementation{Name: "rgt-e2e-client", Version: "test"}, nil)
	cs, err := client.Connect(ctx, transport, nil) // initialize + notifications/initialized
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer cs.Close()

	init := cs.InitializeResult()
	if init == nil || init.ServerInfo == nil || init.ServerInfo.Name != "rgt-vault-mcp" {
		t.Fatalf("unexpected initialize result: %+v", init)
	}
	if !slices.Contains(sdk.SupportedProtocolVersions(), init.ProtocolVersion) {
		t.Fatalf("negotiated unsupported protocol version %q", init.ProtocolVersion)
	}
	if err := cs.Ping(ctx, nil); err != nil {
		t.Fatalf("ping: %v", err)
	}

	// tools/list
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
	}
	for _, want := range []string{"list_secrets", "lease_secret", "execute_secret", "revoke_secret"} {
		if !slices.Contains(names, want) {
			t.Errorf("tools/list missing %q (got %v)", want, names)
		}
	}

	callTool := func(name string, args map[string]any) *sdk.CallToolResult {
		t.Helper()
		res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("tools/call %s: %v", name, err)
		}
		return res
	}

	// lease_secret
	res := callTool("lease_secret", map[string]any{"namespace": "prod", "name": "api-key"})
	if res.IsError || toolText(t, res) != "s3cr3t-value" {
		t.Fatalf("lease_secret: isError=%v text=%q", res.IsError, toolText(t, res))
	}

	// execute_secret: plaintext must not come back.
	res = callTool("execute_secret", map[string]any{
		"namespace": "prod", "name": "api-key", "action": "http.get",
		"params": map[string]any{"url": "https://example.invalid/"},
	})
	if res.IsError {
		t.Fatalf("execute_secret failed: %q", toolText(t, res))
	}
	if txt := toolText(t, res); strings.Contains(txt, "s3cr3t-value") || !strings.Contains(txt, `"completed"`) {
		t.Fatalf("execute_secret result unexpected/leaks plaintext: %q", txt)
	}

	// execute_secret error path: backend body must be sanitised.
	res = callTool("execute_secret", map[string]any{"namespace": "prod", "name": "broken", "action": "http.get"})
	if !res.IsError {
		t.Fatal("execute_secret on broken backend: want isError")
	}
	if txt := toolText(t, res); txt != "backend error: 500 Internal Server Error" || strings.Contains(txt, "INTERNAL-DETAIL") {
		t.Fatalf("execute_secret error not sanitised: %q", txt)
	}

	// revoke_secret, then lease again -> sanitised 404.
	res = callTool("revoke_secret", map[string]any{"namespace": "prod", "name": "api-key"})
	if res.IsError || toolText(t, res) != "revoked prod/api-key" {
		t.Fatalf("revoke_secret: isError=%v text=%q", res.IsError, toolText(t, res))
	}
	res = callTool("lease_secret", map[string]any{"namespace": "prod", "name": "api-key"})
	if !res.IsError || toolText(t, res) != "secret not found" {
		t.Fatalf("lease after revoke: isError=%v text=%q", res.IsError, toolText(t, res))
	}

	// Backend side: every request authenticated, execute body well-formed.
	calls := fv.snapshot()
	if len(calls) != 5 {
		t.Fatalf("backend saw %d calls, want 5: %+v", len(calls), calls)
	}
	wantPaths := []string{
		"GET /v1/secrets?namespace=prod&name=api-key",
		"POST /v1/secrets/prod/api-key/use",
		"POST /v1/secrets/prod/broken/use",
		"POST /v1/secrets/prod/api-key/revoke",
		"GET /v1/secrets?namespace=prod&name=api-key",
	}
	for i, c := range calls {
		if got := c.Method + " " + c.Path; got != wantPaths[i] {
			t.Errorf("call %d = %s, want %s", i, got, wantPaths[i])
		}
		if c.Auth != "Bearer "+testToken {
			t.Errorf("call %d missing bearer token: %q", i, c.Auth)
		}
	}
	if b := calls[1].Body; b["action"] != "http.get" || b["agent"] == "" || b["params"].(map[string]any)["url"] != "https://example.invalid/" {
		t.Errorf("execute body = %+v", b)
	}
}

func TestSDKClient_InProcessPipes(t *testing.T) {
	fv := newFakeVault()
	backend := httptest.NewServer(fv)
	defer backend.Close()

	var logBuf bytes.Buffer
	var logMu sync.Mutex
	s := rgtmcp.NewServer(backend.URL, testToken)
	s.SetLogger(log.New(writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logBuf.Write(p)
	}), "", 0))

	clientToServerR, clientToServerW := io.Pipe()
	serverToClientR, serverToClientW := io.Pipe()
	// Unblock the server goroutine if the test fails early.
	defer clientToServerW.Close()
	defer serverToClientR.Close()
	done := make(chan error, 1)
	go func() {
		err := s.Serve(clientToServerR, serverToClientW)
		_ = serverToClientW.Close()
		done <- err
	}()

	runLifecycle(t, &sdk.IOTransport{Reader: serverToClientR, Writer: clientToServerW}, fv)

	_ = clientToServerW.Close()
	select {
	case err := <-done:
		if err != nil && err != io.ErrClosedPipe {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not exit after client closed stdin")
	}

	// The detail goes to the operator log, not the client.
	logMu.Lock()
	defer logMu.Unlock()
	if !strings.Contains(logBuf.String(), "INTERNAL-DETAIL") {
		t.Errorf("backend error body was not logged server-side; log=%q", logBuf.String())
	}
}

func TestSDKClient_StdioSubprocess(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a subprocess")
	}
	fv := newFakeVault()
	backend := httptest.NewServer(fv)
	defer backend.Close()

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(),
		"RGT_MCP_E2E_CHILD=1",
		"RGT_MCP_E2E_BACKEND="+backend.URL,
		"RGT_MCP_E2E_TOKEN="+testToken,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	runLifecycle(t, &sdk.CommandTransport{Command: cmd}, fv)

	if !strings.Contains(stderr.String(), "INTERNAL-DETAIL") {
		t.Errorf("child did not log backend error detail to stderr; stderr=%q", stderr.String())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
