package mcp_test

// The go-sdk client drives the MCP server against the REAL internal/server
// router (server.OpenStack + server.New on a real vault: encrypted SQLite,
// keychain, hash-chained audit, ABAC policy, capability registry), so a
// change in a server route breaks these tests instead of silently breaking a
// tool.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/captoken"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/kdf"
	rgtmcp "github.com/WilliamHudspeth/rgt-vault/go/internal/mcp"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers/providerstest"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/server"
)

// realPolicy allows everything except the agent "intruder" (denied
// everything) and "limited" (denied the secrets.use capability).
const realPolicy = `rules:
  - effect: allow
    agent: "*"
    namespace: "*"
    purpose: "*"
    action: "*"
  - effect: deny
    agent: intruder
    action: "*"
  - effect: deny
    agent: limited
    action: secrets.use
`

const realPolicyRules = 3

type realBackend struct {
	URL        string
	AgentToken string
	PolicyFile string
	TokenDir   string
	signer     *captoken.HMACTokenVerifier
}

// startRealBackend serves the real router over httptest with the LEGACY
// shared token (the label-driven tests below name several agents with one
// token). sdk_identity_test.go runs MCP on the per-agent token store.
func startRealBackend(t *testing.T) *realBackend {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	hexKey := hex.EncodeToString(key)
	rb := &realBackend{TokenDir: dir, PolicyFile: write("policy.yaml", realPolicy)}
	stack, err := server.OpenStack(context.Background(), server.StackOptions{
		DBPath:         filepath.Join(dir, "vault", "vault.db"),
		PolicyFile:     rb.PolicyFile,
		MasterProvider: providerstest.NewMemory(),
		HarnessKeyFile: write("harness.key", hexKey+"\n"),
		KDFParams:      kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	rb.signer, err = captoken.NewHMACTokenVerifier([]byte(hexKey))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := auth.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	ts := auth.NewTokenStore(filepath.Join(dir, "agent.token"))
	if err := ts.Write(tok); err != nil {
		t.Fatal(err)
	}
	rb.AgentToken = tok
	h, err := server.New(server.Config{
		Vault: stack.Vault, AgentTokens: ts, LegacyPrivilegedRoutes: true, Broker: stack.Broker,
		Actions: stack.Actions, Capabilities: stack.Capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	rb.URL = srv.URL
	return rb
}

func (rb *realBackend) do(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, rb.URL+path, rd)
	req.Header.Set("Authorization", "Bearer "+rb.AgentToken)
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (rb *realBackend) seed(t *testing.T, ns, name, value string) {
	t.Helper()
	code, out := rb.do(t, "POST", "/v1/secrets", map[string]string{"name": name, "namespace": ns, "value": value, "agent": "bot", "purpose": "ci"})
	if code != http.StatusOK {
		t.Fatalf("seed: HTTP %d %s", code, out)
	}
}

func (rb *realBackend) sign(t *testing.T, agent, capability string, version int) string {
	t.Helper()
	tok, err := rb.signer.Sign(agent, capability, version, nil, 300)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// auditDump returns the whole audit log as text.
func (rb *realBackend) auditDump(t *testing.T) string {
	t.Helper()
	code, out := rb.do(t, "GET", "/v1/audit?limit=1000", nil)
	if code != http.StatusOK {
		t.Fatalf("audit: HTTP %d", code)
	}
	return string(out)
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// sdkSession connects the go-sdk client to s over in-process pipes.
func sdkSession(t *testing.T, s *rgtmcp.Server) (*sdk.ClientSession, context.Context) {
	t.Helper()
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	done := make(chan struct{})
	t.Cleanup(func() { <-done }) // runs last: join the server goroutine
	t.Cleanup(func() { _ = c2sW.Close() })
	t.Cleanup(func() { _ = s2cR.Close() })
	go func() {
		defer close(done)
		_ = s.Serve(c2sR, s2cW)
		_ = s2cW.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "rgt-e2e", Version: "test"}, nil).
		Connect(ctx, &sdk.IOTransport{Reader: s2cR, Writer: c2sW}, nil)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, ctx
}

func callTool(t *testing.T, cs *sdk.ClientSession, ctx context.Context, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return toolText(t, res), res.IsError
}

func TestSDKClient_RealRouter(t *testing.T) {
	rb := startRealBackend(t)
	rb.seed(t, "prod", "api-key", "s3cr3t-value")

	s := rgtmcp.NewServer(rb.URL, rb.AgentToken)
	// This backend runs the legacy shared token: the label is the subject.
	_ = s.SetAgent(rgtmcp.DefaultAgent)
	s.SetLogger(log.New(io.Discard, "", 0))
	cs, ctx := sdkSession(t, s)
	call := func(name string, args map[string]any) (string, bool) {
		return callTool(t, cs, ctx, name, args)
	}
	key := map[string]any{"namespace": "prod", "name": "api-key"}

	if txt, isErr := call("list_secrets", map[string]any{"namespace": "prod"}); isErr || !strings.Contains(txt, `"api-key"`) || strings.Contains(txt, "s3cr3t-value") {
		t.Fatalf("list_secrets: (%q, %v)", txt, isErr)
	}
	if txt, isErr := call("lease_secret", key); isErr || txt != "s3cr3t-value" {
		t.Fatalf("lease_secret against real router: (%q, %v)", txt, isErr)
	}
	if txt, isErr := call("execute_secret", map[string]any{"namespace": "prod", "name": "api-key", "action": "echo"}); isErr || strings.Contains(txt, "s3cr3t-value") {
		t.Fatalf("execute_secret: (%q, %v)", txt, isErr)
	}
	if txt, isErr := call("revoke_secret", key); isErr {
		t.Fatalf("revoke_secret: %q", txt)
	}
	if txt, isErr := call("lease_secret", key); !isErr || txt != "secret not found" {
		t.Fatalf("lease after revoke: (%q, %v)", txt, isErr)
	}
}

func TestSDKClient_ToolListIncludesCapabilityTools(t *testing.T) {
	rb := startRealBackend(t)
	cs, ctx := sdkSession(t, rgtmcp.NewServer(rb.URL, rb.AgentToken))
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
		if tool.Name == "execute_capability" {
			raw, _ := json.Marshal(tool.InputSchema)
			for _, want := range []string{`"capability"`, `"capability_token"`, `"agent_id"`, `"version"`, `"payload"`} {
				if !strings.Contains(string(raw), want) {
					t.Errorf("execute_capability schema lacks %s: %s", want, raw)
				}
			}
		}
	}
	for _, name := range []string{"list_secrets", "lease_secret", "revoke_secret", "execute_secret", "execute_capability", "list_capabilities"} {
		if !got[name] {
			t.Errorf("tool %q missing: %v", name, got)
		}
	}
}

func TestSDKClient_ExecuteCapability_RealRouter(t *testing.T) {
	rb := startRealBackend(t)
	logs := &lockedBuf{}
	s := rgtmcp.NewServer(rb.URL, rb.AgentToken)
	s.SetLogger(log.New(logs, "", 0))
	cs, ctx := sdkSession(t, s)
	call := func(args map[string]any) (string, bool) { return callTool(t, cs, ctx, "execute_capability", args) }

	// Token supplied as a tool argument.
	good := rb.sign(t, "bot", "secrets.echo", 1)
	txt, isErr := call(map[string]any{"capability": "secrets.echo", "agent_id": "bot", "capability_token": good, "payload": map[string]any{"message": "hello"}})
	if isErr {
		t.Fatalf("execute_capability: %q", txt)
	}
	var out struct {
		OK     bool           `json:"ok"`
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal([]byte(txt), &out); err != nil || !out.OK || out.Result == nil {
		t.Fatalf("result = %q (%v)", txt, err)
	}
	if !strings.Contains(txt, "hello") {
		t.Errorf("payload not echoed by secrets.echo: %s", txt)
	}

	// Failures map to Python's fixed messages.
	for _, c := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"forged token", map[string]any{"capability": "secrets.echo", "agent_id": "bot", "capability_token": "eyJ4IjoxfQ.AAAA"}, "unauthorized"},
		{"agent mismatch", map[string]any{"capability": "secrets.echo", "agent_id": "mallory", "capability_token": good}, "unauthorized"},
		{"capability mismatch", map[string]any{"capability": "secrets.use", "agent_id": "bot", "capability_token": good}, "unauthorized"},
		{"unknown capability", map[string]any{"capability": "no.such", "agent_id": "bot", "capability_token": rb.sign(t, "bot", "no.such", 1)}, "capability not found"},
	} {
		txt, isErr := call(c.args)
		if !isErr || txt != c.want {
			t.Errorf("%s: got (%q, %v), want %q", c.name, txt, isErr, c.want)
		}
	}
	// A version the capability does not support is a client error and says so.
	if txt, isErr := call(map[string]any{"capability": "secrets.echo", "agent_id": "bot", "capability_token": rb.sign(t, "bot", "secrets.echo", 2), "version": 2}); !isErr || !strings.HasPrefix(txt, "invalid request:") {
		t.Errorf("unsupported version: (%q, %v)", txt, isErr)
	}
	// No token anywhere.
	if txt, isErr := call(map[string]any{"capability": "secrets.echo", "agent_id": "bot"}); !isErr || !strings.HasPrefix(txt, "missing capability token") {
		t.Errorf("no token: (%q, %v)", txt, isErr)
	}

	// No credential reached the log or the vault's audit trail.
	audit := rb.auditDump(t)
	for _, secret := range []string{good, rb.AgentToken} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("credential in the MCP log: %q", logs.String())
		}
		if secret == good && strings.Contains(audit, secret) {
			t.Error("capability token in the audit log")
		}
	}
	if !strings.Contains(audit, "CAPABILITY_EXECUTED") {
		t.Errorf("successful execution not audited: %s", audit)
	}
}

func TestSDKClient_ExecuteCapability_TokenFile(t *testing.T) {
	rb := startRealBackend(t)
	s := rgtmcp.NewServer(rb.URL, rb.AgentToken)
	s.SetLogger(log.New(io.Discard, "", 0))
	if err := s.SetAgent("filebot"); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(rb.TokenDir, "cap.token")
	if err := os.WriteFile(tokenFile, []byte(rb.sign(t, "filebot", "secrets.echo", 1)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadCapabilityTokenFile(tokenFile); err != nil {
		t.Fatal(err)
	}
	cs, ctx := sdkSession(t, s)
	// Neither agent_id nor capability_token passed: both come from the server.
	txt, isErr := callTool(t, cs, ctx, "execute_capability", map[string]any{"capability": "secrets.echo", "payload": map[string]any{"message": "from file"}})
	if isErr || !strings.Contains(txt, "from file") {
		t.Fatalf("token-file execute: (%q, %v)", txt, isErr)
	}
	// The default token is bound to filebot: another agent_id is refused.
	if txt, isErr := callTool(t, cs, ctx, "execute_capability", map[string]any{"capability": "secrets.echo", "agent_id": "other"}); !isErr || txt != "unauthorized" {
		t.Fatalf("token bound to another agent: (%q, %v)", txt, isErr)
	}
}

func TestSDKClient_ListCapabilities_RealRouter(t *testing.T) {
	rb := startRealBackend(t)
	s := rgtmcp.NewServer(rb.URL, rb.AgentToken)
	_ = s.SetAgent(rgtmcp.DefaultAgent) // legacy shared-token backend
	s.SetLogger(log.New(io.Discard, "", 0))
	cs, ctx := sdkSession(t, s)
	names := func(agent string) map[string]bool {
		t.Helper()
		args := map[string]any{}
		if agent != "" {
			args["agent"] = agent
		}
		txt, isErr := callTool(t, cs, ctx, "list_capabilities", args)
		if isErr {
			t.Fatalf("list_capabilities(%q): %s", agent, txt)
		}
		var out struct {
			Agent        string `json:"agent"`
			Capabilities []struct {
				Name              string   `json:"name"`
				Description       string   `json:"description"`
				SupportedVersions []int    `json:"supported_versions"`
				ParamsSchema      []string `json:"params_schema"`
			} `json:"capabilities"`
		}
		if err := json.Unmarshal([]byte(txt), &out); err != nil {
			t.Fatalf("%q: %v", txt, err)
		}
		got := map[string]bool{}
		for _, c := range out.Capabilities {
			got[c.Name] = true
			if len(c.SupportedVersions) == 0 {
				t.Errorf("%s: no versions", c.Name)
			}
		}
		return got
	}
	if all := names(""); !all["secrets.echo"] || !all["secrets.use"] {
		t.Errorf("default agent sees %v", all)
	}
	if lim := names("limited"); !lim["secrets.echo"] || lim["secrets.use"] {
		t.Errorf("limited agent sees %v (secrets.use is denied by policy)", lim)
	}
	if none := names("intruder"); len(none) != 0 {
		t.Errorf("intruder sees %v", none)
	}
}

func TestSDKClient_PolicyResource_RealRouter(t *testing.T) {
	rb := startRealBackend(t)
	s := rgtmcp.NewServer(rb.URL, rb.AgentToken)
	s.SetLogger(log.New(io.Discard, "", 0))
	s.SetPolicyFile(rb.PolicyFile)
	cs, ctx := sdkSession(t, s)

	list, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Resources) != 1 || list.Resources[0].URI != "vault://policy" || list.Resources[0].MIMEType != "application/json" {
		t.Fatalf("resources = %+v", list.Resources)
	}
	read, err := cs.ReadResource(ctx, &sdk.ReadResourceParams{URI: "vault://policy"})
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Contents) != 1 {
		t.Fatalf("contents = %+v", read.Contents)
	}
	var summary map[string]any
	if err := json.Unmarshal([]byte(read.Contents[0].Text), &summary); err != nil {
		t.Fatal(err)
	}
	if summary["rules"] != float64(realPolicyRules) || summary["default_ttl"] != float64(300) || len(summary) != 2 {
		t.Fatalf("summary = %v", summary)
	}
	for _, leak := range []string{"intruder", "limited", "secrets.use"} {
		if strings.Contains(read.Contents[0].Text, leak) {
			t.Errorf("policy internals leaked (%q): %s", leak, read.Contents[0].Text)
		}
	}
	if _, err := cs.ReadResource(ctx, &sdk.ReadResourceParams{URI: "vault://secrets"}); err == nil {
		t.Error("unknown resource readable")
	}
}
