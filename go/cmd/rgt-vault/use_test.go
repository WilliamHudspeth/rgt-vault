package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/actions"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/kdf"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers/providerstest"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/server"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/totp"
)

// realStack is the real server.New stack (per-agent tokens, optional approval
// broker with TOTP, the four built-in actions allowed to reach loopback over
// plain http) for the CLI tests of use, actions and requests.
type realStack struct {
	url, agentTok, opTok, totpSecret string
}

type stackOpts struct {
	policy   string
	approval bool
}

const policyBotCIOnly = "rules:\n  - effect: allow\n    agent: bot\n    namespace: \"*\"\n    purpose: \"ci*\"\n    action: \"*\"\n"

func startRealStack(t *testing.T, o stackOpts) *realStack {
	t.Helper()
	isolateEnv(t)
	dir := t.TempDir()
	if o.policy == "" {
		o.policy = allowAllPolicy
	}
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte(o.policy), 0o600); err != nil {
		t.Fatal(err)
	}
	so := server.StackOptions{
		DBPath: filepath.Join(dir, "vault", "vault.db"), PolicyFile: policy,
		MasterProvider: providerstest.NewMemory(),
		KDFParams:      kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1},
	}
	secret, err := totp.GenerateSecret(20)
	if err != nil {
		t.Fatal(err)
	}
	if o.approval {
		totpFile := filepath.Join(dir, "totp.secret")
		if err := os.WriteFile(totpFile, []byte(secret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		so.RequireApproval, so.TOTPSecretFile, so.ApprovalTimeout = true, totpFile, 60*time.Second
	}
	stack, err := server.OpenStack(context.Background(), so)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	// The built-in actions, allowed to reach the loopback test servers.
	reg, err := actions.NewBuiltinRegistry(actions.Config{AllowPrivateNetwork: true, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	store := auth.OpenStore(filepath.Join(dir, "tokens.json"))
	mk := func(agent string, scopes ...auth.Scope) string {
		tok, _, err := store.Mint(auth.MintOptions{Agent: agent, Scopes: scopes})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	s := &realStack{
		agentTok:   mk("bot", auth.ScopeAgent, auth.ScopeLease),
		opTok:      mk("operator", auth.ScopeOperator),
		totpSecret: secret,
	}
	h, err := server.New(server.Config{Vault: stack.Vault, Tokens: store, Broker: stack.Broker, Actions: reg, Capabilities: stack.Capabilities})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

func (s *realStack) agent(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	return runCLI(t, stdin, append([]string{"--host", s.url, "--token", s.agentTok}, args...)...)
}

func (s *realStack) operator(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	return runCLI(t, stdin, append([]string{"--host", s.url, "--token", s.opTok}, args...)...)
}

// upstream is a test API that records what it was called with.
type upstream struct {
	*httptest.Server
	mu   sync.Mutex
	seen []upstreamCall
}

type upstreamCall struct{ method, path, auth, body string }

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.seen = append(u.seen, upstreamCall{r.Method, r.URL.Path, r.Header.Get("Authorization"), string(b)})
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"hello":"upstream","choices":[{"message":{"content":"hi"}}]}`)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *upstream) calls() []upstreamCall {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]upstreamCall(nil), u.seen...)
}

// use runs all four built-in actions through the CLI, and the secret value
// reaches the upstream service only, never the CLI's output.
func TestUseAllBuiltinActions(t *testing.T) {
	s := startRealStack(t, stackOpts{})
	up := newUpstream(t)
	const secretValue = "sk-test-never-printed-7f3a"
	if code, _, e := s.agent(t, secretValue+"\n", "set", "api", "--namespace", "ci", "--purpose", "setup"); code != 0 {
		t.Fatalf("set: %d %s", code, e)
	}

	// actions lists the four, with their parameters.
	code, out, e := s.agent(t, "", "actions")
	if code != 0 {
		t.Fatalf("actions: %d %s", code, e)
	}
	for _, want := range []string{"echo\t", "http_get_with_auth\t", "http_post_with_auth\t", "openai_chat\t", "params: url, headers", "params: message"} {
		if !strings.Contains(out, want) {
			t.Errorf("actions output lacks %q:\n%s", want, out)
		}
	}

	// echo, with --param.
	code, out, e = s.agent(t, "", "use", "api", "--namespace", "ci", "--action", "echo", "--purpose", "ci-test", "--param", "message=hello")
	if code != 0 || !strings.Contains(out, `"message": "hello"`) || !strings.Contains(out, `"leaked_secret": false`) {
		t.Fatalf("echo: %d %q %q", code, out, e)
	}

	// http_get_with_auth.
	code, out, e = s.agent(t, "", "use", "api", "--namespace", "ci", "--action", "http_get_with_auth", "--purpose", "ci-test", "--param", "url="+up.URL+"/me")
	if code != 0 || !strings.Contains(out, "upstream") {
		t.Fatalf("http_get: %d %q %q", code, out, e)
	}

	// http_post_with_auth, body from --params-json on stdin (non-string value).
	pj := `{"url":"` + up.URL + `/items","body":{"name":"widget","qty":2}}`
	code, out, e = s.agent(t, pj, "use", "api", "--namespace", "ci", "--action", "http_post_with_auth", "--purpose", "ci-test", "--params-json", "-")
	if code != 0 || !strings.Contains(out, "upstream") {
		t.Fatalf("http_post: %d %q %q", code, out, e)
	}

	// openai_chat, params from a file plus a --param for base_url.
	file := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(file, []byte(`{"model":"m1","messages":[{"role":"user","content":"hi"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, e = s.agent(t, "", "use", "api", "--namespace", "ci", "--action", "openai_chat", "--purpose", "ci-test",
		"--params-json", file, "--param", "base_url="+up.URL)
	if code != 0 || !strings.Contains(out, "choices") {
		t.Fatalf("openai_chat: %d %q %q", code, out, e)
	}

	calls := up.calls()
	if len(calls) != 3 {
		t.Fatalf("upstream saw %d calls, want 3: %+v", len(calls), calls)
	}
	for _, c := range calls {
		if c.auth != "Bearer "+secretValue {
			t.Errorf("%s %s: Authorization %q, want the secret as a bearer token", c.method, c.path, c.auth)
		}
	}
	if calls[1].method != "POST" || !strings.Contains(calls[1].body, `"qty":2`) {
		t.Errorf("post call: %+v", calls[1])
	}
	if !strings.Contains(calls[2].path, "chat/completions") || !strings.Contains(calls[2].body, `"model":"m1"`) {
		t.Errorf("chat call: %+v", calls[2])
	}
}

// A policy denial prints the server's reason and the incident id.
func TestUsePolicyDenialPrintsReasonAndIncident(t *testing.T) {
	s := startRealStack(t, stackOpts{policy: policyBotCIOnly})
	if code, _, e := s.agent(t, "v\n", "set", "api", "--namespace", "ci", "--purpose", "ci-setup"); code != 0 {
		t.Fatalf("set: %d %s", code, e)
	}
	code, out, stderr := s.agent(t, "", "use", "api", "--namespace", "ci", "--action", "echo", "--purpose", "billing")
	if code != 1 || out != "" {
		t.Fatalf("exit %d out %q", code, out)
	}
	for _, want := range []string{"use failed: ", "denied", "HTTP 403 PolicyDeniedError", ", incident "} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr %q lacks %q", stderr, want)
		}
	}
	// An unknown action and an unknown secret also carry the server's text.
	if code, _, stderr = s.agent(t, "", "use", "api", "--namespace", "ci", "--action", "nope", "--purpose", "ci-x"); code != 1 || !strings.Contains(stderr, "HTTP 404 ActionNotFoundError") {
		t.Errorf("unknown action: %d %q", code, stderr)
	}
	if code, _, stderr = s.agent(t, "", "use", "ghost", "--namespace", "ci", "--action", "echo", "--purpose", "ci-x"); code != 1 || !strings.Contains(stderr, "HTTP 404 SecretNotFoundError") {
		t.Errorf("unknown secret: %d %q", code, stderr)
	}
	// A bad parameter is a client error with the server's message.
	if code, _, stderr = s.agent(t, "", "use", "api", "--namespace", "ci", "--action", "echo", "--purpose", "ci-x", "--param", "bogus=1"); code != 1 || !strings.Contains(stderr, "HTTP 400") {
		t.Errorf("bad param: %d %q", code, stderr)
	}
}

func TestUseFlagsAndParams(t *testing.T) {
	isolateEnv(t)
	srv, seen := recordingServer(t, 200, `{"ok":true,"action":"echo","result":{"a":1}}`)
	run := func(stdin string, args ...string) (int, string, string) {
		return runCLI(t, stdin, append([]string{"--host", srv.URL, "--token", cliToken}, args...)...)
	}
	code, out, e := run("", "use", "a b", "--namespace", "n/s", "--action", "echo", "--purpose", "p", "--agent", "bot", "--param", "k=v=w", "--param", "x=")
	if code != 0 || out != "{\n  \"a\": 1\n}\n" {
		t.Fatalf("exit %d out %q err %q", code, out, e)
	}
	got := (*seen)[0]
	if got.Method != "POST" || got.Path != "/v1/secrets/n%2Fs/a%20b/use" {
		t.Errorf("request: %+v", got)
	}
	want := map[string]any{"action": "echo", "agent": "bot", "purpose": "p", "params": map[string]any{"k": "v=w", "x": ""}}
	if b, _ := json.Marshal(got.Body); string(b) != mustJSON(want) {
		t.Errorf("body %s, want %s", b, mustJSON(want))
	}

	// agent and purpose are omitted when not given; params is always an object.
	*seen = nil
	if code, _, e := run("", "use", "k", "--action", "echo"); code != 0 {
		t.Fatalf("exit %d %s", code, e)
	}
	if b, _ := json.Marshal((*seen)[0].Body); string(b) != `{"action":"echo","params":{}}` {
		t.Errorf("minimal body %s", b)
	}

	// Mistakes are refused before anything is sent.
	n := len(*seen)
	pf := filepath.Join(t.TempDir(), "p.json")
	_ = os.WriteFile(pf, []byte(`{"k":"v"}`), 0o600)
	bad := map[string][]string{
		"no action":         {"use", "k"},
		"param no equals":   {"use", "k", "--action", "echo", "--param", "oops"},
		"param empty key":   {"use", "k", "--action", "echo", "--param", "=v"},
		"duplicate param":   {"use", "k", "--action", "echo", "--param", "a=1", "--param", "a=2"},
		"dup json and flag": {"use", "k", "--action", "echo", "--params-json", pf, "--param", "k=2"},
		"missing file":      {"use", "k", "--action", "echo", "--params-json", pf + ".nope"},
		"empty name":        {"use", "", "--action", "echo"},
	}
	for name, args := range bad {
		if code, _, _ := run("", args...); code != 1 {
			t.Errorf("%s: exit %d, want 1", name, code)
		}
	}
	for name, stdin := range map[string]string{"array": `[1]`, "string": `"x"`, "null": `null`, "two objects": `{"a":1}{"b":2}`, "garbage": `{`} {
		if code, _, e := run(stdin, "use", "k", "--action", "echo", "--params-json", "-"); code != 1 || !strings.Contains(e, "--params-json") {
			t.Errorf("params-json %s: exit %d err %q", name, code, e)
		}
	}
	if len(*seen) != n {
		t.Errorf("%d requests were sent for invalid input", len(*seen)-n)
	}
	// A server answer without a result is an error, not an empty success.
	srv2, _ := recordingServer(t, 200, `{"ok":true}`)
	if code, _, e := runCLI(t, "", "--host", srv2.URL, "--token", cliToken, "use", "k", "--action", "echo"); code != 1 || !strings.Contains(e, "no result") {
		t.Errorf("no result: %d %q", code, e)
	}
	srv3, _ := recordingServer(t, 200, `not json`)
	if code, _, _ := runCLI(t, "", "--host", srv3.URL, "--token", cliToken, "actions"); code != 1 {
		t.Errorf("actions bad json: %d", code)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestSetRequire2FAAndNoteBody(t *testing.T) {
	isolateEnv(t)
	srv, seen := recordingServer(t, 200, `{"ok":true}`)
	code, _, e := runCLI(t, "v\n", "--host", srv.URL, "--token", cliToken, "set", "k", "--require-2fa", "--note", "deploy key")
	if code != 0 {
		t.Fatalf("exit %d %s", code, e)
	}
	b := (*seen)[0].Body
	if b["require_2fa"] != true || b["note"] != "deploy key" {
		t.Errorf("body %v", b)
	}
}
