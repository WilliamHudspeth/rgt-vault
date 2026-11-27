package tui_test

// The TUI client and model against the REAL server router (server.OpenStack +
// server.New): approval broker, TOTP second factor, separate operator token,
// fingerprints from the ciphertext, metadata columns.

import (
	"bytes"
	"context"
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

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/totp"
	"rgt-vault-server/internal/tui"
)

const sentinel = "REAL-SERVER-PLAINTEXT-SENTINEL"

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

type realEnv struct {
	url        string
	agentTok   string
	opTok      string
	totpSecret string
}

func startReal(t *testing.T) *realEnv {
	t.Helper()
	dir := t.TempDir()
	secret, err := totp.GenerateSecret(20)
	if err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "policy.yaml")
	totpFile := filepath.Join(dir, "totp.secret")
	for p, c := range map[string]string{
		policy:   "rules:\n  - effect: allow\n    agent: \"*\"\n    namespace: \"*\"\n    purpose: \"*\"\n    action: \"*\"\n",
		totpFile: secret + "\n",
	} {
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stack, err := server.OpenStack(context.Background(), server.StackOptions{
		DBPath:          filepath.Join(dir, "vault", "vault.db"),
		PolicyFile:      policy,
		MasterProvider:  providerstest.NewMemory(),
		RequireApproval: true,
		TOTPSecretFile:  totpFile,
		ApprovalTimeout: 60 * time.Second,
		KDFParams:       kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	// Per-agent token store (batch H1): the agent "bot" may use, lease and
	// read the audit log; the operator token only approves and audits.
	store := auth.OpenStore(filepath.Join(dir, "tokens.json"))
	mk := func(agent string, scopes ...auth.Scope) string {
		tok, _, err := store.Mint(auth.MintOptions{Agent: agent, Scopes: scopes})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	agentTok := mk("bot", auth.ScopeAgent, auth.ScopeLease, auth.ScopeAudit)
	opTok := mk("operator", auth.ScopeOperator)
	h, err := server.New(server.Config{
		Vault: stack.Vault, Tokens: store, Broker: stack.Broker,
		Actions: stack.Actions, Capabilities: stack.Capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &realEnv{url: srv.URL, agentTok: agentTok, opTok: opTok, totpSecret: secret}
}

func (e *realEnv) raw(t *testing.T, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.url+path, rd)
	req.Header.Set("Authorization", "Bearer "+token)
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 70 * time.Second}).Do(req)
	if err != nil {
		t.Error(err) // may run in a goroutine: no Fatal
		return 0, nil
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// collector accumulates everything a teatest program renders.
type collector struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (c *collector) waitFor(t *testing.T, tm *teatest.TestModel, cond func(string) bool) {
	t.Helper()
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.buf.Write(b)
		return cond(c.buf.String())
	}, teatest.WithDuration(15*time.Second), teatest.WithCheckInterval(20*time.Millisecond))
}

func (c *collector) all() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func TestRealServer_ListShowsMetadataAndDistinctFingerprints(t *testing.T) {
	e := startReal(t)
	for _, s := range []struct {
		name, value, note string
		twofa             bool
	}{
		{"alpha", "value-one", "first note", false},
		{"beta", "value-two", "second note", true},
	} {
		code, out := e.raw(t, "POST", "/v1/secrets", e.agentTok, map[string]any{
			"name": s.name, "namespace": "prod", "value": s.value, "agent": "bot", "purpose": "seed",
			"note": s.note, "require_2fa": s.twofa,
		})
		if code != 200 {
			t.Fatalf("seed %s: %d %s", s.name, code, out)
		}
	}
	c := tui.NewHTTPClient(e.url, e.agentTok)
	c.SetOperatorToken(e.opTok)
	if !c.Health() || !c.VerifyAudit() {
		t.Fatal("health / audit verification against the real server")
	}
	infos, err := c.ListSecrets("prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 2 {
		t.Fatalf("infos = %+v", infos)
	}
	by := map[string]tui.SecretInfo{}
	for _, s := range infos {
		by[s.Name] = s
	}
	if by["alpha"].Note != "first note" || by["alpha"].Require2FA || by["beta"].Note != "second note" || !by["beta"].Require2FA {
		t.Errorf("metadata = %+v", by)
	}
	const emptyHash = "e3b0c442"
	fa, fb := by["alpha"].Fingerprint, by["beta"].Fingerprint
	if len(fa) != 8 || len(fb) != 8 || fa == fb || fa == emptyHash || fb == emptyHash {
		t.Errorf("fingerprints alpha=%q beta=%q (must be real, distinct, not sha256(\"\"))", fa, fb)
	}
	if strings.Contains(strings.ToLower(fa+fb), "value") {
		t.Error("fingerprint looks like a value")
	}
	entries, err := c.GetAuditLog(100)
	if err != nil || len(entries) == 0 {
		t.Fatalf("audit = %v, %v", entries, err)
	}
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Timestamp > entries[i].Timestamp {
			t.Fatalf("audit not oldest-first at %d", i)
		}
	}
	// The operator token does not work on the agent API (and vice versa).
	bad := tui.NewHTTPClient(e.url, e.opTok)
	if _, err := bad.ListSecrets("prod"); err == nil || strings.Contains(err.Error(), e.opTok) {
		t.Errorf("operator token on the agent API: %v", err)
	}
}

func TestRealServer_ApprovalFlowWithTOTP(t *testing.T) {
	e := startReal(t)
	if code, out := e.raw(t, "POST", "/v1/secrets", e.agentTok, map[string]any{
		"name": "guarded", "namespace": "prod", "value": sentinel, "agent": "bot", "purpose": "seed", "require_2fa": true,
	}); code != 200 {
		t.Fatalf("seed: %d %s", code, out)
	}

	// The agent asks for the value; the server holds the request.
	type result struct {
		code int
		body string
	}
	agentDone := make(chan result, 1)
	go func() {
		code, body := e.raw(t, "POST", "/v1/secrets/prod/guarded/lease", e.agentTok, map[string]any{"purpose": "deploy"})
		agentDone <- result{code, string(body)}
	}()

	client := tui.NewHTTPClient(e.url, e.agentTok)
	client.SetOperatorToken(e.opTok)
	tm := teatest.NewTestModel(t, tui.New(client, "prod").WithRequestPollInterval(50*time.Millisecond), teatest.WithInitialTermSize(140, 30))
	col := &collector{}
	col.waitFor(t, tm, func(s string) bool { return strings.Contains(s, "online") && strings.Contains(s, "guarded") })

	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	col.waitFor(t, tm, func(s string) bool {
		return strings.Contains(s, "1 pending request(s)") && strings.Contains(s, "bot") && strings.Contains(s, "deploy")
	})

	// Wrong code first: refused, the request stays pending.
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	col.waitFor(t, tm, func(s string) bool { return strings.Contains(s, "2FA required to approve 'guarded'") })
	for _, r := range "000000" {
		tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	col.waitFor(t, tm, func(s string) bool { return strings.Contains(s, "Rejected (bad/missing 2FA code") })

	// The right code approves; the agent then gets its value.
	code, err := totp.Generate(e.totpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code == "000000" {
		t.Skip("TOTP code collides with the wrong-code probe")
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	col.waitFor(t, tm, func(s string) bool { return strings.Count(s, "2FA required to approve 'guarded'") >= 2 })
	for _, r := range code {
		tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	col.waitFor(t, tm, func(s string) bool { return strings.Contains(s, "Approved.") })

	select {
	case res := <-agentDone:
		if res.code != 200 || !strings.Contains(res.body, sentinel) {
			t.Fatalf("agent after approval: %d %s", res.code, res.body)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("agent request was never released")
	}

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	tm.WaitFinished(t, teatest.WithFinalTimeout(5*time.Second))

	// Nothing the TUI drew contains a token, the TOTP code or the secret value.
	all := col.all()
	for name, bad := range map[string]string{"agent token": e.agentTok, "operator token": e.opTok, "value": sentinel, "totp code": code, "wrong code": "000000", "totp secret": e.totpSecret} {
		if strings.Contains(all, bad) {
			t.Errorf("TUI output contains the %s", name)
		}
	}
}

func TestRealServer_DenyAndAgentGets403(t *testing.T) {
	e := startReal(t)
	if code, out := e.raw(t, "POST", "/v1/secrets", e.agentTok, map[string]any{
		"name": "plain", "namespace": "prod", "value": sentinel, "agent": "bot", "purpose": "seed",
	}); code != 200 {
		t.Fatalf("seed: %d %s", code, out)
	}
	agentDone := make(chan int, 1)
	go func() {
		code, _ := e.raw(t, "POST", "/v1/secrets/prod/plain/lease", e.agentTok, map[string]any{"purpose": "p"})
		agentDone <- code
	}()
	client := tui.NewHTTPClient(e.url, e.agentTok)
	client.SetOperatorToken(e.opTok)
	deadline := time.Now().Add(10 * time.Second)
	var reqs []tui.PendingRequest
	for time.Now().Before(deadline) {
		var err error
		if reqs, err = client.ListRequests(); err != nil {
			t.Fatal(err)
		}
		if len(reqs) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(reqs) != 1 || reqs[0].Agent != "bot" || reqs[0].SecretName != "plain" || reqs[0].Require2FA {
		t.Fatalf("requests = %+v", reqs)
	}
	if err := client.Deny(reqs[0].RequestID, "not today"); err != nil {
		t.Fatal(err)
	}
	if got := <-agentDone; got != http.StatusForbidden {
		t.Fatalf("agent after deny: %d", got)
	}
	// Deciding twice is a rejection, not a failure.
	if err := client.Deny(reqs[0].RequestID, "again"); err == nil || err != tui.ErrRejected {
		t.Errorf("second deny = %v, want ErrRejected", err)
	}
	if err := client.Approve("no-such-id", ""); err != tui.ErrRejected {
		t.Errorf("unknown id = %v, want ErrRejected", err)
	}
	// An agent-token client cannot reach the operator endpoints once a
	// separate operator token exists.
	if _, err := tui.NewHTTPClient(e.url, e.agentTok).ListRequests(); err == nil {
		t.Error("agent token listed approval requests")
	}
}
