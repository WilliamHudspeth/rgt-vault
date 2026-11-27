package mcp_test

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/kdf"
	rgtmcp "rgt-vault-server/internal/mcp"
	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/vault"
)

// identityPolicy lets "bot" and "peer" do everything in their own
// namespace only.
const identityPolicy = `rules:
  - effect: allow
    agent: bot
    namespace: bot-ns
    purpose: "*"
    action: "*"
  - effect: allow
    agent: peer
    namespace: peer-ns
    purpose: "*"
    action: "*"
`

// MCP on the per-agent token store (batch H1): the MCP server holds a token
// minted for one agent, sends no agent label, and the backend acts as that
// agent. Plaintext (lease_secret) needs the lease scope; another agent's
// secrets stay out of reach even when the label names that agent.
func TestMCP_PerAgentTokens(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte(identityPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	stack, err := server.OpenStack(context.Background(), server.StackOptions{
		DBPath:         filepath.Join(dir, "vault", "vault.db"),
		PolicyFile:     policy,
		MasterProvider: providerstest.NewMemory(),
		KDFParams:      kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	for _, s := range []struct{ ns, name, agent, value string }{
		{"bot-ns", "k", "bot", "bot-value"}, {"peer-ns", "k", "peer", "peer-value"},
	} {
		if err := stack.Vault.SetSecret(context.Background(), vault.SetSecretRequest{
			Name: s.name, Namespace: s.ns, Agent: s.agent, Purpose: "seed", Value: []byte(s.value),
		}); err != nil {
			t.Fatal(err)
		}
	}
	store := auth.OpenStore(filepath.Join(dir, "tokens.json"))
	mint := func(agent string, scopes ...auth.Scope) string {
		tok, _, err := store.Mint(auth.MintOptions{Agent: agent, Scopes: scopes})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	leaser := mint("bot", auth.ScopeAgent, auth.ScopeLease)
	plain := mint("bot", auth.ScopeAgent)
	h, err := server.New(server.Config{Vault: stack.Vault, Tokens: store, Actions: stack.Actions, Capabilities: stack.Capabilities})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	session := func(token, label string) func(string, map[string]any) (string, bool) {
		s := rgtmcp.NewServer(srv.URL, token)
		if err := s.SetAgent(label); err != nil {
			t.Fatal(err)
		}
		s.SetLogger(log.New(io.Discard, "", 0))
		cs, ctx := sdkSession(t, s)
		return func(name string, args map[string]any) (string, bool) { return callTool(t, cs, ctx, name, args) }
	}

	call := session(leaser, "")
	if txt, isErr := call("lease_secret", map[string]any{"namespace": "bot-ns", "name": "k"}); isErr || txt != "bot-value" {
		t.Fatalf("own lease: (%q, %v)", txt, isErr)
	}
	// IDOR: bot's token cannot read peer's secret (ABAC as bot)...
	if txt, isErr := call("lease_secret", map[string]any{"namespace": "peer-ns", "name": "k"}); !isErr || txt == "peer-value" {
		t.Fatalf("cross-agent lease: (%q, %v)", txt, isErr)
	}
	// ...nor by naming peer (the label is refused, 403).
	spoof := session(leaser, "peer")
	if txt, isErr := spoof("lease_secret", map[string]any{"namespace": "peer-ns", "name": "k"}); !isErr || txt == "peer-value" {
		t.Fatalf("spoofed label lease: (%q, %v)", txt, isErr)
	}
	if txt, isErr := spoof("execute_secret", map[string]any{"namespace": "peer-ns", "name": "k", "action": "secrets.echo"}); !isErr {
		t.Fatalf("spoofed label execute: (%q, %v)", txt, isErr)
	}
	// An agent-only token can use but not read.
	callPlain := session(plain, "")
	if txt, isErr := callPlain("lease_secret", map[string]any{"namespace": "bot-ns", "name": "k"}); !isErr || txt == "bot-value" {
		t.Fatalf("agent-only lease: (%q, %v)", txt, isErr)
	}
	if txt, isErr := callPlain("list_capabilities", map[string]any{}); isErr {
		t.Fatalf("list_capabilities as the token's agent: %s", txt)
	}
	if txt, isErr := callPlain("list_secrets", map[string]any{"namespace": "bot-ns"}); isErr {
		t.Fatalf("list_secrets: %s", txt)
	}
}
