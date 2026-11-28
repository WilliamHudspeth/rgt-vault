package mcp_test

// RGT-536: a refused tool call reaches the model with the server's class and
// reason, through the real router (per-agent tokens, ABAC policy, approval
// broker), driven by the go-sdk client.

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/kdf"
	rgtmcp "github.com/WilliamHudspeth/rgt-vault/go/internal/mcp"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers/providerstest"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/server"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/vault"
)

const errorsPolicy = `rules:
  - effect: allow
    agent: bot
    namespace: bot-ns
    purpose: "*"
    action: "*"
`

func TestSDKClient_RefusalsCarryTheReason(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte(errorsPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	stack, err := server.OpenStack(context.Background(), server.StackOptions{
		DBPath:          filepath.Join(dir, "vault", "vault.db"),
		PolicyFile:      policy,
		MasterProvider:  providerstest.NewMemory(),
		KDFParams:       kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1},
		RequireApproval: true,
		ApprovalTimeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	// Seed through the vault API (policy denies "seed", so seed as bot in its ns).
	for _, s := range []struct{ ns, name, agent string }{{"bot-ns", "k", "bot"}} {
		if err := stack.Vault.SetSecret(context.Background(), vault.SetSecretRequest{
			Name: s.name, Namespace: s.ns, Agent: s.agent, Purpose: "seed", Value: []byte("v"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	store := auth.OpenStore(filepath.Join(dir, "tokens.json"))
	mint := func(scopes ...auth.Scope) string {
		tok, _, err := store.Mint(auth.MintOptions{Agent: "bot", Scopes: scopes})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	agentOnly := mint(auth.ScopeAgent)
	h, err := server.New(server.Config{Vault: stack.Vault, Tokens: store, Actions: stack.Actions, Capabilities: stack.Capabilities, Broker: stack.Broker})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	s := rgtmcp.NewServer(srv.URL, agentOnly)
	s.SetLogger(log.New(io.Discard, "", 0))
	cs, ctx := sdkSession(t, s)

	t.Run("policy denial", func(t *testing.T) {
		txt, isErr := callTool(t, cs, ctx, "execute_secret", map[string]any{"namespace": "other-ns", "name": "k", "action": "echo"})
		if !isErr || !strings.HasPrefix(txt, "PolicyDeniedError: ") || !strings.Contains(txt, "bot") || !strings.Contains(txt, "(HTTP 403, incident ") {
			t.Fatalf("got (%q, %v)", txt, isErr)
		}
		if strings.Contains(txt, "backend error") {
			t.Fatalf("status-only text: %q", txt)
		}
	})
	t.Run("insufficient scope", func(t *testing.T) {
		txt, isErr := callTool(t, cs, ctx, "lease_secret", map[string]any{"namespace": "bot-ns", "name": "k"})
		if !isErr || !strings.Contains(txt, "insufficient scope") || !strings.Contains(txt, "(HTTP 403, incident ") {
			t.Fatalf("got (%q, %v)", txt, isErr)
		}
	})
	t.Run("approval timeout", func(t *testing.T) {
		txt, isErr := callTool(t, cs, ctx, "execute_secret", map[string]any{"namespace": "bot-ns", "name": "k", "action": "echo"})
		if !isErr || !strings.HasPrefix(txt, "approval timed out: a human did not approve in time") || !strings.Contains(txt, "(HTTP 403") {
			t.Fatalf("got (%q, %v)", txt, isErr)
		}
	})
	t.Run("tool descriptions name the approval wait", func(t *testing.T) {
		res, err := cs.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, tool := range res.Tools {
			waits := tool.Name == "execute_secret" || tool.Name == "lease_secret" || tool.Name == "execute_capability"
			if has := strings.Contains(tool.Description, "May wait up to 2m10s for a human to approve"); has != waits {
				t.Errorf("%s: approval note present=%v want %v: %q", tool.Name, has, waits, tool.Description)
			}
		}
	})
}
