package main

import (
	"database/sql"
	"io"

	"context"
	_ "modernc.org/sqlite"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/vault"
)

func TestMain(m *testing.M) {
	kdfParams = kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1}
	os.Exit(m.Run())
}

const allowAllPolicy = "rules:\n  - effect: allow\n    agent: \"*\"\n    namespace: \"*\"\n    purpose: \"*\"\n    action: \"*\"\n"

// useProvider makes every vault the CLI opens in this test use prov (no OS
// keyring in CI) and restores the seam afterwards.
func useProvider(t *testing.T, prov vault.MasterProvider) {
	t.Helper()
	old := newProvider
	newProvider = func(name string) (vault.MasterProvider, error) {
		if name != "keyring" && name != "platform" {
			return nil, os.ErrInvalid
		}
		return prov, nil
	}
	t.Cleanup(func() { newProvider = old })
}

// vaultEnv is an isolated CLI environment: a HOME, an in-memory master
// provider and a db path under a temp dir.
type vaultEnv struct {
	t      *testing.T
	home   string
	dir    string
	db     string
	policy string
	prov   *providerstest.Memory
}

func newVaultEnv(t *testing.T) *vaultEnv {
	t.Helper()
	isolateEnv(t)
	home, _ := os.UserHomeDir()
	dir := t.TempDir()
	e := &vaultEnv{t: t, home: home, dir: dir, db: filepath.Join(dir, "vault", "vault.db"), prov: providerstest.NewMemory()}
	e.policy = filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(e.policy, []byte(allowAllPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	useProvider(t, e.prov)
	t.Setenv("RGT_VAULT_DB", "")
	t.Setenv("RGT_VAULT_POLICY", "")
	t.Setenv("RGT_VAULT_PROVIDER", "")
	return e
}

// args prepends --db/--policy to a subcommand line.
func (e *vaultEnv) args(a ...string) []string {
	return append([]string{"--db", e.db, "--policy", e.policy}, a...)
}

func (e *vaultEnv) cli(stdin string, a ...string) (int, string, string) {
	e.t.Helper()
	return runCLI(e.t, stdin, e.args(a...)...)
}

func (e *vaultEnv) mustCLI(stdin string, a ...string) string {
	e.t.Helper()
	code, out, errb := e.cli(stdin, a...)
	if code != 0 {
		e.t.Fatalf("%v: exit %d\nstdout: %s\nstderr: %s", a, code, out, errb)
	}
	return out
}

// open opens the env's vault directly (for seeding and inspection).
func (e *vaultEnv) open() *server.Stack {
	e.t.Helper()
	stack, err := server.OpenStack(context.Background(), server.StackOptions{
		DBPath: e.db, PolicyFile: e.policy, MasterProvider: e.prov, KDFParams: kdfParams,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = stack.Close() })
	return stack
}

func (e *vaultEnv) seed(ns, name, value string) {
	e.t.Helper()
	stack := e.open()
	if err := stack.Vault.SetSecret(context.Background(), vault.SetSecretRequest{
		Name: name, Namespace: ns, Agent: "system", Purpose: "seed", Value: []byte(value),
	}); err != nil {
		e.t.Fatal(err)
	}
	_ = stack.Close()
}

// startServer serves the env's vault through server.New on httptest and
// returns the URL and the agent token.
func (e *vaultEnv) startServer() (url, token string) {
	e.t.Helper()
	stack := e.open()
	tok, err := auth.GenerateToken()
	if err != nil {
		e.t.Fatal(err)
	}
	ts := auth.NewTokenStore(filepath.Join(e.dir, "agent.token"))
	if err := ts.Write(tok); err != nil {
		e.t.Fatal(err)
	}
	h, err := server.New(server.Config{Vault: stack.Vault, AgentTokens: ts, LegacyPrivilegedRoutes: true, Actions: stack.Actions, Capabilities: stack.Capabilities})
	if err != nil {
		e.t.Fatal(err)
	}
	srv := newTestServer(e.t, h)
	return srv.URL, strings.TrimSpace(tok)
}

func newTestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// openRW opens a database read/write for tests that damage a fixture copy.
func openRW(path string) (*sql.DB, error) { return sql.Open("sqlite", path) }

// runServeForTest runs the CLI's serve with a ready callback, by wiring the
// same command tree the binary uses.
func runServeForTest(ctx context.Context, args []string, ready chan<- string) int {
	serveReady = func(a string) { ready <- a }
	defer func() { serveReady = nil }()
	return runContext(ctx, args, strings.NewReader(""), io.Discard, io.Discard)
}
