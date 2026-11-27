package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/vault"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// TestMain swaps the master provider for an in-memory one (no OS keyring in
// CI) and uses cheap Argon2 parameters for the throwaway test vaults.
func TestMain(m *testing.M) {
	newProvider = func(name string) (vault.MasterProvider, error) {
		if name != "keyring" && name != "platform" {
			return nil, fmt.Errorf("unknown provider %q", name)
		}
		return providerstest.NewMemory(), nil
	}
	kdfParams = kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1}
	os.Exit(m.Run())
}

func TestDefaultBindIsLoopback(t *testing.T) {
	cfg, err := parseConfig(nil, env(map[string]string{"HOME": t.TempDir()}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.host != "127.0.0.1" {
		t.Errorf("default host = %q, want 127.0.0.1", cfg.host)
	}
	if cfg.port != "8765" {
		t.Errorf("default port = %q", cfg.port)
	}
	if len(cfg.origins) != 0 {
		t.Errorf("CORS must default to empty allow-list, got %v", cfg.origins)
	}
}

func TestBindOverridePrecedence(t *testing.T) {
	e := env(map[string]string{"RGT_VAULT_HOST": "10.0.0.5", "RGT_VAULT_PORT": "9000", "RGT_VAULT_TOKEN_FILE": "/tmp/x.token"})
	cfg, err := parseConfig(nil, e, io.Discard)
	if err != nil || cfg.host != "10.0.0.5" || cfg.port != "9000" || cfg.tokenFile != "/tmp/x.token" {
		t.Fatalf("env override: %+v %v", cfg, err)
	}
	cfg, err = parseConfig([]string{"--host", "::1", "--port", "1234"}, e, io.Discard)
	if err != nil || cfg.host != "::1" || cfg.port != "1234" {
		t.Fatalf("flag override: %+v %v", cfg, err)
	}
}

func TestParseConfigErrors(t *testing.T) {
	for _, args := range [][]string{{"--port", "abc"}, {"--port", "70000"}, {"--bogus"}} {
		if _, err := parseConfig(args, env(nil), io.Discard); err == nil {
			t.Errorf("args %v: expected error", args)
		}
	}
	if _, err := parseConfig(nil, env(map[string]string{"RGT_VAULT_MAX_BODY_BYTES": "-1"}), io.Discard); err == nil {
		t.Error("negative max body accepted")
	}
	cfg, err := parseConfig(nil, env(map[string]string{"RGT_VAULT_MAX_BODY_BYTES": "42", "CORS_ALLOWED_ORIGINS": "https://a.example,*"}), io.Discard)
	if err != nil || cfg.maxBody != 42 || len(cfg.origins) != 1 || len(cfg.rejected) != 1 {
		t.Errorf("cfg = %+v err=%v", cfg, err)
	}
}

func TestIsLoopback(t *testing.T) {
	for h, want := range map[string]bool{"127.0.0.1": true, "::1": true, "localhost": true, "127.0.0.2": true, "0.0.0.0": false, "": false, "::": false, "192.168.1.1": false} {
		if isLoopback(h) != want {
			t.Errorf("isLoopback(%q) != %v", h, want)
		}
	}
}

// startServer runs the real run() and returns its address, captured output and a stop func.
func startServer(t *testing.T, args []string, e map[string]string) (addr, tokenPath string, out, logs *bytes.Buffer, stop func()) {
	t.Helper()
	tokenPath = e["RGT_VAULT_TOKEN_FILE"]
	if tokenPath == "" {
		tokenPath = filepath.Join(t.TempDir(), "srv.token")
		e["RGT_VAULT_TOKEN_FILE"] = tokenPath
	}
	if e["RGT_VAULT_DB"] == "" {
		e["RGT_VAULT_DB"] = filepath.Join(t.TempDir(), "vault", "vault.db")
	}
	out, logs = &bytes.Buffer{}, &bytes.Buffer{}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, args, env(e), out, log.New(logs, "", 0), func(a string) { ready <- a })
	}()
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatalf("run exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}
	return addr, tokenPath, out, logs, func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("shutdown error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("shutdown timed out")
		}
	}
}

func TestTokenNeverLoggedOrPrinted(t *testing.T) {
	addr, tokenPath, out, logs, stop := startServer(t, []string{"--port", "0"}, map[string]string{})
	defer stop()

	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(raw))
	if len(token) < 32 {
		t.Fatalf("token looks wrong: len=%d", len(token))
	}

	// Authenticated request so any request-path logging also gets exercised.
	req, _ := http.NewRequest("GET", "http://"+addr+"/v1/actions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("authed status = %d", resp.StatusCode)
	}

	for name, buf := range map[string]*bytes.Buffer{"stdout": out, "log": logs} {
		if strings.Contains(buf.String(), token) {
			t.Errorf("%s contains the full bearer token:\n%s", name, buf.String())
		}
	}
	// Positive control: path and the short id ARE shown.
	if !strings.Contains(logs.String(), tokenPath) || !strings.Contains(logs.String(), "Token ID: ") {
		t.Errorf("log lacks token path/id:\n%s", logs.String())
	}
	if !strings.Contains(out.String(), "id ") || !strings.Contains(out.String(), tokenPath) {
		t.Errorf("banner lacks token path/id:\n%s", out.String())
	}
}

func TestServerBindsLoopbackByDefault(t *testing.T) {
	addr, _, _, logs, stop := startServer(t, []string{"--port", "0"}, map[string]string{})
	defer stop()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Errorf("bound to %q, want 127.0.0.1:*", addr)
	}
	if strings.Contains(logs.String(), "WARNING: listening on non-loopback") {
		t.Error("loopback bind must not warn")
	}
}

func TestNonLoopbackBindWarns(t *testing.T) {
	_, _, _, logs, stop := startServer(t, []string{"--host", "0.0.0.0", "--port", "0"}, map[string]string{})
	defer stop()
	if !strings.Contains(logs.String(), "non-loopback") {
		t.Errorf("no warning for 0.0.0.0 bind:\n%s", logs.String())
	}
}

func TestServerCORSFromEnvAndWildcardWarning(t *testing.T) {
	addr, _, _, logs, stop := startServer(t, []string{"--port", "0"},
		map[string]string{"CORS_ALLOWED_ORIGINS": "https://ok.example,*"})
	defer stop()
	if !strings.Contains(logs.String(), "ignoring CORS origin") {
		t.Errorf("wildcard not warned about:\n%s", logs.String())
	}
	get := func(origin string) string {
		req, _ := http.NewRequest("GET", "http://"+addr+"/healthz", nil)
		req.Header.Set("Origin", origin)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.Header.Get("Access-Control-Allow-Origin")
	}
	if got := get("https://ok.example"); got != "https://ok.example" {
		t.Errorf("allowed origin ACAO = %q", got)
	}
	if got := get("https://other.example"); got != "" {
		t.Errorf("other origin ACAO = %q", got)
	}
}

func TestRunFailsOnBusyPortAndBadFlags(t *testing.T) {
	addr, _, _, _, stop := startServer(t, []string{"--port", "0"}, map[string]string{})
	defer stop()
	port := addr[strings.LastIndex(addr, ":")+1:]
	e := map[string]string{"RGT_VAULT_TOKEN_FILE": filepath.Join(t.TempDir(), "t2"), "RGT_VAULT_DB": filepath.Join(t.TempDir(), "v.db")}
	if err := run(context.Background(), []string{"--port", port}, env(e), io.Discard, log.New(io.Discard, "", 0), nil); err == nil {
		t.Error("expected listen error on a busy port")
	}
	if err := run(context.Background(), []string{"--port", "x"}, env(e), io.Discard, log.New(io.Discard, "", 0), nil); err == nil {
		t.Error("expected error on bad port")
	}
	bad := map[string]string{"RGT_VAULT_TOKEN_FILE": t.TempDir()} // a directory, unreadable as token
	if err := run(context.Background(), []string{"--port", "0"}, env(bad), io.Discard, log.New(io.Discard, "", 0), nil); err == nil {
		t.Error("expected token load error")
	}
}

// TestSystemdUnitIsSandboxed pins the hardening directives of the Go unit.
func TestSystemdUnitIsSandboxed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "rgt-vault-go.service"))
	if err != nil {
		t.Fatal(err)
	}
	unit := string(raw)
	for _, want := range []string{
		"User=rgtvault", "Group=rgtvault", "NoNewPrivileges=true", "ProtectSystem=strict",
		"ProtectHome=true", "PrivateTmp=true", "PrivateDevices=true", "CapabilityBoundingSet=",
		"RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", "SystemCallFilter=@system-service",
		"MemoryDenyWriteExecute=true", "UMask=0077", "--host 127.0.0.1",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q", want)
		}
	}
	if strings.Contains(unit, "User=root") || strings.Contains(unit, "0.0.0.0") {
		t.Error("unit must not run as root or bind 0.0.0.0")
	}
}

func TestParseConfigVaultFlags(t *testing.T) {
	cfg, err := parseConfig(nil, env(nil), io.Discard)
	if err != nil || cfg.db != "~/.secure-vault/vault.db" || cfg.provider != "keyring" || cfg.policy != "" ||
		cfg.approvalTimeout != 120*time.Second || cfg.requireApproval || cfg.allowPrivateNetwork {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
	e := env(map[string]string{
		"RGT_VAULT_DB": "/e/v.db", "RGT_VAULT_POLICY": "/e/p.yaml", "RGT_VAULT_PROVIDER": "platform",
		"RGT_VAULT_OPERATOR_TOKEN_FILE": "/e/op", "RGT_VAULT_TOTP_SECRET_FILE": "/e/totp", "RGT_VAULT_HARNESS_KEY_FILE": "/e/hk",
	})
	cfg, err = parseConfig([]string{"--require-approval"}, e, io.Discard)
	if err != nil || cfg.db != "/e/v.db" || cfg.policy != "/e/p.yaml" || cfg.provider != "platform" ||
		cfg.operatorTokenFile != "/e/op" || cfg.totpSecretFile != "/e/totp" || cfg.harnessKeyFile != "/e/hk" {
		t.Fatalf("env: %+v %v", cfg, err)
	}
	cfg, err = parseConfig([]string{"--db", "/f/v.db", "--provider", "keyring", "--require-approval",
		"--approval-timeout", "5s", "--allow-private-network"}, e, io.Discard)
	if err != nil || cfg.db != "/f/v.db" || cfg.provider != "keyring" || cfg.approvalTimeout != 5*time.Second || !cfg.allowPrivateNetwork {
		t.Fatalf("flags: %+v %v", cfg, err)
	}
	for _, bad := range [][]string{
		{"--provider", "tpm"}, {"--approval-timeout", "0s"}, {"extra-arg"},
		{"--totp-secret-file", "/x"}, // without --require-approval
	} {
		if _, err := parseConfig(bad, env(nil), io.Discard); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

// The server runs on a real, persistent vault: a secret written through
// one run is there after a restart on the same --db.
func TestServerPersistsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte("rules:\n  - effect: allow\n    agent: \"*\"\n    namespace: \"*\"\n    purpose: \"*\"\n    action: \"*\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prov := providerstest.NewMemory()
	old := newProvider
	newProvider = func(string) (vault.MasterProvider, error) { return prov, nil }
	defer func() { newProvider = old }()

	db := filepath.Join(dir, "vault", "vault.db")
	e := map[string]string{"RGT_VAULT_DB": db, "RGT_VAULT_POLICY": policy}
	addr, tokenPath, out, _, stop := startServer(t, []string{"--port", "0"}, e)
	raw, _ := os.ReadFile(tokenPath)
	token := strings.TrimSpace(string(raw))
	call := func(addr, method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, "http://"+addr+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := call(addr, "POST", "/v1/secrets", `{"name":"k","value":"persisted","namespace":"p"}`); code != 200 {
		t.Fatalf("set: %d %s", code, body)
	}
	if !strings.Contains(out.String(), db) {
		t.Errorf("banner lacks the vault path:\n%s", out.String())
	}
	stop()

	e["RGT_VAULT_TOKEN_FILE"] = tokenPath
	addr2, _, _, _, stop2 := startServer(t, []string{"--port", "0"}, e)
	defer stop2()
	if code, body := call(addr2, "GET", "/v1/secrets?namespace=p&name=k", ""); code != 200 || !strings.Contains(body, `"persisted"`) {
		t.Fatalf("after restart: %d %s", code, body)
	}
	if _, err := os.Stat(filepath.Join(dir, "vault", "keychain.json")); err != nil {
		t.Errorf("keychain.json not next to the db: %v", err)
	}
}

func TestServerApprovalAndOperatorWiring(t *testing.T) {
	dir := t.TempDir()
	totpFile := filepath.Join(dir, "totp.secret")
	if err := os.WriteFile(totpFile, []byte("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hk := filepath.Join(dir, "harness.key")
	if err := os.WriteFile(hk, []byte(strings.Repeat("k", 40)), 0o600); err != nil {
		t.Fatal(err)
	}
	opPath := filepath.Join(dir, "operator.token")
	addr, tokenPath, _, logs, stop := startServer(t, []string{"--port", "0", "--require-approval",
		"--totp-secret-file", totpFile, "--operator-token-file", opPath, "--harness-key-file", hk,
		"--allow-private-network"}, map[string]string{})
	defer stop()
	agentRaw, _ := os.ReadFile(tokenPath)
	opRaw, _ := os.ReadFile(opPath)
	agentTok, opTok := strings.TrimSpace(string(agentRaw)), strings.TrimSpace(string(opRaw))
	get := func(tok, path string) int {
		req, _ := http.NewRequest("GET", "http://"+addr+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if get(opTok, "/v1/requests") != 200 || get(agentTok, "/v1/requests") != 401 || get(opTok, "/v1/audit") != 401 {
		t.Error("operator scope not separated")
	}
	for _, want := range []string{"Operator token file", "allow-private-network", "no --policy"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, logs.String())
		}
	}
	if strings.Contains(logs.String(), opTok) || strings.Contains(logs.String(), agentTok) {
		t.Error("a token was logged")
	}
}

func TestServerStartupErrors(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "agent.token")
	base := func() map[string]string {
		return map[string]string{"RGT_VAULT_TOKEN_FILE": tok, "RGT_VAULT_DB": filepath.Join(dir, "v", "vault.db")}
	}
	runWith := func(args []string, e map[string]string) error {
		return run(context.Background(), append([]string{"--port", "0"}, args...), env(e), io.Discard, log.New(io.Discard, "", 0), nil)
	}
	if _, _, err := auth.LoadOrCreateToken(tok); err != nil {
		t.Fatal(err)
	}
	// operator token equal to the agent token
	e := base()
	e["RGT_VAULT_OPERATOR_TOKEN_FILE"] = tok
	if err := runWith(nil, e); err == nil || !strings.Contains(err.Error(), "differ") {
		t.Errorf("same operator token: %v", err)
	}
	e = base()
	e["RGT_VAULT_POLICY"] = filepath.Join(dir, "missing.yaml")
	if err := runWith(nil, e); err == nil || !strings.Contains(err.Error(), "open vault") {
		t.Errorf("missing policy: %v", err)
	}
	e = base()
	e["RGT_VAULT_OPERATOR_TOKEN_FILE"] = dir // a directory
	if err := runWith(nil, e); err == nil {
		t.Error("unreadable operator token accepted")
	}
	old := newProvider
	newProvider = func(string) (vault.MasterProvider, error) { return nil, fmt.Errorf("no keyring here") }
	defer func() { newProvider = old }()
	if err := runWith(nil, base()); err == nil || !strings.Contains(err.Error(), "no keyring") {
		t.Errorf("provider error: %v", err)
	}
}

func TestWriteTimeoutOutlastsApproval(t *testing.T) {
	if got := writeTimeout(config{}); got != 60*time.Second {
		t.Errorf("default = %s", got)
	}
	if got := writeTimeout(config{requireApproval: true, approvalTimeout: 120 * time.Second}); got != 180*time.Second {
		t.Errorf("with approval = %s", got)
	}
}
