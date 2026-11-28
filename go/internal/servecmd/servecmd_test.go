package servecmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"rgt-vault-server/internal/auth"
	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/vault"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

var testKDF = kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1}

// memProvider is the in-memory master provider (no OS keyring in CI).
func memProvider(name string) (vault.MasterProvider, error) {
	if name != "keyring" && name != "platform" {
		return nil, fmt.Errorf("unknown provider %q", name)
	}
	return providerstest.NewMemory(), nil
}

// flagsOf is the Flags a bare `serve` parses to.
func flagsOf(mod func(*Flags)) Flags {
	f := Flags{ApprovalTimeout: DefaultApprovalTimeout}
	if mod != nil {
		mod(&f)
	}
	return f
}

func parse(f Flags, getenv func(string) string) (config, error) {
	return parseConfig(f, &VaultFlags{}, getenv)
}

func TestDefaults(t *testing.T) {
	cfg, err := parse(flagsOf(nil), env(map[string]string{"HOME": t.TempDir()}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.host != "127.0.0.1" || cfg.port != "8765" {
		t.Errorf("default bind = %s:%s, want 127.0.0.1:8765 (D6)", cfg.host, cfg.port)
	}
	if cfg.vault.Provider != "keyring" || cfg.vault.Policy != "" || !strings.HasSuffix(filepath.ToSlash(cfg.vault.DB), "/.secure-vault/vault.db") {
		t.Errorf("vault defaults: %+v", cfg.vault)
	}
	if len(cfg.origins) != 0 {
		t.Errorf("CORS must default to empty allow-list, got %v", cfg.origins)
	}
	if cfg.approvalTimeout != 120*time.Second || cfg.requireApproval || cfg.allowPrivateNetwork || cfg.allowInsecure {
		t.Errorf("defaults: %+v", cfg)
	}
}

func TestPrecedenceFlagOverEnvOverDefault(t *testing.T) {
	e := env(map[string]string{
		"RGT_VAULT_HOST": "10.0.0.5", "RGT_VAULT_PORT": "9000", "RGT_VAULT_TOKEN_FILE": "/tmp/x.token",
		"RGT_VAULT_DB": "/e/v.db", "RGT_VAULT_POLICY": "/e/p.yaml", "RGT_VAULT_PROVIDER": "platform",
		"RGT_VAULT_OPERATOR_TOKEN_FILE": "/e/op", "RGT_VAULT_TOTP_SECRET_FILE": "/e/totp", "RGT_VAULT_HARNESS_KEY_FILE": "/e/hk",
	})
	cfg, err := parse(flagsOf(func(f *Flags) { f.RequireApproval, f.LegacySharedToken = true, true }), e)
	if err != nil || cfg.host != "10.0.0.5" || cfg.port != "9000" || cfg.tokenFile != "/tmp/x.token" ||
		cfg.vault.DB != "/e/v.db" || cfg.vault.Policy != "/e/p.yaml" || cfg.vault.Provider != "platform" ||
		cfg.operatorTokenFile != "/e/op" || cfg.totpSecretFile != "/e/totp" || cfg.harnessKeyFile != "/e/hk" {
		t.Fatalf("env: %+v %v", cfg, err)
	}
	vf := &VaultFlags{DB: "/f/v.db", Provider: "keyring", Policy: "/f/p.yaml"}
	cfg, err = parseConfig(flagsOf(func(f *Flags) {
		f.Host, f.Port, f.RequireApproval, f.ApprovalTimeout, f.AllowPrivateNetwork = "::1", "1234", true, 5*time.Second, true
	}), vf, e)
	if err != nil || cfg.host != "::1" || cfg.port != "1234" || cfg.vault.DB != "/f/v.db" || cfg.vault.Provider != "keyring" ||
		cfg.vault.Policy != "/f/p.yaml" || cfg.approvalTimeout != 5*time.Second || !cfg.allowPrivateNetwork {
		t.Fatalf("flags: %+v %v", cfg, err)
	}
}

func TestParseConfigErrors(t *testing.T) {
	bad := []Flags{
		flagsOf(func(f *Flags) { f.ApprovalTimeout = MaxApprovalTimeout + time.Second }),
		flagsOf(func(f *Flags) { f.Port = "abc" }),
		flagsOf(func(f *Flags) { f.Port = "70000" }),
		flagsOf(func(f *Flags) { f.ApprovalTimeout = 0 }),
		flagsOf(func(f *Flags) { f.TOTPSecretFile = "/x" }), // without --require-approval
	}
	for i, f := range bad {
		if _, err := parse(f, env(nil)); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
	// --require-approval without an operator token would let the agent token approve.
	legacy := func(f *Flags) { f.LegacySharedToken, f.TokenFile = true, "/agent" }
	if _, err := parse(flagsOf(func(f *Flags) { legacy(f); f.RequireApproval = true }), env(nil)); err == nil || !strings.Contains(err.Error(), "--operator-token-file") {
		t.Errorf("legacy --require-approval without operator token: %v", err)
	}
	if _, err := parse(flagsOf(func(f *Flags) { legacy(f); f.RequireApproval, f.OperatorTokenFile = true, "/op" }), env(nil)); err != nil {
		t.Errorf("legacy --require-approval with operator token: %v", err)
	}
	// Per-agent mode: approval needs no operator token FILE (operator scope
	// lives in the store), and the legacy file flags are refused.
	if _, err := parse(flagsOf(func(f *Flags) { f.RequireApproval, f.TokenStore = true, "/s.json" }), env(nil)); err != nil {
		t.Errorf("store --require-approval: %v", err)
	}
	for _, mod := range []func(*Flags){
		func(f *Flags) { f.TokenFile = "/x" },
		func(f *Flags) { f.OperatorTokenFile = "/x" },
		func(f *Flags) { legacy(f); f.TokenStore = "/s.json" },
	} {
		if _, err := parse(flagsOf(mod), env(nil)); err == nil {
			t.Errorf("mixed legacy/store flags accepted: %+v", flagsOf(mod))
		}
	}
	if _, err := parseConfig(flagsOf(nil), &VaultFlags{Provider: "tpm"}, env(nil)); err == nil {
		t.Error("unknown provider accepted")
	}
	if _, err := parse(flagsOf(nil), env(map[string]string{"RGT_VAULT_MAX_BODY_BYTES": "-1"})); err == nil {
		t.Error("negative max body accepted")
	}
	cfg, err := parse(flagsOf(nil), env(map[string]string{"RGT_VAULT_MAX_BODY_BYTES": "42", "CORS_ALLOWED_ORIGINS": "https://a.example,*"}))
	if err != nil || cfg.maxBody != 42 || len(cfg.origins) != 1 || len(cfg.rejected) != 1 {
		t.Errorf("cfg = %+v err=%v", cfg, err)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for h, want := range map[string]bool{"127.0.0.1": true, "::1": true, "[::1]": true, "localhost": true, "LOCALHOST": true,
		"127.0.0.2": true, "0.0.0.0": false, "": false, "::": false, "192.168.1.1": false, "example.com": false} {
		if IsLoopbackHost(h) != want {
			t.Errorf("IsLoopbackHost(%q) != %v", h, want)
		}
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

func TestDefaultPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for got, name := range map[string]string{DefaultTokenPath(): "server.token", DefaultOperatorTokenPath(): "operator.token", DefaultTOTPPath(): "totp.secret"} {
		if want := filepath.Join(home, ".config", "rgt-vault", name); got != want {
			t.Errorf("%s path = %q, want %q", name, got, want)
		}
	}
}

// startServer runs the real command and returns its address, captured output and a stop func.
func startServer(t *testing.T, args []string, e map[string]string) (addr, tokenPath string, out, logs *bytes.Buffer, stop func()) {
	t.Helper()
	tokenPath = e["RGT_VAULT_TOKEN_FILE"]
	if tokenPath == "" && e["RGT_VAULT_TOKEN_STORE"] == "" {
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
		done <- execute(ctx, args, Env{
			Getenv: env(e), Stdout: out, Logger: log.New(logs, "", 0),
			Ready: func(a string) { ready <- a },
		})
	}()
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatalf("serve exited early: %v", err)
	case <-time.After(10 * time.Second):
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

// execute parses args with the real cobra command and runs it with e. The
// provider defaults to in-memory and Argon2 to cheap parameters.
func execute(ctx context.Context, args []string, e Env) error {
	if e.NewProvider == nil {
		e.NewProvider = memProvider
	}
	if e.KDFParams == (kdf.Params{}) {
		e.KDFParams = testKDF
	}
	if e.Stdout == nil {
		e.Stdout = io.Discard
	}
	if e.Logger == nil {
		e.Logger = log.New(io.Discard, "", 0)
	}
	// The pre-H1 tests here drive the shared token files: they run in the
	// (explicit) legacy mode. Store-mode tests pass --token-store.
	if e.Getenv != nil && e.Getenv("RGT_VAULT_TOKEN_FILE") != "" && !hasArg(args, "--token-store") {
		args = append([]string{"--legacy-shared-token"}, args...)
	}
	cmd := NewCommand(e, nil)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	return cmd.ExecuteContext(ctx)
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
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(tokenPath); fi.Mode().Perm() != 0o600 {
			t.Errorf("token file mode = %o, want 600", fi.Mode().Perm())
		}
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

// A non-loopback bind is refused unless explicitly allowed, and then warns.
func TestNonLoopbackBind(t *testing.T) {
	e := map[string]string{"RGT_VAULT_TOKEN_FILE": filepath.Join(t.TempDir(), "t"), "RGT_VAULT_DB": filepath.Join(t.TempDir(), "v.db")}
	err := execute(context.Background(), []string{"--host", "0.0.0.0", "--port", "0"}, Env{Getenv: env(e)})
	if err == nil || !strings.Contains(err.Error(), "not a loopback address") {
		t.Fatalf("0.0.0.0 without --allow-non-loopback: %v", err)
	}
	if _, serr := os.Stat(e["RGT_VAULT_TOKEN_FILE"]); serr == nil {
		t.Error("token file created before the bind check")
	}
	_, _, _, logs, stop := startServer(t, []string{"--host", "0.0.0.0", "--port", "0", "--allow-non-loopback"}, map[string]string{})
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
	ctx := context.Background()
	if err := execute(ctx, []string{"--port", port}, Env{Getenv: env(e)}); err == nil {
		t.Error("expected listen error on a busy port")
	}
	if err := execute(ctx, []string{"--port", "x"}, Env{Getenv: env(e)}); err == nil {
		t.Error("expected error on bad port")
	}
	if err := execute(ctx, []string{"--bogus"}, Env{Getenv: env(e)}); err == nil {
		t.Error("expected error on unknown flag")
	}
	if err := execute(ctx, []string{"extra-arg"}, Env{Getenv: env(e)}); err == nil {
		t.Error("expected error on a positional argument")
	}
	bad := map[string]string{"RGT_VAULT_TOKEN_FILE": t.TempDir()} // a directory, unreadable as token
	if err := execute(ctx, []string{"--port", "0"}, Env{Getenv: env(bad)}); err == nil {
		t.Error("expected token load error")
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
	db := filepath.Join(dir, "vault", "vault.db")
	e := map[string]string{"RGT_VAULT_DB": db, "RGT_VAULT_POLICY": policy}
	// The same provider (master secret) across both runs, like a real keyring.
	prov := providerstest.NewMemory()
	run := func() (string, string, *bytes.Buffer, func()) {
		out, logs := &bytes.Buffer{}, &bytes.Buffer{}
		ctx, cancel := context.WithCancel(context.Background())
		ready, done := make(chan string, 1), make(chan error, 1)
		tokenPath := e["RGT_VAULT_TOKEN_FILE"]
		if tokenPath == "" {
			tokenPath = filepath.Join(dir, "srv.token")
			e["RGT_VAULT_TOKEN_FILE"] = tokenPath
		}
		go func() {
			done <- execute(ctx, []string{"--port", "0", "--legacy-allow-privileged-routes"}, Env{
				Getenv: env(e), Stdout: out, Logger: log.New(logs, "", 0), Ready: func(a string) { ready <- a },
				NewProvider: func(string) (vault.MasterProvider, error) { return prov, nil },
			})
		}()
		select {
		case a := <-ready:
			return a, tokenPath, out, func() {
				cancel()
				if err := <-done; err != nil {
					t.Errorf("shutdown: %v", err)
				}
			}
		case err := <-done:
			t.Fatalf("serve exited early: %v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("server did not start")
		}
		return "", "", nil, nil
	}
	addr, tokenPath, out, stop := run()
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

	addr2, _, _, stop2 := run()
	defer stop2()
	if code, body := call(addr2, "POST", "/v1/secrets/p/k/lease", `{"agent":"a"}`); code != 200 || !strings.Contains(body, `"persisted"`) {
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
	// With --harness-key-file the verifier is wired: the capability endpoint
	// no longer fails closed on a missing verifier (a bad token is rejected
	// as such, 401/403/400, not by the "no verifier" 5xx path).
	req, _ := http.NewRequest("POST", "http://"+addr+"/v1/capabilities/execute", strings.NewReader(`{"capability":"secrets.echo","agent":"a","token":"x.y"}`))
	req.Header.Set("Authorization", "Bearer "+agentTok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		t.Errorf("capability execute with a harness key: HTTP %d", resp.StatusCode)
	}
}

func TestServerStartupErrors(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "agent.token")
	base := func() map[string]string {
		return map[string]string{"RGT_VAULT_TOKEN_FILE": tok, "RGT_VAULT_DB": filepath.Join(dir, "v", "vault.db")}
	}
	runWith := func(args []string, e map[string]string, np func(string) (vault.MasterProvider, error)) error {
		return execute(context.Background(), append([]string{"--port", "0"}, args...), Env{Getenv: env(e), NewProvider: np})
	}
	if _, _, err := auth.LoadOrCreateToken(tok); err != nil {
		t.Fatal(err)
	}
	// operator token equal to the agent token
	e := base()
	e["RGT_VAULT_OPERATOR_TOKEN_FILE"] = tok
	if err := runWith(nil, e, nil); err == nil || !strings.Contains(err.Error(), "differ") {
		t.Errorf("same operator token: %v", err)
	}
	e = base()
	e["RGT_VAULT_POLICY"] = filepath.Join(dir, "missing.yaml")
	if err := runWith(nil, e, nil); err == nil || !strings.Contains(err.Error(), "open vault") {
		t.Errorf("missing policy: %v", err)
	}
	e = base()
	e["RGT_VAULT_OPERATOR_TOKEN_FILE"] = dir // a directory
	if err := runWith(nil, e, nil); err == nil {
		t.Error("unreadable operator token accepted")
	}
	if err := runWith(nil, base(), func(string) (vault.MasterProvider, error) { return nil, fmt.Errorf("no keyring here") }); err == nil || !strings.Contains(err.Error(), "no keyring") {
		t.Errorf("provider error: %v", err)
	}
}

// A weak or empty token file is refused instead of being served (RGT-498).
func TestWeakTokenRefused(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{"short": "hunter2\n", "empty": "", "repeated": strings.Repeat("A", 44)} {
		tok := filepath.Join(dir, name+".token")
		if err := os.WriteFile(tok, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		e := map[string]string{"RGT_VAULT_TOKEN_FILE": tok, "RGT_VAULT_DB": filepath.Join(dir, name, "v.db")}
		err := execute(context.Background(), []string{"--port", "0"}, Env{Getenv: env(e)})
		if err == nil || !strings.Contains(err.Error(), "too weak") {
			t.Errorf("%s token: %v", name, err)
		}
		if err != nil && content != "" && strings.Contains(err.Error(), strings.TrimSpace(content)) {
			t.Errorf("%s token echoed in %q", name, err)
		}
	}
	// A weak operator token too.
	good := filepath.Join(dir, "good.token")
	op := filepath.Join(dir, "op.token")
	_ = os.WriteFile(op, []byte("short\n"), 0o600)
	e := map[string]string{"RGT_VAULT_TOKEN_FILE": good, "RGT_VAULT_OPERATOR_TOKEN_FILE": op, "RGT_VAULT_DB": filepath.Join(dir, "g", "v.db")}
	if err := execute(context.Background(), []string{"--port", "0"}, Env{Getenv: env(e)}); err == nil || !strings.Contains(err.Error(), "operator token") {
		t.Errorf("weak operator token: %v", err)
	}
}

func TestValidateToken(t *testing.T) {
	good, err := auth.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 40)
	for i := range raw {
		raw[i] = byte(i*i*37 + 0xfb) // not a progression; exercises '+' and '/' in std base64
	}
	seq, step5 := make([]byte, 40), make([]byte, 40)
	for i := range seq {
		seq[i], step5[i] = byte(i), byte(5*i)
	}
	for name, tok := range map[string]string{
		"generated":     good,
		"generated+nl":  good + "\n",
		"raw url":       strings.TrimRight(good, "="),
		"hex 32 bytes":  "9f3a61c27be0d45812aa90cb7734e1fd05b6c8a2713d9e4f6a0b25c7e8d1f349",
		"std base64":    base64.StdEncoding.EncodeToString(raw),
		"raw std":       base64.RawStdEncoding.EncodeToString(raw),
		"url base64 40": base64.URLEncoding.EncodeToString(raw),
	} {
		if err := ValidateToken(tok); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
	for name, tok := range map[string]string{
		"empty": "", "blank": "  \n", "short": "abc",
		"31 bytes":   base64.StdEncoding.EncodeToString(raw[:31]),
		"plain text": "this is not base64 at all, but it is long enough",
		"all zero":   strings.Repeat("00", 40), "hex 16 bytes": strings.Repeat("ab", 16),
		"sequential hex":    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"sequential base64": base64.StdEncoding.EncodeToString(seq),
		"step-5 hex":        hex.EncodeToString(step5),
		"15 distinct bytes": hex.EncodeToString(append(bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 250}, 3), 1, 2, 3))[:96],
		"repeated A":        strings.Repeat("A", 44), "short pattern": strings.Repeat("abcd", 20),
	} {
		err := ValidateToken(tok)
		if err == nil {
			t.Errorf("%s accepted", name)
		} else if !strings.Contains(err.Error(), "too weak") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTightenFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := TightenFile(p); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %o", fi.Mode().Perm())
		}
	}
	if err := TightenFile(p); err != nil { // already tight
		t.Fatal(err)
	}
	if err := TightenFile(p + ".missing"); err == nil {
		t.Error("missing file accepted")
	}
}

// NewCommand registers the vault flags itself when none are shared.
func TestNewCommandFlags(t *testing.T) {
	cmd := NewCommand(Env{}, nil)
	for _, name := range []string{"db", "policy", "provider", "host", "port", "allow-non-loopback", "token-file",
		"operator-token-file", "require-approval", "totp-secret-file", "approval-timeout", "harness-key-file", "allow-private-network"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag --%s missing", name)
		}
	}
	if got := cmd.Flags().Lookup("port").Usage; !strings.Contains(got, "8765") {
		t.Errorf("--port help = %q", got)
	}
	// With shared flags the command does not define its own.
	shared := &VaultFlags{}
	root := &cobra.Command{Use: "root"}
	shared.Register(root, true)
	serve := NewCommand(Env{}, shared)
	root.AddCommand(serve)
	if serve.LocalNonPersistentFlags().Lookup("db") != nil {
		t.Error("serve defined its own --db next to the shared one")
	}
}

func TestMainPrintsErrorAndReturnsCode(t *testing.T) {
	var errb bytes.Buffer
	cmd := NewCommand(Env{Getenv: env(nil)}, nil)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetErr(&errb)
	if code := Main(cmd, []string{"--port", "not-a-port"}); code != 1 || !strings.Contains(errb.String(), "Error: invalid port") {
		t.Errorf("code %d stderr %q", code, errb.String())
	}
}

func TestTightenFileClearsSpecialBits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600|os.ModeSetgid|os.ModeSticky); err != nil {
		t.Skip("cannot set special bits here:", err)
	}
	if err := TightenFile(p); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
}

func TestTokensEqualAndListenContext(t *testing.T) {
	if !tokensEqual("a", "a") || tokensEqual("a", "b") || tokensEqual("a", "aa") {
		t.Error("tokensEqual")
	}
	e := map[string]string{"RGT_VAULT_TOKEN_FILE": filepath.Join(t.TempDir(), "t"), "RGT_VAULT_DB": filepath.Join(t.TempDir(), "v.db")}
	err := execute(context.Background(), []string{"--host", "203.0.113.9", "--allow-non-loopback", "--port", "0"}, Env{Getenv: env(e)})
	if err == nil || !strings.Contains(err.Error(), "listen on 203.0.113.9:0") {
		t.Errorf("listen error lacks the address: %v", err)
	}
}

func hasArg(args []string, a string) bool {
	for _, x := range args {
		if x == a || strings.HasPrefix(x, a+"=") {
			return true
		}
	}
	return false
}
