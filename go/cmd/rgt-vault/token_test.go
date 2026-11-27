package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rgt-vault-server/internal/auth"
)

func tokenLine(t *testing.T, out string) string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	return lines[len(lines)-1]
}

func TestTokenCommands(t *testing.T) {
	isolateEnv(t)
	store := filepath.Join(t.TempDir(), "cfg", "tokens.json")
	t.Setenv("RGT_VAULT_TOKEN_STORE", store)

	code, out, stderr := runCLI(t, "", "token", "mint", "--agent", "bot", "--scope", "agent,lease", "--expires", "24h")
	if code != 0 {
		t.Fatalf("mint: %d %s", code, stderr)
	}
	tok := tokenLine(t, out)
	if !strings.Contains(out, "agent bot") || !strings.Contains(out, "scopes agent,lease") || !strings.Contains(out, "shown once") || len(tok) < 43 {
		t.Fatalf("mint output %q", out)
	}
	p, err := auth.OpenStore(store).Authenticate(tok)
	if err != nil || p.Agent != "bot" || !p.Has(auth.ScopeLease) {
		t.Fatalf("minted token: %+v %v", p, err)
	}
	assertMode0600(t, store)

	// --out writes 0600 and prints no token; never overwrites.
	outFile := filepath.Join(t.TempDir(), "ops.token")
	code, out, _ = runCLI(t, "", "token", "mint", "--store", store, "--agent", "ops", "--scope", "operator", "--out", outFile)
	opsTok := strings.TrimSpace(string(mustRead(t, outFile)))
	if code != 0 || strings.Contains(out, opsTok) || !strings.Contains(out, "written to") {
		t.Fatalf("mint --out: %d %q", code, out)
	}
	assertMode0600(t, outFile)
	if code, _, stderr := runCLI(t, "", "token", "mint", "--agent", "x", "--out", outFile); code != 1 || !strings.Contains(stderr, "not overwriting") {
		t.Errorf("mint --out over an existing file: %d %q", code, stderr)
	}

	// list: ids, agents, scopes, expiry; never a token or a hash.
	code, out, _ = runCLI(t, "", "token", "list")
	if code != 0 || !strings.Contains(out, "ID") || !strings.Contains(out, "bot") || !strings.Contains(out, "ops") || !strings.Contains(out, "never") {
		t.Fatalf("list: %d %q", code, out)
	}
	code, jsonOut, _ := runCLI(t, "", "token", "list", "--json")
	var listed struct {
		Tokens []auth.TokenInfo `json:"tokens"`
	}
	if code != 0 || json.Unmarshal([]byte(jsonOut), &listed) != nil || len(listed.Tokens) != 3 {
		t.Fatalf("list --json: %d %q", code, jsonOut)
	}
	for _, secret := range []string{tok, opsTok} {
		d := sha256.Sum256([]byte(secret))
		for _, o := range []string{out, jsonOut} {
			if strings.Contains(o, secret) || strings.Contains(o, hex.EncodeToString(d[:])) {
				t.Fatal("token list leaks a token or its hash")
			}
		}
	}
	botID := ""
	for _, in := range listed.Tokens {
		if in.Agent == "bot" {
			botID = in.ID
		}
	}

	// rotate: new token, old one dead, same agent/scopes.
	code, out, stderr = runCLI(t, "", "token", "rotate", botID)
	if code != 0 || !strings.Contains(out, "rotated "+botID+" -> id ") {
		t.Fatalf("rotate: %d %q %q", code, out, stderr)
	}
	newTok := tokenLine(t, out)
	st := auth.OpenStore(store)
	if _, err := st.Authenticate(tok); err == nil {
		t.Error("old token still valid after rotate")
	}
	np, err := st.Authenticate(newTok)
	if err != nil || np.Agent != "bot" || !np.Has(auth.ScopeLease) {
		t.Fatalf("rotated token: %+v %v", np, err)
	}
	// revoke
	if code, out, _ := runCLI(t, "", "token", "revoke", np.TokenID); code != 0 || !strings.Contains(out, "revoked id "+np.TokenID) {
		t.Errorf("revoke: %d %q", code, out)
	}
	if _, err := st.Authenticate(newTok); err == nil {
		t.Error("revoked token still valid")
	}
	if code, _, stderr := runCLI(t, "", "token", "revoke", np.TokenID); code != 1 || !strings.Contains(stderr, "no token with that id") {
		t.Errorf("revoke twice: %d %q", code, stderr)
	}
	if code, _, _ := runCLI(t, "", "token", "rotate", "tok_missing"); code != 1 {
		t.Error("rotate unknown id")
	}

	// import: a legacy token file keeps working under an agent.
	legacy, _ := auth.GenerateToken()
	lf := mustWrite(t, t.TempDir(), "server.token", legacy+"\n")
	code, out, stderr = runCLI(t, "", "token", "import", "--file", lf, "--agent", "ci-runner", "--scope", "agent")
	if code != 0 || strings.Contains(out, legacy) || !strings.Contains(out, "imported") {
		t.Fatalf("import: %d %q %q", code, out, stderr)
	}
	if p, err := st.Authenticate(legacy); err != nil || p.Agent != "ci-runner" {
		t.Errorf("imported token: %+v %v", p, err)
	}
	if code, _, stderr := runCLI(t, "", "token", "import", "--file", lf, "--agent", "x"); code != 1 || !strings.Contains(stderr, "already") {
		t.Errorf("import twice: %d %q", code, stderr)
	}
	weak := mustWrite(t, t.TempDir(), "weak", "hunter2\n")
	if code, out, stderr := runCLI(t, "", "token", "import", "--file", weak, "--agent", "x"); code != 1 || strings.Contains(out+stderr, "hunter2") {
		t.Errorf("weak import: %d %q", code, stderr)
	}

	// Bad input.
	for _, args := range [][]string{
		{"token", "mint"}, // --agent required
		{"token", "mint", "--agent", "bot", "--scope", "root"},
		{"token", "mint", "--agent", "bad agent"},
		{"token", "import", "--file", filepath.Join(t.TempDir(), "missing"), "--agent", "x"},
		{"token", "import", "--file", lf, "--agent", "x", "--scope", ""},
	} {
		if code, _, _ := runCLI(t, "", args...); code != 1 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

// init (per-agent mode) mints an operator token into the store, imports an
// existing operator token file once, and --force revokes the replaced one.
func TestInitTokenStore(t *testing.T) {
	e := newVaultEnv(t)
	store := filepath.Join(e.dir, "cfg", "tokens.json")
	op := filepath.Join(e.dir, "cfg", "operator.token")
	args := func(extra ...string) []string {
		return e.args(append([]string{"init", "--token-store", store, "--operator-token-file", op}, extra...)...)
	}
	// An operator token file from a pre-H1 init is imported.
	legacy, _ := auth.GenerateToken()
	if err := os.MkdirAll(filepath.Dir(op), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(op, []byte(legacy+"\n"), 0o600)
	code, out, stderr := runCLI(t, "", args()...)
	if code != 0 || !strings.Contains(out, "imported into the store") || strings.Contains(out, legacy) {
		t.Fatalf("init import: %d %q %q", code, out, stderr)
	}
	st := auth.OpenStore(store)
	p, err := st.Authenticate(legacy)
	if err != nil || p.Agent != "operator" || !p.Has(auth.ScopeOperator) || !p.Has(auth.ScopeLease) || !p.Has(auth.ScopeAgent) {
		t.Fatalf("imported operator token: %+v %v", p, err)
	}
	// Again: kept.
	if code, out, _ := runCLI(t, "", args()...); code != 0 || !strings.Contains(out, "kept (in the store as "+p.TokenID) {
		t.Fatalf("second init: %d %q", code, out)
	}
	// --force: a new token, the old one revoked.
	code, out, _ = runCLI(t, "", args("--force")...)
	if code != 0 || !strings.Contains(out, "replaced") || !strings.Contains(out, p.TokenID+" revoked") {
		t.Fatalf("init --force: %d %q", code, out)
	}
	if _, err := st.Authenticate(legacy); err == nil {
		t.Error("replaced operator token still valid")
	}
	fresh := strings.TrimSpace(string(mustRead(t, op)))
	if fp, err := st.Authenticate(fresh); err != nil || fp.Agent != "operator" {
		t.Errorf("new operator token: %+v %v", fp, err)
	}
	if strings.Contains(out, fresh) {
		t.Error("init printed the token")
	}
	assertMode0600(t, op)
	assertMode0600(t, store)

	// A fresh directory: created; a custom operator agent; "-" skips it.
	store2 := filepath.Join(e.dir, "c2", "tokens.json")
	op2 := filepath.Join(e.dir, "c2", "op.token")
	if code, out, stderr := runCLI(t, "", "init", "--tokens-only", "--token-store", store2, "--operator-token-file", op2, "--operator-agent", "root-ops"); code != 0 || !strings.Contains(out, "created as tok_") {
		t.Fatalf("init fresh: %d %q %q", code, out, stderr)
	}
	if p, err := auth.OpenStore(store2).Authenticate(strings.TrimSpace(string(mustRead(t, op2)))); err != nil || p.Agent != "root-ops" {
		t.Errorf("custom operator agent: %+v %v", p, err)
	}
	store3 := filepath.Join(e.dir, "c3", "tokens.json")
	if code, out, _ := runCLI(t, "", "init", "--tokens-only", "--token-store", store3, "--operator-token-file", "-"); code != 0 || !strings.Contains(out, "no operator token") {
		t.Errorf("init -: %d %q", code, out)
	}
	if infos, err := auth.OpenStore(store3).List(); err != nil || len(infos) != 0 {
		t.Errorf("store3 = %v %v", infos, err)
	}
	// Errors: a weak operator file, a corrupt store, --token-file without legacy.
	weakOp := mustWrite(t, e.dir, "weak.token", "hunter2\n")
	if code, _, stderr := runCLI(t, "", "init", "--tokens-only", "--token-store", store3, "--operator-token-file", weakOp); code != 1 || !strings.Contains(stderr, "too weak") {
		t.Errorf("weak operator file: %d %q", code, stderr)
	}
	bad := mustWrite(t, e.dir, "bad.json", "{")
	if code, _, _ := runCLI(t, "", "init", "--tokens-only", "--token-store", bad, "--operator-token-file", op2); code != 1 {
		t.Error("corrupt store accepted")
	}
	if b, _ := os.ReadFile(bad); string(b) != "{" {
		t.Error("corrupt store rewritten")
	}
	if code, _, stderr := runCLI(t, "", "init", "--tokens-only", "--token-file", "/x"); code != 1 || !strings.Contains(stderr, "--legacy-shared-token") {
		t.Errorf("--token-file without legacy: %d %q", code, stderr)
	}
}

// The CLI client token: flag > RGT_VAULT_TOKEN > RGT_VAULT_TOKEN_FILE >
// operator.token > server.token.
func TestResolveToken(t *testing.T) {
	isolateEnv(t)
	home, _ := os.UserHomeDir()
	cfg := filepath.Join(home, ".config", "rgt-vault")
	if resolveToken("") != "" {
		t.Error("no token anywhere")
	}
	mustWrite(t, mkdir(t, cfg), "server.token", "legacy\n")
	if got := resolveToken(""); got != "legacy" {
		t.Errorf("server.token: %q", got)
	}
	mustWrite(t, cfg, "operator.token", "op\n")
	if got := resolveToken(""); got != "op" {
		t.Errorf("operator.token first: %q", got)
	}
	f := mustWrite(t, t.TempDir(), "agent.token", " file \n")
	t.Setenv("RGT_VAULT_TOKEN_FILE", f)
	if got := resolveToken(""); got != "file" {
		t.Errorf("RGT_VAULT_TOKEN_FILE: %q", got)
	}
	t.Setenv("RGT_VAULT_TOKEN", "env")
	if got := resolveToken(""); got != "env" {
		t.Errorf("env: %q", got)
	}
	if got := resolveToken("flag"); got != "flag" {
		t.Errorf("flag: %q", got)
	}
}

func mkdir(t *testing.T, p string) string {
	t.Helper()
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}
