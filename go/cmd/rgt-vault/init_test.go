package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func (e *vaultEnv) initArgs(extra ...string) []string {
	return append([]string{"init", "--legacy-shared-token",
		"--token-file", filepath.Join(e.dir, "cfg", "server.token"),
		"--operator-token-file", filepath.Join(e.dir, "cfg", "operator.token")}, extra...)
}

func TestInitCreatesVaultAndTokens(t *testing.T) {
	e := newVaultEnv(t)
	tok, op, hk := filepath.Join(e.dir, "cfg", "server.token"), filepath.Join(e.dir, "cfg", "operator.token"), filepath.Join(e.dir, "cfg", "harness.key")
	code, out, stderr := runCLI(t, "", e.args(e.initArgs("--harness-key-file", hk)...)...)
	if code != 0 {
		t.Fatalf("init: exit %d: %s", code, stderr)
	}
	for _, p := range []string{tok, op, hk} {
		assertMode0600(t, p)
	}
	if _, err := os.Stat(e.db); err != nil {
		t.Errorf("vault.db not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(e.db), "keychain.json")); err != nil {
		t.Errorf("keychain.json not created: %v", err)
	}
	a, _ := os.ReadFile(tok)
	b, _ := os.ReadFile(op)
	if bytes.Equal(a, b) || len(bytes.TrimSpace(a)) < 43 || a[len(a)-1] != '\n' {
		t.Errorf("tokens look wrong: %q / %q", a, b)
	}
	for _, secret := range []string{strings.TrimSpace(string(a)), strings.TrimSpace(string(b))} {
		if strings.Contains(out, secret) {
			t.Error("init printed a token")
		}
	}
	if !strings.Contains(out, "created") || !strings.Contains(out, "vault:") {
		t.Errorf("summary = %q", out)
	}
	// What init made is what serve needs: the server opens on these files.
	if e.open().Vault.VaultID() == "" {
		t.Error("vault not usable")
	}
}

// Running init again changes nothing; --force replaces only the tokens.
func TestInitIsIdempotentAndNonDestructive(t *testing.T) {
	e := newVaultEnv(t)
	tok, op := filepath.Join(e.dir, "cfg", "server.token"), filepath.Join(e.dir, "cfg", "operator.token")
	if code, _, stderr := runCLI(t, "", e.args(e.initArgs()...)...); code != 0 {
		t.Fatal(stderr)
	}
	e.seed("prod", "k", "precious")
	read := func(p string) []byte { b, _ := os.ReadFile(p); return b }
	dir := filepath.Dir(e.db)
	before := map[string][]byte{tok: read(tok), op: read(op), filepath.Join(dir, "keychain.json"): read(filepath.Join(dir, "keychain.json"))}
	// The agent token's mode is tightened (not rewritten) when it was loose.
	if err := os.Chmod(tok, 0o644); err != nil {
		t.Fatal(err)
	}

	code, out, stderr := runCLI(t, "", e.args(e.initArgs()...)...)
	if code != 0 || strings.Count(out, "kept") != 3 || strings.Contains(out, "created") {
		t.Fatalf("second init: exit %d out %q err %q", code, out, stderr)
	}
	for p, want := range before {
		if got := read(p); !bytes.Equal(got, want) {
			t.Errorf("%s changed by a second init", p)
		}
	}
	assertMode0600(t, tok)
	// The secret written between the two runs survived.
	if v := e.mustCLI("", "get", "k", "--namespace", "prod", "--purpose", "t", "--offline"); v != "precious\n" {
		t.Errorf("secret lost: %q", v)
	}

	// --force replaces the tokens, never the vault.
	code, out, stderr = runCLI(t, "", e.args(e.initArgs("--force")...)...)
	if code != 0 || strings.Count(out, "replaced") != 2 {
		t.Fatalf("init --force: exit %d out %q err %q", code, out, stderr)
	}
	if bytes.Equal(read(tok), before[tok]) || bytes.Equal(read(op), before[op]) {
		t.Error("--force kept the old tokens")
	}
	if !bytes.Equal(read(filepath.Join(dir, "keychain.json")), before[filepath.Join(dir, "keychain.json")]) {
		t.Error("--force touched keychain.json")
	}
	if v := e.mustCLI("", "get", "k", "--namespace", "prod", "--purpose", "t", "--offline"); v != "precious\n" {
		t.Errorf("--force lost the secret: %q", v)
	}
}

func TestInitRefusesWeakExistingToken(t *testing.T) {
	e := newVaultEnv(t)
	tok := filepath.Join(e.dir, "cfg", "server.token")
	if err := os.MkdirAll(filepath.Dir(tok), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tok, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := runCLI(t, "", e.args(e.initArgs()...)...)
	if code != 1 || !strings.Contains(stderr, "too weak") || !strings.Contains(stderr, "--force") || strings.Contains(out+stderr, "hunter2") {
		t.Fatalf("exit %d out %q err %q", code, out, stderr)
	}
	if b, _ := os.ReadFile(tok); string(b) != "hunter2\n" {
		t.Error("weak token was overwritten without --force")
	}
	if code, _, _ := runCLI(t, "", e.args(e.initArgs("--force")...)...); code != 0 {
		t.Error("--force did not replace the weak token")
	}
}

func TestInitOptions(t *testing.T) {
	e := newVaultEnv(t)
	// --tokens-only creates no vault; "-" skips the operator token.
	tok := filepath.Join(e.dir, "t", "server.token")
	code, out, stderr := runCLI(t, "", e.args("init", "--legacy-shared-token", "--tokens-only", "--token-file", tok, "--operator-token-file", "-")...)
	if code != 0 || strings.Contains(out, "vault:") || strings.Contains(out, "operator token file") {
		t.Fatalf("exit %d out %q err %q", code, out, stderr)
	}
	assertMode0600(t, tok)
	if _, err := os.Stat(e.db); err == nil {
		t.Error("--tokens-only created the vault")
	}
	// Unwritable token location, unknown provider, no token path.
	blocker := filepath.Join(e.dir, "file")
	_ = os.WriteFile(blocker, nil, 0o600)
	if code, _, _ := runCLI(t, "", e.args("init", "--legacy-shared-token", "--tokens-only", "--token-file", filepath.Join(blocker, "server.token"), "--operator-token-file", "-")...); code != 1 {
		t.Errorf("unwritable path: exit %d", code)
	}
	if code, _, stderr := runCLI(t, "", "--db", e.db, "--provider", "tpm", "init", "--legacy-shared-token", "--token-file", tok); code != 1 || !strings.Contains(stderr, "unknown provider") {
		t.Errorf("bad provider: exit %d err %q", code, stderr)
	}
	if code, _, _ := runCLI(t, "", e.args("init", "--legacy-shared-token", "--tokens-only", "--token-file", "", "--operator-token-file", "-")...); code != 1 {
		t.Errorf("empty token path: exit %d", code)
	}
}

func TestInitDefaultPathsUnderHome(t *testing.T) {
	e := newVaultEnv(t)
	if code, _, stderr := runCLI(t, "", "--db", e.db, "init"); code != 0 {
		t.Fatalf("init: %s", stderr)
	}
	// Per-agent mode (the default): the store and the operator token, no
	// shared server.token.
	assertMode0600(t, filepath.Join(e.home, ".config", "rgt-vault", "tokens.json"))
	assertMode0600(t, filepath.Join(e.home, ".config", "rgt-vault", "operator.token"))
	if _, err := os.Stat(filepath.Join(e.home, ".config", "rgt-vault", "server.token")); err == nil {
		t.Error("init created the legacy shared token without --legacy-shared-token")
	}
}

// writeSecretFile never clobbers without overwrite, even when racing.
func TestWriteSecretFileNoClobberRace(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d", "f")
	var wg sync.WaitGroup
	created := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := writeSecretFile(p, []byte{byte('a' + i)}, false)
			if err != nil {
				t.Error(err)
			}
			created <- c
		}(i)
	}
	wg.Wait()
	close(created)
	n := 0
	for c := range created {
		if c {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d writers won, want exactly 1", n)
	}
	b, _ := os.ReadFile(p)
	if len(b) != 1 {
		t.Errorf("content %q", b)
	}
	assertMode0600(t, p)
	// overwrite replaces it atomically and leaves no temp files.
	if c, err := writeSecretFile(p, []byte("new"), true); err != nil || !c {
		t.Fatalf("overwrite: %v %v", c, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Errorf("content %q", b)
	}
	if ents, _ := os.ReadDir(filepath.Dir(p)); len(ents) != 1 {
		t.Errorf("temp files left: %v", ents)
	}
}
