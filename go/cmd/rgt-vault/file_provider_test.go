package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/server"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/vault"
)

// fileEnv is an isolated environment with NO provider seam: the real file
// provider runs, and the session D-Bus is unset (headless host, RGT-522).
type fileEnv struct {
	t    *testing.T
	home string
	db   string
}

func newFileEnv(t *testing.T) *fileEnv {
	t.Helper()
	isolateEnv(t)
	home, _ := os.UserHomeDir()
	// With a umask of 002 t.TempDir() is group-writable, which the key's
	// ancestor checks (rightly) refuse.
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	old := newProvider
	newProvider = nil
	t.Cleanup(func() { newProvider = old })
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	for _, k := range []string{"RGT_VAULT_DB", "RGT_VAULT_POLICY", "RGT_VAULT_PROVIDER", providers.EnvMasterKeyFile,
		providers.EnvCredentialsDirectory, providers.EnvMasterCredential, providers.EnvInsecureKeyACL} {
		t.Setenv(k, "")
	}
	return &fileEnv{t: t, home: home, db: filepath.Join(home, "vault", "vault.db")}
}

func (e *fileEnv) run(a ...string) (int, string, string) {
	e.t.Helper()
	return runCLI(e.t, "", append([]string{"--db", e.db}, a...)...)
}

var vaultIDLine = regexp.MustCompile(`id ([A-Za-z0-9-]+) `)

func (e *fileEnv) mustInit(a ...string) (out, id string) {
	e.t.Helper()
	code, out, stderr := e.run(append([]string{"--provider", "file"}, append(a, "init")...)...)
	if code != 0 {
		e.t.Fatalf("init --provider file: exit %d\nstdout: %s\nstderr: %s", code, out, stderr)
	}
	m := vaultIDLine.FindStringSubmatch(out)
	if m == nil {
		e.t.Fatalf("no vault id in %q", out)
	}
	return out, m[1]
}

func assertKeyFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	if len(b) != 45 || b[44] != '\n' {
		t.Fatalf("key file is %d bytes, want 44 base64 characters + newline", len(b))
	}
	raw, err := providers.DecodeKeyFile(b)
	if err != nil || len(raw) != 32 {
		t.Fatalf("key file does not decode to 32 bytes: %v", err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(p)
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("key file mode %04o, want 0600", fi.Mode().Perm())
		}
	}
	return b
}

// serveOnce starts `serve` with args, waits until it listens, then stops it.
func serveOnce(t *testing.T, args ...string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan int, 1)
	go func() { done <- runServeForTest(ctx, append(args, "serve", "--port", "0"), ready) }()
	select {
	case <-ready:
		cancel()
		if code := <-done; code != 0 {
			t.Fatalf("serve exited %d after cancel", code)
		}
	case code := <-done:
		cancel()
		t.Fatalf("serve %v exited early: %d", args, code)
	}
}

// Acceptance 1: init and serve with --provider file and no Secret Service,
// key at the per-vault default path.
func TestInitServeFileProviderDefaultPath(t *testing.T) {
	e := newFileEnv(t)
	out, id := e.mustInit()
	keyPath := filepath.Join(e.home, ".config", "rgt-vault", "keys", id+".key")
	first := assertKeyFile(t, keyPath)
	if !strings.Contains(out, keyPath) {
		t.Errorf("init output does not name the key file %s:\n%s", keyPath, out)
	}
	serveOnce(t, "--db", e.db, "--provider", "file")
	// Re-running init opens the same vault and never rewrites the key.
	e.mustInit()
	if again := assertKeyFile(t, keyPath); !bytes.Equal(first, again) {
		t.Fatal("init rewrote the key file")
	}
	// The env var selects the provider too.
	t.Setenv("RGT_VAULT_PROVIDER", "file")
	serveOnce(t, "--db", e.db)
}

// Acceptance 1 (explicit path) and 3 (rotation with a path source).
func TestInitServeFileProviderExplicitPath(t *testing.T) {
	e := newFileEnv(t)
	keyPath := filepath.Join(e.home, "secrets", "master.key")
	e.mustInit("--master-key-file", keyPath)
	before := assertKeyFile(t, keyPath)
	if ents, _ := os.ReadDir(filepath.Join(e.home, ".config", "rgt-vault", "keys")); len(ents) != 0 {
		t.Fatalf("default key dir used with --master-key-file: %v", ents)
	}
	serveOnce(t, "--db", e.db, "--provider", "file", "--master-key-file", keyPath)
	t.Setenv(providers.EnvMasterKeyFile, keyPath)
	serveOnce(t, "--db", e.db, "--provider", "file")
	t.Setenv(providers.EnvMasterKeyFile, "")

	// Without the key file the vault does not open (and no new key appears).
	aside := keyPath + ".aside"
	if err := os.Rename(keyPath, aside); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := e.run("--provider", "file", "--master-key-file", keyPath, "get", "--offline", "--purpose", "t", "x"); code == 0 || !strings.Contains(stderr, "no master key file") {
		t.Fatalf("open without the key: exit %d %q", code, stderr)
	}
	if _, err := os.Lstat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a new key file was created for an existing vault")
	}
	if err := os.Rename(aside, keyPath); err != nil {
		t.Fatal(err)
	}

	// rotate --target master through the vault, then re-open.
	policy := filepath.Join(e.home, "policy.yaml")
	if err := os.WriteFile(policy, []byte(allowAllPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	open := func() *server.Stack {
		prov, err := server.NewProviderWith(server.ProviderFile, server.ProviderOptions{MasterKeyFile: keyPath})
		if err != nil {
			t.Fatal(err)
		}
		st, err := server.OpenStack(context.Background(), server.StackOptions{DBPath: e.db, PolicyFile: policy, MasterProvider: prov, KDFParams: kdfParams})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	st := open()
	if err := st.Vault.SetSecret(context.Background(), vault.SetSecretRequest{Name: "k", Namespace: "n", Agent: "system", Purpose: "t", Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	epoch := st.Vault.KeyEpoch()
	if err := st.Vault.RotateMaster(context.Background()); err != nil {
		t.Fatalf("RotateMaster: %v", err)
	}
	_ = st.Close()
	after := assertKeyFile(t, keyPath)
	if bytes.Equal(before, after) {
		t.Fatal("rotation did not change the key file")
	}
	st = open()
	defer st.Close()
	var got string
	if err := st.Vault.Lease(context.Background(), vault.LeaseRequest{Name: "k", Namespace: "n", Agent: "system", Purpose: "t"},
		func(b []byte) error { got = string(b); return nil }); err != nil || got != "v" {
		t.Fatalf("secret after rotation: %q, %v", got, err)
	}
	if st.Vault.KeyEpoch() != epoch+1 {
		t.Fatalf("epoch %d after rotation, want %d", st.Vault.KeyEpoch(), epoch+1)
	}
	// No temp file and no .prev left: the rotation was confirmed; the key is
	// bound to this vault.
	var names []string
	ents, _ := os.ReadDir(filepath.Dir(keyPath))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "master.key,master.key.vault-id" {
		t.Fatalf("key dir holds %v, want master.key and master.key.vault-id", names)
	}
}

// Acceptance 3: $CREDENTIALS_DIRECTORY (systemd LoadCredential[Encrypted]=).
func TestFileProviderSystemdCredential(t *testing.T) {
	e := newFileEnv(t)
	keyPath := filepath.Join(e.home, "provision", "master.key")
	e.mustInit("--master-key-file", keyPath)
	credDir := filepath.Join(e.home, "credentials")
	if err := os.Mkdir(credDir, 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(keyPath)
	raw, err := providers.DecodeKeyFile(b)
	if err != nil {
		t.Fatal(err)
	}
	// systemd-creds encrypt of a raw file: 32 raw bytes are accepted too.
	cred := filepath.Join(credDir, providers.DefaultMasterCredential)
	if err := os.WriteFile(cred, raw, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil { // only the credential holds the key now
		t.Fatal(err)
	}
	t.Setenv(providers.EnvCredentialsDirectory, credDir)
	serveOnce(t, "--db", e.db, "--provider", "file")

	prov, err := server.NewProviderWith(server.ProviderFile, server.ProviderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := prov.(*providers.CredentialProvider); !ok {
		t.Fatalf("provider is %T, want the credential provider", prov)
	}
	st, err := server.OpenStack(context.Background(), server.StackOptions{DBPath: e.db, MasterProvider: prov, KDFParams: kdfParams})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	epoch := st.Vault.KeyEpoch()
	if err := st.Vault.RotateMaster(context.Background()); !errors.Is(err, vault.ErrRotateNotSupported) {
		t.Fatalf("RotateMaster with a credential = %v, want ErrRotateNotSupported", err)
	}
	if st.Vault.KeyEpoch() != epoch {
		t.Fatal("a refused rotation changed the epoch")
	}
	if got, _ := os.ReadFile(cred); !bytes.Equal(got, raw) {
		t.Fatal("the credential was modified")
	}

	// A named credential that is missing is an error naming the unit setting.
	t.Setenv(providers.EnvMasterCredential, "other-name")
	if code, _, stderr := e.run("--provider", "file", "get", "--offline", "--purpose", "t", "x"); code == 0 || !strings.Contains(stderr, "LoadCredentialEncrypted=") {
		t.Fatalf("missing named credential: exit %d %q", code, stderr)
	}
}

// Acceptance 4: an unreachable keyring makes init exit 1 with the remedy,
// naming --provider file first, and leaves no files behind.
func TestInitUnreachableKeyringLeavesNothing(t *testing.T) {
	cases := []struct {
		name string
		prov vault.MasterProvider
	}{
		// The probe fails: nothing is even attempted.
		{"probe", &unreachableKeyring{probe: true}},
		// The probe passes but the bootstrap write fails after vault.db
		// was created: init removes what it created.
		{"bootstrap", &unreachableKeyring{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newFileEnv(t)
			useProvider(t, c.prov)
			code, out, stderr := e.run("init")
			if code != 1 {
				t.Fatalf("exit %d, want 1\nstdout: %s\nstderr: %s", code, out, stderr)
			}
			assertRemedy(t, stderr)
			assertNoVaultFiles(t, e.db)
		})
	}
}

// The real keyring backend with no reachable session bus (Linux only: on
// macOS/Windows runners the real keyring may well be available).
func TestInitRealKeyringNoBus(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Secret Service is the Linux keyring")
	}
	e := newFileEnv(t)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(e.home, "no-such-bus"))
	code, out, stderr := e.run("init")
	if code != 1 {
		t.Fatalf("exit %d, want 1\nstdout: %s\nstderr: %s", code, out, stderr)
	}
	assertRemedy(t, stderr)
	assertNoVaultFiles(t, e.db)
	if _, err := os.Stat(filepath.Join(e.home, ".config", "rgt-vault", "tokens.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("token store created despite the failure: %v", err)
	}
}

func assertRemedy(t *testing.T, stderr string) {
	t.Helper()
	i := strings.Index(stderr, "rgt-vault init --provider file")
	if !strings.Contains(stderr, "no OS keyring is available here") || i < 0 {
		t.Fatalf("remedy missing:\n%s", stderr)
	}
	for _, other := range []string{"desktop keyring", "--provider platform"} {
		if j := strings.Index(stderr, other); j >= 0 && j < i {
			t.Fatalf("%q is suggested before --provider file:\n%s", other, stderr)
		}
	}
	if !strings.Contains(stderr, "No files were created.") && !strings.Contains(stderr, "No vault or key files were left behind.") {
		t.Fatalf("no 'No files were created.' / 'left behind':\n%s", stderr)
	}
}

func assertNoVaultFiles(t *testing.T, db string) {
	t.Helper()
	for _, f := range vaultFiles(db) {
		if _, err := os.Lstat(f); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left behind (%v)", f, err)
		}
	}
}

// unreachableKeyring behaves like the keyring provider when no Secret
// Service is running.
type unreachableKeyring struct{ probe bool }

var errNoSecretService = errors.New("The name org.freedesktop.secrets was not provided by any .service files")

func (u *unreachableKeyring) Probe() error {
	if u.probe {
		return errNoSecretService
	}
	return nil
}
func (u *unreachableKeyring) BootstrapMasterSecret() error     { return errNoSecretService }
func (u *unreachableKeyring) GetMasterSecret() ([]byte, error) { return nil, errNoSecretService }

// Other commands that open a vault print the remedy too.
func TestOpenUnreachableKeyringRemedy(t *testing.T) {
	e := newFileEnv(t)
	e.mustInit()
	useProvider(t, &unreachableKeyring{})
	code, _, stderr := e.run("get", "--offline", "--purpose", "t", "x")
	if code == 0 || !strings.Contains(stderr, "provider seal file --from-keyring") || !strings.Contains(stderr, "--provider file") {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
}

func TestMasterKeyFileNeedsFileProvider(t *testing.T) {
	e := newFileEnv(t)
	code, _, stderr := e.run("--provider", "keyring", "--master-key-file", "/x", "init")
	if code == 0 || !strings.Contains(stderr, "--master-key-file needs --provider file") {
		t.Fatalf("exit %d %q", code, stderr)
	}
	code, _, stderr = e.run("--provider", "bogus", "init")
	if code == 0 || !strings.Contains(stderr, "'keyring', 'file' or 'platform'") {
		t.Fatalf("exit %d %q", code, stderr)
	}
}

// A key file that fails the checks stops init before vault.db exists.
func TestInitFileProviderRefusesInsecureKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	e := newFileEnv(t)
	keyPath := filepath.Join(e.home, "loose.key")
	if err := os.WriteFile(keyPath, providers.EncodeKeyFile(make([]byte, 32)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := e.run("--provider", "file", "--master-key-file", keyPath, "init")
	if code == 0 || !strings.Contains(stderr, "chmod 600") || !strings.Contains(stderr, "No files were created") {
		t.Fatalf("exit %d %q", code, stderr)
	}
	assertNoVaultFiles(t, e.db)
}

// Acceptance 5: provider seal file.
func TestSealFile(t *testing.T) {
	e := newFileEnv(t)
	out := filepath.Join(e.home, "sealed", "master.key")
	code, stdout, stderr := runCLI(t, "", "provider", "seal", "file", "--generate", "--out", out)
	if code != 0 || !strings.Contains(stdout, "--provider file --master-key-file "+out) {
		t.Fatalf("seal --generate: %d %q %q", code, stdout, stderr)
	}
	first := assertKeyFile(t, out)
	if strings.Contains(stdout, strings.TrimSpace(string(first))) {
		t.Fatal("the key was printed")
	}
	// Never overwritten without --force.
	if code, _, stderr := runCLI(t, "", "provider", "seal", "file", "--generate", "--out", out); code == 0 || !strings.Contains(stderr, "--force") {
		t.Fatalf("overwrite without --force: %d %q", code, stderr)
	}
	if again := assertKeyFile(t, out); !bytes.Equal(first, again) {
		t.Fatal("overwritten without --force")
	}
	if code, _, stderr := runCLI(t, "", "provider", "seal", "file", "--generate", "--out", out, "--force"); code != 0 {
		t.Fatalf("--force: %d %q", code, stderr)
	}
	if again := assertKeyFile(t, out); bytes.Equal(first, again) {
		t.Fatal("--force did not replace the key")
	}

	// --master-file: exactly 32 raw bytes.
	raw := filepath.Join(e.home, "raw.bin")
	secret := bytes.Repeat([]byte{7}, 32)
	if err := os.WriteFile(raw, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	out2 := filepath.Join(e.home, "sealed", "from-raw.key")
	if code, _, stderr := runCLI(t, "", "provider", "seal", "file", "--master-file", raw, "--out", out2); code != 0 {
		t.Fatalf("--master-file: %d %q", code, stderr)
	}
	if got, _ := providers.DecodeKeyFile(assertKeyFile(t, out2)); !bytes.Equal(got, secret) {
		t.Fatal("--master-file content not preserved")
	}
	if err := os.WriteFile(raw, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI(t, "", "provider", "seal", "file", "--master-file", raw, "--out", out2+".2"); code == 0 || !strings.Contains(stderr, "exactly 32") {
		t.Fatalf("short --master-file: %d %q", code, stderr)
	}

	// --from-keyring: the keyring's secret, re-encoded.
	oldKR := keyringProvider
	t.Cleanup(func() { keyringProvider = oldKR })
	mem := &staticProvider{secret: bytes.Repeat([]byte{9}, 32)}
	keyringProvider = func() vault.MasterProvider { return mem }
	out3 := filepath.Join(e.home, "sealed", "from-keyring.key")
	if code, _, stderr := runCLI(t, "", "provider", "seal", "file", "--from-keyring", "--out", out3); code != 0 {
		t.Fatalf("--from-keyring: %d %q", code, stderr)
	}
	if got, _ := providers.DecodeKeyFile(assertKeyFile(t, out3)); !bytes.Equal(got, mem.secret) {
		t.Fatal("--from-keyring content not preserved")
	}

	// --out - to a pipe/buffer works; to a terminal it is refused.
	code, stdout, stderr = runCLI(t, "", "provider", "seal", "file", "--from-keyring", "--out", "-")
	if got, err := providers.DecodeKeyFile([]byte(stdout)); code != 0 || err != nil || !bytes.Equal(got, mem.secret) {
		t.Fatalf("--out -: %d %v %q", code, err, stderr)
	}
	oldTerm := stdoutIsTerminal
	t.Cleanup(func() { stdoutIsTerminal = oldTerm })
	stdoutIsTerminal = func(io.Writer) bool { return true }
	code, stdout, stderr = runCLI(t, "", "provider", "seal", "file", "--generate", "--out", "-")
	if code == 0 || stdout != "" || !strings.Contains(stderr, "terminal") {
		t.Fatalf("--out - on a terminal: %d %q %q", code, stdout, stderr)
	}
	if code, _, stderr := runCLI(t, "", "provider", "seal", "file", "--generate"); code == 0 || !strings.Contains(stderr, "--out") {
		t.Fatalf("no --out: %d %q", code, stderr)
	}

	// The sealed file is usable by init --provider file.
	e.mustInit("--master-key-file", out3)
	if got, _ := providers.DecodeKeyFile(assertKeyFile(t, out3)); !bytes.Equal(got, mem.secret) {
		t.Fatal("init replaced a pre-provisioned key")
	}
}

type staticProvider struct{ secret []byte }

func (s *staticProvider) GetMasterSecret() ([]byte, error) {
	return append([]byte(nil), s.secret...), nil
}

// openFileStack opens the vault at db with the file provider on keyPath.
func openFileStack(t *testing.T, db, keyPath, policy string) (*server.Stack, vault.MasterProvider, error) {
	t.Helper()
	prov, err := server.NewProviderWith(server.ProviderFile, server.ProviderOptions{MasterKeyFile: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	st, err := server.OpenStack(context.Background(), server.StackOptions{DBPath: db, PolicyFile: policy, MasterProvider: prov, KDFParams: kdfParams})
	return st, prov, err
}

func writePolicy(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte(allowAllPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func leaseValue(t *testing.T, st *server.Stack) string {
	t.Helper()
	var got string
	if err := st.Vault.Lease(context.Background(), vault.LeaseRequest{Name: "k", Namespace: "n", Agent: "system", Purpose: "t"},
		func(b []byte) error { got = string(b); return nil }); err != nil {
		t.Fatalf("lease: %v", err)
	}
	return got
}

// Review H1: a crash after the provider switched to the new key but before
// the re-wrapped keychain reached disk must not lose the vault: the old key
// is in <key>.prev, the open error says so, and restoring it opens the vault.
func TestRotationCrashKeepsPreviousKey(t *testing.T) {
	e := newFileEnv(t)
	keyPath := filepath.Join(e.home, "keys", "master.key")
	e.mustInit("--master-key-file", keyPath)
	policy := writePolicy(t, e.home)
	st, prov, err := openFileStack(t, e.db, keyPath, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Vault.SetSecret(context.Background(), vault.SetSecretRequest{Name: "k", Namespace: "n", Agent: "system", Purpose: "t", Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	// The provider step of RotateMaster, then "kill -9": no re-wrap, no commit.
	newKey, err := prov.(vault.Rotator).RotateMasterSecret()
	if err != nil {
		t.Fatal(err)
	}
	providers.Wipe(newKey)
	_ = st.Close()

	prev := providers.PrevPath(keyPath)
	if _, err := os.Stat(prev); err != nil {
		t.Fatalf("no %s after the provider step: %v", prev, err)
	}
	_, _, err = openFileStack(t, e.db, keyPath, policy)
	if err == nil || !strings.Contains(err.Error(), prev) || !strings.Contains(err.Error(), "PREVIOUS master secret") {
		t.Fatalf("re-open after the crash: %v", err)
	}
	if _, err := os.Stat(prev); err != nil {
		t.Fatal("a failed open removed .prev")
	}
	// The documented recovery.
	if err := os.Rename(prev, keyPath); err != nil {
		t.Fatal(err)
	}
	st, _, err = openFileStack(t, e.db, keyPath, policy)
	if err != nil {
		t.Fatalf("open with the restored key: %v", err)
	}
	defer st.Close()
	if leaseValue(t, st) != "v" {
		t.Fatal("secret lost")
	}
	// A completed rotation removes .prev.
	if err := st.Vault.RotateMaster(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(prev); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".prev kept after a completed rotation: %v", err)
	}
}

// Review L5: seal file --force over a live key keeps it as .prev.
func TestSealForceKeepsPreviousKey(t *testing.T) {
	e := newFileEnv(t)
	keyPath := filepath.Join(e.home, "keys", "master.key")
	e.mustInit("--master-key-file", keyPath)
	before := assertKeyFile(t, keyPath)
	if code, out, stderr := runCLI(t, "", "provider", "seal", "file", "--generate", "--force", "--out", keyPath); code != 0 || !strings.Contains(out, ".prev") {
		t.Fatalf("seal --force: %d %q %q", code, out, stderr)
	}
	if got, _ := os.ReadFile(providers.PrevPath(keyPath)); !bytes.Equal(got, before) {
		t.Fatal(".prev does not hold the replaced key")
	}
	// A second --force must not overwrite the only copy of the old key.
	if code, _, stderr := runCLI(t, "", "provider", "seal", "file", "--generate", "--force", "--out", keyPath); code == 0 || !strings.Contains(stderr, ".prev") {
		t.Fatalf("second --force: %d %q", code, stderr)
	}
	_, _, err := openFileStack(t, e.db, keyPath, "")
	if err == nil || !strings.Contains(err.Error(), "mv "+providers.PrevPath(keyPath)) {
		t.Fatalf("open with the replaced key: %v", err)
	}
}

// Review L3: a key that does not match names the source and the vault.
func TestWrongKeyMessage(t *testing.T) {
	e := newFileEnv(t)
	keyPath := filepath.Join(e.home, "keys", "master.key")
	_, id := e.mustInit("--master-key-file", keyPath)
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI(t, "", "provider", "seal", "file", "--generate", "--out", keyPath); code != 0 {
		t.Fatal(stderr)
	}
	_, _, err := openFileStack(t, e.db, keyPath, "")
	if err == nil || !strings.Contains(err.Error(), keyPath) || !strings.Contains(err.Error(), "does not match this vault") || !strings.Contains(err.Error(), id) {
		t.Fatalf("wrong key: %v", err)
	}
}

// Review H2: a key file bound to one vault is refused for another.
func TestSharedKeyFileRefused(t *testing.T) {
	e := newFileEnv(t)
	keyPath := filepath.Join(e.home, "keys", "master.key")
	_, idA := e.mustInit("--master-key-file", keyPath)
	if b, err := os.ReadFile(providers.VaultIDPath(keyPath)); err != nil || strings.TrimSpace(string(b)) != idA {
		t.Fatalf("binding %q, %v", b, err)
	}
	dbB := filepath.Join(e.home, "vault-b", "vault.db")
	code, _, stderr := runCLI(t, "", "--db", dbB, "--provider", "file", "--master-key-file", keyPath, "init")
	if code == 0 || !strings.Contains(stderr, "belongs to vault "+idA) {
		t.Fatalf("second vault on the same key: %d %q", code, stderr)
	}
	assertNoVaultFiles(t, dbB)
	st, _, err := openFileStack(t, e.db, keyPath, "")
	if err != nil {
		t.Fatalf("vault A no longer opens: %v", err)
	}
	_ = st.Close()
}

// Review M2: under systemd without the credential, no silent plaintext key.
func TestCredentialsDirWithoutCredentialRefused(t *testing.T) {
	e := newFileEnv(t)
	credDir := filepath.Join(e.home, "creds")
	if err := os.Mkdir(credDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(providers.EnvCredentialsDirectory, credDir)
	code, _, stderr := e.run("--provider", "file", "init")
	if code == 0 || !strings.Contains(stderr, "rgt-vault-master") || !strings.Contains(stderr, credDir) {
		t.Fatalf("init: %d %q", code, stderr)
	}
	assertNoVaultFiles(t, e.db)
	if _, err := os.Stat(filepath.Join(e.home, ".config", "rgt-vault", "keys")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a default key dir was created")
	}
	// An explicit key file is the documented override.
	e.mustInit("--master-key-file", filepath.Join(e.home, "k", "master.key"))
}

// bootstrapThenFail creates a key file in Bootstrap and then cannot read it
// (like a file provider whose run fails after bootstrapping).
type bootstrapThenFail struct{ path string }

func (b *bootstrapThenFail) BootstrapMasterSecret() error {
	return os.WriteFile(b.path, []byte("x"), 0o600)
}
func (b *bootstrapThenFail) GetMasterSecret() ([]byte, error) { return nil, errors.New("boom") }
func (b *bootstrapThenFail) CreatedFiles() []string           { return []string{b.path} }

// Review L1: a key bootstrapped by a failing init is removed too, and the
// file provider's probe creates nothing.
func TestInitCleansBootstrappedKey(t *testing.T) {
	e := newFileEnv(t)
	key := filepath.Join(e.home, "boot.key")
	useProvider(t, &bootstrapThenFail{path: key})
	if code, _, stderr := e.run("init"); code == 0 || !strings.Contains(stderr, "No vault or key files were left behind") {
		t.Fatalf("init: %d %q", code, stderr)
	}
	if _, err := os.Stat(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("bootstrapped key left behind")
	}
	assertNoVaultFiles(t, e.db)

	prov, err := server.NewProviderWith(server.ProviderFile, server.ProviderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := prov.(interface{ Probe() error }).Probe(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.home, ".config")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Probe created directories")
	}
}

// slowFailingFirst fails the first bootstrap after holding it until release
// is closed; later bootstraps succeed (an in-memory key).
type slowFailingFirst struct {
	mu       sync.Mutex
	calls    int
	entered  chan struct{}
	release  chan struct{}
	secret   []byte
	hasValue bool
}

func (s *slowFailingFirst) BootstrapMasterSecret() error {
	s.mu.Lock()
	s.calls++
	first := s.calls == 1
	s.mu.Unlock()
	if first {
		close(s.entered)
		<-s.release
		return errors.New("first init fails")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.hasValue {
		s.secret, s.hasValue = bytes.Repeat([]byte{3}, 32), true
	}
	return nil
}

func (s *slowFailingFirst) GetMasterSecret() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.hasValue {
		return nil, errors.New("no secret")
	}
	return append([]byte(nil), s.secret...), nil
}

// Review M1: two inits race; the one that fails must not remove the vault
// the other created. Without the init lock, B completes while A is parked
// in its bootstrap, then A fails and deletes B's vault.
func TestConcurrentInitKeepsVault(t *testing.T) {
	e := newFileEnv(t)
	prov := &slowFailingFirst{entered: make(chan struct{}), release: make(chan struct{})}
	useProvider(t, prov)
	args := []string{"--db", e.db, "init", "--operator-token-file", "-"}
	aDone := make(chan int, 1)
	go func() { c, _, _ := runCLI(t, "", args...); aDone <- c }()
	<-prov.entered
	bDone := make(chan int, 1)
	go func() { c, _, _ := runCLI(t, "", args...); bDone <- c }()
	bCode := -1
	select {
	case bCode = <-bDone: // only possible without the lock
	case <-time.After(500 * time.Millisecond):
	}
	close(prov.release)
	if c := <-aDone; c == 0 {
		t.Fatal("A should fail")
	}
	if bCode == -1 {
		bCode = <-bDone
	}
	if bCode != 0 {
		t.Fatalf("B exited %d", bCode)
	}
	if !vaultFileExists(e.db) {
		t.Fatal("the vault B created was removed by A's cleanup")
	}
}
