package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rgt-vault-server/internal/providers"
	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/totp"
	"rgt-vault-server/internal/vault"
)

func TestEnroll2FA(t *testing.T) {
	e := newVaultEnv(t)
	out := filepath.Join(e.dir, "sec", "totp.secret")
	// Not a terminal (captured output): the secret is NOT printed, but the file is written.
	code, quiet, stderr := runCLI(t, "", "enroll-2fa", "--out", out, "--account", "alice")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	assertMode0600(t, out)
	secret := strings.TrimSpace(string(mustRead(t, out)))
	if strings.Contains(quiet, secret) || strings.Contains(quiet, "otpauth://") || !strings.Contains(quiet, "not printed") {
		t.Errorf("non-terminal output leaked or lacks the notice:\n%s", quiet)
	}
	// --show-secret prints it (the secret of this run replaces the file's: --force).
	code, stdout, stderr := runCLI(t, "", "enroll-2fa", "--out", out, "--account", "alice", "--show-secret", "--force")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	secret = strings.TrimSpace(string(mustRead(t, out)))
	if _, err := totp.DecodeSecret(secret); err != nil || len(secret) < 32 {
		t.Fatalf("secret %q: %v", secret, err)
	}
	for _, want := range []string{"otpauth://totp/rgt-vault:alice?secret=" + secret, "secret: " + secret, "--totp-secret-file " + out} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, stdout)
		}
	}
	// The file is what serve --totp-secret-file reads.
	if _, err := totp.NewReplayGuardedVerifier(secret); err != nil {
		t.Fatal(err)
	}

	// Never overwritten without --force; the file is untouched.
	if code, _, stderr := runCLI(t, "", "enroll-2fa", "--out", out); code != 1 || !strings.Contains(stderr, "already exists") {
		t.Errorf("no --force: exit %d err %q", code, stderr)
	}
	if got := strings.TrimSpace(string(mustRead(t, out))); got != secret {
		t.Error("secret changed without --force")
	}
	if code, _, _ := runCLI(t, "", "enroll-2fa", "--out", ""); code != 1 {
		t.Errorf("empty --out: exit %d", code)
	}
}

// --force is audited in the vault's chain, before the old secret is replaced.
func TestEnroll2FAForceIsAudited(t *testing.T) {
	e := newVaultEnv(t)
	e.seed("prod", "k", "v")
	out := filepath.Join(e.dir, "totp.secret")
	e.mustCLI("", "enroll-2fa", "--out", out)
	old := mustRead(t, out)

	e.mustCLI("", "enroll-2fa", "--out", out, "--force")
	if string(mustRead(t, out)) == string(old) {
		t.Error("--force kept the old secret")
	}
	assertMode0600(t, out)
	stack := e.open()
	rows, err := stack.Vault.AuditLog(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.Action == auditTOTPReplaced {
			found = true
		}
	}
	if !found {
		t.Errorf("no %s row: %+v", auditTOTPReplaced, rows)
	}
	if ok, _ := stack.Vault.VerifyAuditChain(context.Background()); !ok {
		t.Error("chain broken by the audit row")
	}
	_ = stack.Close()

	// Without a vault there is nothing to audit into: a notice, not a failure.
	solo := filepath.Join(t.TempDir(), "totp")
	_ = os.WriteFile(solo, []byte("OLD\n"), 0o600)
	code, _, stderr := runCLI(t, "", "--db", filepath.Join(t.TempDir(), "no", "vault.db"), "enroll-2fa", "--out", solo, "--force")
	if code != 0 || !strings.Contains(stderr, "not audited") {
		t.Errorf("no vault: exit %d err %q", code, stderr)
	}
	// A vault that exists but cannot be opened blocks the replacement.
	useProvider(t, providerstest.NewMemory()) // wrong master secret
	before := mustRead(t, out)
	code, _, stderr = e.cli("", "enroll-2fa", "--out", out, "--force")
	if code != 1 || !strings.Contains(stderr, "cannot record it in the audit log") {
		t.Errorf("unopenable vault: exit %d err %q", code, stderr)
	}
	if string(mustRead(t, out)) != string(before) {
		t.Error("secret replaced although the audit row could not be written")
	}
}

type sealCall struct {
	kind, a, b string
	secret     []byte
	extra      any
}

func fakeSeals(t *testing.T) *[]sealCall {
	t.Helper()
	var calls []sealCall
	oD, oM, oT, oK := sealDPAPI, sealMacOS, sealTPM, keyringProvider
	t.Cleanup(func() { sealDPAPI, sealMacOS, sealTPM, keyringProvider = oD, oM, oT, oK })
	sealDPAPI = func(secret []byte, out string, entropy []byte) error {
		calls = append(calls, sealCall{"dpapi", out, "", append([]byte(nil), secret...), entropy})
		return nil
	}
	sealMacOS = func(secret []byte, service, account string, update bool) error {
		calls = append(calls, sealCall{"macos", service, account, append([]byte(nil), secret...), update})
		return nil
	}
	sealTPM = func(secret []byte, dir string, pcrs []int, bank string) (string, string, error) {
		calls = append(calls, sealCall{"tpm", dir, bank, append([]byte(nil), secret...), pcrs})
		return filepath.Join(dir, "master_secret.priv"), filepath.Join(dir, "master_secret.pub"), nil
	}
	keyringProvider = func() vault.MasterProvider {
		return providerstest.NewMemoryFixed([]byte("0123456789abcdef0123456789abcdef"))
	}
	return &calls
}

func TestIsTerminal(t *testing.T) {
	if isTerminal(&strings.Builder{}) {
		t.Error("a builder is not a terminal")
	}
	f, err := os.Open(os.DevNull)
	if err == nil {
		defer f.Close()
		if isTerminal(f) {
			t.Error("/dev/null is not a terminal")
		}
	}
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	if isTerminal(w) {
		t.Error("a pipe is not a terminal")
	}
}

func TestProviderSeal(t *testing.T) {
	isolateEnv(t)
	t.Setenv(providers.EnvDPAPIBlob, "")
	t.Setenv(providers.EnvTPMPrivate, "")
	calls := fakeSeals(t)
	dir := t.TempDir()
	masterFile := filepath.Join(dir, "m.bin")
	_ = os.WriteFile(masterFile, []byte("raw-master-bytes-of-32-bytes-long"), 0o600)

	// DPAPI: --generate (32 random bytes), the secret is never printed.
	blob := filepath.Join(dir, "blob.b64")
	code, out, stderr := runCLI(t, "", "provider", "seal", "dpapi", "--generate", "--out", blob, "--entropy-file", masterFile)
	if code != 0 || !strings.Contains(out, "Sealed the master secret with DPAPI into "+blob) {
		t.Fatalf("dpapi: exit %d out %q err %q", code, out, stderr)
	}
	c := (*calls)[0]
	if c.kind != "dpapi" || c.a != blob || len(c.secret) != 32 || len(c.extra.([]byte)) == 0 {
		t.Errorf("dpapi call %+v", c)
	}
	if strings.Contains(out, string(c.secret)) {
		t.Error("secret printed")
	}
	// An existing blob needs --force.
	_ = os.WriteFile(blob, []byte("x"), 0o600)
	if code, _, stderr := runCLI(t, "", "provider", "seal", "dpapi", "--master-file", masterFile, "--out", blob); code != 1 || !strings.Contains(stderr, "already exists") {
		t.Errorf("dpapi overwrite: exit %d err %q", code, stderr)
	}
	if code, _, _ := runCLI(t, "", "provider", "seal", "dpapi", "--master-file", masterFile, "--out", blob, "--force"); code != 0 {
		t.Error("--force refused")
	}
	if got := (*calls)[1]; string(got.secret) != "raw-master-bytes-of-32-bytes-long" {
		t.Errorf("--master-file bytes = %q", got.secret)
	}
	// Default blob from the env var.
	t.Setenv(providers.EnvDPAPIBlob, filepath.Join(dir, "env.blob"))
	if code, _, _ := runCLI(t, "", "provider", "seal", "dpapi", "--generate"); code != 0 || (*calls)[2].a != filepath.Join(dir, "env.blob") {
		t.Errorf("env blob: %+v", (*calls)[2])
	}

	// macOS: printable text, base64 when generated; --update passes through.
	if code, out, _ := runCLI(t, "", "provider", "seal", "macos", "--generate", "--service", "svc", "--account", "acc", "--update"); code != 0 || !strings.Contains(out, `"svc"`) {
		t.Errorf("macos: %d %q", code, out)
	}
	m := (*calls)[3]
	if m.kind != "macos" || m.a != "svc" || m.b != "acc" || m.extra != true || len(m.secret) != 44 {
		t.Errorf("macos call %+v", m)
	}
	// ... --from-keyring (text form)
	if code, _, _ := runCLI(t, "", "provider", "seal", "macos", "--from-keyring"); code != 0 || string((*calls)[4].secret) != "0123456789abcdef0123456789abcdef" ||
		(*calls)[4].a != providers.DefaultMacOSService {
		t.Errorf("macos from keyring: %+v", (*calls)[4])
	}

	// TPM: PCRs and bank pass through; the dir defaults to VAULT_TPM_PRIV's.
	tdir := filepath.Join(dir, "sealed")
	if code, out, stderr := runCLI(t, "", "provider", "seal", "tpm", "--generate", "--out-dir", tdir, "--pcr", "0,2,7", "--pcr-bank", "sha1"); code != 0 ||
		!strings.Contains(out, providers.EnvTPMPrivate+"="+filepath.Join(tdir, "master_secret.priv")) {
		t.Fatalf("tpm: exit %d out %q err %q", code, out, stderr)
	}
	tp := (*calls)[5]
	if tp.kind != "tpm" || tp.a != tdir || tp.b != "sha1" || len(tp.extra.([]int)) != 3 {
		t.Errorf("tpm call %+v", tp)
	}
	t.Setenv(providers.EnvTPMPrivate, filepath.Join(dir, "envdir", "x.priv"))
	if code, _, _ := runCLI(t, "", "provider", "seal", "tpm", "--generate"); code != 0 || (*calls)[6].a != filepath.Join(dir, "envdir") {
		t.Errorf("tpm env dir: %+v", (*calls)[6])
	}
	_ = os.MkdirAll(tdir, 0o700)
	_ = os.WriteFile(filepath.Join(tdir, "master_secret.priv"), []byte("x"), 0o600)
	if code, _, stderr := runCLI(t, "", "provider", "seal", "tpm", "--generate", "--out-dir", tdir); code != 1 || !strings.Contains(stderr, "already exists") {
		t.Errorf("tpm overwrite: exit %d err %q", code, stderr)
	}
}

func TestProviderSealErrors(t *testing.T) {
	isolateEnv(t)
	calls := fakeSeals(t)
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	_ = os.WriteFile(empty, nil, 0o600)
	for name, args := range map[string][]string{
		"no source":        {"dpapi", "--out", filepath.Join(dir, "b")},
		"two sources":      {"dpapi", "--generate", "--from-keyring"},
		"missing file":     {"dpapi", "--master-file", filepath.Join(dir, "none")},
		"empty file":       {"tpm", "--master-file", empty},
		"unknown backend":  {"floppy", "--generate"},
		"bad entropy file": {"dpapi", "--generate", "--entropy-file", filepath.Join(dir, "none"), "--out", filepath.Join(dir, "b2")},
	} {
		if code, _, stderr := runCLI(t, "", append([]string{"provider", "seal"}, args...)...); code != 1 || !strings.HasPrefix(stderr, "Error: ") {
			t.Errorf("%s: exit %d err %q", name, code, stderr)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("a seal ran despite the errors: %+v", *calls)
	}
	// Backend and keyring failures are reported, not swallowed.
	sealDPAPI = func([]byte, string, []byte) error { return errors.New("dpapi boom") }
	sealMacOS = func([]byte, string, string, bool) error { return errors.New("mac boom") }
	sealTPM = func([]byte, string, []int, string) (string, string, error) { return "", "", errors.New("tpm boom") }
	keyringProvider = func() vault.MasterProvider { return providerstest.NewMemoryFixed(nil) }
	for want, args := range map[string][]string{
		"dpapi boom": {"dpapi", "--generate", "--out", filepath.Join(dir, "b3")},
		"mac boom":   {"macos", "--generate"},
		"tpm boom":   {"tpm", "--generate", "--out-dir", filepath.Join(dir, "t")},
	} {
		if code, _, stderr := runCLI(t, "", append([]string{"provider", "seal"}, args...)...); code != 1 || !strings.Contains(stderr, want) {
			t.Errorf("%s: exit %d err %q", want, code, stderr)
		}
	}
	// A non-printable secret cannot go into the macOS keychain (real helper).
	sealMacOS = providers.SealMacOSKeychain
	if code, _, stderr := runCLI(t, "", "provider", "seal", "macos", "--master-file", mustWrite(t, dir, "bin", "\x00\x01\x02")); code != 1 {
		t.Errorf("macos binary secret: exit %d err %q", code, stderr)
	}
}

func mustWrite(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// `serve` through the CLI root: the real vault, persistent across restarts.
func TestServeSubcommandPersists(t *testing.T) {
	e := newVaultEnv(t)
	tok := filepath.Join(e.dir, "srv.token")
	run1 := func(ctx context.Context) {}
	_ = run1
	start := func() (addr string, stop func()) {
		ctx, cancel := context.WithCancel(context.Background())
		ready := make(chan string, 1)
		done := make(chan int, 1)
		go func() {
			done <- runServeForTest(ctx, e.args("serve", "--port", "0", "--token-file", tok), ready)
		}()
		select {
		case addr = <-ready:
		case code := <-done:
			t.Fatalf("serve exited early: %d", code)
		}
		return addr, func() { cancel(); <-done }
	}
	addr, stop := start()
	token := strings.TrimSpace(string(mustRead(t, tok)))
	assertMode0600(t, tok)
	url := "http://" + addr
	if code, out, stderr := runCLI(t, "persist-me\n", "--host", url, "--token", token, "set", "k", "--namespace", "p"); code != 0 {
		t.Fatalf("set: %d %s %s", code, out, stderr)
	}
	stop()
	addr, stop = start()
	defer stop()
	if code, out, stderr := runCLI(t, "", "--host", "http://"+addr, "--token", token, "get", "k", "--namespace", "p"); code != 0 || out != "persist-me\n" {
		t.Fatalf("after restart: exit %d out %q err %q", code, out, stderr)
	}
}
