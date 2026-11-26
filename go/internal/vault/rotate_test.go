package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"rgt-vault-server/internal/keychain"
	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/store"
)

// TestRotateDEKKeepsAllVersions is RGT-499: after RotateDEK, SUPERSEDED and
// REVOKED versions still decrypt (Python's rotate_dek loses them).
func TestRotateDEKKeepsAllVersions(t *testing.T) {
	ctx := context.Background()
	v, prov := newVault(t, allowAllPolicy)
	set(t, v, "n", "multi", "v1")
	set(t, v, "n", "multi", "v2")
	set(t, v, "n", "multi", "v3")
	set(t, v, "n", "gone", "revoked-v1")
	if err := v.RevokeSecret(ctx, "n", "gone", SystemAgent); err != nil {
		t.Fatal(err)
	}
	oldDEK := append([]byte(nil), v.dek...)
	oldKeychain, _ := os.ReadFile(v.KeychainPath())

	if err := v.RotateDEK(ctx); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oldDEK, v.dek) {
		t.Fatal("DEK unchanged")
	}
	if newKC, _ := os.ReadFile(v.KeychainPath()); bytes.Equal(oldKeychain, newKC) {
		t.Fatal("keychain.json unchanged")
	}
	if _, err := os.Stat(v.KeychainPath() + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("keychain.json.new left behind")
	}
	if c, b, _ := v.store.DEKUsage(ctx); c != 0 || b != 0 {
		t.Fatalf("usage not reset: %d/%d", c, b)
	}
	if r := lastAudit(t, v, 1)[0]; r.Action != "ROTATE" || r.SecretName.String != "DEK" || r.Details.String != "Data Encryption Key rotated successfully" {
		t.Fatalf("rotate row %+v", r)
	}
	check := func(v *Vault) {
		t.Helper()
		for ver, want := range map[int64]string{1: "v1", 2: "v2", 3: "v3"} {
			if got, err := get(t, v, "n", "multi", ver); err != nil || got != want {
				t.Errorf("multi v%d = %q, %v", ver, got, err)
			}
		}
		if got, err := get(t, v, "n", "gone", 1); err != nil || got != "revoked-v1" {
			t.Errorf("revoked v1 = %q, %v", got, err)
		}
		mustVerify(t, v)
	}
	check(v)
	// Every row is under the new DEK (none decrypts with the old one).
	recs, _ := v.store.ExportData(ctx)
	if len(recs.Secrets) != 4 {
		t.Fatalf("%d rows", len(recs.Secrets))
	}
	_ = v.Close()
	check(openT(t, Config{DBPath: v.store.Path(), Provider: prov, PolicyYAML: allowAllPolicy}))
}

// TestRotateDEKOnPythonFixtureKeepsVersions runs the Go rotation on the
// Python small/ vault, whose version history was partly orphaned by
// Python's own rotate_dek: rows that still decrypted keep decrypting, the
// orphaned ones are left untouched, and a version revoked by Go survives.
func TestRotateDEKOnPythonFixtureKeepsVersions(t *testing.T) {
	ctx := context.Background()
	m := loadManifest(t, "small")
	db, prov := copyFixture(t, "small")
	v := openT(t, Config{DBPath: db, Provider: prov, PolicyYAML: fixturePolicy(t, "small")})
	if err := v.RevokeSecret(ctx, "prod", "API_KEY", SystemAgent); err != nil {
		t.Fatal(err)
	}
	if err := v.RotateDEK(ctx); err != nil {
		t.Fatal(err)
	}
	for _, s := range m.Secrets {
		want := expectedRead(s)
		if got := readVersion(t, v, s.Namespace, s.Name, s.Version); got != want {
			t.Errorf("%s/%s v%d %s: got %s want %s", s.Namespace, s.Name, s.Version, s.Status, got, want)
		}
	}
	// SUPERSEDED post-rotation v1 (Python-written) is the RGT-499 case.
	if got, err := get(t, v, "default", "post-rotation", 1); err != nil || got != "after-v1" {
		t.Fatalf("superseded python row after Go RotateDEK: %q %v", got, err)
	}
	if got, err := get(t, v, "prod", "API_KEY", 1); err != nil || got != "sk_live_0123456789abcdef" {
		t.Fatalf("revoked python row after Go RotateDEK: %q %v", got, err)
	}
	mustVerify(t, v)
}

func setMany(t *testing.T, v *Vault, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		set(t, v, "bulk", fmt.Sprintf("s%04d", i), fmt.Sprintf("value-%04d", i))
	}
	// A few extra versions so SUPERSEDED rows are part of the rewrite.
	for i := 0; i < 10; i++ {
		set(t, v, "bulk", fmt.Sprintf("s%04d", i), fmt.Sprintf("value-%04d-v2", i))
	}
}

func checkMany(t *testing.T, v *Vault, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		want := fmt.Sprintf("value-%04d", i)
		ver := int64(1)
		if got, err := get(t, v, "bulk", fmt.Sprintf("s%04d", i), ver); err != nil || got != want {
			t.Fatalf("s%04d v1 = %q, %v", i, got, err)
		}
	}
	for i := 0; i < 10; i++ {
		if got, err := get(t, v, "bulk", fmt.Sprintf("s%04d", i), 0); err != nil || got != fmt.Sprintf("value-%04d-v2", i) {
			t.Fatalf("s%04d latest = %q, %v", i, got, err)
		}
	}
}

const (
	envCrashDir   = "RGT_VAULT_TEST_CRASH_DIR"
	envCrashAt    = "RGT_VAULT_TEST_CRASH_AT"
	envCrashPhase = "RGT_VAULT_TEST_CRASH_PHASE"
)

// TestCrashHelper is not a test: it is the child process of the crash
// tests. It opens the vault in $RGT_VAULT_TEST_CRASH_DIR and kills itself
// (os.Exit, no cleanup, no rollback) in the middle of RotateDEK.
func TestCrashHelper(t *testing.T) {
	dir := os.Getenv(envCrashDir)
	if dir == "" {
		t.Skip("helper process")
	}
	v, err := Open(context.Background(), Config{
		DBPath: filepath.Join(dir, "vault.db"), Provider: providerstest.File{Path: filepath.Join(dir, "master.bin")},
		PolicyYAML: allowAllPolicy, KDFParams: testParams,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(3)
	}
	at, _ := strconv.Atoi(os.Getenv(envCrashAt))
	switch os.Getenv(envCrashPhase) {
	case "rewrite":
		v.testRewriteRow = func(n int) error {
			if n == at {
				os.Exit(42)
			}
			return nil
		}
	case "before-rename":
		v.testBeforeSwap = func() error { os.Exit(42); return nil }
	}
	_ = v.RotateDEK(context.Background())
	os.Exit(4) // the rotation must not complete
}

func runCrash(t *testing.T, dir, phase string, at int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), envCrashDir+"="+dir, envCrashPhase+"="+phase, envCrashAt+"="+strconv.Itoa(at))
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 42 {
		t.Fatalf("child did not crash where expected: %v\n%s", err, out)
	}
}

func newFileVault(t *testing.T) (string, providerstest.File, *Vault) {
	t.Helper()
	dir := t.TempDir()
	prov := providerstest.File{Path: filepath.Join(dir, "master.bin")}
	if _, err := prov.RotateMasterSecret(); err != nil { // writes a random master
		t.Fatal(err)
	}
	v := openT(t, Config{DBPath: filepath.Join(dir, "vault.db"), Provider: prov, PolicyYAML: allowAllPolicy})
	return dir, prov, v
}

// TestRotateDEK1kAtomicity is the RGT-152 acceptance test: a 1,000-secret
// RotateDEK interrupted midway (in-process failure, and a real process
// death in the middle of the transaction) leaves the old keychain and the
// old rows in effect; a later rotation then succeeds.
func TestRotateDEK1kAtomicity(t *testing.T) {
	const n = 1000
	ctx := context.Background()
	dir, prov, v := newFileVault(t)
	setMany(t, v, n)
	kc0, _ := os.ReadFile(v.KeychainPath())
	epoch0 := v.KeyEpoch()
	rows0 := len(auditRows(t, v))

	// 1. In-process failure at row 500: rollback.
	v.testRewriteRow = func(i int) error {
		if i == 500 {
			return errors.New("injected failure")
		}
		return nil
	}
	if err := v.RotateDEK(ctx); err == nil {
		t.Fatal("rotation should fail")
	}
	v.testRewriteRow = nil
	if kc, _ := os.ReadFile(v.KeychainPath()); !bytes.Equal(kc, kc0) {
		t.Fatal("keychain.json changed by a failed rotation")
	}
	if _, err := os.Stat(v.KeychainPath() + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(".new not cleaned up")
	}
	if e, _ := v.store.KeyEpoch(ctx); e != epoch0 || v.KeyEpoch() != epoch0 {
		t.Fatalf("epoch changed: db %d mem %d", e, v.KeyEpoch())
	}
	// Only the hook row was added; no ROTATE row.
	if rows := auditRows(t, v); len(rows) != rows0+1 || rows[len(rows)-1].Action != "HOOK_ROTATE" {
		t.Fatalf("audit rows after failed rotation: %d (+%d)", len(rows), len(rows)-rows0)
	}
	checkMany(t, v, n)
	_ = v.Close()

	// 2. Process killed in the middle of the rewrite transaction.
	runCrash(t, dir, "rewrite", 500)
	if kc, _ := os.ReadFile(filepath.Join(dir, "keychain.json")); !bytes.Equal(kc, kc0) {
		t.Fatal("keychain.json changed by a crashed rotation")
	}
	v = openT(t, Config{DBPath: filepath.Join(dir, "vault.db"), Provider: prov, PolicyYAML: allowAllPolicy})
	if v.KeyEpoch() != epoch0 {
		t.Fatalf("epoch after crash %d, want %d", v.KeyEpoch(), epoch0)
	}
	if _, err := os.Stat(v.KeychainPath() + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale .new not removed on open")
	}
	checkMany(t, v, n)
	mustVerify(t, v)

	// 3. A clean rotation now rewrites all 1,010 rows.
	if err := v.RotateDEK(ctx); err != nil {
		t.Fatal(err)
	}
	if v.KeyEpoch() != epoch0+1 {
		t.Fatalf("epoch %d", v.KeyEpoch())
	}
	checkMany(t, v, n)
	mustVerify(t, v)
}

// TestRotateDEKCrashAfterCommit kills the process after the database commit
// but before keychain.json.new is renamed: Open completes the rotation.
func TestRotateDEKCrashAfterCommit(t *testing.T) {
	dir, prov, v := newFileVault(t)
	setMany(t, v, 50)
	epoch0 := v.KeyEpoch()
	_ = v.Close()

	runCrash(t, dir, "before-rename", 0)
	if _, err := os.Stat(filepath.Join(dir, "keychain.json.new")); err != nil {
		t.Fatalf("expected a pending keychain.json.new: %v", err)
	}
	v = openT(t, Config{DBPath: filepath.Join(dir, "vault.db"), Provider: prov, PolicyYAML: allowAllPolicy})
	if v.KeyEpoch() != epoch0+1 {
		t.Fatalf("epoch %d, want %d", v.KeyEpoch(), epoch0+1)
	}
	if _, err := os.Stat(filepath.Join(dir, "keychain.json.new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(".new still present after recovery")
	}
	checkMany(t, v, 50)
	mustVerify(t, v)
}

func TestRotateDEKFailureAfterCommitMarksBroken(t *testing.T) {
	ctx := context.Background()
	dir, prov, v := newFileVault(t)
	set(t, v, "n", "s", "v")
	v.testBeforeSwap = func() error { return errors.New("disk full") }
	if err := v.RotateDEK(ctx); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("want ErrInconsistent, got %v", err)
	}
	if _, err := get(t, v, "n", "s", 0); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("broken vault still serving: %v", err)
	}
	_ = v.Close()
	v = openT(t, Config{DBPath: filepath.Join(dir, "vault.db"), Provider: prov, PolicyYAML: allowAllPolicy})
	if got, err := get(t, v, "n", "s", 0); err != nil || got != "v" {
		t.Fatalf("after recovery %q %v", got, err)
	}
}

func TestPendingKeychainHandling(t *testing.T) {
	ctx := context.Background()
	dir, prov, v := newFileVault(t)
	set(t, v, "n", "s", "v")
	_ = v.Close()
	// A valid keychain with a stray .new (from a rotation that never
	// committed) opens, and the .new is removed.
	other, _, ov := newFileVault(t)
	_ = ov.Close()
	copyFile(t, filepath.Join(other, "keychain.json"), filepath.Join(dir, "keychain.json.new"))
	vv, err := Open(context.Background(), Config{DBPath: filepath.Join(dir, "vault.db"), Provider: prov, KDFParams: testParams})
	if err != nil {
		t.Fatalf("a valid keychain with a stray .new must open: %v", err)
	}
	_ = vv.Close()
	if _, err := os.Stat(filepath.Join(dir, "keychain.json.new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stray .new not removed")
	}

	// The DB epoch is ahead of keychain.json (a rollback) and the .new
	// belongs to another vault: the rollback error stands, nothing renamed.
	st, err := store.Open(ctx, filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.IncrementKeyEpoch(ctx); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	copyFile(t, filepath.Join(other, "keychain.json"), filepath.Join(dir, "keychain.json.new"))
	_, err = Open(ctx, Config{DBPath: filepath.Join(dir, "vault.db"), Provider: prov, KDFParams: testParams})
	if !errors.Is(err, keychain.ErrRollback) {
		t.Fatalf("want rollback error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "keychain.json.new")); err != nil {
		t.Fatal("foreign .new must not be consumed")
	}
}

func TestAutoRotateOnUsageThreshold(t *testing.T) {
	ctx := context.Background()
	v, _ := newVault(t, allowAllPolicy)
	v.dekMaxEncryptions = 3
	set(t, v, "n", "a", "1")
	set(t, v, "n", "b", "2")
	if v.KeyEpoch() != 1 {
		t.Fatal("rotated too early")
	}
	set(t, v, "n", "c", "3")
	if v.KeyEpoch() != 2 {
		t.Fatalf("no auto-rotation at the threshold (epoch %d)", v.KeyEpoch())
	}
	if c, _, _ := v.store.DEKUsage(ctx); c != 0 {
		t.Fatalf("usage not reset: %d", c)
	}
	v.dekMaxEncryptions = DEKMaxEncryptions
	v.dekMaxBytes = 10
	set(t, v, "n", "d", "0123456789")
	if v.KeyEpoch() != 3 {
		t.Fatalf("no auto-rotation on the byte threshold (epoch %d)", v.KeyEpoch())
	}
	// autoRotateDEK re-checks: below the threshold it does nothing.
	if err := v.autoRotateDEK(ctx); err != nil || v.KeyEpoch() != 3 {
		t.Fatalf("spurious rotation: %v epoch %d", err, v.KeyEpoch())
	}
	for _, n := range []string{"a", "b", "c", "d"} {
		if _, err := get(t, v, "n", n, 0); err != nil {
			t.Fatal(err)
		}
	}
	mustVerify(t, v)
}

func TestRotateMaster(t *testing.T) {
	ctx := context.Background()

	// Not supported: nothing changes, not even the audit chain.
	fixed := providerstest.Fixed{Secret: bytes.Repeat([]byte{7}, 32)}
	v := openT(t, Config{DBPath: filepath.Join(t.TempDir(), "vault.db"), Provider: fixed, PolicyYAML: allowAllPolicy})
	err := v.RotateMaster(ctx)
	if !errors.Is(err, ErrRotateNotSupported) || len(auditRows(t, v)) != 0 || v.KeyEpoch() != 1 {
		t.Fatalf("unsupported: %v", err)
	}

	// Provider failure: epoch unchanged.
	mv, prov := newVault(t, allowAllPolicy)
	set(t, mv, "n", "s", "v")
	prov.RotateErr = errors.New("keyring locked")
	if err := mv.RotateMaster(ctx); err == nil || mv.KeyEpoch() != 1 {
		t.Fatalf("provider error: %v epoch %d", err, mv.KeyEpoch())
	}
	prov.RotateErr = nil

	// Success: same DEK, new wrap, epoch+1, Python's audit row.
	dek := append([]byte(nil), mv.dek...)
	kc0, _ := os.ReadFile(mv.KeychainPath())
	if err := mv.RotateMaster(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dek, mv.dek) || mv.KeyEpoch() != 2 {
		t.Fatal("RotateMaster must keep the DEK and bump the epoch")
	}
	if kc, _ := os.ReadFile(mv.KeychainPath()); bytes.Equal(kc, kc0) {
		t.Fatal("keychain not rewrapped")
	}
	checkRows(t, lastAudit(t, mv, 2), []wantRow{
		{action: "HOOK_ROTATE", nullName: true, details: offHookAllow},
		{action: "ROTATE", name: "MASTER_KEY", details: "Master key rotated successfully"},
	})
	_ = mv.Close()
	mv = openT(t, Config{DBPath: mv.store.Path(), Provider: prov, PolicyYAML: allowAllPolicy})
	if got, err := get(t, mv, "n", "s", 0); err != nil || got != "v" {
		t.Fatalf("after master rotation: %q %v", got, err)
	}

	// The epoch moved on disk behind our back: refuse to rotate.
	if _, err := mv.store.IncrementKeyEpoch(ctx); err != nil {
		t.Fatal(err)
	}
	if err := mv.RotateDEK(ctx); err == nil {
		t.Fatal("rotation over a foreign epoch change")
	}
}
