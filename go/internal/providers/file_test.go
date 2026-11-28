package providers

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// secureDir is a 0700 temp dir (t.TempDir() is group-writable under a
// umask of 002, which the ancestor checks refuse).
func secureDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDecodeKeyFile(t *testing.T) {
	raw := bytes.Repeat([]byte{0xfb}, 32) // encodes with '-'/'_' vs '+'/'/'
	url := base64.URLEncoding.EncodeToString(raw)
	std := base64.StdEncoding.EncodeToString(raw)
	cases := []struct {
		name string
		in   []byte
		ok   bool
	}{
		{"url padded + newline", []byte(url + "\n"), true},
		{"url unpadded", []byte(strings.TrimRight(url, "=")), true},
		{"std alphabet", []byte(std), true},
		{"crlf", []byte(url + "\r\n"), true},
		{"32 raw bytes", raw, true},
		{"31 raw bytes", raw[:31], false},
		{"32 printable characters (a passphrase)", []byte("correct horse battery staple 123"), false},
		{"33 raw bytes", append(append([]byte(nil), raw...), 1), false},
		{"base64 of 31 bytes", []byte(base64.URLEncoding.EncodeToString(raw[:31])), false},
		{"base64 of 33 bytes", []byte(base64.URLEncoding.EncodeToString(append(raw, 1))), false},
		{"garbage", []byte("not a key at all!!"), false},
		{"empty", nil, false},
		{"over 128 bytes", bytes.Repeat([]byte("A"), 129), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := DecodeKeyFile(c.in)
			if c.ok {
				if err != nil || !bytes.Equal(got, raw) {
					t.Fatalf("DecodeKeyFile = %x, %v", got, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted %q", c.in)
			}
			if strings.Contains(err.Error(), string(c.in)) && len(c.in) > 0 {
				t.Fatal("error echoes the content")
			}
		})
	}
	if enc := EncodeKeyFile(raw); string(enc) != url+"\n" {
		t.Fatalf("EncodeKeyFile = %q", enc)
	}
}

func TestFileProviderSources(t *testing.T) {
	dir := secureDir(t)
	cred := filepath.Join(dir, "creds")
	if err := os.Mkdir(cred, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cred, DefaultMasterCredential), EncodeKeyFile(make([]byte, 32)), 0o400); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(dir, "keys")

	// 1. An explicit path wins over everything.
	p, err := NewFileProvider(FileOptions{Path: filepath.Join(dir, "x.key"), KeysDir: keys,
		Getenv: env(map[string]string{EnvCredentialsDirectory: cred})})
	if fp, ok := p.(*FileProvider); err != nil || !ok || !fp.explicit {
		t.Fatalf("explicit: %T %v", p, err)
	}
	// 2. Then the systemd credential.
	p, err = NewFileProvider(FileOptions{KeysDir: keys, Getenv: env(map[string]string{EnvCredentialsDirectory: cred})})
	if _, ok := p.(*CredentialProvider); err != nil || !ok {
		t.Fatalf("credential: %T %v", p, err)
	}
	if CanRotate(p) {
		t.Fatal("the credential provider must not be a Rotator")
	}
	if got, err := p.GetMasterSecret(); err != nil || len(got) != 32 {
		t.Fatalf("credential read: %v", err)
	}
	if err := p.(*CredentialProvider).Probe(); err != nil {
		t.Fatalf("credential probe: %v", err)
	}
	if loc := p.(*CredentialProvider).Location(); loc != filepath.Join(cred, DefaultMasterCredential) {
		t.Fatalf("location %q", loc)
	}
	// $CREDENTIALS_DIRECTORY without our credential is refused (review M2)
	// instead of silently creating a plaintext default key; an explicit path
	// still works.
	other := filepath.Join(dir, "other-creds")
	_ = os.Mkdir(other, 0o700)
	_, err = NewFileProvider(FileOptions{KeysDir: keys, Getenv: env(map[string]string{EnvCredentialsDirectory: other})})
	if !errors.Is(err, ErrMasterSecretUnavailable) || !strings.Contains(err.Error(), other) || !strings.Contains(err.Error(), "--master-key-file") {
		t.Fatalf("credentials dir without the credential: %v", err)
	}
	p, err = NewFileProvider(FileOptions{Path: filepath.Join(dir, "x.key"), Getenv: env(map[string]string{EnvCredentialsDirectory: other})})
	if _, ok := p.(*FileProvider); err != nil || !ok {
		t.Fatalf("explicit path under systemd: %T %v", p, err)
	}
	p, err = NewFileProvider(FileOptions{KeysDir: keys, Getenv: env(nil)})
	if fp, ok := p.(*FileProvider); err != nil || !ok || fp.keysDir != keys {
		t.Fatalf("default: %T %v", p, err)
	}
	// A NAMED credential must exist.
	_, err = NewFileProvider(FileOptions{KeysDir: keys, Getenv: env(map[string]string{EnvCredentialsDirectory: other, EnvMasterCredential: "mine"})})
	if !errors.Is(err, ErrMasterSecretUnavailable) || !strings.Contains(err.Error(), "LoadCredentialEncrypted=mine") {
		t.Fatalf("missing named credential: %v", err)
	}
	_, err = NewFileProvider(FileOptions{KeysDir: keys, Getenv: env(map[string]string{EnvMasterCredential: "mine"})})
	if !errors.Is(err, ErrMasterSecretUnavailable) || !strings.Contains(err.Error(), "CREDENTIALS_DIRECTORY") {
		t.Fatalf("named credential without a credentials dir: %v", err)
	}
	for _, bad := range []string{"../x", "a/b", ".."} {
		if _, err := NewFileProvider(FileOptions{KeysDir: keys, Getenv: env(map[string]string{EnvMasterCredential: bad})}); err == nil {
			t.Errorf("credential name %q accepted", bad)
		}
	}
	// The default keys dir is under the home directory.
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	p, err = NewFileProvider(FileOptions{Getenv: env(nil)})
	if fp, ok := p.(*FileProvider); err != nil || !ok || fp.keysDir != filepath.Join(dir, ".config", "rgt-vault", "keys") {
		t.Fatalf("default keys dir: %T %v", p, err)
	}
}

func TestFileProviderLifecycle(t *testing.T) {
	keys := filepath.Join(secureDir(t), "keys")
	mp, err := NewFileProvider(FileOptions{KeysDir: keys, Getenv: env(nil)})
	if err != nil {
		t.Fatal(err)
	}
	p := mp.(*FileProvider)
	t.Cleanup(func() { _ = p.Close() }) // Windows: release the lock handle before TempDir cleanup
	if !strings.Contains(p.Location(), "<vault-id>.key") {
		t.Fatalf("unbound location %q", p.Location())
	}
	// Unbound: every operation refuses.
	if _, err := p.GetMasterSecret(); err == nil {
		t.Fatal("GetMasterSecret before BindVault")
	}
	if err := p.BootstrapMasterSecret(); err == nil {
		t.Fatal("Bootstrap before BindVault")
	}
	if _, err := p.RotateMasterSecret(); err == nil {
		t.Fatal("Rotate before BindVault")
	}
	if err := p.Probe(); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	for _, bad := range []string{"", "../x", "a/b", ".hidden", strings.Repeat("a", 129)} {
		if err := p.BindVault(bad); err == nil {
			t.Errorf("BindVault(%q) accepted", bad)
		}
	}
	const id = "8a2b8db0-b325-441f-a67d-cff270ed7c07"
	if err := p.BindVault(id); err != nil {
		t.Fatal(err)
	}
	if err := p.BindVault("other-id"); err == nil {
		t.Fatal("re-bound to another vault")
	}
	path := DefaultKeyPath(keys, id)
	if p.Location() != path {
		t.Fatalf("location %q", p.Location())
	}
	// Missing file: fail closed, never regenerate.
	if _, err := p.GetMasterSecret(); !errors.Is(err, ErrMasterSecretUnavailable) || !strings.Contains(err.Error(), "Refusing to create") {
		t.Fatalf("missing key: %v", err)
	}
	if err := p.BootstrapMasterSecret(); err != nil {
		t.Fatal(err)
	}
	first, err := p.GetMasterSecret()
	if err != nil || len(first) != 32 {
		t.Fatalf("after bootstrap: %v", err)
	}
	if err := p.BootstrapMasterSecret(); err != nil { // existing file: kept
		t.Fatal(err)
	}
	if again, _ := p.GetMasterSecret(); !bytes.Equal(first, again) {
		t.Fatal("bootstrap overwrote the key")
	}
	if err := p.Probe(); err != nil {
		t.Fatalf("Probe of a bound, existing key: %v", err)
	}
	rotated, err := p.RotateMasterSecret()
	if err != nil {
		t.Fatal(err)
	}
	if now, _ := p.GetMasterSecret(); !bytes.Equal(now, rotated) || bytes.Equal(now, first) {
		t.Fatal("rotation did not persist a new key")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := p.GetMasterSecret(); !errors.Is(err, ErrMasterSecretUnavailable) || !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("loose key accepted: %v", err)
		}
		if err := p.Probe(); err == nil {
			t.Fatal("Probe accepted a loose key")
		}
	}
	// Content that is not a key is refused without echoing it.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("hunter2-not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetMasterSecret(); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("bad content: %v", err)
	}
}

func TestFileProviderExplicit(t *testing.T) {
	d := secureDir(t)
	path := filepath.Join(d, "sub", "master.key")
	mp, err := NewFileProvider(FileOptions{Path: path, Getenv: env(nil)})
	if err != nil {
		t.Fatal(err)
	}
	p := mp.(*FileProvider)
	if err := p.BindVault("whatever"); err != nil || p.Location() != path {
		t.Fatalf("BindVault on an explicit path: %v %q", err, p.Location())
	}
	if err := p.Probe(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Probe created the key directory (it must have no side effects)")
	}
	if err := p.BootstrapMasterSecret(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetMasterSecret(); err != nil {
		t.Fatal(err)
	}
}

func TestInsecureKeyACLWarning(t *testing.T) {
	var warned []string
	_, err := NewFileProvider(FileOptions{Path: "x", Getenv: env(map[string]string{EnvInsecureKeyACL: "1"}),
		Warn: func(s string) { warned = append(warned, s) }})
	if err != nil || len(warned) != 1 || !strings.Contains(warned[0], EnvInsecureKeyACL) {
		t.Fatalf("warned %v, err %v", warned, err)
	}
}

func TestKeyringUnavailable(t *testing.T) {
	for msg, want := range map[string]bool{
		"The name org.freedesktop.secrets was not provided by any .service files":        true,
		"dial unix /run/user/1000/bus: connect: no such file or directory":               true,
		"dbus: DBUS_SESSION_BUS_ADDRESS not set":                                         true,
		"exec: \"dbus-launch\": executable file not found in $PATH":                      true,
		"A specified logon session does not exist. It may already have been terminated.": true,
		"User interaction is not allowed.":                                               true,
		"permission denied":                                                              false,
	} {
		if got := IsKeyringUnavailable(errors.New(msg)); got != want {
			t.Errorf("IsKeyringUnavailable(%q) = %v", msg, got)
		}
	}
	if IsKeyringUnavailable(nil) || !IsKeyringUnavailable(ErrKeyringUnavailable) {
		t.Fatal("nil / sentinel")
	}

	fk := useFakeKeyring(t)
	p := NewKeyringProvider("", "")
	if err := p.Probe(); err != nil { // missing entry is fine
		t.Fatalf("probe of an empty keyring: %v", err)
	}
	_ = fk
	old := keyringGet
	t.Cleanup(func() { keyringGet = old })
	keyringGet = func(string, string) (string, error) {
		return "", errors.New("The name org.freedesktop.secrets was not provided by any .service files")
	}
	if err := p.Probe(); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("probe: %v", err)
	}
	if _, err := p.GetMasterSecret(); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("get: %v", err)
	}
	if _, err := p.InitializeIfMissing(); !errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("init: %v", err)
	}
	keyringGet = func(string, string) (string, error) { return "", errors.New("boom") }
	if err := p.Probe(); err == nil || errors.Is(err, ErrKeyringUnavailable) {
		t.Fatalf("other error: %v", err)
	}
	if !strings.Contains(p.Location(), KeyringBackendName()) {
		t.Fatalf("location %q", p.Location())
	}
}

// Review H1: rotation keeps the old key in .prev until it is confirmed.
func TestFileProviderRotationKeepsPrev(t *testing.T) {
	d := secureDir(t)
	path := filepath.Join(d, "master.key")
	mp, _ := NewFileProvider(FileOptions{Path: path, Getenv: env(nil)})
	p := mp.(*FileProvider)
	t.Cleanup(func() { _ = p.Close() })
	if err := p.BindVault("vault-1"); err != nil {
		t.Fatal(err)
	}
	if err := p.BootstrapMasterSecret(); err != nil {
		t.Fatal(err)
	}
	if got := p.CreatedFiles(); len(got) != 1 || got[0] != path {
		t.Fatalf("CreatedFiles = %v", got)
	}
	old, _ := p.GetMasterSecret()
	if _, err := p.PreviousMasterSecret(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("previous before any rotation: %v", err)
	}
	newKey, err := p.RotateMasterSecret()
	if err != nil {
		t.Fatal(err)
	}
	prev, err := p.PreviousMasterSecret()
	if err != nil || !bytes.Equal(prev, old) {
		t.Fatalf(".prev = %v (equal %v)", err, bytes.Equal(prev, old))
	}
	if cur, _ := p.GetMasterSecret(); !bytes.Equal(cur, newKey) {
		t.Fatal("the key file does not hold the new key")
	}
	// An unconfirmed rotation blocks the next one (never overwrite .prev).
	if _, err := p.RotateMasterSecret(); err == nil || !strings.Contains(err.Error(), ".prev") {
		t.Fatalf("second rotation with .prev present: %v", err)
	}
	if !strings.Contains(p.RecoveryHint(), "mv "+PrevPath(path)+" "+path) {
		t.Fatalf("hint %q", p.RecoveryHint())
	}
	if err := p.ConfirmMasterSecret("vault-1", newKey); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(PrevPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("confirm kept .prev")
	}
	if _, err := p.RotateMasterSecret(); err != nil {
		t.Fatalf("rotation after confirm: %v", err)
	}
}

// Review H2: the key is bound to one vault.
func TestFileProviderVaultBinding(t *testing.T) {
	d := secureDir(t)
	path := filepath.Join(d, "master.key")
	newP := func() *FileProvider {
		mp, _ := NewFileProvider(FileOptions{Path: path, Getenv: env(nil)})
		p := mp.(*FileProvider)
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	a := newP()
	if err := a.BindVault("vault-a"); err != nil {
		t.Fatal(err)
	}
	if err := a.BootstrapMasterSecret(); err != nil {
		t.Fatal(err)
	}
	keyA, _ := a.GetMasterSecret()
	if err := a.ConfirmMasterSecret("vault-a", keyA); err != nil {
		t.Fatal(err)
	}
	if err := a.ConfirmMasterSecret("vault-a", keyA); err != nil { // idempotent
		t.Fatal(err)
	}
	b := newP()
	if err := b.BindVault("vault-b"); !errors.Is(err, ErrMasterSecretUnavailable) || !strings.Contains(err.Error(), "belongs to vault vault-a") {
		t.Fatalf("second vault bound: %v", err)
	}
	// Even if a caller skips BindVault's verdict, rotation and confirmation
	// refuse a key bound elsewhere.
	if _, err := b.RotateMasterSecret(); err == nil || !strings.Contains(err.Error(), "belongs to vault vault-a") {
		t.Fatalf("rotate a key bound to another vault: %v", err)
	}
	if err := b.ConfirmMasterSecret("vault-b", keyA); err == nil {
		t.Fatal("confirm re-bound the key")
	}
	if got, _ := os.ReadFile(VaultIDPath(path)); strings.TrimSpace(string(got)) != "vault-a" {
		t.Fatalf("binding changed to %q", got)
	}
	if err := a.BindVault("vault-b"); err == nil {
		t.Fatal("re-bound a provider to another vault")
	}
}

// boundPair returns two providers on the same key file, both bound to the
// same vault and the key bootstrapped and confirmed: "A" (the serve that
// rotates) and "B" (another process, e.g. an offline export).
func boundPair(t *testing.T) (a, b *FileProvider, path string, oldKey []byte) {
	t.Helper()
	path = filepath.Join(secureDir(t), "master.key")
	mk := func() *FileProvider {
		mp, err := NewFileProvider(FileOptions{Path: path, Getenv: env(nil)})
		if err != nil {
			t.Fatal(err)
		}
		p := mp.(*FileProvider)
		if err := p.BindVault("vault-1"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	a = mk()
	if err := a.BootstrapMasterSecret(); err != nil {
		t.Fatal(err)
	}
	oldKey, _ = a.GetMasterSecret()
	if err := a.ConfirmMasterSecret("vault-1", oldKey); err != nil {
		t.Fatal(err)
	}
	return a, mk(), path, oldKey
}

// within runs fn and fails the test if it takes longer than d (a blocking
// lock would otherwise hang the test binary for its whole timeout).
func within(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v (blocked on the key lock?)", what, d)
	}
}

// Review MED-1 (a): while A rotates (A holds <key>.lock, .prev present), a
// confirmation by another process B, even one that holds the current key,
// returns at once and removes nothing; after A dies the old key is still in
// .prev. Without the lock in ConfirmMasterSecret, B removes .prev.
func TestConfirmCannotRemovePrevMidRotation(t *testing.T) {
	a, b, path, oldKey := boundPair(t)
	newKey, err := a.RotateMasterSecret()
	if err != nil {
		t.Fatal(err)
	}
	within(t, 5*time.Second, "confirm during another process's rotation", func() {
		if err := b.ConfirmMasterSecret("vault-1", newKey); err != nil {
			t.Error(err)
		}
	})
	_ = a.Close() // "kill -9" of A during its re-wrap
	prev, err := b.PreviousMasterSecret()
	if err != nil || !bytes.Equal(prev, oldKey) {
		t.Fatalf("%s lost mid-rotation: %v", PrevPath(path), err)
	}
}

// While B holds the key lock (between its comparison and its removal), a
// rotation fails fast with ErrKeyLocked instead of hanging, and changes
// nothing (review MED-B, provider side).
func TestRotationFailsFastWhenKeyLocked(t *testing.T) {
	a, b, path, oldKey := boundPair(t)
	// A pending .prev (from a crashed rotation) makes B take the lock.
	if _, err := a.RotateMasterSecret(); err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	oldWait := rotationLockWait
	t.Cleanup(func() { rotationLockWait, confirmHook = oldWait, nil })
	rotationLockWait = 200 * time.Millisecond
	var rotErr error
	confirmHook = func() {
		confirmHook = nil
		start := time.Now()
		_, rotErr = a.RotateMasterSecret()
		if time.Since(start) > 3*time.Second {
			rotErr = errors.New("rotation waited too long")
		}
	}
	cur, _ := b.GetMasterSecret()
	within(t, 10*time.Second, "confirm", func() { _ = b.ConfirmMasterSecret("vault-1", cur) })
	if !errors.Is(rotErr, ErrKeyLocked) || !strings.Contains(rotErr.Error(), LockPath(path)) {
		t.Fatalf("rotation while the key is locked: %v", rotErr)
	}
	_ = oldKey
}

// Review MED-1 (b): A rotated and died before re-wrapping (lock released);
// B, which unwrapped with the OLD key, confirms afterwards. The key file no
// longer holds B's secret, so .prev stays. Without the comparison, B
// removes the only key that opens the vault.
func TestConfirmKeepsPrevWhenKeyChanged(t *testing.T) {
	a, b, path, oldKey := boundPair(t)
	if _, err := a.RotateMasterSecret(); err != nil {
		t.Fatal(err)
	}
	_ = a.Close() // the rotating process died
	if err := b.ConfirmMasterSecret("vault-1", oldKey); err != nil {
		t.Fatal(err)
	}
	if prev, err := b.PreviousMasterSecret(); err != nil || !bytes.Equal(prev, oldKey) {
		t.Fatalf("%s removed by a confirm with a stale key: %v", PrevPath(path), err)
	}
	// While A still holds the lock (rotation in progress), B's confirm is
	// skipped at once instead of waiting.
	a2, _, _, _ := boundPair(t)
	if _, err := a2.RotateMasterSecret(); err != nil {
		t.Fatal(err)
	}
	other, _ := NewFileProvider(FileOptions{Path: a2.path, Getenv: env(nil), Warn: func(string) {}})
	o := other.(*FileProvider)
	t.Cleanup(func() { _ = o.Close() })
	_ = o.BindVault("vault-1")
	cur, _ := o.GetMasterSecret()
	within(t, 2*time.Second, "confirm during another process's rotation", func() {
		if err := o.ConfirmMasterSecret("vault-1", cur); err != nil {
			t.Error(err)
		}
	})
	if _, err := os.Stat(PrevPath(a2.path)); err != nil {
		t.Fatal("confirm during another process's rotation removed .prev")
	}
	// The rotating process itself confirms with the new key: .prev goes.
	if err := a2.ConfirmMasterSecret("vault-1", cur); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(PrevPath(a2.path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rotating process's confirm kept .prev")
	}
}

// Review MED-2: a .prev is only ever removed by the vault the key is bound to.
func TestPrevRemovedOnlyByOwningVault(t *testing.T) {
	a, _, path, _ := boundPair(t)
	newKey, err := a.RotateMasterSecret()
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	mp, _ := NewFileProvider(FileOptions{Path: path, Getenv: env(nil)})
	other := mp.(*FileProvider)
	t.Cleanup(func() { _ = other.Close() })
	other.path, other.vaultID = path, "vault-2" // even if BindVault were bypassed
	if err := other.ConfirmMasterSecret("vault-2", newKey); err == nil {
		t.Fatal("another vault confirmed the key")
	}
	if _, err := os.Stat(PrevPath(path)); err != nil {
		t.Fatal("another vault removed .prev")
	}
}

// Review LOW (M18): when writing the new key fails, .prev is removed and the
// key file is unchanged.
func TestRotateWriteFailureCleansPrev(t *testing.T) {
	a, _, path, oldKey := boundPair(t)
	old := replaceSecret
	t.Cleanup(func() { replaceSecret = old })
	replaceSecret = func(string, []byte) error { return errors.New("disk full") }
	if _, err := a.RotateMasterSecret(); err == nil {
		t.Fatal("rotation succeeded")
	}
	if _, err := os.Stat(PrevPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(".prev left behind after a failed rotation")
	}
	if cur, _ := a.GetMasterSecret(); !bytes.Equal(cur, oldKey) {
		t.Fatal("key file changed by a failed rotation")
	}
	// And the lock was released: the next rotation works at once.
	replaceSecret = old
	done := make(chan error, 1)
	go func() { _, err := a.RotateMasterSecret(); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lock still held after a failed rotation")
	}
}

// Review LOW (M08): a rotation is refused while an unconfirmed .prev exists,
// with a message that says why, and .prev is left exactly as it was.
func TestRotateRefusedWithPendingPrev(t *testing.T) {
	a, _, path, oldKey := boundPair(t)
	if _, err := a.RotateMasterSecret(); err != nil {
		t.Fatal(err)
	}
	_, err := a.RotateMasterSecret()
	if err == nil || !strings.Contains(err.Error(), "earlier rotation that was not confirmed") {
		t.Fatalf("second rotation: %v", err)
	}
	if prev, _ := a.PreviousMasterSecret(); !bytes.Equal(prev, oldKey) {
		t.Fatalf("%s changed", PrevPath(path))
	}
}

// Review LOW (2): an unsafe key directory is reported as itself.
func TestBindVaultReportsUnsafeDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix modes")
	}
	d := secureDir(t)
	keys := filepath.Join(d, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keys, 0o770); err != nil {
		t.Fatal(err)
	}
	mp, _ := NewFileProvider(FileOptions{Path: filepath.Join(keys, "master.key"), Getenv: env(nil)})
	err := mp.(*FileProvider).BindVault("vault-1")
	if err == nil || strings.Contains(err.Error(), "vault binding") || !strings.Contains(err.Error(), "group-writable") {
		t.Fatalf("err = %v", err)
	}
}

// Review MED-A: .prev is owned through its own sidecar. Even after
// <key>.vault-id was removed (seal --force, or an operator "releasing" the
// key) and another vault bound the key, that vault never removes .prev.
func TestPrevOwnedByItsOwnSidecar(t *testing.T) {
	a, _, path, oldKey := boundPair(t)
	if _, err := a.RotateMasterSecret(); err != nil {
		t.Fatal(err)
	}
	_ = a.Close() // crashed before the re-wrap: .prev is vault-1's only key
	if b, _ := os.ReadFile(PrevOwnerPath(path)); strings.TrimSpace(string(b)) != "vault-1" {
		t.Fatalf(".prev owner %q", b)
	}
	if err := os.Remove(VaultIDPath(path)); err != nil {
		t.Fatal(err)
	}
	mp, _ := NewFileProvider(FileOptions{Path: path, Getenv: env(nil), Warn: func(string) {}})
	b := mp.(*FileProvider)
	t.Cleanup(func() { _ = b.Close() })
	if err := b.BindVault("vault-2"); err != nil {
		t.Fatal(err)
	}
	cur, _ := b.GetMasterSecret()
	if err := b.ConfirmMasterSecret("vault-2", cur); err != nil {
		t.Fatal(err)
	}
	if prev, err := b.PreviousMasterSecret(); err != nil || !bytes.Equal(prev, oldKey) {
		t.Fatalf("vault-2 removed vault-1's .prev: %v", err)
	}
	// A .prev without an owner record is never removed either.
	if err := os.Remove(PrevOwnerPath(path)); err != nil {
		t.Fatal(err)
	}
	if err := b.ConfirmMasterSecret("vault-2", cur); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(PrevPath(path)); err != nil {
		t.Fatal("an ownerless .prev was removed")
	}
}

// Review LOW (M7): a rotation of a key that was never confirmed binds it to
// the rotating vault first.
func TestRotationBindsFirst(t *testing.T) {
	path := filepath.Join(secureDir(t), "master.key")
	mp, _ := NewFileProvider(FileOptions{Path: path, Getenv: env(nil)})
	p := mp.(*FileProvider)
	t.Cleanup(func() { _ = p.Close() })
	if err := p.BindVault("vault-9"); err != nil {
		t.Fatal(err)
	}
	if err := p.BootstrapMasterSecret(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(VaultIDPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("bound before any confirmation")
	}
	if _, err := p.RotateMasterSecret(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{VaultIDPath(path), PrevOwnerPath(path)} {
		if b, err := os.ReadFile(f); err != nil || strings.TrimSpace(string(b)) != "vault-9" {
			t.Fatalf("%s = %q, %v", f, b, err)
		}
	}
}

// Review MED-C: a key in a read-only directory (a Kubernetes/Docker secret
// mount) opens: no lock file is needed without a .prev, and a binding that
// cannot be written is only a warning.
func TestConfirmReadOnlyKeyDir(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("Unix permissions, non-root")
	}
	for _, withBinding := range []bool{true, false} {
		dir := filepath.Join(secureDir(t), "mount")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "k.key")
		key := EncodeKeyFile(bytes.Repeat([]byte{0x81}, 32))
		if err := os.WriteFile(path, key, 0o400); err != nil {
			t.Fatal(err)
		}
		if withBinding {
			if err := os.WriteFile(VaultIDPath(path), []byte("vault-ro\n"), 0o400); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		var warned []string
		mp, _ := NewFileProvider(FileOptions{Path: path, Getenv: env(nil), Warn: func(s string) { warned = append(warned, s) }})
		p := mp.(*FileProvider)
		if err := p.BindVault("vault-ro"); err != nil {
			t.Fatal(err)
		}
		cur, err := p.GetMasterSecret()
		if err != nil {
			t.Fatal(err)
		}
		within(t, 2*time.Second, "confirm on a read-only dir", func() {
			if err := p.ConfirmMasterSecret("vault-ro", cur); err != nil {
				t.Errorf("binding=%v: confirm failed the open: %v", withBinding, err)
			}
		})
		if _, err := os.Lstat(LockPath(path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a lock file was needed")
		}
		if !withBinding && len(warned) == 0 {
			t.Error("no warning for the unwritable binding")
		}
	}
}

// Review MED-C: without a .prev, confirming takes no lock and creates no
// lock file (opens never depend on a writable key directory).
func TestConfirmWithoutPrevTakesNoLock(t *testing.T) {
	_, b, path, oldKey := boundPair(t)
	if err := b.ConfirmMasterSecret("vault-1", oldKey); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(LockPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock file created without a .prev: %v", err)
	}
}
