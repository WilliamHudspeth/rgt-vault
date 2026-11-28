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
	if err := p.ConfirmMasterSecret("vault-1"); err != nil {
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
		return mp.(*FileProvider)
	}
	a := newP()
	if err := a.BindVault("vault-a"); err != nil {
		t.Fatal(err)
	}
	if err := a.BootstrapMasterSecret(); err != nil {
		t.Fatal(err)
	}
	if err := a.ConfirmMasterSecret("vault-a"); err != nil {
		t.Fatal(err)
	}
	if err := a.ConfirmMasterSecret("vault-a"); err != nil { // idempotent
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
	if err := b.ConfirmMasterSecret("vault-b"); err == nil {
		t.Fatal("confirm re-bound the key")
	}
	if got, _ := os.ReadFile(VaultIDPath(path)); strings.TrimSpace(string(got)) != "vault-a" {
		t.Fatalf("binding changed to %q", got)
	}
	if err := a.BindVault("vault-b"); err == nil {
		t.Fatal("re-bound a provider to another vault")
	}
}
