package providers

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// useFakeDPAPI installs reversible fake protect/unprotect functions that also
// check the entropy, recording the calls.
func useFakeDPAPI(t *testing.T) {
	t.Helper()
	oldP, oldU := dpapiProtect, dpapiUnprotect
	dpapiProtect = func(secret, entropy []byte) ([]byte, error) {
		return append(append([]byte("BLOB|"), entropy...), append([]byte("|"), secret...)...), nil
	}
	dpapiUnprotect = func(blob, entropy []byte) ([]byte, error) {
		prefix := append(append([]byte("BLOB|"), entropy...), '|')
		if !bytes.HasPrefix(blob, prefix) {
			return nil, errors.New("DPAPI decryption failed: wrong entropy")
		}
		return bytes.Clone(blob[len(prefix):]), nil
	}
	t.Cleanup(func() { dpapiProtect, dpapiUnprotect = oldP, oldU })
}

func TestDPAPISealAndGet(t *testing.T) {
	useFakeDPAPI(t)
	path := filepath.Join(t.TempDir(), "sub", "sealed.bin")
	secret := seq32()
	if err := SealDPAPI(secret, path, nil); err != nil {
		t.Fatal(err)
	}
	text, _ := os.ReadFile(path)
	if _, err := base64.StdEncoding.DecodeString(string(text)); err != nil {
		t.Fatalf("blob file must be plain base64: %v", err)
	}
	p, err := NewDPAPIProvider(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.GetMasterSecret()
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("got %x %v", got, err)
	}
}

func TestDPAPIBase64WhitespaceTolerated(t *testing.T) {
	useFakeDPAPI(t)
	path := filepath.Join(t.TempDir(), "b.bin")
	b64 := base64.StdEncoding.EncodeToString([]byte("BLOB||hello"))
	// Python's b64decode ignores newlines and spaces.
	if err := os.WriteFile(path, []byte(b64[:4]+"\r\n "+b64[4:]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, _ := NewDPAPIProvider(path, nil)
	got, err := p.GetMasterSecret()
	if err != nil || string(got) != "hello" {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestDPAPIEntropyAndFailures(t *testing.T) {
	useFakeDPAPI(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "sealed.bin")
	if err := SealDPAPI([]byte("s"), path, []byte("pepper")); err != nil {
		t.Fatal(err)
	}
	good, _ := NewDPAPIProvider(path, []byte("pepper"))
	if got, err := good.GetMasterSecret(); err != nil || string(got) != "s" {
		t.Fatalf("with entropy: %q %v", got, err)
	}
	bad, _ := NewDPAPIProvider(path, nil)
	if _, err := bad.GetMasterSecret(); !errors.Is(err, ErrMasterSecretUnavailable) {
		t.Fatalf("wrong entropy: %v", err)
	}

	if _, err := NewDPAPIProvider(filepath.Join(dir, "nope"), nil); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing blob: %v", err)
	}
	if _, err := NewDPAPIProvider(dir, nil); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("directory is not a blob: %v", err)
	}

	junk := filepath.Join(dir, "junk.bin")
	_ = os.WriteFile(junk, []byte("***not base64***"), 0o600)
	jp, _ := NewDPAPIProvider(junk, nil)
	if _, err := jp.GetMasterSecret(); !errors.Is(err, ErrMasterSecretUnavailable) {
		t.Fatalf("invalid base64: %v", err)
	}

	// File vanishes after construction.
	gone := filepath.Join(dir, "gone.bin")
	_ = os.WriteFile(gone, []byte("QQ=="), 0o600)
	gp, _ := NewDPAPIProvider(gone, nil)
	_ = os.Remove(gone)
	if _, err := gp.GetMasterSecret(); err == nil {
		t.Fatal("read of vanished file succeeded")
	}
}

func TestSealDPAPIRejectsEmptySecret(t *testing.T) {
	useFakeDPAPI(t)
	if err := SealDPAPI(nil, filepath.Join(t.TempDir(), "b"), nil); err == nil {
		t.Fatal("empty secret sealed")
	}
}

func TestStatRegularPermissionIsNotNotFound(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	_ = os.Mkdir(locked, 0o000)
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	err := statRegular(filepath.Join(locked, "blob"), "x")
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("permission error must not be reported as not-found: %v", err)
	}
}

func TestDPAPIRotate(t *testing.T) {
	useFakeDPAPI(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "sealed.bin")
	_ = SealDPAPI([]byte("old"), path, nil)
	p, _ := NewDPAPIProvider(path, nil)
	nw, err := p.RotateMasterSecret()
	if err != nil || len(nw) != MasterSecretSize {
		t.Fatalf("rotate: %x %v", nw, err)
	}
	got, _ := p.GetMasterSecret()
	if !bytes.Equal(got, nw) {
		t.Fatal("blob was not replaced with the new secret")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}

	dpapiProtect = func(_, _ []byte) ([]byte, error) { return nil, errors.New("seal boom") }
	if _, err := p.RotateMasterSecret(); err == nil {
		t.Fatal("seal failure must propagate")
	}
	after, _ := p.GetMasterSecret()
	if !bytes.Equal(after, nw) {
		t.Fatal("failed rotation must leave the old blob intact")
	}
}

func TestSealDPAPIFileErrors(t *testing.T) {
	useFakeDPAPI(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	_ = os.WriteFile(file, nil, 0o600)
	// Parent is a regular file → MkdirAll fails.
	if err := SealDPAPI([]byte("x"), filepath.Join(file, "x", "blob"), nil); err == nil {
		t.Fatal("expected mkdir failure")
	}
	// Target is an existing directory → rename fails and temp file is cleaned.
	target := filepath.Join(dir, "d")
	_ = os.Mkdir(target, 0o700)
	if err := SealDPAPI([]byte("x"), target, nil); err == nil {
		t.Fatal("expected rename failure")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "f" && e.Name() != "d" {
			t.Fatalf("leftover %s", e.Name())
		}
	}
	// A bad temp dir (parent missing is created by MkdirAll; make dir read-only)
	if os.Geteuid() != 0 {
		ro := filepath.Join(dir, "ro")
		_ = os.Mkdir(ro, 0o500)
		if err := SealDPAPI([]byte("x"), filepath.Join(ro, "blob"), nil); err == nil {
			t.Fatal("expected create-temp failure")
		}
	}
	dpapiProtect = func(_, _ []byte) ([]byte, error) { return nil, errors.New("x") }
	if err := SealDPAPI([]byte("x"), filepath.Join(dir, "z"), nil); err == nil {
		t.Fatal("protect failure must propagate")
	}
}

func TestDPAPIUnsupportedOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("real DPAPI on Windows; see dpapi_windows_test.go")
	}
	if _, err := platformDPAPIProtect(nil, nil); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("got %v", err)
	}
	if _, err := platformDPAPIUnprotect(nil, nil); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("got %v", err)
	}
}
