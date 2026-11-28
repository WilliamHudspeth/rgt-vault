package secfile

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// keyDir returns a fresh 0700 directory under t.TempDir().
func keyDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(secureTemp(t), "keys")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// secureTemp is t.TempDir() made 0700: with a umask of 002 the temp dir is
// group-writable and (rightly) refused as an ancestor.
func secureTemp(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestCreateOpenReplace(t *testing.T) {
	d := keyDir(t)
	p := filepath.Join(d, "a.key")
	if err := CreateSecret(p, []byte("one\n")); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	got, err := OpenSecret(p, Options{})
	if err != nil || string(got) != "one\n" {
		t.Fatalf("OpenSecret = %q, %v", got, err)
	}
	// Never overwritten.
	err = CreateSecret(p, []byte("two\n"))
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second CreateSecret = %v, want fs.ErrExist", err)
	}
	if got, _ := OpenSecret(p, Options{}); string(got) != "one\n" {
		t.Fatalf("file was overwritten: %q", got)
	}
	if err := ReplaceSecret(p, []byte("three\n")); err != nil {
		t.Fatalf("ReplaceSecret: %v", err)
	}
	if got, err := OpenSecret(p, Options{}); err != nil || string(got) != "three\n" {
		t.Fatalf("after replace = %q, %v", got, err)
	}
	ents, _ := os.ReadDir(d)
	if len(ents) != 1 {
		t.Fatalf("temp file left behind: %v", ents)
	}
}

func TestOpenMissing(t *testing.T) {
	_, err := OpenSecret(filepath.Join(keyDir(t), "nope.key"), Options{})
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want fs.ErrNotExist", err)
	}
}

func TestSizeLimit(t *testing.T) {
	d := keyDir(t)
	p := filepath.Join(d, "big.key")
	if err := CreateSecret(p, bytes.Repeat([]byte("x"), 129)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSecret(p, Options{MaxSize: 128}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("129 bytes with limit 128: err = %v, want ErrTooLarge", err)
	}
	if _, err := OpenSecret(p, Options{MaxSize: 129}); err != nil {
		t.Fatalf("129 bytes with limit 129: %v", err)
	}
	if got := (Options{}).maxSize(); got != DefaultMaxSize {
		t.Fatalf("default max size = %d", got)
	}
}

func TestCreateNeedsParent(t *testing.T) {
	err := CreateSecret(filepath.Join(t.TempDir(), "missing", "a.key"), []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("err = %v, want 'does not exist'", err)
	}
	err = ReplaceSecret(filepath.Join(t.TempDir(), "missing", "a.key"), []byte("x"))
	if err == nil {
		t.Fatal("ReplaceSecret without a parent succeeded")
	}
}

func TestEnsureDir(t *testing.T) {
	d := filepath.Join(secureTemp(t), "a", "b", "keys")
	if err := EnsureDir(d); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
		t.Fatalf("not created: %v", err)
	}
	if err := EnsureDir(d); err != nil { // idempotent
		t.Fatalf("EnsureDir again: %v", err)
	}
	if err := CheckDir(filepath.Join(d, "missing")); err == nil {
		t.Fatal("CheckDir of a missing dir succeeded")
	}
	f := filepath.Join(d, "file")
	if err := CreateSecret(f, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(f); err == nil {
		t.Fatal("EnsureDir over a file succeeded")
	}
}

func TestOptionsWarn(t *testing.T) {
	var got string
	Options{Warn: func(s string) { got = s }}.warn("hi")
	Options{}.warn("ignored") // nil Warn is fine
	if got != "hi" {
		t.Fatalf("warn = %q", got)
	}
}
