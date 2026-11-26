package providerstest

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMemory(t *testing.T) {
	m := NewMemory()
	a, err := m.GetMasterSecret()
	if err != nil || len(a) != 32 {
		t.Fatal(a, err)
	}
	a[0] ^= 0xff // callers get a copy
	b, _ := m.GetMasterSecret()
	if bytes.Equal(a, b) {
		t.Fatal("Get must return a copy")
	}
	n, err := m.RotateMasterSecret()
	c, _ := m.GetMasterSecret()
	if err != nil || !bytes.Equal(n, c) || bytes.Equal(n, b) {
		t.Fatal("rotate must change the secret")
	}
	if err := m.BootstrapMasterSecret(); err != nil || !m.BootstrapOK {
		t.Fatal("bootstrap")
	}
	if m.Gets != 3 || m.Rotations != 1 || m.Bootstraps != 1 {
		t.Fatalf("counters %d %d %d", m.Gets, m.Rotations, m.Bootstraps)
	}
	boom := errors.New("boom")
	m.GetErr, m.RotateErr = boom, boom
	if _, err := m.GetMasterSecret(); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if _, err := m.RotateMasterSecret(); !errors.Is(err, boom) {
		t.Fatal(err)
	}
}

func TestMemoryFixedAndFixed(t *testing.T) {
	src := []byte("0123456789abcdef0123456789abcdef")
	m := NewMemoryFixed(src)
	src[0] = 'X'
	got, _ := m.GetMasterSecret()
	if got[0] != '0' {
		t.Fatal("constructor must copy")
	}
	f := Fixed{Secret: []byte("abc")}
	if g, err := f.GetMasterSecret(); err != nil || string(g) != "abc" {
		t.Fatal(g, err)
	}
}

func TestFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "master.bin")
	f := File{Path: p}
	if _, err := f.GetMasterSecret(); err == nil {
		t.Fatal("missing file")
	}
	_ = os.WriteFile(p, nil, 0o600)
	if _, err := f.GetMasterSecret(); err == nil {
		t.Fatal("empty file")
	}
	_ = os.WriteFile(p, []byte("sekrit"), 0o600)
	if g, err := f.GetMasterSecret(); err != nil || string(g) != "sekrit" {
		t.Fatal(g, err)
	}
	n, err := f.RotateMasterSecret()
	g, _ := f.GetMasterSecret()
	if err != nil || len(n) != 32 || !bytes.Equal(n, g) {
		t.Fatal(n, err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	bad := File{Path: filepath.Join(t.TempDir(), "no", "dir")}
	if _, err := bad.RotateMasterSecret(); err == nil {
		t.Fatal("rotate into missing dir")
	}
}
