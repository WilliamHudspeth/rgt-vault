//go:build windows

package providers

import (
	"bytes"
	"path/filepath"
	"testing"
)

// Real CryptProtectData/CryptUnprotectData round trip (flags=4).
func TestDPAPIRealRoundTrip(t *testing.T) {
	secret := seq32()
	path := filepath.Join(t.TempDir(), "sealed.bin")
	if err := SealDPAPI(secret, path, nil); err != nil {
		t.Fatal(err)
	}
	p, err := NewDPAPIProvider(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.GetMasterSecret()
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("round trip: %x %v", got, err)
	}
}

func TestDPAPIRealEntropy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sealed.bin")
	if err := SealDPAPI([]byte("s3cret"), path, []byte("pepper")); err != nil {
		t.Fatal(err)
	}
	good, _ := NewDPAPIProvider(path, []byte("pepper"))
	if got, err := good.GetMasterSecret(); err != nil || string(got) != "s3cret" {
		t.Fatalf("%q %v", got, err)
	}
	bad, _ := NewDPAPIProvider(path, []byte("wrong"))
	if _, err := bad.GetMasterSecret(); err == nil {
		t.Fatal("wrong entropy must fail")
	}
	none, _ := NewDPAPIProvider(path, nil)
	if _, err := none.GetMasterSecret(); err == nil {
		t.Fatal("missing entropy must fail")
	}
}

func TestDPAPIRealRotate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sealed.bin")
	if err := SealDPAPI([]byte("old"), path, nil); err != nil {
		t.Fatal(err)
	}
	p, _ := NewDPAPIProvider(path, nil)
	nw, err := p.RotateMasterSecret()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := p.GetMasterSecret(); !bytes.Equal(got, nw) {
		t.Fatal("rotate did not persist")
	}
}

func TestDPAPIRealGarbageBlob(t *testing.T) {
	if _, err := platformDPAPIUnprotect([]byte("not a dpapi blob"), nil); err == nil {
		t.Fatal("garbage must fail")
	}
}
