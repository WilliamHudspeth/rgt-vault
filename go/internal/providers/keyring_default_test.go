//go:build !windows && !darwin

package providers

import (
	"bytes"
	"errors"
	"testing"

	"github.com/zalando/go-keyring"
)

// Exercises the real go-keyring wiring against go-keyring's in-memory mock.
func TestGoKeyringBackendWiring(t *testing.T) {
	keyring.MockInit()
	if _, err := platformKeyringGet("svc", "u"); !errors.Is(err, errKeyNotFound) {
		t.Fatalf("missing entry must map to errKeyNotFound, got %v", err)
	}
	if err := platformKeyringSet("svc", "u", "v"); err != nil {
		t.Fatal(err)
	}
	if v, err := platformKeyringGet("svc", "u"); err != nil || v != "v" {
		t.Fatalf("%q %v", v, err)
	}

	keyring.MockInitWithError(errors.New("no secret service"))
	if _, err := platformKeyringGet("svc", "u"); err == nil || errors.Is(err, errKeyNotFound) {
		t.Fatalf("backend failure must not look like a missing entry: %v", err)
	}
}

func TestKeyringProviderEndToEndOnMock(t *testing.T) {
	keyring.MockInit()
	p := NewKeyringProvider("", "")
	if _, err := p.GetMasterSecret(); !errors.Is(err, ErrMasterSecretUnavailable) {
		t.Fatalf("fresh keyring must fail closed: %v", err)
	}
	if err := Bootstrap(p); err != nil {
		t.Fatal(err)
	}
	a, err := p.GetMasterSecret()
	if err != nil || len(a) != 32 {
		t.Fatalf("%x %v", a, err)
	}
	// A value written the way Python keyring does is readable as-is.
	if err := keyring.Set("rgt_vault", "master_key", pyVector); err != nil {
		t.Fatal(err)
	}
	if got, err := p.GetMasterSecret(); err != nil || !bytes.Equal(got, seq32()) {
		t.Fatalf("python-written value: %x %v", got, err)
	}
	b, err := Rotate(p)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := p.GetMasterSecret(); !bytes.Equal(got, b) {
		t.Fatal("rotated secret not stored")
	}
}
