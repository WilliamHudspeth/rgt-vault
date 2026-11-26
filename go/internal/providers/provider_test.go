package providers

import (
	"errors"
	"testing"

	"rgt-vault-server/internal/providers/providerstest"
)

// Compile-time structural conformance (no import of the vault package).
var (
	_ MasterProvider = (*KeyringProvider)(nil)
	_ Rotator        = (*KeyringProvider)(nil)
	_ Bootstrapper   = (*KeyringProvider)(nil)
	_ MasterProvider = (*MacOSKeychainProvider)(nil)
	_ MasterProvider = (*DPAPIProvider)(nil)
	_ Rotator        = (*DPAPIProvider)(nil)
	_ MasterProvider = (*TPMProvider)(nil)
	_ Rotator        = (*TPMProvider)(nil)
	_ MasterProvider = (*providerstest.Memory)(nil)
	_ Rotator        = (*providerstest.Memory)(nil)
	_ Bootstrapper   = (*providerstest.Memory)(nil)
)

func TestCapabilityHelpers(t *testing.T) {
	mem := providerstest.NewMemory()
	if !CanRotate(mem) {
		t.Fatal("Memory should be rotatable")
	}
	old, _ := mem.GetMasterSecret()
	nw, err := Rotate(mem)
	if err != nil || len(nw) != MasterSecretSize || string(nw) == string(old) {
		t.Fatalf("Rotate: %v %x", err, nw)
	}
	if err := Bootstrap(mem); err != nil || mem.Bootstraps != 1 {
		t.Fatalf("Bootstrap: %v %d", err, mem.Bootstraps)
	}

	ro := providerstest.Fixed{Secret: []byte("x")}
	if CanRotate(ro) {
		t.Fatal("read-only provider must not be rotatable")
	}
	if _, err := Rotate(ro); !errors.Is(err, ErrRotateNotSupported) {
		t.Fatalf("Rotate on read-only: %v", err)
	}
	if err := Bootstrap(ro); err != nil {
		t.Fatalf("Bootstrap on provider without the capability must be a no-op: %v", err)
	}
}

func TestWipe(t *testing.T) {
	b := []byte{1, 2, 3}
	Wipe(b)
	if b[0]|b[1]|b[2] != 0 {
		t.Fatalf("not wiped: %v", b)
	}
}
