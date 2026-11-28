//go:build unix

package captoken

import (
	"crypto/x509"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestOwnerAllowed(t *testing.T) {
	if !ownerAllowed(1000, 1000) || !ownerAllowed(0, 1000) || ownerAllowed(1001, 1000) {
		t.Fatal("owner rule")
	}
}

// TestKeyFileForeignOwnerRefused pretends the process runs as another uid,
// so the test's own files look foreign-owned.
func TestKeyFileForeignOwnerRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("files created by root are root-owned, which is allowed")
	}
	priv := testSeed("owner")
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pubDER, _ := x509.MarshalPKIXPublicKey(priv.Public())
	privPath := writeKey(t, "priv", pemOf(t, "PRIVATE KEY", der), 0o600)
	pubPath := writeKey(t, "pub", pemOf(t, "PUBLIC KEY", pubDER), 0o644)
	if _, err := LoadEd25519PrivateKeyFile(privPath); err != nil {
		t.Fatalf("own file: %v", err)
	}
	real := geteuid
	geteuid = func() int { return real() + 1 }
	t.Cleanup(func() { geteuid = real })
	if _, err := LoadEd25519PrivateKeyFile(privPath); !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("private: %v", err)
	}
	if _, err := LoadEd25519PublicKeyFile(pubPath); !errors.Is(err, ErrValidation) || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("public: %v", err)
	}
}
