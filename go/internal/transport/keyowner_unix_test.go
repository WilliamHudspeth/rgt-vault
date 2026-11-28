//go:build unix

package transport

import (
	"os"
	"strings"
	"testing"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/tlstest"
)

func TestOwnerAllowed(t *testing.T) {
	for _, c := range []struct {
		file, euid uint32
		ok         bool
	}{{1000, 1000, true}, {0, 1000, true}, {0, 0, true}, {1001, 1000, false}, {1000, 0, false}} {
		if got := ownerAllowed(c.file, c.euid); got != c.ok {
			t.Errorf("ownerAllowed(%d, %d) = %v", c.file, c.euid, got)
		}
	}
}

// Needs root to hand the file to another user; skipped otherwise.
func TestKeyOwnedByAnotherUserIsRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	ca := tlstest.NewCA(t)
	f := ca.Localhost(t, t.TempDir())
	if err := os.Chown(f.Key, 54321, -1); err != nil {
		t.Skip("cannot chown here:", err)
	}
	// root (euid 0) running the server must not use a key owned by someone else.
	if err := CheckKeyFile(f.Key); err == nil || !strings.Contains(err.Error(), "owned by uid 54321") {
		t.Errorf("foreign-owned key accepted: %v", err)
	}
}
