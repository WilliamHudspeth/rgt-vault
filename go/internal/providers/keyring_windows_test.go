//go:build windows

package providers

import (
	"fmt"
	"testing"
	"time"

	"github.com/danieljoos/wincred"
)

// TestWinVaultOnRealCredentialManager checks the Python-keyring (WinVault)
// convention against the real Credential Manager. Python's behaviour is
// reproduced from keyring 25.7 source (winvault.go); this test is the part
// that could not be run by the author on Windows and is the compat check the
// plan asked for: entries written here must be readable by Python
// keyring.get_password(service, user) and vice versa.
func TestWinVaultOnRealCredentialManager(t *testing.T) {
	service := fmt.Sprintf("rgt_vault_wintest_%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupLiveKeyring(service, "master_key"); cleanupLiveKeyring(service, "other") })

	if err := platformKeyringSet(service, "master_key", "AAECAw=="); err != nil {
		t.Fatal(err)
	}
	// Python's layout: TargetName == service, UserName == user, UTF-16LE blob.
	c, err := wincred.GetGenericCredential(service)
	if err != nil {
		t.Fatalf("entry must live under the bare service name: %v", err)
	}
	if c.UserName != "master_key" || string(c.CredentialBlob) != string(encodeWinBlob("AAECAw==")) {
		t.Fatalf("unexpected credential layout: user=%q blob=%x", c.UserName, c.CredentialBlob)
	}
	if v, err := platformKeyringGet(service, "master_key"); err != nil || v != "AAECAw==" {
		t.Fatalf("get: %q %v", v, err)
	}

	// A second user collides: the first entry moves to "<user>@<service>".
	if err := platformKeyringSet(service, "other", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := wincred.GetGenericCredential("master_key@" + service); err != nil {
		t.Fatalf("collision must preserve the old entry under the compound target: %v", err)
	}
	if v, _ := platformKeyringGet(service, "master_key"); v != "AAECAw==" {
		t.Fatalf("compound lookup: %q", v)
	}

	if _, err := platformKeyringGet(service+"-missing", "nobody"); err != errKeyNotFound {
		t.Fatalf("missing: %v", err)
	}
}
