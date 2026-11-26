//go:build darwin

package providers

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Live macOS Keychain test: seal through `security -i`, read back through
// find-generic-password. Opt-in (RGT_TEST_MACOS_KEYCHAIN=1) because it writes
// to the login keychain (a unique throw-away item, deleted afterwards).
func TestLiveMacOSKeychain(t *testing.T) {
	if os.Getenv("RGT_TEST_MACOS_KEYCHAIN") != "1" {
		t.Skip("set RGT_TEST_MACOS_KEYCHAIN=1 to test against the real login keychain")
	}
	service := fmt.Sprintf("rgt-vault-test-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_ = exec.Command("security", "delete-generic-password", "-s", service, "-a", "acct").Run()
	})
	const secret = "c2VjcmV0LXZhbHVlLTEyMw=="
	if err := SealMacOSKeychain([]byte(secret), service, "acct", false); err != nil {
		t.Fatal(err)
	}
	got, err := NewMacOSKeychainProvider(service, "acct").GetMasterSecret()
	if err != nil || string(got) != secret {
		t.Fatalf("got %q %v", got, err)
	}
	if err := SealMacOSKeychain([]byte("other"), service, "acct", false); err == nil {
		t.Fatal("seal without -U must not overwrite")
	}
	if err := SealMacOSKeychain([]byte("other"), service, "acct", true); err != nil {
		t.Fatal(err)
	}
	// The keyring provider must write a value Python keyring can read raw.
	kp := NewKeyringProvider(service+"-kr", "master_key")
	t.Cleanup(func() {
		_ = exec.Command("security", "delete-generic-password", "-s", service+"-kr", "-a", "master_key").Run()
	})
	raw, err := kp.RotateMasterSecret()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := exec.Command("security", "find-generic-password", "-s", service+"-kr", "-a", "master_key", "-w").Output()
	if len(out) == 0 || strings.HasPrefix(string(out), "go-keyring-base64:") {
		t.Fatalf("keyring value must be stored raw, got %q", out)
	}
	if got, err := kp.GetMasterSecret(); err != nil || len(got) != len(raw) {
		t.Fatalf("%v %v", got, err)
	}
}
