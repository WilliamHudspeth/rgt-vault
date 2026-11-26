package providers

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestLiveKeyring runs the KeyringProvider against the REAL OS keyring (Secret
// Service / macOS Keychain / Windows Credential Manager). It is opt-in
// (RGT_TEST_REAL_KEYRING=1) because CI runners need a keyring daemon; it uses
// a unique throw-away service name and cleans up after itself.
func TestLiveKeyring(t *testing.T) {
	if os.Getenv("RGT_TEST_REAL_KEYRING") != "1" {
		t.Skip("set RGT_TEST_REAL_KEYRING=1 to test against the real OS keyring")
	}
	service := fmt.Sprintf("rgt_vault_test_%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupLiveKeyring(service, "master_key") })

	p := NewKeyringProvider(service, "master_key")
	if _, err := p.GetMasterSecret(); err == nil {
		t.Fatal("fresh service must have no secret")
	}
	if err := p.BootstrapMasterSecret(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	first, err := p.GetMasterSecret()
	if err != nil || len(first) != 32 {
		t.Fatalf("get: %x %v", first, err)
	}
	again, _ := p.InitializeIfMissing()
	if !bytes.Equal(first, again) {
		t.Fatal("InitializeIfMissing replaced an existing secret")
	}
	rotated, err := p.RotateMasterSecret()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := p.GetMasterSecret(); !bytes.Equal(got, rotated) {
		t.Fatal("rotated secret not persisted")
	}
}
