//go:build linux

package providers

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

// Live TPM test, mirroring tests/test_tpm_live.py: seal and unseal with the
// real tpm2-tools against /dev/tpmrm0 (or a software TPM exposed through
// TPM2TOOLS_TCTI). Skipped unless the tools and a TPM are usable. Run as a
// member of the tss group, e.g.: sg tss -c "go test -run Live ./internal/providers".
func skipUnlessTPM(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("tpm2_createprimary"); err != nil {
		t.Skip("tpm2-tools not installed")
	}
	if os.Getenv("TPM2TOOLS_TCTI") == "" {
		f, err := os.OpenFile("/dev/tpmrm0", os.O_RDWR, 0)
		if err != nil {
			t.Skip("/dev/tpmrm0 not accessible (run as a member of the tss group)")
		}
		_ = f.Close()
	}
}

func TestLiveTPMSealUnseal(t *testing.T) {
	skipUnlessTPM(t)
	secret := seq32()
	priv, pub, err := SealTPM(secret, t.TempDir(), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewTPMProvider(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.GetMasterSecret()
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("unseal: %x %v", got, err)
	}
	nw, err := p.RotateMasterSecret()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p.GetMasterSecret(); err != nil || !bytes.Equal(got, nw) {
		t.Fatalf("after rotate: %x %v", got, err)
	}
}
