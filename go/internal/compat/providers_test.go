package compat

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"rgt-vault-server/internal/providers"
)

// fixedSecret is a throw-away 32-byte master secret.
func fixedSecret() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(0xA0 + i)
	}
	return b
}

// TestPythonDPAPIInterop (Windows only): Python seals the master secret with
// CryptProtectData (pywin32), Go unseals it with CryptUnprotectData, and the
// reverse, with and without entropy; a wrong entropy is refused by Go.
// Needs RGT_VAULT_PYTHON with `pip install -e '.[windows]'`.
func TestPythonDPAPIInterop(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("DPAPI exists on Windows only")
	}
	py := python(t)
	secret := fixedSecret()
	for _, ent := range [][]byte{nil, []byte("pepper-123")} {
		entHex := "-"
		if ent != nil {
			entHex = hex.EncodeToString(ent)
		}
		t.Run("entropy="+fmt.Sprint(ent != nil), func(t *testing.T) {
			dir := t.TempDir()

			// Python seals -> Go unseals.
			pyBlob := filepath.Join(dir, "py.blob")
			runPython(t, py, nil, "dpapi-seal", pyBlob, entHex, hex.EncodeToString(secret))
			p, err := providers.NewDPAPIProvider(pyBlob, ent)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := p.GetMasterSecret(); err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("Go unseal of Python's blob: %x, %v", got, err)
			}
			if ent != nil {
				bad, _ := providers.NewDPAPIProvider(pyBlob, []byte("wrong"))
				if _, err := bad.GetMasterSecret(); err == nil {
					t.Error("wrong entropy must be refused")
				}
			}

			// Go seals -> Python unseals.
			goBlob := filepath.Join(dir, "go.blob")
			if err := providers.SealDPAPI(secret, goBlob, ent); err != nil {
				t.Fatal(err)
			}
			if r := runPython(t, py, nil, "dpapi-unseal", goBlob, entHex, hex.EncodeToString(secret)); r["match"] != true {
				t.Fatalf("Python's unseal of Go's blob differs from the sealed secret: %v", r)
			}
		})
	}
}

// TestPythonMacOSKeychainInterop (macOS only): Python seals with
// `security add-generic-password`, Go reads it back, and the reverse.
func TestPythonMacOSKeychainInterop(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the macOS Keychain exists on macOS only")
	}
	py := python(t)
	const secret = "c2VjcmV0LXZhbHVlLTEyMw==" // the master secret is stored as text
	service := fmt.Sprintf("rgt-compat-%d", time.Now().UnixNano())
	for _, acct := range []string{"py-seals", "go-seals"} {
		t.Cleanup(func() { runPython(t, py, nil, "macos-delete", service, acct) })
	}

	runPython(t, py, nil, "macos-seal", service, "py-seals", secret)
	got, err := providers.NewMacOSKeychainProvider(service, "py-seals").GetMasterSecret()
	if err != nil || string(got) != secret {
		t.Fatalf("Go reads Python's keychain item as %q, %v", got, err)
	}

	if err := providers.SealMacOSKeychain([]byte(secret), service, "go-seals", false); err != nil {
		t.Fatal(err)
	}
	if r := runPython(t, py, nil, "macos-unseal", service, "go-seals", secret); r["match"] != true {
		t.Fatalf("Python's read of Go's keychain item differs from the sealed secret: %v", r)
	}
}

// TestPythonTPMInterop (Linux, tpm2-tools plus a TPM or a software TPM
// exposed through TPM2TOOLS_TCTI, e.g. swtpm): Python seals to a PCR policy,
// Go unseals it, and the reverse. Both sides use tpm2-tools' TCTI
// auto-discovery, so the one environment variable serves both.
func TestPythonTPMInterop(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the TPM provider is Linux-only")
	}
	if _, err := exec.LookPath("tpm2_createprimary"); err != nil {
		t.Skip("tpm2-tools not installed")
	}
	if os.Getenv("TPM2TOOLS_TCTI") == "" {
		t.Skip("set TPM2TOOLS_TCTI (e.g. swtpm:port=2321) to run against a software TPM")
	}
	py := python(t)
	secret := fixedSecret()

	pyDir := t.TempDir()
	r := runPython(t, py, nil, "tpm-seal", pyDir, hex.EncodeToString(secret))
	p, err := providers.NewTPMProvider(fmt.Sprint(r["priv"]), fmt.Sprint(r["pub"]))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p.GetMasterSecret(); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Go unseal of Python's TPM blob: %x, %v", got, err)
	}

	priv, pub, err := providers.SealTPM(secret, t.TempDir(), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if r := runPython(t, py, nil, "tpm-unseal", priv, pub, hex.EncodeToString(secret)); r["match"] != true {
		t.Fatalf("Python's unseal of Go's TPM blob differs from the sealed secret: %v", r)
	}
}
