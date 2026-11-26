package providers

import (
	"os"
	"path/filepath"
	"testing"
)

func envMap(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestPlatformDarwinDefaultsAndEnv(t *testing.T) {
	p, err := platformProviderFor("darwin", envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	m := p.(*MacOSKeychainProvider)
	if m.Service != "com.agentvault.master" || m.Account != "master-key" {
		t.Fatalf("defaults: %+v", m)
	}
	p, _ = platformProviderFor("darwin", envMap(map[string]string{"VAULT_KEYCHAIN_SERVICE": "S", "VAULT_KEYCHAIN_ACCOUNT": "A"}))
	m = p.(*MacOSKeychainProvider)
	if m.Service != "S" || m.Account != "A" {
		t.Fatalf("env: %+v", m)
	}
}

func TestPlatformLinuxTPM(t *testing.T) {
	// Default paths do not exist in the test environment: Python raises
	// FileNotFoundError from the constructor, and so do we.
	if _, err := os.Stat(DefaultTPMPrivatePath); err != nil {
		if _, err := platformProviderFor("linux", envMap(nil)); err == nil {
			t.Fatal("expected missing default blob error")
		}
	}
	_, priv, pub := sealedFixture(t)
	p, err := platformProviderFor("linux", envMap(map[string]string{"VAULT_TPM_PRIV": priv, "VAULT_TPM_PUB": pub}))
	if err != nil {
		t.Fatal(err)
	}
	if tp := p.(*TPMProvider); tp.PrivatePath != priv || tp.PublicPath != pub {
		t.Fatalf("%+v", tp)
	}
	// Other Unixes take the TPM branch too ("Linux and others").
	if _, err := platformProviderFor("freebsd", envMap(map[string]string{"VAULT_TPM_PRIV": priv, "VAULT_TPM_PUB": pub})); err != nil {
		t.Fatal(err)
	}
}

func TestPlatformWindowsDPAPI(t *testing.T) {
	if _, err := platformProviderFor("windows", envMap(nil)); err == nil {
		if _, serr := os.Stat(DefaultDPAPIBlobPath); serr != nil {
			t.Fatal("default blob path should not exist here")
		}
	}
	blob := filepath.Join(t.TempDir(), "b.bin")
	_ = os.WriteFile(blob, []byte("QQ=="), 0o600)
	p, err := platformProviderFor("windows", envMap(map[string]string{"VAULT_DPAPI_BLOB": blob}))
	if err != nil || p.(*DPAPIProvider).BlobPath != blob {
		t.Fatalf("%v %v", p, err)
	}
	// A set-but-empty variable overrides the default (os.environ.get semantics).
	if _, err := platformProviderFor("windows", envMap(map[string]string{"VAULT_DPAPI_BLOB": ""})); err == nil {
		t.Fatal("empty override should fail on the empty path")
	}
}

func TestNewPlatformProviderRealEnv(t *testing.T) {
	_, priv, pub := sealedFixture(t)
	t.Setenv("VAULT_TPM_PRIV", priv)
	t.Setenv("VAULT_TPM_PUB", pub)
	t.Setenv("VAULT_KEYCHAIN_SERVICE", "svc")
	t.Setenv("VAULT_KEYCHAIN_ACCOUNT", "acct")
	blob := filepath.Join(t.TempDir(), "b.bin")
	_ = os.WriteFile(blob, []byte("QQ=="), 0o600)
	t.Setenv("VAULT_DPAPI_BLOB", blob)
	if p, err := NewPlatformProvider(); err != nil || p == nil {
		t.Fatalf("%v %v", p, err)
	}
}
