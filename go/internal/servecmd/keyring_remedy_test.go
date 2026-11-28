package servecmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers"
)

func TestKeyringRemedyText(t *testing.T) {
	cause := errors.New("The name org.freedesktop.secrets was not provided by any .service files")
	for goos, want := range map[string][]string{
		"linux":   {"no Secret Service on the session D-Bus", "provider seal tpm", "docs/guides/providers.md#systemd", "(mode 0600)"},
		"windows": {"Windows Credential Manager", "provider seal dpapi", "VAULT_DPAPI_BLOB=FILE", "owner-only ACL"},
		"darwin":  {"macOS login Keychain", "security unlock-keychain"},
	} {
		e := &KeyringRemedyError{Init: true, NothingCreated: true, Cause: cause, goos: goos}
		msg := e.Error()
		first := strings.Index(msg, "1. Key file")
		if first < 0 || !strings.Contains(msg, "rgt-vault init --provider file") || !strings.HasSuffix(msg, "No files were created.") {
			t.Errorf("%s:\n%s", goos, msg)
		}
		for _, w := range want {
			if !strings.Contains(msg, w) {
				t.Errorf("%s: missing %q in:\n%s", goos, w, msg)
			}
		}
		if goos == "darwin" && strings.Contains(msg, "  3. ") {
			t.Errorf("darwin has no hardened option 3:\n%s", msg)
		}
		if !errors.Is(e, cause) {
			t.Error("Unwrap")
		}
		open := (&KeyringRemedyError{Cause: cause, goos: goos}).Error()
		if !strings.Contains(open, "provider seal file --from-keyring") || strings.Contains(open, "No files were created") {
			t.Errorf("%s open variant:\n%s", goos, open)
		}
	}
}

func TestWithKeyringRemedy(t *testing.T) {
	if WithKeyringRemedy(nil) != nil {
		t.Fatal("nil")
	}
	plain := errors.New("boom")
	if WithKeyringRemedy(plain) != plain {
		t.Fatal("unrelated error rewritten")
	}
	var re *KeyringRemedyError
	if err := WithKeyringRemedy(providers.ErrKeyringUnavailable); !errors.As(err, &re) || re.Init {
		t.Fatalf("got %v", err)
	}
}

func TestResolveFileProvider(t *testing.T) {
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	v := &VaultFlags{Provider: "file"}
	r, err := v.Resolve(get(map[string]string{providers.EnvMasterKeyFile: "/k/master.key"}))
	if err != nil || r.MasterKeyFile != "/k/master.key" || r.ProviderOptions().MasterKeyFile != "/k/master.key" {
		t.Fatalf("env path: %+v %v", r, err)
	}
	v.MasterKeyFile = "/flag.key"
	if r, _ := v.Resolve(get(map[string]string{providers.EnvMasterKeyFile: "/env.key"})); r.MasterKeyFile != "/flag.key" {
		t.Fatalf("flag must win: %q", r.MasterKeyFile)
	}
	// The env var is ignored for other providers; the flag is an error.
	r, err = (&VaultFlags{}).Resolve(get(map[string]string{providers.EnvMasterKeyFile: "/env.key"}))
	if err != nil || r.MasterKeyFile != "" {
		t.Fatalf("keyring with env path: %+v %v", r, err)
	}
	if _, err := (&VaultFlags{Provider: "platform", MasterKeyFile: "/x"}).Resolve(get(nil)); err == nil {
		t.Fatal("--master-key-file accepted with --provider platform")
	}
}
