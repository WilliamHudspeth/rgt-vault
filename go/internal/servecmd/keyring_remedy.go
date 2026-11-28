package servecmd

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers"
)

// KeyringRemedyError is returned when the OS keyring cannot be reached. Its
// message says what to do (docs/design/file-provider.md, 5.4).
type KeyringRemedyError struct {
	// Init selects the `rgt-vault init` wording (choose a provider for a NEW
	// vault); otherwise the wording is for opening an existing vault.
	Init bool
	// NothingCreated appends "No files were created." (init only).
	NothingCreated bool
	// Cause is the keyring error.
	Cause error
	goos  string
}

func (e *KeyringRemedyError) Unwrap() error { return e.Cause }

func (e *KeyringRemedyError) Error() string {
	goos := e.goos
	if goos == "" {
		goos = runtime.GOOS
	}
	var b strings.Builder
	why, keyring, mode := "no Secret Service on the session D-Bus", "start and unlock a Secret Service (GNOME Keyring, KWallet, KeePassXC)", "mode 0600"
	switch goos {
	case "windows":
		why = "the Windows Credential Manager is not available in this logon session"
		keyring = "run rgt-vault in an interactive logon session with a loaded user profile (not as a service account)"
		mode = "owner-only ACL"
	case "darwin":
		why = "the macOS login Keychain is locked or not available to this session"
		keyring = "unlock the login Keychain (security unlock-keychain) or run from a logged-in session"
	}
	fmt.Fprintf(&b, "no OS keyring is available here (%s).\n", why)
	if !e.Init {
		b.WriteString("This vault's master key is read from the OS keyring (--provider keyring, the default). Either:\n\n")
		fmt.Fprintf(&b, "  - make the keyring reachable: %s, then re-run; or\n", keyring)
		b.WriteString("  - if the key is in a key file, pass --provider file [--master-key-file PATH]; or\n")
		b.WriteString("  - move the key to a file from a session where the keyring works:\n")
		b.WriteString("      rgt-vault provider seal file --from-keyring --out PATH\n")
		b.WriteString("    then use --provider file --master-key-file PATH (docs/guides/providers.md).")
		return b.String()
	}
	b.WriteString("rgt-vault keeps the vault's master key in a provider. Choose one:\n\n")
	b.WriteString("  1. Key file (works on any machine; recommended for servers and headless hosts):\n")
	b.WriteString("       rgt-vault init --provider file\n")
	fmt.Fprintf(&b, "     The key goes to ~/.config/rgt-vault/keys/<vault-id>.key (%s). Anyone who can read that file\n", mode)
	b.WriteString("     and the vault can open the vault: keep it out of backups of ~/.secure-vault.")
	if goos == "linux" {
		b.WriteString(" Under systemd, encrypt it\n     at rest with systemd-creds (TPM2 or host key): docs/guides/providers.md#systemd")
	}
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "  2. A desktop keyring: %s, then re-run init.\n", keyring)
	switch goos {
	case "windows":
		b.WriteString("\n  3. DPAPI (Windows, hardened): rgt-vault provider seal dpapi --generate --out FILE, then\n")
		b.WriteString("       " + providers.EnvDPAPIBlob + "=FILE rgt-vault init --provider platform\n")
	case "darwin":
	default:
		b.WriteString("\n  3. TPM 2.0 (Linux, hardened): rgt-vault provider seal tpm --generate --out-dir DIR, then\n")
		b.WriteString("       VAULT_TPM_PRIV=DIR/master_secret.priv VAULT_TPM_PUB=DIR/master_secret.pub rgt-vault init --provider platform\n")
	}
	if e.NothingCreated {
		b.WriteString("\nNo files were created.")
	}
	return strings.TrimRight(b.String(), "\n")
}

// WithKeyringRemedy replaces an unreachable-keyring error by a
// [KeyringRemedyError] for opening an existing vault; other errors are
// returned unchanged.
func WithKeyringRemedy(err error) error {
	if err == nil || !providers.IsKeyringUnavailable(err) {
		return err
	}
	return &KeyringRemedyError{Cause: err}
}
