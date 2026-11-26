package providers

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Defaults of python/providers/__init__.py for macOS.
const (
	DefaultMacOSService = "com.agentvault.master"
	DefaultMacOSAccount = "master-key"
)

const (
	macOSSecurityTool = "security"
	// securityItemNotFound is `security`'s exit status for errSecItemNotFound.
	securityItemNotFound = 44
	// securityMaxCommand mirrors the 4096-byte limit of `security -i` lines.
	securityMaxCommand = 4096
)

// MacOSKeychainProvider reads the master secret from a generic-password item
// of the macOS login keychain with `security find-generic-password -w`. The
// item's password is TEXT: its UTF-8 bytes are the master secret (Python:
// stdout.strip().encode("utf-8")).
type MacOSKeychainProvider struct {
	Service string
	Account string
	run     Runner
}

// NewMacOSKeychainProvider returns a provider for service/account; empty
// values fall back to the Python defaults.
func NewMacOSKeychainProvider(service, account string) *MacOSKeychainProvider {
	if service == "" {
		service = DefaultMacOSService
	}
	if account == "" {
		account = DefaultMacOSAccount
	}
	return &MacOSKeychainProvider{Service: service, Account: account, run: execRunner}
}

// GetMasterSecret runs `security find-generic-password -s S -a A -w`.
func (p *MacOSKeychainProvider) GetMasterSecret() ([]byte, error) {
	out, err := p.run(context.Background(), macOSSecurityTool,
		[]string{"find-generic-password", "-s", p.Service, "-a", p.Account, "-w"}, nil)
	if err != nil {
		var ee *ExitError
		reason := describeRunError(err)
		if errors.As(err, &ee) && ee.Code == securityItemNotFound {
			reason = "item not found in keychain"
		}
		return nil, fmt.Errorf("%w: failed to read keychain item %q/%q: %s", ErrMasterSecretUnavailable, p.Service, p.Account, reason)
	}
	secret := strings.TrimSpace(string(out))
	Wipe(out)
	if secret == "" {
		return nil, fmt.Errorf("%w: keychain item exists but password is empty", ErrMasterSecretUnavailable)
	}
	return []byte(secret), nil
}

// SealMacOSKeychain stores masterSecret as the password of the generic-password
// item service/account (Python: macos_keychain.seal_master_secret). With
// updatable the item is overwritten if it exists (-U).
//
// The secret must be printable ASCII text without leading/trailing spaces:
// macOS hex-encodes anything else on read, and GetMasterSecret strips outer
// whitespace. A base64 or hex string of random bytes is the intended form.
//
// Python's version passed the path of a temp file as the -w password, which
// stored the PATH instead of the secret; that defect is not ported. Here the
// command is fed to `security -i` on stdin, so the secret never appears in any
// process's argv.
func SealMacOSKeychain(masterSecret []byte, service, account string, updatable bool) error {
	return sealMacOS(context.Background(), execRunner, masterSecret, service, account, updatable, true)
}

func sealMacOS(ctx context.Context, run Runner, secret []byte, service, account string, updatable, validate bool) error {
	if validate {
		if err := checkMacOSSecret(secret); err != nil {
			return err
		}
	}
	if service == "" || account == "" {
		return errors.New("keychain service and account are required")
	}
	cmd := "add-generic-password"
	if updatable {
		cmd += " -U"
	}
	line := fmt.Sprintf("%s -s %s -a %s -w %s -T /usr/bin/security\n", cmd,
		shellQuote(service), shellQuote(account), shellQuote(string(secret)))
	if len(line) > securityMaxCommand {
		return errors.New("keychain item values are too large for security(1)")
	}
	_, err := run(ctx, macOSSecurityTool, []string{"-i"}, []byte(line))
	if err != nil {
		return fmt.Errorf("security add-generic-password failed: %s", describeRunError(err))
	}
	return nil
}

func checkMacOSSecret(secret []byte) error {
	if len(secret) == 0 {
		return errors.New("macOS keychain master secret is empty")
	}
	for _, b := range secret {
		if b < 0x20 || b > 0x7e {
			return errors.New("macOS keychain master secret must be printable ASCII text (e.g. base64 or hex)")
		}
	}
	if secret[0] == ' ' || secret[len(secret)-1] == ' ' {
		return errors.New("macOS keychain master secret must not start or end with a space")
	}
	return nil
}

// shellQuote quotes s for the POSIX-style parser of `security -i`.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("@%+=:,./-_", c) >= 0) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// SealMacOSKeychainWith is [SealMacOSKeychain] with an injected [Runner], for
// tests of other packages.
func SealMacOSKeychainWith(run Runner, masterSecret []byte, service, account string, updatable bool) error {
	return sealMacOS(context.Background(), run, masterSecret, service, account, updatable, true)
}
