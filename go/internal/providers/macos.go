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
	macOSSecurityTool = "/usr/bin/security" // absolute: never resolved through $PATH
	// securityItemNotFound is `security`'s exit status for errSecItemNotFound.
	securityItemNotFound = 44
	// securityMaxCommand mirrors the 4096-byte limit of `security -i` lines.
	securityMaxCommand = 4095 // fgets(buf, 4096) in security -i, minus the NUL
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
	secret, err := securityFind(context.Background(), p.run, p.Service, p.Account)
	if err != nil {
		reason := describeRunError(err)
		if errors.Is(err, errKeyNotFound) {
			reason = "item not found in keychain"
		}
		return nil, fmt.Errorf("%w: failed to read keychain item %q/%q: %s", ErrMasterSecretUnavailable, p.Service, p.Account, reason)
	}
	if secret == "" {
		return nil, fmt.Errorf("%w: keychain item exists but password is empty", ErrMasterSecretUnavailable)
	}
	return []byte(secret), nil
}

// securityFind runs `security find-generic-password -s S -a A -w` and returns
// the stripped password. errKeyNotFound means errSecItemNotFound (exit 44).
func securityFind(ctx context.Context, run Runner, service, account string) (string, error) {
	out, err := run(ctx, macOSSecurityTool,
		[]string{"find-generic-password", "-s", service, "-a", account, "-w"}, nil)
	if err != nil {
		var ee *ExitError
		if errors.As(err, &ee) && ee.Code == securityItemNotFound {
			return "", errKeyNotFound
		}
		Wipe(out)
		return "", err
	}
	defer Wipe(out)
	secret := strings.TrimSpace(string(out))
	return secret, nil
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
	// The command is a single line parsed by security(1)'s own tokenizer, not
	// by a shell: refuse anything whose quoting we cannot guarantee (control
	// characters would end the line; quotes and backslashes are interpreted
	// differently by the tokenizer than by POSIX shells).
	for name, v := range map[string]string{"service": service, "account": account, "secret": string(secret)} {
		if err := checkSecurityToken(name, v); err != nil {
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
	stdin := []byte(line)
	defer Wipe(stdin)
	_, err := run(ctx, macOSSecurityTool, []string{"-i"}, stdin)
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

// checkSecurityToken rejects characters that would break out of the single
// line handed to `security -i`: control characters, and the quote and
// backslash characters whose handling differs between security(1) and POSIX.
func checkSecurityToken(name, v string) error {
	for i := 0; i < len(v); i++ {
		if c := v[i]; c < 0x20 || c == 0x7f || c == '\\' || c == '\'' || c == '"' || c == '`' {
			return fmt.Errorf("keychain %s contains a character that cannot be passed safely to security(1)", name)
		}
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
