package providers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Defaults of python/keychain.py KeyringProvider.
const (
	DefaultKeyringService = "rgt_vault"
	DefaultKeyringUser    = "master_key"
)

// errKeyNotFound is what every keyring backend returns for "no such entry".
var errKeyNotFound = errors.New("keyring entry not found")

// Keyring backend seams. The per-OS backend files (keyring_*.go) install the
// real implementations; tests replace them with fakes.
var (
	keyringGet = platformKeyringGet
	keyringSet = platformKeyringSet
)

// KeyringProvider keeps the master secret in the OS keyring (Secret Service,
// macOS Keychain or Windows Credential Manager) as urlsafe-base64 of 32 bytes
// under service "rgt_vault", user "master_key". It is the default CLI
// provider and is byte-compatible with Python's KeyringProvider.
type KeyringProvider struct {
	Service string
	User    string
}

// NewKeyringProvider returns a provider for service/user; empty values fall
// back to the Python defaults.
func NewKeyringProvider(service, user string) *KeyringProvider {
	if service == "" {
		service = DefaultKeyringService
	}
	if user == "" {
		user = DefaultKeyringUser
	}
	return &KeyringProvider{Service: service, User: user}
}

// GetMasterSecret reads and decodes the stored secret. A missing entry fails
// closed with [ErrMasterSecretUnavailable]; it never regenerates (Python
// P0-2: doing so would brick an existing vault).
func (p *KeyringProvider) GetMasterSecret() ([]byte, error) {
	encoded, err := keyringGet(p.Service, p.User)
	if err != nil {
		if errors.Is(err, errKeyNotFound) {
			return nil, p.missingError()
		}
		return nil, fmt.Errorf("read OS keyring entry %q/%q: %w", p.Service, p.User, classifyKeyringError(err))
	}
	if encoded == "" {
		return nil, p.missingError()
	}
	return decodeKeyringSecret(encoded)
}

func (p *KeyringProvider) missingError() error {
	return fmt.Errorf("%w: no master secret found in OS keyring under service %q / account %q. "+
		"Refusing to regenerate -- doing so would brick the vault. "+
		"If this is a fresh install, call InitializeIfMissing or pass an explicit master provider; "+
		"otherwise recover the keyring entry or re-seal the master secret with the platform provider",
		ErrMasterSecretUnavailable, p.Service, p.User)
}

// RotateMasterSecret generates a new 32-byte secret, stores it, and returns it.
func (p *KeyringProvider) RotateMasterSecret() ([]byte, error) {
	raw, err := newMasterSecret()
	if err != nil {
		return nil, err
	}
	if err := keyringSet(p.Service, p.User, base64.URLEncoding.EncodeToString(raw)); err != nil {
		Wipe(raw)
		return nil, fmt.Errorf("write OS keyring entry %q/%q: %w", p.Service, p.User, classifyKeyringError(err))
	}
	return raw, nil
}

// BootstrapMasterSecret implements [Bootstrapper].
func (p *KeyringProvider) BootstrapMasterSecret() error {
	secret, err := p.InitializeIfMissing()
	Wipe(secret)
	return err
}

// InitializeIfMissing creates a new master secret if and only if the keyring
// entry is missing, and returns the (existing or new) secret. A keyring error
// other than "not found" is returned as-is and nothing is created.
//
// Like Python, the get-then-set is not atomic: if two processes race, the
// last writer wins and the loser fails on its next DEK unwrap.
func (p *KeyringProvider) InitializeIfMissing() ([]byte, error) {
	existing, err := keyringGet(p.Service, p.User)
	switch {
	case err == nil && existing != "":
		return decodeKeyringSecret(existing)
	case err != nil && !errors.Is(err, errKeyNotFound):
		return nil, fmt.Errorf("read OS keyring entry %q/%q: %w", p.Service, p.User, classifyKeyringError(err))
	}
	return p.RotateMasterSecret()
}

// decodeKeyringSecret reproduces base64.urlsafe_b64decode(encoded + padding):
// both alphabets are accepted and missing "=" padding is tolerated (legacy
// Fernet keys were stored unpadded by some versions).
func decodeKeyringSecret(encoded string) ([]byte, error) {
	s := strings.TrimRight(strings.TrimSpace(encoded), "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) == 0 {
		// Do not include the stored value in the error.
		return nil, fmt.Errorf("%w: keyring entry is empty or not valid urlsafe-base64", ErrMasterSecretUnavailable)
	}
	return raw, nil
}
