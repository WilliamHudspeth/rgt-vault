package providers

import (
	"fmt"
	"os"
	"runtime"
)

// Environment variables read by [NewPlatformProvider] (python/providers/__init__.py).
const (
	EnvDPAPIBlob       = "VAULT_DPAPI_BLOB"
	EnvKeychainService = "VAULT_KEYCHAIN_SERVICE"
	EnvKeychainAccount = "VAULT_KEYCHAIN_ACCOUNT"
	EnvTPMPrivate      = "VAULT_TPM_PRIV"
	EnvTPMPublic       = "VAULT_TPM_PUB"
)

// NewPlatformProvider returns the platform master-secret provider for the
// current OS, configured from the environment: DPAPI on Windows, the macOS
// Keychain on darwin, the TPM everywhere else (create_platform_provider).
func NewPlatformProvider() (MasterProvider, error) {
	return platformProviderFor(runtime.GOOS, os.LookupEnv)
}

// platformProviderFor is the testable core of [NewPlatformProvider].
func platformProviderFor(goos string, lookup func(string) (string, bool)) (MasterProvider, error) {
	env := func(key, def string) string {
		// Like os.environ.get, a set-but-empty variable wins over the default.
		if v, ok := lookup(key); ok {
			return v
		}
		return def
	}
	switch goos {
	case "windows":
		p, err := NewDPAPIProvider(env(EnvDPAPIBlob, DefaultDPAPIBlobPath), nil)
		if err != nil {
			return nil, fmt.Errorf("platform provider: %w", err)
		}
		return p, nil
	case "darwin":
		return NewMacOSKeychainProvider(
			env(EnvKeychainService, DefaultMacOSService),
			env(EnvKeychainAccount, DefaultMacOSAccount)), nil
	default:
		p, err := NewTPMProvider(env(EnvTPMPrivate, DefaultTPMPrivatePath), env(EnvTPMPublic, DefaultTPMPublicPath))
		if err != nil {
			return nil, fmt.Errorf("platform provider: %w", err)
		}
		return p, nil
	}
}
