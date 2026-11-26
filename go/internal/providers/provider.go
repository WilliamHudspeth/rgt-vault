// Package providers supplies the root-of-trust master secret to the vault.
//
// It is the Go port of python/keychain.py (KeyringProvider) and
// python/providers/* (macOS Keychain, Windows DPAPI, Linux TPM 2.0), plus the
// "seal" helpers that provision those backends.
//
// The package deliberately does not import the vault package. The vault
// consumes providers structurally through [MasterProvider] and the optional
// [Rotator] and [Bootstrapper] interfaces, mirroring the duck-typed protocol
// that python/vault.py uses (getattr(provider, "rotate_secret"),
// getattr(provider, "bootstrap_master_secret")).
//
// Security notes:
//   - Providers never shell out: external tools are started with an argv
//     slice through the [Runner] seam, never through a shell.
//   - Errors never echo the stdout/stderr of external tools (RGT-371); they
//     carry the tool name and exit status only.
//   - The only use of package unsafe is dpapi_windows.go (Windows syscall
//     buffer handling); see the memory-safety documentation for the allowlist.
package providers

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// MasterSecretSize is the length in bytes of a freshly generated master
// secret (os.urandom(32) in Python).
const MasterSecretSize = 32

var (
	// ErrMasterSecretUnavailable means the backing store holds no usable
	// master secret. Callers must fail closed: regenerating a secret would
	// make an existing vault permanently unreadable (Python P0-2).
	ErrMasterSecretUnavailable = errors.New("master secret unavailable")

	// ErrRotateNotSupported is returned when a provider cannot rotate the
	// master secret automatically (it must be re-sealed out-of-band).
	ErrRotateNotSupported = errors.New("provider does not support automated master-key rotation")

	// ErrUnsupportedPlatform is returned by a provider whose backend only
	// exists on another operating system (for example DPAPI off Windows).
	ErrUnsupportedPlatform = errors.New("provider is not supported on this platform")

	// ErrTPM wraps every failure of the tpm2-tools sequence.
	ErrTPM = errors.New("TPM operation failed")
)

// MasterProvider is the source of the root-of-trust master secret. It is the
// only method the vault needs on every provider. The returned slice is owned
// by the caller, who should wipe it with [Wipe] once the keys are derived.
type MasterProvider interface {
	GetMasterSecret() ([]byte, error)
}

// Rotator is implemented by providers that can generate and persist a new
// master secret (Python: rotate_secret). The new secret is returned.
type Rotator interface {
	RotateMasterSecret() ([]byte, error)
}

// Bootstrapper is implemented by providers that can create the master secret
// on first use if, and only if, none exists (Python: bootstrap_master_secret).
// The vault calls it only when no keychain.json exists yet.
type Bootstrapper interface {
	BootstrapMasterSecret() error
}

// CanRotate reports whether p supports automated master-key rotation. The
// vault must check this BEFORE bumping the key epoch (Python P1-4), so a
// provider that cannot rotate leaves the vault untouched.
func CanRotate(p MasterProvider) bool {
	_, ok := p.(Rotator)
	return ok
}

// Rotate rotates the master secret of p, or returns [ErrRotateNotSupported].
func Rotate(p MasterProvider) ([]byte, error) {
	r, ok := p.(Rotator)
	if !ok {
		return nil, fmt.Errorf("%w: %T: re-seal the master secret out-of-band and use RotateDEK instead", ErrRotateNotSupported, p)
	}
	return r.RotateMasterSecret()
}

// Bootstrap calls BootstrapMasterSecret when p implements [Bootstrapper] and
// is a no-op otherwise (Python's base-class default).
func Bootstrap(p MasterProvider) error {
	if b, ok := p.(Bootstrapper); ok {
		return b.BootstrapMasterSecret()
	}
	return nil
}

// Wipe overwrites b with zeros. It is best-effort hygiene for secret buffers.
func Wipe(b []byte) {
	clear(b)
}

// newMasterSecret returns MasterSecretSize random bytes from the OS CSPRNG.
func newMasterSecret() ([]byte, error) {
	b := make([]byte, MasterSecretSize)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate master secret: %w", err)
	}
	return b, nil
}
