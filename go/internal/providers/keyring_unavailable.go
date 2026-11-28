package providers

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
)

// ErrKeyringUnavailable means the OS keyring cannot be reached at all here
// (no Secret Service on the session D-Bus, no session bus, no logon session
// on Windows, a locked/non-interactive macOS Keychain). It is different from
// "no entry", which is [ErrMasterSecretUnavailable].
var ErrKeyringUnavailable = errors.New("no OS keyring is available here")

// keyringUnavailableMarkers are substrings of the backend errors that mean
// "unreachable". The Linux markers are verified (go-keyring with no Secret
// Service / no bus); the Windows and macOS ones are UNVERIFIED on real hosts
// (the macOS backend reports only the tool's exit status, RGT-371).
var keyringUnavailableMarkers = []string{
	"org.freedesktop.secrets",                // Secret Service not provided by any .service files
	"was not provided by any .service files", // same, other wording
	"dbus_session_bus_address",               // no session bus
	"dbus-launch",                            // autolaunch failed
	"/bus: connect",                          // $XDG_RUNTIME_DIR/bus missing
	"connect: no such file or directory",     // bus socket missing
	"logon session does not exist",           // Windows ERROR_NO_SUCH_LOGON_SESSION (1312)
	"user interaction is not allowed",        // macOS errSecInteractionNotAllowed
}

// IsKeyringUnavailable reports whether err means the OS keyring cannot be
// reached (as opposed to a missing entry or a decoding error).
func IsKeyringUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrKeyringUnavailable) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, m := range keyringUnavailableMarkers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

// classifyKeyringError wraps an unreachable-keyring error with
// [ErrKeyringUnavailable]; other errors are returned unchanged.
func classifyKeyringError(err error) error {
	if err != nil && !errors.Is(err, ErrKeyringUnavailable) && IsKeyringUnavailable(err) {
		return fmt.Errorf("%w (%s): %w", ErrKeyringUnavailable, KeyringBackendName(), err)
	}
	return err
}

// KeyringBackendName names the OS keyring of this platform.
func KeyringBackendName() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows Credential Manager"
	case "darwin":
		return "macOS login Keychain"
	}
	return "Secret Service on the session D-Bus"
}

// Probe checks that the keyring can be reached (a missing entry is fine: a
// new vault creates it). An unreachable keyring wraps [ErrKeyringUnavailable].
func (p *KeyringProvider) Probe() error {
	_, err := keyringGet(p.Service, p.User)
	if err == nil || errors.Is(err, errKeyNotFound) {
		return nil
	}
	return fmt.Errorf("read OS keyring entry %q/%q: %w", p.Service, p.User, classifyKeyringError(err))
}

// Location names the keyring entry (never the secret).
func (p *KeyringProvider) Location() string {
	return fmt.Sprintf("%s, service %q account %q", KeyringBackendName(), p.Service, p.User)
}
