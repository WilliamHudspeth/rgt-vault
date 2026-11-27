package vault

import (
	"errors"
	"fmt"

	"rgt-vault-server/internal/store"
	"rgt-vault-server/internal/validation"
)

// Sentinel errors. Every error returned by this package can be matched with
// errors.Is against the sentinels below; its Error() text is the message
// Python raises in the same situation.
var (
	// ErrValidation is a rejected argument (Python ValidationError). It is
	// the validation package's sentinel, so errors from either package match.
	ErrValidation = validation.ErrValidation

	// ErrPolicyDenied is Python's PolicyDeniedError: the hook, the ABAC policy
	// or the approval gate refused the operation.
	ErrPolicyDenied = errors.New("vault: policy denied")

	// ErrPermission is Python's PermissionError (rate limit, honeytoken).
	ErrPermission = errors.New("vault: permission denied")
	// ErrRateLimited is a rate-limit refusal; it also matches ErrPermission.
	ErrRateLimited = errors.New("vault: rate limit exceeded")
	// ErrHoneytoken is a honeytoken access; it also matches ErrPermission.
	ErrHoneytoken = errors.New("vault: honeytoken access detected")

	// ErrNotFound is Python's SecretNotFoundError. It also matches
	// store.ErrNotFound.
	ErrNotFound = errors.New("vault: secret not found")

	// ErrRotateNotSupported is Python's RotateNotSupportedError: the master
	// provider cannot rotate its secret automatically.
	ErrRotateNotSupported = errors.New("vault: master-key rotation not supported by provider")

	// ErrUnsupportedDEKVersion is a row whose dek_version is not 1. It also
	// matches ErrValidation (Python raises ValidationError).
	ErrUnsupportedDEKVersion = errors.New("vault: unsupported DEK version")

	// ErrLegacyVault means the database holds legacy Fernet secrets
	// (dek_version 0), which the Go line does not migrate (decision D3).
	ErrLegacyVault = errors.New("vault: legacy Fernet vault")

	// ErrKeychainMissing means keychain.json is missing although the
	// database already holds secrets.
	ErrKeychainMissing = errors.New("vault: keychain.json missing for a non-empty vault")

	// ErrClosed is returned by every method after Close.
	ErrClosed = errors.New("vault: closed")

	// ErrInconsistent means a rotation failed after its database commit;
	// the in-memory key no longer matches the database. Re-open the vault
	// (Open completes the interrupted rotation).
	ErrInconsistent = errors.New("vault: state changed on disk, re-open the vault")
)

// Error is the concrete error type of this package. Its message is Python's;
// kinds are the sentinels it matches; cause (optional) is the wrapped error.
type Error struct {
	msg   string
	kinds []error
	cause error
}

func (e *Error) Error() string { return e.msg }

// Is reports whether target is one of e's sentinel kinds.
func (e *Error) Is(target error) bool {
	for _, k := range e.kinds {
		if k == target {
			return true
		}
	}
	return false
}

// Unwrap returns the underlying cause, if any.
func (e *Error) Unwrap() error { return e.cause }

func newErr(kinds []error, cause error, format string, a ...any) error {
	return &Error{msg: fmt.Sprintf(format, a...), kinds: kinds, cause: cause}
}

func validationErr(format string, a ...any) error {
	return &validation.Error{Message: fmt.Sprintf(format, a...)}
}

func deniedErr(format string, a ...any) error {
	return newErr([]error{ErrPolicyDenied}, nil, format, a...)
}

func rateLimitedErr(agent string) error {
	return newErr([]error{ErrRateLimited, ErrPermission}, nil, "Rate limit exceeded for agent '%s'", agent)
}

func honeytokenErr(namespace, name string) error {
	return newErr([]error{ErrHoneytoken, ErrPermission}, nil, "Honeytoken access detected: %s/%s", namespace, name)
}

func notFoundErr(namespace, name string, cause error) error {
	return newErr([]error{ErrNotFound, store.ErrNotFound}, cause, "Secret '%s/%s' not found.", namespace, name)
}

func unsupportedDEKErr(v int64) error {
	return newErr([]error{ErrUnsupportedDEKVersion, ErrValidation}, nil, "Unsupported DEK version %d", v)
}
