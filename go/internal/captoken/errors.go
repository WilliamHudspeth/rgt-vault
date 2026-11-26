package captoken

import "fmt"

// Kind classifies a token failure. It mirrors the Python exception
// hierarchy in python/token.py (TokenError and its subclasses), plus
// two Go-only kinds (ErrAudience, ErrNotImplemented, ErrValidation).
type Kind int

const (
	kindAny Kind = iota // matches every token-verification failure
	kindExpired
	kindSignature
	kindMalformed
	kindVersion
	kindBinding
	kindAudience
	kindNotImplemented
	kindValidation
)

// Error is the error type returned by this package. Use errors.Is with
// the sentinel values (ErrExpired, ErrSignature, ...) to classify it.
// The message never contains the token itself.
type Error struct {
	kind Kind
	msg  string
}

func (e *Error) Error() string {
	if e.msg == "" {
		return "captoken: " + e.kind.String()
	}
	return "captoken: " + e.kind.String() + ": " + e.msg
}

// Is makes errors.Is(err, ErrExpired) work. A target sentinel (empty
// message) matches on Kind; ErrToken matches every token-verification
// failure (Python's TokenError) but not ErrValidation / ErrNotImplemented.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok || t.msg != "" {
		return false
	}
	if t.kind == kindAny {
		switch e.kind {
		case kindExpired, kindSignature, kindMalformed, kindVersion, kindBinding, kindAudience:
			return true
		}
		return false
	}
	return t.kind == e.kind
}

func (k Kind) String() string {
	switch k {
	case kindExpired:
		return "token expired"
	case kindSignature:
		return "bad signature"
	case kindMalformed:
		return "malformed token"
	case kindVersion:
		return "unsupported token version"
	case kindBinding:
		return "context binding mismatch"
	case kindAudience:
		return "audience mismatch"
	case kindNotImplemented:
		return "not implemented"
	case kindValidation:
		return "invalid argument"
	}
	return "token error"
}

// Sentinels for errors.Is.
var (
	// ErrToken matches every token-verification failure (Python TokenError).
	ErrToken = &Error{kind: kindAny}
	// ErrExpired: the token's exp is in the past (TokenExpiredError).
	ErrExpired = &Error{kind: kindExpired}
	// ErrSignature: the signature did not verify (TokenSignatureError).
	ErrSignature = &Error{kind: kindSignature}
	// ErrMalformed: envelope or payload is not well-formed (TokenMalformedError).
	ErrMalformed = &Error{kind: kindMalformed}
	// ErrVersion: unsupported token format version (TokenVersionError).
	ErrVersion = &Error{kind: kindVersion}
	// ErrBinding: request arguments violate the token's context bindings
	// (TokenBindingError).
	ErrBinding = &Error{kind: kindBinding}
	// ErrAudience: the token is for a different agent, capability or
	// capability version than the request. Go-only; Python's
	// TwoFactorHook performs these comparisons inline.
	ErrAudience = &Error{kind: kindAudience}
	// ErrNotImplemented: the Ed25519 placeholder (RGT-35 / RGT-46).
	ErrNotImplemented = &Error{kind: kindNotImplemented}
	// ErrValidation: invalid caller input to Sign / constructors
	// (Python ValidationError).
	ErrValidation = &Error{kind: kindValidation}
)

func newErr(k Kind, format string, a ...any) error {
	return &Error{kind: k, msg: fmt.Sprintf(format, a...)}
}
