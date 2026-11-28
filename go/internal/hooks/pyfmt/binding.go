package pyfmt

import (
	"errors"
	"sort"
	"strings"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/captoken"
)

// BindingError is a context-binding failure carrying Python's
// TokenBindingError message. It unwraps to the captoken error, so
// errors.Is(err, captoken.ErrBinding) holds.
type BindingError struct {
	Message string
	Cause   error
}

func (e *BindingError) Error() string { return e.Message }

// Unwrap returns the captoken.ErrBinding error.
func (e *BindingError) Unwrap() error { return e.Cause }

// CheckContext runs tok.CheckContext(payload) (the authoritative decision)
// and, on failure, returns a *BindingError whose message is the one
// python/token.py CapabilityV2Token.check_context raises for the first
// failing binding (bindings are visited in sorted key order, which is the
// order of the canonical token payload Python iterates):
//
//	capability 'c' requires context key 'k' in the request
//	capability 'c' context binding failed for 'k': expected X, got Y
func CheckContext(tok *captoken.CapabilityV2Token, payload map[string]any) error {
	err := tok.CheckContext(payload)
	if err == nil {
		return nil
	}
	keys := make([]string, 0, len(tok.ContextBindings))
	for k := range tok.ContextBindings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		expected := tok.ContextBindings[k]
		got, ok := payload[k]
		if !ok {
			return &BindingError{
				Message: "capability " + Repr(tok.Capability) + " requires context key " + Repr(k) + " in the request",
				Cause:   err,
			}
		}
		one := captoken.CapabilityV2Token{Capability: tok.Capability, ContextBindings: map[string]any{k: expected}}
		if one.CheckContext(map[string]any{k: got}) != nil {
			return &BindingError{
				Message: "capability " + Repr(tok.Capability) + " context binding failed for " + Repr(k) +
					": expected " + Repr(expected) + ", got " + Repr(got),
				Cause: err,
			}
		}
	}
	// Unreachable unless CheckContext and the per-key check disagree; keep
	// the decision (deny) with the captoken wording.
	return &BindingError{Message: err.Error(), Cause: err}
}

// TokenErrorClass returns the python/token.py exception class name that
// corresponds to a captoken error (type(e).__name__ in Python's audit
// reasons), or "TokenError" for any other token failure.
func TokenErrorClass(err error) string {
	switch {
	case errors.Is(err, captoken.ErrExpired):
		return "TokenExpiredError"
	case errors.Is(err, captoken.ErrSignature):
		return "TokenSignatureError"
	case errors.Is(err, captoken.ErrMalformed):
		return "TokenMalformedError"
	case errors.Is(err, captoken.ErrVersion):
		return "TokenVersionError"
	case errors.Is(err, captoken.ErrBinding):
		return "TokenBindingError"
	case errors.Is(err, captoken.ErrReplay):
		return "TokenReplayError"
	}
	return "TokenError"
}

// TokenErrorMessage strips the "captoken: <kind>: " prefix from a captoken
// error, leaving the message Python's exception carries.
func TokenErrorMessage(err error) string {
	s := err.Error()
	rest, ok := strings.CutPrefix(s, "captoken: ")
	if !ok {
		return s
	}
	if _, msg, ok := strings.Cut(rest, ": "); ok {
		return msg
	}
	return rest
}
