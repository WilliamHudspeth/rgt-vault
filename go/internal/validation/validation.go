// Package validation is the Go port of python/input_validation.py: strict,
// allowlist-based server-side validation of names, namespaces, agent
// identifiers, integers and free text (Unicode NFC + general-category
// allowlist), plus a linear-time regex helper.
//
// Error messages are the same as Python's ValidationError messages, and all
// errors satisfy errors.Is(err, ErrValidation).
//
// Deliberate differences from Python (both stricter, documented here and in
// the tests):
//   - Python validates names with re.match(r"^...+$"), where `$` also matches
//     just before a trailing "\n", so "abc\n" is accepted. Go rejects any
//     newline: the allowlists are applied to the whole string.
//   - Python checks length with len() (code points); so does Go. Invalid
//     UTF-8 cannot occur in a Python str; Go rejects it.
//
// Unicode data: category checks use Go's unicode tables and normalization
// uses golang.org/x/text; Python uses unicodedata. Code points assigned in
// one Unicode version but not the other can therefore be classified
// differently (e.g. very recently assigned characters).
package validation

import (
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

// ErrValidation is matched (errors.Is) by every error this package returns.
var ErrValidation = errors.New("validation error")

// Error is a validation failure (python: rgt_vault.exceptions.ValidationError).
type Error struct{ Message string }

func (e *Error) Error() string { return e.Message }

// Is makes errors.Is(err, ErrValidation) true.
func (e *Error) Is(target error) bool { return target == ErrValidation }

func fail(format string, a ...any) error {
	return &Error{Message: fmt.Sprintf(format, a...)}
}

// Maximum lengths, in characters (code points).
const (
	MaxNameLen      = 256
	MaxNamespaceLen = 128
	MaxAgentLen     = 128
	// DefaultFreeTextMax is validate_free_text's default max_len.
	DefaultFreeTextMax = 512
)

// pyIsSpace mirrors Python's str.isspace for a single character: Unicode
// white space plus the four ASCII separators U+001C..U+001F.
func pyIsSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

func isBlank(s string) bool {
	for _, r := range s {
		if !pyIsSpace(r) {
			return false
		}
	}
	return true // also true for ""
}

func allASCIIIn(s string, ok func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// ^[a-zA-Z0-9_.\- ]+$
func nameChar(c byte) bool { return isAlnum(c) || c == '_' || c == '.' || c == '-' || c == ' ' }

// ^[a-zA-Z0-9_.\-@]+$
func agentChar(c byte) bool { return isAlnum(c) || c == '_' || c == '.' || c == '-' || c == '@' }

// ^[a-zA-Z0-9_.\-]+$
func namespaceChar(c byte) bool { return isAlnum(c) || c == '_' || c == '.' || c == '-' }

func validateIdent(field, value string, maxLen int, ok func(byte) bool, allowed string) (string, error) {
	if isBlank(value) {
		return "", fail("'%s' cannot be empty or whitespace.", field)
	}
	if utf8.RuneCountInString(value) > maxLen {
		return "", fail("'%s' exceeds the maximum allowed length of %d characters.", field, maxLen)
	}
	if !allASCIIIn(value, ok) {
		return "", fail("'%s' contains characters not permitted by the allowlist (allowed: %s).", field, allowed)
	}
	return value, nil
}

// ValidateName returns value if it is a valid secret name: 1-256 characters
// from [a-zA-Z0-9_. -] and not blank.
func ValidateName(value string) (string, error) {
	return validateIdent("name", value, MaxNameLen, nameChar, "a-z A-Z 0-9 _ . -")
}

// ValidateNamespace returns value if it is a valid namespace: 1-128
// characters from [a-zA-Z0-9_.-].
func ValidateNamespace(value string) (string, error) {
	return validateIdent("namespace", value, MaxNamespaceLen, namespaceChar, "a-z A-Z 0-9 _ . -")
}

// ValidateAgent returns value if it is a valid agent identifier: 1-128
// characters from [a-zA-Z0-9_.@-].
func ValidateAgent(value string) (string, error) {
	return validateIdent("agent", value, MaxAgentLen, agentChar, "a-z A-Z 0-9 _ . - @")
}
