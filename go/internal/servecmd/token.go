package servecmd

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// MinTokenBytes is the minimum entropy of a bearer token: 32 random bytes
// (what auth.GenerateToken and `rgt-vault init` produce).
const MinTokenBytes = 32

// ErrWeakToken is returned by ValidateToken. Its text never contains the
// token.
var ErrWeakToken = errors.New("token is too weak: it must be at least 32 random bytes encoded as " +
	"base64 or hex (create one with `rgt-vault init`, or `openssl rand -base64 32`)")

// ValidateToken rejects a bearer token that does not decode, as base64
// (standard or URL-safe, padded or not) or hex, to at least MinTokenBytes
// bytes with some variety (not "AAAA..." or a short repeating pattern) (RGT-498). The error never echoes
// the token.
func ValidateToken(token string) error {
	t := strings.TrimSpace(token)
	if t == "" {
		return fmt.Errorf("%w (the file is empty)", ErrWeakToken)
	}
	for _, dec := range []func(string) ([]byte, error){
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(t); err == nil && len(b) >= MinTokenBytes && distinctBytes(b) >= minDistinctBytes {
			return nil
		}
	}
	return ErrWeakToken
}

// minDistinctBytes rejects degenerate tokens ("AAAA...", "0000...", a short
// pattern repeated): 32 random bytes have about 29 distinct values.
const minDistinctBytes = 8

func distinctBytes(b []byte) int {
	var seen [256]bool
	n := 0
	for _, c := range b {
		if !seen[c] {
			seen[c] = true
			n++
		}
	}
	return n
}

// TightenFile restricts an existing secret file to its owner (0600). On
// Windows POSIX modes are not meaningful and Chmod only toggles the
// read-only attribute, so it is skipped there by the callers' tests, not
// here: a failure is returned as is.
func TightenFile(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm() == 0o600 {
		return nil
	}
	return os.Chmod(path, 0o600)
}
