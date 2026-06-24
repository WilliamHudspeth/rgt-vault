// Package auth provides bearer-token authentication for the rgt-vault HTTP server.
//
// The token is a random 32-byte value, urlsafe-base64-encoded (43 characters
// plus padding). Token verification uses constant-time comparison to avoid
// timing side channels.
//
// Audit integration: every authenticated request gets a short "token id"
// (the first 8 hex chars of sha256(token)) recorded in the audit log.
// This lets the operator correlate HTTP activity without ever recording
// the token itself.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Server auth errors.
var (
	ErrMissingAuth   = errors.New("missing Authorization header")
	ErrEmptyToken    = errors.New("empty bearer token")
	ErrInvalidToken  = errors.New("invalid bearer token")
	ErrTokenNotFound = errors.New("token file not found")
)

// TokenStore is a file-backed bearer token store.
// The on-disk format is intentionally trivial: the file's contents are the
// token string (no JSON wrapper, no metadata).
type TokenStore struct {
	Path string
}

// NewTokenStore creates a new TokenStore with the given path.
func NewTokenStore(path string) *TokenStore {
	return &TokenStore{Path: path}
}

// GenerateToken returns a fresh urlsafe-base64-encoded 32-byte random token.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// TokenID returns a stable short identifier for a token, safe to record in audit logs.
func TokenID(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])[:8]
}

// Exists reports whether the token file exists on disk.
func (ts *TokenStore) Exists() bool {
	_, err := os.Stat(ts.Path)
	return err == nil
}

// Write writes the token to the token file, creating parent directories as needed.
func (ts *TokenStore) Write(token string) error {
	if token == "" {
		return errors.New("refusing to write an empty token")
	}
	dir := filepath.Dir(ts.Path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create token directory: %w", err)
	}
	if err := os.WriteFile(ts.Path, []byte(strings.TrimSpace(token)+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}
	return nil
}

// Read reads the token from the token file.
func (ts *TokenStore) Read() (string, error) {
	data, err := os.ReadFile(ts.Path)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrTokenNotFound, ts.Path)
	}
	return strings.TrimSpace(string(data)), nil
}

// constantTimeCompare compares two strings in constant time.
func constantTimeCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Verify checks the presented Authorization header against the stored token.
// It accepts both "Bearer <token>" and raw token formats.
// Returns the token ID (safe to log) on success, or an error on failure.
func (ts *TokenStore) Verify(authHeader string) (string, error) {
	if authHeader == "" {
		return "", ErrMissingAuth
	}

	presented := strings.TrimSpace(authHeader)
	if strings.HasPrefix(strings.ToLower(presented), "bearer ") {
		presented = strings.TrimSpace(presented[7:])
	}

	if presented == "" {
		return "", ErrEmptyToken
	}

	stored, err := ts.Read()
	if err != nil {
		return "", err
	}

	if !constantTimeCompare(presented, stored) {
		return "", ErrInvalidToken
	}

	return TokenID(presented), nil
}

// LoadOrCreateToken returns (path, token), creating the file with a fresh token if missing.
func LoadOrCreateToken(path string) (string, string, error) {
	ts := NewTokenStore(path)
	if ts.Exists() {
		token, err := ts.Read()
		if err != nil {
			return "", "", err
		}
		return path, token, nil
	}

	token, err := GenerateToken()
	if err != nil {
		return "", "", err
	}
	if err := ts.Write(token); err != nil {
		return "", "", err
	}
	return path, token, nil
}
