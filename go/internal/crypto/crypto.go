// Package crypto provides AES-256-GCM encryption and decryption primitives
// for rgt-vault-server, matching the wire format of the Python rgt_vault.crypto
// module so that the two implementations are byte-for-byte compatible.
//
// Wire format:
//
//	+----------------+----------------+----------+
//	| nonce (12 B)   | ciphertext     | tag (16) |
//	+----------------+----------------+----------+
//
// The nonce is randomly generated per Encrypt() call. The DEK must be exactly
// 32 bytes. The AAD is bound into the authentication tag, so tampering with the
// AAD, the key, or the ciphertext all cause Decrypt() to return an error of
// type *DecryptionError.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Sentinel errors. Callers should use errors.Is to check.
var (
	// ErrInvalidDEKLength is returned when the DEK is not exactly 32 bytes.
	ErrInvalidDEKLength = errors.New("crypto: DEK must be exactly 32 bytes")

	// ErrInvalidToken is returned when the ciphertext token is too short to
	// contain the 12-byte nonce + 16-byte tag, or is otherwise malformed.
	ErrInvalidToken = errors.New("crypto: ciphertext is too short to be valid")

	// ErrDecryptionFailed is returned when the AES-GCM authentication tag
	// check fails. The cause (wrong key, wrong AAD, tampered ciphertext) is
	// intentionally NOT surfaced to callers, to avoid leaking which dimension
	// of the input was wrong.
	ErrDecryptionFailed = errors.New("crypto: decryption failed: ciphertext is invalid or tampered with")
)

// minTokenSize is the smallest valid ciphertext: 12 (nonce) + 0 (empty PT) + 16 (tag) = 28 bytes.
const minTokenSize = 12 + 16

// nonceSize is the AES-GCM nonce length in bytes (96 bits, per NIST SP 800-38D).
const nonceSize = 12

// tagSize is the AES-GCM authentication tag length in bytes (128 bits).
const tagSize = 16

// dekSize is the required DEK length in bytes (AES-256 = 32 bytes).
const dekSize = 32

// Encrypt encrypts plaintext using AES-256-GCM with the given 32-byte DEK and
// additional authenticated data (AAD). The output is nonce || ciphertext || tag.
//
// plaintext may be empty (zero-length) or any byte slice; the AAD may be empty
// but must be a non-nil byte slice (use []byte{} for "no AAD"). The DEK must be
// exactly 32 bytes.
//
// Each call generates a fresh random 12-byte nonce via crypto/rand.
func Encrypt(plaintext, dek, aad []byte) ([]byte, error) {
	if len(dek) != dekSize {
		return nil, ErrInvalidDEKLength
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		// aes.NewCipher only fails if len(dek) != 16/24/32, which we've already
		// checked, but guard against future changes in the stdlib.
		return nil, fmt.Errorf("crypto: aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: cipher.NewGCM: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: read nonce: %w", err)
	}

	// Seal(dst, nonce, plaintext, aad) appends the ciphertext+tag to dst.
	// Go's stdlib does NOT prepend the nonce — it expects the caller to
	// store the nonce separately and pass it back to Open. To match the
	// Python rgt_vault.crypto.Encrypt wire format (nonce || ciphertext ||
	// tag) we preallocate a slice of the exact final size and Seal into it.
	sealed := make([]byte, nonceSize, nonceSize+len(plaintext)+tagSize)
	copy(sealed, nonce)
	sealed = gcm.Seal(sealed, nonce, plaintext, aad)
	return sealed, nil
}

// Decrypt decrypts a token produced by Encrypt and returns the original plaintext.
// The DEK and AAD must match those used during encryption, or Decrypt returns
// an *DecryptionError-equivalent (ErrDecryptionFailed, satisfying errors.Is).
//
// On any failure (wrong key, wrong AAD, truncated input, tampered ciphertext),
// Decrypt returns ErrDecryptionFailed. The underlying GCM error is NOT exposed.
func Decrypt(token, dek, aad []byte) ([]byte, error) {
	if len(dek) != dekSize {
		return nil, ErrInvalidDEKLength
	}
	if len(token) < minTokenSize {
		return nil, ErrInvalidToken
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes.NewCipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: cipher.NewGCM: %w", err)
	}

	nonce := token[:nonceSize]
	ciphertext := token[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		// Intentionally do not leak err (which is *cipher.MessageAuthenticationError
		// or similar) to the caller; that would be a useful oracle for an attacker.
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}
