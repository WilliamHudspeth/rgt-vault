// Tests for the internal/crypto package.
//
// These tests provide cross-language parity with the Python rgt_vault.crypto
// module (rgt_vault/crypto.py). The contract is:
//
//   - Wire format: nonce(12) || ciphertext || tag(16) — same on both sides.
//   - DEK is exactly 32 bytes; mismatched sizes fail with ErrInvalidDEKLength.
//   - AAD is bound into the authentication tag; changing the AAD causes
//     Decrypt to fail with ErrDecryptionFailed.
//   - All decryption failures (wrong key, wrong AAD, tampered ciphertext,
//     truncated input) collapse to a single error type to prevent an oracle
//     that distinguishes "wrong key" from "tampered".
//
// The TestCrossLanguageVector test vector (TestVectorCrossLang) was generated
// by the Python rgt_vault.crypto.encrypt and is hardcoded here. The Go side
// must decrypt it to the exact plaintext. This is the real Go↔Python parity
// gate.
package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// allZerosKey is a 32-byte key of bytes 0x00, 0x01, ..., 0x1f.
var allZerosKey = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

// freshKey returns a fresh random 32-byte DEK, suitable for use across tests.
func freshKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return k
}

// --- Basic round-trip tests ------------------------------------------------

func TestRoundTrip_EmptyPlaintext(t *testing.T) {
	k := freshKey(t)
	ct, err := Encrypt([]byte{}, k, []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if got, want := len(ct), 12+0+16; got != want {
		t.Errorf("empty plaintext: ct length = %d, want %d", got, want)
	}
	pt, err := Decrypt(ct, k, []byte("aad"))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(pt) != 0 {
		t.Errorf("empty plaintext round-trip: got %d bytes, want 0", len(pt))
	}
}

func TestRoundTrip_ShortText(t *testing.T) {
	k := freshKey(t)
	pt := []byte("hello world")
	ct, err := Encrypt(pt, k, []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if got, want := len(ct), len(pt)+12+16; got != want {
		t.Errorf("ct length = %d, want %d", got, want)
	}
	got, err := Decrypt(ct, k, []byte("aad"))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, pt)
	}
}

func TestRoundTrip_Binary(t *testing.T) {
	k := freshKey(t)
	pt := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF}, 1024) // 3 KB
	ct, err := Encrypt(pt, k, []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(ct, k, []byte("aad"))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Errorf("binary round-trip mismatch: len got=%d want=%d", len(got), len(pt))
	}
}

func TestRoundTrip_EmptyAAD(t *testing.T) {
	k := freshKey(t)
	pt := []byte("data with no aad")
	ct, err := Encrypt(pt, k, []byte{})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(ct, k, []byte{})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Errorf("round-trip with empty AAD: got %q, want %q", got, pt)
	}
}

// --- Nonce randomness ------------------------------------------------------

func TestEncrypt_NonceIsRandom(t *testing.T) {
	// Two encrypts of the same plaintext + key + AAD must produce different
	// ciphertexts (with overwhelming probability). This proves the nonce is
	// not deterministic.
	k := freshKey(t)
	pt := []byte("same plaintext")
	aad := []byte("same aad")

	ct1, err := Encrypt(pt, k, aad)
	if err != nil {
		t.Fatalf("Encrypt #1: %v", err)
	}
	ct2, err := Encrypt(pt, k, aad)
	if err != nil {
		t.Fatalf("Encrypt #2: %v", err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Error("two encrypts of identical inputs produced identical ciphertexts — nonce is not random")
	}
	// First 12 bytes (nonce) must differ.
	if bytes.Equal(ct1[:12], ct2[:12]) {
		t.Error("two encrypts produced identical nonces")
	}
}

// --- Wire format -----------------------------------------------------------

func TestEncrypt_WireFormatLength(t *testing.T) {
	// Ciphertext length must be: 12 (nonce) + len(plaintext) + 16 (tag).
	for _, size := range []int{0, 1, 16, 64, 256, 1024, 4096} {
		pt := make([]byte, size)
		ct, err := Encrypt(pt, freshKey(t), []byte("aad"))
		if err != nil {
			t.Fatalf("Encrypt size=%d: %v", size, err)
		}
		if got, want := len(ct), 12+size+16; got != want {
			t.Errorf("size=%d: ct length = %d, want %d", size, got, want)
		}
	}
}

// --- Failure modes ---------------------------------------------------------

func TestEncrypt_InvalidDEKLength(t *testing.T) {
	for _, size := range []int{0, 16, 24, 31, 33, 64} {
		dek := make([]byte, size)
		_, err := Encrypt([]byte("pt"), dek, []byte("aad"))
		if !errors.Is(err, ErrInvalidDEKLength) {
			t.Errorf("DEK size=%d: expected ErrInvalidDEKLength, got %v", size, err)
		}
	}
}

func TestDecrypt_TruncatedToken(t *testing.T) {
	// Tokens shorter than 12 (nonce) + 16 (tag) = 28 bytes must fail.
	// Mirrors Python test_decrypt_truncated_raises_decryption_error.
	for _, size := range []int{0, 1, 12, 16, 27} {
		token := make([]byte, size)
		_, err := Decrypt(token, allZerosKey, []byte("aad"))
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("token size=%d: expected ErrInvalidToken, got %v", size, err)
		}
	}
}

func TestDecrypt_InvalidDEKLength(t *testing.T) {
	// Even a well-formed token must fail with ErrInvalidDEKLength if the DEK
	// is the wrong size, without ever touching the GCM path.
	ct, _ := Encrypt([]byte("pt"), allZerosKey, []byte("aad"))
	for _, size := range []int{0, 16, 24, 31, 33} {
		dek := make([]byte, size)
		_, err := Decrypt(ct, dek, []byte("aad"))
		if !errors.Is(err, ErrInvalidDEKLength) {
			t.Errorf("DEK size=%d: expected ErrInvalidDEKLength, got %v", size, err)
		}
	}
}

func TestDecrypt_WrongAAD(t *testing.T) {
	// Mirrors Python test_decrypt_wrong_aad_raises_decryption_error.
	k := freshKey(t)
	ct, err := Encrypt([]byte("plaintext"), k, []byte("good-aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, err = Decrypt(ct, k, []byte("bad-aad"))
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("wrong AAD: expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	// Mirrors Python test_decrypt_wrong_key_raises_decryption_error.
	ct, err := Encrypt([]byte("plaintext"), bytes.Repeat([]byte{'k'}, 32), []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, err = Decrypt(ct, bytes.Repeat([]byte{'j'}, 32), []byte("aad"))
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("wrong key: expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	// Tamper: flip one byte of the ciphertext. The GCM tag check must fail.
	k := freshKey(t)
	ct, err := Encrypt([]byte("the quick brown fox"), k, []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Flip the last byte (which is inside the auth tag — strongest tamper).
	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 0x01
	_, err = Decrypt(tampered, k, []byte("aad"))
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("tampered ciphertext: expected ErrDecryptionFailed, got %v", err)
	}
	// Also test tampering with the nonce (first 12 bytes).
	tampered2 := bytes.Clone(ct)
	tampered2[0] ^= 0x80
	_, err = Decrypt(tampered2, k, []byte("aad"))
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("tampered nonce: expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecrypt_FailureCollapsesToSingleError(t *testing.T) {
	// The Python contract says: callers cannot distinguish "wrong key" from
	// "wrong AAD" from "tampered" by exception type. Verify the same in Go
	// via errors.Is: all three must satisfy ErrDecryptionFailed.
	k1 := bytes.Repeat([]byte{'k'}, 32)
	k2 := bytes.Repeat([]byte{'j'}, 32)

	ct, _ := Encrypt([]byte("pt"), k1, []byte("good"))

	err1 := mustFail(t, func() error { _, e := Decrypt(ct, k2, []byte("good")); return e })
	err2 := mustFail(t, func() error { _, e := Decrypt(ct, k1, []byte("bad")); return e })
	tampered := bytes.Clone(ct)
	tampered[20] ^= 0x01
	err3 := mustFail(t, func() error { _, e := Decrypt(tampered, k1, []byte("good")); return e })

	if !errors.Is(err1, ErrDecryptionFailed) ||
		!errors.Is(err2, ErrDecryptionFailed) ||
		!errors.Is(err3, ErrDecryptionFailed) {
		t.Errorf("failure modes do not collapse to a single error type: %v / %v / %v", err1, err2, err3)
	}
	// And the error messages must NOT leak which dimension failed.
	for i, e := range []error{err1, err2, err3} {
		msg := e.Error()
		if strings.Contains(msg, "key") || strings.Contains(msg, "aad") || strings.Contains(msg, "tag") {
			t.Errorf("err%d leaks dimension in message: %q", i+1, msg)
		}
	}
}

func mustFail(t *testing.T, fn func() error) error {
	t.Helper()
	err := fn()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	return err
}

// --- Cross-language parity test vector --------------------------------------
//
// TestVectorCrossLang was generated by Python rgt_vault.crypto.encrypt:
//
//   python3 -c "
//   import sys; sys.path.insert(0, '/home/will/rgt-vault')
//   from rgt_vault.crypto import encrypt
//   print(encrypt(b'Go test parity check', bytes(range(32)), b'cross-lang-aad').hex())
//   "
//
// The Go side must decrypt this exact byte string to the plaintext below.
// If this test fails, the Go and Python AES-GCM implementations are not
// byte-for-byte compatible — do not land the change.

const (
	crossLangKeyHex    = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	crossLangAAD       = "cross-lang-aad"
	crossLangPlaintext = "Go test parity check"
	crossLangTokenHex  = "a82f398a4b83c1b23923ab147cc08eeb2661326d17caf049259664c2020c711c7d1488f5c556ff78816cd2ae3e5085f4"
)

func TestCrossLanguageVector(t *testing.T) {
	key, err := hexDecode(crossLangKeyHex)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	token, err := hexDecode(crossLangTokenHex)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	pt, err := Decrypt(token, key, []byte(crossLangAAD))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != crossLangPlaintext {
		t.Errorf("cross-language parity FAILED: got %q, want %q", pt, crossLangPlaintext)
	}
	// Token length must be 12 (nonce) + 22 (PT) + 16 (tag) = 50.
	if got, want := len(token), 12+len(crossLangPlaintext)+16; got != want {
		t.Errorf("token length = %d, want %d", got, want)
	}
}

// hexDecode is a tiny local helper to keep this test file self-contained.
func hexDecode(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var hi, lo byte
		var err error
		if hi, err = hexNibble(s[2*i]); err != nil {
			return nil, err
		}
		if lo, err = hexNibble(s[2*i+1]); err != nil {
			return nil, err
		}
		out[i] = (hi << 4) | lo
	}
	return out, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', nil
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, nil
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, errors.New("invalid hex character")
}
