package keychain

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/kdf"
)

// selfTestKAT is the ciphertext that Python's run_crypto_selftest inputs
// produce (testdata/py/selftest.json). The Python self-test only checks a
// round trip; pinning the bytes also proves at startup that the Go KDF and
// wrap still match Python.
const selfTestKAT = "b20ba876360961504789f86894dfc5ba3a006073adef7639"

// SelfTest is the port of run_crypto_selftest: derive a key and nonce with
// small Argon2 parameters, wrap and unwrap a test DEK, and check that a
// wrong AAD is rejected. It additionally compares the ciphertext against a
// Python known-answer value. Call it once at startup, before opening a
// vault; any error means the binary must not be used.
func SelfTest() error {
	kat, err := hex.DecodeString(selfTestKAT)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSelfTest, err)
	}
	return selfTest(kat)
}

func selfTest(kat []byte) error {
	if err := runSelfTest(kat); err != nil {
		return fmt.Errorf("%w: %v", ErrSelfTest, err)
	}
	return nil
}

func runSelfTest(kat []byte) error {
	master := []byte("selftest_master")
	salt := bytes.Repeat([]byte("selftest_salt"), 4)
	params := kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1}

	aead, nonce, err := deriveAEAD(master, salt, []byte("test_context"), params)
	if err != nil {
		return err
	}
	plaintext := []byte("test_dek")
	aad := []byte("test_aad")
	ct := aead.Seal(nil, nonce[:], plaintext, aad)
	pt, err := aead.Open(nil, nonce[:], ct, aad)
	if err != nil || !bytes.Equal(pt, plaintext) {
		return errors.New("AESGCM unwrap failed")
	}
	if _, err := aead.Open(nil, nonce[:], ct, []byte("wrong_aad")); err == nil {
		return errors.New("AESGCM allowed bad AAD")
	}
	if subtle.ConstantTimeCompare(ct, kat) != 1 {
		return errors.New("known-answer mismatch with the Python implementation")
	}
	return nil
}
