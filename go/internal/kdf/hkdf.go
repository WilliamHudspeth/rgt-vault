// hkdf.go: small helper around golang.org/x/crypto/hkdf that pulls
// `length` bytes from a key stream derived from (input, info) using the
// given hash constructor.
//
// The Python implementation calls hkdf.HKDF(algorithm=..., length=...,
// salt=None, info=...). The Go equivalent: salt is implicitly zero-length
// (HKDF's "no salt" mode is salt = nil and the spec treats that as
// HashLen zero bytes of salt).
//
// hkdfExpand returns the requested number of bytes, or an error if the
// underlying reader failed (which it shouldn't, since hash.Hash.Read is
// total).
package kdf

import (
	"fmt"
	"hash"

	"golang.org/x/crypto/hkdf"
)

func hkdfExpand(ikm, info []byte, length int, newHash func() hash.Hash) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("hkdfExpand: length must be positive, got %d", length)
	}
	reader := hkdf.New(newHash, ikm, nil, info)
	out := make([]byte, length)
	if _, err := reader.Read(out); err != nil {
		return nil, fmt.Errorf("hkdfExpand: read failed: %w", err)
	}
	return out, nil
}
