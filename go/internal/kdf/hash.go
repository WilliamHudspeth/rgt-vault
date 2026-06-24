// hash.go: thin wrappers around crypto/hashes so that the kdf package can
// pass a Hash factory to hkdfExpand. Kept in its own file so the main
// kdf.go stays focused on the orchestration logic.
package kdf

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// sha256NewFunc and sha512NewFunc are factory functions matching the
// signature required by hkdf.New (which itself accepts a func() hash.Hash).
//
// We expose them as variables (not functions) so they can be swapped out
// in tests if we ever need to. In practice they always point to the
// stdlib implementations.
var (
	sha256NewFunc = func() hash.Hash { return sha256.New() }
	sha512NewFunc = func() hash.Hash { return sha512.New() }
)
