// rand.go: thin wrapper around crypto/rand for the kdf package's
// randReader variable. Exposed as its own type so tests can swap it.
package kdf

import cryptorand "crypto/rand"

// cryptoRandReader is the default source of cryptographic randomness
// used by the default randReader. It is a variable (not a function call)
// so that future tests can override it; see randReader in kdf.go.
var cryptoRandReader = cryptorand.Reader
