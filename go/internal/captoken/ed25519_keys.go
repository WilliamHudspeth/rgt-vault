package captoken

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"runtime"
)

// maxKeyFile bounds what is read from an Ed25519 key file.
const maxKeyFile = 16 * 1024

// Key files:
//
//	public key:  PEM "PUBLIC KEY" only (PKIX, as `openssl pkey -pubout`
//	             writes). Raw bytes are refused: 32 raw bytes could just as
//	             well be a private seed, and a public-key file is allowed to
//	             be world-readable.
//	private key: PEM "PRIVATE KEY" (PKCS #8, as `openssl genpkey -algorithm
//	             ed25519` writes) or exactly 32 raw bytes (the seed).
//
// Permissions and ownership (not checked on Windows, where mode bits do not
// describe the ACL): both files must be owned by the user running the
// process or by root; a private key file must not be accessible to group or
// others (0600 or stricter); a public key file must not be writable by group
// or others (anyone who can replace it can mint tokens).

// LoadEd25519PublicKeyFile reads a trusted public key. A file holding a
// private key is refused: a verifier-only deployment never holds one.
func LoadEd25519PublicKeyFile(path string) (ed25519.PublicKey, error) {
	raw, err := readKeyFile(path, 0o022)
	if err != nil {
		return nil, err
	}
	if blk, rest := pem.Decode(raw); blk != nil {
		if len(trimSpace(rest)) != 0 {
			return nil, keyErr(path, "trailing data after the PEM block")
		}
		switch blk.Type {
		case "PUBLIC KEY":
			k, err := x509.ParsePKIXPublicKey(blk.Bytes)
			if err != nil {
				return nil, keyErr(path, "not a PKIX public key")
			}
			pub, ok := k.(ed25519.PublicKey)
			if !ok {
				return nil, keyErr(path, "public key is not Ed25519")
			}
			if err := checkPublicKey(pub); err != nil {
				return nil, keyErr(path, "public key "+err.Error())
			}
			return pub, nil
		case "PRIVATE KEY", "ED25519 PRIVATE KEY", "OPENSSH PRIVATE KEY":
			return nil, keyErr(path, "holds a PRIVATE key; a verifier needs only the public key")
		default:
			return nil, keyErr(path, fmt.Sprintf("unsupported PEM block %q", blk.Type))
		}
	}
	return nil, keyErr(path, "expected a PEM PUBLIC KEY block (raw bytes are accepted for private keys only)")
}

// LoadEd25519PrivateKeyFile reads an issuer's private key.
func LoadEd25519PrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	raw, err := readKeyFile(path, 0o077)
	if err != nil {
		return nil, err
	}
	defer wipe(raw)
	if blk, rest := pem.Decode(raw); blk != nil {
		defer wipe(blk.Bytes)
		if len(trimSpace(rest)) != 0 {
			return nil, keyErr(path, "trailing data after the PEM block")
		}
		if blk.Type != "PRIVATE KEY" {
			return nil, keyErr(path, fmt.Sprintf("expected a PEM PRIVATE KEY (PKCS #8), got %q", blk.Type))
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, keyErr(path, "not a PKCS #8 private key")
		}
		priv, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, keyErr(path, "private key is not Ed25519")
		}
		return priv, nil
	}
	if len(raw) != ed25519.SeedSize {
		return nil, keyErr(path, "expected a PEM PRIVATE KEY or exactly 32 raw seed bytes")
	}
	return ed25519.NewKeyFromSeed(raw), nil
}

// NewEd25519VerifierFromFiles trusts each public key file under its
// KeyID.
func NewEd25519VerifierFromFiles(paths []string, opts ...Ed25519Option) (*Ed25519Verifier, error) {
	keys := make(map[string]ed25519.PublicKey, len(paths))
	for _, p := range paths {
		pub, err := LoadEd25519PublicKeyFile(p)
		if err != nil {
			return nil, err
		}
		keys[KeyID(pub)] = pub
	}
	return NewEd25519Verifier(keys, opts...)
}

// readKeyFile opens path, checks the permission bits of the OPENED file
// (no stat/open race), and reads at most maxKeyFile bytes.
func readKeyFile(path string, forbidden os.FileMode) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied key path
	if err != nil {
		return nil, keyErr(path, "cannot open")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, keyErr(path, "cannot stat")
	}
	if !st.Mode().IsRegular() {
		return nil, keyErr(path, "not a regular file")
	}
	if err := checkKeyMode(st.Mode(), forbidden, runtime.GOOS); err != nil {
		return nil, keyErr(path, err.Error())
	}
	if err := checkKeyOwner(st); err != nil {
		return nil, keyErr(path, err.Error())
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, keyErr(path, "read failed")
	}
	if len(raw) > maxKeyFile {
		wipe(raw)
		return nil, keyErr(path, "file too large for a key")
	}
	return raw, nil
}

func checkKeyMode(mode, forbidden os.FileMode, goos string) error {
	if goos == "windows" {
		return nil
	}
	if perm := mode.Perm(); perm&forbidden != 0 {
		return fmt.Errorf("permissions %#o are too open (must not include %#o; chmod 600)", perm, forbidden)
	}
	return nil
}

func keyErr(path, why string) error {
	return newErr(kindValidation, "ed25519 key file %q: %s", path, why)
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\n' || b[0] == '\r' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
