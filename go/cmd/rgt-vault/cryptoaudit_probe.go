package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/auth"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/captoken"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/crypto"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/cryptopolicy"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/kdf"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/keychain"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/totp"
)

// Test seams: crypto-audit drives the repo's real Encrypt/Decrypt through
// these so tests can inject a drifting implementation and prove the audit
// reports FAIL instead of printing hard-coded values.
var (
	cryptoAuditEncrypt = crypto.Encrypt
	cryptoAuditDecrypt = crypto.Decrypt
)

// liveProbeInfo is the outcome of one live probe.
type liveProbeInfo struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// liveProbesInfo groups the probes that exercise repo code and whose
// observations feed the report (so the printed sizes cannot drift from code).
type liveProbesInfo struct {
	Cipher   liveProbeInfo `json:"cipher_round_trip"`
	Keychain liveProbeInfo `json:"keychain_default_kdf"`
	Tokens   liveProbeInfo `json:"token_sizes"`
}

// argon2CalibrationInfo is a read-only timing of one Argon2id wrap with the
// shipped default parameters. It is informational and never changes the
// result or any on-disk format.
type argon2CalibrationInfo struct {
	Params    kdf.Params `json:"params"`
	ElapsedMS int64      `json:"elapsed_ms"`
	Note      string     `json:"note"`
}

// cipherObservation holds sizes measured from real ciphertext.
type cipherObservation struct {
	KeyBytes   int
	NonceBytes int
	TagBytes   int
}

// probeCipher encrypts and decrypts through crypto.Encrypt/Decrypt, parses the
// real output with an independent stdlib AES-GCM and reports the observed
// nonce and tag sizes. Any deviation from the frozen format is an error.
func probeCipher() (cipherObservation, error) {
	var obs cipherObservation
	key := make([]byte, cryptopolicy.RequiredAESKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return obs, fmt.Errorf("probe key: %w", err)
	}
	defer keychain.Wipe(key)
	pt := make([]byte, 37)
	if _, err := rand.Read(pt); err != nil {
		return obs, fmt.Errorf("probe plaintext: %w", err)
	}
	aad := []byte("crypto-audit-probe:aad")
	obs.KeyBytes = len(key)

	ct, err := cryptoAuditEncrypt(pt, key, aad)
	if err != nil {
		return obs, fmt.Errorf("encrypt probe: %w", err)
	}

	// Independent reference parse: the nonce is the stdlib GCM nonce size at
	// the front, the tag the stdlib overhead at the back.
	block, err := aes.NewCipher(key)
	if err != nil {
		return obs, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return obs, err
	}
	obs.NonceBytes = gcm.NonceSize()
	obs.TagBytes = gcm.Overhead()
	if want := obs.NonceBytes + len(pt) + obs.TagBytes; len(ct) != want {
		return obs, fmt.Errorf("ciphertext length %d != nonce(%d)+plaintext(%d)+tag(%d)=%d", len(ct), obs.NonceBytes, len(pt), obs.TagBytes, want)
	}
	opened, err := gcm.Open(nil, ct[:obs.NonceBytes], ct[obs.NonceBytes:], aad)
	if err != nil || !bytes.Equal(opened, pt) {
		return obs, errors.New("probe ciphertext is not nonce||ciphertext||tag AES-256-GCM")
	}

	// Empty plaintext: total length is exactly nonce + tag.
	empty, err := cryptoAuditEncrypt(nil, key, aad)
	if err != nil {
		return obs, fmt.Errorf("encrypt empty probe: %w", err)
	}
	if len(empty) != obs.NonceBytes+obs.TagBytes {
		return obs, fmt.Errorf("empty-plaintext ciphertext is %d bytes, want %d", len(empty), obs.NonceBytes+obs.TagBytes)
	}

	// Repo Decrypt round trip, wrong AAD, tamper.
	got, err := cryptoAuditDecrypt(ct, key, aad)
	if err != nil || !bytes.Equal(got, pt) {
		return obs, errors.New("Decrypt round trip failed")
	}
	if _, err := cryptoAuditDecrypt(ct, key, []byte("wrong-aad")); !errors.Is(err, crypto.ErrDecryptionFailed) {
		return obs, errors.New("Decrypt accepted a wrong AAD")
	}
	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := cryptoAuditDecrypt(tampered, key, aad); !errors.Is(err, crypto.ErrDecryptionFailed) {
		return obs, errors.New("Decrypt accepted a tampered tag")
	}

	// Fresh nonce per call.
	ct2, err := cryptoAuditEncrypt(pt, key, aad)
	if err != nil {
		return obs, fmt.Errorf("encrypt probe 2: %w", err)
	}
	if bytes.Equal(ct[:obs.NonceBytes], ct2[:obs.NonceBytes]) {
		return obs, errors.New("two Encrypt calls produced the same nonce")
	}

	// Non-32-byte keys are rejected unconditionally.
	for _, n := range []int{0, 16, 24, 31, 33} {
		bad := make([]byte, n)
		if _, err := cryptoAuditEncrypt(pt, bad, aad); !errors.Is(err, crypto.ErrInvalidDEKLength) {
			return obs, fmt.Errorf("Encrypt accepted a %d-byte key", n)
		}
		if _, err := cryptoAuditDecrypt(ct, bad, aad); !errors.Is(err, crypto.ErrInvalidDEKLength) {
			return obs, fmt.Errorf("Decrypt accepted a %d-byte key", n)
		}
	}

	if obs.KeyBytes != cryptopolicy.RequiredAESKeyBytes ||
		obs.NonceBytes != cryptopolicy.RequiredNonceBytes ||
		obs.TagBytes != cryptopolicy.RequiredTagBytes {
		return obs, fmt.Errorf("observed key/nonce/tag = %d/%d/%d, frozen format is %d/%d/%d",
			obs.KeyBytes, obs.NonceBytes, obs.TagBytes,
			cryptopolicy.RequiredAESKeyBytes, cryptopolicy.RequiredNonceBytes, cryptopolicy.RequiredTagBytes)
	}
	return obs, nil
}

// keychainObservation holds values read from a real keychain.json written with
// the shipped default KDF parameters.
type keychainObservation struct {
	Params     kdf.Params
	SaltBytes  int
	DEKBytes   int
	Wrapped    int
	CalibrateM time.Duration
}

// probeKeychain creates a real keychain.json in a throwaway directory with
// kdf.DefaultParams() (what vault.Open uses when Config.KDFParams is zero),
// reads the parameters and salt length back from the file, and unwraps it
// again. The elapsed time of the wrap is the Argon2id calibration figure.
func probeKeychain() (keychainObservation, error) {
	var obs keychainObservation
	dir, err := os.MkdirTemp("", "rgt-crypto-audit-*")
	if err != nil {
		return obs, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "keychain.json")

	master := make([]byte, cryptopolicy.RequiredAESKeyBytes)
	if _, err := rand.Read(master); err != nil {
		return obs, err
	}
	defer keychain.Wipe(master)

	const vaultID = "00000000-0000-4000-8000-000000000000"
	mgr := keychain.New(path)
	defer mgr.Close()
	start := time.Now()
	dek, err := mgr.Initialize(master, vaultID, 1, kdf.DefaultParams())
	obs.CalibrateM = time.Since(start)
	if err != nil {
		return obs, fmt.Errorf("initialize probe keychain: %w", err)
	}
	defer keychain.Wipe(dek)
	obs.DEKBytes = len(dek)

	audit, err := cryptopolicy.Default().CheckKeychainFile(path)
	if err != nil {
		return obs, err
	}
	obs.Params = audit.Params
	obs.SaltBytes = audit.SaltBytes
	obs.Wrapped = audit.WrappedDEKBytes
	if !audit.Compliant {
		return obs, fmt.Errorf("default-parameter keychain violates default policy: %v", audit.Violations)
	}

	mgr2 := keychain.New(path)
	defer mgr2.Close()
	dek2, err := mgr2.Load(master, vaultID, 1)
	if err != nil {
		return obs, fmt.Errorf("reload probe keychain: %w", err)
	}
	defer keychain.Wipe(dek2)
	if !bytes.Equal(dek, dek2) {
		return obs, errors.New("reloaded DEK differs from initialized DEK")
	}

	def := cryptopolicy.Default()
	if obs.Params.MemoryCost < def.MinArgon2MemoryKiB || obs.Params.TimeCost < def.MinArgon2TimeCost ||
		obs.Params.Parallelism < def.MinArgon2Parallelism {
		return obs, fmt.Errorf("shipped default Argon2 params %+v are below the built-in policy floors", obs.Params)
	}
	if obs.SaltBytes != keychain.SaltSize || obs.SaltBytes < def.MinArgon2SaltBytes {
		return obs, fmt.Errorf("observed salt %d bytes, want %d", obs.SaltBytes, keychain.SaltSize)
	}
	if obs.DEKBytes != cryptopolicy.RequiredAESKeyBytes || obs.Wrapped != cryptopolicy.RequiredWrappedLen {
		return obs, fmt.Errorf("observed DEK/wrapped %d/%d bytes, want %d/%d",
			obs.DEKBytes, obs.Wrapped, cryptopolicy.RequiredAESKeyBytes, cryptopolicy.RequiredWrappedLen)
	}
	return obs, nil
}

// tokenObservation holds sizes measured from freshly generated tokens.
type tokenObservation struct {
	Bearer      int
	TOTP        int
	CapTokenMin int
}

// probeTokens generates a real bearer token and TOTP secret and measures the
// decoded sizes; it also finds the capability-token HMAC key minimum by
// probing the verifier constructor.
func probeTokens() (tokenObservation, error) {
	var obs tokenObservation
	tok, err := auth.GenerateToken()
	if err != nil {
		return obs, err
	}
	raw, err := base64.URLEncoding.DecodeString(tok)
	if err != nil {
		return obs, fmt.Errorf("bearer token is not urlsafe base64: %w", err)
	}
	obs.Bearer = len(raw)
	keychain.Wipe(raw)

	sec, err := totp.GenerateSecret(totp.DefaultSecretLength)
	if err != nil {
		return obs, err
	}
	rawTOTP, err := totp.DecodeSecret(sec)
	if err != nil {
		return obs, err
	}
	obs.TOTP = len(rawTOTP)
	keychain.Wipe(rawTOTP)

	for n := 1; n <= 64; n++ {
		if _, err := captoken.NewHMACTokenVerifier(make([]byte, n)); err == nil {
			obs.CapTokenMin = n
			break
		}
	}
	if obs.Bearer != 32 {
		return obs, fmt.Errorf("bearer token is %d bytes, want 32", obs.Bearer)
	}
	if obs.TOTP != totp.DefaultSecretLength {
		return obs, fmt.Errorf("TOTP secret is %d bytes, want %d", obs.TOTP, totp.DefaultSecretLength)
	}
	if obs.CapTokenMin != captoken.MinSecretLen {
		return obs, fmt.Errorf("capability-token HMAC key minimum is %d bytes, want %d", obs.CapTokenMin, captoken.MinSecretLen)
	}
	return obs, nil
}

func probeResult(err error) liveProbeInfo {
	if err != nil {
		return liveProbeInfo{OK: false, Error: err.Error()}
	}
	return liveProbeInfo{OK: true}
}
