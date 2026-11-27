package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rgt-vault-server/internal/crypto"
	"rgt-vault-server/internal/cryptopolicy"
	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/keychain"
	"rgt-vault-server/internal/store"
)

const asvsV6Policy = `
rules:
  - agent: "*"
    namespace: "*"
    purpose: "*"
    actions: ["read", "write", "revoke"]
    effect: allow
`

type asvsRotatableProvider struct {
	secret []byte
}

func (p *asvsRotatableProvider) GetMasterSecret() ([]byte, error) {
	return append([]byte(nil), p.secret...), nil
}

func (p *asvsRotatableProvider) RotateMasterSecret() ([]byte, error) {
	next := make([]byte, len(p.secret))
	for i, b := range p.secret {
		next[i] = b ^ 0x55
	}
	p.secret = next
	return append([]byte(nil), next...), nil
}

func openASVSVault(t *testing.T, prov MasterProvider) (*Vault, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vault.db")
	v, err := Open(context.Background(), Config{
		DBPath:     dbPath,
		Provider:   prov,
		PolicyYAML: asvsV6Policy,
		KDFParams:  kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1},
	})
	if err != nil {
		t.Fatalf("vault.Open: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v, dir
}

// TestASVSV6_VaultCiphertextStructure12ByteNonce verifies ASVS 6.2.3 (RGT-398)
// and 6.2.7 (RGT-402) on REAL vault ciphertext persisted in SQLite:
//   - stored blob length is 12 (nonce) + len(plaintext) + 16 (GCM tag);
//   - ct[:12] is the 96-bit AES-256-GCM nonce;
//   - manual decryption with stdlib aes.NewCipher(32B DEK) + cipher.NewGCM and
//     AAD = "vault_id:namespace:name" reproduces the exact plaintext.
func TestASVSV6_VaultCiphertextStructure12ByteNonce(t *testing.T) {
	ctx := context.Background()
	prov := &asvsRotatableProvider{secret: bytes.Repeat([]byte{0x21}, 32)}
	v, _ := openASVSVault(t, prov)

	plaintext := []byte("super-secret-api-token-for-asvs-v6-verification")
	if err := v.SetSecret(ctx, SetSecretRequest{
		Namespace: "prod",
		Name:      "stripe_key",
		Agent:     "agent-1",
		Purpose:   "billing",
		Value:     plaintext,
	}); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	var storedCT []byte
	var dekVer int64
	if err := v.aux.QueryRowContext(ctx,
		"SELECT ciphertext, dek_version FROM secrets WHERE namespace = 'prod' AND name = 'stripe_key' AND status = 'ACTIVE'",
	).Scan(&storedCT, &dekVer); err != nil {
		t.Fatalf("read stored ciphertext: %v", err)
	}

	if dekVer != 1 {
		t.Fatalf("dek_version = %d, want 1", dekVer)
	}
	wantLen := 12 + len(plaintext) + 16
	if len(storedCT) != wantLen {
		t.Fatalf("stored ciphertext length = %d, want %d (12B nonce + %dB PT + 16B tag)", len(storedCT), wantLen, len(plaintext))
	}

	// Manually decrypt the raw SQLite BLOB using stdlib AES-256-GCM directly
	// to prove wire format and AAD binding independently of internal/crypto.
	v.mu.RLock()
	dek := append([]byte(nil), v.dek...)
	v.mu.RUnlock()
	defer keychain.Wipe(dek)

	if len(dek) != 32 {
		t.Fatalf("DEK length = %d, want 32 (AES-256)", len(dek))
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	if gcm.NonceSize() != 12 || gcm.Overhead() != 16 {
		t.Fatalf("GCM params nonce=%d tag=%d, want 12/16", gcm.NonceSize(), gcm.Overhead())
	}

	nonce := storedCT[:12]
	bodyAndTag := storedCT[12:]
	aad := []byte(v.VaultID() + ":prod:stripe_key")

	pt, err := gcm.Open(nil, nonce, bodyAndTag, aad)
	if err != nil {
		t.Fatalf("manual AES-256-GCM decrypt of real vault.db blob failed: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("decrypted plaintext = %q, want %q", pt, plaintext)
	}

	// Wrong AAD must fail authentication.
	if _, err := gcm.Open(nil, nonce, bodyAndTag, []byte(v.VaultID()+":prod:other_key")); err == nil {
		t.Fatal("AES-GCM Open succeeded with wrong AAD")
	}
}

// TestASVSV6_VaultNonceUniqueness verifies ASVS 6.2.6 (RGT-401):
// across N=200 real vault encryptions (same plaintext and name -> 200 versions
// in SQLite), every 12-byte GCM nonce stored in vault.db is unique.
func TestASVSV6_VaultNonceUniqueness(t *testing.T) {
	ctx := context.Background()
	prov := &asvsRotatableProvider{secret: bytes.Repeat([]byte{0x33}, 32)}
	v, _ := openASVSVault(t, prov)

	const n = 200
	samePlaintext := []byte("identical-plaintext-every-version")
	for i := 0; i < n; i++ {
		if err := v.SetSecret(ctx, SetSecretRequest{
			Namespace: "default",
			Name:      "repeated_secret",
			Agent:     "agent-1",
			Purpose:   "test",
			Value:     samePlaintext,
		}); err != nil {
			t.Fatalf("SetSecret #%d: %v", i, err)
		}
	}

	rows, err := v.aux.QueryContext(ctx, "SELECT ciphertext FROM secrets WHERE name = 'repeated_secret'")
	if err != nil {
		t.Fatalf("query ciphertexts: %v", err)
	}
	defer rows.Close()

	seenNonces := make(map[[12]byte]struct{}, n)
	count := 0
	for rows.Next() {
		var ct []byte
		if err := rows.Scan(&ct); err != nil {
			t.Fatal(err)
		}
		if len(ct) != 12+len(samePlaintext)+16 {
			t.Fatalf("row %d ciphertext len = %d, want %d", count, len(ct), 12+len(samePlaintext)+16)
		}
		var nonce [12]byte
		copy(nonce[:], ct[:12])
		if _, dup := seenNonces[nonce]; dup {
			t.Fatalf("duplicate 12-byte GCM nonce detected at row %d: %x", count, nonce)
		}
		seenNonces[nonce] = struct{}{}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != n {
		t.Fatalf("scanned %d ciphertext rows, want %d", count, n)
	}
}

// TestASVSV6_VaultPlaintextAndDEKNeverOnDisk verifies ASVS 6.1.1 (RGT-393) and
// 1.6.2 (RGT-244): after creating a vault and storing a secret, scanning every
// file on disk (vault.db, WAL/SHM if present, keychain.json) never finds the
// secret plaintext, the DEK, or the master secret in raw, hex, or base64 forms.
func TestASVSV6_VaultPlaintextAndDEKNeverOnDisk(t *testing.T) {
	ctx := context.Background()
	master := []byte("MasterSecretBytes_ASVS_V6_Check!")
	prov := &asvsRotatableProvider{secret: master}
	v, dir := openASVSVault(t, prov)

	secretVal := []byte("TOP_SECRET_PII_SSN_999_00_1234_DO_NOT_PERSIST_CLEAR")
	if err := v.SetSecret(ctx, SetSecretRequest{
		Namespace: "pii",
		Name:      "customer_ssn",
		Agent:     "agent-1",
		Purpose:   "verify",
		Value:     secretVal,
	}); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	v.mu.RLock()
	dek := append([]byte(nil), v.dek...)
	v.mu.RUnlock()
	defer keychain.Wipe(dek)

	// Force a WAL checkpoint and close so everything is flushed into vault.db.
	if _, err := v.aux.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatalf("wal_checkpoint: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	needles := map[string][]byte{
		"plaintext-raw":  secretVal,
		"plaintext-b64":  []byte(base64.StdEncoding.EncodeToString(secretVal)),
		"dek-raw":        dek,
		"dek-hex":        []byte(hex.EncodeToString(dek)),
		"dek-std-b64":    []byte(base64.StdEncoding.EncodeToString(dek)),
		"dek-url-b64":    []byte(base64.RawURLEncoding.EncodeToString(dek)),
		"master-raw":     master,
		"master-hex":     []byte(hex.EncodeToString(master)),
		"master-std-b64": []byte(base64.StdEncoding.EncodeToString(master)),
		"master-url-b64": []byte(base64.RawURLEncoding.EncodeToString(master)),
	}

	scanned := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for label, needle := range needles {
			if bytes.Contains(data, needle) {
				t.Fatalf("file %s contains %s in clear", e.Name(), label)
			}
		}
	}
	if scanned < 2 {
		t.Fatalf("expected to scan at least vault.db and keychain.json, scanned %d files", scanned)
	}
}

// TestASVSV6_VaultTamperingFailsClosedGenerically verifies ASVS 6.2.1 (RGT-396)
// and 6.2.7 (RGT-402):
// (1) raw DB tamper without updating checksum is caught by store.ErrChecksum;
// (2) tampering with ciphertext, nonce, GCM tag, or swapping ciphertexts across
//
//	names (breaking AAD vault_id:namespace:name) even WITH a recomputed SQLite
//	checksum fails closed at AES-GCM with the single generic error
//	crypto.ErrDecryptionFailed without leaking key, AAD, tag, or plaintext.
func TestASVSV6_VaultTamperingFailsClosedGenerically(t *testing.T) {
	ctx := context.Background()
	prov := &asvsRotatableProvider{secret: bytes.Repeat([]byte{0x44}, 32)}
	v, _ := openASVSVault(t, prov)

	for _, name := range []string{"alpha", "beta"} {
		if err := v.SetSecret(ctx, SetSecretRequest{
			Namespace: "default",
			Name:      name,
			Agent:     "agent-1",
			Purpose:   "test",
			Value:     []byte("secret-value-for-" + name),
		}); err != nil {
			t.Fatalf("SetSecret(%s): %v", name, err)
		}
	}

	readCT := func(name string) []byte {
		t.Helper()
		var ct []byte
		if err := v.aux.QueryRowContext(ctx,
			"SELECT ciphertext FROM secrets WHERE name = ? AND status = 'ACTIVE'", name,
		).Scan(&ct); err != nil {
			t.Fatal(err)
		}
		return ct
	}
	writeCT := func(name string, ct []byte, updateChecksum bool) {
		t.Helper()
		if updateChecksum {
			sum := sha256.Sum256(ct)
			if _, err := v.aux.ExecContext(ctx,
				"UPDATE secrets SET ciphertext = ?, checksum = ? WHERE name = ? AND status = 'ACTIVE'",
				ct, hex.EncodeToString(sum[:]), name); err != nil {
				t.Fatal(err)
			}
			return
		}
		if _, err := v.aux.ExecContext(ctx,
			"UPDATE secrets SET ciphertext = ? WHERE name = ? AND status = 'ACTIVE'", ct, name); err != nil {
			t.Fatal(err)
		}
	}

	alphaOrig := readCT("alpha")
	betaOrig := readCT("beta")

	// 1. Tamper without updating checksum -> caught at storage layer (store.ErrChecksum).
	rawTamper := bytes.Clone(alphaOrig)
	rawTamper[len(rawTamper)-1] ^= 0x01
	writeCT("alpha", rawTamper, false)
	err := v.Lease(ctx, LeaseRequest{Namespace: "default", Name: "alpha", Agent: "agent-1", Purpose: "test"}, func(s []byte) error {
		t.Error("callback must never run on tampered ciphertext")
		return nil
	})
	if !errors.Is(err, store.ErrChecksum) {
		t.Fatalf("tampered without checksum update: got %v, want store.ErrChecksum", err)
	}

	// 2. Tamper nonce, body, tag, and swap ciphertext across names (AAD mismatch),
	// updating the SQLite SHA-256 checksum so the AES-256-GCM layer is exercised.
	flipAt := func(src []byte, idx int) []byte {
		out := bytes.Clone(src)
		out[idx] ^= 0x01
		return out
	}
	gcmCases := []struct {
		name string
		ct   []byte
	}{
		{"tampered nonce", flipAt(alphaOrig, 0)},
		{"tampered ciphertext body", flipAt(alphaOrig, 15)},
		{"tampered GCM tag", flipAt(alphaOrig, len(alphaOrig)-1)},
		{"cross-secret ciphertext swap (AAD mismatch)", bytes.Clone(betaOrig)},
	}

	var canonicalMsg string
	for _, tc := range gcmCases {
		t.Run(tc.name, func(t *testing.T) {
			writeCT("alpha", tc.ct, true)
			err := v.Lease(ctx, LeaseRequest{Namespace: "default", Name: "alpha", Agent: "agent-1", Purpose: "test"}, func(s []byte) error {
				t.Error("callback must never execute on GCM authentication failure")
				return nil
			})
			if !errors.Is(err, crypto.ErrDecryptionFailed) {
				t.Fatalf("%s: got %v, want crypto.ErrDecryptionFailed", tc.name, err)
			}
			msg := err.Error()
			if canonicalMsg == "" {
				canonicalMsg = msg
			} else if msg != canonicalMsg {
				t.Errorf("error message diverged across GCM failure modes: %q vs %q", msg, canonicalMsg)
			}
			lower := strings.ToLower(msg)
			for _, leak := range []string{"aad", "nonce", "tag", "key", "alpha", "beta", "secret-value"} {
				if strings.Contains(lower, leak) {
					t.Errorf("error message %q leaks %q", msg, leak)
				}
			}
		})
	}
}

// TestASVSV6_VaultCloseAndLeaseZeroizeKeyMaterial verifies ASVS 6.4.2 (RGT-408)
// best-effort zeroization in Go:
// - Lease() overwrites the plaintext buffer after callback return (and on error);
// - Close() overwrites v.dek in-place with zero bytes.
func TestASVSV6_VaultCloseAndLeaseZeroizeKeyMaterial(t *testing.T) {
	ctx := context.Background()
	prov := &asvsRotatableProvider{secret: bytes.Repeat([]byte{0x55}, 32)}
	v, _ := openASVSVault(t, prov)

	want := []byte("ephemeral-leased-secret-value")
	if err := v.SetSecret(ctx, SetSecretRequest{
		Namespace: "default",
		Name:      "leased",
		Agent:     "agent-1",
		Purpose:   "test",
		Value:     want,
	}); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	// Capture the slice header passed to Lease callback (without copying) and
	// verify it is zeroed as soon as Lease returns.
	var leasedBuf []byte
	if err := v.Lease(ctx, LeaseRequest{Namespace: "default", Name: "leased", Agent: "agent-1", Purpose: "test"}, func(s []byte) error {
		if !bytes.Equal(s, want) {
			t.Fatalf("Lease got %q, want %q", s, want)
		}
		leasedBuf = s
		return nil
	}); err != nil {
		t.Fatalf("Lease: %v", err)
	}
	for i, b := range leasedBuf {
		if b != 0 {
			t.Fatalf("leased plaintext byte %d not zeroed after Lease return (got 0x%02x)", i, b)
		}
	}

	// Also verify zeroization when callback returns an error.
	var errBuf []byte
	cbErr := errors.New("caller failed")
	err := v.Lease(ctx, LeaseRequest{Namespace: "default", Name: "leased", Agent: "agent-1", Purpose: "test"}, func(s []byte) error {
		errBuf = s
		return cbErr
	})
	if !errors.Is(err, cbErr) {
		t.Fatalf("Lease err = %v, want %v", err, cbErr)
	}
	for i, b := range errBuf {
		if b != 0 {
			t.Fatalf("leased plaintext byte %d not zeroed after callback error (got 0x%02x)", i, b)
		}
	}

	// Capture backing array of v.dek and verify Close() zeroes it in-place.
	v.mu.RLock()
	dekBacking := v.dek
	v.mu.RUnlock()
	if len(dekBacking) != 32 {
		t.Fatalf("v.dek len = %d, want 32", len(dekBacking))
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for i, b := range dekBacking {
		if b != 0 {
			t.Fatalf("v.dek byte %d not zeroed after Vault.Close (got 0x%02x)", i, b)
		}
	}
}

// TestASVSV6_VaultRotationAndPolicyAlignment verifies ASVS 1.6.3 (RGT-245),
// 6.2.6 (RGT-401), and RGT-220 constant parity:
//   - DEKMaxEncryptions / DEKMaxBytes match cryptopolicy defaults;
//   - RotateDEK replaces the DEK, re-encrypts secrets with new ciphertexts/nonces,
//     and bumps key_epoch;
//   - RotateMaster re-wraps under a rotated master secret and bumps key_epoch;
//   - restoring a stale keychain.json from an older epoch fails closed with ErrRollback.
func TestASVSV6_VaultRotationAndPolicyAlignment(t *testing.T) {
	pol := cryptopolicy.Default()
	if DEKMaxEncryptions != pol.MaxEncryptionsPerDEK {
		t.Fatalf("DEKMaxEncryptions=%d != cryptopolicy default %d", DEKMaxEncryptions, pol.MaxEncryptionsPerDEK)
	}
	if DEKMaxBytes != pol.MaxBytesPerDEK {
		t.Fatalf("DEKMaxBytes=%d != cryptopolicy default %d", DEKMaxBytes, pol.MaxBytesPerDEK)
	}

	ctx := context.Background()
	prov := &asvsRotatableProvider{secret: bytes.Repeat([]byte{0x66}, 32)}
	v, dir := openASVSVault(t, prov)

	secret := []byte("value-across-rotations")
	if err := v.SetSecret(ctx, SetSecretRequest{
		Namespace: "default", Name: "rot", Agent: "agent-1", Purpose: "test", Value: secret,
	}); err != nil {
		t.Fatal(err)
	}

	// Snapshot epoch 1 keychain.json, DEK, and ciphertext.
	oldKeychainBytes, err := os.ReadFile(v.KeychainPath())
	if err != nil {
		t.Fatal(err)
	}
	v.mu.RLock()
	dek1 := append([]byte(nil), v.dek...)
	v.mu.RUnlock()
	defer keychain.Wipe(dek1)

	var ct1 []byte
	if err := v.aux.QueryRowContext(ctx, "SELECT ciphertext FROM secrets WHERE name = 'rot'").Scan(&ct1); err != nil {
		t.Fatal(err)
	}

	// RotateDEK -> new DEK, new ciphertext, new nonce, epoch 2.
	if err := v.RotateDEK(ctx); err != nil {
		t.Fatalf("RotateDEK: %v", err)
	}
	if v.KeyEpoch() != 2 {
		t.Fatalf("KeyEpoch after RotateDEK = %d, want 2", v.KeyEpoch())
	}
	v.mu.RLock()
	dek2 := append([]byte(nil), v.dek...)
	v.mu.RUnlock()
	defer keychain.Wipe(dek2)
	if bytes.Equal(dek1, dek2) {
		t.Fatal("RotateDEK did not replace DEK")
	}

	var ct2 []byte
	if err := v.aux.QueryRowContext(ctx, "SELECT ciphertext FROM secrets WHERE name = 'rot'").Scan(&ct2); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct1, ct2) || bytes.Equal(ct1[:12], ct2[:12]) {
		t.Fatal("RotateDEK did not re-encrypt secret with a fresh nonce")
	}

	// Secret still leases identically after RotateDEK.
	if err := v.Lease(ctx, LeaseRequest{Namespace: "default", Name: "rot", Agent: "agent-1", Purpose: "test"}, func(s []byte) error {
		if !bytes.Equal(s, secret) {
			return fmt.Errorf("got %q, want %q", s, secret)
		}
		return nil
	}); err != nil {
		t.Fatalf("Lease after RotateDEK: %v", err)
	}

	// RotateMaster -> same DEK, new master secret, epoch 3.
	if err := v.RotateMaster(ctx); err != nil {
		t.Fatalf("RotateMaster: %v", err)
	}
	if v.KeyEpoch() != 3 {
		t.Fatalf("KeyEpoch after RotateMaster = %d, want 3", v.KeyEpoch())
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	// Replacing keychain.json with epoch-1 snapshot must fail closed on Open (rollback protection).
	if err := os.WriteFile(filepath.Join(dir, keychain.FileName), oldKeychainBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Open(ctx, Config{
		DBPath:     filepath.Join(dir, "vault.db"),
		Provider:   prov,
		PolicyYAML: asvsV6Policy,
		KDFParams:  kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1},
	})
	if !errors.Is(err, keychain.ErrRollback) {
		t.Fatalf("Open with rolled-back keychain.json: got %v, want keychain.ErrRollback", err)
	}
}
