package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rgt-vault-server/internal/crypto"
	"rgt-vault-server/internal/kdf"
	"rgt-vault-server/internal/keychain"
)

func TestCryptoAuditRegisteredAndTextOutput(t *testing.T) {
	isolateEnv(t)
	code, stdout, stderr := runCLI(t, "", "crypto-audit")
	if code != 0 {
		t.Fatalf("crypto-audit exit %d, stderr=%q, stdout=%q", code, stderr, stdout)
	}
	for _, want := range []string{
		"AES-256-GCM",
		"256-bit key, 96-bit nonce, 128-bit tag",
		"Argon2id -> HKDF-SHA512 -> HKDF-SHA256",
		"memory=262144 KiB (256 MiB), time=4, parallelism=4, salt=32 bytes",
		"master=32 B, DEK=32 B, KEK=32 B",
		"CSPRNG:",
		"SelfTest (KAT):   PASS",
		"Overall:          PASS",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("crypto-audit stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestCryptoAuditJSONAndPolicy(t *testing.T) {
	isolateEnv(t)
	dir := t.TempDir()
	polPath := filepath.Join(dir, "crypto-policy.yaml")
	if err := os.WriteFile(polPath, []byte("min_argon2_memory_mb: 512\nmin_argon2_time_cost: 6\nmax_encryptions_per_dek: 1000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runCLI(t, "", "crypto-audit", "--json", "--policy", polPath)
	if code != 0 {
		t.Fatalf("crypto-audit --json exit %d, stderr=%q", code, stderr)
	}
	var report cryptoAuditReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("unmarshal JSON report: %v\nraw:\n%s", err, stdout)
	}
	if !report.OK || !report.CSPRNG.OK || !report.SelfTest.OK {
		t.Fatalf("expected OK report, got %+v", report)
	}
	if report.Cipher.Algorithm != "AES-256-GCM" || report.Cipher.KeyBytes != 32 || report.Cipher.NonceBytes != 12 || report.Cipher.TagBytes != 16 {
		t.Fatalf("unexpected cipher info: %+v", report.Cipher)
	}
	if report.KDF.PolicyMinMemoryKiB != 512*1024 || report.KDF.PolicyMinTimeCost != 6 || report.DEKRotation.PolicyMaxEncryptions != 1_000_000 {
		t.Fatalf("policy floors not reflected in report: %+v", report)
	}

	// Weakening policy is rejected with exit 1.
	weakPath := filepath.Join(dir, "weak.yaml")
	if err := os.WriteFile(weakPath, []byte("min_argon2_time_cost: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = runCLI(t, "", "crypto-audit", "--policy", weakPath)
	if code != 1 || !strings.Contains(stderr, "cannot weaken") {
		t.Fatalf("weak policy: exit %d stderr=%q", code, stderr)
	}
}

func TestCryptoAuditWithKeychainFile(t *testing.T) {
	isolateEnv(t)
	dir := t.TempDir()

	// Compliant v1 keychain.json.
	okKC := filepath.Join(dir, "ok-keychain.json")
	okJSON := `{
  "version": 1,
  "kdf": "argon2id",
  "argon2_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "argon2_memory_cost": 262144,
  "argon2_time_cost": 4,
  "argon2_parallelism": 4,
  "wrapped_dek": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "created_at": "2026-11-26T00:00:00+00:00",
  "key_epoch": 1
}`
	if err := os.WriteFile(okKC, []byte(okJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI(t, "", "crypto-audit", "--keychain", okKC)
	if code != 0 || !strings.Contains(stdout, "Keychain File:") || !strings.Contains(stdout, "PASS") {
		t.Fatalf("compliant keychain: exit %d stdout=%q stderr=%q", code, stdout, stderr)
	}

	// Non-compliant real keychain with weak Argon2 params fails audit.
	weakKC := filepath.Join(dir, "weak-keychain.json")
	mgr := keychain.New(weakKC)
	defer mgr.Close()
	if _, err := mgr.Initialize(bytes.Repeat([]byte{0x11}, 32), "11111111-2222-4333-8444-555555555555", 1, kdf.Params{MemoryCost: 1024, TimeCost: 1, Parallelism: 1}); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runCLI(t, "", "crypto-audit", "--keychain", weakKC)
	if code != 1 || !strings.Contains(stdout, "violation:") || !strings.Contains(stdout, "Overall:          FAIL") {
		t.Fatalf("weak keychain: exit %d stdout=%q stderr=%q", code, stdout, stderr)
	}

	// Missing keychain returns error.
	code, _, stderr = runCLI(t, "", "crypto-audit", "--keychain", filepath.Join(dir, "missing.json"))
	if code != 1 || !strings.Contains(stderr, "inspect keychain") {
		t.Fatalf("missing keychain: exit %d stderr=%q", code, stderr)
	}
}

func TestCryptoAuditFailurePaths(t *testing.T) {
	isolateEnv(t)

	// SelfTest failure fails closed with exit 1.
	origST := cryptoAuditSelfTest
	t.Cleanup(func() { cryptoAuditSelfTest = origST })
	cryptoAuditSelfTest = func() error { return errors.New("synthetic KAT mismatch") }

	code, stdout, stderr := runCLI(t, "", "crypto-audit")
	if code != 1 || !strings.Contains(stdout, "SelfTest (KAT):   FAIL (synthetic KAT mismatch)") || !strings.Contains(stderr, "crypto-audit failed") {
		t.Fatalf("selftest fail: exit %d stdout=%q stderr=%q", code, stdout, stderr)
	}
	cryptoAuditSelfTest = origST

	// CSPRNG error fails closed.
	origRand := cryptoAuditRandRead
	t.Cleanup(func() { cryptoAuditRandRead = origRand })
	cryptoAuditRandRead = func(b []byte) (int, error) { return 0, errors.New("entropy unavailable") }

	code, stdout, _ = runCLI(t, "", "crypto-audit")
	if code != 1 || !strings.Contains(stdout, "FAIL (entropy unavailable)") {
		t.Fatalf("rand err: exit %d stdout=%q", code, stdout)
	}

	// CSPRNG short read fails closed.
	cryptoAuditRandRead = func(b []byte) (int, error) { return 4, nil }
	code, stdout, _ = runCLI(t, "", "crypto-audit")
	if code != 1 || !strings.Contains(stdout, "short read: 4/32 bytes") {
		t.Fatalf("rand short read: exit %d stdout=%q", code, stdout)
	}

	// CSPRNG all-zero output fails closed.
	cryptoAuditRandRead = func(b []byte) (int, error) {
		clear(b)
		return len(b), nil
	}
	code, stdout, _ = runCLI(t, "", "crypto-audit")
	if code != 1 || !strings.Contains(stdout, "32 zero bytes") {
		t.Fatalf("rand all zero: exit %d stdout=%q", code, stdout)
	}
}

func TestFormatByteSize(t *testing.T) {
	cases := map[int64]string{
		512 * (1 << 30):  "512 GiB",
		1536 * (1 << 20): "1.50 GiB",
		4 * (1 << 20):    "4 MiB",
		1536 * 1024:      "1.50 MiB",
		4096:             "4096 B",
	}
	for in, want := range cases {
		if got := formatByteSize(in); got != want {
			t.Errorf("formatByteSize(%d) = %q, want %q", in, got, want)
		}
	}
}

// TestCryptoAuditLivePinnedValues pins the numbers crypto-audit reports. They
// are measured from real ciphertext, a real keychain.json and real token
// generators, so this test fails if the code (not just the printout) drifts.
func TestCryptoAuditLivePinnedValues(t *testing.T) {
	isolateEnv(t)
	code, stdout, stderr := runCLI(t, "", "crypto-audit", "--json")
	if code != 0 {
		t.Fatalf("exit %d stderr=%q stdout=%q", code, stderr, stdout)
	}
	var r cryptoAuditReport
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatal(err)
	}
	if !r.LiveProbes.Cipher.OK || !r.LiveProbes.Keychain.OK || !r.LiveProbes.Tokens.OK {
		t.Fatalf("live probes not OK: %+v", r.LiveProbes)
	}
	if r.Cipher.KeyBytes != 32 || r.Cipher.NonceBytes != 12 || r.Cipher.TagBytes != 16 {
		t.Errorf("cipher sizes drifted: %+v", r.Cipher)
	}
	if want := (kdf.Params{MemoryCost: 262144, TimeCost: 4, Parallelism: 4}); r.KDF.DefaultParams != want {
		t.Errorf("default Argon2 params drifted: got %+v want %+v", r.KDF.DefaultParams, want)
	}
	if r.KDF.DefaultSaltBytes != 32 {
		t.Errorf("salt bytes drifted: %d", r.KDF.DefaultSaltBytes)
	}
	ks := r.KeySizes
	if ks.MasterSecretBytes != 32 || ks.DEKBytes != 32 || ks.KEKBytes != 32 ||
		ks.BearerTokenBytes != 32 || ks.CapTokenMinBytes != 32 || ks.TOTPSecretDefault != 20 {
		t.Errorf("key sizes drifted: %+v", ks)
	}
	if r.Calibration.Params != r.KDF.DefaultParams || r.Calibration.ElapsedMS < 0 || r.Calibration.Note == "" {
		t.Errorf("calibration report malformed: %+v", r.Calibration)
	}
}

// TestCryptoAuditDetectsCipherDrift injects drifting Encrypt/Decrypt
// implementations and requires crypto-audit to report FAIL instead of
// printing the frozen constants.
func TestCryptoAuditDetectsCipherDrift(t *testing.T) {
	isolateEnv(t)
	origEnc, origDec := cryptoAuditEncrypt, cryptoAuditDecrypt
	t.Cleanup(func() { cryptoAuditEncrypt, cryptoAuditDecrypt = origEnc, origDec })

	// 8-byte nonce instead of 12.
	cryptoAuditEncrypt = func(pt, key, aad []byte) ([]byte, error) {
		if len(key) != 32 {
			return crypto.Encrypt(pt, key, aad)
		}
		block, _ := aes.NewCipher(key)
		g, err := cipher.NewGCMWithNonceSize(block, 8)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, 8)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		return g.Seal(nonce, nonce, pt, aad), nil
	}
	code, stdout, _ := runCLI(t, "", "crypto-audit")
	if code != 1 || !strings.Contains(stdout, "Encrypt/Decrypt round trip, nonce/tag from real ciphertext — FAIL") {
		t.Fatalf("short nonce not detected: exit %d\n%s", code, stdout)
	}

	// Decrypt that ignores the AAD.
	cryptoAuditEncrypt = origEnc
	cryptoAuditDecrypt = func(token, key, _ []byte) ([]byte, error) {
		// Decrypt with the AAD the probe used, whatever is asked.
		return origDec(token, key, []byte("crypto-audit-probe:aad"))
	}
	code, stdout, _ = runCLI(t, "", "crypto-audit")
	if code != 1 || !strings.Contains(stdout, "FAIL (Decrypt accepted a wrong AAD)") {
		t.Fatalf("AAD-ignoring Decrypt not detected: exit %d\n%s", code, stdout)
	}

	// A tag-ignoring Decrypt.
	cryptoAuditDecrypt = func(token, key, aad []byte) ([]byte, error) {
		if len(key) != 32 || len(token) < 28 {
			return origDec(token, key, aad)
		}
		return token[12 : len(token)-16], nil
	}
	code, stdout, _ = runCLI(t, "", "crypto-audit")
	if code != 1 || !strings.Contains(stdout, "FAIL") {
		t.Fatalf("tag-ignoring Decrypt not detected: exit %d\n%s", code, stdout)
	}
}
