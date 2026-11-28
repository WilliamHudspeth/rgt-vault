package keychain

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/kdf"
)

// TestASVSV6_KeychainCloseZeroizesDEK verifies ASVS 6.4.2 (RGT-408) best-effort
// zeroization: Manager.Close() overwrites the internal m.dek backing array with
// zero bytes in-place and clears m.dek.
func TestASVSV6_KeychainCloseZeroizesDEK(t *testing.T) {
	kcPath := filepath.Join(t.TempDir(), FileName)
	mgr := New(kcPath)
	master := bytes.Repeat([]byte{0xA5}, 32)
	dekCopy, err := mgr.Initialize(master, "11111111-2222-4333-8444-555555555555", 1, small)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	defer Wipe(dekCopy)

	// Capture a reference to the Manager's internal DEK slice backing array.
	mgr.mu.Lock()
	internalSlice := mgr.dek
	mgr.mu.Unlock()
	if len(internalSlice) != DEKSize {
		t.Fatalf("internal DEK length = %d, want %d", len(internalSlice), DEKSize)
	}
	if !bytes.Equal(internalSlice, dekCopy) {
		t.Fatal("internal DEK did not match returned DEK before Close")
	}

	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Backing array must now be all zeros.
	for i, b := range internalSlice {
		if b != 0 {
			t.Fatalf("internal DEK byte %d not zeroed after Close (got 0x%02x)", i, b)
		}
	}
	if _, err := mgr.ActiveDEK(); !errors.Is(err, ErrDEKNotLoaded) {
		t.Fatalf("ActiveDEK after Close: got %v, want ErrDEKNotLoaded", err)
	}
}

// TestASVSV6_KeychainDEKNeverPersistedInClear verifies ASVS 6.1.1 (RGT-393) and
// 1.6.2 (RGT-244): neither the DEK nor the master secret appears in clear (raw,
// hex, std-base64, or url-base64) inside keychain.json.
func TestASVSV6_KeychainDEKNeverPersistedInClear(t *testing.T) {
	kcPath := filepath.Join(t.TempDir(), FileName)
	mgr := New(kcPath)
	defer mgr.Close()

	master := []byte("0123456789abcdef0123456789ABCDEF")
	dek, err := mgr.Initialize(master, "11111111-2222-4333-8444-555555555555", 1, small)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	defer Wipe(dek)

	raw, err := os.ReadFile(kcPath)
	if err != nil {
		t.Fatalf("read keychain.json: %v", err)
	}

	for label, secret := range map[string][]byte{"DEK": dek, "master": master} {
		encodings := map[string][]byte{
			"raw":        secret,
			"hex":        []byte(hex.EncodeToString(secret)),
			"std-base64": []byte(base64.StdEncoding.EncodeToString(secret)),
			"url-base64": []byte(base64.RawURLEncoding.EncodeToString(secret)),
		}
		for encName, needle := range encodings {
			if bytes.Contains(raw, needle) {
				t.Fatalf("keychain.json leaked %s in %s form", label, encName)
			}
		}
	}
}

// TestASVSV6_KeychainSaltUniqueness verifies ASVS 6.2.6 (RGT-401):
// every Initialize and Rewrap uses a fresh 32-byte random salt so the
// KDF-derived (KEK, nonce) pair is never reused.
func TestASVSV6_KeychainSaltUniqueness(t *testing.T) {
	kcPath := filepath.Join(t.TempDir(), FileName)
	mgr := New(kcPath)
	defer mgr.Close()

	master := bytes.Repeat([]byte{0x3C}, 32)
	vid := "11111111-2222-4333-8444-555555555555"
	salts := make(map[string]struct{}, 20)

	dek, err := mgr.Initialize(master, vid, 1, small)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	Wipe(dek)

	recordSalt := func(step int) {
		t.Helper()
		raw, err := os.ReadFile(kcPath)
		if err != nil {
			t.Fatal(err)
		}
		var doc fileV1
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		saltBytes, err := base64.StdEncoding.DecodeString(doc.Argon2Salt)
		if err != nil {
			t.Fatal(err)
		}
		if len(saltBytes) != SaltSize {
			t.Fatalf("step %d: salt length = %d, want %d", step, len(saltBytes), SaltSize)
		}
		if _, dup := salts[doc.Argon2Salt]; dup {
			t.Fatalf("step %d: duplicate Argon2 salt %q", step, doc.Argon2Salt)
		}
		salts[doc.Argon2Salt] = struct{}{}
	}

	recordSalt(0)
	for i := 1; i < 20; i++ {
		if err := mgr.Rewrap(master, vid, int64(i+1), small); err != nil {
			t.Fatalf("Rewrap %d: %v", i, err)
		}
		recordSalt(i)
	}
}

// TestASVSV6_KeychainTamperingFailsClosed verifies ASVS 6.2.1 (RGT-396) & 6.2.7 (RGT-402):
// wrong master, wrong vault_id (AAD), tampered wrapped_dek ciphertext, tampered
// GCM tag, and tampered salt all collapse to generic ErrUnwrapFailed without
// leaking which dimension failed; epoch rollback fails with ErrRollback.
func TestASVSV6_KeychainTamperingFailsClosed(t *testing.T) {
	dir := t.TempDir()
	kcPath := filepath.Join(dir, FileName)
	mgr := New(kcPath)
	defer mgr.Close()

	master := bytes.Repeat([]byte{0x5A}, 32)
	wrongMaster := bytes.Repeat([]byte{0xA5}, 32)
	vid := "11111111-2222-4333-8444-555555555555"
	if dek, err := mgr.Initialize(master, vid, 2, small); err != nil {
		t.Fatalf("Initialize: %v", err)
	} else {
		Wipe(dek)
	}

	origRaw, err := os.ReadFile(kcPath)
	if err != nil {
		t.Fatal(err)
	}

	writeMutated := func(name string, mutate func(d *fileV1)) string {
		t.Helper()
		var d fileV1
		if err := json.Unmarshal(origRaw, &d); err != nil {
			t.Fatal(err)
		}
		mutate(&d)
		b, err := json.MarshalIndent(d, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Tamper ciphertext body (byte 0 of wrapped_dek).
	tamperCT := writeMutated("tamper-ct.json", func(d *fileV1) {
		b, _ := base64.StdEncoding.DecodeString(d.WrappedDEK)
		b[0] ^= 0x01
		d.WrappedDEK = base64.StdEncoding.EncodeToString(b)
	})
	// Tamper GCM auth tag (last byte of wrapped_dek).
	tamperTag := writeMutated("tamper-tag.json", func(d *fileV1) {
		b, _ := base64.StdEncoding.DecodeString(d.WrappedDEK)
		b[len(b)-1] ^= 0x80
		d.WrappedDEK = base64.StdEncoding.EncodeToString(b)
	})
	// Tamper salt.
	tamperSalt := writeMutated("tamper-salt.json", func(d *fileV1) {
		b, _ := base64.StdEncoding.DecodeString(d.Argon2Salt)
		b[0] ^= 0xFF
		d.Argon2Salt = base64.StdEncoding.EncodeToString(b)
	})

	cases := []struct {
		name   string
		path   string
		master []byte
		vid    string
	}{
		{"wrong master", kcPath, wrongMaster, vid},
		{"wrong vault_id (AAD)", kcPath, master, "22222222-2222-4333-8444-555555555555"},
		{"tampered wrapped_dek ciphertext", tamperCT, master, vid},
		{"tampered wrapped_dek tag", tamperTag, master, vid},
		{"tampered salt", tamperSalt, master, vid},
	}
	var firstMsg string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := New(tc.path)
			defer m.Close()
			_, err := m.Load(tc.master, tc.vid, 2)
			if !errors.Is(err, ErrUnwrapFailed) {
				t.Fatalf("Load: got %v, want ErrUnwrapFailed", err)
			}
			msg := err.Error()
			if firstMsg == "" {
				firstMsg = msg
			} else if msg != firstMsg {
				t.Errorf("error message differs across failure modes: %q vs %q", msg, firstMsg)
			}
			for _, leak := range []string{"master", "aad", "tag", "salt", "vault"} {
				if strings.Contains(strings.ToLower(msg), leak) {
					t.Errorf("error message %q leaks %q", msg, leak)
				}
			}
		})
	}

	// Rollback epoch check fails closed with ErrRollback.
	m := New(kcPath)
	defer m.Close()
	if _, err := m.Load(master, vid, 3); !errors.Is(err, ErrRollback) {
		t.Fatalf("epoch rollback: got %v, want ErrRollback", err)
	}

	// SelfTest verifies KDF + wrap + wrong-AAD rejection + Python KAT.
	if err := SelfTest(); err != nil {
		t.Fatalf("SelfTest: %v", err)
	}
	// Verify default params match kdf.DefaultParams() when used with validateParams.
	if err := validateParams(kdf.DefaultParams()); err != nil {
		t.Fatalf("validateParams(DefaultParams): %v", err)
	}
}
