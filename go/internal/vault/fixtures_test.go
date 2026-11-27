package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"rgt-vault-server/internal/keychain"
)

var vaultFixtures = []string{"small", "default", "epoch1"}

// expectedRead is what Python's manifest says a by-version lease returns.
func expectedRead(s manifestSecret) string {
	if s.ReadByVersion == "ok" {
		return s.PlaintextSHA256
	}
	return s.ReadByVersion
}

// checkFixtureReads leases every stored row by version and the latest
// version of every name, and compares with the manifest.
func checkFixtureReads(t *testing.T, v *Vault, m manifest) {
	t.Helper()
	for _, s := range m.Secrets {
		if got, want := readVersion(t, v, s.Namespace, s.Name, s.Version), expectedRead(s); got != want {
			t.Errorf("%s/%s v%d (%s): got %s, want %s", s.Namespace, s.Name, s.Version, s.Status, got, want)
		}
		if s.ReadLatest != nil {
			want := *s.ReadLatest
			if want == "ok" {
				want = s.PlaintextSHA256
			}
			if got := readVersion(t, v, s.Namespace, s.Name, 0); got != want {
				t.Errorf("%s/%s latest: got %s, want %s", s.Namespace, s.Name, got, want)
			}
		}
	}
}

func TestOpenPythonFixtures(t *testing.T) {
	ctx := context.Background()
	for _, fx := range vaultFixtures {
		t.Run(fx, func(t *testing.T) {
			m := loadManifest(t, fx)
			db, prov := copyFixture(t, fx)
			v := openT(t, Config{DBPath: db, Provider: prov, PolicyYAML: fixturePolicy(t, fx)})

			if v.VaultID() != m.VaultID || v.KeyEpoch() != m.KeyEpoch {
				t.Fatalf("vault_id/epoch = %s/%d, want %s/%d", v.VaultID(), v.KeyEpoch(), m.VaultID, m.KeyEpoch)
			}
			if v.PolicyHash() != m.PolicyHash {
				t.Errorf("policy hash %q, want %q", v.PolicyHash(), m.PolicyHash)
			}

			// Chain verdict, first/last hash and size BEFORE Go touches it.
			ok, err := v.VerifyAuditChain(ctx)
			if err != nil || ok != m.Audit.Verify {
				t.Fatalf("verify = %v, %v; want %v", ok, err, m.Audit.Verify)
			}
			rows := auditRows(t, v)
			if len(rows) == 0 || rows[0].EntryHash != m.Audit.FirstHash || rows[len(rows)-1].EntryHash != m.Audit.LastHash {
				t.Fatalf("first/last entry hash differ from the manifest")
			}
			if int64(len(rows)) != m.RowCounts["audit_logs"] {
				t.Fatalf("audit rows %d, want %d", len(rows), m.RowCounts["audit_logs"])
			}

			// Export of the untouched vault is byte-identical to Python's.
			exp, err := v.Export(ctx)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(exp)
			if hex.EncodeToString(sum[:]) != m.Export.SHA256 {
				pyExp, _ := os.ReadFile(filepath.Join(pyvaultDir, fx, "export.b64"))
				t.Fatalf("export differs from Python's export_vault (len %d vs %d)", len(exp), len(pyExp))
			}

			// Fingerprints are checksum[:8] (honeytokens refuse).
			for _, s := range m.Secrets {
				if s.Status != "ACTIVE" {
					continue
				}
				fp, err := v.Fingerprint(ctx, s.Namespace, s.Name, s.Version)
				if s.Honeytoken {
					if !errors.Is(err, ErrHoneytoken) || !errors.Is(err, ErrPermission) {
						t.Errorf("fingerprint of honeytoken: %v", err)
					}
					continue
				}
				if err != nil || fp != s.Fingerprint {
					t.Errorf("fingerprint %s/%s = %q, %v; want %q", s.Namespace, s.Name, fp, err, s.Fingerprint)
				}
			}

			checkFixtureReads(t, v, m)
			mustVerify(t, v)
		})
	}
}

// TestFixtureWriteRotateReverify writes from Go, rotates the DEK and the
// master key, and checks every read again (RGT-499: versions that decrypted
// before the Go rotation still decrypt after it).
func TestFixtureWriteRotateReverify(t *testing.T) {
	ctx := context.Background()
	for _, fx := range vaultFixtures {
		t.Run(fx, func(t *testing.T) {
			m := loadManifest(t, fx)
			db, prov := copyFixture(t, fx)
			cfg := Config{DBPath: db, Provider: prov, PolicyYAML: fixturePolicy(t, fx)}
			v := openT(t, cfg)

			set(t, v, "go", "written-by-go", "go-v1")
			set(t, v, "go", "written-by-go", "go-v2")
			set(t, v, "go", "to-revoke", "revoked-value")
			if err := v.RevokeSecret(ctx, "go", "to-revoke", SystemAgent); err != nil {
				t.Fatal(err)
			}
			epoch := v.KeyEpoch()
			if err := v.RotateDEK(ctx); err != nil {
				t.Fatalf("RotateDEK: %v", err)
			}
			if err := v.RotateMaster(ctx); err != nil {
				t.Fatalf("RotateMaster: %v", err)
			}
			if v.KeyEpoch() != epoch+2 {
				t.Fatalf("epoch %d, want %d", v.KeyEpoch(), epoch+2)
			}
			check := func(v *Vault) {
				t.Helper()
				checkFixtureReads(t, v, m)
				for ver, want := range map[int64]string{1: "go-v1", 2: "go-v2"} {
					if got, err := get(t, v, "go", "written-by-go", ver); err != nil || got != want {
						t.Errorf("go v%d = %q, %v", ver, got, err)
					}
				}
				if got, err := get(t, v, "go", "to-revoke", 1); err != nil || got != "revoked-value" {
					t.Errorf("revoked version after RotateDEK = %q, %v", got, err)
				}
				mustVerify(t, v)
			}
			check(v)
			_ = v.Close()

			// Re-open from disk with the rotated master.
			check(openT(t, cfg))
		})
	}
}

func TestRollbackDetected(t *testing.T) {
	db, prov := copyFixture(t, "small")
	// epoch1's keychain (epoch 1) next to small's database (epoch 3).
	copyFile(t, filepath.Join(pyvaultDir, "epoch1", "keychain.json"), filepath.Join(filepath.Dir(db), "keychain.json"))
	_, err := Open(context.Background(), Config{DBPath: db, Provider: prov, KDFParams: testParams})
	if !errors.Is(err, keychain.ErrRollback) {
		t.Fatalf("want rollback error, got %v", err)
	}
}

func TestWrongMasterRefused(t *testing.T) {
	db, _ := copyFixture(t, "epoch1")
	other := filepath.Join(t.TempDir(), "other.bin")
	if err := os.WriteFile(other, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(context.Background(), Config{DBPath: db, Provider: fileProv(other), KDFParams: testParams})
	if !errors.Is(err, keychain.ErrUnwrapFailed) {
		t.Fatalf("want unwrap failure, got %v", err)
	}
}

// TestEdgeDatabases opens the G0 edge DBs with the vault layer: chain
// verdicts match Python's, and the legacy Fernet DB is refused (D3)
// without writing a keychain next to it.
func TestEdgeDatabases(t *testing.T) {
	ctx := context.Background()
	verdicts := map[string]bool{
		"chain_ok.db": true, "null_details_policy_ok.db": true, "null_details_hashed_empty.db": false,
		"tampered_details.db": false, "tampered_entry_hash.db": false, "tampered_timestamp.db": false,
		"deleted_middle.db": false, "agent_id_not_hashed.db": true, "empty.db": true,
	}
	for file, want := range verdicts {
		t.Run(file, func(t *testing.T) {
			dir := t.TempDir()
			db := filepath.Join(dir, "vault.db")
			copyFile(t, filepath.Join(pyvaultDir, "edge", file), db)
			v := openT(t, Config{DBPath: db, Provider: memProv()})
			ok, err := v.VerifyAuditChain(ctx)
			if err != nil || ok != want {
				t.Fatalf("verify = %v, %v; want %v", ok, err, want)
			}
		})
	}

	t.Run("legacy_dek0.db", func(t *testing.T) {
		dir := t.TempDir()
		db := filepath.Join(dir, "vault.db")
		copyFile(t, filepath.Join(pyvaultDir, "edge", "legacy_dek0.db"), db)
		_, err := Open(ctx, Config{DBPath: db, Provider: memProv(), KDFParams: testParams})
		if !errors.Is(err, ErrLegacyVault) {
			t.Fatalf("want ErrLegacyVault, got %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "keychain.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a keychain was created for a legacy vault: %v", err)
		}
	})
}
