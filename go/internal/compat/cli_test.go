package compat

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// TestCLIMigrateCheck runs the real rgt-vault binary's read-only migration
// commands against each Python-created vault. They must report READY, show
// what Python recorded (vault id, epoch, the five migrations, DEK versions,
// audit rows and verdict), need no master secret, and not modify vault.db.
func TestCLIMigrateCheck(t *testing.T) {
	for _, fx := range fixtures {
		t.Run(fx, func(t *testing.T) {
			m := loadManifest(t, fx)
			d := copyFixture(t, fx)
			before := fileSHA(t, d.DB)

			out, errOut, code := runBin(t, nil, "migrate", "check", "--db", d.DB)
			if code != 0 {
				t.Fatalf("migrate check: exit %d\n%s\n%s", code, out, errOut)
			}
			for _, want := range []string{
				"vault_id:     " + m.VaultID,
				fmt.Sprintf("key_epoch:    %d", m.KeyEpoch),
				"migrations:   1,2,3,4,5",
				fmt.Sprintf("keychain.json version 1, kdf argon2id, key_epoch %d", m.KeyEpoch),
				fmt.Sprintf("audit rows:   %d", m.RowCounts["audit_logs"]),
				"audit chain:  OK",
				"verdict:      READY",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("migrate check output lacks %q:\n%s", want, out)
				}
			}
			if want := fmt.Sprintf("secrets:      %d rows (dek_version 1: %d)", m.RowCounts["secrets"], m.RowCounts["secrets"]); !strings.Contains(out, want) {
				t.Errorf("migrate check output lacks %q:\n%s", want, out)
			}

			out, _, code = runBin(t, nil, "verify-audit", "--db", d.DB)
			if code != 0 || strings.TrimSpace(out) != "OK" {
				t.Errorf("verify-audit: exit %d %q", code, out)
			}
			out, _, code = runBin(t, nil, "status", "--db", d.DB)
			if code != 0 || !strings.Contains(out, "vault_id:     "+m.VaultID) || !strings.Contains(out, "audit chain:  OK") {
				t.Errorf("status: exit %d\n%s", code, out)
			}

			if got := fileSHA(t, d.DB); got != before {
				t.Error("read-only migration commands modified vault.db")
			}
		})
	}
}

// TestCLIMigrateCheckRefusals: a rolled-back keychain (epoch1's file next
// to small's database) and a missing keychain.json are both NOT READY.
func TestCLIMigrateCheckRefusals(t *testing.T) {
	d := copyFixture(t, "small")
	copyFile(t, filepath.Join(pyvaultDir, "epoch1", "keychain.json"), d.Keychain)
	_, errOut, code := runBin(t, nil, "migrate", "check", "--db", d.DB)
	if code != 1 || !strings.Contains(errOut, "does not match the database epoch") {
		t.Errorf("rolled-back keychain: exit %d %q", code, errOut)
	}

	d = copyFixture(t, "small")
	if err := os.Remove(d.Keychain); err != nil {
		t.Fatal(err)
	}
	_, errOut, code = runBin(t, nil, "migrate", "check", "--db", d.DB)
	if code != 1 || !strings.Contains(errOut, "keychain.json is missing") {
		t.Errorf("missing keychain: exit %d %q", code, errOut)
	}
}
