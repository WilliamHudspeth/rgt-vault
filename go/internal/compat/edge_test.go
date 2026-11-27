package compat

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rgt-vault-server/internal/providers/providerstest"
	"rgt-vault-server/internal/server"
	"rgt-vault-server/internal/vault"
)

type edgeDB struct {
	File        string `json:"file"`
	Kind        string `json:"kind"`
	Verify      bool   `json:"verify_audit_chain"`
	FirstBadIdx *int   `json:"first_bad_index"`
	Rows        []struct {
		ID int64 `json:"id"`
	} `json:"rows"`
}

func loadEdge(t *testing.T) []edgeDB {
	t.Helper()
	var m struct {
		Databases []edgeDB `json:"databases"`
	}
	readJSON(t, filepath.Join(pyvaultDir, "edge", "manifest.json"), &m)
	return m.Databases
}

// copyEdge copies one edge database to a temp dir (so no keychain.json can
// pre-exist next to it) and returns its path.
func copyEdge(t *testing.T, file string) string {
	t.Helper()
	dir := t.TempDir()
	db := filepath.Join(dir, "vault.db")
	copyFile(t, filepath.Join(pyvaultDir, "edge", file), db)
	return db
}

// TestEdgeChainVerdicts: for each audit-chain database Python produced, the
// Go store opened through the whole stack gives Python's verdict, and the
// offline CLI (migrate check / verify-audit, no master secret) agrees and
// names the same first bad row. The quirks pinned here silently fail in a
// naive port: NULL details hashed as "None", isoformat without microseconds,
// agent_id outside the hash, a deleted middle row.
func TestEdgeChainVerdicts(t *testing.T) {
	for _, db := range loadEdge(t) {
		if db.Kind != "audit" {
			continue
		}
		t.Run(db.File, func(t *testing.T) {
			path := copyEdge(t, db.File)

			stack, err := server.OpenStack(context.Background(), server.StackOptions{
				DBPath: path, MasterProvider: providerstest.NewMemory(), KDFParams: testKDF,
			})
			if err != nil {
				t.Fatalf("OpenStack: %v", err)
			}
			ok, err := stack.Vault.VerifyAuditChain(context.Background())
			_ = stack.Close()
			if err != nil || ok != db.Verify {
				t.Fatalf("stack verdict %v, %v; Python said %v", ok, err, db.Verify)
			}

			// Offline CLI on a fresh copy (opening the stack appended rows).
			path = copyEdge(t, db.File)
			out, errOut, code := runBin(t, nil, "verify-audit", "--db", path)
			if db.Verify {
				if code != 0 || strings.TrimSpace(out) != "OK" {
					t.Fatalf("verify-audit: exit %d out %q err %q; Python said valid", code, out, errOut)
				}
				return
			}
			if code != 2 || strings.TrimSpace(out) != "TAMPERED" {
				t.Fatalf("verify-audit: exit %d out %q err %q; Python said broken", code, out, errOut)
			}
			if db.FirstBadIdx == nil {
				t.Fatal("manifest has no first_bad_index for a broken chain")
			}
			want := fmt.Sprintf("audit_logs id %d", db.Rows[*db.FirstBadIdx].ID)
			if !strings.Contains(errOut, want) {
				t.Errorf("verify-audit stderr %q does not name %q (Python's first bad row)", errOut, want)
			}
		})
	}
}

// TestLegacyFernetVaultRefused is decision D3: a vault that still holds
// dek_version 0 (Fernet) rows is refused by the stack and by `migrate check`
// with the instruction to open it once with the last Python release, and
// refusing writes nothing (no keychain.json appears next to the database).
func TestLegacyFernetVaultRefused(t *testing.T) {
	path := copyEdge(t, "legacy_dek0.db")
	dir := filepath.Dir(path)

	_, err := server.OpenStack(context.Background(), server.StackOptions{
		DBPath: path, MasterProvider: providerstest.NewMemory(), KDFParams: testKDF,
	})
	if !errors.Is(err, vault.ErrLegacyVault) {
		t.Fatalf("OpenStack on a legacy vault: %v, want ErrLegacyVault", err)
	}
	if !strings.Contains(err.Error(), "last Python release") {
		t.Errorf("refusal does not say what to do: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "keychain.json")); !os.IsNotExist(err) {
		t.Errorf("refusing created keychain.json (stat err %v)", err)
	}

	before := fileSHA(t, path)
	_, errOut, code := runBin(t, nil, "migrate", "check", "--db", path)
	if code != 1 || !strings.Contains(errOut, "dek_version=0") || !strings.Contains(errOut, "last Python release") {
		t.Fatalf("migrate check: exit %d stderr %q, want exit 1 with the D3 message", code, errOut)
	}
	if got := fileSHA(t, path); got != before {
		t.Error("migrate check modified the legacy database file")
	}
}
