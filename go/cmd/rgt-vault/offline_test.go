package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/providers/providerstest"
)

const pyvaultDir = "../../testdata/pyvault"

// copyTree copies the files of dir (one level) into a temp dir. Fixtures are
// always copied first: WAL-mode databases grow -wal/-shm files when opened.
func copyTree(t *testing.T, dir string) string {
	t.Helper()
	dst := t.TempDir()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func sha(t *testing.T, path string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

type edgeManifest struct {
	Databases []struct {
		File          string `json:"file"`
		Kind          string `json:"kind"`
		Verify        bool   `json:"verify_audit_chain"`
		FirstBadIndex *int   `json:"first_bad_index"`
		RowCount      int    `json:"row_count"`
		Rows          []struct {
			ID int64 `json:"id"`
		} `json:"rows"`
	} `json:"databases"`
}

func loadEdge(t *testing.T) edgeManifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pyvaultDir, "edge", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m edgeManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// Offline verify-audit reproduces Python's own verdict on every edge database
// (NULL details/policy_hash, tampered rows, a deleted row), exit 2 on TAMPERED,
// and never modifies the file.
func TestVerifyAuditOfflineMatchesPython(t *testing.T) {
	isolateEnv(t)
	edge := loadEdge(t)
	dir := copyTree(t, filepath.Join(pyvaultDir, "edge"))
	n := 0
	for _, d := range edge.Databases {
		if d.Kind != "audit" {
			continue
		}
		n++
		t.Run(d.File, func(t *testing.T) {
			db := filepath.Join(dir, d.File)
			before := sha(t, db)
			code, out, stderr := runCLI(t, "", "--db", db, "verify-audit")
			if d.Verify {
				if code != 0 || out != "OK\n" {
					t.Fatalf("exit %d out %q err %q, Python says the chain verifies", code, out, stderr)
				}
			} else {
				if code != 2 || out != "TAMPERED\n" || !strings.Contains(stderr, "audit chain verification failed") {
					t.Fatalf("exit %d out %q err %q, Python says TAMPERED", code, out, stderr)
				}
				// The first bad row is reported (1-based position -> row id).
				if d.FirstBadIndex != nil && *d.FirstBadIndex < len(d.Rows) {
					want := "audit_logs id " + itoa(d.Rows[*d.FirstBadIndex].ID)
					if !strings.Contains(stderr, want) {
						t.Errorf("stderr %q lacks %q", stderr, want)
					}
				}
			}
			if sha(t, db) != before {
				t.Error("read-only verify modified the database file")
			}
		})
	}
	if n < 8 {
		t.Fatalf("only %d audit edge databases", n)
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestVerifyAuditOfflineFixturesAndErrors(t *testing.T) {
	isolateEnv(t)
	for _, fx := range []string{"small", "default", "epoch1"} {
		db := filepath.Join(copyTree(t, filepath.Join(pyvaultDir, fx)), "vault.db")
		if code, out, stderr := runCLI(t, "", "verify-audit", "--offline", "--db", db); code != 0 || out != "OK\n" {
			t.Errorf("%s: exit %d out %q err %q", fx, code, out, stderr)
		}
	}
	dir := t.TempDir()
	if code, _, stderr := runCLI(t, "", "--db", filepath.Join(dir, "none.db"), "verify-audit"); code != 1 || !strings.Contains(stderr, "does not exist") {
		t.Errorf("missing db: exit %d err %q", code, stderr)
	}
	if code, _, stderr := runCLI(t, "", "--db", dir, "verify-audit"); code != 1 || !strings.Contains(stderr, "is a directory") {
		t.Errorf("directory: exit %d err %q", code, stderr)
	}
	junk := filepath.Join(dir, "junk.db")
	_ = os.WriteFile(junk, []byte(strings.Repeat("not sqlite ", 100)), 0o600)
	if code, _, stderr := runCLI(t, "", "--db", junk, "verify-audit"); code != 1 || !strings.Contains(stderr, "not a readable SQLite database") {
		t.Errorf("junk: exit %d err %q", code, stderr)
	}
	// A database with no audit table is an empty, valid chain.
	if code, out, _ := runCLI(t, "", "--db", filepath.Join(copyTree(t, filepath.Join(pyvaultDir, "edge")), "empty.db"), "verify-audit"); code != 0 || out != "OK\n" {
		t.Errorf("empty chain: exit %d out %q", code, out)
	}
}

func TestStatusOffline(t *testing.T) {
	isolateEnv(t)
	db := filepath.Join(copyTree(t, filepath.Join(pyvaultDir, "small")), "vault.db")
	before := sha(t, db)
	code, out, stderr := runCLI(t, "", "--db", db, "status")
	if code != 0 {
		t.Fatalf("exit %d err %q", code, stderr)
	}
	for _, want := range []string{
		"vault_id:     5a11c0de-0000-4000-8000-000000000001", "key_epoch:    3", "active secrets: 12",
		"audit rows:   52", "last action:  ", "audit chain:  OK",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	if sha(t, db) != before {
		t.Error("status modified the database")
	}
	// Tampered chain: exit 2, summary still printed.
	edge := copyTree(t, filepath.Join(pyvaultDir, "edge"))
	code, out, _ = runCLI(t, "", "status", "--offline", "--db", filepath.Join(edge, "tampered_details.db"))
	if code != 2 || !strings.Contains(out, "audit chain:  TAMPERED") || !strings.Contains(out, "(not set)") {
		t.Errorf("tampered: exit %d out %q", code, out)
	}
	// Server status is still the default.
	srv, _ := recordingServer(t, 200, `{}`)
	if code, out, _ := runCLI(t, "", "--host", srv.URL, "status"); code != 0 || !strings.HasPrefix(out, "Server OK") {
		t.Errorf("online status: exit %d out %q", code, out)
	}
}

// migrate check reports a Python vault's state read-only and refuses what the
// Go line cannot open.
func TestMigrateCheck(t *testing.T) {
	isolateEnv(t)
	for _, fx := range []string{"small", "default", "epoch1"} {
		t.Run(fx, func(t *testing.T) {
			dir := copyTree(t, filepath.Join(pyvaultDir, fx))
			db := filepath.Join(dir, "vault.db")
			before := sha(t, db)
			code, out, stderr := runCLI(t, "", "--db", db, "migrate", "check")
			if code != 0 || !strings.Contains(out, "verdict:      READY") || !strings.Contains(out, "audit chain:  OK") ||
				!strings.Contains(out, "dek_version 1:") || !strings.Contains(out, "migrations:   1,2,3,4,5") {
				t.Fatalf("exit %d err %q\n%s", code, stderr, out)
			}
			var m struct {
				VaultID  string `json:"vault_id"`
				KeyEpoch int    `json:"key_epoch"`
			}
			b, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
			_ = json.Unmarshal(b, &m)
			if !strings.Contains(out, m.VaultID) || !strings.Contains(out, "key_epoch:    "+itoa(int64(m.KeyEpoch))+"\n") {
				t.Errorf("vault id/epoch missing:\n%s", out)
			}
			if strings.Contains(out, "wrapped_dek") || sha(t, db) != before {
				t.Error("leaked key material or modified the db")
			}
		})
	}
}

func TestMigrateCheckRefusals(t *testing.T) {
	isolateEnv(t)
	edge := copyTree(t, filepath.Join(pyvaultDir, "edge"))

	// dek_version 0 (D3): refuse with the "open once with Python" message.
	code, out, stderr := runCLI(t, "", "--db", filepath.Join(edge, "legacy_dek0.db"), "migrate", "check")
	if code != 1 || !strings.Contains(out, "NOT READY") || !strings.Contains(out, "dek_version 0: 1") ||
		!strings.Contains(stderr, "legacy Fernet") || !strings.Contains(stderr, "open it once with the last Python release") {
		t.Errorf("legacy: exit %d\nstdout %s\nstderr %s", code, out, stderr)
	}

	// A tampered chain is exit 2 (like verify-audit).
	code, out, stderr = runCLI(t, "", "--db", filepath.Join(edge, "tampered_entry_hash.db"), "migrate", "check")
	if code != 2 || !strings.Contains(out, "audit chain:  TAMPERED") || !strings.Contains(stderr, "audit chain verification failed") {
		t.Errorf("tampered: exit %d\n%s\n%s", code, out, stderr)
	}

	// Rolled-back keychain: small's db with epoch1's keychain.json.
	small := copyTree(t, filepath.Join(pyvaultDir, "small"))
	kc, _ := os.ReadFile(filepath.Join(pyvaultDir, "epoch1", "keychain.json"))
	_ = os.WriteFile(filepath.Join(small, "keychain.json"), kc, 0o600)
	code, out, _ = runCLI(t, "", "--db", filepath.Join(small, "vault.db"), "migrate", "check")
	if code != 1 || !strings.Contains(out, "does not match the database epoch 3") {
		t.Errorf("rollback: exit %d\n%s", code, out)
	}
	// ... unless an interrupted rotation (keychain.json.new) explains it.
	_ = os.WriteFile(filepath.Join(small, "keychain.json.new"), kc, 0o600)
	if code, out, _ = runCLI(t, "", "--db", filepath.Join(small, "vault.db"), "migrate", "check"); code != 0 || !strings.Contains(out, "interrupted rotation") {
		t.Errorf("pending rotation: exit %d\n%s", code, out)
	}

	// Missing keychain.json with secrets in the vault.
	noKC := copyTree(t, filepath.Join(pyvaultDir, "small"))
	_ = os.Remove(filepath.Join(noKC, "keychain.json"))
	code, out, _ = runCLI(t, "", "--db", filepath.Join(noKC, "vault.db"), "migrate", "check")
	if code != 1 || !strings.Contains(out, "keychain.json is missing but the vault holds secrets") {
		t.Errorf("no keychain: exit %d\n%s", code, out)
	}
	// Corrupt and odd keychains.
	for name, content := range map[string]string{"bad json": "{not json", "wrong kdf": `{"version":2,"kdf":"scrypt","key_epoch":3}`} {
		d := copyTree(t, filepath.Join(pyvaultDir, "small"))
		_ = os.WriteFile(filepath.Join(d, "keychain.json"), []byte(content), 0o600)
		if code, out, _ := runCLI(t, "", "--db", filepath.Join(d, "vault.db"), "migrate", "check"); code != 1 {
			t.Errorf("%s: exit %d\n%s", name, code, out)
		}
	}
	// An audit-only edge database has no keychain and no secrets: ready.
	if code, out, _ := runCLI(t, "", "--db", filepath.Join(edge, "chain_ok.db"), "migrate", "check"); code != 0 || !strings.Contains(out, "keychain.json not found") {
		t.Errorf("no secrets: exit %d\n%s", code, out)
	}
	// Errors.
	if code, _, _ := runCLI(t, "", "--db", filepath.Join(t.TempDir(), "x.db"), "migrate", "check"); code != 1 {
		t.Errorf("missing db: exit %d", code)
	}
}

// A database whose schema is newer than this build, and unsupported DEK
// versions, are refused.
func TestMigrateCheckNewerSchemaAndUnknownDEK(t *testing.T) {
	isolateEnv(t)
	d := copyTree(t, filepath.Join(pyvaultDir, "small"))
	db := filepath.Join(d, "vault.db")
	execSQL(t, db, "INSERT INTO schema_migrations (version, applied_at) VALUES (9, 'x')", "UPDATE secrets SET dek_version = 7 WHERE id = 2")
	code, out, _ := runCLI(t, "", "--db", db, "migrate", "check")
	if code != 1 || !strings.Contains(out, "newer than this build knows") || !strings.Contains(out, "unsupported dek_version 7") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

func execSQL(t *testing.T, path string, stmts ...string) {
	t.Helper()
	old := t.TempDir()
	_ = old
	db, err := openRW(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
}

var _ = bytes.Equal
var _ = providerstest.NewMemory
