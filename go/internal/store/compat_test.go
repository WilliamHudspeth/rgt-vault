package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// manifest mirrors testdata/manifest.json written by gen_fixtures.py.
type manifest struct {
	PyVault struct {
		VaultID     string           `json:"vault_id"`
		KeyEpoch    int64            `json:"key_epoch"`
		DEKUsage    [2]int64         `json:"dek_usage"`
		AuditRows   int64            `json:"audit_rows"`
		ChainOK     bool             `json:"chain_ok"`
		Migrations  []int            `json:"migrations"`
		Secrets     []map[string]any `json:"secrets"`
		Honeytokens []map[string]any `json:"honeytokens"`
		Schema      []schemaRow      `json:"schema"`
	} `json:"pyvault"`
	FreshSchema []schemaRow `json:"fresh_schema"`
	Edge        struct {
		ChainOK bool `json:"chain_ok"`
	} `json:"edge"`
	Tampered struct {
		ChainOK bool `json:"chain_ok"`
	} `json:"tampered"`
}

type schemaRow struct {
	Type    string  `json:"type"`
	Name    string  `json:"name"`
	TblName string  `json:"tbl_name"`
	SQL     *string `json:"sql"`
}

func loadManifest(t *testing.T) manifest {
	t.Helper()
	b, err := os.ReadFile("testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// copyFixture copies a checked-in DB to a temp dir (fixtures are never
// modified in place) and returns the copy's path.
func copyFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "vault.db")
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return dst
}

func openT(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func readSchema(t *testing.T, s *Store) []schemaRow {
	t.Helper()
	rows, err := s.db.Query("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []schemaRow
	for rows.Next() {
		var r schemaRow
		var q sql.NullString
		if err := rows.Scan(&r.Type, &r.Name, &r.TblName, &q); err != nil {
			t.Fatal(err)
		}
		if q.Valid {
			v := q.String
			r.SQL = &v
		}
		out = append(out, r)
	}
	return out
}

func schemaEqual(t *testing.T, got, want []schemaRow) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("schema has %d objects, Python %d", len(got), len(want))
	}
	for i := range got {
		g, w := got[i], want[i]
		gs, ws := "<NULL>", "<NULL>"
		if g.SQL != nil {
			gs = *g.SQL
		}
		if w.SQL != nil {
			ws = *w.SQL
		}
		if g.Type != w.Type || g.Name != w.Name || g.TblName != w.TblName || gs != ws {
			t.Errorf("schema object %d differs:\n go: %s %s %s %q\n py: %s %s %s %q", i,
				g.Type, g.Name, g.TblName, gs, w.Type, w.Name, w.TblName, ws)
		}
	}
}

// TestMigrationsByteEqualPython pins the embedded migrations to the Python
// originals while python/ exists (after GZ the check is skipped).
func TestMigrationsByteEqualPython(t *testing.T) {
	pyDir := filepath.Join("..", "..", "..", "python", "storage", "migrations")
	pyFiles, err := filepath.Glob(filepath.Join(pyDir, "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pyFiles) == 0 {
		t.Skip("python/storage/migrations not present (python/ removed)")
	}
	goEntries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	if len(goEntries) != len(pyFiles) {
		t.Fatalf("go has %d migration files, python %d", len(goEntries), len(pyFiles))
	}
	for _, p := range pyFiles {
		want, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := migrationFS.ReadFile("migrations/" + filepath.Base(p))
		if err != nil {
			t.Fatalf("missing embedded %s: %v", filepath.Base(p), err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from python/storage/migrations", filepath.Base(p))
		}
	}
	ms, err := migrations()
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range ms {
		if m.version != i+1 {
			t.Errorf("migration %d has version %d", i, m.version)
		}
	}
}

func TestFreshSchemaMatchesPython(t *testing.T) {
	m := loadManifest(t)
	s := openT(t, filepath.Join(t.TempDir(), "sub", "vault.db"))
	schemaEqual(t, readSchema(t, s), m.FreshSchema)
	assertMigrations(t, s, m.PyVault.Migrations)

	// Re-opening is a no-op (no migration re-applied, schema unchanged).
	path := s.Path()
	_ = s.Close()
	s2 := openT(t, path)
	schemaEqual(t, readSchema(t, s2), m.FreshSchema)
	assertMigrations(t, s2, m.PyVault.Migrations)
}

func assertMigrations(t *testing.T, s *Store, want []int) {
	t.Helper()
	rows, err := s.db.Query("SELECT version, applied_at FROM schema_migrations ORDER BY version")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got []int
	for rows.Next() {
		var v int
		var at string
		if err := rows.Scan(&v, &at); err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(at, "+00:00") {
			t.Errorf("applied_at %q is not a Python isoformat UTC timestamp", at)
		}
		got = append(got, v)
	}
	if len(got) != len(want) {
		t.Fatalf("migrations %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("migrations %v, want %v", got, want)
		}
	}
}

func TestPragmas(t *testing.T) {
	s := openT(t, filepath.Join(t.TempDir(), "vault.db"))
	ctx := context.Background()
	// Pin one connection so every PRAGMA is read from the same one.
	conn, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	for pragma, want := range map[string]string{
		"foreign_keys": "1",
		"journal_mode": "wal",
		"synchronous":  "1", // NORMAL
		"busy_timeout": "5000",
	} {
		var got string
		if err := conn.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("PRAGMA %s = %s, want %s", pragma, got, want)
		}
	}
}

func TestPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions only (as in Python)")
	}
	dir := filepath.Join(t.TempDir(), "vaultdir")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "vault.db")
	s := openT(t, path)
	if _, err := s.KeyEpoch(context.Background()); err != nil { // force a write (WAL file)
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{dir: 0o700, path: 0o600} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s mode %o, want %o", p, got, want)
		}
	}
	if fi, err := os.Stat(path + "-wal"); err == nil && fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("WAL file mode %o is group/world accessible", fi.Mode().Perm())
	}
}

// TestOpenPythonVault opens a vault.db written by the real Python
// VaultManager and checks every value against the generator's manifest.
func TestOpenPythonVault(t *testing.T) {
	m := loadManifest(t)
	ctx := context.Background()
	s := openT(t, copyFixture(t, "pyvault.db"))

	schemaEqual(t, readSchema(t, s), m.PyVault.Schema)
	assertMigrations(t, s, m.PyVault.Migrations)

	if id, err := s.VaultID(ctx); err != nil || id != m.PyVault.VaultID {
		t.Errorf("VaultID = %q, %v; want %q", id, err, m.PyVault.VaultID)
	}
	if e, err := s.KeyEpoch(ctx); err != nil || e != m.PyVault.KeyEpoch {
		t.Errorf("KeyEpoch = %d, %v; want %d", e, err, m.PyVault.KeyEpoch)
	}
	if c, b, err := s.DEKUsage(ctx); err != nil || c != m.PyVault.DEKUsage[0] || b != m.PyVault.DEKUsage[1] {
		t.Errorf("DEKUsage = %d,%d,%v; want %v", c, b, err, m.PyVault.DEKUsage)
	}
	n, err := s.AuditLogCount(ctx)
	if err != nil || n != m.PyVault.AuditRows || n < 1000 {
		t.Fatalf("AuditLogCount = %d, %v; want %d (>= 1000)", n, err, m.PyVault.AuditRows)
	}
	ok, err := s.VerifyAuditChain(ctx)
	if err != nil || ok != m.PyVault.ChainOK || !ok {
		t.Fatalf("VerifyAuditChain = %v, %v; Python said %v", ok, err, m.PyVault.ChainOK)
	}

	// Every ACTIVE secret reads back byte-identical (checksum verified).
	active := 0
	for _, sec := range m.PyVault.Secrets {
		ns, name := sec["namespace"].(string), sec["name"].(string)
		want, err := base64.StdEncoding.DecodeString(sec["ciphertext"].(string))
		if err != nil {
			t.Fatal(err)
		}
		ver := int64(sec["version"].(float64))
		ct, dv, err := s.GetSecretVersion(ctx, ns, name, ver, "")
		if err != nil || !bytes.Equal(ct, want) || dv != int64(sec["dek_version"].(float64)) {
			t.Errorf("GetSecretVersion(%s/%s v%d) = %d bytes, dek %d, %v", ns, name, ver, len(ct), dv, err)
		}
		if sec["status"] == StatusActive {
			active++
			ct, _, err := s.GetSecret(ctx, ns, name, "")
			if err != nil || !bytes.Equal(ct, want) {
				t.Errorf("GetSecret(%s/%s) mismatch: %v", ns, name, err)
			}
			req, err := s.Requires2FA(ctx, ns, name)
			if err != nil || req != (sec["require_2fa"].(float64) != 0) {
				t.Errorf("Requires2FA(%s/%s) = %v, %v", ns, name, req, err)
			}
		}
	}
	recs, err := s.IterAllActiveSecrets(ctx)
	if err != nil || len(recs) != active {
		t.Errorf("IterAllActiveSecrets = %d, %v; want %d", len(recs), err, active)
	}
	for _, h := range m.PyVault.Honeytokens {
		if ok, err := s.IsHoneytoken(ctx, h["namespace"].(string), h["name"].(string)); err != nil || !ok {
			t.Errorf("IsHoneytoken(%v) = %v, %v", h, ok, err)
		}
	}
	list, err := s.ListSecrets(ctx, "default", "", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, si := range list {
		if si.Name == "api_key" && (si.LatestVersion != 3 || !si.Require2FA || si.Note != "third") {
			t.Errorf("api_key list entry = %+v", si)
		}
	}

	// The chain still verifies after Go appended its GET/LIST rows.
	if ok, err := s.VerifyAuditChain(ctx); err != nil || !ok {
		t.Fatalf("chain broken after Go reads: %v %v", ok, err)
	}
}

func TestPythonEdgeAndTamperedVerdicts(t *testing.T) {
	m := loadManifest(t)
	ctx := context.Background()
	for name, want := range map[string]bool{"pyedge.db": m.Edge.ChainOK, "pytampered.db": m.Tampered.ChainOK} {
		s := openT(t, copyFixture(t, name))
		got, err := s.VerifyAuditChain(ctx)
		if err != nil || got != want {
			t.Errorf("%s: Go verdict %v (%v), Python %v", name, got, err, want)
		}
	}
	if !m.Edge.ChainOK || m.Tampered.ChainOK {
		t.Fatalf("fixture verdicts unexpected: edge=%v tampered=%v", m.Edge.ChainOK, m.Tampered.ChainOK)
	}
	// Appending in Go on top of NULL-rendered rows keeps the chain valid.
	s := openT(t, copyFixture(t, "pyedge.db"))
	if err := s.LogAudit(ctx, AuditEvent{Action: "GO", SecretName: Name("a"), Details: "from go"}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.VerifyAuditChain(ctx); !ok {
		t.Fatal("chain broken after Go append on edge DB")
	}
}

// TestMigrateFrom0001 builds a pre-namespace (0001-only) vault with data and
// lets Open run 0002..0005 over it, including 0002's own BEGIN/COMMIT.
func TestMigrateFrom0001(t *testing.T) {
	m := loadManifest(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "vault.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := migrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		createSchemaMigrations,
		ms[0].sql,
		"INSERT INTO schema_migrations (version, applied_at) VALUES (1, '2025-01-01T00:00:00+00:00')",
		"INSERT INTO secrets (name, version, ciphertext, checksum, created_at, updated_at, is_current) VALUES ('old', 1, x'01', 'c1', 't', 't', 0)",
		"INSERT INTO secrets (name, version, ciphertext, checksum, created_at, updated_at, is_current) VALUES ('old', 2, x'02', 'c2', 't', 't', 1)",
		"INSERT INTO honeytokens (name) VALUES ('trap')",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	_ = db.Close()

	s := openT(t, path)
	schemaEqual(t, readSchema(t, s), m.FreshSchema)
	rows, err := s.db.Query("SELECT namespace, name, version, status, secret_id, dek_version FROM secrets ORDER BY version")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got []string
	for rows.Next() {
		var ns, name, status, sid string
		var v int
		var dv sql.NullInt64
		if err := rows.Scan(&ns, &name, &v, &status, &sid, &dv); err != nil {
			t.Fatal(err)
		}
		if len(sid) != 36 || sid[14] != '4' {
			t.Errorf("secret_id %q is not a uuid4", sid)
		}
		got = append(got, ns+"/"+name+"/"+status)
		if dv.Int64 != 0 {
			t.Errorf("dek_version %v, want legacy 0", dv)
		}
	}
	if strings.Join(got, ",") != "default/old/SUPERSEDED,default/old/ACTIVE" {
		t.Errorf("migrated rows = %v", got)
	}
	if ok, err := s.IsHoneytoken(ctx, "default", "trap"); err != nil || !ok {
		t.Errorf("honeytoken not migrated: %v %v", ok, err)
	}
	if legacy, err := s.HasLegacySecrets(ctx); err != nil || !legacy {
		t.Errorf("HasLegacySecrets = %v, %v", legacy, err)
	}
}

// TestPythonReadsGoWrites has the REAL Python StorageBackend open a vault
// that Go modified, read everything and verify the chain (RGT-151
// acceptance: "add a row in Go, verify in Python"). It needs a Python with
// rgt_vault installed: set RGT_VAULT_PYTHON=/path/to/.venv/bin/python.
func TestPythonReadsGoWrites(t *testing.T) {
	py := os.Getenv("RGT_VAULT_PYTHON")
	if py == "" {
		t.Skip("set RGT_VAULT_PYTHON to a python with rgt_vault installed to run the Python round-trip")
	}
	ctx := context.Background()
	path := copyFixture(t, "pyvault.db")
	s := openT(t, path)
	writeGoRows(t, s)
	before, _ := s.AuditLogCount(ctx)
	_ = s.Close()

	// A brand-new Go-created vault must be readable by Python too.
	fresh := filepath.Join(t.TempDir(), "fresh", "vault.db")
	fs := openT(t, fresh)
	writeGoRows(t, fs)
	_ = fs.Close()

	for _, db := range []string{path, fresh} {
		cmd := exec.Command(py, "testdata/gen_fixtures.py", "--verify", db)
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("python verify %s: %v", db, err)
		}
		var r map[string]any
		if err := json.Unmarshal(out, &r); err != nil {
			t.Fatalf("python output: %v\n%s", err, out)
		}
		t.Logf("python report for %s: chain_ok=%v audit_rows=%v chain_ok_after_python_writes=%v audit_rows_after=%v",
			filepath.Base(filepath.Dir(db)), r["chain_ok"], r["audit_rows"], r["chain_ok_after_python_writes"], r["audit_rows_after_python_writes"])
		if r["chain_ok"] != true || r["chain_ok_after_python_writes"] != true {
			t.Errorf("python verify_audit_chain on Go-modified %s: %v / after python writes %v", db, r["chain_ok"], r["chain_ok_after_python_writes"])
		}
		found := false
		for _, a := range r["active_entries"].([]any) {
			am := a.(map[string]any)
			if am["namespace"] == "go" && am["name"] == "from_go" {
				found = am["version"] == float64(2) && am["requires_2fa"] == true && am["is_honeytoken"] == true
			}
		}
		if !found {
			t.Errorf("python did not read the Go-written secret correctly: %s", out)
		}
		if db == path && r["audit_rows"] != float64(before) {
			t.Errorf("python saw %v audit rows, Go wrote %d", r["audit_rows"], before)
		}
	}

	// And Go verifies the chain Python extended.
	s2 := openT(t, path)
	if ok, err := s2.VerifyAuditChain(ctx); err != nil || !ok {
		t.Errorf("Go verify after Python writes: %v %v", ok, err)
	}
}

// writeGoRows exercises every write path on s.
func writeGoRows(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.SetSecret(ctx, SetSecretParams{Namespace: "go", Name: "from_go", Ciphertext: []byte("ct-v1"), DEKVersion: 1, Note: "n1"})
	must(err)
	_, err = s.SetSecret(ctx, SetSecretParams{Namespace: "go", Name: "from_go", Ciphertext: []byte("ct-v2 ✓"), DEKVersion: 1, Note: "n2", Require2FA: true, PolicyHash: "ph"})
	must(err)
	_, err = s.SetSecret(ctx, SetSecretParams{Namespace: "go", Name: "revoked", Ciphertext: []byte{0, 1, 2}, DEKVersion: 1})
	must(err)
	must(s.RevokeSecret(ctx, "go", "revoked", "ph"))
	must(s.AddHoneytoken(ctx, "go", "from_go"))
	_, _, err = s.GetSecret(ctx, "go", "from_go", "ph")
	must(err)
	_, err = s.ListSecrets(ctx, "go", "ph", 10, 0)
	must(err)
	must(s.LogAudit(ctx, AuditEvent{Action: "GO\tACTION", Details: "multi\r\nline", AgentID: Name("agent-go")}))
	_, _, err = s.IncrementDEKUsage(ctx, 42)
	must(err)
	_, err = s.IncrementKeyEpoch(ctx)
	must(err)
	_, err = s.BulkRewriteActiveSecrets(ctx, func(r SecretRecord) ([]byte, int64, error) {
		return r.Ciphertext, r.DEKVersion, nil
	})
	must(err)
	if ok, err := s.VerifyAuditChain(ctx); err != nil || !ok {
		t.Fatalf("Go chain after writes: %v %v", ok, err)
	}
}
