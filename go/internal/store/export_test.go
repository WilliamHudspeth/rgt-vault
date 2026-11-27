package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestMetadata(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	id, err := s.VaultID(ctx)
	if err != nil || len(id) != 36 {
		t.Fatalf("VaultID = %q %v", id, err)
	}
	if id2, _ := s.VaultID(ctx); id2 != id {
		t.Errorf("VaultID changed: %s -> %s", id, id2)
	}
	if e, err := s.KeyEpoch(ctx); err != nil || e != 1 {
		t.Errorf("KeyEpoch = %d %v", e, err)
	}
	for want := int64(2); want <= 3; want++ {
		if e, err := s.IncrementKeyEpoch(ctx); err != nil || e != want {
			t.Errorf("IncrementKeyEpoch = %d %v, want %d", e, err, want)
		}
	}
	var stored string
	if err := s.db.QueryRow("SELECT value FROM metadata WHERE key = 'key_epoch'").Scan(&stored); err != nil || stored != "3" {
		t.Errorf("stored epoch %q %v", stored, err)
	}
	// IncrementKeyEpoch on a vault that never read its epoch starts from 1.
	s2 := newStore(t)
	if e, err := s2.IncrementKeyEpoch(ctx); err != nil || e != 2 {
		t.Errorf("IncrementKeyEpoch fresh = %d %v", e, err)
	}

	if c, b, err := s.DEKUsage(ctx); err != nil || c != 0 || b != 0 {
		t.Errorf("DEKUsage fresh = %d %d %v", c, b, err)
	}
	if c, b, err := s.IncrementDEKUsage(ctx, 10); err != nil || c != 1 || b != 10 {
		t.Errorf("Increment 1 = %d %d %v", c, b, err)
	}
	if c, b, err := s.IncrementDEKUsage(ctx, 5); err != nil || c != 2 || b != 15 {
		t.Errorf("Increment 2 = %d %d %v", c, b, err)
	}
	if err := s.ResetDEKUsage(ctx); err != nil {
		t.Fatal(err)
	}
	if c, b, _ := s.DEKUsage(ctx); c != 0 || b != 0 {
		t.Errorf("after reset = %d %d", c, b)
	}

	// Corrupt metadata is an error, not a silent 0.
	if _, err := s.db.Exec("UPDATE metadata SET value = 'x' WHERE key = 'key_epoch'"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.KeyEpoch(ctx); err == nil {
		t.Error("non-integer epoch accepted")
	}
	if _, err := s.IncrementKeyEpoch(ctx); err == nil {
		t.Error("non-integer epoch incremented")
	}
	if _, err := s.db.Exec("UPDATE metadata SET value = ' 4 ' WHERE key = 'key_epoch'"); err != nil {
		t.Fatal(err)
	}
	if e, err := s.KeyEpoch(ctx); err != nil || e != 4 {
		t.Errorf("int(' 4 ') = %d %v", e, err)
	}
	if h, ok, err := s.LastAuditHash(ctx); err != nil || ok || h != "" {
		t.Errorf("LastAuditHash empty = %q %v %v", h, ok, err)
	}
	if ok, err := s.VerifyAuditChain(ctx); err != nil || !ok {
		t.Errorf("empty chain = %v %v", ok, err)
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	ctx := context.Background()
	src := openT(t, copyFixture(t, "pyvault.db"))
	writeGoRows(t, src)
	exp, err := src.ExportData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(exp.Secrets) == 0 || len(exp.AuditLogs) < 1000 || len(exp.Honeytokens) == 0 {
		t.Fatalf("export sizes %d/%d/%d", len(exp.Secrets), len(exp.AuditLogs), len(exp.Honeytokens))
	}
	if keys := keysOf(exp.Secrets[0]); keys != "id,secret_id,namespace,name,version,ciphertext,checksum,created_at,updated_at,status,dek_version,note,require_2fa" {
		t.Errorf("secret keys = %s", keys)
	}
	if v, ok := exp.Secrets[0].Get("ciphertext"); !ok || v.(string) == "" {
		t.Error("ciphertext not exported as base64 text")
	}
	if _, ok := exp.Secrets[0].Get("nope"); ok {
		t.Error("Get of a missing key reported present")
	}
	b, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data, err := DecodeImportJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	dst := newStore(t)
	if err := dst.ImportData(ctx, data); err != nil {
		t.Fatal(err)
	}
	exp2, err := dst.ExportData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// agent_id is not imported (Python import_data omits it); otherwise equal.
	for _, r := range exp.AuditLogs {
		for i := range r {
			if r[i].Key == "agent_id" {
				r[i].Value = nil
			}
		}
	}
	b1, _ := json.Marshal(exp)
	b2, _ := json.Marshal(exp2)
	if !bytes.Equal(b1, b2) {
		t.Error("export -> import -> export is not stable")
	}
	if ok, _ := dst.VerifyAuditChain(ctx); !ok {
		t.Error("imported chain does not verify")
	}
	ct1, _, err1 := src.GetSecret(ctx, "go", "from_go", "")
	ct2, _, err2 := dst.GetSecret(ctx, "go", "from_go", "")
	if err1 != nil || err2 != nil || !bytes.Equal(ct1, ct2) {
		t.Errorf("imported secret differs: %v %v", err1, err2)
	}
}

func keysOf(r OrderedRow) string {
	var k []string
	for _, c := range r {
		k = append(k, c.Key)
	}
	return strings.Join(k, ",")
}

// TestImportPythonExport imports Python's own export_data JSON.
func TestImportPythonExport(t *testing.T) {
	ctx := context.Background()
	m := loadManifest(t)
	b, err := os.ReadFile("testdata/pyexport.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := DecodeImportJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	s := newStore(t)
	if err := s.ImportData(ctx, data); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.AuditLogCount(ctx); n != m.PyVault.AuditRows {
		t.Errorf("audit rows %d, want %d", n, m.PyVault.AuditRows)
	}
	if ok, _ := s.VerifyAuditChain(ctx); !ok {
		t.Error("Python export chain does not verify after Go import")
	}
	py := openT(t, copyFixture(t, "pyvault.db"))
	for _, sec := range m.PyVault.Secrets {
		if sec["status"] != StatusActive {
			continue
		}
		ns, name := sec["namespace"].(string), sec["name"].(string)
		a, _, err1 := s.GetSecret(ctx, ns, name, "")
		b, _, err2 := py.GetSecret(ctx, ns, name, "")
		if err1 != nil || err2 != nil || !bytes.Equal(a, b) {
			t.Errorf("%s/%s differs after import: %v %v", ns, name, err1, err2)
		}
	}
	if ok, _ := s.IsHoneytoken(ctx, "default", "canary"); !ok {
		t.Error("honeytoken not imported")
	}
}

func TestImportValidation(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if _, err := s.SetSecret(ctx, SetSecretParams{Namespace: "ns", Name: "keep", Ciphertext: []byte("x"), DEKVersion: 1}); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		`[]`:                                    "Import data must be a dictionary",
		`{"secrets": {}}`:                       "Import field 'secrets' must be a list",
		`{"audit_logs": "x"}`:                   "Import field 'audit_logs' must be a list",
		`{"honeytokens": 1}`:                    "Import field 'honeytokens' must be a list",
		`{"secrets": [{"id": 1, "name": "a"}]}`: "Malformed secret entry in import data",
		`{"secrets": [1]}`:                      "Malformed secret entry in import data",
		`{"audit_logs": [{"id": 1, "action": "a"}]}`:                       "Malformed audit log entry in import data",
		`{"honeytokens": [{"namespace": "x"}]}`:                            "Malformed honeytoken entry in import data",
		`{"secrets": [{"id": 1, "name": "a", "ciphertext": "!!"}]}`:        "Failed to decode ciphertext: ",
		`{"secrets": [{"id": 1, "name": "a", "ciphertext": "QQ==\n"}]}`:    "Failed to decode ciphertext: ",
		`{"secrets": [{"id": 1, "name": "a", "ciphertext": 5}]}`:           "Failed to decode ciphertext: ",
		`{"secrets": [{"id": 1, "name": {"x": 1}, "ciphertext": "QQ=="}]}`: "Error binding parameter",
	}
	for in, want := range cases {
		data, err := DecodeImportJSON([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		err = s.ImportData(ctx, data)
		if !errors.Is(err, ErrInvalidArgument) || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("%s: got %v, want prefix %q", in, err, want)
		}
	}
	// A constraint failure (duplicate honeytoken) rolls the whole import back.
	data, _ := DecodeImportJSON([]byte(`{"honeytokens": [{"name": "h"}, {"name": "h"}]}`))
	if err := s.ImportData(ctx, data); err == nil {
		t.Error("duplicate honeytoken accepted")
	}
	if _, _, err := s.GetSecret(ctx, "ns", "keep", ""); err != nil {
		t.Errorf("failed import deleted data: %v", err)
	}
	if _, err := DecodeImportJSON([]byte(`{} {}`)); err == nil {
		t.Error("trailing JSON accepted")
	}
	if _, err := DecodeImportJSON([]byte(`{`)); err == nil {
		t.Error("broken JSON accepted")
	}

	// Defaults: Python's dict.get fallbacks and is_current / require_2fa rules.
	data, _ = DecodeImportJSON([]byte(`{
	  "secrets": [
	    {"id": 1, "name": "cur", "ciphertext": "QQ==", "is_current": 1, "require_2fa": "yes"},
	    {"id": 2, "name": "old", "ciphertext": "QQ==", "is_current": 0, "require_2fa": 0, "version": 2.0},
	    {"id": 3, "name": "t", "ciphertext": "QQ==", "is_current": true, "require_2fa": [], "dek_version": false}
	  ],
	  "audit_logs": [{"id": 7, "action": "X", "entry_hash": "h", "details": null}],
	  "honeytokens": [{"name": "trap"}],
	  "secrets_extra": null
	}`))
	if err := s.ImportData(ctx, data); err != nil {
		t.Fatal(err)
	}
	rows, err := s.db.Query("SELECT name, namespace, version, status, require_2fa, dek_version, checksum, note FROM secrets ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got []string
	for rows.Next() {
		var name, ns, status, sum, note string
		var ver, req, dv int
		if err := rows.Scan(&name, &ns, &ver, &status, &req, &dv, &sum, &note); err != nil {
			t.Fatal(err)
		}
		got = append(got, strings.Join([]string{name, ns, fmtI(ver), status, fmtI(req), fmtI(dv), sum, note}, "/"))
	}
	want := "cur/default/1/ACTIVE/1/1//,old/default/2/SUPERSEDED/0/1//,t/default/1/ACTIVE/0/0//"
	if strings.Join(got, ",") != want {
		t.Errorf("imported rows\n got %s\nwant %s", strings.Join(got, ","), want)
	}
	a, _ := s.IterAuditLog(ctx)
	if len(a) != 1 || a[0].ID != 7 || a[0].Details.Valid || a[0].Timestamp != "" || a[0].PrevHash.String != "" || a[0].SecretName.Valid {
		t.Errorf("imported audit row = %+v", a)
	}
	if ok, _ := s.IsHoneytoken(ctx, "default", "trap"); !ok {
		t.Error("honeytoken default namespace")
	}
}

func fmtI(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestPyHelpers(t *testing.T) {
	for v, want := range map[any]bool{nil: false, true: true, false: false, "": false, "a": true,
		json.Number("0"): false, json.Number("0.0"): false, json.Number("2"): true, 0.0: false, 1.5: true,
		int64(0): false, int64(3): true, 0: false, 4: true} {
		if got := pyTruthy(v); got != want {
			t.Errorf("pyTruthy(%#v) = %v", v, got)
		}
	}
	if pyTruthy([]any{}) || !pyTruthy([]any{1}) || pyTruthy(map[string]any{}) || !pyTruthy(map[string]any{"a": 1}) || !pyTruthy(struct{}{}) {
		t.Error("pyTruthy containers")
	}
	for v, want := range map[any]bool{true: true, false: false, json.Number("1"): true, json.Number("1.0"): true,
		json.Number("2"): false, 1.0: true, int64(1): true, 1: true, "1": false, nil: false} {
		if got := pyEqualsOne(v); got != want {
			t.Errorf("pyEqualsOne(%#v) = %v", v, got)
		}
	}
	for v, want := range map[any]string{nil: "'NoneType'", true: "'bool'", json.Number("1"): "'int'",
		json.Number("1.5"): "'float'", 1.5: "'float'", int8(1): "'int8'"} {
		if got := pyTypeName(v); got != want {
			t.Errorf("pyTypeName(%#v) = %s", v, got)
		}
	}
	if pyTypeName([]any{}) != "'list'" || pyTypeName(map[string]any{}) != "'dict'" {
		t.Error("pyTypeName containers")
	}
	if _, err := bindAll(json.Number("1e999")); err == nil {
		t.Error("out-of-range number bound")
	}
	if out, err := bindAll(json.Number("1.5"), false, 3, []byte("b")); err != nil || out[0] != 1.5 || out[1] != int64(0) || out[2] != 3 {
		t.Errorf("bindAll = %v %v", out, err)
	}
	if n, err := parseMetaInt("k", "\t\n 7\r\v\f"); err != nil || n != 7 {
		t.Errorf("parseMetaInt = %d %v", n, err)
	}
}

// TestConcurrentWriters hammers one vault from many goroutines through TWO
// Store instances (two connection pools, as two processes would be: only
// SQLite's BEGIN IMMEDIATE + busy_timeout serialises them across stores).
// The chain must not fork and no counter update may be lost. Run with -race.
func TestConcurrentWriters(t *testing.T) {
	ctx := context.Background()
	path := newStore(t).Path()
	a, b := openT(t, path), openT(t, path)
	const workers, perWorker = 8, 15
	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker*4)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			s := a
			if w%2 == 1 {
				s = b
			}
			for i := 0; i < perWorker; i++ {
				name := "k" + fmtI(w%3) // shared names: concurrent versions of the same secret
				if _, err := s.SetSecret(ctx, SetSecretParams{Namespace: "ns", Name: name, Ciphertext: []byte{byte(w), byte(i)}, DEKVersion: 1}); err != nil {
					errs <- err
				}
				if _, _, err := s.GetSecret(ctx, "ns", name, ""); err != nil {
					errs <- err
				}
				if err := s.LogAudit(ctx, AuditEvent{Action: "TICK", Details: fmtI(i)}); err != nil {
					errs <- err
				}
				if _, _, err := s.IncrementDEKUsage(ctx, 3); err != nil {
					errs <- err
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	total := int64(workers * perWorker)
	if n, _ := a.AuditLogCount(ctx); n != 3*total {
		t.Errorf("audit rows %d, want %d", n, 3*total)
	}
	if ok, err := b.VerifyAuditChain(ctx); err != nil || !ok {
		t.Fatalf("chain forked under concurrency: %v %v", ok, err)
	}
	// prev_hash of every row equals the previous row's entry_hash.
	rows, _ := a.IterAuditLog(ctx)
	for i := 1; i < len(rows); i++ {
		if rows[i].PrevHash.String != rows[i-1].EntryHash {
			t.Fatalf("row %d prev_hash does not link", rows[i].ID)
		}
	}
	if c, by, _ := a.DEKUsage(ctx); c != total || by != 3*total {
		t.Errorf("DEK usage %d/%d, want %d/%d (lost update)", c, by, total, 3*total)
	}
	// Exactly one ACTIVE version per name, versions 1..n without gaps.
	for k := 0; k < 3; k++ {
		var active, maxV, cnt int
		if err := a.db.QueryRow("SELECT SUM(status='ACTIVE'), MAX(version), COUNT(*) FROM secrets WHERE name = ?", "k"+fmtI(k)).Scan(&active, &maxV, &cnt); err != nil {
			t.Fatal(err)
		}
		if active != 1 || maxV != cnt {
			t.Errorf("k%d: %d active, max version %d, %d rows", k, active, maxV, cnt)
		}
	}
}

func TestOpenErrors(t *testing.T) {
	ctx := context.Background()
	if _, err := Open(ctx, ""); err == nil {
		t.Error("empty path accepted")
	}
	if _, err := Open(ctx, filepath.Join(t.TempDir(), "a?b.db")); err == nil {
		t.Error("'?' path accepted")
	}
	// A file where the directory should be.
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, filepath.Join(f, "vault.db")); err == nil {
		t.Error("path under a regular file accepted")
	}
	// Not a database.
	bad := filepath.Join(t.TempDir(), "bad.db")
	if err := os.WriteFile(bad, bytes.Repeat([]byte("not sqlite"), 200), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, bad); err == nil {
		t.Error("garbage file opened")
	}
	if p, err := DefaultDBPath(); err != nil || !strings.HasSuffix(p, filepath.Join(".secure-vault", "vault.db")) {
		t.Errorf("DefaultDBPath = %q %v", p, err)
	}
	// A failing migration (table already exists in an unexpected shape)
	// surfaces as an error.
	weird := filepath.Join(t.TempDir(), "weird.db")
	s := openT(t, weird)
	if _, err := s.db.Exec("DELETE FROM schema_migrations WHERE version = 3"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := Open(ctx, weird); err == nil || !strings.Contains(err.Error(), "0003_metadata.sql") {
		t.Errorf("re-applying 0003 should fail (duplicate column), got %v", err)
	}
}

func TestClosedStoreErrors(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_ = s.Close()
	checks := map[string]error{}
	_, checks["VaultID"] = s.VaultID(ctx)
	_, checks["KeyEpoch"] = s.KeyEpoch(ctx)
	_, checks["IncrementKeyEpoch"] = s.IncrementKeyEpoch(ctx)
	_, _, checks["DEKUsage"] = s.DEKUsage(ctx)
	_, _, checks["IncrementDEKUsage"] = s.IncrementDEKUsage(ctx, 1)
	checks["ResetDEKUsage"] = s.ResetDEKUsage(ctx)
	_, _, checks["LastAuditHash"] = s.LastAuditHash(ctx)
	checks["LogAudit"] = s.LogAudit(ctx, AuditEvent{Action: "x"})
	_, checks["GetAuditLog"] = s.GetAuditLog(ctx, 1)
	_, checks["AuditLogCount"] = s.AuditLogCount(ctx)
	_, checks["VerifyAuditChain"] = s.VerifyAuditChain(ctx)
	_, checks["SetSecret"] = s.SetSecret(ctx, SetSecretParams{})
	_, _, checks["GetSecret"] = s.GetSecret(ctx, "a", "b", "")
	_, checks["ListSecrets"] = s.ListSecrets(ctx, "a", "", 1, 0)
	_, checks["Requires2FA"] = s.Requires2FA(ctx, "a", "b")
	checks["RevokeSecret"] = s.RevokeSecret(ctx, "a", "b", "")
	checks["AddHoneytoken"] = s.AddHoneytoken(ctx, "a", "b")
	_, checks["IsHoneytoken"] = s.IsHoneytoken(ctx, "a", "b")
	_, checks["IterAllActiveSecrets"] = s.IterAllActiveSecrets(ctx)
	checks["UpdateSecretCiphertext"] = s.UpdateSecretCiphertext(ctx, 1, nil, 1)
	_, checks["HasLegacySecrets"] = s.HasLegacySecrets(ctx)
	_, checks["BulkRewriteActiveSecrets"] = s.BulkRewriteActiveSecrets(ctx, nil)
	_, checks["ActiveSecretCounts"] = s.ActiveSecretCounts(ctx)
	_, checks["ExportData"] = s.ExportData(ctx)
	checks["ImportData"] = s.ImportData(ctx, map[string]any{})
	for name, err := range checks {
		if err == nil {
			t.Errorf("%s on a closed store returned nil error", name)
		}
	}
}
