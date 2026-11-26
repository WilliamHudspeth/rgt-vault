package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"rgt-vault-server/internal/audit"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	return openT(t, filepath.Join(t.TempDir(), "vault.db"))
}

func lastAudit(t *testing.T, s *Store) AuditRow {
	t.Helper()
	rows, err := s.GetAuditLog(context.Background(), 1)
	if err != nil || len(rows) != 1 {
		t.Fatalf("GetAuditLog: %v %v", rows, err)
	}
	return rows[0]
}

func TestSetSecretVersionsAndAudit(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	fixed := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return fixed }

	v, err := s.SetSecret(ctx, SetSecretParams{Namespace: "ns", Name: "k", Ciphertext: []byte("a"), DEKVersion: 1, SecretID: "given-id", PolicyHash: "ph", Note: "hello"})
	if err != nil || v != 1 {
		t.Fatalf("SetSecret v1 = %d, %v", v, err)
	}
	a := lastAudit(t, s)
	if a.Action != "SET_SECRET" || a.SecretName.String != "k" || a.Details.String != "Version 1 created in ns" ||
		a.PolicyHash.String != "ph" || a.Timestamp != "2026-11-26T12:00:00+00:00" || a.PrevHash.String != "" || a.AgentID.Valid {
		t.Errorf("audit row = %+v", a)
	}
	want := audit.EntryHash("", "2026-11-26T12:00:00+00:00", "SET_SECRET", "k", "Version 1 created in ns", "ph")
	if a.EntryHash != want {
		t.Errorf("entry hash %s, want %s", a.EntryHash, want)
	}

	s.now = func() time.Time { return fixed.Add(1500 * time.Microsecond) }
	v, err = s.SetSecret(ctx, SetSecretParams{Namespace: "ns", Name: "k", Ciphertext: []byte("b"), DEKVersion: 1, SecretID: "ignored", Require2FA: true})
	if err != nil || v != 2 {
		t.Fatalf("SetSecret v2 = %d, %v", v, err)
	}
	if a := lastAudit(t, s); a.Timestamp != "2026-11-26T12:00:00.001500+00:00" || a.Details.String != "Version 2 created in ns" {
		t.Errorf("v2 audit = %+v", a)
	}
	rows, err := s.db.Query("SELECT version, status, secret_id, checksum, note, require_2fa, created_at FROM secrets WHERE name = 'k' ORDER BY version")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got []string
	for rows.Next() {
		var ver, req int
		var status, sid, sum, note, created string
		if err := rows.Scan(&ver, &status, &sid, &sum, &note, &req, &created); err != nil {
			t.Fatal(err)
		}
		if sid != "given-id" {
			t.Errorf("version %d secret_id %q, want inherited given-id", ver, sid)
		}
		if len(sum) != 64 {
			t.Errorf("checksum %q", sum)
		}
		got = append(got, status)
	}
	if strings.Join(got, ",") != "SUPERSEDED,ACTIVE" {
		t.Errorf("statuses = %v", got)
	}

	// A new name gets a generated uuid4.
	if _, err := s.SetSecret(ctx, SetSecretParams{Namespace: "ns", Name: "fresh", Ciphertext: []byte("x"), DEKVersion: 1}); err != nil {
		t.Fatal(err)
	}
	var sid string
	if err := s.db.QueryRow("SELECT secret_id FROM secrets WHERE name = 'fresh'").Scan(&sid); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(sid) {
		t.Errorf("secret_id %q is not a uuid4", sid)
	}

	// Same name in another namespace is independent.
	if v, err := s.SetSecret(ctx, SetSecretParams{Namespace: "other", Name: "k", Ciphertext: []byte("o"), DEKVersion: 1}); err != nil || v != 1 {
		t.Errorf("other/k = %d, %v", v, err)
	}
	if ok, _ := s.VerifyAuditChain(ctx); !ok {
		t.Error("chain does not verify")
	}
}

func TestGetSecret(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	for _, ct := range []string{"one", "two"} {
		if _, err := s.SetSecret(ctx, SetSecretParams{Namespace: "ns", Name: "k", Ciphertext: []byte(ct), DEKVersion: 1}); err != nil {
			t.Fatal(err)
		}
	}
	ct, dv, err := s.GetSecret(ctx, "ns", "k", "ph")
	if err != nil || string(ct) != "two" || dv != 1 {
		t.Fatalf("GetSecret = %q %d %v", ct, dv, err)
	}
	if a := lastAudit(t, s); a.Action != "GET_SECRET" || a.Details.String != "Version latest accessed from ns" || a.PolicyHash.String != "ph" {
		t.Errorf("audit = %+v", a)
	}
	ct, _, err = s.GetSecretVersion(ctx, "ns", "k", 1, "")
	if err != nil || string(ct) != "one" {
		t.Fatalf("GetSecretVersion(1) = %q %v", ct, err)
	}
	if a := lastAudit(t, s); a.Details.String != "Version 1 accessed from ns" {
		t.Errorf("audit = %+v", a)
	}

	// Not found: audited and committed, ErrNotFound returned.
	n0, _ := s.AuditLogCount(ctx)
	if _, _, err := s.GetSecret(ctx, "ns", "missing", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if a := lastAudit(t, s); a.Action != "GET_SECRET_FAILED" || a.Details.String != "Secret not found in ns" || a.SecretName.String != "missing" {
		t.Errorf("audit = %+v", a)
	}
	if _, _, err := s.GetSecretVersion(ctx, "ns", "k", 0, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("version 0: %v", err)
	}
	if n1, _ := s.AuditLogCount(ctx); n1 != n0+2 {
		t.Errorf("audit rows %d -> %d", n0, n1)
	}

	// Checksum mismatch: audited and committed, ErrChecksum with Python's message.
	if _, err := s.db.Exec("UPDATE secrets SET ciphertext = x'00' WHERE name = 'k' AND version = 2"); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.GetSecret(ctx, "ns", "k", "")
	if !errors.Is(err, ErrChecksum) || !strings.Contains(err.Error(), "Integrity check failed for secret 'ns/k'") {
		t.Fatalf("checksum: %v", err)
	}
	if a := lastAudit(t, s); a.Action != "GET_SECRET_FAILED" || a.Details.String != "Checksum mismatch" {
		t.Errorf("audit = %+v", a)
	}
	if ok, _ := s.VerifyAuditChain(ctx); !ok {
		t.Error("chain does not verify")
	}
}

func TestListSecrets(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	for _, n := range []string{"a", "b", "c"} {
		if _, err := s.SetSecret(ctx, SetSecretParams{Namespace: "ns", Name: n, Ciphertext: []byte(n), DEKVersion: 1, Note: "note " + n, Require2FA: n == "b"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RevokeSecret(ctx, "ns", "c", ""); err != nil {
		t.Fatal(err)
	}
	l, err := s.ListSecrets(ctx, "ns", "ph", 100, 0)
	if err != nil || len(l) != 2 {
		t.Fatalf("ListSecrets = %v, %v", l, err)
	}
	if l[1].Name != "b" || !l[1].Require2FA || l[1].Note != "note b" || l[1].Status != StatusActive || l[1].LatestVersion != 1 {
		t.Errorf("entry = %+v", l[1])
	}
	a := lastAudit(t, s)
	if a.Action != "LIST_SECRETS" || a.SecretName.Valid || a.Details.String != "Listed 2 secrets in ns" {
		t.Errorf("audit = %+v", a)
	}
	if l, err := s.ListSecrets(ctx, "ns", "", 1, 1); err != nil || len(l) != 1 || l[0].Name != "b" {
		t.Errorf("paged = %v %v", l, err)
	}
	if l, err := s.ListSecrets(ctx, "empty", "", 1, 0); err != nil || l == nil || len(l) != 0 {
		t.Errorf("empty = %#v %v", l, err)
	}
	for _, c := range []struct {
		limit, offset int
		msg           string
	}{{0, 0, "limit must be between 1 and 1000"}, {1001, 0, "limit must be between 1 and 1000"}, {1, -1, "offset must be >= 0"}} {
		_, err := s.ListSecrets(ctx, "ns", "", c.limit, c.offset)
		if !errors.Is(err, ErrInvalidArgument) || err.Error() != c.msg {
			t.Errorf("ListSecrets(%d,%d) = %v", c.limit, c.offset, err)
		}
	}
}

func TestRevokeHoneytokens2FA(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if _, err := s.SetSecret(ctx, SetSecretParams{Namespace: "ns", Name: "k", Ciphertext: []byte("x"), DEKVersion: 1, Require2FA: true}); err != nil {
		t.Fatal(err)
	}
	if req, err := s.Requires2FA(ctx, "ns", "k"); err != nil || !req {
		t.Errorf("Requires2FA = %v %v", req, err)
	}
	if err := s.RevokeSecret(ctx, "ns", "k", "ph"); err != nil {
		t.Fatal(err)
	}
	if a := lastAudit(t, s); a.Action != "REVOKE_SECRET" || a.Details.String != "Revoked active secret in ns" || a.SecretName.String != "k" {
		t.Errorf("audit = %+v", a)
	}
	if req, _ := s.Requires2FA(ctx, "ns", "k"); req {
		t.Error("revoked secret still requires 2FA")
	}
	if _, _, err := s.GetSecret(ctx, "ns", "k", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoked secret readable: %v", err)
	}
	if ct, _, err := s.GetSecretVersion(ctx, "ns", "k", 1, ""); err != nil || string(ct) != "x" {
		t.Errorf("explicit version of revoked: %q %v", ct, err)
	}
	// Revoking a missing secret still audits (Python behaviour).
	if err := s.RevokeSecret(ctx, "ns", "missing", ""); err != nil {
		t.Fatal(err)
	}
	if a := lastAudit(t, s); a.SecretName.String != "missing" {
		t.Errorf("audit = %+v", a)
	}

	for i := 0; i < 2; i++ { // INSERT OR IGNORE
		if err := s.AddHoneytoken(ctx, "ns", "trap"); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _ := s.IsHoneytoken(ctx, "ns", "trap"); !ok {
		t.Error("honeytoken missing")
	}
	if ok, _ := s.IsHoneytoken(ctx, "other", "trap"); ok {
		t.Error("honeytoken leaked across namespaces")
	}
}

func TestBulkRewrite(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	const n = 2500 // > 2 pages of rewriteBatch
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		dv := 1
		if i%10 == 0 {
			dv = 0
		}
		if _, err := tx.Exec(`INSERT INTO secrets (secret_id, namespace, name, version, ciphertext, checksum, created_at, updated_at, status, dek_version)
			VALUES ('id', 'ns', ?, 1, ?, ?, 't', 't', 'ACTIVE', ?)`, "s"+strconv.Itoa(i), []byte("old"), checksum([]byte("old")), dv); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO secrets (secret_id, namespace, name, version, ciphertext, checksum, created_at, updated_at, status, dek_version)
		VALUES ('id', 'ns', 'gone', 1, x'00', 'c', 't', 't', 'REVOKED', 1)`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// A failing rewrite leaves every row untouched.
	calls := 0
	_, err = s.BulkRewriteActiveSecrets(ctx, func(r SecretRecord) ([]byte, int64, error) {
		calls++
		if calls == n-1 {
			return nil, 0, errors.New("boom")
		}
		return []byte("new"), 2, nil
	})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("want boom, got %v", err)
	}
	var changed int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM secrets WHERE dek_version = 2").Scan(&changed); err != nil || changed != 0 {
		t.Fatalf("rollback failed: %d rows changed (%v)", changed, err)
	}

	legacy, err := s.BulkRewriteLegacySecrets(ctx, func(r SecretRecord) ([]byte, int64, error) {
		if r.DEKVersion != 0 {
			t.Errorf("non-legacy row %d passed", r.ID)
		}
		return []byte("mig"), 1, nil
	})
	if err != nil || legacy != n/10 {
		t.Fatalf("legacy rewrite = %d, %v", legacy, err)
	}
	if has, _ := s.HasLegacySecrets(ctx); has {
		t.Error("legacy rows remain")
	}

	seen := map[int64]bool{}
	got, err := s.BulkRewriteActiveSecrets(ctx, func(r SecretRecord) ([]byte, int64, error) {
		if seen[r.ID] {
			t.Errorf("row %d rewritten twice", r.ID)
		}
		seen[r.ID] = true
		return append([]byte("new-"), r.Ciphertext...), 7, nil
	})
	if err != nil || got != n {
		t.Fatalf("rewrite = %d, %v", got, err)
	}
	recs, err := s.IterAllActiveSecrets(ctx)
	if err != nil || len(recs) != n {
		t.Fatalf("active = %d %v", len(recs), err)
	}
	for _, r := range recs {
		if r.DEKVersion != 7 || !bytes.HasPrefix(r.Ciphertext, []byte("new-")) {
			t.Fatalf("row %+v not rewritten", r)
		}
	}
	// Checksums were recomputed: every active row reads back.
	if _, _, err := s.GetSecret(ctx, "ns", "s5", ""); err != nil {
		t.Errorf("read after rewrite: %v", err)
	}

	if err := s.UpdateSecretCiphertext(ctx, recs[0].ID, []byte("single"), 9); err != nil {
		t.Fatal(err)
	}
	ct, dv, err := s.GetSecret(ctx, recs[0].Namespace, recs[0].Name, "")
	if err != nil || string(ct) != "single" || dv != 9 {
		t.Errorf("after update: %q %d %v", ct, dv, err)
	}
	counts, err := s.ActiveSecretCounts(ctx)
	if err != nil || len(counts) != 1 || counts[0] != (NamespaceCount{"ns", n}) {
		t.Errorf("counts = %v %v", counts, err)
	}
}
