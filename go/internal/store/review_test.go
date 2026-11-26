package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestExportDoesNotTakeWriteLock: an export holds only a read snapshot, so
// a writer in another Store (another process) can commit while it runs.
func TestExportDoesNotTakeWriteLock(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if _, err := s.SetSecret(ctx, SetSecretParams{Namespace: "ns", Name: "k", Ciphertext: []byte("x"), DEKVersion: 1}); err != nil {
		t.Fatal(err)
	}
	other := openT(t, s.Path())
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var exportErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := s.ExportData(ctx); err != nil {
				exportErr = err
				return
			}
		}
	}()
	start := time.Now()
	for i := 0; i < 30; i++ {
		if err := other.LogAudit(ctx, AuditEvent{Action: "W"}); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	if exportErr != nil {
		t.Fatal(exportErr)
	}
	if time.Since(start) > 4*time.Second {
		t.Errorf("writers were blocked by concurrent exports (%v)", time.Since(start))
	}
	if ok, _ := s.VerifyAuditChain(ctx); !ok {
		t.Error("chain broken")
	}
	// The pooled connection used by the export is not left inside a tx.
	if _, err := s.SetSecret(ctx, SetSecretParams{Namespace: "ns", Name: "k2", Ciphertext: []byte("y"), DEKVersion: 1}); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidNullStringHashedAsEmpty(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if err := s.LogAudit(ctx, AuditEvent{Action: "A", SecretName: sql.NullString{String: "stale", Valid: false}}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.VerifyAuditChain(ctx); !ok {
		t.Error("an invalid NullString with a String value broke the chain")
	}
	if a := lastAudit(t, s); a.SecretName.Valid {
		t.Errorf("secret_name stored %v, want NULL", a.SecretName)
	}
}

func TestDecodeAndBindEdgeCases(t *testing.T) {
	for _, in := range []string{`{} }`, `{} ]`, `{} 1`, `{}{}`} {
		if _, err := DecodeImportJSON([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if _, err := DecodeImportJSON([]byte("{}\n  ")); err != nil {
		t.Errorf("trailing whitespace rejected: %v", err)
	}
	data, _ := DecodeImportJSON([]byte(`{"secrets": [{"id": 9223372036854775808, "name": "a", "ciphertext": "QQ=="}]}`))
	if err := newStore(t).ImportData(context.Background(), data); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("int64 overflow: %v", err)
	}
	if _, err := newStore(t).BulkRewriteActiveSecrets(context.Background(), nil); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("nil rewrite fn: %v", err)
	}
}

func TestBulkRewriteNegativeIDs(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	for _, id := range []int64{-1 << 63, -5, 3} {
		if _, err := s.db.Exec(`INSERT INTO secrets (id, secret_id, namespace, name, version, ciphertext, checksum, created_at, updated_at, status, dek_version)
			VALUES (?, 'i', 'ns', ?, 1, x'00', 'c', 't', 't', 'ACTIVE', 1)`, id, "n"+fmtI(int(id%1000))); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.BulkRewriteActiveSecrets(ctx, func(r SecretRecord) ([]byte, int64, error) { return []byte("z"), 1, nil })
	if err != nil || n != 3 {
		t.Errorf("rewrote %d rows (%v), want 3 incl. id=MinInt64", n, err)
	}
}

func TestOpenPathCharacters(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"a#b", "a%20b", "a b", "ünï"} {
		path := filepath.Join(t.TempDir(), name, "vault.db")
		s := openT(t, path)
		if _, err := s.KeyEpoch(ctx); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var fk int
		if err := s.db.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
			t.Errorf("%s: PRAGMAs not applied (foreign_keys=%d, %v)", name, fk, err)
		}
		if st, _ := filepath.Glob(path); len(st) != 1 {
			t.Errorf("%s: database not created at the given path", name)
		}
	}
	if _, err := Open(ctx, "file:"+filepath.Join(t.TempDir(), "v.db")); err == nil {
		t.Error("file: path accepted")
	}
}
