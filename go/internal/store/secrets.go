package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"rgt-vault-server/internal/audit"
)

// Secret status values stored in secrets.status.
const (
	StatusActive     = "ACTIVE"
	StatusSuperseded = "SUPERSEDED"
	StatusRevoked    = "REVOKED"
)

// ErrNotFound is returned by GetSecret when no matching row exists (Python
// returns None). The GET_SECRET_FAILED audit row has been committed.
var ErrNotFound = errors.New("store: secret not found")

// ErrChecksum is the Go form of Python's ChecksumError: the stored checksum
// does not match sha256(ciphertext). The GET_SECRET_FAILED audit row has been
// committed. Errors wrap it with Python's message.
var ErrChecksum = errors.New("store: checksum mismatch")

// ErrInvalidArgument marks errors that Python raises as ValueError.
var ErrInvalidArgument = errors.New("store: invalid argument")

// valueError carries Python's ValueError message verbatim.
type valueError struct{ msg string }

func (e *valueError) Error() string        { return e.msg }
func (e *valueError) Is(target error) bool { return target == ErrInvalidArgument }

func newValueError(format string, a ...any) error {
	return &valueError{msg: fmt.Sprintf(format, a...)}
}

func checksum(ct []byte) string {
	sum := sha256.Sum256(ct)
	return hex.EncodeToString(sum[:])
}

// SetSecretParams are the arguments of set_secret.
type SetSecretParams struct {
	Namespace  string
	Name       string
	Ciphertext []byte
	DEKVersion int64
	// SecretID is used only for a brand-new name; an existing name keeps its
	// secret_id. Empty means generate a UUIDv4.
	SecretID   string
	PolicyHash string
	Note       string
	Require2FA bool
}

// SetSecret stores a new ACTIVE version of (namespace, name), marking the
// previous ACTIVE version SUPERSEDED, and appends the SET_SECRET audit row in
// the same BEGIN IMMEDIATE transaction (set_secret). It returns the new
// version number.
func (s *Store) SetSecret(ctx context.Context, p SetSecretParams) (int64, error) {
	sum := checksum(p.Ciphertext)
	now := audit.PyISOTime(s.now())
	secretID := p.SecretID
	if secretID == "" {
		var err error
		if secretID, err = newUUID4(); err != nil {
			return 0, err
		}
	}
	var next int64
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		var existing string
		err := tx.QueryRowContext(ctx,
			"SELECT secret_id FROM secrets WHERE namespace = ? AND name = ? LIMIT 1", p.Namespace, p.Name).Scan(&existing)
		switch {
		case err == nil:
			secretID = existing
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		if _, err := tx.ExecContext(ctx,
			"UPDATE secrets SET status = 'SUPERSEDED' WHERE namespace = ? AND name = ? AND status = 'ACTIVE'",
			p.Namespace, p.Name); err != nil {
			return err
		}
		var maxV sql.NullInt64
		if err := tx.QueryRowContext(ctx,
			"SELECT MAX(version) FROM secrets WHERE namespace = ? AND name = ?", p.Namespace, p.Name).Scan(&maxV); err != nil {
			return err
		}
		next = 1
		if maxV.Valid {
			next = maxV.Int64 + 1
		}
		req := 0
		if p.Require2FA {
			req = 1
		}
		if _, err := tx.ExecContext(ctx, `
                    INSERT INTO secrets (secret_id, namespace, name, version, ciphertext, checksum, created_at, updated_at, status, dek_version, note, require_2fa)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?)`,
			secretID, p.Namespace, p.Name, next, p.Ciphertext, sum, now, now, p.DEKVersion, p.Note, req); err != nil {
			return err
		}
		return s.appendAuditInTx(ctx, tx, AuditEvent{
			Action:     "SET_SECRET",
			SecretName: Name(p.Name),
			Details:    fmt.Sprintf("Version %d created in %s", next, p.Namespace),
			PolicyHash: p.PolicyHash,
		})
	})
	if err != nil {
		return 0, fmt.Errorf("store: set secret: %w", err)
	}
	return next, nil
}

// GetSecret returns the ciphertext and dek_version of the newest ACTIVE
// version (get_secret with version=None).
func (s *Store) GetSecret(ctx context.Context, namespace, name, policyHash string) ([]byte, int64, error) {
	return s.getSecret(ctx, namespace, name, nil, policyHash)
}

// GetSecretVersion returns a specific version in any status (get_secret with
// an explicit version).
func (s *Store) GetSecretVersion(ctx context.Context, namespace, name string, version int64, policyHash string) ([]byte, int64, error) {
	return s.getSecret(ctx, namespace, name, &version, policyHash)
}

// getSecret ports get_secret: the read and its audit row commit together, so
// an unlogged read is impossible. Missing rows and checksum mismatches are
// audited as GET_SECRET_FAILED and committed before the error is returned.
func (s *Store) getSecret(ctx context.Context, namespace, name string, version *int64, policyHash string) ([]byte, int64, error) {
	var (
		ct     []byte
		dekVer int64
	)
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		var row *sql.Row
		if version != nil {
			row = tx.QueryRowContext(ctx, `
                        SELECT ciphertext, checksum, dek_version FROM secrets
                        WHERE namespace = ? AND name = ? AND version = ?`, namespace, name, *version)
		} else {
			row = tx.QueryRowContext(ctx, `
                        SELECT ciphertext, checksum, dek_version FROM secrets
                        WHERE namespace = ? AND name = ? AND status = 'ACTIVE' ORDER BY version DESC LIMIT 1`, namespace, name)
		}
		var (
			sum string
			dv  sql.NullInt64
		)
		err := row.Scan(&ct, &sum, &dv)
		if errors.Is(err, sql.ErrNoRows) {
			if aerr := s.appendAuditInTx(ctx, tx, AuditEvent{
				Action:     "GET_SECRET_FAILED",
				SecretName: Name(name),
				Details:    "Secret not found in " + namespace,
				PolicyHash: policyHash,
			}); aerr != nil {
				return aerr
			}
			return &commitThenError{err: ErrNotFound}
		}
		if err != nil {
			return err
		}
		if checksum(ct) != sum {
			if aerr := s.appendAuditInTx(ctx, tx, AuditEvent{
				Action:     "GET_SECRET_FAILED",
				SecretName: Name(name),
				Details:    "Checksum mismatch",
				PolicyHash: policyHash,
			}); aerr != nil {
				return aerr
			}
			return &commitThenError{err: fmt.Errorf("%w: Integrity check failed for secret '%s/%s'", ErrChecksum, namespace, name)}
		}
		// dek_version is nullable in the schema (0003 adds it with DEFAULT 0);
		// Python would return None. Report NULL as 0 (legacy).
		dekVer = dv.Int64
		which := "latest"
		if version != nil {
			which = strconv.FormatInt(*version, 10)
		}
		return s.appendAuditInTx(ctx, tx, AuditEvent{
			Action:     "GET_SECRET",
			SecretName: Name(name),
			Details:    fmt.Sprintf("Version %s accessed from %s", which, namespace),
			PolicyHash: policyHash,
		})
	})
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrChecksum) {
		return nil, 0, err
	}
	if err != nil {
		return nil, 0, fmt.Errorf("store: get secret: %w", err)
	}
	return ct, dekVer, nil
}

// SecretInfo is one list_secrets entry. It never contains the value.
type SecretInfo struct {
	SecretID      string `json:"secret_id"`
	Name          string `json:"name"`
	LatestVersion int64  `json:"latest_version"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
	Status        string `json:"status"`
	Note          string `json:"note"`
	Require2FA    bool   `json:"require_2fa"`
}

// ListSecrets lists ACTIVE secrets in namespace and then appends a
// LIST_SECRETS audit row (list_secrets). As in Python, the read and the audit
// row are separate transactions and the order is SQLite's natural order.
func (s *Store) ListSecrets(ctx context.Context, namespace, policyHash string, limit, offset int) ([]SecretInfo, error) {
	if limit < 1 || limit > 1000 {
		return nil, newValueError("limit must be between 1 and 1000")
	}
	if offset < 0 {
		return nil, newValueError("offset must be >= 0")
	}
	rows, err := s.db.QueryContext(ctx, `
                SELECT secret_id, name, version, created_at, updated_at, status, note, require_2fa
                FROM secrets
                WHERE namespace = ? AND status = 'ACTIVE'
                LIMIT ? OFFSET ?`, namespace, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("store: list secrets: %w", err)
	}
	out := []SecretInfo{}
	for rows.Next() {
		var (
			si  SecretInfo
			req sql.NullInt64
		)
		if err := rows.Scan(&si.SecretID, &si.Name, &si.LatestVersion, &si.CreatedAt, &si.UpdatedAt,
			&si.Status, &si.Note, &req); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: list secrets: %w", err)
		}
		si.Require2FA = req.Int64 != 0
		out = append(out, si)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("store: list secrets: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list secrets: %w", err)
	}
	if err := s.LogAudit(ctx, AuditEvent{
		Action:     "LIST_SECRETS",
		Details:    fmt.Sprintf("Listed %d secrets in %s", len(out), namespace),
		PolicyHash: policyHash,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// Requires2FA reports whether the ACTIVE version of the secret is flagged for
// a TOTP second factor (requires_2fa). A missing secret reports false.
func (s *Store) Requires2FA(ctx context.Context, namespace, name string) (bool, error) {
	var req sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		"SELECT require_2fa FROM secrets WHERE namespace = ? AND name = ? AND status = 'ACTIVE' LIMIT 1",
		namespace, name).Scan(&req)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: read require_2fa: %w", err)
	}
	return req.Int64 != 0, nil
}

// RevokeSecret marks the ACTIVE version REVOKED and appends REVOKE_SECRET in
// the same transaction (revoke_secret). Revoking a missing secret still
// writes the audit row, as in Python.
func (s *Store) RevokeSecret(ctx context.Context, namespace, name, policyHash string) error {
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			"UPDATE secrets SET status = 'REVOKED' WHERE namespace = ? AND name = ? AND status = 'ACTIVE'",
			namespace, name); err != nil {
			return err
		}
		return s.appendAuditInTx(ctx, tx, AuditEvent{
			Action:     "REVOKE_SECRET",
			SecretName: Name(name),
			Details:    "Revoked active secret in " + namespace,
			PolicyHash: policyHash,
		})
	})
	if err != nil {
		return fmt.Errorf("store: revoke secret: %w", err)
	}
	return nil
}

// AddHoneytoken registers (namespace, name) as a honeytoken (INSERT OR
// IGNORE, add_honeytoken).
func (s *Store) AddHoneytoken(ctx context.Context, namespace, name string) error {
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO honeytokens (namespace, name) VALUES (?, ?)", namespace, name)
		return err
	})
	if err != nil {
		return fmt.Errorf("store: add honeytoken: %w", err)
	}
	return nil
}

// IsHoneytoken reports whether (namespace, name) is a honeytoken.
func (s *Store) IsHoneytoken(ctx context.Context, namespace, name string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, "SELECT 1 FROM honeytokens WHERE namespace = ? AND name = ?", namespace, name).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: read honeytokens: %w", err)
	}
	return true, nil
}

// SecretRecord is one row handed to the DEK-rotation rewrite.
type SecretRecord struct {
	ID         int64
	Namespace  string
	Name       string
	Ciphertext []byte
	DEKVersion int64
}

// IterAllActiveSecrets returns every ACTIVE secret (iter_all_active_secrets).
func (s *Store) IterAllActiveSecrets(ctx context.Context) ([]SecretRecord, error) {
	return s.querySecretRecords(ctx, s.db,
		"SELECT id, namespace, name, ciphertext, dek_version FROM secrets WHERE status = 'ACTIVE'")
}

func (s *Store) querySecretRecords(ctx context.Context, q querier, query string, args ...any) ([]SecretRecord, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: read secrets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []SecretRecord
	for rows.Next() {
		var (
			r  SecretRecord
			dv sql.NullInt64
		)
		if err := rows.Scan(&r.ID, &r.Namespace, &r.Name, &r.Ciphertext, &dv); err != nil {
			return nil, fmt.Errorf("store: read secrets: %w", err)
		}
		r.DEKVersion = dv.Int64
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read secrets: %w", err)
	}
	return out, nil
}

// UpdateSecretCiphertext replaces one row's ciphertext, checksum and
// dek_version (update_secret_ciphertext). No audit row, as in Python.
func (s *Store) UpdateSecretCiphertext(ctx context.Context, id int64, ct []byte, dekVersion int64) error {
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			"UPDATE secrets SET ciphertext = ?, checksum = ?, dek_version = ? WHERE id = ?",
			ct, checksum(ct), dekVersion, id)
		return err
	})
	if err != nil {
		return fmt.Errorf("store: update ciphertext: %w", err)
	}
	return nil
}

// HasLegacySecrets reports whether any ACTIVE secret has dek_version = 0.
func (s *Store) HasLegacySecrets(ctx context.Context) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx,
		"SELECT 1 FROM secrets WHERE status = 'ACTIVE' AND dek_version = 0 LIMIT 1").Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: read secrets: %w", err)
	}
	return true, nil
}

// RewriteFunc returns the new ciphertext and dek_version for one row. It
// runs while the store's write lock is held and must not call the Store.
type RewriteFunc func(rec SecretRecord) (newCiphertext []byte, newDEKVersion int64, err error)

// rewriteBatch matches Python's fetchmany(1000).
const rewriteBatch = 1000

// BulkRewriteActiveSecrets applies fn to every ACTIVE secret in ONE
// BEGIN IMMEDIATE transaction (bulk_rewrite_active_secrets, used by
// rotate_dek). If fn or any UPDATE fails, nothing is modified. It returns
// the number of rows rewritten. Like Python it writes no audit row; the
// caller (vault.RotateDEK) logs the rotation.
func (s *Store) BulkRewriteActiveSecrets(ctx context.Context, fn RewriteFunc) (int, error) {
	return s.bulkRewrite(ctx, "status = 'ACTIVE'", fn)
}

// BulkRewriteLegacySecrets is BulkRewriteActiveSecrets restricted to
// dek_version = 0 rows (bulk_rewrite_legacy_secrets).
func (s *Store) BulkRewriteLegacySecrets(ctx context.Context, fn RewriteFunc) (int, error) {
	return s.bulkRewrite(ctx, "status = 'ACTIVE' AND dek_version = 0", fn)
}

func (s *Store) bulkRewrite(ctx context.Context, where string, fn RewriteFunc) (int, error) {
	n := 0
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		// Page by id instead of holding one cursor open across the UPDATEs
		// (Python's fetchmany): the same rows, bounded memory, and no
		// statement is stepped while the table it reads is modified.
		var last int64 = -1 << 63
		for {
			batch, err := s.querySecretRecords(ctx, tx,
				"SELECT id, namespace, name, ciphertext, dek_version FROM secrets WHERE "+where+
					" AND id > ? ORDER BY id LIMIT ?", last, rewriteBatch)
			if err != nil {
				return err
			}
			if len(batch) == 0 {
				return nil
			}
			for _, rec := range batch {
				ct, ver, err := fn(rec)
				if err != nil {
					return fmt.Errorf("rewrite row %d: %w", rec.ID, err)
				}
				if _, err := tx.ExecContext(ctx,
					"UPDATE secrets SET ciphertext = ?, checksum = ?, dek_version = ? WHERE id = ?",
					ct, checksum(ct), ver, rec.ID); err != nil {
					return err
				}
				n++
			}
			last = batch[len(batch)-1].ID
		}
	})
	if err != nil {
		return 0, fmt.Errorf("store: bulk rewrite: %w", err)
	}
	return n, nil
}

// NamespaceCount is one row of ActiveSecretCounts.
type NamespaceCount struct {
	Namespace string
	Count     int64
}

// ActiveSecretCounts returns ACTIVE secret counts per namespace, ordered by
// namespace (the query cmd_status runs directly on the connection).
func (s *Store) ActiveSecretCounts(ctx context.Context) ([]NamespaceCount, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT namespace, COUNT(*) FROM secrets WHERE status = 'ACTIVE' GROUP BY namespace ORDER BY namespace")
	if err != nil {
		return nil, fmt.Errorf("store: count secrets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []NamespaceCount
	for rows.Next() {
		var c NamespaceCount
		if err := rows.Scan(&c.Namespace, &c.Count); err != nil {
			return nil, fmt.Errorf("store: count secrets: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: count secrets: %w", err)
	}
	return out, nil
}
