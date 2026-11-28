package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/audit"
)

// AuditEvent is one audit entry to append. SecretName and AgentID are
// nullable columns (Python None -> NULL). Action and Details are sanitised by
// the audit package before they are hashed and stored.
type AuditEvent struct {
	Action     string
	SecretName sql.NullString
	Details    string
	PolicyHash string
	AgentID    sql.NullString
}

// Name is a convenience for a non-NULL secret_name / agent_id value.
func Name(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }

// AuditRow is one stored audit_logs row (all columns, as SELECT * returns).
type AuditRow struct {
	ID         int64
	Action     string
	SecretName sql.NullString
	Timestamp  string
	Details    sql.NullString
	PrevHash   sql.NullString
	EntryHash  string
	PolicyHash sql.NullString
	AgentID    sql.NullString
}

// ChainRow converts r to the verifier's row form. Every column is present
// (as with Python's dict(sqlite3.Row)), so a NULL renders as "None" where
// Python's verifier would.
func (r AuditRow) ChainRow() audit.Row {
	return audit.Row{
		Timestamp:  audit.Str(r.Timestamp),
		Action:     audit.Str(r.Action),
		SecretName: audit.FromNullable(r.SecretName.String, r.SecretName.Valid),
		Details:    audit.FromNullable(r.Details.String, r.Details.Valid),
		PolicyHash: audit.FromNullable(r.PolicyHash.String, r.PolicyHash.Valid),
		EntryHash:  audit.Str(r.EntryHash),
		PrevHash:   audit.FromNullable(r.PrevHash.String, r.PrevHash.Valid),
		AgentID:    audit.FromNullable(r.AgentID.String, r.AgentID.Valid),
	}
}

// LogAudit appends one audit entry in its own BEGIN IMMEDIATE transaction
// under the process write lock (log_audit): the read of the tail hash and
// the INSERT are one indivisible step, so concurrent writers cannot fork the
// chain.
func (s *Store) LogAudit(ctx context.Context, ev AuditEvent) error {
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		return s.appendAuditInTx(ctx, tx, ev)
	})
}

// appendAuditInTx ports _append_audit_in_tx: it reads prev_hash through the
// same transaction and inserts the new row there.
func (s *Store) appendAuditInTx(ctx context.Context, tx *sql.Tx, ev AuditEvent) error {
	prev := ""
	var p sql.NullString
	err := tx.QueryRowContext(ctx, "SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1").Scan(&p)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return fmt.Errorf("store: read audit tail: %w", err)
	default:
		// Python: prev_row[0] -- a NULL entry_hash is impossible (NOT NULL).
		prev = p.String
	}
	name := ""
	if ev.SecretName.Valid {
		name = ev.SecretName.String
	}
	e := audit.Next(prev, s.now(), ev.Action, name, ev.Details, ev.PolicyHash)
	if _, err := tx.ExecContext(ctx, `
            INSERT INTO audit_logs (action, secret_name, timestamp, details, prev_hash, entry_hash, policy_hash, agent_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Action, ev.SecretName, e.Timestamp, e.Details, e.PrevHash, e.EntryHash, e.PolicyHash, ev.AgentID); err != nil {
		return fmt.Errorf("store: insert audit row: %w", err)
	}
	return nil
}

// LastAuditHash returns the newest entry_hash, or ok=false for an empty log
// (last_audit_hash).
func (s *Store) LastAuditHash(ctx context.Context) (hash string, ok bool, err error) {
	err = s.db.QueryRowContext(ctx, "SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1").Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: read audit tail: %w", err)
	}
	return hash, true, nil
}

const auditColumns = "id, action, secret_name, timestamp, details, prev_hash, entry_hash, policy_hash, agent_id"

// GetAuditLog returns the newest limit rows, newest first (get_audit_log).
// As in SQLite, a negative limit means no limit.
func (s *Store) GetAuditLog(ctx context.Context, limit int) ([]AuditRow, error) {
	return s.queryAudit(ctx, "SELECT "+auditColumns+" FROM audit_logs ORDER BY id DESC LIMIT ?", limit)
}

// IterAuditLog returns every row, oldest first (iter_audit_log).
func (s *Store) IterAuditLog(ctx context.Context) ([]AuditRow, error) {
	return s.queryAudit(ctx, "SELECT "+auditColumns+" FROM audit_logs ORDER BY id ASC")
}

func (s *Store) queryAudit(ctx context.Context, q string, args ...any) ([]AuditRow, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: read audit log: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		if err := rows.Scan(&r.ID, &r.Action, &r.SecretName, &r.Timestamp, &r.Details,
			&r.PrevHash, &r.EntryHash, &r.PolicyHash, &r.AgentID); err != nil {
			return nil, fmt.Errorf("store: read audit log: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read audit log: %w", err)
	}
	return out, nil
}

// AuditLogCount returns the number of audit rows (audit_log_count).
func (s *Store) AuditLogCount(ctx context.Context) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs").Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count audit log: %w", err)
	}
	return n, nil
}

// VerifyAuditChain walks the whole audit log oldest-first and reports whether
// the hash chain is intact, with exactly the semantics of Python's
// VaultManager.verify_audit_chain (see audit.Verify; an empty log verifies).
func (s *Store) VerifyAuditChain(ctx context.Context) (bool, error) {
	rows, err := s.IterAuditLog(ctx)
	if err != nil {
		return false, err
	}
	chain := make([]audit.Row, len(rows))
	for i, r := range rows {
		chain[i] = r.ChainRow()
	}
	return audit.Verify(chain), nil
}
