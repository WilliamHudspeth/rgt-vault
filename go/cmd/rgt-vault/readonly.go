package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"rgt-vault-server/internal/audit"
	"rgt-vault-server/internal/store"

	_ "modernc.org/sqlite" // the pure-Go driver store registers too; explicit for this file
)

// roDB is a vault database opened strictly read-only: no migrations, no
// metadata initialisation, no audit rows, no master secret. The offline
// verify-audit, status and migrate check commands use it, so looking at a
// vault (even one the Go line cannot open yet) never changes it.
type roDB struct {
	path string
	db   *sql.DB
}

// roDSN builds the SQLite URI for a read-only open of path.
func roDSN(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // Windows drive path: file:///C:/dir/vault.db
	}
	u := url.URL{Scheme: "file", Path: p}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "query_only(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	return u.String() + "?" + q.Encode(), nil
}

// openReadOnly opens an existing database file read-only.
func openReadOnly(path string) (*roDB, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("database %s does not exist", path)
		}
		return nil, fmt.Errorf("database %s: %w", path, err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("database %s is a directory", path)
	}
	dsn, err := roDSN(path)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %s read-only: %w", path, err)
	}
	// One connection: the queries are sequential and tiny.
	db.SetMaxOpenConns(1)
	r := &roDB{path: path, db: db}
	// Fail now, with a clear message, if this is not a SQLite database.
	if _, err := r.tables(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%s is not a readable SQLite database: %w", path, err)
	}
	return r, nil
}

func (r *roDB) Close() error { return r.db.Close() }

// tables returns the set of table names.
func (r *roDB) tables(ctx context.Context) (map[string]bool, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type = 'table'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[n] = true
	}
	return out, rows.Err()
}

// metadata returns the metadata table (empty if it does not exist).
func (r *roDB) metadata(ctx context.Context, tables map[string]bool) (map[string]string, error) {
	out := map[string]string{}
	if !tables["metadata"] {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, "SELECT key, value FROM metadata")
	if err != nil {
		return nil, fmt.Errorf("reading metadata: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("reading metadata: %w", err)
		}
		out[k] = v
	}
	return out, rows.Err()
}

// migrations returns the applied schema_migrations versions, ascending.
func (r *roDB) migrations(ctx context.Context, tables map[string]bool) ([]int64, error) {
	if !tables["schema_migrations"] {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, fmt.Errorf("reading schema_migrations: %w", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("reading schema_migrations: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// auditChain is the verdict of the audit hash chain.
type auditChain struct {
	Rows int
	// FirstBad is the id of the first row that does not verify, 0 if OK.
	FirstBad int64
	OK       bool
}

// verifyAudit reads every audit row oldest-first and verifies the chain with
// exactly the semantics of Python's verify_audit_chain (internal/audit). A
// database without an audit_logs table has an empty, valid chain.
func (r *roDB) verifyAudit(ctx context.Context, tables map[string]bool) (auditChain, error) {
	if !tables["audit_logs"] {
		return auditChain{OK: true}, nil
	}
	rows, err := r.db.QueryContext(ctx,
		"SELECT id, action, secret_name, timestamp, details, prev_hash, entry_hash, policy_hash, agent_id FROM audit_logs ORDER BY id ASC")
	if err != nil {
		return auditChain{}, fmt.Errorf("reading audit log: %w", err)
	}
	defer rows.Close()
	var chain []audit.Row
	var ids []int64
	for rows.Next() {
		var ar store.AuditRow
		if err := rows.Scan(&ar.ID, &ar.Action, &ar.SecretName, &ar.Timestamp, &ar.Details,
			&ar.PrevHash, &ar.EntryHash, &ar.PolicyHash, &ar.AgentID); err != nil {
			return auditChain{}, fmt.Errorf("reading audit log: %w", err)
		}
		chain = append(chain, ar.ChainRow())
		ids = append(ids, ar.ID)
	}
	if err := rows.Err(); err != nil {
		return auditChain{}, fmt.Errorf("reading audit log: %w", err)
	}
	res := auditChain{Rows: len(chain), OK: true}
	if i := audit.FirstInvalid(chain); i >= 0 {
		res.OK, res.FirstBad = false, ids[i]
	}
	return res, nil
}

// secretStats are the counts migrate check and status report.
type secretStats struct {
	Total int64
	// ByDEK counts rows per dek_version.
	ByDEK map[int64]int64
	// ByStatus counts rows per status.
	ByStatus map[string]int64
	// LegacyActive counts ACTIVE rows with dek_version 0 (the rows the Go
	// vault refuses, decision D3).
	LegacyActive int64
	// ActiveByNamespace counts ACTIVE rows per namespace.
	ActiveByNamespace map[string]int64
}

func (r *roDB) secretStats(ctx context.Context, tables map[string]bool) (secretStats, error) {
	st := secretStats{ByDEK: map[int64]int64{}, ByStatus: map[string]int64{}, ActiveByNamespace: map[string]int64{}}
	if !tables["secrets"] {
		return st, nil
	}
	rows, err := r.db.QueryContext(ctx, "SELECT namespace, status, COALESCE(dek_version, 0), COUNT(*) FROM secrets GROUP BY namespace, status, COALESCE(dek_version, 0)")
	if err != nil {
		return st, fmt.Errorf("reading secrets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ns, status string
		var dek, n int64
		if err := rows.Scan(&ns, &status, &dek, &n); err != nil {
			return st, fmt.Errorf("reading secrets: %w", err)
		}
		st.Total += n
		st.ByDEK[dek] += n
		st.ByStatus[status] += n
		if status == "ACTIVE" {
			st.ActiveByNamespace[ns] += n
			if dek == 0 {
				st.LegacyActive += n
			}
		}
	}
	return st, rows.Err()
}

// lastAudit returns the newest audit row (ok false if the log is empty).
func (r *roDB) lastAudit(ctx context.Context, tables map[string]bool) (action, ts, name string, ok bool, err error) {
	if !tables["audit_logs"] {
		return "", "", "", false, nil
	}
	var n sql.NullString
	err = r.db.QueryRowContext(ctx, "SELECT action, timestamp, secret_name FROM audit_logs ORDER BY id DESC LIMIT 1").Scan(&action, &ts, &n)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, fmt.Errorf("reading audit log: %w", err)
	}
	return action, ts, n.String, true, nil
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
