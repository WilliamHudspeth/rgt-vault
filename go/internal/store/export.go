package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Column is one key/value of an exported row.
type Column struct {
	Key   string
	Value any
}

// OrderedRow is one exported table row. It marshals to a JSON object whose
// keys are in table-column order, like Python's dict(sqlite3.Row).
type OrderedRow []Column

// Get returns the value of key and whether it is present.
func (r OrderedRow) Get(key string) (any, bool) {
	for _, c := range r {
		if c.Key == key {
			return c.Value, true
		}
	}
	return nil, false
}

// MarshalJSON implements json.Marshaler with stable key order.
func (r OrderedRow) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, c := range r {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := json.Marshal(c.Key)
		if err != nil {
			return nil, err
		}
		v, err := json.Marshal(c.Value)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// Export is the result of ExportData: every row of secrets (ciphertext as
// standard base64), audit_logs and honeytokens. It marshals to the same
// object Python's export_data returns; the vault layer adds "vault_id" and
// base64-wraps the JSON (export_vault).
type Export struct {
	Secrets     []OrderedRow `json:"secrets"`
	AuditLogs   []OrderedRow `json:"audit_logs"`
	Honeytokens []OrderedRow `json:"honeytokens"`
}

// ExportData dumps the three tables (export_data). Rows are in SQLite's
// natural order with every column, as SELECT * returns them.
func (s *Store) ExportData(ctx context.Context) (*Export, error) {
	// One DEFERRED read transaction on a pinned connection gives a consistent
	// snapshot of all three tables without taking the write lock (db.BeginTx
	// would issue BEGIN IMMEDIATE because of _txlock=immediate), so WAL lets
	// writers proceed while an export runs.
	tx, err := s.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: export: %w", err)
	}
	defer func() { _ = tx.Close() }()
	if _, err := tx.ExecContext(ctx, "BEGIN DEFERRED"); err != nil {
		return nil, fmt.Errorf("store: export: %w", err)
	}
	defer func() { _, _ = tx.ExecContext(context.WithoutCancel(ctx), "ROLLBACK") }()
	out := &Export{}
	if out.Secrets, err = dumpTable(ctx, tx, "SELECT * FROM secrets"); err != nil {
		return nil, err
	}
	for _, r := range out.Secrets {
		for i := range r {
			if r[i].Key != "ciphertext" {
				continue
			}
			switch v := r[i].Value.(type) {
			case []byte:
				r[i].Value = base64.StdEncoding.EncodeToString(v)
			case string:
				r[i].Value = base64.StdEncoding.EncodeToString([]byte(v))
			}
		}
	}
	if out.AuditLogs, err = dumpTable(ctx, tx, "SELECT * FROM audit_logs"); err != nil {
		return nil, err
	}
	if out.Honeytokens, err = dumpTable(ctx, tx, "SELECT * FROM honeytokens"); err != nil {
		return nil, err
	}
	return out, nil
}

func dumpTable(ctx context.Context, q querier, query string) ([]OrderedRow, error) {
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("store: export: %w", err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("store: export: %w", err)
	}
	out := []OrderedRow{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, fmt.Errorf("store: export: %w", err)
		}
		r := make(OrderedRow, len(cols))
		for i, c := range cols {
			r[i] = Column{Key: c, Value: vals[i]}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: export: %w", err)
	}
	return out, nil
}

// DecodeImportJSON parses an export JSON document the way Python's
// json.loads does for import_data: numbers keep integer precision.
func DecodeImportJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("store: trailing data after JSON document")
	}
	return v, nil
}

// ImportData replaces the contents of secrets, audit_logs and honeytokens
// with data (import_data), in one transaction: on any error nothing changes.
// data is a decoded JSON object (see DecodeImportJSON); validation, defaults
// and error messages are Python's. Audit rows are inserted as given (no
// re-hashing, no agent_id), so the imported chain verifies only if it did in
// the source vault.
func (s *Store) ImportData(ctx context.Context, data any) error {
	obj, ok := data.(map[string]any)
	if !ok {
		return newValueError("Import data must be a dictionary")
	}
	asList := func(key string) ([]any, error) {
		v, present := obj[key]
		if !present || v == nil {
			return nil, nil
		}
		l, ok := v.([]any)
		if !ok {
			return nil, newValueError("Import field '%s' must be a list", key)
		}
		return l, nil
	}
	secrets, err := asList("secrets")
	if err != nil {
		return err
	}
	auditLogs, err := asList("audit_logs")
	if err != nil {
		return err
	}
	honeytokens, err := asList("honeytokens")
	if err != nil {
		return err
	}

	return s.writeTx(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{"DELETE FROM secrets", "DELETE FROM audit_logs", "DELETE FROM honeytokens"} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return fmt.Errorf("store: import: %w", err)
			}
		}
		for _, item := range secrets {
			sm, ok := item.(map[string]any)
			if !ok || !has(sm, "id") || !has(sm, "name") || !has(sm, "ciphertext") {
				return newValueError("Malformed secret entry in import data")
			}
			ct, err := pyB64Decode(sm["ciphertext"])
			if err != nil {
				return newValueError("Failed to decode ciphertext: %v", err)
			}
			defaultID, err := newUUID4()
			if err != nil {
				return err
			}
			defaultStatus := StatusSuperseded
			if pyEqualsOne(sm["is_current"]) {
				defaultStatus = StatusActive
			}
			req := 0
			if pyTruthy(sm["require_2fa"]) {
				req = 1
			}
			args, err := bindAll(
				sm["id"],
				getOr(sm, "secret_id", defaultID),
				getOr(sm, "namespace", "default"),
				sm["name"],
				getOr(sm, "version", int64(1)),
				ct,
				getOr(sm, "checksum", ""),
				getOr(sm, "created_at", ""),
				getOr(sm, "updated_at", ""),
				getOr(sm, "status", defaultStatus),
				getOr(sm, "dek_version", int64(1)),
				getOr(sm, "note", ""),
				req,
			)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
                    INSERT INTO secrets (id, secret_id, namespace, name, version, ciphertext, checksum, created_at, updated_at, status, dek_version, note, require_2fa)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, args...); err != nil {
				return fmt.Errorf("store: import secret: %w", err)
			}
		}
		for _, item := range auditLogs {
			am, ok := item.(map[string]any)
			if !ok || !has(am, "id") || !has(am, "action") || !has(am, "entry_hash") {
				return newValueError("Malformed audit log entry in import data")
			}
			args, err := bindAll(
				am["id"],
				am["action"],
				am["secret_name"], // .get(): missing -> None
				getOr(am, "timestamp", ""),
				getOr(am, "details", ""),
				getOr(am, "prev_hash", ""),
				am["entry_hash"],
				getOr(am, "policy_hash", ""),
			)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
                    INSERT INTO audit_logs (id, action, secret_name, timestamp, details, prev_hash, entry_hash, policy_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, args...); err != nil {
				return fmt.Errorf("store: import audit row: %w", err)
			}
		}
		for _, item := range honeytokens {
			hm, ok := item.(map[string]any)
			if !ok || !has(hm, "name") {
				return newValueError("Malformed honeytoken entry in import data")
			}
			args, err := bindAll(getOr(hm, "namespace", "default"), hm["name"])
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO honeytokens (namespace, name) VALUES (?, ?)", args...); err != nil {
				return fmt.Errorf("store: import honeytoken: %w", err)
			}
		}
		return nil
	})
}

func has(m map[string]any, k string) bool { _, ok := m[k]; return ok }

// getOr is Python's dict.get(k, default): a present null stays nil.
func getOr(m map[string]any, k string, def any) any {
	if v, ok := m[k]; ok {
		return v
	}
	return def
}

// bindAll converts decoded JSON values to SQLite bind values the way
// Python's sqlite3 adapts them (int, float, str, None, bool->int). Objects
// and arrays cannot be bound, as in Python.
func bindAll(vals ...any) ([]any, error) {
	out := make([]any, len(vals))
	for i, v := range vals {
		switch x := v.(type) {
		case nil, string, []byte, int, int64:
			out[i] = x
		case bool:
			if x {
				out[i] = int64(1)
			} else {
				out[i] = int64(0)
			}
		case float64:
			out[i] = x
		case json.Number:
			if n, err := x.Int64(); err == nil {
				out[i] = n
			} else if !strings.ContainsAny(x.String(), ".eE") {
				// Python's sqlite3 raises OverflowError for ints beyond int64.
				return nil, newValueError("Error binding parameter %d: Python int too large to convert to SQLite INTEGER", i+1)
			} else if f, err := x.Float64(); err == nil {
				out[i] = f
			} else {
				return nil, newValueError("Error binding parameter %d: number out of range", i+1)
			}
		default:
			return nil, newValueError("Error binding parameter %d: type %T is not supported", i+1, v)
		}
	}
	return out, nil
}

// pyTruthy is Python truthiness for decoded JSON values.
func pyTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		f, err := x.Float64()
		return err != nil || f != 0
	case float64:
		return x != 0
	case int64:
		return x != 0
	case int:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// pyEqualsOne is Python's `v == 1` (True and 1.0 also compare equal).
func pyEqualsOne(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case json.Number:
		f, err := x.Float64()
		return err == nil && f == 1
	case float64:
		return x == 1
	case int64:
		return x == 1
	case int:
		return x == 1
	}
	return false
}

// pyB64Decode is base64.b64decode(v, validate=True): ASCII standard
// alphabet only (no whitespace, unlike Go's decoder, which skips CR/LF).
func pyB64Decode(v any) ([]byte, error) {
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("argument should be a bytes-like object or ASCII string, not %s", pyTypeName(v))
	}
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("Non-base64 digit found")
	}
	return base64.StdEncoding.DecodeString(s)
}

func pyTypeName(v any) string {
	switch x := v.(type) {
	case nil:
		return "'NoneType'"
	case bool:
		return "'bool'"
	case json.Number:
		if _, err := x.Int64(); err == nil {
			return "'int'"
		}
		return "'float'"
	case float64:
		return "'float'"
	case []any:
		return "'list'"
	case map[string]any:
		return "'dict'"
	}
	return fmt.Sprintf("'%T'", v)
}
