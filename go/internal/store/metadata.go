package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
)

// VaultID returns the vault's UUID from metadata, creating a random UUIDv4
// on first use (get_vault_id). The insert is INSERT OR IGNORE + re-read so
// two concurrent first callers agree on one id.
func (s *Store) VaultID(ctx context.Context) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key = 'vault_id'").Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("store: read vault_id: %w", err)
	}
	newID, err := newUUID4()
	if err != nil {
		return "", err
	}
	err = s.writeTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO metadata (key, value) VALUES ('vault_id', ?)", newID); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key = 'vault_id'").Scan(&id)
	})
	if err != nil {
		return "", fmt.Errorf("store: create vault_id: %w", err)
	}
	return id, nil
}

// KeyEpoch returns the master-key epoch, initialising it to 1 on first use
// (get_key_epoch).
func (s *Store) KeyEpoch(ctx context.Context) (int64, error) {
	v, ok, err := s.readMeta(ctx, s.db, "key_epoch")
	if err != nil {
		return 0, err
	}
	if ok {
		return parseMetaInt("key_epoch", v)
	}
	var epoch int64
	err = s.writeTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO metadata (key, value) VALUES ('key_epoch', '1')"); err != nil {
			return err
		}
		v, _, err := s.readMeta(ctx, tx, "key_epoch")
		if err != nil {
			return err
		}
		epoch, err = parseMetaInt("key_epoch", v)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("store: init key_epoch: %w", err)
	}
	return epoch, nil
}

// IncrementKeyEpoch bumps the epoch by one and returns the new value
// (increment_key_epoch). Python reads and writes in two steps; here both run
// in one write transaction, which stores the same value.
func (s *Store) IncrementKeyEpoch(ctx context.Context) (int64, error) {
	var next int64
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO metadata (key, value) VALUES ('key_epoch', '1')"); err != nil {
			return err
		}
		v, _, err := s.readMeta(ctx, tx, "key_epoch")
		if err != nil {
			return err
		}
		cur, err := parseMetaInt("key_epoch", v)
		if err != nil {
			return err
		}
		next = cur + 1
		_, err = tx.ExecContext(ctx, "UPDATE metadata SET value = ? WHERE key = 'key_epoch'", strconv.FormatInt(next, 10))
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("store: increment key_epoch: %w", err)
	}
	return next, nil
}

// DEKUsage returns (encrypt_count, bytes_encrypted) for the active DEK
// (get_dek_usage). Missing rows read as 0.
func (s *Store) DEKUsage(ctx context.Context) (count, nbytes int64, err error) {
	return s.dekUsage(ctx, s.db)
}

// dekUsage reads both counters with ONE statement, so the pair always comes
// from a single read snapshot (no torn read against a concurrent increment
// or reset).
func (s *Store) dekUsage(ctx context.Context, q querier) (count, nbytes int64, err error) {
	rows, err := q.QueryContext(ctx,
		"SELECT key, value FROM metadata WHERE key IN ('dek_encrypt_count', 'dek_encrypt_bytes')")
	if err != nil {
		return 0, 0, fmt.Errorf("store: read DEK usage: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return 0, 0, fmt.Errorf("store: read DEK usage: %w", err)
		}
		n, err := parseMetaInt(k, v)
		if err != nil {
			return 0, 0, err
		}
		if k == "dek_encrypt_count" {
			count = n
		} else {
			nbytes = n
		}
	}
	if err := rows.Err(); err != nil {
		return 0, 0, fmt.Errorf("store: read DEK usage: %w", err)
	}
	return count, nbytes, nil
}

// IncrementDEKUsage atomically adds one encryption and byteCount bytes to the
// DEK usage counters and returns the new totals (increment_dek_usage). The
// arithmetic is done in SQL, inside one BEGIN IMMEDIATE transaction, with the
// same statements as Python.
func (s *Store) IncrementDEKUsage(ctx context.Context, byteCount int64) (count, nbytes int64, err error) {
	err = s.writeTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO metadata (key, value) VALUES ('dek_encrypt_count', '1') "+
				"ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO metadata (key, value) VALUES ('dek_encrypt_bytes', ?) "+
				"ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + ? AS TEXT)",
			strconv.FormatInt(byteCount, 10), byteCount); err != nil {
			return err
		}
		count, nbytes, err = s.dekUsage(ctx, tx)
		return err
	})
	if err != nil {
		return 0, 0, fmt.Errorf("store: increment DEK usage: %w", err)
	}
	return count, nbytes, nil
}

// ResetDEKUsage zeroes both DEK usage counters (reset_dek_usage).
func (s *Store) ResetDEKUsage(ctx context.Context) error {
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		for _, k := range []string{"dek_encrypt_count", "dek_encrypt_bytes"} {
			if _, err := tx.ExecContext(ctx,
				"INSERT INTO metadata (key, value) VALUES (?, '0') "+
					"ON CONFLICT(key) DO UPDATE SET value = excluded.value", k); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: reset DEK usage: %w", err)
	}
	return nil
}

// querier is satisfied by *sql.DB and *sql.Tx.
type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func (s *Store) readMeta(ctx context.Context, q querier, key string) (string, bool, error) {
	var v string
	err := q.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key = ?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: read metadata %s: %w", key, err)
	}
	return v, true, nil
}

// parseMetaInt mirrors Python's int(str): surrounding whitespace is allowed.
func parseMetaInt(key, v string) (int64, error) {
	n, err := strconv.ParseInt(trimPySpace(v), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("store: metadata %s is not an integer: %q", key, v)
	}
	return n, nil
}

func trimPySpace(v string) string {
	i, j := 0, len(v)
	for i < j && isSpace(v[i]) {
		i++
	}
	for j > i && isSpace(v[j-1]) {
		j--
	}
	return v[i:j]
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

// newUUID4 returns a random RFC 4122 version-4 UUID in Python str(uuid4())
// form (lowercase, hyphenated).
func newUUID4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("store: random uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
