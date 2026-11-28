// Package store is the Go port of the rgt-vault SQLite storage backend
// (python/storage/sqlite.py, class StorageBackend).
//
// It opens and writes the SAME vault.db files as the Python line:
//
//   - the five migration files are embedded verbatim from
//     python/storage/migrations (a test pins byte equality while python/
//     exists) and applied with the same schema_migrations bookkeeping;
//   - every connection gets the same PRAGMAs (foreign_keys=ON,
//     journal_mode=WAL, synchronous=NORMAL, busy_timeout=5000);
//   - the parent directory is chmod 0700 and a new database file is 0600
//     (POSIX only, as in Python);
//   - audit rows are hashed with go/internal/audit (the Python hash input,
//     Python isoformat timestamps) and, for set/get/revoke, are appended in
//     the SAME transaction as the secret operation;
//   - event names and detail strings are the Python ones, byte for byte.
//
// Writes are serialised by a process-level mutex and run in BEGIN IMMEDIATE
// transactions on a dedicated connection (database/sql pins a Tx to one
// connection; the DSN sets _txlock=immediate), which is the Go equivalent of
// Python's threading.Lock + BEGIN IMMEDIATE.
//
// The store never sees plaintext: ciphertexts are opaque bytes produced by
// the vault layer (batch G7).
//
// Format is frozen: do not add migrations here until python/ is removed (GZ).
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/audit"

	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" driver (CGO_ENABLED=0)
)

// migrationFS holds the verbatim copies of python/storage/migrations/*.sql.
//
//go:embed migrations/*.sql
var migrationFS embed.FS

// createSchemaMigrations is the exact statement text Python executes before
// the migration files (sqlite.py _apply_migrations). SQLite stores CREATE
// TABLE text in sqlite_master, so the whitespace is kept identical to Python
// to make the resulting schema byte-identical.
const createSchemaMigrations = `
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
        `

// connParams are applied to every pooled connection. They are the PRAGMAs
// Python's _get_conn runs on each new connection, plus _txlock=immediate so
// that every database/sql transaction starts with BEGIN IMMEDIATE.
const connParams = "_pragma=busy_timeout(5000)" +
	"&_pragma=foreign_keys(ON)" +
	"&_pragma=journal_mode(WAL)" +
	"&_pragma=synchronous(NORMAL)" +
	"&_txlock=immediate"

// DefaultDBPath returns ~/.secure-vault/vault.db (Python DEFAULT_DB_PATH).
func DefaultDBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("store: resolve home directory: %w", err)
	}
	return filepath.Join(home, ".secure-vault", "vault.db"), nil
}

// Store is an open vault.db. It is safe for concurrent use.
type Store struct {
	path string
	db   *sql.DB
	// mu serialises every write transaction in this process (Python's
	// _audit_lock). It is not reentrant: callbacks passed to the bulk
	// rewrite functions must not call back into the Store.
	mu sync.Mutex
	// now is the clock; tests may replace it.
	now func() time.Time
}

// Open opens (creating if needed) the SQLite vault database at path and
// applies any pending migrations, exactly as StorageBackend.__init__ does.
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: empty database path")
	}
	if strings.ContainsRune(path, '?') {
		// The driver splits the DSN at the first '?'.
		return nil, fmt.Errorf("store: database path must not contain '?': %q", path)
	}
	if strings.HasPrefix(path, "file:") {
		// The driver would treat the whole DSN as a SQLite URI.
		return nil, fmt.Errorf("store: database path must not start with \"file:\": %q", path)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create directory: %w", err)
	}
	if isPOSIX() {
		_ = os.Chmod(dir, 0o700) // non-fatal if we don't own the parent dir (as in Python)
	}

	isNew := false
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		isNew = true
		// Pre-create the file 0600 so neither it nor the -wal/-shm files
		// (SQLite copies the main file's mode) are ever world-readable. The
		// end state is identical to Python's create-then-chmod.
		if isPOSIX() {
			f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil && !errors.Is(err, fs.ErrExist) {
				return nil, fmt.Errorf("store: create database file: %w", err)
			}
			if f != nil {
				_ = f.Close()
			}
		}
	} else if err != nil {
		return nil, fmt.Errorf("store: stat database file: %w", err)
	}

	db, err := sql.Open("sqlite", path+"?"+connParams)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	s := &Store{path: path, db: db, now: time.Now}
	if err := s.applyMigrations(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if isNew && isPOSIX() {
		_ = os.Chmod(path, 0o600)
	}
	return s, nil
}

func isPOSIX() bool { return runtime.GOOS != "windows" }

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

type migration struct {
	version int
	name    string
	sql     string
}

// migrations returns the embedded migrations sorted by file name, skipping
// files whose prefix before the first '_' is not an integer (as Python does).
func migrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var out []migration
	for _, n := range names {
		prefix, _, _ := strings.Cut(n, "_")
		v, err := strconv.Atoi(prefix)
		if err != nil {
			continue
		}
		b, err := migrationFS.ReadFile("migrations/" + n)
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: n, sql: string(b)})
	}
	return out, nil
}

// applyMigrations ports StorageBackend._apply_migrations.
//
// Python issues BEGIN and then cursor.executescript(script); executescript
// COMMITs any pending transaction first, so in effect each file runs as a raw
// script outside any transaction and the bookkeeping INSERT commits on its
// own. Files are therefore NOT wrapped in a transaction here either: 0002
// carries its own BEGIN TRANSACTION/COMMIT and would fail inside one.
func (s *Store) applyMigrations(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("store: connect: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, createSchemaMigrations); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}
	applied := map[int]bool{}
	rows, err := conn.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("store: read schema_migrations: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: read schema_migrations: %w", err)
		}
		applied[v] = true
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("store: read schema_migrations: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store: read schema_migrations: %w", err)
	}

	ms, err := migrations()
	if err != nil {
		return fmt.Errorf("store: load migrations: %w", err)
	}
	for _, m := range ms {
		if applied[m.version] {
			continue
		}
		if _, err := conn.ExecContext(ctx, m.sql); err != nil {
			// A script that opened its own transaction (0002) may have
			// left it open on failure; close it so the connection is clean.
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
			return fmt.Errorf("store: migration %s: %w", m.name, err)
		}
		if _, err := conn.ExecContext(ctx,
			"INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
			m.version, audit.PyISOTime(s.now())); err != nil {
			return fmt.Errorf("store: record migration %s: %w", m.name, err)
		}
	}
	return nil
}

// writeTx runs fn in a BEGIN IMMEDIATE transaction under the process write
// lock. fn's error (or a panic) rolls the transaction back. If fn returns a
// *commitThenError, the transaction is committed and its inner error returned
// (Python's "audit the failure, commit, then raise" pattern).
func (s *Store) writeTx(ctx context.Context, fn func(tx *sql.Tx) error) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	ferr := fn(tx)
	var cte *commitThenError
	if ferr != nil && !errors.As(ferr, &cte) {
		return ferr
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	committed = true
	if cte != nil {
		return cte.err
	}
	return nil
}

// commitThenError asks writeTx to commit and then return err.
type commitThenError struct{ err error }

func (e *commitThenError) Error() string { return e.err.Error() }
