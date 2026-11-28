package vault

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	// The pure-Go SQLite driver the store already uses (registered as
	// "sqlite"); imported here for the vault's own rotation connection.
	_ "modernc.org/sqlite"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/crypto"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/keychain"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/store"
)

// auxConnParams are the store's connection parameters (the PRAGMAs of
// Python's _get_conn plus BEGIN IMMEDIATE), except synchronous=FULL: a
// rotation commit must be durable before keychain.json is replaced.
const auxConnParams = "_pragma=busy_timeout(5000)" +
	"&_pragma=foreign_keys(ON)" +
	"&_pragma=journal_mode(WAL)" +
	"&_pragma=synchronous(FULL)" +
	"&_txlock=immediate"

// rewritePage bounds the rows held in memory during RotateDEK.
const rewritePage = 256

func openAux(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?"+auxConnParams)
	if err != nil {
		return nil, fmt.Errorf("vault: open database: %w", err)
	}
	db.SetMaxOpenConns(2)
	return db, nil
}

// syncDir makes a rename in dir durable (best effort; not supported on
// every platform).
func syncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
}

// installPending renames keychain.json.new over keychain.json and loads it.
// A missing .new whose target already holds the new epoch (another process
// completed the rename on Open) counts as success.
func (v *Vault) installPending(master []byte, epoch int64) (*keychain.Manager, []byte, error) {
	newPath := v.keychainPath + ".new"
	if err := os.Rename(newPath, v.keychainPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("install new keychain: %w", err)
	}
	syncDir(filepath.Dir(v.keychainPath))
	km := keychain.New(v.keychainPath)
	dek, err := km.Load(master, v.vaultID, epoch)
	if err != nil {
		return nil, nil, fmt.Errorf("reload new keychain: %w", err)
	}
	return km, dek, nil
}

// failAfterCommit marks the vault unusable after a rotation committed to the
// database but could not install the new key in memory; the caller holds
// v.mu exclusively. Open completes the rotation from keychain.json.new.
func (v *Vault) failAfterCommit(err error) error {
	keychain.Wipe(v.dek)
	v.dek = nil
	if v.km != nil {
		_ = v.km.Close()
	}
	v.broken = err
	return newErr([]error{ErrInconsistent}, err, "%s: %v", ErrInconsistent.Error(), err)
}

// RotateMaster rotates the master secret and re-wraps the SAME DEK under it
// with a new epoch; no secret is re-encrypted (python rotate_master_key).
//
// Only providers implementing Rotator support it. The capability is checked
// BEFORE anything changes (Python P1-4): platform providers (DPAPI, TPM,
// macOS Keychain) must be re-sealed out-of-band, then use RotateDEK.
//
// The new wrap is staged in keychain.json.new and the epoch bump committed
// before it replaces keychain.json, so a crash at any point leaves a state
// Open can complete. (As in Python, the provider switches to the new master
// secret before the commit; if the commit then fails, keychain.json.new holds
// the only wrap under the new master and Open uses it.)
func (v *Vault) RotateMaster(ctx context.Context) error {
	if err := v.withR(func() error { return nil }); err != nil {
		return err
	}
	rot, ok := v.provider.(Rotator)
	if !ok {
		return newErr([]error{ErrRotateNotSupported}, nil,
			"%T does not support automated master-key rotation. Re-seal the master secret out-of-band "+
				"(DPAPI/TPM/Keychain) and use RotateDEK instead.", v.provider)
	}
	v.rotMu.Lock()
	defer v.rotMu.Unlock()
	if err := v.hookConsult(ctx, OpRotate, SystemAgent, "_admin", "rotate_master_key", nil); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.usable(); err != nil {
		return err
	}

	oldMaster, err := v.provider.GetMasterSecret()
	if err != nil {
		return err
	}
	defer keychain.Wipe(oldMaster)

	// Stage: a copy of keychain.json, loaded, so Rewrap can write .new.
	newPath := v.keychainPath + ".new"
	cur, err := os.ReadFile(v.keychainPath)
	if err != nil {
		return fmt.Errorf("vault: read keychain: %w", err)
	}
	if err := os.WriteFile(newPath, cur, 0o600); err != nil {
		return fmt.Errorf("vault: stage keychain: %w", err)
	}
	pending := keychain.New(newPath)
	defer func() { _ = pending.Close() }()
	staged, err := pending.Load(oldMaster, v.vaultID, v.keyEpoch)
	keychain.Wipe(staged)
	if err != nil {
		_ = os.Remove(newPath)
		return err
	}

	// The provider is rotated inside the transaction, after the epoch
	// checks, so a failure before that point changes nothing.
	var newMaster []byte
	rewrapped := false
	defer func() { keychain.Wipe(newMaster) }()
	newEpoch, err := v.inRotationTx(ctx, func(_ *sql.Tx, newEpoch int64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		if newMaster, err = rot.RotateMasterSecret(); err != nil {
			newMaster = nil
			return err
		}
		if err := pending.Rewrap(newMaster, v.vaultID, newEpoch, v.kdfParams); err != nil {
			return err
		}
		rewrapped = true
		syncDir(filepath.Dir(newPath))
		if v.testMasterPreCommit != nil {
			return v.testMasterPreCommit()
		}
		return nil
	}, nil)
	if err != nil {
		var cu *commitUnknownError
		switch {
		case newMaster == nil && !errors.As(err, &cu):
			_ = os.Remove(newPath) // the provider was not touched
			return err
		case rewrapped:
			// The only wrap under the new master is in .new: keep it, and
			// stop using this handle so nothing overwrites it.
			return v.failAfterCommit(fmt.Errorf("master secret rotated in the provider but the key epoch was not "+
				"committed; %s holds the DEK wrapped under the new master, re-open the vault to complete: %w", newPath, err))
		default:
			return v.failAfterCommit(fmt.Errorf("master secret rotated in the provider but the DEK could not be "+
				"re-wrapped; restore the previous master secret in the provider%s: %w", recoveryHint(v.provider), err))
		}
	}
	if v.testBeforeSwap != nil {
		if err := v.testBeforeSwap(); err != nil {
			return v.failAfterCommit(err)
		}
	}
	km, dek, err := v.installPending(newMaster, newEpoch)
	if err != nil {
		return v.failAfterCommit(err)
	}
	keychain.Wipe(dek) // same DEK as v.dek
	_ = v.km.Close()
	v.km, v.keyEpoch = km, newEpoch
	if r, ok := v.provider.(MasterRecovery); ok { // the new keychain is installed: drop the previous secret
		_ = r.ConfirmMasterSecret(v.vaultID) // best effort: the next Open confirms again
	}
	return v.logAudit(ctx, "ROTATE", store.Name("MASTER_KEY"), "Master key rotated successfully")
}

// RotateDEK generates a new DEK and re-encrypts every secret version under
// it (python rotate_dek, with RGT-499 fixed: Python rewrites only ACTIVE
// rows, so older versions stop decrypting; Go rewrites all of them).
//
// Atomicity: the epoch bump, the DEK usage reset and every row rewrite are
// ONE BEGIN IMMEDIATE transaction (synchronous=FULL); the new key is written
// to keychain.json.new inside it. A failure before the commit removes the
// .new file while still holding the write lock and rolls everything back, so
// the old keychain and rows stay in effect. After the commit the .new file
// replaces keychain.json; if the process dies in between, Open completes it.
//
// Rows that do not decrypt under the current DEK and are not ACTIVE (for
// example versions an earlier Python rotate_dek orphaned) are left as they
// are; an ACTIVE row that does not decrypt aborts the rotation.
//
// A vault must be opened by one process at a time while it rotates: another
// process holding the old DEK in memory would keep writing under it.
func (v *Vault) RotateDEK(ctx context.Context) error {
	if err := v.withR(func() error { return nil }); err != nil {
		return err
	}
	v.rotMu.Lock()
	defer v.rotMu.Unlock()
	return v.rotateDEK(ctx, false)
}

// autoRotateDEK rotates when the usage counters are (still) over a threshold.
// Re-checking under the rotation lock means concurrent writers that all
// crossed the threshold trigger one rotation, not many.
func (v *Vault) autoRotateDEK(ctx context.Context) error {
	// A rotation already in progress resets the counters; do not wait for
	// it (a rotate hook that writes a secret would otherwise deadlock).
	if !v.rotMu.TryLock() {
		return nil
	}
	defer v.rotMu.Unlock()
	return v.rotateDEK(ctx, true)
}

func (v *Vault) overThreshold(ctx context.Context) (bool, error) {
	count, nbytes, err := v.store.DEKUsage(ctx)
	if err != nil {
		return false, err
	}
	return count >= v.dekMaxEncryptions || nbytes >= v.dekMaxBytes, nil
}

// rotateDEK runs with v.rotMu held and v.mu not held.
func (v *Vault) rotateDEK(ctx context.Context, onlyIfOver bool) error {
	if onlyIfOver {
		var over bool
		if err := v.withR(func() (err error) { over, err = v.overThreshold(ctx); return err }); err != nil || !over {
			return err
		}
	}
	if err := v.hookConsult(ctx, OpRotate, SystemAgent, "_admin", "rotate_dek", nil); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.usable(); err != nil {
		return err
	}
	master, err := v.provider.GetMasterSecret()
	if err != nil {
		return err
	}
	defer keychain.Wipe(master)

	newPath := v.keychainPath + ".new"
	pending := keychain.New(newPath)
	defer func() { _ = pending.Close() }()
	var newDEK []byte
	defer func() { keychain.Wipe(newDEK) }()

	newEpoch, err := v.inRotationTx(ctx, func(tx *sql.Tx, newEpoch int64) error {
		var err error
		if newDEK, err = pending.Initialize(master, v.vaultID, newEpoch, v.kdfParams); err != nil {
			return err
		}
		syncDir(filepath.Dir(newPath))
		if err := v.rewriteAll(ctx, tx, newDEK); err != nil {
			return err
		}
		// RGT-219: the new DEK starts its own encryption/byte budget at
		// zero (the statements of store.ResetDEKUsage, in this transaction).
		for _, k := range []string{"dek_encrypt_count", "dek_encrypt_bytes"} {
			if _, err := tx.ExecContext(ctx, "INSERT INTO metadata (key, value) VALUES (?, '0') "+
				"ON CONFLICT(key) DO UPDATE SET value = excluded.value", k); err != nil {
				return fmt.Errorf("vault: rotation: reset DEK usage: %w", err)
			}
		}
		return nil
	}, func() { _ = os.Remove(newPath) })
	if err != nil {
		var cu *commitUnknownError
		if errors.As(err, &cu) {
			return v.failAfterCommit(err) // keep .new; Open decides from the epochs
		}
		return err
	}
	if v.testAfterCommit != nil {
		v.testAfterCommit()
	}
	if v.testBeforeSwap != nil {
		if err := v.testBeforeSwap(); err != nil {
			return v.failAfterCommit(err)
		}
	}
	km, dek, err := v.installPending(master, newEpoch)
	if err != nil {
		return v.failAfterCommit(err)
	}
	keychain.Wipe(v.dek)
	_ = v.km.Close()
	v.km, v.dek, v.keyEpoch = km, dek, newEpoch
	return v.logAudit(ctx, "ROTATE", store.Name("DEK"), "Data Encryption Key rotated successfully")
}

// readEpoch reads metadata.key_epoch.
func readEpoch(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (int64, error) {
	var cur string
	if err := q.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key = 'key_epoch'").Scan(&cur); err != nil {
		return 0, fmt.Errorf("vault: read key_epoch: %w", err)
	}
	epoch, err := strconv.ParseInt(strings.TrimSpace(cur), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("vault: invalid key_epoch %q: %w", cur, err)
	}
	return epoch, nil
}

// inRotationTx starts a BEGIN IMMEDIATE transaction on the vault's own
// connection, bumps key_epoch exactly as store.IncrementKeyEpoch does, runs
// fn with the new epoch and commits. On failure onAbort (if any) runs while
// the write lock is still held, then the transaction rolls back. The caller
// holds v.mu exclusively, so no store write of this vault runs concurrently.
//
// Cancellation of ctx is honoured only before the commit: once the commit
// has been issued, its outcome is read back from the database rather than
// guessed, so a committed rotation is never undone by a late cancellation.
func (v *Vault) inRotationTx(ctx context.Context, fn func(tx *sql.Tx, newEpoch int64) error, onAbort func()) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	bg := context.WithoutCancel(ctx)
	tx, err := v.aux.BeginTx(bg, nil)
	if err != nil {
		return 0, fmt.Errorf("vault: rotation: begin: %w", err)
	}
	abort := func(err error) (int64, error) {
		if onAbort != nil {
			onAbort()
		}
		_ = tx.Rollback()
		return 0, err
	}
	if _, err := tx.ExecContext(bg, "INSERT OR IGNORE INTO metadata (key, value) VALUES ('key_epoch', '1')"); err != nil {
		return abort(fmt.Errorf("vault: rotation: %w", err))
	}
	epoch, err := readEpoch(bg, tx)
	if err != nil {
		return abort(err)
	}
	if epoch != v.keyEpoch {
		return abort(fmt.Errorf("vault: rotation: key_epoch changed on disk (%d, expected %d); re-open the vault", epoch, v.keyEpoch))
	}
	newEpoch := epoch + 1
	if _, err := tx.ExecContext(bg, "UPDATE metadata SET value = ? WHERE key = 'key_epoch'",
		strconv.FormatInt(newEpoch, 10)); err != nil {
		return abort(fmt.Errorf("vault: rotation: %w", err))
	}
	// fn checks ctx itself: past this point a commit is not cancelled.
	if err := fn(tx, newEpoch); err != nil {
		return abort(err)
	}
	if cerr := tx.Commit(); cerr != nil {
		// Did it commit anyway? Ask the database (the transaction is over
		// either way, so this read cannot see uncommitted state). Only a
		// confirmed rollback runs onAbort.
		got, err := readEpoch(bg, v.aux)
		switch {
		case err == nil && got == newEpoch:
			return newEpoch, nil
		case err == nil && got == epoch:
			if onAbort != nil {
				onAbort()
			}
			return 0, fmt.Errorf("vault: rotation: commit: %w", cerr)
		default:
			return 0, &commitUnknownError{fmt.Errorf("vault: rotation: commit outcome unknown: %w", cerr)}
		}
	}
	return newEpoch, nil
}

// commitUnknownError: the rotation commit failed and its outcome could not
// be read back. keychain.json.new is kept; Open decides from the epochs.
type commitUnknownError struct{ err error }

func (e *commitUnknownError) Error() string { return e.err.Error() }
func (e *commitUnknownError) Unwrap() error { return e.err }

type rewriteRow struct {
	id         int64
	namespace  string
	name       string
	ciphertext []byte
	dekVersion int64
	status     string
}

// rewriteAll re-encrypts every secret row under newDEK inside tx, paging by
// id so memory stays bounded and no cursor is open across the UPDATEs.
func (v *Vault) rewriteAll(ctx context.Context, tx *sql.Tx, newDEK []byte) error {
	bg := context.WithoutCancel(ctx)
	var last int64 = -1 << 63
	n := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		rows, err := rewritePageRows(bg, tx, last)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		for _, r := range rows {
			if v.testRewriteRow != nil {
				if err := v.testRewriteRow(n); err != nil {
					return err
				}
			}
			n++
			ct, ok, err := v.reencrypt(r, newDEK)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			sum := sha256.Sum256(ct)
			if _, err := tx.ExecContext(bg,
				"UPDATE secrets SET ciphertext = ?, checksum = ?, dek_version = ? WHERE id = ?",
				ct, hex.EncodeToString(sum[:]), 1, r.id); err != nil {
				return fmt.Errorf("vault: rotation: update row %d: %w", r.id, err)
			}
		}
		last = rows[len(rows)-1].id
	}
}

func rewritePageRows(ctx context.Context, tx *sql.Tx, after int64) ([]rewriteRow, error) {
	q, err := tx.QueryContext(ctx,
		"SELECT id, namespace, name, ciphertext, dek_version, status FROM secrets WHERE id > ? ORDER BY id LIMIT ?",
		after, rewritePage)
	if err != nil {
		return nil, fmt.Errorf("vault: rotation: read secrets: %w", err)
	}
	defer func() { _ = q.Close() }()
	var out []rewriteRow
	for q.Next() {
		var r rewriteRow
		if err := q.Scan(&r.id, &r.namespace, &r.name, &r.ciphertext, &r.dekVersion, &r.status); err != nil {
			return nil, fmt.Errorf("vault: rotation: read secrets: %w", err)
		}
		out = append(out, r)
	}
	if err := q.Err(); err != nil {
		return nil, fmt.Errorf("vault: rotation: read secrets: %w", err)
	}
	return out, nil
}

// reencrypt returns the row's ciphertext under newDEK, or ok=false for a
// non-ACTIVE row that cannot be decrypted (left unchanged).
func (v *Vault) reencrypt(r rewriteRow, newDEK []byte) (ct []byte, ok bool, err error) {
	active := r.status == store.StatusActive
	if r.dekVersion != 1 {
		if active {
			return nil, false, fmt.Errorf("vault: rotation: active secret %s/%s (row %d) has unsupported dek_version %d",
				r.namespace, r.name, r.id, r.dekVersion)
		}
		return nil, false, nil
	}
	aad := v.aad(r.namespace, r.name)
	pt, err := crypto.Decrypt(r.ciphertext, v.dek, aad)
	if err != nil {
		if active {
			return nil, false, fmt.Errorf("vault: rotation: decrypt %s/%s (row %d): %w", r.namespace, r.name, r.id, err)
		}
		return nil, false, nil
	}
	defer keychain.Wipe(pt)
	ct, err = crypto.Encrypt(pt, newDEK, aad)
	if err != nil {
		return nil, false, err
	}
	return ct, true, nil
}

// recoveryHint is ": <hint>" for a provider that keeps the previous master
// secret (MasterRecovery), else "".
func recoveryHint(p MasterProvider) string {
	if r, ok := p.(MasterRecovery); ok {
		return " (" + r.RecoveryHint() + ")"
	}
	return ""
}
