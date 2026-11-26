package vault

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	// The pure-Go SQLite driver the store already uses (registered as
	// "sqlite"); imported here for the rotation's own transaction.
	_ "modernc.org/sqlite"

	"rgt-vault-server/internal/crypto"
	"rgt-vault-server/internal/keychain"
	"rgt-vault-server/internal/store"
)

// rotationConnParams are the store's connection parameters (PRAGMAs of
// Python's _get_conn plus BEGIN IMMEDIATE for every transaction).
const rotationConnParams = "_pragma=busy_timeout(5000)" +
	"&_pragma=foreign_keys(ON)" +
	"&_pragma=journal_mode(WAL)" +
	"&_pragma=synchronous(NORMAL)" +
	"&_txlock=immediate"

// rewritePage bounds the rows held in memory during RotateDEK.
const rewritePage = 256

// RotateMaster rotates the master secret and re-wraps the SAME DEK under it
// with a new epoch; no secret is re-encrypted (python rotate_master_key).
//
// Only providers implementing Rotator support it. The capability is checked
// BEFORE anything changes (Python P1-4): platform providers (DPAPI, TPM,
// macOS Keychain) must be re-sealed out-of-band, then use RotateDEK.
//
// The epoch bump and the keychain re-wrap happen inside one database
// transaction, so a failing re-wrap leaves the epoch unchanged. (As in
// Python, the provider has already switched to the new master secret at that
// point; a failure there needs the old master restored by the operator.)
func (v *Vault) RotateMaster(ctx context.Context) error {
	rot, ok := v.provider.(Rotator)
	if !ok {
		return newErr([]error{ErrRotateNotSupported}, nil,
			"%T does not support automated master-key rotation. Re-seal the master secret out-of-band "+
				"(DPAPI/TPM/Keychain) and use RotateDEK instead.", v.provider)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.usable(); err != nil {
		return err
	}
	if err := v.hookConsult(ctx, OpRotate, SystemAgent, "_admin", "rotate_master_key", nil); err != nil {
		return err
	}

	newMaster, err := rot.RotateMasterSecret()
	if err != nil {
		return err
	}
	defer keychain.Wipe(newMaster)

	newEpoch, err := v.inRotationTx(ctx, func(tx *sql.Tx, newEpoch int64) error {
		return v.km.Rewrap(newMaster, v.vaultID, newEpoch, v.kdfParams)
	})
	if err != nil {
		return err
	}
	v.keyEpoch = newEpoch
	return v.logAudit(ctx, "ROTATE", store.Name("MASTER_KEY"), "Master key rotated successfully")
}

// RotateDEK generates a new DEK and re-encrypts every secret version under
// it (python rotate_dek, with RGT-499 fixed: Python rewrites only ACTIVE
// rows, so older versions stop decrypting; Go rewrites all of them).
//
// Atomicity: the epoch bump and every row rewrite are ONE BEGIN IMMEDIATE
// transaction; the new key is first written to keychain.json.new. Any failure
// before the commit rolls everything back and deletes the .new file, so the
// old keychain and the old rows stay in effect. After the commit the .new
// file is renamed over keychain.json; if the process dies in between, Open
// finishes the rename.
//
// Rows that do not decrypt under the current DEK and are not ACTIVE (for
// example versions an earlier Python rotate_dek orphaned) are left as they
// are; an ACTIVE row that does not decrypt aborts the rotation.
func (v *Vault) RotateDEK(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.usable(); err != nil {
		return err
	}
	return v.rotateDEKLocked(ctx)
}

// autoRotateDEK runs RotateDEK when the usage counters are (still) over a
// threshold. Re-checking under the exclusive lock means concurrent writers
// that all crossed the threshold trigger one rotation, not many.
func (v *Vault) autoRotateDEK(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.usable(); err != nil {
		return err
	}
	count, nbytes, err := v.store.DEKUsage(ctx)
	if err != nil {
		return err
	}
	if count < v.dekMaxEncryptions && nbytes < v.dekMaxBytes {
		return nil
	}
	return v.rotateDEKLocked(ctx)
}

func (v *Vault) rotateDEKLocked(ctx context.Context) error {
	if err := v.hookConsult(ctx, OpRotate, SystemAgent, "_admin", "rotate_dek", nil); err != nil {
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
	committed := false
	defer func() {
		if !committed {
			keychain.Wipe(newDEK)
			_ = os.Remove(newPath)
		}
	}()

	newEpoch, err := v.inRotationTx(ctx, func(tx *sql.Tx, newEpoch int64) error {
		var err error
		if newDEK, err = pending.Initialize(master, v.vaultID, newEpoch, v.kdfParams); err != nil {
			return err
		}
		return v.rewriteAll(ctx, tx, newDEK)
	})
	if err != nil {
		return err
	}
	committed = true
	if v.testAfterCommit != nil {
		v.testAfterCommit()
	}

	// From here on the database holds rows under newDEK. Any failure leaves
	// the in-memory key stale: mark the vault broken so it must be re-opened
	// (Open then completes the rename from keychain.json.new).
	fail := func(err error) error {
		keychain.Wipe(newDEK)
		v.broken = err
		return newErr([]error{ErrInconsistent}, err, "%s: %v", ErrInconsistent.Error(), err)
	}
	if v.testBeforeSwap != nil {
		if err := v.testBeforeSwap(); err != nil {
			return fail(err)
		}
	}
	if err := os.Rename(newPath, v.keychainPath); err != nil {
		return fail(fmt.Errorf("install new keychain: %w", err))
	}
	km := keychain.New(v.keychainPath)
	dek, err := km.Load(master, v.vaultID, newEpoch)
	if err != nil {
		return fail(fmt.Errorf("reload new keychain: %w", err))
	}
	keychain.Wipe(newDEK)
	keychain.Wipe(v.dek)
	_ = v.km.Close()
	v.km, v.dek, v.keyEpoch = km, dek, newEpoch

	// RGT-219: the new DEK starts its own encryption/byte budget at zero.
	if err := v.store.ResetDEKUsage(ctx); err != nil {
		return err
	}
	return v.logAudit(ctx, "ROTATE", store.Name("DEK"), "Data Encryption Key rotated successfully")
}

// inRotationTx opens a dedicated connection to the vault database, starts a
// BEGIN IMMEDIATE transaction, bumps key_epoch exactly as the store's
// IncrementKeyEpoch does, runs fn with the new epoch and commits. Any error
// rolls back. The caller holds v.mu exclusively, so no store write of this
// vault runs concurrently; other processes wait on SQLite's write lock.
func (v *Vault) inRotationTx(ctx context.Context, fn func(tx *sql.Tx, newEpoch int64) error) (int64, error) {
	db, err := sql.Open("sqlite", v.store.Path()+"?"+rotationConnParams)
	if err != nil {
		return 0, fmt.Errorf("vault: rotation: open database: %w", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("vault: rotation: begin: %w", err)
	}
	done := false
	defer func() {
		if !done {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO metadata (key, value) VALUES ('key_epoch', '1')"); err != nil {
		return 0, fmt.Errorf("vault: rotation: %w", err)
	}
	var cur string
	if err := tx.QueryRowContext(ctx, "SELECT value FROM metadata WHERE key = 'key_epoch'").Scan(&cur); err != nil {
		return 0, fmt.Errorf("vault: rotation: read key_epoch: %w", err)
	}
	epoch, err := strconv.ParseInt(strings.TrimSpace(cur), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("vault: rotation: invalid key_epoch %q: %w", cur, err)
	}
	if epoch != v.keyEpoch {
		return 0, fmt.Errorf("vault: rotation: key_epoch changed on disk (%d, expected %d); re-open the vault", epoch, v.keyEpoch)
	}
	newEpoch := epoch + 1
	if _, err := tx.ExecContext(ctx, "UPDATE metadata SET value = ? WHERE key = 'key_epoch'",
		strconv.FormatInt(newEpoch, 10)); err != nil {
		return 0, fmt.Errorf("vault: rotation: %w", err)
	}
	if err := fn(tx, newEpoch); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("vault: rotation: commit: %w", err)
	}
	done = true
	return newEpoch, nil
}

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
	var last int64 = -1 << 63
	n := 0
	for {
		rows, err := v.rewritePageRows(ctx, tx, last)
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
			if _, err := tx.ExecContext(ctx,
				"UPDATE secrets SET ciphertext = ?, checksum = ?, dek_version = ? WHERE id = ?",
				ct, hex.EncodeToString(sum[:]), 1, r.id); err != nil {
				return fmt.Errorf("vault: rotation: update row %d: %w", r.id, err)
			}
		}
		last = rows[len(rows)-1].id
	}
}

func (v *Vault) rewritePageRows(ctx context.Context, tx *sql.Tx, after int64) ([]rewriteRow, error) {
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
