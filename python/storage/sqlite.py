import base64
import contextlib
import hashlib
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from rgt_vault.exceptions import ChecksumError

DEFAULT_DB_PATH = Path.home() / ".secure-vault" / "vault.db"


def _utcnow_iso() -> str:
    """Timezone-aware UTC timestamp (replaces deprecated datetime.utcnow)."""
    return datetime.now(timezone.utc).isoformat()


def _sanitize_log_field(value: str) -> str:
    """Encode CRLF and other control characters to prevent log injection (RGT-415).

    Log entries are stored in SQLite but may also be forwarded to syslog or
    SIEM systems where newline injection could forge fake log lines.
    """
    return value.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")


class StorageBackend:
    def __init__(self, db_path: Union[str, Path] = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        # Serialize audit-chain writes within a process so concurrent writers
        # cannot read the same prev_hash and fork the hash chain.
        self._audit_lock = threading.Lock()
        self._init_db()

    @contextlib.contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA busy_timeout = 5000")
            yield conn
        finally:
            conn.close()

    def _apply_migrations(self, conn: sqlite3.Connection) -> None:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
        """)

        applied = {row[0] for row in cursor.execute("SELECT version FROM schema_migrations").fetchall()}

        migrations_dir = Path(__file__).parent / "migrations"
        if not migrations_dir.exists():
            return

        for sql_file in sorted(migrations_dir.glob("*.sql")):
            try:
                version = int(sql_file.name.split("_")[0])
            except ValueError:
                continue

            if version not in applied:
                with open(sql_file) as f:
                    script = f.read()
                # Run the migration script and the bookkeeping insert in a
                # single transaction. If either fails, the whole migration
                # is rolled back and re-attempted on next startup.
                cursor.execute("BEGIN")
                try:
                    cursor.executescript(script)
                    cursor.execute(
                        "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                        (version, _utcnow_iso()),
                    )
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            try:
                os.chmod(self.db_path.parent, 0o700)
            except OSError:
                pass  # Non-fatal if we don't own the parent dir

        is_new_db = not self.db_path.exists()

        with self._get_conn() as conn:
            self._apply_migrations(conn)

        if is_new_db and os.name == "posix":
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass

    def get_vault_id(self) -> str:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM metadata WHERE key = 'vault_id'")
            row = cursor.fetchone()
            if row:
                return row[0]
            new_id = str(uuid.uuid4())
            cursor.execute("INSERT INTO metadata (key, value) VALUES ('vault_id', ?)", (new_id,))
            conn.commit()
            return new_id

    def get_key_epoch(self) -> int:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM metadata WHERE key = 'key_epoch'")
            row = cursor.fetchone()
            if row:
                return int(row[0])
            cursor.execute("INSERT INTO metadata (key, value) VALUES ('key_epoch', '1')")
            conn.commit()
            return 1

    def increment_key_epoch(self) -> int:
        current = self.get_key_epoch()
        new_epoch = current + 1
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE metadata SET value = ? WHERE key = 'key_epoch'", (str(new_epoch),))
            conn.commit()
        return new_epoch

    def get_dek_usage(self) -> Tuple[int, int]:
        """Return (encrypt_count, bytes_encrypted) for the active DEK (RGT-219).

        Same metadata table used by get_key_epoch/get_vault_id. Missing rows
        (fresh vault, or a vault created before this ticket) read as (0, 0).
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM metadata WHERE key = 'dek_encrypt_count'")
            row = cursor.fetchone()
            count = int(row[0]) if row else 0
            cursor.execute("SELECT value FROM metadata WHERE key = 'dek_encrypt_bytes'")
            row = cursor.fetchone()
            nbytes = int(row[0]) if row else 0
            return count, nbytes

    def increment_dek_usage(self, byte_count: int) -> Tuple[int, int]:
        """Atomically bump both counters by one encryption / byte_count bytes.

        The increment is computed server-side (SQL arithmetic against the
        row's current value, inside one transaction) rather than read in
        Python and written back in a second transaction. An earlier version
        did read-then-write across two separate connections/transactions --
        a genuine lost-update race under concurrent set_secret() calls,
        caught in review (independent audit, not caught by the original
        author or two prior reviewers) -- fixed here.
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            cursor.execute(
                "INSERT INTO metadata (key, value) VALUES ('dek_encrypt_count', '1') "
                "ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)"
            )
            cursor.execute(
                "INSERT INTO metadata (key, value) VALUES ('dek_encrypt_bytes', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + ? AS TEXT)",
                (str(byte_count), byte_count),
            )
            cursor.execute("SELECT value FROM metadata WHERE key = 'dek_encrypt_count'")
            count = int(cursor.fetchone()[0])
            cursor.execute("SELECT value FROM metadata WHERE key = 'dek_encrypt_bytes'")
            nbytes = int(cursor.fetchone()[0])
            conn.commit()
            return count, nbytes

    def reset_dek_usage(self) -> None:
        """Zero both counters. Call after a successful DEK rotation."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO metadata (key, value) VALUES ('dek_encrypt_count', '0') "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
            )
            cursor.execute(
                "INSERT INTO metadata (key, value) VALUES ('dek_encrypt_bytes', '0') "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
            )
            conn.commit()

    def last_audit_hash(self) -> Optional[str]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            return row[0] if row else None

    def log_audit(
        self,
        action: str,
        secret_name: Optional[str] = None,
        details: str = "",
        policy_hash: str = "",
        agent_id: Optional[str] = None,
    ) -> None:
        timestamp = _utcnow_iso()
        safe_details = _sanitize_log_field(details)
        safe_action = _sanitize_log_field(action)
        # Read-prev-then-insert must be atomic, or concurrent writers fork the
        # hash chain. We take a process-level lock (in-process serialization)
        # and BEGIN IMMEDIATE (cross-process write lock) so the SELECT of the
        # previous hash and the INSERT happen as one indivisible step.
        with self._audit_lock, self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            try:
                cursor.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
                row = cursor.fetchone()
                prev_hash = row[0] if row else ""
                raw = f"{prev_hash}|{timestamp}|{safe_action}|{secret_name or ''}|{safe_details}|{policy_hash}"
                entry_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
                cursor.execute(
                    """
                    INSERT INTO audit_logs (action, secret_name, timestamp, details, prev_hash, entry_hash, policy_hash, agent_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (safe_action, secret_name, timestamp, safe_details, prev_hash, entry_hash, policy_hash, agent_id),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def iter_audit_log(self) -> List[Dict[str, Any]]:
        """Return ALL audit rows in chronological order (oldest first).

        Used by ``VaultManager.verify_audit_chain`` so verification is not
        silently capped at a fixed limit. Callers that only need a tail
        should use ``get_audit_log``.
        """
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC")
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def audit_log_count(self) -> int:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            (n,) = cursor.execute("SELECT COUNT(*) FROM audit_logs").fetchone()
            return int(n)

    def set_secret(
        self,
        namespace: str,
        name: str,
        ciphertext: bytes,
        dek_version: int,
        secret_id: Optional[str] = None,
        policy_hash: str = "",
        note: str = "",
        require_2fa: bool = False,
    ) -> None:
        checksum = hashlib.sha256(ciphertext).hexdigest()
        now = _utcnow_iso()
        if not secret_id:
            secret_id = str(uuid.uuid4())

        with self._audit_lock, self._get_conn() as conn:
            cursor = conn.cursor()
            try:
                # P0-4 / P2-1 / P2-2 audit fix: take a write lock for the
                # entire update-supersede-insert sequence so concurrent
                # writers for the same name serialize cleanly and a crash
                # leaves either the old version or the new version, never a
                # half-applied state.
                cursor.execute("BEGIN IMMEDIATE")
                # If secret exists, inherit secret_id
                cursor.execute(
                    "SELECT secret_id FROM secrets WHERE namespace = ? AND name = ? LIMIT 1", (namespace, name)
                )
                row = cursor.fetchone()
                if row:
                    secret_id = row[0]

                cursor.execute(
                    "UPDATE secrets SET status = 'SUPERSEDED' WHERE namespace = ? AND name = ? AND status = 'ACTIVE'",
                    (namespace, name),
                )
                cursor.execute("SELECT MAX(version) FROM secrets WHERE namespace = ? AND name = ?", (namespace, name))
                row = cursor.fetchone()
                next_version = (row[0] + 1) if row and row[0] is not None else 1

                cursor.execute(
                    """
                    INSERT INTO secrets (secret_id, namespace, name, version, ciphertext, checksum, created_at, updated_at, status, dek_version, note, require_2fa)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?)
                """,
                    (secret_id, namespace, name, next_version, ciphertext, checksum, now, now, dek_version, note, 1 if require_2fa else 0),
                )

                # P2-4 audit fix: write the audit entry inside the same
                # transaction as the secret insert. If either fails, the
                # other rolls back -- a write that's logged but didn't
                # happen (or vice versa) would be an integrity gap.
                self._append_audit_in_tx(
                    cursor,
                    "SET_SECRET",
                    name,
                    f"Version {next_version} created in {namespace}",
                    policy_hash,
                )
                conn.commit()
                return
            except Exception:
                conn.rollback()
                raise

    def get_secret(
        self, namespace: str, name: str, version: Optional[int] = None, policy_hash: str = ""
    ) -> Optional[Tuple[bytes, int]]:
        # P0-5 audit fix: combine the read and the audit-log write into one
        # transaction. If the audit write fails (disk full, DB locked, etc.),
        # the read is rolled back too -- an unlogged read is a silent
        # integrity gap for a tamper-evident audit chain. The caller will
        # see the exception and can decide whether to retry.
        with self._audit_lock, self._get_conn() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                if version is not None:
                    cursor.execute(
                        """
                        SELECT ciphertext, checksum, dek_version FROM secrets
                        WHERE namespace = ? AND name = ? AND version = ?
                    """,
                        (namespace, name, version),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT ciphertext, checksum, dek_version FROM secrets
                        WHERE namespace = ? AND name = ? AND status = 'ACTIVE' ORDER BY version DESC LIMIT 1
                    """,
                        (namespace, name),
                    )

                row = cursor.fetchone()

                if row:
                    ciphertext, checksum, dek_version = row
                    if hashlib.sha256(ciphertext).hexdigest() != checksum:
                        # Audit the failure and commit -- the integrity
                        # violation is recorded, then surface the error.
                        self._append_audit_in_tx(
                            cursor,
                            "GET_SECRET_FAILED",
                            name,
                            "Checksum mismatch",
                            policy_hash,
                        )
                        conn.commit()
                        raise ChecksumError(f"Integrity check failed for secret '{namespace}/{name}'")

                    self._append_audit_in_tx(
                        cursor,
                        "GET_SECRET",
                        name,
                        f"Version {'latest' if version is None else version} accessed from {namespace}",
                        policy_hash,
                    )
                    conn.commit()
                    return ciphertext, dek_version

                self._append_audit_in_tx(
                    cursor,
                    "GET_SECRET_FAILED",
                    name,
                    f"Secret not found in {namespace}",
                    policy_hash,
                )
                conn.commit()
                return None
            except Exception:
                conn.rollback()
                raise

    def _append_audit_in_tx(
        self,
        cursor,
        action: str,
        secret_name: Optional[str],
        details: str,
        policy_hash: str,
        agent_id: Optional[str] = None,
    ) -> None:
        """Append an audit entry inside an already-open transaction.

        Used by ``get_secret``, ``set_secret``, ``revoke_secret``, and
        ``bulk_rewrite_active_secrets`` to keep the data-mutating step
        and its audit row as a single atomic step. Reads ``prev_hash``
        via the same cursor so the chain stays consistent within the
        transaction.
        """
        timestamp = _utcnow_iso()
        safe_details = _sanitize_log_field(details)
        safe_action = _sanitize_log_field(action)
        cursor.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
        prev_row = cursor.fetchone()
        prev_hash = prev_row[0] if prev_row else ""
        raw = f"{prev_hash}|{timestamp}|{safe_action}|{secret_name or ''}|{safe_details}|{policy_hash}"
        entry_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        cursor.execute(
            """
            INSERT INTO audit_logs (action, secret_name, timestamp, details, prev_hash, entry_hash, policy_hash, agent_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (safe_action, secret_name, timestamp, safe_details, prev_hash, entry_hash, policy_hash, agent_id),
        )

    def list_secrets(self, namespace: str, policy_hash: str = "", limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT secret_id, name, version, created_at, updated_at, status, note, require_2fa
                FROM secrets
                WHERE namespace = ? AND status = 'ACTIVE'
                LIMIT ? OFFSET ?
            """,
                (namespace, limit, offset),
            )
            rows = cursor.fetchall()

            secrets = []
            for row in rows:
                secrets.append(
                    {
                        "secret_id": row[0],
                        "name": row[1],
                        "latest_version": row[2],
                        "created_at": row[3],
                        "updated_at": row[4],
                        "status": row[5],
                        # Title-safe metadata: never includes the secret value.
                        "note": row[6],
                        "require_2fa": bool(row[7]),
                    }
                )

        self.log_audit("LIST_SECRETS", None, f"Listed {len(secrets)} secrets in {namespace}", policy_hash)
        return secrets

    def requires_2fa(self, namespace: str, name: str) -> bool:
        """Return True if the active secret is flagged for TOTP at approval time."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT require_2fa FROM secrets WHERE namespace = ? AND name = ? AND status = 'ACTIVE' LIMIT 1",
                (namespace, name),
            )
            row = cursor.fetchone()
            return bool(row[0]) if row else False

    def add_honeytoken(self, namespace: str, name: str) -> None:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO honeytokens (namespace, name) VALUES (?, ?)", (namespace, name))
            conn.commit()

    def is_honeytoken(self, namespace: str, name: str) -> bool:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM honeytokens WHERE namespace = ? AND name = ?", (namespace, name))
            row = cursor.fetchone()
            return row is not None

    def iter_all_active_secrets(self) -> List[Tuple[int, str, str, bytes, int]]:
        """Returns list of (id, namespace, name, ciphertext, dek_version) for active secrets."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, namespace, name, ciphertext, dek_version FROM secrets WHERE status = 'ACTIVE'")
            return cursor.fetchall()

    def update_secret_ciphertext(self, record_id: int, new_ciphertext: bytes, new_dek_version: int) -> None:
        new_checksum = hashlib.sha256(new_ciphertext).hexdigest()
        with self._get_conn() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                cursor.execute(
                    "UPDATE secrets SET ciphertext = ?, checksum = ?, dek_version = ? WHERE id = ?",
                    (new_ciphertext, new_checksum, new_dek_version, record_id),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def has_legacy_secrets(self) -> bool:
        """Returns True if any active secrets have dek_version=0."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("SELECT 1 FROM secrets WHERE status = 'ACTIVE' AND dek_version = 0 LIMIT 1").fetchone()
            return row is not None

    def bulk_rewrite_active_secrets(self, rewrite_fn) -> int:
        """Apply ``rewrite_fn(record_id, namespace, name, ciphertext, dek_version) ->
        (new_ciphertext, new_dek_version)`` to every ACTIVE secret, in a
        single SQLite transaction.

        Used by ``VaultManager.rotate_dek`` and ``_migrate_legacy_secrets``
        to make the multi-row rewrite atomic. If any single row fails the
        rewrite, the transaction rolls back and no row is modified. On
        success, returns the number of rows rewritten.
        """
        rewritten = 0
        with self._audit_lock, self._get_conn() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                cursor.execute(
                    "SELECT id, namespace, name, ciphertext, dek_version FROM secrets WHERE status = 'ACTIVE'"
                )
                
                while True:
                    rows = cursor.fetchmany(1000)
                    if not rows:
                        break
                        
                    for record_id, namespace, name, ciphertext, dek_version in rows:
                        new_ct, new_ver = rewrite_fn(
                            record_id,
                            namespace,
                            name,
                            ciphertext,
                            dek_version,
                        )
                        new_checksum = hashlib.sha256(new_ct).hexdigest()
                        conn.execute(
                            "UPDATE secrets SET ciphertext = ?, checksum = ?, dek_version = ? WHERE id = ?",
                            (new_ct, new_checksum, new_ver, record_id),
                        )
                        rewritten += 1
                conn.commit()
                return rewritten
            except Exception:
                conn.rollback()
                raise

    def bulk_rewrite_legacy_secrets(self, rewrite_fn) -> int:
        """Apply ``rewrite_fn`` to every ACTIVE secret with dek_version=0, in a
        single SQLite transaction.
        
        Using fetchmany() minimizes memory overhead for large databases.
        """
        rewritten = 0
        with self._audit_lock, self._get_conn() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                cursor.execute(
                    "SELECT id, namespace, name, ciphertext, dek_version FROM secrets WHERE status = 'ACTIVE' AND dek_version = 0"
                )
                
                while True:
                    rows = cursor.fetchmany(1000)
                    if not rows:
                        break
                        
                    for record_id, namespace, name, ciphertext, dek_version in rows:
                        new_ct, new_ver = rewrite_fn(
                            record_id,
                            namespace,
                            name,
                            ciphertext,
                            dek_version,
                        )
                        new_checksum = hashlib.sha256(new_ct).hexdigest()
                        # Use connection to execute update so we don't clobber the select cursor
                        conn.execute(
                            "UPDATE secrets SET ciphertext = ?, checksum = ?, dek_version = ? WHERE id = ?",
                            (new_ct, new_checksum, new_ver, record_id),
                        )
                        rewritten += 1
                conn.commit()
                return rewritten
            except Exception:
                conn.rollback()
                raise

    def export_data(self) -> Dict[str, Any]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            secrets = []
            for r in cursor.execute("SELECT * FROM secrets").fetchall():
                d = dict(r)
                d["ciphertext"] = base64.b64encode(d["ciphertext"]).decode("utf-8")
                secrets.append(d)
            audit = [dict(r) for r in cursor.execute("SELECT * FROM audit_logs").fetchall()]
            honeytokens = [dict(r) for r in cursor.execute("SELECT * FROM honeytokens").fetchall()]
            return {"secrets": secrets, "audit_logs": audit, "honeytokens": honeytokens}

    def import_data(self, data: Dict[str, Any], master_key: Optional[bytes] = None) -> None:
        if not isinstance(data, dict):
            raise ValueError("Import data must be a dictionary")

        # Each collection must be a list (or absent). A present-but-non-list
        # value (e.g. None) is malformed input, not a programming error.
        def _as_list(key: str) -> list:
            value = data.get(key)
            if value is None:
                return []
            if not isinstance(value, list):
                raise ValueError(f"Import field '{key}' must be a list")
            return value

        secrets = _as_list("secrets")
        audit_logs = _as_list("audit_logs")
        honeytokens = _as_list("honeytokens")

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM secrets")
            cursor.execute("DELETE FROM audit_logs")
            cursor.execute("DELETE FROM honeytokens")

            for s in secrets:
                if not isinstance(s, dict) or "id" not in s or "name" not in s or "ciphertext" not in s:
                    raise ValueError("Malformed secret entry in import data")
                try:
                    ct = base64.b64decode(s["ciphertext"], validate=True)
                except Exception as e:
                    raise ValueError(f"Failed to decode ciphertext: {e}")
                cursor.execute(
                    """
                    INSERT INTO secrets (id, secret_id, namespace, name, version, ciphertext, checksum, created_at, updated_at, status, dek_version, note, require_2fa)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        s["id"],
                        s.get("secret_id", str(uuid.uuid4())),
                        s.get("namespace", "default"),
                        s["name"],
                        s.get("version", 1),
                        ct,
                        s.get("checksum", ""),
                        s.get("created_at", ""),
                        s.get("updated_at", ""),
                        s.get("status", "ACTIVE" if s.get("is_current") == 1 else "SUPERSEDED"),
                        s.get("dek_version", 1),
                        # Preserve per-secret metadata so a 2FA-gated secret is
                        # never silently downgraded on import.
                        s.get("note", ""),
                        1 if s.get("require_2fa") else 0,
                    ),
                )

            for a in audit_logs:
                if not isinstance(a, dict) or "id" not in a or "action" not in a or "entry_hash" not in a:
                    raise ValueError("Malformed audit log entry in import data")
                cursor.execute(
                    """
                    INSERT INTO audit_logs (id, action, secret_name, timestamp, details, prev_hash, entry_hash, policy_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        a["id"],
                        a["action"],
                        a.get("secret_name"),
                        a.get("timestamp", ""),
                        a.get("details", ""),
                        a.get("prev_hash", ""),
                        a["entry_hash"],
                        a.get("policy_hash", ""),
                    ),
                )

            for h in honeytokens:
                if not isinstance(h, dict) or "name" not in h:
                    raise ValueError("Malformed honeytoken entry in import data")
                cursor.execute(
                    "INSERT INTO honeytokens (namespace, name) VALUES (?, ?)",
                    (h.get("namespace", "default"), h["name"]),
                )
            conn.commit()

    def revoke_secret(self, namespace: str, name: str, policy_hash: str = "") -> None:
        # P2-1 audit fix: revoke + audit row in one transaction.
        with self._audit_lock, self._get_conn() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                cursor.execute(
                    "UPDATE secrets SET status = 'REVOKED' WHERE namespace = ? AND name = ? AND status = 'ACTIVE'",
                    (namespace, name),
                )
                self._append_audit_in_tx(
                    cursor,
                    "REVOKE_SECRET",
                    name,
                    f"Revoked active secret in {namespace}",
                    policy_hash,
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
