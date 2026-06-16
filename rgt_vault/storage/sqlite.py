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

DEFAULT_DB_PATH = Path.home() / ".secure-vault" / "vault.db"


def _utcnow_iso() -> str:
    """Timezone-aware UTC timestamp (replaces deprecated datetime.utcnow)."""
    return datetime.now(timezone.utc).isoformat()


class StorageBackend:
    def __init__(self, db_path: Union[str, Path] = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        # Serialize audit-chain writes within a process so concurrent writers
        # cannot read the same prev_hash and fork the hash chain.
        self._audit_lock = threading.Lock()
        self._init_db()

    @contextlib.contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
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
                version = int(sql_file.name.split('_')[0])
            except ValueError:
                continue
                
            if version not in applied:
                with open(sql_file) as f:
                    script = f.read()
                cursor.executescript(script)
                cursor.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", 
                               (version, _utcnow_iso()))
                conn.commit()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == 'posix':
            try:
                os.chmod(self.db_path.parent, 0o700)
            except OSError:
                pass # Non-fatal if we don't own the parent dir

        is_new_db = not self.db_path.exists()
            
        with self._get_conn() as conn:
            self._apply_migrations(conn)
            
        if is_new_db and os.name == 'posix':
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

    def last_audit_hash(self) -> Optional[str]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            return row[0] if row else None

    def log_audit(self, action: str, secret_name: Optional[str] = None, details: str = "", policy_hash: str = "") -> None:
        timestamp = _utcnow_iso()
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
                raw = f"{prev_hash}|{timestamp}|{action}|{secret_name or ''}|{details}|{policy_hash}"
                entry_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
                cursor.execute("""
                    INSERT INTO audit_logs (action, secret_name, timestamp, details, prev_hash, entry_hash, policy_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (action, secret_name, timestamp, details, prev_hash, entry_hash, policy_hash))
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

    def set_secret(self, namespace: str, name: str, ciphertext: bytes, dek_version: int, secret_id: Optional[str] = None, policy_hash: str = "") -> None:
        checksum = hashlib.sha256(ciphertext).hexdigest()
        now = _utcnow_iso()
        if not secret_id:
            secret_id = str(uuid.uuid4())
        
        with self._get_conn() as conn:
            cursor = conn.cursor()
            # If secret exists, inherit secret_id
            cursor.execute("SELECT secret_id FROM secrets WHERE namespace = ? AND name = ? LIMIT 1", (namespace, name))
            row = cursor.fetchone()
            if row:
                secret_id = row[0]
                
            cursor.execute("UPDATE secrets SET status = 'SUPERSEDED' WHERE namespace = ? AND name = ? AND status = 'ACTIVE'", (namespace, name))
            cursor.execute("SELECT MAX(version) FROM secrets WHERE namespace = ? AND name = ?", (namespace, name))
            row = cursor.fetchone()
            next_version = (row[0] + 1) if row and row[0] is not None else 1
            
            cursor.execute("""
                INSERT INTO secrets (secret_id, namespace, name, version, ciphertext, checksum, created_at, updated_at, status, dek_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
            """, (secret_id, namespace, name, next_version, ciphertext, checksum, now, now, dek_version))
            conn.commit()
            
        self.log_audit("SET_SECRET", name, f"Version {next_version} created in {namespace}", policy_hash)

    def get_secret(self, namespace: str, name: str, version: Optional[int] = None, policy_hash: str = "") -> Optional[Tuple[bytes, int]]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if version is not None:
                cursor.execute("""
                    SELECT ciphertext, checksum, dek_version FROM secrets 
                    WHERE namespace = ? AND name = ? AND version = ?
                """, (namespace, name, version))
            else:
                cursor.execute("""
                    SELECT ciphertext, checksum, dek_version FROM secrets 
                    WHERE namespace = ? AND name = ? AND status = 'ACTIVE' ORDER BY version DESC LIMIT 1
                """, (namespace, name))
            
            row = cursor.fetchone()
            
            if row:
                ciphertext, checksum, dek_version = row
                if hashlib.sha256(ciphertext).hexdigest() != checksum:
                    self.log_audit("GET_SECRET_FAILED", name, "Checksum mismatch", policy_hash)
                    raise ValueError(f"Integrity check failed for secret '{namespace}/{name}'")
                    
                self.log_audit("GET_SECRET", name, f"Version {'latest' if version is None else version} accessed from {namespace}", policy_hash)
                return ciphertext, dek_version
                
            self.log_audit("GET_SECRET_FAILED", name, f"Secret not found in {namespace}", policy_hash)
            return None

    def list_secrets(self, namespace: str, policy_hash: str = "") -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT secret_id, name, version, created_at, updated_at, status 
                FROM secrets 
                WHERE namespace = ? AND status = 'ACTIVE'
            """, (namespace,))
            rows = cursor.fetchall()
            
            secrets = []
            for row in rows:
                secrets.append({
                    "secret_id": row[0],
                    "name": row[1],
                    "latest_version": row[2],
                    "created_at": row[3],
                    "updated_at": row[4],
                    "status": row[5]
                })
                
        self.log_audit("LIST_SECRETS", None, f"Listed {len(secrets)} secrets in {namespace}", policy_hash)
        return secrets

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
            cursor.execute(
                "UPDATE secrets SET ciphertext = ?, checksum = ?, dek_version = ? WHERE id = ?",
                (new_ciphertext, new_checksum, new_dek_version, record_id)
            )
            conn.commit()

    def export_data(self) -> Dict[str, Any]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            secrets = []
            for r in cursor.execute("SELECT * FROM secrets").fetchall():
                d = dict(r)
                d["ciphertext"] = base64.b64encode(d["ciphertext"]).decode('utf-8')
                secrets.append(d)
            audit = [dict(r) for r in cursor.execute("SELECT * FROM audit_logs").fetchall()]
            honeytokens = [dict(r) for r in cursor.execute("SELECT * FROM honeytokens").fetchall()]
            return {
                "secrets": secrets,
                "audit_logs": audit,
                "honeytokens": honeytokens
            }

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
                cursor.execute("""
                    INSERT INTO secrets (id, secret_id, namespace, name, version, ciphertext, checksum, created_at, updated_at, status, dek_version)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (s["id"], s.get("secret_id", str(uuid.uuid4())), s.get("namespace", "default"), s["name"], s.get("version", 1), ct, s.get("checksum", ""),
                      s.get("created_at", ""), s.get("updated_at", ""), s.get("status", "ACTIVE" if s.get("is_current") == 1 else "SUPERSEDED"), s.get("dek_version", 1)))
            
            for a in audit_logs:
                if not isinstance(a, dict) or "id" not in a or "action" not in a or "entry_hash" not in a:
                    raise ValueError("Malformed audit log entry in import data")
                cursor.execute("""
                    INSERT INTO audit_logs (id, action, secret_name, timestamp, details, prev_hash, entry_hash, policy_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (a["id"], a["action"], a.get("secret_name"), a.get("timestamp", ""),
                      a.get("details", ""), a.get("prev_hash", ""), a["entry_hash"], a.get("policy_hash", "")))
            
            for h in honeytokens:
                if not isinstance(h, dict) or "name" not in h:
                    raise ValueError("Malformed honeytoken entry in import data")
                cursor.execute(
                    "INSERT INTO honeytokens (namespace, name) VALUES (?, ?)",
                    (h.get("namespace", "default"), h["name"])
                )
            conn.commit()

    def revoke_secret(self, namespace: str, name: str, policy_hash: str = "") -> None:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE secrets SET status = 'REVOKED' WHERE namespace = ? AND name = ? AND status = 'ACTIVE'", (namespace, name))
            conn.commit()
        self.log_audit("REVOKE_SECRET", name, f"Revoked active secret in {namespace}", policy_hash)
