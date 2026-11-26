#!/usr/bin/env python3
"""Generate Go store compat fixtures from the REAL Python implementation.

Reference code (frozen; the Python line is EOL and this file only reads it):
  python/storage/sqlite.py   StorageBackend (schema, migrations, every method)
  python/vault.py            VaultManager (set/lease/list/revoke/rotate_dek,
                             rotate_master_key, verify_audit_chain)

Usage, from the repo root with `pip install -e '.[server,dev]'` in a venv:

  python go/internal/store/testdata/gen_fixtures.py
      Regenerate the fixtures next to this file:
        pyvault.db         a vault.db written by a real VaultManager: two
                           namespaces, versions (SUPERSEDED), REVOKED, note and
                           require_2fa, unicode, a 16 KiB value, a honeytoken,
                           rotate_dek, rotate_master_key, and >= 1000 audit
                           rows (CR/LF/TAB, NULL secret_name, unicode details)
        pyedge.db          audit rows with NULL details / policy_hash (the
                           "None" rendering quirk) that Python verifies True
        pytampered.db      pyedge.db with one stored details value altered
        pyexport.json      StorageBackend.export_data() of pyvault.db, as
                           export_vault serialises it (json.dumps indent=2)
        manifest.json      expected values: schema (sqlite_master), applied
                           migration versions, metadata, every secrets row,
                           honeytokens, audit row count, real-Python verdicts

  python go/internal/store/testdata/gen_fixtures.py --verify DB
      Open DB (e.g. one Go wrote) with the real StorageBackend and print a JSON
      report: real verify_audit_chain verdict, row counts, metadata, every
      ACTIVE secret read back through get_secret (checksum-verified), the
      list_secrets view per namespace, a full export_data, and a second chain
      verdict after Python appended its own rows on top of Go's. The report
      holds only counts, ids, versions and booleans, never secret material.

  python go/internal/store/testdata/gen_fixtures.py --out DIR
      Write fresh fixtures to DIR instead (to compare with the checked-in ones).

Fixtures are not byte-reproducible (they embed wall-clock timestamps and
random ids); the checked-in files are the pinned artefacts and Go tests only
read copies of them.
"""

import base64
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import types
from pathlib import Path

from rgt_vault.storage.sqlite import StorageBackend
from rgt_vault.vault import VaultManager

HERE = Path(__file__).resolve().parent
ALLOW_ALL = "rules:\n  - effect: allow\n"


class _Provider:
    """Fixed master secret so the generator needs no OS keyring."""

    def __init__(self):
        self.secret = b"\x07" * 32

    def get_secret(self):
        return self.secret

    def rotate_secret(self):
        self.secret = b"\x08" * 32
        return self.secret


def verify(storage):
    """Call the REAL VaultManager.verify_audit_chain on a bare storage."""
    return VaultManager.verify_audit_chain(types.SimpleNamespace(storage=storage))


def checkpoint(db):
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()
    for ext in ("-wal", "-shm"):
        p = Path(str(db) + ext)
        if p.exists():
            p.unlink()


def schema(db):
    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name").fetchall()
    conn.close()
    return [{"type": t, "name": n, "tbl_name": tn, "sql": s} for t, n, tn, s in rows]


def dump(db, query):
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute(query).fetchall()]
    conn.close()
    for r in rows:
        if isinstance(r.get("ciphertext"), bytes):
            r["ciphertext"] = base64.b64encode(r["ciphertext"]).decode()
    return rows


def build_vault(tmp):
    db = os.path.join(tmp, "vault.db")
    v = VaultManager(db_path=db, master_provider=_Provider(), policy_yaml=ALLOW_ALL, rate_limit=1_000_000)
    v.set_secret("api_key", "v1", namespace="default", note="first")
    v.set_secret("api_key", "v2", namespace="default", note="second")
    v.set_secret("api_key", "v3", namespace="default", note="third", require_2fa=True)
    v.set_secret("db_password", "hunter2", namespace="prod")
    v.set_secret("to_revoke", "gone", namespace="prod")
    v.revoke_secret("prod", "to_revoke")
    v.set_secret("unicode_value", "ünïcødé ✓ 秘密", namespace="default", note="naïve note")
    v.set_secret("big", "x" * 16384, namespace="prod")
    v.storage.add_honeytoken("default", "canary")
    v.set_secret("canary", "trap", namespace="default")
    with v.lease_secret("api_key", "agent-a", "default", "test") as buf:
        assert bytes(buf) == b"v3"
    v.list_secrets("default", "agent-a")
    v.rotate_dek()
    v.rotate_master_key()
    # Filler to reach >= 1000 audit rows, exercising sanitisation and NULLs.
    i = 0
    while v.storage.audit_log_count() < 1000:
        v.storage.log_audit(
            "EVT\tTAB" if i % 7 == 0 else "FILLER",
            None if i % 3 == 0 else f"name-{i}",
            f"line1\r\nline2 {i} ✓" if i % 5 == 0 else f"detail {i}",
            v.policy_hash,
            agent_id=None if i % 2 else f"agent-{i % 4}",
        )
        i += 1
    assert v.verify_audit_chain()
    return v, db


def build_edge(tmp):
    db = os.path.join(tmp, "edge.db")
    st = StorageBackend(db)
    st.log_audit("SET_SECRET", "a", "Version 1 created in default", "abc")
    st.log_audit("LIST_SECRETS", None, "Listed 1 secrets in default", "")
    # Rows as an old/imported vault may hold them: NULL details and NULL
    # policy_hash. Python's verifier renders a present NULL as "None", so
    # these rows are hashed that way and verify True in Python.
    conn = sqlite3.connect(db)
    for action, name, details, ph in [
        ("IMPORT", "VAULT", None, None),
        ("GET_SECRET", "a", "Version latest accessed from default", None),
        ("REVOKE_SECRET", "a", None, "abc"),
    ]:
        (prev,) = conn.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
        ts = "2026-11-26T12:00:00+00:00"
        raw = f"{prev}|{ts}|{action}|{name or ''}|{details}|{ph}"
        h = hashlib.sha256(raw.encode()).hexdigest()
        conn.execute(
            "INSERT INTO audit_logs (action, secret_name, timestamp, details, prev_hash, entry_hash, policy_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (action, name, ts, details, prev, h, ph),
        )
    conn.commit()
    conn.close()
    st.log_audit("AFTER", "a", "tail", "abc")
    edge_ok = verify(st)
    tampered = os.path.join(tmp, "tampered.db")
    checkpoint(db)
    shutil.copy(db, tampered)
    conn = sqlite3.connect(tampered)
    conn.execute("UPDATE audit_logs SET details = 'forged' WHERE id = 2")
    conn.commit()
    conn.close()
    tampered_ok = verify(StorageBackend(tampered))
    return db, tampered, edge_ok, tampered_ok


def generate(out=HERE):
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        v, db = build_vault(tmp)
        vault_id = v.storage.get_vault_id()
        epoch = v.storage.get_key_epoch()
        dek_count, dek_bytes = v.storage.get_dek_usage()
        export = v.storage.export_data()
        audit_count = v.storage.audit_log_count()
        chain_ok = v.verify_audit_chain()
        checkpoint(db)

        fresh = os.path.join(tmp, "fresh", "vault.db")
        StorageBackend(fresh)
        checkpoint(fresh)

        edge, tampered, edge_ok, tampered_ok = build_edge(tmp)
        checkpoint(edge)
        checkpoint(tampered)

        manifest = {
            "generator": "go/internal/store/testdata/gen_fixtures.py",
            "python_sqlite_version": sqlite3.sqlite_version,
            "pyvault": {
                "vault_id": vault_id,
                "key_epoch": epoch,
                "dek_usage": [dek_count, dek_bytes],
                "audit_rows": audit_count,
                "chain_ok": chain_ok,
                "migrations": [r["version"] for r in dump(db, "SELECT version FROM schema_migrations ORDER BY version")],
                "secrets": dump(db, "SELECT * FROM secrets ORDER BY id"),
                "honeytokens": dump(db, "SELECT * FROM honeytokens ORDER BY namespace, name"),
                "schema": schema(db),
            },
            "fresh_schema": schema(fresh),
            "edge": {"chain_ok": edge_ok, "rows": dump(edge, "SELECT * FROM audit_logs ORDER BY id")},
            "tampered": {"chain_ok": tampered_ok},
        }
        shutil.copy(db, out / "pyvault.db")
        shutil.copy(edge, out / "pyedge.db")
        shutil.copy(tampered, out / "pytampered.db")
    (out / "pyexport.json").write_text(json.dumps(export, indent=2) + "\n")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote fixtures to {out}: chain_ok={chain_ok} edge_ok={edge_ok} tampered_ok={tampered_ok}")


def verify_db(db):
    """Print a report of counts, ids, versions and booleans only.

    The report never contains secret material: no plaintext, no ciphertext,
    no checksum and nothing else returned by get_secret. Reads are checked
    here, in Python; a mismatch exits non-zero instead of being reported.
    """
    st = StorageBackend(db)
    report = {"chain_ok": verify(st), "audit_rows": st.audit_log_count()}
    report["vault_id"] = st.get_vault_id()
    report["key_epoch"] = st.get_key_epoch()
    conn = sqlite3.connect(db)
    report["migrations"] = [r[0] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]
    active = conn.execute(
        "SELECT namespace, name, version, checksum FROM secrets WHERE status = 'ACTIVE' ORDER BY namespace, name"
    ).fetchall()
    namespaces = sorted({r[0] for r in conn.execute("SELECT namespace FROM secrets")})
    conn.close()
    entries = []
    for ns, name, version, stored_sum in active:
        # Real get_secret: verifies the checksum and appends an audit row.
        ct, _ = st.get_secret(ns, name)
        intact = hashlib.sha256(ct).hexdigest() == stored_sum
        del ct
        if not intact:
            # Fail closed (non-zero exit); never report anything derived
            # from the secret read.
            raise SystemExit(f"read-back mismatch for {ns}/{name}")
        entries.append(
            {
                "namespace": ns,
                "name": name,
                "version": version,
                "requires_2fa": st.requires_2fa(ns, name),
                "is_honeytoken": st.is_honeytoken(ns, name),
            }
        )
    report["active_entries"] = entries
    report["list_counts"] = {ns: len(st.list_secrets(ns)) for ns in namespaces}
    report["export_counts"] = {k: len(v) for k, v in st.export_data().items()}
    report["chain_ok_after_python_writes"] = verify(st)
    report["audit_rows_after_python_writes"] = st.audit_log_count()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--verify":
        verify_db(sys.argv[2])
    elif len(sys.argv) == 1:
        generate()
    elif len(sys.argv) == 3 and sys.argv[1] == "--out":
        generate(Path(sys.argv[2]))
    else:
        sys.exit(__doc__)
