#!/usr/bin/env python3
"""Generate Go audit-chain golden vectors from the REAL Python implementation.

Reference code (frozen, Python line is EOL; this file only reads it):
  python/storage/sqlite.py   _sanitize_log_field, _utcnow_iso, log_audit,
                             _append_audit_in_tx, iter_audit_log
  python/vault.py            VaultManager.verify_audit_chain

Usage (from the repo root, with `pip install -e '.[server,dev]'` in a venv):
  python go/internal/audit/testdata/gen_vectors.py            # regenerate the JSON
  python go/internal/audit/testdata/gen_vectors.py --verify F  # real Python verify of a chains JSON

Writes next to this file:
  vectors.json  sanitize / entry-hash / isoformat unit vectors
  chains.json   whole chains + the verdict of the real verify_audit_chain
                for the full chain and for every prefix (row-by-row)

Chain verdicts always come from calling the real VaultManager.verify_audit_chain.
Rows come from a real StorageBackend (real SQLite file, real iter_audit_log);
"missing key" rows (a key absent from the dict, which Python renders '') are fed
through the same real verify via a replaced iter_audit_log.

Output is NOT byte-reproducible (real chains embed wall-clock timestamps); the
checked-in JSON is the pinned artefact, Go tests read it, they never regenerate.
"""

import copy
import hashlib
import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from rgt_vault.storage.sqlite import _sanitize_log_field, _utcnow_iso  # noqa: F401
from rgt_vault.vault import VaultManager

HERE = Path(__file__).resolve().parent
ALLOW_ALL = "rules:\n  - effect: allow\n"
POLICY_HASH = hashlib.sha256(ALLOW_ALL.encode()).hexdigest()[:16]


class _Provider:
    def get_secret(self):
        return b"\x07" * 32

    def rotate_secret(self):
        return b"\x07" * 32


def make_vault(tmp):
    return VaultManager(
        db_path=os.path.join(tmp, "vault.db"),
        master_provider=_Provider(),
        policy_yaml=ALLOW_ALL,
    )


def py_hash(prev, ts, action, secret_name, details, policy_hash):
    """The writer's formula, copied from sqlite.py log_audit (reference only)."""
    sa = _sanitize_log_field(action)
    sd = _sanitize_log_field(details)
    raw = f"{prev}|{ts}|{sa}|{secret_name or ''}|{sd}|{policy_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def verify(vault, rows):
    """Run the REAL verify_audit_chain over `rows` (list of dicts)."""
    snapshot = copy.deepcopy(rows)
    vault.storage.iter_audit_log = lambda: snapshot
    return vault.verify_audit_chain()


def verdicts(vault, rows):
    """Full verdict + verdict of every prefix rows[:k+1] (row-by-row)."""
    full = verify(vault, rows)
    prefixes = [verify(vault, rows[: k + 1]) for k in range(len(rows))]
    first_bad = next((i for i, ok in enumerate(prefixes) if not ok), -1)
    return {"python_verdict": full, "python_prefix_verdicts": prefixes, "python_first_bad": first_bad}


def chain(name, desc, rows, vault):
    out = {"name": name, "description": desc, "rows": rows}
    out.update(verdicts(vault, rows))
    return out


def read_rows(db_path):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    rows = [dict(r) for r in con.execute("SELECT * FROM audit_logs ORDER BY id ASC")]
    con.close()
    return rows


def raw_rows(db_path, build):
    """Insert hand-built rows into a fresh real SQLite audit table and read back."""
    with tempfile.TemporaryDirectory() as tmp:
        v = make_vault(tmp)
        con = sqlite3.connect(v.storage.db_path)
        con.execute("DELETE FROM audit_logs")
        for r in build:
            con.execute(
                "INSERT INTO audit_logs (action, secret_name, timestamp, details, prev_hash, entry_hash, policy_hash, agent_id) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    r["action"],
                    r["secret_name"],
                    r["timestamp"],
                    r["details"],
                    r["prev_hash"],
                    r["entry_hash"],
                    r["policy_hash"],
                    r["agent_id"],
                ),
            )
        con.commit()
        con.close()
        return read_rows(v.storage.db_path)


def main():
    chains = []

    # ---- 1. Real VaultManager chain with several actions -------------------
    with tempfile.TemporaryDirectory() as tmp:
        v = make_vault(tmp)
        v.set_secret("db_pass", "hunter2", namespace="prod", agent="agent-a", purpose="deploy")
        v.set_secret("api_key", "k-1", namespace="prod", agent="agent-a", purpose="deploy", note="first")
        v.set_secret("api_key", "k-2", namespace="prod", agent="agent-b", purpose="rotate")
        with v.lease_secret("db_pass", "agent-a", "prod", "deploy") as _buf:
            pass
        v.simulate("agent-a", "prod", "deploy", "read")
        v.revoke_secret("prod", "api_key", agent="agent-a")
        # Direct audit rows with log-injection characters, unicode, NULL secret_name.
        v.storage.log_audit("CUSTOM\nEVENT", None, "line1\r\nline2\tTab é中\U0001f600", POLICY_HASH, agent_id="agent-z")
        v.storage.log_audit("PLAIN", "s", "", POLICY_HASH)
        v.rotate_dek()
        v.set_secret("after_rotate", "x", namespace="prod", agent="agent-a", purpose="deploy")
        rows = read_rows(v.storage.db_path)
        assert len(rows) >= 8, len(rows)
        real = chain(
            "real_vault_manager",
            "Chain produced by the real VaultManager/SQLiteBackend: set_secret x3, lease, simulate, revoke, "
            "injection/unicode log_audit rows, rotate_dek, set_secret. Real timestamps, real policy_hash, agent_id set on some rows.",
            rows,
            v,
        )
        assert real["python_verdict"] is True, "real chain must verify"
        chains.append(real)

        # ---- 2. Tampered variants of the real chain (all verified by real Python) ----
        mid = len(rows) // 2

        def tampered(label, desc, fn):
            rs = copy.deepcopy(rows)
            fn(rs)
            chains.append(chain(label, desc, rs, v))

        tampered(
            "tamper_details",
            "details of a middle row changed",
            lambda rs: rs[mid].__setitem__("details", rs[mid]["details"] + "x"),
        )
        tampered("tamper_action", "action of a middle row changed", lambda rs: rs[mid].__setitem__("action", "FORGED"))
        tampered(
            "tamper_secret_name",
            "secret_name of a middle row changed",
            lambda rs: rs[mid].__setitem__("secret_name", "other"),
        )
        tampered(
            "tamper_timestamp",
            "timestamp of a middle row changed",
            lambda rs: rs[mid].__setitem__("timestamp", "2000-01-01T00:00:00+00:00"),
        )
        tampered(
            "tamper_policy_hash",
            "policy_hash of a middle row changed",
            lambda rs: rs[mid].__setitem__("policy_hash", "deadbeefdeadbeef"),
        )
        tampered(
            "tamper_entry_hash",
            "entry_hash of a middle row changed",
            lambda rs: rs[mid].__setitem__("entry_hash", "0" * 64),
        )
        tampered("tamper_delete_middle", "a middle row deleted", lambda rs: rs.pop(mid))
        tampered("tamper_delete_first", "first row deleted (genesis no longer empty-prev)", lambda rs: rs.pop(0))
        tampered(
            "tamper_swap_rows",
            "two adjacent rows swapped",
            lambda rs: rs.__setitem__(slice(mid, mid + 2), [rs[mid + 1], rs[mid]]),
        )
        tampered(
            "tamper_stored_prev_hash_only",
            "ONLY the stored prev_hash column changed: Python verify never reads it, so verdict stays True",
            lambda rs: rs[mid].__setitem__("prev_hash", "f" * 64),
        )
        tampered(
            "tamper_agent_id_only",
            "ONLY agent_id changed: agent_id is not hashed, verdict stays True (known limitation N4/RGT-416)",
            lambda rs: rs[mid].__setitem__("agent_id", "attacker"),
        )
        tampered(
            "tamper_truncate_tail",
            "tail rows dropped: still a valid chain prefix (Python cannot detect tail truncation)",
            lambda rs: rs.__delitem__(slice(len(rs) - 2, None)),
        )
        tampered(
            "tamper_raw_newline_in_action",
            "action stored with a RAW newline (writer would have stored '\\\\n'): verify hashes stored bytes as-is, mismatch",
            lambda rs: rs[mid].__setitem__("action", "RAW\nNEWLINE"),
        )

    # ---- 2b. 1000-row chain from the real backend (RGT-151 acceptance fixture) ----
    with tempfile.TemporaryDirectory() as tmp:
        v = make_vault(tmp)
        for i in range(1000):
            v.storage.log_audit(
                "BULK_%d" % (i % 7),
                None if i % 5 == 0 else "secret-%d" % (i % 13),
                "row %d\tTab\r\nCRLF \u00e9" % i if i % 11 == 0 else "row %d" % i,
                POLICY_HASH if i % 3 else "",
                agent_id="agent-%d" % (i % 4),
            )
        rows = read_rows(v.storage.db_path)
        assert len(rows) == 1000
        big = chain("real_1000_rows", "1000 rows via the real StorageBackend.log_audit (RGT-151 acceptance).", rows, v)
        assert big["python_verdict"] is True
        chains.append(big)

    # ---- 3. Edge chains with NULL / missing columns ------------------------

    def build(rows_spec, none_literal):
        """Build a chain; hash NULL details/policy_hash as 'None' (verifier view) or '' (writer view)."""
        out, prev = [], ""
        for i, (action, sn, details, ph) in enumerate(rows_spec):
            tstamp = f"2026-01-01T00:00:{i:02d}+00:00"
            d = details
            p = ph
            hd = "None" if (d is None and none_literal) else (d or "")
            hp = "None" if (p is None and none_literal) else (p or "")
            raw = f"{prev}|{tstamp}|{action}|{sn or ''}|{hd}|{hp}"
            h = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            out.append(
                {
                    "action": action,
                    "secret_name": sn,
                    "timestamp": tstamp,
                    "details": d,
                    "prev_hash": prev,
                    "entry_hash": h,
                    "policy_hash": p,
                    "agent_id": None,
                }
            )
            prev = h
        return out

    spec = [
        ("SET", "a", "d1", "ph"),
        ("IMPORT", None, None, None),  # NULL secret_name + NULL details + NULL policy_hash
        ("SET", "b", None, "ph"),  # NULL details only
        ("SET", "c", "d3", None),  # NULL policy_hash only
        ("END", None, "", ""),  # empty strings (not NULL)
    ]
    with tempfile.TemporaryDirectory() as tmp:
        v = make_vault(tmp)
        for label, desc, none_literal in [
            (
                "edge_null_hashed_as_None",
                "Rows with NULL details/policy_hash whose hash was computed with the literal 'None' (Python verifier view): VALID under Python.",
                True,
            ),
            (
                "edge_null_hashed_as_empty",
                "Rows with NULL details/policy_hash hashed as '' (writer view, e.g. a NULLed column): INVALID under Python because present-NULL renders 'None'. The quirk.",
                False,
            ),
        ]:
            rows = raw_rows(None, build(spec, none_literal))
            chains.append(chain(label, desc, rows, v))

        # Missing keys (dict without the key at all): renders '' not 'None'.
        base = raw_rows(None, build(spec, True))
        missing = copy.deepcopy(base)
        for r in missing:
            r.pop("details", None)
            r.pop("policy_hash", None)
        # hash those rows as if the keys were absent ('' rendering)
        prev = ""
        for r in missing:
            raw = f"{prev}|{r['timestamp']}|{r['action']}|{r['secret_name'] or ''}||"
            r["entry_hash"] = hashlib.sha256(raw.encode()).hexdigest()
            prev = r["entry_hash"]
        chains.append(
            chain(
                "edge_missing_keys_hashed_as_empty",
                "Row dicts WITHOUT details/policy_hash keys, hashed as '': VALID (missing key renders '', unlike present NULL).",
                missing,
                v,
            )
        )
        missing_bad = copy.deepcopy(base)
        for r in missing_bad:
            r.pop("details", None)
            r.pop("policy_hash", None)
        chains.append(
            chain(
                "edge_missing_keys_hashed_as_None",
                "Same rows without keys but hashes computed with 'None': INVALID (missing key renders '').",
                missing_bad,
                v,
            )
        )

        # NULL / empty entry_hash and empty chain.
        nul_hash = raw_rows(None, build(spec, True))
        nul_hash[0]["entry_hash"] = None
        chains.append(chain("edge_null_entry_hash", "first row entry_hash NULL (compared as '')", nul_hash, v))
        chains.append(chain("edge_empty_chain", "no rows: vacuously True", [], v))
        one = raw_rows(None, build(spec[:1], True))
        chains.append(chain("edge_single_row", "single valid row (genesis prev = '')", one, v))

    # ---- unit vectors ------------------------------------------------------
    sanitize_in = [
        "",
        "plain",
        "a\rb",
        "a\nb",
        "a\tb",
        "a\r\nb",
        "\r\n\t",
        "\n\n\n",
        "back\\slash",
        "already\\nescaped",
        "\\r\\n\\t literal backslash-letters",
        "nul\x00byte",
        "bell\x07 esc\x1b[31m vt\x0b ff\x0c",
        "unicode é中\U0001f600   line-sep \u0085",
        "cr only\rcr",
        "mixed \tA\nB\rC\r\nD\t",
        "x" * 300,
    ]
    sanitize = [{"in": s, "out": _sanitize_log_field(s)} for s in sanitize_in]

    hash_cases = []
    cases = [
        ("", "2026-01-01T00:00:00+00:00", "SET", "name", "details", "ph"),
        ("", "2026-01-01T00:00:00.123456+00:00", "SET", None, "", ""),
        ("a" * 64, "2026-11-26T12:34:56.000001+00:00", "CUSTOM\nEVENT", "n", "x\r\ny\tz", "0123456789abcdef"),
        ("b" * 64, "2026-11-26T12:34:56+00:00", "A|B", "n|m", "d|e|f", "p|q"),
        ("c" * 64, "2026-11-26T12:34:56+00:00", "unicode", "né", "中文\U0001f600", "ph"),
        ("", "", "", None, "", ""),
        ("d" * 64, "ts", "SECRETSET", "", "empty-name-equals-none", ""),
    ]
    for prev, t, action, sn, details, ph in cases:
        hash_cases.append(
            {
                "prev": prev,
                "timestamp": t,
                "action": action,
                "secret_name": sn,
                "details": details,
                "policy_hash": ph,
                "expected": py_hash(prev, t, action, sn, details, ph),
                "stored_action": _sanitize_log_field(action),
                "stored_details": _sanitize_log_field(details),
            }
        )

    iso = []
    for sec, us in [
        (0, 0),
        (0, 1),
        (1, 999999),
        (1700000000, 0),
        (1700000000, 123456),
        (1700000000, 100000),
        (1700000000, 10),
        (1764160496, 0),
        (1764160496, 500000),
        (253402300799, 999999),  # 9999-12-31T23:59:59.999999
        (-62135596800 + 86400 * 366, 0),  # early year, exercises zero-padded year
    ]:
        dt = datetime.fromtimestamp(sec, tz=timezone.utc).replace(microsecond=us)
        iso.append({"unix_sec": sec, "microsecond": us, "expected": dt.isoformat()})
    # Sanity: the helper the writer really uses produces the same shape.
    now = _utcnow_iso()
    assert now.endswith("+00:00"), now

    (HERE / "vectors.json").write_text(
        json.dumps({"sanitize": sanitize, "entry_hash": hash_cases, "iso_time": iso}, indent=1, ensure_ascii=True)
        + "\n"
    )
    (HERE / "chains.json").write_text(json.dumps({"chains": chains}, indent=1, ensure_ascii=True) + "\n")
    print(f"wrote {len(sanitize)} sanitize, {len(hash_cases)} hash, {len(iso)} iso vectors, {len(chains)} chains")
    for c in chains:
        print(
            f"  {c['name']:38s} rows={len(c['rows']):2d} verdict={c['python_verdict']} first_bad={c['python_first_bad']}"
        )


def verify_file(path):
    """Run the REAL verify_audit_chain over every chain in a chains JSON file.

    Used to confirm Python accepts a chain extended by Go (RGT-151: add a row in
    Go, verify in Python). Prints one verdict per chain.
    """
    data = json.loads(Path(path).read_text())
    with tempfile.TemporaryDirectory() as tmp:
        v = make_vault(tmp)
        for c in data["chains"]:
            print(f"{c['name']}: rows={len(c['rows'])} python_verdict={verify(v, c['rows'])}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3 and sys.argv[1] == "--verify":
        verify_file(sys.argv[2])
    else:
        main()
