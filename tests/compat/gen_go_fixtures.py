#!/usr/bin/env python3
"""Generate the static compatibility fixtures that pin the Go port to Python.

Python (``rgt_vault``) is the reference implementation. This script drives the
REAL Python code (``VaultManager``, ``StorageBackend``, ``HardenedDEKManager``,
``HMACTokenVerifier``, ``TwoFactorHook``, ``totp``, ``ABACPolicyEngine``,
``input_validation``) with a deterministic fixed-master stub provider and writes
the results under ``go/testdata/pyvault/`` so the Go tests can consume them
after ``python/`` has been removed.

NOTE: the master secrets, HMAC keys and TOTP seeds below are FIXED TEST
FIXTURES, not real secrets. They are derived from public labels on purpose.

Usage (from the repo root)::

    python3 -m venv .venv && .venv/bin/pip install -e ".[server,dev]"
    .venv/bin/python tests/compat/gen_go_fixtures.py            # regenerate everything
    .venv/bin/python tests/compat/gen_go_fixtures.py --only vectors,edge

The fixtures are generated once and committed. Salts, DEKs, nonces, UUIDs and
wall-clock timestamps inside the vaults are random, so a re-run produces
different bytes (the *expectations* in the manifests stay equivalent). Only
regenerate when a Python behaviour that the Go port must mirror has changed.

The module is import-safe: ``tests/compat/test_fixtures_selfcheck.py`` imports
the ``eval_*`` functions below to re-derive every expectation from the committed
inputs with the real Python code.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import hmac
import json
import os
import platform
import shutil
import sqlite3
import sys
import tempfile
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple
from unittest import mock

import cryptography
from cryptography.fernet import Fernet

import rgt_vault.hook as hook_mod
import rgt_vault.keychain as keychain_mod
import rgt_vault.storage.sqlite as sqlite_mod
import rgt_vault.token as token_mod
import rgt_vault.vault as vault_mod
from rgt_vault import input_validation as iv
from rgt_vault import totp
from rgt_vault.auth import ABACPolicyEngine
from rgt_vault.crypto import decrypt
from rgt_vault.hook import HookRequest, TwoFactorHook
from rgt_vault.keychain import HardenedDEKManager, KeyDerivationOrchestrator, MasterSecret
from rgt_vault.providers.base import MasterSecretProvider
from rgt_vault.storage.sqlite import StorageBackend
from rgt_vault.token import CapabilityV2Token, HMACTokenVerifier
from rgt_vault.vault import VaultManager

REPO = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO / "go" / "testdata" / "pyvault"

# Small Argon2 params so Go tests are fast. All three differ from 1 so a Go
# reader that hard-codes a parameter instead of reading keychain.json fails.
SMALL_MEMORY, SMALL_TIME, SMALL_PARALLELISM = 4096, 2, 2
DEFAULT_PARAMS = (262144, 4, 4)

FAR_FUTURE = 4102444800  # 2100-01-01T00:00:00Z

# One fixed UUID per vault so manifests/AADs are recognisable.
VAULT_IDS = {
    "small": "5a11c0de-0000-4000-8000-000000000001",
    "default": "5a11c0de-0000-4000-8000-000000000002",
    "epoch1": "5a11c0de-0000-4000-8000-000000000003",
}

POLICY_MAIN = """rules:
  - effect: allow
    agent: "*"
    namespace: "*"
    purpose: "*"
    action: "*"
  - effect: deny
    agent: intruder
    action: read
"""

# A MiB of printable, deterministic, incompressible-looking text.
BIG_LEN = 1024 * 1024


def big_value() -> str:
    """16384 x sha256('big:<i>').hexdigest() == exactly 1 MiB of ASCII."""
    return "".join(hashlib.sha256(f"big:{i}".encode()).hexdigest() for i in range(BIG_LEN // 64))


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


def enc_str(s: str) -> Any:
    """Plain JSON string when safe, else a code-point object (lone surrogates)."""
    if any(0xD800 <= ord(c) <= 0xDFFF for c in s):
        return {"type": "cps", "cps": [ord(c) for c in s]}
    return s


def dec_arg(obj: Any) -> Any:
    """Decode a vector input: plain JSON values pass through, typed objects are expanded."""
    if isinstance(obj, dict) and "type" in obj:
        t = obj["type"]
        if t == "cps":
            return "".join(chr(c) for c in obj["cps"])
        if t == "repeat":
            return obj["char"] * obj["count"]
        if t == "bytes":
            return bytes.fromhex(obj["hex"])
        if t == "repeat_bytes":
            return bytes.fromhex(obj["hex"]) * obj["count"]
        if t == "null":
            return None
        if t == "int":
            return int(obj["value"])
        if t == "float":
            return float(obj["value"])
        if t == "bool":
            return bool(obj["value"])
        if t == "list":
            return list(obj["value"])
        raise ValueError(f"unknown typed arg {t!r}")
    return obj


def err_obj(e: BaseException) -> Dict[str, Any]:
    return {"ok": False, "error": type(e).__name__, "message": str(e)}


@contextlib.contextmanager
def frozen_time(now: float) -> Iterator[None]:
    with mock.patch("time.time", return_value=float(now)):
        yield


# ---------------------------------------------------------------------------
# Vault fixtures
# ---------------------------------------------------------------------------


def derive_master(label: str, n: int) -> bytes:
    return hashlib.sha256(f"rgt-vault-g0-master|{label}|{n}".encode()).digest()


class FixedMasterProvider(MasterSecretProvider):
    """Deterministic stub provider. ``rotate_secret`` moves to the next fixed master."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.n = 1

    def get_secret(self) -> bytes:
        return derive_master(self.label, self.n)

    def rotate_secret(self) -> bytes:
        self.n += 1
        return self.get_secret()


class SmallParamsDEKManager(HardenedDEKManager):
    """Real HardenedDEKManager with small Argon2 defaults (the code path is unchanged).

    ``VaultManager`` always passes the production defaults (262144/4/4) when it
    wraps a DEK; for fast Go tests we replace only those defaults. The params
    are written to keychain.json and read back from there on load.
    """

    def initialize_dek(
        self, master, vault_id, epoch, memory_cost=SMALL_MEMORY, time_cost=SMALL_TIME, parallelism=SMALL_PARALLELISM
    ):
        return super().initialize_dek(master, vault_id, epoch, memory_cost, time_cost, parallelism)

    def rewrap_dek(
        self, master, vault_id, epoch, memory_cost=SMALL_MEMORY, time_cost=SMALL_TIME, parallelism=SMALL_PARALLELISM
    ):
        return super().rewrap_dek(master, vault_id, epoch, memory_cost, time_cost, parallelism)


def seed_vault_id(db_path: Path, vault_id: str) -> None:
    sb = StorageBackend(db_path)
    with sb._get_conn() as conn:
        conn.execute("INSERT OR IGNORE INTO metadata (key, value) VALUES ('vault_id', ?)", (vault_id,))
        conn.commit()


class VaultBuilder:
    """Runs a scripted scenario against the real VaultManager and records expectations."""

    def __init__(self, name: str, work: Path, small: bool) -> None:
        self.name = name
        self.work = work
        self.small = small
        self.db = work / "vault.db"
        self.keychain = work / "keychain.json"
        self.provider = FixedMasterProvider(name)
        self.versions: Dict[Tuple[str, str], int] = {}
        self.expected: Dict[Tuple[str, str, int], str] = {}
        self.undecryptable: set = set()
        self.honeytokens: List[Tuple[str, str]] = []
        self.flow: List[str] = []
        work.mkdir(parents=True, exist_ok=True)
        seed_vault_id(self.db, VAULT_IDS[name])

    @contextlib.contextmanager
    def patched(self) -> Iterator[None]:
        if self.small:
            with mock.patch.object(vault_mod, "HardenedDEKManager", SmallParamsDEKManager):
                yield
        else:
            yield

    def open(self, policy_yaml: str) -> VaultManager:
        return VaultManager(db_path=str(self.db), master_provider=self.provider, policy_yaml=policy_yaml)

    def put(self, vm: VaultManager, ns: str, name: str, value: str, **kw: Any) -> None:
        vm.set_secret(name, value, namespace=ns, **kw)
        v = self.versions.get((ns, name), 0) + 1
        self.versions[(ns, name)] = v
        self.expected[(ns, name, v)] = value
        self.flow.append(f"set_secret {ns}/{name} -> version {v}" + (" (previous version SUPERSEDED)" if v > 1 else ""))

    def mark_non_active_undecryptable(self) -> None:
        """After rotate_dek, non-ACTIVE rows keep ciphertext under the OLD dek (Python only rewrites ACTIVE rows)."""
        for r in self.secret_rows():
            if r["status"] != "ACTIVE":
                self.undecryptable.add((r["namespace"], r["name"], r["version"]))

    def secret_rows(self) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        try:
            rows = [dict(r) for r in conn.execute("SELECT * FROM secrets ORDER BY id")]
        finally:
            conn.close()
        return rows


def _sql_all(db: Path, query: str) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(query)]
    finally:
        conn.close()


def finalize_db(db: Path) -> None:
    """Checkpoint + drop the WAL so vault.db is a single self-contained file."""
    conn = sqlite3.connect(db)
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
    for suffix in ("-wal", "-shm"):
        p = Path(str(db) + suffix)
        if p.exists():
            p.unlink()


def describe_vault(b: VaultBuilder, vm: VaultManager, export_bytes: bytes) -> Dict[str, Any]:
    keychain = json.loads(b.keychain.read_text(encoding="utf-8"))
    aad_prefix = vm.vault_id
    honey = {(ns, n) for ns, n in b.honeytokens}
    secrets: List[Dict[str, Any]] = []
    for r in b.secret_rows():
        ns, name, version = r["namespace"], r["name"], r["version"]
        key = (ns, name, version)
        aad = f"{aad_prefix}:{ns}:{name}".encode()
        try:
            pt = decrypt(r["ciphertext"], vm.dek, aad).decode("utf-8")
            decrypts = True
        except Exception:
            pt, decrypts = None, False
        want_undecryptable = key in b.undecryptable
        assert decrypts == (not want_undecryptable), f"decrypt expectation mismatch for {key}"
        if decrypts and key in b.expected:
            assert pt == b.expected[key], f"plaintext mismatch for {key}"
        entry: Dict[str, Any] = {
            "id": r["id"],
            "secret_id": r["secret_id"],
            "namespace": ns,
            "name": name,
            "version": version,
            "status": r["status"],
            "dek_version": r["dek_version"],
            "note": r["note"],
            "require_2fa": bool(r["require_2fa"]),
            "honeytoken": (ns, name) in honey,
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
            "checksum": r["checksum"],
            "fingerprint": r["checksum"][:8],
            "ciphertext_len": len(r["ciphertext"]),
            "aad": f"{aad_prefix}:{ns}:{name}",
            "decrypts_with_current_dek": decrypts,
            # null for SUPERSEDED rows: a latest-read of that name returns the ACTIVE row instead.
            "read_latest": (
                ("PermissionError" if (ns, name) in honey else "ok")
                if r["status"] == "ACTIVE"
                else ("SecretNotFoundError" if r["status"] == "REVOKED" else None)
            ),
            # by-version reads ignore status but still hit the honeytoken check first
            "read_by_version": (
                "PermissionError" if (ns, name) in honey else ("ok" if decrypts else "DecryptionError")
            ),
        }
        if pt is not None:
            entry["plaintext_len_bytes"] = len(pt.encode("utf-8"))
            entry["plaintext_sha256"] = hashlib.sha256(pt.encode("utf-8")).hexdigest()
            if len(pt) >= BIG_LEN:
                entry["plaintext_gen"] = (
                    "''.join(sha256(f'big:{i}').hexdigest() for i in range(16384))  # exactly 1 MiB"
                )
            else:
                entry["plaintext"] = pt
        secrets.append(entry)

    audit = _sql_all(b.db, "SELECT * FROM audit_logs ORDER BY id")
    actions: Dict[str, int] = {}
    for a in audit:
        actions[a["action"]] = actions.get(a["action"], 0) + 1
    meta = {r["key"]: r["value"] for r in _sql_all(b.db, "SELECT key, value FROM metadata")}
    export_obj = json.loads(base64.b64decode(export_bytes))
    statuses = [s["status"] for s in secrets]
    return {
        "fixture": b.name,
        "generated_by": "tests/compat/gen_go_fixtures.py",
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "files": {
            "db": "vault.db",
            "keychain": "keychain.json",
            "master": "master.bin",
            "policy": "policy.yaml",
            "export": "export.b64",
        },
        "vault_id": vm.vault_id,
        "key_epoch": vm.key_epoch,
        "keychain": keychain,
        "master_hex": b.provider.get_secret().hex(),
        "dek_hex": vm.dek.hex(),
        "policy_hash": vm.policy_hash,
        "policy_hashes_in_chain": sorted({a["policy_hash"] for a in audit if a["policy_hash"] is not None}),
        "metadata": meta,
        "migrations_applied": [
            r["version"] for r in _sql_all(b.db, "SELECT version FROM schema_migrations ORDER BY version")
        ],
        "row_counts": {
            "secrets": len(secrets),
            "secrets_active": statuses.count("ACTIVE"),
            "secrets_superseded": statuses.count("SUPERSEDED"),
            "secrets_revoked": statuses.count("REVOKED"),
            "audit_logs": len(audit),
            "honeytokens": len(_sql_all(b.db, "SELECT * FROM honeytokens")),
        },
        "honeytokens": [{"namespace": ns, "name": n} for ns, n in b.honeytokens],
        "secrets": secrets,
        "audit": {
            "verify_audit_chain": vm.verify_audit_chain(),
            "first_entry_hash": audit[0]["entry_hash"] if audit else None,
            "last_entry_hash": audit[-1]["entry_hash"] if audit else None,
            "actions": actions,
            "rows_with_empty_policy_hash": sum(1 for a in audit if a["policy_hash"] == ""),
            "rows_with_agent_id": sum(1 for a in audit if a["agent_id"] is not None),
        },
        "export": {
            "file": "export.b64",
            "sha256": hashlib.sha256(export_bytes).hexdigest(),
            "vault_id": export_obj["vault_id"],
            "secrets": len(export_obj["secrets"]),
            "audit_logs": len(export_obj["audit_logs"]),
            "honeytokens": len(export_obj["honeytokens"]),
        },
        "read_semantics": [
            "read of the latest version only sees the ACTIVE row (SUPERSEDED/REVOKED-only names -> SecretNotFoundError)",
            "read by explicit version ignores status; it then needs the CURRENT dek to decrypt",
            "rotate_dek rewrites only ACTIVE rows, so SUPERSEDED rows written before it do not decrypt afterwards",
            "a honeytoken name raises PermissionError on lease/fingerprint and writes HONEYTOKEN_TRIGGERED",
        ],
        "flow": b.flow,
    }


def write_vault_dir(out: Path, b: VaultBuilder, vm: VaultManager, policy_yaml: str) -> None:
    export_bytes = vm.export_vault()
    finalize_db(b.db)
    manifest = describe_vault(b, vm, export_bytes)
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(b.db, out / "vault.db")
    shutil.copyfile(b.keychain, out / "keychain.json")
    (out / "master.bin").write_bytes(b.provider.get_secret())
    with open(out / "policy.yaml", "w", encoding="utf-8", newline="\n") as f:
        f.write(policy_yaml)
    (out / "export.b64").write_bytes(export_bytes)
    write_json(out / "manifest.json", manifest)
    assert not (out / "keychain.json.new").exists()


def build_small(out: Path, work: Path) -> None:
    b = VaultBuilder("small", work, small=True)
    with b.patched():
        # Session 0: empty policy => default deny. Writes a POLICY_DENIED row whose policy_hash is "".
        vm0 = b.open("")
        try:
            vm0.set_secret("denied-write", "x", namespace="default", agent="system")
        except Exception as e:
            assert type(e).__name__ == "PolicyDeniedError"
        else:
            raise AssertionError("empty policy must deny the write")
        b.flow.append("session 0 (empty policy): set_secret denied -> POLICY_DENIED row with empty policy_hash")
        del vm0

        vm = b.open(POLICY_MAIN)
        assert vm.key_epoch == 1
        p = b.put
        p(vm, "prod", "DB_PASSWORD", "hunter2-v1", agent="deploy-bot", purpose="deploy", note="primary database")
        p(
            vm,
            "prod",
            "DB_PASSWORD",
            "hunter2-v2-rotated",
            agent="deploy-bot",
            purpose="deploy",
            note="primary database",
        )
        p(vm, "prod", "API_KEY", "sk_live_0123456789abcdef", note="rotated quarterly")
        p(vm, "prod", "TOTP_SEED", "JBSWY3DPEHPK3PXP", note="needs 2FA", require_2fa=True)
        p(vm, "prod", "OLD_TOKEN", "legacy-token-value")
        vm.revoke_secret("prod", "OLD_TOKEN", agent="system")
        b.flow.append("revoke_secret prod/OLD_TOKEN -> REVOKED")
        p(
            vm,
            "default",
            "unicode-secret",
            "p\u00e4ssw\u00f6rd-\u65e5\u672c\u8a9e-\U0001f510-\u03a9\u2248\u00e7\u221a\u222b",
            note="\u00dcn\u00efc\u00f6de n\u00f6te \u2713",
        )
        p(
            vm, "default", "nfc-vs-nfd", "caf\u00e9 / cafe\u0301"
        )  # composed and decomposed 'e acute' must NOT be normalised
        p(vm, "default", "multiline", "line1\r\nline2\n\ttabbed")
        p(vm, "default", "padded", "  leading and trailing  ")
        p(vm, "default", "big-secret", big_value(), note="exactly 1 MiB")
        p(vm, "prod", "NBSP-name_ok", "\u00a0nbsp-prefixed value")
        # Honeytoken: a decoy row plus the honeytokens entry.
        vm.storage.add_honeytoken("prod", "AWS_ROOT_KEY")
        b.honeytokens.append(("prod", "AWS_ROOT_KEY"))
        p(vm, "prod", "AWS_ROOT_KEY", "AKIAFAKEDECOYKEY00000", note="decoy")
        try:
            vm.get_fingerprint("AWS_ROOT_KEY", "prod")
        except PermissionError:
            pass
        else:
            raise AssertionError("honeytoken fingerprint did not trigger")
        b.flow.append("get_fingerprint prod/AWS_ROOT_KEY -> HONEYTOKEN_TRIGGERED")
        with vm.lease_secret("API_KEY", "ci-bot", "prod", "deploy") as buf:
            assert bytes(buf) == b"sk_live_0123456789abcdef"
        b.flow.append("lease_secret prod/API_KEY as ci-bot -> LEASE_GRANTED/LEASE_RETURNED")
        try:
            with vm.lease_secret("API_KEY", "intruder", "prod", "deploy"):
                raise AssertionError("intruder must be denied")
        except Exception as e:
            assert type(e).__name__ == "PolicyDeniedError"
        b.flow.append("lease_secret as intruder -> POLICY_DENIED (explicit deny rule)")
        vm.list_secrets("prod", "ci-bot", "")
        vm.simulate("ci-bot", "prod", "deploy", "read")
        vm.get_fingerprint("API_KEY", "prod")
        b.flow.append("list_secrets, simulate, get_fingerprint")

        vm.rotate_master_key()  # epoch 1 -> 2, new fixed master, same DEK
        assert vm.key_epoch == 2
        b.flow.append("rotate_master_key -> epoch 2 (new master, DEK re-wrapped, DEK unchanged)")
        p(vm, "default", "pre-dek-rotation", "before-v1")
        p(vm, "default", "pre-dek-rotation", "before-v2")
        vm.rotate_dek()  # epoch 2 -> 3, new DEK, ACTIVE rows rewritten
        assert vm.key_epoch == 3
        b.mark_non_active_undecryptable()
        b.flow.append(
            "rotate_dek -> epoch 3 (new DEK; ACTIVE rows re-encrypted; SUPERSEDED/REVOKED rows written before it are now undecryptable)"
        )
        p(vm, "default", "post-rotation", "after-v1")
        p(vm, "default", "post-rotation", "after-v2")
        assert vm.verify_audit_chain() is True
        write_vault_dir(out, b, vm, POLICY_MAIN)


def build_default(out: Path, work: Path) -> None:
    b = VaultBuilder("default", work, small=False)
    vm = b.open(POLICY_MAIN)
    p = b.put
    p(vm, "prod", "DB_URL", "postgres://user:p%40ss@db:5432/app", agent="deploy-bot", purpose="deploy")
    p(vm, "prod", "DB_URL", "postgres://user:newpass@db:5432/app", agent="deploy-bot", purpose="deploy")
    p(vm, "default", "unicode", "\u65e5\u672c\u8a9e\u30d1\u30b9\U0001f510 \u00e9")
    p(vm, "default", "needs-totp", "JBSWY3DPEHPK3PXP", note="2FA gated", require_2fa=True)
    vm.rotate_master_key()
    assert vm.key_epoch == 2
    b.flow.append("rotate_master_key -> epoch 2 (rewrap uses the default Argon2 params 262144/4/4)")
    p(vm, "default", "post-rotation-secret", "ok-after-rotate")
    assert vm.verify_audit_chain() is True
    write_vault_dir(out, b, vm, POLICY_MAIN)


def build_epoch1(out: Path, work: Path) -> None:
    b = VaultBuilder("epoch1", work, small=True)
    with b.patched():
        vm = b.open(POLICY_MAIN)
        assert vm.key_epoch == 1
        p = b.put
        p(vm, "default", "alpha", "alpha-v1")
        p(vm, "default", "alpha", "alpha-v2")
        p(vm, "default", "beta", "beta-value", note="plain note")
        p(vm, "default", "gamma", "gamma-2fa", require_2fa=True)
        assert vm.verify_audit_chain() is True
        write_vault_dir(out, b, vm, POLICY_MAIN)


# ---------------------------------------------------------------------------
# Audit-chain edge databases
# ---------------------------------------------------------------------------

#: Replica of the loop body in ``VaultManager.verify_audit_chain``. Used to compute
#: the per-row expected hash / first bad row; the boolean verdict is ALWAYS taken
#: from the real ``verify_audit_chain`` and the two are asserted equal.


def verifier_expected(prev_hash: str, entry: Dict[str, Any]) -> str:
    raw = (
        f"{prev_hash}|{entry.get('timestamp', '')}|"
        f"{entry.get('action', '')}|{entry.get('secret_name') or ''}|"
        f"{entry.get('details', '')}|{entry.get('policy_hash', '')}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def python_verify(db: Path) -> bool:
    """Run the REAL ``VaultManager.verify_audit_chain`` against ``db`` (no keychain needed)."""
    fake = types.SimpleNamespace(storage=StorageBackend(db))
    return bool(VaultManager.verify_audit_chain(fake))  # type: ignore[arg-type]


def audit_rows(db: Path) -> List[Dict[str, Any]]:
    return _sql_all(db, "SELECT * FROM audit_logs ORDER BY id ASC")


def first_bad_index(rows: List[Dict[str, Any]]) -> Optional[int]:
    prev = ""
    for i, e in enumerate(rows):
        if not hmac.compare_digest(e.get("entry_hash") or "", verifier_expected(prev, e)):
            return i
        prev = e.get("entry_hash") or ""
    return None


EDGE_TS = [
    "2026-01-15T10:20:30.123456+00:00",
    "2026-01-15T10:20:31+00:00",  # microsecond == 0 -> no fractional part
    "2026-01-15T10:20:32.000001+00:00",
    "2026-01-15T10:20:33.100000+00:00",
    "2026-12-31T23:59:59.999999+00:00",
    "2027-02-28T00:00:00+00:00",
    "2027-02-28T00:00:00.500000+00:00",
    "2028-02-29T12:00:00+00:00",
]

# (action, secret_name, details, policy_hash, agent_id) -- passed through the REAL log_audit
EDGE_ROWS: List[Tuple[str, Optional[str], str, str, Optional[str]]] = [
    ("SET_SECRET", "db_pass", "Version 1 created in prod", "0123456789abcdef", "deploy-bot"),
    ("LIST_SECRETS", None, "Listed 3 secrets in prod", "", None),
    ("POLICY_DENIED", "x", "Action: read, Agent: a\r\nb, Namespace: n\tm, Reason: r", "0123456789abcdef", None),
    ("ACT\nION\r\t", "weird", "action name is sanitized too", "0123456789abcdef", None),
    (
        "GET_SECRET",
        "na\u00efve-\u540d\u524d",
        "Version 2 cr\u00e9\u00e9 \u2014 \u65e5\u672c\u8a9e \U0001f510",
        "0123456789abcdef",
        "ci-bot",
    ),
    ("ROTATE", "MASTER_KEY", "", "", None),
    ("LEASE_GRANTED", "db_pass", "Agent: x" + " y" * 50, "fedcba9876543210", "x"),
    (
        "LEASE_RETURNED",
        "db_pass",
        "already \\n escaped stays \\r literal \x0b\x1b control kept",
        "fedcba9876543210",
        "x",
    ),
]


def build_edge_chain(path: Path, n: Optional[int] = None) -> None:
    rows = EDGE_ROWS if n is None else EDGE_ROWS[:n]
    sb = StorageBackend(path)
    stamps = iter(EDGE_TS)
    with mock.patch.object(sqlite_mod, "_utcnow_iso", side_effect=lambda: next(stamps)):
        for action, name, details, ph, agent in rows:
            sb.log_audit(action, name, details, ph, agent_id=agent)


def raw_insert(
    path: Path,
    *,
    action: str,
    secret_name: Optional[str],
    timestamp: str,
    details: Optional[str],
    policy_hash: Optional[str],
    hashed_details: str,
    hashed_policy: str,
) -> None:
    """Append a row the way ``import_data`` could produce it: NULL columns, hash chosen explicitly."""
    prev_rows = audit_rows(path)
    prev = prev_rows[-1]["entry_hash"] if prev_rows else ""
    raw = f"{prev}|{timestamp}|{action}|{secret_name or ''}|{hashed_details}|{hashed_policy}"
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "INSERT INTO audit_logs (action, secret_name, timestamp, details, prev_hash, entry_hash, policy_hash, agent_id)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
            (action, secret_name, timestamp, details, prev, h, policy_hash),
        )
        conn.commit()
    finally:
        conn.close()


def sql_exec(path: Path, query: str, params: Tuple[Any, ...] = ()) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute(query, params)
        conn.commit()
    finally:
        conn.close()


def build_edge(out: Path, work: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    dbs: List[Dict[str, Any]] = []

    def finish(name: str, path: Path, description: str, kind: str = "audit") -> None:
        finalize_db(path)
        rows = audit_rows(path)
        verdict = python_verify(path)
        finalize_db(path)
        bad = first_bad_index(rows)
        assert verdict == (bad is None), f"{name}: real verify={verdict} but replica first_bad={bad}"
        prev = ""
        enriched = []
        for e in rows:
            exp = verifier_expected(prev, e)
            enriched.append({**e, "expected_hash": exp})
            prev = e.get("entry_hash") or ""
        shutil.copyfile(path, out / f"{name}.db")
        dbs.append(
            {
                "file": f"{name}.db",
                "kind": kind,
                "description": description,
                "verify_audit_chain": verdict,
                "first_bad_index": bad,
                "row_count": len(rows),
                "rows": enriched,
            }
        )

    # 1. clean chain, every awkward-but-valid shape.
    p = work / "chain_ok.db"
    build_edge_chain(p)
    finish(
        "chain_ok",
        p,
        "Rows written by the real log_audit: NULL secret_name, empty details/policy_hash, CRLF/tab sanitisation in "
        "action+details, unicode, microsecond==0 timestamps. Verdict True.",
    )

    # 2. NULL details/policy_hash rows whose hash was computed the way the verifier computes it ("None").
    p = work / "null_details_policy_ok.db"
    build_edge_chain(p, 4)
    raw_insert(
        p,
        action="IMPORTED",
        secret_name="n1",
        timestamp="2026-03-01T00:00:00+00:00",
        details=None,
        policy_hash="0123456789abcdef",
        hashed_details="None",
        hashed_policy="0123456789abcdef",
    )
    raw_insert(
        p,
        action="IMPORTED",
        secret_name="n2",
        timestamp="2026-03-01T00:00:01.250000+00:00",
        details="has details",
        policy_hash=None,
        hashed_details="has details",
        hashed_policy="None",
    )
    raw_insert(
        p,
        action="IMPORTED",
        secret_name=None,
        timestamp="2026-03-01T00:00:02+00:00",
        details=None,
        policy_hash=None,
        hashed_details="None",
        hashed_policy="None",
    )
    finish(
        "null_details_policy_ok",
        p,
        "Rows with NULL details and/or NULL policy_hash whose entry_hash was computed with the literal string 'None' "
        "(what verify_audit_chain renders for a present NULL, via entry.get(k, '')). Python verdict True: a Go verifier "
        "must render NULL as 'None' for details and policy_hash (but secret_name NULL as '').",
    )

    # 3. NULL details but hashed as '' (what log_audit/exporter would have hashed) -> Python says False.
    p = work / "null_details_hashed_empty.db"
    build_edge_chain(p, 3)
    raw_insert(
        p,
        action="IMPORTED",
        secret_name="n1",
        timestamp="2026-03-01T00:00:00+00:00",
        details=None,
        policy_hash="0123456789abcdef",
        hashed_details="",
        hashed_policy="0123456789abcdef",
    )
    finish(
        "null_details_hashed_empty",
        p,
        "NULL details but entry_hash computed from ''. Python's verifier renders the NULL as 'None' so it reports the "
        "chain as BROKEN (verdict False, first bad index 3). Pins the quirk.",
    )

    # 4. Tampered row content.
    p = work / "tampered_details.db"
    build_edge_chain(p)
    sql_exec(p, "UPDATE audit_logs SET details = 'tampered' WHERE id = 5")
    finish("tampered_details", p, "Row id 5 (index 4) details altered after the fact. Verdict False.")

    # 5. Tampered stored hash.
    p = work / "tampered_entry_hash.db"
    build_edge_chain(p)
    sql_exec(p, "UPDATE audit_logs SET entry_hash = ? WHERE id = 3", ("0" * 64,))
    finish("tampered_entry_hash", p, "Row id 3 (index 2) entry_hash replaced by zeros. Verdict False.")

    # 6. Tampered timestamp (strip the microseconds).
    p = work / "tampered_timestamp.db"
    build_edge_chain(p)
    sql_exec(p, "UPDATE audit_logs SET timestamp = '2026-01-15T10:20:30+00:00' WHERE id = 1")
    finish(
        "tampered_timestamp", p, "Row id 1 timestamp rewritten without its fractional part. Verdict False (index 0)."
    )

    # 7. Deleted middle row.
    p = work / "deleted_middle.db"
    build_edge_chain(p)
    sql_exec(p, "DELETE FROM audit_logs WHERE id = 4")
    finish("deleted_middle", p, "Row id 4 deleted from the middle. The next row no longer links. Verdict False.")

    # 8. agent_id is NOT part of the hash.
    p = work / "agent_id_not_hashed.db"
    build_edge_chain(p)
    sql_exec(
        p, "UPDATE audit_logs SET agent_id = 'someone-else', prev_hash = 'not-the-previous-hash' WHERE id IN (1, 2, 5)"
    )
    finish(
        "agent_id_not_hashed",
        p,
        "agent_id (and prev_hash) rewritten: the chain still verifies (neither is hashed). True.",
    )

    # 9. Empty log.
    p = work / "empty.db"
    StorageBackend(p)
    finish("empty", p, "Schema only, zero audit rows. Verdict True (vacuous).")

    # 10. Legacy dek_version=0 (Fernet) row: the Go port refuses these (decision D3).
    p = work / "legacy_dek0.db"
    fkey = base64.urlsafe_b64encode(hashlib.sha256(b"rgt-vault-g0-fernet").digest())
    sb = StorageBackend(p)
    sb.set_secret("default", "legacy", Fernet(fkey).encrypt(b"legacy-plaintext"), 0)
    finish(
        "legacy_dek0",
        p,
        "One ACTIVE secret with dek_version=0 (Fernet ciphertext; the Fernet key lives in the OS keyring as "
        "rgt_vault/master_key, here fernet_key). Python migrates these on open; Go refuses them (D3).",
        kind="legacy",
    )
    dbs[-1]["fernet_key"] = fkey.decode()
    dbs[-1]["legacy_plaintext"] = "legacy-plaintext"

    write_json(
        out / "manifest.json",
        {
            "generated_by": "tests/compat/gen_go_fixtures.py",
            "python": platform.python_version(),
            "note": "verify_audit_chain verdicts come from the real VaultManager.verify_audit_chain; first_bad_index is "
            "0-based over rows ordered by id ASC; expected_hash is what the verifier computes for each row given the "
            "stored previous entry_hash.",
            "hash_input": "f'{prev_entry_hash}|{timestamp}|{action}|{secret_name or \"\"}|{details}|{policy_hash}' "
            "with details/policy_hash rendered via str() of the stored value (NULL -> 'None'); sha256 hexdigest; "
            "agent_id is not part of it",
            "databases": dbs,
        },
    )


# ---------------------------------------------------------------------------
# Vector families: every family has an eval_* function that re-derives the
# expectation from the case inputs with the real Python code.
# ---------------------------------------------------------------------------

# ---- capability tokens ----------------------------------------------------

V2_KEY = hashlib.sha256(b"rgt-vault-g0-harness-key-v2").digest()
V1_KEY = hashlib.sha256(b"rgt-vault-g0-harness-key-v1").digest()
V2_OTHER_KEY = hashlib.sha256(b"rgt-vault-g0-wrong-key").digest()


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def sign_payload(key: bytes, payload: bytes) -> str:
    """Envelope a raw payload with a valid HMAC (lets us sign payloads the real signer would refuse)."""
    return token_mod._envelope(payload, hmac.new(key, payload, hashlib.sha256).digest())


def v2_payload(agent: Any, cap: Any, ver: Any, bindings: Any, exp: Any, v: Any = 2) -> bytes:
    """Same bytes as token._canonical_payload but with arbitrary JSON values (for malformed cases)."""
    return json.dumps(
        {
            "v": v,
            "agent_id": agent,
            "capability": cap,
            "capability_version": ver,
            "context_bindings": bindings,
            "exp": exp,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def eval_v2_verify(key_hex: str, token: str, now: int) -> Dict[str, Any]:
    verifier = HMACTokenVerifier(bytes.fromhex(key_hex))
    try:
        with frozen_time(now):
            tok = verifier.verify(token)
    except Exception as e:  # incl. non-TokenError leaks (TypeError/ValueError)
        return err_obj(e)
    return {
        "ok": True,
        "claims": {
            "agent_id": tok.agent_id,
            "capability": tok.capability,
            "capability_version": tok.capability_version,
            "context_bindings": dict(tok.context_bindings),
            "expires_at": tok.expires_at,
            "token_id": tok.token_id,
        },
    }


def eval_v2_sign(key_hex: str, case: Dict[str, Any]) -> str:
    verifier = HMACTokenVerifier(bytes.fromhex(key_hex))
    with frozen_time(case["now"]):
        return verifier.sign(
            case["agent_id"],
            case["capability"],
            case["capability_version"],
            case["context_bindings"],
            case["ttl_seconds"],
        )


def eval_check_context(bindings: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    tok = CapabilityV2Token("a", "c", 1, bindings)
    try:
        tok.check_context(ctx)
    except Exception as e:
        return {"ok": False, "error": type(e).__name__}
    return {"ok": True}


def eval_is_expired(exp: int, now: int) -> bool:
    return CapabilityV2Token("a", "c", 1, {}, exp).is_expired(now)


def build_tokens_v2() -> Dict[str, Any]:
    key = V2_KEY
    key_hex = key.hex()

    def mk(
        name: str, agent: str, cap: str, ver: int, bindings: Dict[str, Any], exp: int = FAR_FUTURE, why: str = ""
    ) -> Dict[str, Any]:
        payload = token_mod._canonical_payload(agent, cap, ver, bindings, exp)
        return {
            "name": name,
            "why": why,
            "payload_json": payload.decode("ascii"),
            "token": sign_payload(key, payload),
        }

    good = [
        mk("basic", "research-agent", "github.read_repo", 1, {"repo": "org/research"}),
        mk("no_bindings", "agent-2", "secrets.echo", 1, {}),
        mk(
            "keys_sorted_nested",
            "agent-3",
            "cap.nested",
            3,
            {"zeta": 1, "alpha": "a", "mid": [1, 2, {"x": None}], "flag": True, "nested": {"b": 1, "a": 2}},
            why="sort_keys at every level; true/null spelled as JSON",
        ),
        mk(
            "unicode_ensure_ascii",
            "ag\u00e9nt-\u65e5\u672c",
            "cap.\u00fcn\u00ef",
            1,
            {"nom": "Jos\u00e9 \U0001f510"},
            why="Python ensure_ascii: \\u00e9, astral char as surrogate pair \\ud83d\\udd10. Go json.Marshal would NOT escape these",
        ),
        mk(
            "html_chars_unescaped",
            "agent-4",
            "cap.html",
            1,
            {"q": "<script>&'\"</script>"},
            why="Python leaves < > & raw; Go json.Marshal would emit \\u003c \\u003e \\u0026",
        ),
        mk(
            "control_chars",
            "agent-5",
            "cap.ctl",
            1,
            {"s": 'a\x00b\x7fc\u2028d\n\t"\\/'},
            why="DEL (0x7f) IS escaped (\\u007f) by Python ensure_ascii; '/' is not escaped",
        ),
        mk("float_binding", "agent-6", "cap.float", 1, {"f": 1.5, "i": 7}),
        mk(
            "big_int_binding",
            "agent-7",
            "cap.bigint",
            1,
            {"big": 9007199254740993},
            why="above 2^53: a Go decoder into float64/any loses precision; use json.Number to re-sign byte-identically",
        ),
        mk("version_7", "agent-8", "cap.v", 7, {}),
        mk("exp_zero_never_expires", "agent-9", "cap.exp0", 1, {}, exp=0, why="is_expired is False when exp <= 0"),
        mk("exp_negative_never_expires", "agent-9", "cap.expneg", 1, {}, exp=-5, why="exp <= 0 never expires"),
        mk("exp_small_expired", "agent-9", "cap.expired", 1, {}, exp=1000, why="verified at now=1001 below"),
    ]
    verify_cases: List[Dict[str, Any]] = []
    for g in good:
        verify_cases.append({**g, "now": 1_900_000_000 if g["name"] != "exp_small_expired" else 1001})
    # expiry boundary: now == exp is still valid, now == exp+1 is expired
    boundary = next(g for g in good if g["name"] == "exp_small_expired")
    verify_cases.append(
        {**boundary, "name": "exp_boundary_now_equals_exp", "now": 1000, "why": "expired only when now > exp"}
    )

    def add(
        name: str, token: str, now: int = 1_900_000_000, why: str = "", key_hex_override: Optional[str] = None
    ) -> None:
        case: Dict[str, Any] = {"name": name, "why": why, "token": token, "now": now}
        if key_hex_override:
            case["key_hex"] = key_hex_override
        verify_cases.append(case)

    basic = good[0]
    b_payload, b_sig = basic["token"].split(".")
    flip = lambda s: ("A" if s[0] != "A" else "B") + s[1:]  # noqa: E731
    add("tampered_payload_char", flip(b_payload) + "." + b_sig)
    add("tampered_signature_char", b_payload + "." + flip(b_sig))
    add("truncated_signature", b_payload + "." + b_sig[:-4])
    add(
        "wrong_key",
        sign_payload(V2_OTHER_KEY, v2_payload("a", "c", 1, {}, FAR_FUTURE)),
        why="valid HMAC under a different key",
    )
    add("no_dot", b_payload + b_sig)
    add("three_parts", b_payload + "." + b_sig + ".extra")
    add("empty_string", "")
    add("empty_payload_part", "." + b_sig)
    add("empty_signature_part", b_payload + ".")
    add("bad_base64_payload", "!!!!." + b_sig)
    add(
        "padded_base64_accepted",
        b_payload + "=" * (-len(b_payload) % 4) + "." + b_sig + "=" * (-len(b_sig) % 4),
        why="'=' padding is accepted (lenient)",
    )
    add(
        "embedded_newline_accepted",
        b_payload[:10] + "\n" + b_payload[10:] + "." + b_sig,
        why="non-alphabet chars are discarded by Python's non-strict b64decode",
    )
    # standard-alphabet chars in place of urlsafe ones
    for g in good:
        p_, s_ = g["token"].split(".")
        if "-" in p_ or "_" in p_ or "-" in s_ or "_" in s_:
            std = lambda s: s.replace("-", "+").replace("_", "/")  # noqa: E731
            add(
                "standard_alphabet_accepted",
                std(p_) + "." + std(s_),
                why="'+' and '/' decode like '-' and '_' (lenient)",
            )
            break
    else:
        raise AssertionError("no generated token contains '-' or '_': pick payloads that do")

    def signed(name: str, payload: bytes, why: str = "") -> None:
        add(name, sign_payload(key, payload), why=why)

    signed("version_3", v2_payload("a", "c", 1, {}, FAR_FUTURE, v=3), "validly signed, unsupported format version")
    signed(
        "version_missing",
        json.dumps(
            {"agent_id": "a", "capability": "c", "capability_version": 1, "exp": FAR_FUTURE},
            sort_keys=True,
            separators=(",", ":"),
        ).encode(),
        "no v key -> version 0",
    )
    signed("version_string_2_accepted", v2_payload("a", "c", 1, {}, FAR_FUTURE, v="2"), "int('2') == 2")
    signed("version_float_2_accepted", v2_payload("a", "c", 1, {}, FAR_FUTURE, v=2.0), "int(2.0) == 2")
    signed(
        "version_null_leaks_typeerror",
        v2_payload("a", "c", 1, {}, FAR_FUTURE, v=None),
        "int(None) raises TypeError, NOT a TokenError (uncaught in Python)",
    )
    signed(
        "version_garbage_leaks_valueerror",
        v2_payload("a", "c", 1, {}, FAR_FUTURE, v="abc"),
        "int('abc') raises ValueError, NOT a TokenError",
    )
    signed(
        "missing_exp",
        b'{"agent_id":"a","capability":"c","capability_version":1,"context_bindings":{},"v":2}',
        "KeyError -> TokenMalformedError",
    )
    signed(
        "missing_agent_id", b'{"capability":"c","capability_version":1,"context_bindings":{},"exp":4102444800,"v":2}'
    )
    signed("payload_is_list", b"[1,2]")
    signed("payload_is_string", b'"str"')
    signed("payload_not_json", b"not json at all")
    signed("payload_invalid_utf8", b"\xff\xfe{")
    signed(
        "payload_raw_utf8_not_escaped",
        json.dumps(
            {
                "v": 2,
                "agent_id": "\u00e9",
                "capability": "c",
                "capability_version": 1,
                "context_bindings": {},
                "exp": FAR_FUTURE,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8"),
        "verify works on raw bytes; non-ascii payload is fine",
    )
    signed(
        "payload_not_canonical_whitespace",
        b'{ "v": 2, "agent_id": "a", "capability": "c", "capability_version": 1, "exp": 4102444800 }',
        "verify does not require canonical form; token_id hashes the received bytes",
    )
    signed("agent_id_int_coerced", v2_payload(123, "c", 1, {}, FAR_FUTURE), "str(123) == '123'")
    signed("agent_id_null_coerced", v2_payload(None, "c", 1, {}, FAR_FUTURE), "str(None) == 'None'")
    signed("capability_version_string", v2_payload("a", "c", "2", {}, FAR_FUTURE), "int('2')")
    signed("capability_version_float", v2_payload("a", "c", 2.9, {}, FAR_FUTURE), "int(2.9) == 2")
    signed("capability_version_true", v2_payload("a", "c", True, {}, FAR_FUTURE), "int(True) == 1")
    signed(
        "capability_version_null",
        v2_payload("a", "c", None, {}, FAR_FUTURE),
        "int(None) -> TypeError -> TokenMalformedError",
    )
    signed("capability_version_garbage", v2_payload("a", "c", "x", {}, FAR_FUTURE), "ValueError -> TokenMalformedError")
    signed("exp_string_coerced", v2_payload("a", "c", 1, {}, "4102444800"), "int('4102444800')")
    signed("exp_float_coerced", v2_payload("a", "c", 1, {}, 4102444800.7), "int() truncates")
    signed("bindings_null_is_empty", v2_payload("a", "c", 1, None, FAR_FUTURE), "`or {}`")
    signed("bindings_empty_list_is_empty", v2_payload("a", "c", 1, [], FAR_FUTURE), "falsy -> {}")
    signed("bindings_zero_is_empty", v2_payload("a", "c", 1, 0, FAR_FUTURE), "falsy -> {}")
    signed("bindings_nonempty_list", v2_payload("a", "c", 1, [1], FAR_FUTURE), "truthy non-dict -> TokenMalformedError")
    signed("bindings_string", v2_payload("a", "c", 1, "x", FAR_FUTURE), "truthy non-dict -> TokenMalformedError")

    sign_cases = []
    for agent, cap, ver, bindings, ttl, now in [
        ("research-agent", "github.read_repo", 1, {"repo": "org/research"}, 60, 4_000_000_000),
        ("a", "c", 1, {}, 1, 1_700_000_000),
        ("ag\u00e9nt", "cap.\u65e5\u672c", 2, {"k": "\U0001f510<&>", "a": [3, 2, 1]}, 3600, 1_800_000_000),
        ("agent", "cap", 9, {"z": None, "y": False, "x": 1.25}, 86400, 1_700_000_001),
    ]:
        case = {
            "agent_id": agent,
            "capability": cap,
            "capability_version": ver,
            "context_bindings": bindings,
            "ttl_seconds": ttl,
            "now": now,
        }
        tok = eval_v2_sign(key_hex, case)
        payload = base64.urlsafe_b64decode(tok.split(".")[0] + "=" * (-len(tok.split(".")[0]) % 4))
        sign_cases.append({**case, "expected_payload_json": payload.decode("ascii"), "expected_token": tok})
    sign_errors = []
    for case in [
        {
            "agent_id": "a",
            "capability": "c",
            "capability_version": 1,
            "context_bindings": {},
            "ttl_seconds": 0,
            "now": 1,
        },
        {
            "agent_id": "",
            "capability": "c",
            "capability_version": 1,
            "context_bindings": {},
            "ttl_seconds": 5,
            "now": 1,
        },
        {
            "agent_id": "a",
            "capability": "",
            "capability_version": 1,
            "context_bindings": {},
            "ttl_seconds": 5,
            "now": 1,
        },
        {
            "agent_id": "a",
            "capability": "c",
            "capability_version": 0,
            "context_bindings": {},
            "ttl_seconds": 5,
            "now": 1,
        },
    ]:
        try:
            eval_v2_sign(key_hex, case)
        except Exception as e:
            sign_errors.append({**case, "error": type(e).__name__})
        else:
            raise AssertionError(f"expected sign() to reject {case!r}")

    for c in verify_cases:
        c["expect"] = eval_v2_verify(c.get("key_hex", key_hex), c["token"], c["now"])
    # explicit key override example: the same token verifies under its own key and fails under another
    verify_cases.append(
        {
            "name": "valid_token_checked_with_other_key",
            "why": "signature check uses the configured key",
            "key_hex": V2_OTHER_KEY.hex(),
            "token": basic["token"],
            "now": 1_900_000_000,
            "expect": eval_v2_verify(V2_OTHER_KEY.hex(), basic["token"], 1_900_000_000),
        }
    )

    ctx_cases = []
    ctx_specs: List[Tuple[str, Dict[str, Any], Dict[str, Any], str]] = [
        ("equal", {"repo": "a"}, {"repo": "a"}, ""),
        ("extra_context_keys_ok", {"repo": "a"}, {"repo": "a", "x": 1}, ""),
        ("missing_key", {"repo": "a"}, {}, ""),
        ("mismatch", {"repo": "a"}, {"repo": "b"}, ""),
        ("no_bindings_anything_ok", {}, {"anything": 1}, ""),
        ("int_vs_float_equal", {"n": 1}, {"n": 1.0}, "Python 1 == 1.0"),
        ("true_vs_one_equal", {"flag": True}, {"flag": 1}, "Python True == 1 (Go: bool != float64)"),
        ("string_vs_int", {"n": "1"}, {"n": 1}, ""),
        ("null_binding_key_present", {"k": None}, {"k": None}, ""),
        ("null_binding_key_absent", {"k": None}, {}, "key must be PRESENT even for null"),
        ("nested_dict_equal", {"d": {"a": 1, "b": [1, 2]}}, {"d": {"b": [1, 2], "a": 1}}, ""),
        ("list_order_matters", {"l": [1, 2]}, {"l": [2, 1]}, ""),
        ("nfc_vs_nfd_differ", {"s": "caf\u00e9"}, {"s": "cafe\u0301"}, "no normalisation"),
        ("multiple_bindings_one_fails", {"a": 1, "b": 2}, {"a": 1, "b": 3}, ""),
    ]
    for name, bnd, ctx, why in ctx_specs:
        ctx_cases.append(
            {
                "name": name,
                "why": why,
                "bindings": bnd,
                "context": ctx,
                "expect": eval_check_context(bnd, ctx),
            }
        )

    expiry_cases = [
        {"exp": exp, "now": now, "expired": eval_is_expired(exp, now)}
        for exp, now in [
            (1000, 999),
            (1000, 1000),
            (1000, 1001),
            (0, 10**12),
            (-1, 10**12),
            (FAR_FUTURE, FAR_FUTURE),
            (FAR_FUTURE, FAR_FUTURE + 1),
        ]
    ]

    # TwoFactorHook v2 dispatch (capability path)
    def req(token: str, **kw: Any) -> Dict[str, Any]:
        base = {
            "operation": "capability",
            "agent": "research-agent",
            "namespace": "",
            "capability": "github.read_repo",
            "capability_version": 1,
            "payload": {"repo": "org/research"},
            "token": token,
        }
        base.update(kw)
        return base

    hook_cases = []
    for name, steps, why in [
        ("allow", [req(basic["token"])], ""),
        (
            "replay_second_use_denied",
            [req(basic["token"]), req(basic["token"])],
            "second consult of the same token_id in one hook instance is a replay",
        ),
        ("agent_mismatch", [req(basic["token"], agent="other")], ""),
        ("capability_mismatch", [req(basic["token"], capability="github.write")], ""),
        ("version_mismatch", [req(basic["token"], capability_version=2)], ""),
        ("context_binding_violation", [req(basic["token"], payload={"repo": "evil/repo"})], ""),
        ("context_missing", [req(basic["token"], payload={})], ""),
        (
            "v2_token_on_legacy_op",
            [req(basic["token"], operation="read", capability=None, capability_version=0)],
            "v2 tokens only authorize capability execution",
        ),
        ("tampered", [req(flip(b_payload) + "." + b_sig)], ""),
        (
            "expired",
            [
                req(
                    next(c for c in verify_cases if c["name"] == "exp_small_expired")["token"],
                    agent="agent-9",
                    capability="cap.expired",
                    payload={},
                )
            ],
            "now=1001 vs exp 1000",
        ),
        ("no_token", [req("")], ""),
    ]:
        now = 1001 if name == "expired" else 1_900_000_000
        hook_cases.append(
            {"name": name, "why": why, "now": now, "requests": steps, "expect": eval_hook(V2_KEY.hex(), now, steps)}
        )

    return {
        "description": "v2 capability tokens (rgt_vault.token). HMAC-SHA256 key is a FIXED TEST KEY, not a real secret. "
        "Wire: b64url(payload).b64url(hmac) without padding; payload = json.dumps(sort_keys, (',',':')) with ensure_ascii. "
        "token_id = sha256_hex(payload)[:16]. 'now' is the clock to inject for verify.",
        "key_hex": key_hex,
        "far_future_exp": FAR_FUTURE,
        "verify": verify_cases,
        "sign": sign_cases,
        "sign_errors": sign_errors,
        "check_context": ctx_cases,
        "is_expired": expiry_cases,
        "hook_v2": {"key_hex": V2_KEY.hex(), "cases": hook_cases},
    }


def eval_hook(key_hex: str, now: int, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run the REAL TwoFactorHook.consult over a sequence of requests on ONE hook instance."""
    hook = TwoFactorHook(bytes.fromhex(key_hex))
    out = []
    with frozen_time(now):
        for r in requests:
            req = HookRequest(
                operation=r["operation"],
                agent=r["agent"],
                namespace=r.get("namespace", ""),
                capability=r.get("capability"),
                capability_version=r.get("capability_version", 0),
                payload=r.get("payload"),
                capability_token=r["token"],
            )
            resp = hook.consult(req)
            out.append({"decision": resp.decision.value, "reason": resp.reason})
    return out


def v1_token(
    key: bytes,
    agent: str,
    ns: str,
    caps: List[str],
    issued: int,
    expires: int,
    tid: str,
    *,
    secret: Optional[bytes] = None,
) -> str:
    """A v1 token signed the way TwoFactorHook._consult_v1 expects (HMAC under the shared secret)."""
    payload = json.dumps(
        {"a": agent, "n": ns, "c": sorted(caps), "i": issued, "x": expires, "t": tid},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    sig = hook_mod._sign(payload, key if secret is None else secret)
    return _b64u(payload) + "." + _b64u(sig)


def build_tokens_v1() -> Dict[str, Any]:
    key = V1_KEY
    now = 1_900_000_000
    ok = v1_token(key, "agent-a", "prod", ["read", "write"], now - 10, now + 50, "t-ok")
    star_ns = v1_token(key, "agent-a", "*", ["read"], now - 10, now + 50, "t-star-ns")
    star_op = v1_token(key, "agent-a", "prod", ["*"], now - 10, now + 50, "t-star-op")
    future = v1_token(key, "agent-a", "prod", ["read"], now + 100, now + 200, "t-future")
    expired = v1_token(key, "agent-a", "prod", ["read"], now - 200, now - 100, "t-expired")
    edge_start = v1_token(key, "agent-a", "prod", ["read"], now, now + 5, "t-edge-start")
    edge_end = v1_token(key, "agent-a", "prod", ["read"], now - 5, now, "t-edge-end")
    unicode_tok = v1_token(key, "ag\u00e9nt-\u65e5", "pr\u00f6d", ["read"], now - 10, now + 50, "t-unicode")
    p_ok, s_ok = ok.split(".")
    # What TwoFactorHook.issue(...).to_compact() actually emits: HMAC under the EMPTY key.
    issued_tok = hook_mod.CapabilityToken(
        agent="agent-a",
        namespace="prod",
        capabilities=["read"],
        issued_at=now - 10,
        expires_at=now + 50,
        token_id="t-issue",
    ).to_compact()

    def r(token: str, **kw: Any) -> Dict[str, Any]:
        base = {"operation": "read", "agent": "agent-a", "namespace": "prod", "token": token}
        base.update(kw)
        return base

    cases_spec: List[Tuple[str, List[Dict[str, Any]], str]] = [
        ("allow", [r(ok)], ""),
        ("allow_write_op", [r(ok, operation="write")], ""),
        ("op_not_covered", [r(ok, operation="revoke")], ""),
        ("namespace_mismatch", [r(ok, namespace="dev")], ""),
        ("agent_mismatch", [r(ok, agent="agent-b")], ""),
        ("wildcard_namespace", [r(star_ns, namespace="anything")], "token namespace '*' covers every namespace"),
        ("wildcard_operation", [r(star_op, operation="rotate")], "capabilities ['*'] covers every operation"),
        ("not_yet_valid", [r(future)], "issued_at > now"),
        ("expired", [r(expired)], ""),
        ("boundary_issued_equals_now", [r(edge_start)], "issued_at <= now <= expires_at is inclusive"),
        ("boundary_expires_equals_now", [r(edge_end)], "inclusive"),
        ("replay_second_use_denied", [r(ok), r(ok)], "second consult of the same token_id on one hook instance"),
        ("tampered_payload", [r(("A" if p_ok[0] != "A" else "B") + p_ok[1:] + "." + s_ok)], ""),
        ("tampered_signature", [r(p_ok + "." + ("A" if s_ok[0] != "A" else "B") + s_ok[1:])], ""),
        ("no_dot", [r(p_ok + s_ok)], ""),
        ("bad_base64", [r("!!!." + s_ok)], ""),
        ("empty_token", [r("")], ""),
        ("unicode_agent_ns", [r(unicode_tok, agent="ag\u00e9nt-\u65e5", namespace="pr\u00f6d")], ""),
        (
            "issue_to_compact_is_signed_with_empty_key",
            [r(issued_tok)],
            "PYTHON BUG pinned as-is: CapabilityToken.to_compact() signs with b'' (placeholder), so tokens minted by "
            "TwoFactorHook.issue().to_compact() can never verify under the hook's shared secret",
        ),
    ]
    cases = [
        {"name": n, "why": w, "now": now, "requests": steps, "expect": eval_hook(key.hex(), now, steps)}
        for n, steps, w in cases_spec
    ]
    return {
        "description": "v1 (legacy, namespace/operation) tokens consulted through the real TwoFactorHook. Payload keys: "
        "a=agent n=namespace c=sorted capabilities i=issued_at x=expires_at t=token_id; signature = HMAC-SHA256(shared_secret, payload). "
        "Key is a FIXED TEST KEY. Go must match 'decision'; 'reason' is Python's wording (the Python self-check pins it verbatim, a Go port need not). Each case runs on a fresh hook.",
        "key_hex": key.hex(),
        "cases": cases,
        "issue_to_compact_token": issued_tok,
    }


# ---- TOTP -----------------------------------------------------------------

TOTP_SECRETS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",
}
RFC_TIMES = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]
RFC_EXPECTED = {
    "SHA1": ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"],
    "SHA256": ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"],
    "SHA512": ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"],
}


def b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode().rstrip("=")


def eval_totp_generate(c: Dict[str, Any]) -> str:
    return totp.generate(
        c["secret"], timestamp=c["timestamp"], digits=c["digits"], period=c["period"], algorithm=c["algorithm"]
    )


def eval_totp_verify(c: Dict[str, Any]) -> Dict[str, Any]:
    try:
        res = totp.verify(
            c["secret"],
            c["code"],
            timestamp=c["timestamp"],
            digits=c["digits"],
            period=c["period"],
            algorithm=c["algorithm"],
            window=c["window"],
        )
    except Exception as e:
        return {"raises": type(e).__name__}
    return {"returns": res}


def eval_totp_replay(c: Dict[str, Any]) -> List[Any]:
    v = totp.ReplayGuardedVerifier(
        c["secret"], digits=c["digits"], period=c["period"], algorithm=c["algorithm"], window=c["window"]
    )
    out: List[Any] = []
    for s in c["steps"]:
        try:
            out.append(v(s["code"], timestamp=s["timestamp"]))
        except Exception as e:
            out.append({"raises": type(e).__name__})
    return out


def eval_totp_uri(c: Dict[str, Any]) -> str:
    return totp.provisioning_uri(
        c["secret"], c["account"], issuer=c["issuer"], digits=c["digits"], period=c["period"], algorithm=c["algorithm"]
    )


def build_totp() -> Dict[str, Any]:
    rfc = []
    for algo, raw in TOTP_SECRETS.items():
        for t, expected in zip(RFC_TIMES, RFC_EXPECTED[algo]):
            c = {
                "algorithm": algo,
                "secret": b32(raw),
                "secret_ascii": raw.decode(),
                "digits": 8,
                "period": 30,
                "timestamp": t,
            }
            code = eval_totp_generate(c)
            assert code == expected, f"RFC 6238 vector {algo}@{t}: python={code} rfc={expected}"
            rfc.append({**c, "code": code})

    gen6 = []
    sec = b32(b"12345678901234567890")
    for algo in TOTP_SECRETS:
        key = b32(TOTP_SECRETS[algo])
        for t in (0, 29, 30, 59, 60, 1700000000, 1700000029, 1700000030, 4102444800):
            c = {"algorithm": algo, "secret": key, "digits": 6, "period": 30, "timestamp": t}
            gen6.append({**c, "code": eval_totp_generate(c)})
    for dg, per, t in [
        (7, 30, 1700000000),
        (8, 60, 1700000000),
        (6, 15, 1700000014),
        (6, 15, 1700000015),
        (10, 30, 1700000000),
    ]:
        c = {"algorithm": "SHA1", "secret": sec, "digits": dg, "period": per, "timestamp": t}
        gen6.append({**c, "code": eval_totp_generate(c)})
    # fractional timestamps and secret spellings
    fractional: List[float] = [59.999, 1700000029.999999, 1700000030.0]
    for ts in fractional:
        c = {"algorithm": "SHA1", "secret": sec, "digits": 6, "period": 30, "timestamp": ts}
        gen6.append({**c, "code": eval_totp_generate(c), "why": "fractional timestamp: floor(t / period)"})
    for label, spelled in [
        ("lowercase", sec.lower()),
        ("spaces", " ".join(sec[i : i + 4] for i in range(0, len(sec), 4))),
        ("surrounding_spaces", "  " + sec + "  "),
        ("complete_padding", b32(b"hello world") + "======"),
        ("complete_padding_lowercase_spaced", " " + b32(b"hello world").lower() + "======  "),
        ("unpadded_11_bytes", b32(b"hello world")),
    ]:
        c = {"algorithm": "SHA1", "secret": spelled, "digits": 6, "period": 30, "timestamp": 1700000000}
        gen6.append({**c, "code": eval_totp_generate(c), "why": f"secret spelling: {label} decodes to the same key"})

    base_t = 1700000000
    base_c = {"secret": sec, "digits": 6, "period": 30, "algorithm": "SHA1"}
    step = lambda k: totp.generate(sec, timestamp=base_t + 30 * k)  # noqa: E731
    verify_cases = []

    def v(name: str, code: str, window: int = 1, **over: Any) -> None:
        c = {**base_c, "timestamp": base_t, "code": code, "window": window, **over}
        verify_cases.append({"name": name, **c, "expect": eval_totp_verify(c)})

    v("current_step", step(0))
    v("previous_step_window1", step(-1))
    v("next_step_window1", step(1))
    v("two_steps_back_window1", step(-2))
    v("two_steps_ahead_window1", step(2))
    v("previous_step_window0", step(-1), window=0)
    v("current_step_window0", step(0), window=0)
    v("two_steps_back_window2", step(-2), window=2)
    v("three_steps_ahead_window2", step(3), window=2)
    v("surrounding_whitespace_accepted", " " + step(0) + "\n")
    v("wrong_code", "000000" if step(0) != "000000" else "000001")
    v("too_short", step(0)[:-1])
    v("too_long", step(0) + "0")
    v("empty", "")
    v("whitespace_only", "   ")
    v("non_digits", "12a456")
    v("negative_sign", "-12345")
    v("plus_sign", "+12345")
    v("fullwidth_digits_raise", "\uff11\uff12\uff13\uff14\uff15\uff16")
    v("arabic_indic_digits_raise", "\u0661\u0662\u0663\u0664\u0665\u0666")
    v("invalid_base32_secret", step(0), secret="not*base32!")
    v("empty_secret", step(0), secret="")
    v(
        "extra_padding_is_invalid",
        step(0),
        secret=sec + "====",
        why="padding is re-added after stripping spaces; extra '=' -> binascii.Error -> False",
    )
    v("sha256_code_checked_as_sha1", totp.generate(b32(TOTP_SECRETS["SHA256"]), timestamp=base_t, algorithm="SHA256"))
    # a code for another secret
    v("other_secret", totp.generate(b32(b"another-secret-key!!"), timestamp=base_t))

    replay_cases = []
    for name, steps in [
        ("same_code_twice", [(0, 0), (0, 0)]),
        ("next_step_then_old_step", [(1, 1), (0, 0)]),
        ("old_step_then_next", [(0, 0), (1, 1)]),
        ("window_consumes_counter_not_time", [(1, 0), (0, 0), (1, 0)]),
        ("far_future_then_back", [(0, 0), (2, 2), (1, 1), (0, 0)]),
    ]:
        # (code_step, timestamp_step) both relative to base_t in 30s units
        c = {**base_c, "window": 1, "steps": [{"code": step(cs), "timestamp": base_t + 30 * ts} for cs, ts in steps]}
        replay_cases.append({"name": name, **c, "expect": eval_totp_replay(c)})
    c = {
        **base_c,
        "window": 1,
        "steps": [
            {"code": " " + step(0) + " ", "timestamp": base_t},
            {"code": "abc", "timestamp": base_t},
            {"code": "", "timestamp": base_t},
        ],
    }
    replay_cases.append({"name": "whitespace_stripped_then_malformed", **c, "expect": eval_totp_replay(c)})
    c = {**base_c, "secret": "!!!", "window": 1, "steps": [{"code": "123456", "timestamp": base_t}]}
    replay_cases.append({"name": "invalid_secret", **c, "expect": eval_totp_replay(c)})

    uri_cases = []
    for issuer, account, algo, dg, per in [
        ("rgt-vault", "alice", "SHA1", 6, 30),
        ("rgt-vault", "alice@example.com", "SHA1", 6, 30),
        ("My Co & Sons", "j\u00fcrgen m\u00fcller", "SHA256", 8, 60),
        ("rgt/vault", "a/b c", "SHA512", 6, 30),
        ("\u65e5\u672c", "\u540d\u524d:x", "SHA1", 7, 45),
        ("is:suer", "ac:count?x=1&y=2#frag", "SHA1", 6, 30),
        ("", "", "SHA1", 6, 30),
        ("100% real", "u+v~w!x*y'z(1)", "SHA1", 6, 30),
    ]:
        c = {"secret": sec, "account": account, "issuer": issuer, "digits": dg, "period": per, "algorithm": algo}
        uri_cases.append(
            {
                **c,
                "uri": eval_totp_uri(c),
                "why": "urllib.parse.quote default safe='/' (slash stays literal; space -> %20; '~' unreserved)",
            }
        )

    return {
        "description": "RFC 6238 TOTP (rgt_vault.totp). 'rfc6238' are the published Appendix B values (asserted by the "
        "generator). Secrets are FIXED TEST SEEDS. verify: window = +/- steps; 'raises' marks an exception that Python "
        "lets escape (hmac.compare_digest on a non-ASCII digit string).",
        "base_timestamp": base_t,
        "rfc6238": rfc,
        "generate": gen6,
        "verify": verify_cases,
        "replay_guard": replay_cases,
        "provisioning_uri": uri_cases,
    }


# ---- ABAC / fnmatch -------------------------------------------------------

ABAC_POLICIES: Dict[str, str] = {
    "allow_all_list": "- effect: allow\n",
    "scoped": """rules:
  - {effect: allow, agent: "ci-*", namespace: "prod/*", purpose: "deploy*", action: read, ttl: 60}
  - {effect: allow, agent: "ci-bot", namespace: "*", purpose: "*", action: "*", ttl: 120}
  - {effect: deny, agent: "*", namespace: "secret.*", purpose: "*", action: "*"}
  - {effect: allow, agent: ops, namespace: "[ab]?", purpose: "[!x]*", action: "re*"}
  - {effect: ALLOW, agent: caseins}
  - {effect: allow, agent: admin, action: write, ttl: abc}
  - {effect: allow, agent: ttl0, ttl: 0}
  - {agent: noeffect}
  - {effect: "", agent: emptyeffect}
  - {effect: permit, agent: unknowneffect}
""",
    "purpose_slash": """rules:
  - {effect: allow, agent: deployer, purpose: "deploy/*", action: read}
  - {effect: allow, agent: single, purpose: "a?c", action: read}
  - {effect: allow, agent: classy, purpose: "rel[0-9]/*", action: read}
  - {effect: allow, agent: literal, purpose: "a/b/c", action: read}
""",
    "deny_precedence": """rules:
  - {effect: deny, agent: "bad*"}
  - {effect: allow}
  - {effect: deny, agent: x, namespace: locked}
""",
    "deny_after_allow": """rules:
  - {effect: allow, agent: "*"}
  - {effect: deny, agent: mallory}
  - {effect: allow, agent: mallory, namespace: public}
""",
    "last_allow_wins_for_rule": """rules:
  - {effect: allow, agent: "u*", ttl: 10}
  - {effect: allow, agent: "user", ttl: 20}
""",
    "case_sensitive": "- {effect: allow, agent: Alice, namespace: Prod, purpose: Deploy, action: Read}\n",
    "unicode": '- {effect: allow, agent: "agent-\u65e5*", namespace: "caf\u00e9", purpose: "*\U0001f510*"}\n',
    "classes": """rules:
  - {effect: allow, agent: "bot-[0-9][0-9]", namespace: "ns?", purpose: "*", action: "[rw]*"}
  - {effect: allow, agent: "[!a-c]*", namespace: "open", purpose: "*", action: read}
  - {effect: deny, agent: "bot-13"}
  - {effect: allow, agent: "x[]]y", namespace: "*", purpose: "*", action: "*"}
  - {effect: allow, agent: "br[ack", namespace: "*", purpose: "*", action: "*"}
""",
    "empty_rules": "rules: []\n",
    "dict_no_rules_key": "foo: bar\n",
    "scalar_policy": "just a string\n",
    "empty_policy": "",
    "ttl_order": """rules:
  - {effect: allow, agent: "*", action: read, ttl: 10}
  - {effect: allow, agent: bot, action: "*", ttl: 20}
  - {effect: allow, agent: bot, action: read, ttl: 30}
  - {effect: allow, action: write, ttl: 40}
  - {effect: allow, agent: "*", action: "*", ttl: 50}
  - {effect: allow, agent: floaty, action: read, ttl: 1.9}
  - {effect: allow, agent: booly, action: read, ttl: true}
  - {effect: allow, agent: strttl, action: read, ttl: "42"}
  - {effect: allow, agent: nullttl, action: read, ttl: null}
  - {effect: allow, agent: negttl, action: read, ttl: -5}
  - {effect: allow, agent: listttl, action: read, ttl: [1]}
""",
}


def eval_abac(policy_yaml: str, agent: str, namespace: str, purpose: str, action: str) -> Dict[str, Any]:
    eng = ABACPolicyEngine(policy_yaml)
    d = eng.evaluate(agent, namespace, purpose, action)
    idx = None
    if d["matched_rule"] is not None:
        idx = next(i for i, r in enumerate(eng.rules) if r is d["matched_rule"])
    return {
        "allowed": d["allowed"],
        "reason": d["reason"],
        "matched_rule_index": idx,
        "ttl": eng.get_lease_ttl(agent, action),
    }


def eval_ttl(policy_yaml: str, agent: str, action: str) -> int:
    return ABACPolicyEngine(policy_yaml).get_lease_ttl(agent, action)


def eval_policy_shape(case: Dict[str, Any]) -> Dict[str, Any]:
    if "yaml_generate" in case:
        g = case["yaml_generate"]
        text = g["prefix"] + g["fill"] * (g["length"] - len(g["prefix"]))
    else:
        text = case["yaml"]
    try:
        eng = ABACPolicyEngine(text)
    except Exception as e:
        return {"error": type(e).__name__}
    out: Dict[str, Any] = {"rules_count": None if eng.rules is None else len(eng.rules)}
    try:
        out["evaluate_read"] = {"allowed": eng.evaluate("a", "n", "p", "read")["allowed"]}
    except Exception as e:
        out["evaluate_read"] = {"raises": type(e).__name__}
    return out


def eval_fnmatch(value: str, pattern: str) -> bool:
    import fnmatch

    return fnmatch.fnmatchcase(value, pattern)


def build_abac() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []

    def c(policy: str, agent: str, ns: str, purpose: str, action: str, why: str = "") -> None:
        res = eval_abac(ABAC_POLICIES[policy], agent, ns, purpose, action)
        cases.append(
            {"policy": policy, "agent": agent, "namespace": ns, "purpose": purpose, "action": action, "why": why, **res}
        )

    # allow_all_list
    c("allow_all_list", "anyone", "any", "any", "read", "rule with only an effect matches everything")
    c("allow_all_list", "", "", "", "", "empty strings match the default '*'")
    # scoped
    c("scoped", "ci-bot", "prod/app", "deploy-now", "read", "rule 0 matches ('*' crosses '/' in namespace)")
    c("scoped", "ci-bot", "prod/app/deep/er", "deploy", "read", "'*' after prod/ matches nested slashes")
    c("scoped", "ci-bot", "prod", "deploy", "read", "rule 0 needs 'prod/' prefix; rule 1 (ci-bot, *) still allows")
    c("scoped", "ci-x", "prod/app", "deploy", "read", "ci-* matches ci-x")
    c("scoped", "ci-x", "prod/app", "deploy", "write", "wrong action for rule 0 -> denied")
    c("scoped", "ci-x", "staging", "deploy", "read", "wrong namespace -> denied")
    c("scoped", "ci-bot", "secret.db", "x", "read", "explicit deny overrides rule 1's allow")
    c("scoped", "ci-bot", "secret.", "x", "read", "deny pattern 'secret.*' matches 'secret.' (empty star)")
    c("scoped", "ci-bot", "secret", "x", "read", "'secret' does not match 'secret.*' -> allowed")
    c("scoped", "ops", "ab", "anything", "read", "[ab]? matches 'ab'; [!x]* matches 'anything'; re* matches read")
    c("scoped", "ops", "ba", "zzz", "revoke", "matches")
    c("scoped", "ops", "cb", "zzz", "read", "[ab] does not match 'c'")
    c("scoped", "ops", "ab", "xray", "read", "[!x]* fails for purpose starting with x")
    c("scoped", "ops", "a/", "zzz", "read", "'?' matches '/' (fnmatch has no path semantics)")
    c("scoped", "ops", "abc", "zzz", "read", "'[ab]?' is exactly two chars")
    c("scoped", "caseins", "n", "p", "a", "effect 'ALLOW' is lower-cased")
    c("scoped", "admin", "n", "p", "write", "ttl 'abc' is invalid -> 300")
    c("scoped", "ttl0", "n", "p", "read", "ttl 0 is clamped to 1")
    c("scoped", "noeffect", "n", "p", "read", "rule without an effect never allows")
    c("scoped", "emptyeffect", "n", "p", "read", "empty effect never allows")
    c("scoped", "unknowneffect", "n", "p", "read", "unknown effect never allows")
    c("scoped", "stranger", "n", "p", "read", "default deny")
    # purpose with '/'
    c("purpose_slash", "deployer", "ns", "deploy/prod", "read", "'*' crosses '/' in purpose")
    c("purpose_slash", "deployer", "ns", "deploy/prod/eu/west", "read", "multiple slashes")
    c("purpose_slash", "deployer", "ns", "deploy/", "read", "empty tail still matches")
    c("purpose_slash", "deployer", "ns", "deploy", "read", "needs the slash")
    c("purpose_slash", "single", "ns", "a/c", "read", "'?' matches '/'")
    c("purpose_slash", "single", "ns", "abc", "read", "")
    c("purpose_slash", "single", "ns", "a//c", "read", "'?' is exactly one char")
    c("purpose_slash", "classy", "ns", "rel5/notes", "read", "[0-9] then slash then star")
    c("purpose_slash", "classy", "ns", "relx/notes", "read", "")
    c("purpose_slash", "literal", "ns", "a/b/c", "read", "literal slashes")
    c("purpose_slash", "literal", "ns", "a/b/c/", "read", "no trailing wildcard")
    # deny precedence
    c("deny_precedence", "badguy", "ns", "p", "read", "deny listed first")
    c("deny_precedence", "good", "ns", "p", "read", "allow-all, no deny")
    c("deny_precedence", "x", "locked", "p", "read", "deny listed AFTER an allow-all still wins")
    c("deny_precedence", "x", "open", "p", "read", "")
    c("deny_after_allow", "mallory", "public", "p", "read", "deny beats later allow")
    c("deny_after_allow", "alice", "public", "p", "read", "")
    c("last_allow_wins_for_rule", "user", "n", "p", "read", "matched_rule is the LAST matching allow rule (index 1)")
    c("last_allow_wins_for_rule", "uxyz", "n", "p", "read", "only rule 0 matches")
    # case sensitivity / unicode
    c("case_sensitive", "Alice", "Prod", "Deploy", "Read", "exact case")
    c("case_sensitive", "alice", "Prod", "Deploy", "Read", "fnmatchcase: case-sensitive on every platform")
    c("case_sensitive", "Alice", "prod", "Deploy", "Read", "")
    c("unicode", "agent-\u65e5\u672c", "caf\u00e9", "use \U0001f510 now", "read", "unicode literal + star")
    c(
        "unicode",
        "agent-\u65e5\u672c",
        "cafe\u0301",
        "use \U0001f510 now",
        "read",
        "NFD namespace does not match NFC pattern",
    )
    c("unicode", "agent-x", "caf\u00e9", "\U0001f510", "read", "")
    # character classes and '?'
    c("classes", "bot-07", "ns1", "p", "write", "[0-9][0-9], ns? and [rw]*")
    c("classes", "bot-7", "ns1", "p", "write", "one digit is not enough")
    c("classes", "bot-07", "ns12", "p", "write", "ns? is exactly one char")
    c("classes", "bot-07", "ns1", "p", "execute", "[rw]* rejects 'e'")
    c("classes", "bot-13", "ns1", "p", "write", "explicit deny for bot-13 beats the allow")
    c("classes", "zed", "open", "p", "read", "[!a-c]* accepts z")
    c("classes", "alice", "open", "p", "read", "[!a-c]* rejects a")
    c("classes", "dave", "open", "p", "read", "[!a-c]* accepts d")
    c("classes", "x]y", "n", "p", "a", "[]] matches a literal ]")
    c("classes", "xy", "n", "p", "a", "[]] needs a character")
    c("classes", "br[ack", "n", "p", "a", "unterminated [ is a literal [")
    c("classes", "bra", "n", "p", "a", "so it is not a class")
    # shapes
    c("empty_rules", "a", "n", "p", "read", "no rules -> default deny")
    c("dict_no_rules_key", "a", "n", "p", "read", "dict without 'rules' -> no rules")
    c("scalar_policy", "a", "n", "p", "read", "scalar YAML -> no rules")
    c("empty_policy", "a", "n", "p", "read", "empty policy -> no rules")
    # newlines: '*' and '?' match newlines
    c("allow_all_list", "a\nb", "n\n", "\n", "read", "newline characters in values")
    c("purpose_slash", "deployer", "ns", "deploy/line1\nline2", "read", "'*' matches a newline")

    ttl_cases = []
    for agent, action in [
        ("bot", "read"),
        ("bot", "write"),
        ("bot", "delete"),
        ("other", "read"),
        ("other", "write"),
        ("other", "delete"),
        ("floaty", "read"),
        ("booly", "read"),
        ("strttl", "read"),
        ("nullttl", "read"),
        ("negttl", "read"),
        ("listttl", "read"),
    ]:
        ttl_cases.append(
            {
                "policy": "ttl_order",
                "agent": agent,
                "action": action,
                "ttl": eval_ttl(ABAC_POLICIES["ttl_order"], agent, action),
            }
        )

    shape_cases: List[Dict[str, Any]] = []
    for name, text in [
        ("list_form", "- effect: allow\n- effect: deny\n"),
        ("rules_form", "rules:\n  - effect: allow\n"),
        ("dict_without_rules", "a: 1\n"),
        ("rules_null", "rules:\n"),
        ("rules_list_of_scalars", "rules:\n  - 1\n  - two\n"),
        ("list_of_scalars", "- 1\n- two\n"),
        ("empty", ""),
        ("whitespace_only", "  \n\t\n"),
        ("scalar", "hello\n"),
        ("number", "42\n"),
        ("invalid_yaml", "rules: [unclosed\n"),
        ("tab_indent_invalid", "rules:\n\t- effect: allow\n"),
    ]:
        sc: Dict[str, Any] = {"name": name, "yaml": text}
        sc["expect"] = eval_policy_shape(sc)
        shape_cases.append(sc)
    for name, length in [("exactly_1MiB_comment", 1024 * 1024), ("1MiB_plus_1", 1024 * 1024 + 1)]:
        sc = {"name": name, "yaml_generate": {"prefix": "# ", "fill": "x", "length": length}}
        sc["expect"] = eval_policy_shape(sc)
        shape_cases.append(sc)

    fn_cases = []
    for value, pattern, why in [
        ("abc", "*", ""),
        ("", "*", "star matches empty"),
        ("a/b/c", "*", "star crosses /"),
        ("a/b/c", "a*c", ""),
        ("a/b", "a?b", "? matches /"),
        ("ab", "a?b", ""),
        ("a\nb", "a?b", "? matches newline"),
        ("a\nb", "a*b", "* matches newline"),
        ("abc", "a[bc]c", ""),
        ("abc", "a[!b]c", ""),
        ("axc", "a[!b]c", ""),
        ("a-c", "a[a-]c", "trailing - is literal"),
        ("abc", "a[a-c]c", ""),
        ("aBc", "a[a-c]c", "case-sensitive range"),
        ("a]c", "a[]]c", "] first in class is literal"),
        ("a]c", "a[!]]c", ""),
        ("axc", "a[!]]c", ""),
        ("a[c", "a[[]c", ""),
        ("a[c", "a[c", "unterminated [ is literal"),
        ("a[", "a[", ""),
        ("a^c", "a[^b]c", "^ at class start is literal in fnmatch"),
        ("abc", "a[^b]c", ""),
        ("a\\c", "a\\c", "backslash is literal, not an escape"),
        ("ac", "a\\c", ""),
        ("a*c", "a\\*c", "no escape mechanism: \\ then wildcard"),
        ("a.c", "a.c", "regex metachar . is literal"),
        ("abc", "a.c", ""),
        ("a+c", "a+c", ""),
        ("(x)", "(x)", ""),
        ("x{2}", "x{2}", ""),
        ("xx", "x{2}", ""),
        ("A", "a", "case-sensitive"),
        ("a", "A", ""),
        ("\u00e9", "\u00e9", ""),
        ("e\u0301", "\u00e9", "no normalisation"),
        ("\U0001f510", "?", "? matches one code point (astral)"),
        ("\U0001f510x", "?x", ""),
        ("deploy/prod", "deploy/*", ""),
        ("deploy", "deploy/*", ""),
        ("ab", "ab*", ""),
        ("abcabc", "*abc", ""),
        ("abcabd", "*abc", ""),
        ("", "", "empty pattern matches empty value"),
        ("x", "", ""),
        ("", "?", ""),
        ("aaa", "a*a*a", ""),
        ("aa", "a*a*a", ""),
        ("-", "[a-c-]", ""),
        ("b", "[a-c-]", ""),
        ("z", "[a-c-]", ""),
        ("5", "[0-9]", ""),
        ("a", "[0-9]", ""),
        ("5", "[!0-9]", ""),
        ("[", "[[]", ""),
        ("!", "[!]", ""),
        ("a", "[a", ""),
        ("[a", "[a", ""),
        ("**", "**", ""),
        ("a", "**", ""),
        ("/", "?", ""),
        ("//", "??", ""),
        ("a b", "a b", "spaces"),
        ("a b", "a?b", ""),
        ("tab\there", "tab?here", ""),
    ]:
        fn_cases.append({"value": value, "pattern": pattern, "why": why, "match": eval_fnmatch(value, pattern)})

    return {
        "description": "ABAC (rgt_vault.auth.ABACPolicyEngine). Matching is fnmatch.fnmatchcase on agent, namespace, purpose, "
        "action (missing rule attribute == '*'). '*' and '?' cross '/' and newlines. Explicit deny wins; otherwise the LAST "
        "matching allow rule is reported. effect is compared case-insensitively. 'ttl' = get_lease_ttl(agent, action) "
        "(default 300).",
        "policies": ABAC_POLICIES,
        "cases": cases,
        "ttl_cases": ttl_cases,
        "policy_shapes": shape_cases,
        "policy_max_bytes": 1024 * 1024,
    }, {
        "description": "Raw fnmatch.fnmatchcase(value, pattern) results from the generating Python ("
        + platform.python_version()
        + "). Only patterns whose "
        "meaning is stable across Python 3.9-3.13 are included.",
        "cases": fn_cases,
    }


# ---- input validation -----------------------------------------------------


def _enc_result(v: Any) -> Any:
    return enc_str(v) if isinstance(v, str) else v


VALIDATION_FNS = {
    "validate_name",
    "validate_namespace",
    "validate_agent",
    "validate_free_text",
    "normalize_unicode",
    "validate_int_bound",
    "string_param",
    "value_param",
}


def eval_validation(case: Dict[str, Any]) -> Dict[str, Any]:
    fn = case["fn"]
    args = [dec_arg(a) for a in case["args"]]
    res: Any
    if fn not in VALIDATION_FNS:
        raise LookupError(f"unknown validation fn {fn!r}")
    try:
        if fn == "validate_name":
            res = iv.validate_name(*args)
        elif fn == "validate_namespace":
            res = iv.validate_namespace(*args)
        elif fn == "validate_agent":
            res = iv.validate_agent(*args)
        elif fn == "validate_free_text":
            res = iv.validate_free_text(*args, **case.get("kwargs", {}))
        elif fn == "normalize_unicode":
            res = iv.normalize_unicode(*args)
        elif fn == "validate_int_bound":
            res = iv.validate_int_bound(*args, **case.get("kwargs", {}))
        elif fn == "string_param":
            # VaultManager._validate_string_param: unbound call, it uses no instance state.
            res = VaultManager._validate_string_param(None, *args, **case.get("kwargs", {}))  # type: ignore[arg-type]
        elif fn == "value_param":
            raw = bytes(VaultManager._normalize_value_param(None, *args))  # type: ignore[arg-type]
            # keep the vector file small: length + digest instead of up to 2 MiB of hex
            return {"ok": True, "result_len": len(raw), "result_sha256": hashlib.sha256(raw).hexdigest()}
        else:
            raise ValueError(fn)
    except Exception as e:
        return {"ok": False, "error": type(e).__name__, "message": str(e)}
    return {"ok": True, "result": _enc_result(res)}


def build_validation() -> Dict[str, Any]:
    cases: List[Dict[str, Any]] = []

    def add(fn: str, *args: Any, why: str = "", **kwargs: Any) -> None:
        case: Dict[str, Any] = {"fn": fn, "args": [enc_arg(a) for a in args], "why": why}
        if kwargs:
            case["kwargs"] = kwargs
        case["expect"] = eval_validation(case)
        cases.append(case)

    rep = lambda ch, n: {"type": "repeat", "char": ch, "count": n}  # noqa: E731

    for fn in ("validate_name", "validate_namespace", "validate_agent"):
        add(fn, "valid")
        add(fn, "with.dot-and_underscore9")
        add(fn, "UPPER_lower_123")
        add(fn, "a", why="single char")
        add(fn, "", why="empty")
        add(fn, "   ", why="whitespace only")
        add(fn, "a b", why="space: allowed in names only")
        add(fn, " lead", why="leading space")
        add(fn, "trail ", why="trailing space")
        add(fn, "a/b", why="slash")
        add(fn, "a\\b")
        add(fn, "a:b")
        add(fn, "a@b", why="@ allowed only in agent")
        add(fn, "a$b")
        add(fn, "a;b")
        add(fn, "a`b")
        add(fn, "a*b")
        add(fn, "a\x00b", why="NUL")
        add(fn, "a\tb")
        add(fn, "a\nb", why="newline in the middle")
        add(fn, "abc\n", why="TRAILING NEWLINE: Python's `$` matches before a final \\n, so this is ACCEPTED")
        add(fn, "abc\n\n", why="two trailing newlines are rejected")
        add(fn, "\nabc", why="leading newline rejected")
        add(fn, "caf\u00e9", why="non-ASCII letter")
        add(fn, "cafe\u0301", why="decomposed")
        add(fn, "\uff21\uff22", why="fullwidth letters are not [A-Za-z]")
        add(fn, "\u0661\u0662", why="Arabic-Indic digits are not [0-9]")
        add(fn, "\u65e5\u672c\u8a9e")
        add(fn, "\U0001f510")
        add(fn, "a\u00a0b", why="NBSP")
        add(fn, "\u00a0", why="NBSP only: strip() removes it -> empty")
        add(fn, "\u200b", why="zero width space")
        add(fn, rep("a", 128), why="128 chars")
        add(fn, rep("a", 129), why="129 chars")
        add(fn, rep("a", 256), why="256 chars")
        add(fn, rep("a", 257), why="257 chars")
        add(fn, None, why="None")
        add(fn, 5, why="int")
        add(fn, {"type": "bytes", "hex": "616263"}, why="bytes")
        add(fn, {"type": "list", "value": ["a"]}, why="list")
        add(fn, {"type": "bool", "value": True}, why="bool")
    add("validate_name", rep("a", 256), why="name max boundary")
    add("validate_name", rep("a", 257), why="name over by one")
    add("validate_namespace", rep("n", 128), why="namespace max boundary")
    add("validate_namespace", rep("n", 129), why="namespace over by one")
    add("validate_agent", rep("g", 128), why="agent max boundary")
    add("validate_agent", rep("g", 129), why="agent over by one")
    add("validate_agent", "user@host.example", why="agent with @")
    add("validate_agent", "@", why="only @")
    add("validate_name", "...", why="dots only")
    add("validate_name", "-", why="dash only")
    add("validate_name", "_x_", why="underscores")

    for text, kw, why in [
        ("plain text", {}, ""),
        ("", {}, "empty is allowed by validate_free_text itself"),
        ("caf\u00e9", {}, "already NFC"),
        ("cafe\u0301", {}, "NFD is normalised to NFC and returned composed"),
        ("A\u030a", {}, "A + combining ring -> U+00C5"),
        ("\u1e9b\u0323", {}, "NFC (not NFKC): U+1E9B U+0323 -> U+1E9B U+0323"),
        ("\ufb01", {}, "ligature stays under NFC"),
        ("\uff21", {}, "fullwidth A stays under NFC"),
        ("\u212b", {}, "ANGSTROM SIGN normalises to U+00C5"),
        ("\u2126", {}, "OHM SIGN normalises to U+03A9"),
        ("emoji \U0001f510 ok", {}, "So category"),
        ("\u65e5\u672c\u8a9e", {}, ""),
        ("with\nnewline", {}, "Cc rejected"),
        ("with\ttab", {}, "Cc rejected"),
        ("nul\x00", {}, "Cc rejected"),
        ("\x7f", {}, "DEL is Cc"),
        ("\x85", {}, "NEL is Cc"),
        ("zero\u200dwidth", {}, "ZWJ is Cf, rejected"),
        ("bom\ufeff", {}, "BOM is Cf, rejected"),
        ("rtl\u202eoverride", {}, "bidi override is Cf, rejected"),
        ("line\u2028sep", {}, "LINE SEPARATOR is Zl, rejected"),
        ("para\u2029sep", {}, "PARAGRAPH SEPARATOR is Zp, rejected"),
        ("nbsp\u00a0ok", {}, "NBSP is Zs, allowed"),
        ("em\u2003space", {}, "EM SPACE is Zs, allowed"),
        ("private\ue000use", {}, "Co rejected"),
        ("unassigned\u0378", {}, "Cn rejected"),
        ("a" * 512, {}, "max_len default 512"),
        ("a" * 513, {}, "513 > 512"),
        ("a" * 10, {"max_len": 10}, "boundary"),
        ("a" * 11, {"max_len": 10}, "over boundary"),
        ("e\u0301" * 5, {"max_len": 5}, "length is measured AFTER normalisation (5 code points)"),
        ("\u212b" * 6, {"max_len": 5}, "post-normalisation length still 6"),
        ("\u0007bell", {}, "BEL"),
        ("tab\u00adsoft-hyphen", {}, "U+00AD is Cf, rejected"),
    ]:
        add("validate_free_text", text, why=why, **kw)
    add("validate_free_text", {"type": "cps", "cps": [0xD800]}, why="lone surrogate is Cs, rejected")
    add("validate_free_text", {"type": "cps", "cps": [0x61, 0xDC00, 0x62]}, why="lone low surrogate")
    add("validate_free_text", None, why="None")
    add("validate_free_text", 5, why="int")
    add("normalize_unicode", "cafe\u0301")
    add("normalize_unicode", "a\x01")
    add("normalize_unicode", 5)

    for args, kw, why in [
        (("limit", 10), {"min_val": 1, "max_val": 100}, ""),
        (("limit", 1), {"min_val": 1, "max_val": 100}, "min boundary"),
        (("limit", 100), {"min_val": 1, "max_val": 100}, "max boundary"),
        (("limit", 0), {"min_val": 1, "max_val": 100}, "below"),
        (("limit", 101), {"min_val": 1, "max_val": 100}, "above"),
        (("limit", -5), {"min_val": 0}, ""),
        (("limit", 5), {}, "no bounds"),
        (("limit", {"type": "bool", "value": True}), {"min_val": 0}, "bool rejected although it subclasses int"),
        (("limit", {"type": "float", "value": 5.0}), {}, "float rejected"),
        (("limit", "5"), {}, "string rejected"),
        (("limit", None), {}, ""),
        (("limit", 10**30), {"max_val": 100}, "huge"),
        (("limit", -(10**30)), {"min_val": 0}, "huge negative"),
    ]:
        add("validate_int_bound", *args, why=why, **kw)

    # VaultManager._validate_string_param(param_name, value, max_len, allow_empty=False)
    for name_, val, max_len, allow_empty, why in [
        ("name", "ok", 256, False, ""),
        ("name", "", 256, False, "empty"),
        ("name", "   ", 256, False, "whitespace"),
        ("name", "\u00a0", 256, False, "strip() removes NBSP"),
        ("name", "x" * 257, 256, False, "length check before regex"),
        ("name", "bad/name", 256, False, "regex"),
        ("name", "abc\n", 256, False, "trailing newline accepted"),
        ("name", 5, 256, False, "not a string"),
        ("namespace", "ns.ok", 128, False, ""),
        ("namespace", "a b", 128, False, "space not allowed in namespace"),
        ("namespace", "x" * 129, 128, False, ""),
        ("agent", "bot@host", 128, False, ""),
        ("agent", "bad agent", 128, False, ""),
        ("note", "", 512, True, "empty note allowed"),
        ("note", "a note \u2713", 512, True, ""),
        ("note", "bad\nnote", 512, True, "Cc rejected"),
        ("note", "x" * 513, 512, True, "len check"),
        ("note", "   ", 512, True, "whitespace note allowed (allow_empty) then free-text ok"),
        ("purpose", "deploy/prod", 256, False, "purpose is free text: '/' is fine"),
        ("purpose", "", 256, False, "purpose empty rejected when allow_empty is False"),
        ("purpose", "tab\there", 256, False, ""),
        ("purpose", "x" * 257, 256, False, ""),
        (
            "other",
            "anything goes \x00",
            10,
            True,
            "unknown param names skip the regex layer (only the length is checked)",
        ),
    ]:
        add("string_param", name_, val, max_len, why=why, allow_empty=allow_empty)

    # VaultManager._normalize_value_param(param_name, value, max_len) -> bytes (vector stores len + sha256)
    mib = 1024 * 1024
    for val, why in [
        ("secret", "str"),
        ({"type": "bytes", "hex": "736563726574"}, "bytes"),
        ("", "empty"),
        ("   ", "spaces only"),
        (" \t\r\n", "ascii whitespace only"),
        ({"type": "bytes", "hex": "0b0c"}, "VT/FF only: bytes.strip() strips them"),
        ({"type": "bytes", "hex": "00"}, "NUL is not whitespace"),
        (
            {"type": "bytes", "hex": "c2a0"},
            "NBSP (UTF-8) is NOT stripped by bytes.strip(): accepted (Go bytes.TrimSpace WOULD trim it)",
        ),
        ({"type": "bytes", "hex": "e28083"}, "EM SPACE: accepted"),
        ({"type": "bytes", "hex": "c285"}, "NEL (UTF-8): accepted"),
        ({"type": "bytes", "hex": "20612020"}, "padded value is stored verbatim"),
        ({"type": "repeat", "char": "a", "count": mib}, "exactly 1 MiB"),
        ({"type": "repeat", "char": "a", "count": mib + 1}, "1 MiB + 1 byte"),
        ({"type": "repeat", "char": "\u00e9", "count": mib // 2}, "1 MiB of 2-byte chars"),
        ({"type": "repeat", "char": "\u00e9", "count": mib // 2 + 1}, "over 1 MiB in UTF-8 bytes"),
        (5, "int"),
        (None, "None"),
    ]:
        vcase: Dict[str, Any] = {"fn": "value_param", "args": ["value", enc_arg(val), mib], "why": why}
        vcase["expect"] = eval_validation(vcase)
        cases.append(vcase)

    return {
        "description": "rgt_vault.input_validation + VaultManager._validate_string_param/_normalize_value_param. "
        "Inputs: plain JSON strings/integers, or typed objects {type: cps|repeat|bytes|null|bool|float|list,...}. 'expect' is the real Python "
        "result. Error messages are informational; compare ok/error and the normalised result.",
        "cases": cases,
    }


def enc_arg(v: Any) -> Any:
    if isinstance(v, str):
        return enc_str(v)
    if v is None:
        return {"type": "null"}
    return v


# ---- timestamps -----------------------------------------------------------


def eval_isoformat(case: Dict[str, Any]) -> str:
    return datetime(
        case["year"],
        case["month"],
        case["day"],
        case["hour"],
        case["minute"],
        case["second"],
        case["microsecond"],
        tzinfo=timezone.utc,
    ).isoformat()


def build_timestamps() -> Dict[str, Any]:
    cases = []
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    for y, mo, d, h, mi, s, us in [
        (2026, 1, 15, 10, 20, 30, 123456),
        (2026, 1, 15, 10, 20, 31, 0),
        (2026, 1, 15, 10, 20, 32, 1),
        (2026, 1, 15, 10, 20, 33, 100000),
        (2026, 1, 15, 10, 20, 33, 10),
        (2026, 12, 31, 23, 59, 59, 999999),
        (1970, 1, 1, 0, 0, 0, 0),
        (1970, 1, 1, 0, 0, 0, 1),
        (2000, 2, 29, 12, 0, 0, 0),
        (2024, 2, 29, 23, 59, 59, 500000),
        (2038, 1, 19, 3, 14, 8, 0),
        (2100, 1, 1, 0, 0, 0, 0),
        (9999, 12, 31, 23, 59, 59, 999999),
        (1, 1, 1, 0, 0, 0, 0),
        (999, 3, 4, 5, 6, 7, 8),
        (2026, 6, 1, 0, 0, 0, 120000),
    ]:
        c = {"year": y, "month": mo, "day": d, "hour": h, "minute": mi, "second": s, "microsecond": us}
        dt = datetime(y, mo, d, h, mi, s, us, tzinfo=timezone.utc)
        cases.append(
            {
                **c,
                "unix_micro": (dt - epoch) // timedelta(microseconds=1),
                "isoformat": eval_isoformat(c),
            }
        )
    return {
        "description": "datetime(..., tzinfo=timezone.utc).isoformat() as used for audit_logs.timestamp and keychain created_at. "
        "'+00:00' (never 'Z'); a fractional part of exactly 6 digits when microsecond != 0 and NO fractional part at all when "
        "microsecond == 0; year zero-padded to 4 digits.",
        "cases": cases,
    }


# ---- audit hash vectors (real log_audit) -----------------------------------

AUDIT_VECTOR_ROWS = EDGE_ROWS + [
    ("A", None, "", "", None),
    ("X" * 200, "n" * 300, "d" * 2000, "p" * 16, "agent"),
    ("CRLF\r\nINJECT", "s\r\nname", "line1\r\nline2\r\n\r\n\ttab\t\ttab2", "0123456789abcdef", None),
    ("UNI", "\u00e9\u65e5", "\U0001f510 \u2014 \u0001ctl", "0123456789abcdef", None),
]


def eval_audit_chain(
    rows: List[Tuple[str, Optional[str], str, str, Optional[str]]], stamps: List[str]
) -> List[Dict[str, Any]]:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "audit.db"
        sb = StorageBackend(path)
        it = iter(stamps)
        with mock.patch.object(sqlite_mod, "_utcnow_iso", side_effect=lambda: next(it)):
            for action, name, details, ph, agent in rows:
                sb.log_audit(action, name, details, ph, agent_id=agent)
        out = audit_rows(path)
        finalize_db(path)
    return out


def eval_sanitize(s: str) -> str:
    return sqlite_mod._sanitize_log_field(s)


def build_audit_vectors() -> Dict[str, Any]:
    stamps = (EDGE_TS * 3)[: len(AUDIT_VECTOR_ROWS)]
    rows = eval_audit_chain(AUDIT_VECTOR_ROWS, stamps)
    chain = []
    for spec, stamp, r in zip(AUDIT_VECTOR_ROWS, stamps, rows):
        chain.append(
            {
                "input": {
                    "action": enc_str(spec[0]),
                    "secret_name": spec[1],
                    "details": enc_str(spec[2]),
                    "policy_hash": spec[3],
                    "agent_id": spec[4],
                    "timestamp": stamp,
                },
                "stored": {
                    k: r[k]
                    for k in (
                        "action",
                        "secret_name",
                        "timestamp",
                        "details",
                        "prev_hash",
                        "entry_hash",
                        "policy_hash",
                        "agent_id",
                    )
                },
            }
        )
    sanitize = [
        {"input": s, "output": eval_sanitize(s)}
        for s in [
            "",
            "plain",
            "a\nb",
            "a\r\nb",
            "a\tb",
            "\r\n\t",
            "\\n literal backslash-n",
            "\x00\x0b\x1b\x7f",
            "\u2028\u2029\u0085",
            "\u00e9\u65e5\U0001f510",
            "mixed\r\nline\tbreaks\n",
        ]
    ]
    return {
        "description": "Real StorageBackend.log_audit output for a chain of rows with an injected clock. entry_hash = sha256_hex("
        "'prev|timestamp|sanitized_action|secret_name or ''|sanitized_details|policy_hash'); the first prev is ''. "
        "sanitize replaces \\r \\n \\t (in that order) by the two-character escapes; nothing else is touched. "
        "agent_id is stored but not hashed.",
        "chain": chain,
        "sanitize": sanitize,
    }


# ---- keychain wrap vectors (real HardenedDEKManager, patched randomness) ---


class _OsWithFixedUrandom:
    """Proxy for the ``os`` module whose ``urandom`` returns the given byte strings in order."""

    def __init__(self, values: List[bytes]) -> None:
        self._values = list(values)

    def urandom(self, n: int) -> bytes:
        v = self._values.pop(0)
        assert len(v) == n, f"urandom({n}) asked, fixture has {len(v)} bytes"
        return v

    def __getattr__(self, name: str) -> Any:
        return getattr(os, name)


def eval_keychain(case: Dict[str, Any]) -> Dict[str, Any]:
    dek = bytes.fromhex(case["dek_hex"])
    salt = bytes.fromhex(case["salt_hex"])
    master = bytes.fromhex(case["master_hex"])
    fixed_now = datetime(2026, 1, 15, 10, 20, 30, 123456, tzinfo=timezone.utc)

    class _FixedDatetime(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> Any:
            return fixed_now

    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "keychain.json")
        mgr = HardenedDEKManager(path)
        # Patch only keychain_mod's view of `os` / `datetime` (not the process-global modules).
        with mock.patch.object(keychain_mod, "os", _OsWithFixedUrandom([dek, salt])):
            with mock.patch.object(keychain_mod, "datetime", _FixedDatetime):
                got = mgr.initialize_dek(
                    MasterSecret(master),
                    case["vault_id"],
                    case["epoch"],
                    case["memory_cost"],
                    case["time_cost"],
                    case["parallelism"],
                )
        assert got == dek
        text = Path(path).read_text(encoding="utf-8")
        loaded = HardenedDEKManager(path).load_dek(MasterSecret(master), case["vault_id"], case["epoch"])
        assert loaded == dek
    orch = KeyDerivationOrchestrator(case["memory_cost"], case["time_cost"], case["parallelism"])
    km = orch.derive_wrapping_key_and_nonce(MasterSecret(master), salt, f"rgt-vault:{case['vault_id']}".encode())
    return {
        "kek_hex": km.key.hex(),
        "nonce_hex": km.nonce.hex(),
        "aad": f"{case['vault_id']}:{case['epoch']}",
        "binding_context": f"rgt-vault:{case['vault_id']}",
        "keychain_json": text,
    }


def build_keychain() -> Dict[str, Any]:
    cases = []
    for name, vault_id, epoch, params, label in [
        ("small_epoch1", VAULT_IDS["small"], 1, (SMALL_MEMORY, SMALL_TIME, SMALL_PARALLELISM), "kc-a"),
        ("small_epoch7", VAULT_IDS["epoch1"], 7, (1024, 1, 1), "kc-b"),
        ("small_p3", "11111111-2222-4333-8444-555555555555", 2, (2048, 3, 3), "kc-c"),
        ("default_params", VAULT_IDS["default"], 2, DEFAULT_PARAMS, "kc-d"),
    ]:
        case = {
            "name": name,
            "vault_id": vault_id,
            "epoch": epoch,
            "memory_cost": params[0],
            "time_cost": params[1],
            "parallelism": params[2],
            "master_hex": hashlib.sha256(f"g0-keychain-master|{label}".encode()).hexdigest(),
            "dek_hex": hashlib.sha256(f"g0-keychain-dek|{label}".encode()).hexdigest(),
            "salt_hex": hashlib.sha256(f"g0-keychain-salt|{label}".encode()).hexdigest(),
        }
        cases.append({**case, **eval_keychain(case)})
    return {
        "description": "Real HardenedDEKManager.initialize_dek with os.urandom (dek, salt) and the clock pinned. "
        "wrapped_dek in keychain_json = AES-256-GCM(kek, nonce, dek, aad) = ciphertext||tag WITHOUT the nonce (the nonce is the "
        "KDF output nonce_hex and is NOT stored). kek = HKDF chain: argon2id(master, salt, 32) -> HKDF-SHA512(info=binding, 64) "
        "-> kek=first 32, nonce=HKDF-SHA256(last 32, info='nonce expansion', 12). Masters/DEKs are FIXED TEST VALUES.",
        "cases": cases,
    }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def build_vectors(out: Path) -> None:
    v = out / "vectors"
    write_json(v / "tokens_v2.json", build_tokens_v2())
    write_json(v / "tokens_v1.json", build_tokens_v1())
    write_json(v / "totp.json", build_totp())
    abac, fn = build_abac()
    write_json(v / "abac.json", abac)
    write_json(v / "fnmatch.json", fn)
    write_json(v / "validation.json", build_validation())
    write_json(v / "timestamps.json", build_timestamps())
    write_json(v / "audit_vectors.json", build_audit_vectors())
    write_json(v / "keychain_wrap.json", build_keychain())


TARGETS: Dict[str, Callable[[Path, Path], None]] = {
    "small": build_small,
    "default": build_default,
    "epoch1": build_epoch1,
    "edge": build_edge,
}
ALL_TARGETS = list(TARGETS) + ["vectors"]


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output directory (default: go/testdata/pyvault)")
    ap.add_argument(
        "--only", default=",".join(ALL_TARGETS), help=f"comma separated subset of: {', '.join(ALL_TARGETS)}"
    )
    args = ap.parse_args(argv)
    wanted = [t.strip() for t in args.only.split(",") if t.strip()]
    unknown = [t for t in wanted if t not in ALL_TARGETS]
    if unknown:
        ap.error(f"unknown target(s): {unknown}")
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rgt-g0-") as td:
        for t in wanted:
            print(f"[g0] building {t} ...", flush=True)
            dest = out / t
            if t == "vectors":
                if (out / "vectors").exists():
                    shutil.rmtree(out / "vectors")
                build_vectors(out)
                continue
            if dest.exists():
                shutil.rmtree(dest)
            TARGETS[t](dest, Path(td) / t)
    print(f"[g0] done -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
