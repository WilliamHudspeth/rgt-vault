"""Prove the committed Go compatibility fixtures are valid.

Every fixture under ``go/testdata/pyvault`` is re-opened / re-evaluated with the REAL Python code and compared with
the committed manifest or vector file. A failure means either the fixtures were edited by hand or Python's
behaviour (the reference the Go port mirrors) drifted since they were generated.

Nothing here writes into the committed tree: vaults are copied to a temp dir first, because opening a vault
appends audit rows.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import shutil
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet

from rgt_vault.crypto import decrypt
from rgt_vault.exceptions import SecretNotFoundError
from rgt_vault.providers.base import MasterSecretProvider
from rgt_vault.storage.sqlite import StorageBackend
from rgt_vault.vault import VaultManager

FIXTURES = Path(__file__).resolve().parents[2] / "go" / "testdata" / "pyvault"


def _load_generator() -> Any:
    path = Path(__file__).with_name("gen_go_fixtures.py")
    spec = importlib.util.spec_from_file_location("gen_go_fixtures", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gen_go_fixtures"] = mod
    spec.loader.exec_module(mod)
    return mod


gen = _load_generator()


def _load(rel: str) -> Any:
    with open(FIXTURES / rel, encoding="utf-8") as f:
        return json.load(f)


def _norm(x: Any) -> Any:
    """Drop informational error messages before comparing expectations."""
    if isinstance(x, dict):
        return {k: _norm(v) for k, v in x.items() if k != "message"}
    if isinstance(x, list):
        return [_norm(v) for v in x]
    return x


def _check(cases: List[Dict[str, Any]], evaluate: Callable[[Dict[str, Any]], Any], key: str = "expect") -> None:
    assert cases, "empty vector list: the check would pass vacuously"
    bad = []
    for i, c in enumerate(cases):
        got = _norm(evaluate(c))
        want = _norm(c[key])
        if got != want:
            bad.append(f"[{i}] {c.get('name', c.get('why', ''))}: expected {want!r}, python now gives {got!r}")
    assert not bad, f"{len(bad)}/{len(cases)} vectors differ:\n" + "\n".join(bad[:10])


class FixedProvider(MasterSecretProvider):
    def __init__(self, master: bytes) -> None:
        self._master = master

    def get_secret(self) -> bytes:
        return self._master

    def rotate_secret(self) -> bytes:  # pragma: no cover - never called here
        raise NotImplementedError


def _copy_vault(name: str, tmp_path: Path) -> Path:
    dst = tmp_path / name
    shutil.copytree(FIXTURES / name, dst)
    return dst


def _count(db: Path, table: str) -> int:
    conn = sqlite3.connect(db)
    try:
        return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])  # noqa: S608 - fixed table names
    finally:
        conn.close()


def _open(d: Path) -> VaultManager:
    master = (d / "master.bin").read_bytes()
    policy = (d / "policy.yaml").read_text(encoding="utf-8")
    return VaultManager(db_path=str(d / "vault.db"), master_provider=FixedProvider(master), policy_yaml=policy)


# ---------------------------------------------------------------------------
# Vaults
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["small", "default", "epoch1"])
def test_vault_fixture_opens_and_matches_manifest(name: str, tmp_path: Path) -> None:
    d = _copy_vault(name, tmp_path)
    m = _load(f"{name}/manifest.json")
    db = d / "vault.db"

    assert not list(d.glob("*-wal")) and not list(d.glob("*-shm")), "fixture must be a single self-contained db file"
    assert len((d / "master.bin").read_bytes()) == 32
    assert json.loads((d / "keychain.json").read_text(encoding="utf-8")) == m["keychain"]
    assert (d / "master.bin").read_bytes().hex() == m["master_hex"]
    # tolerate a CRLF checkout (.gitattributes pins -text, but be robust): the policy text itself is LF
    policy_bytes = (d / "policy.yaml").read_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha256(policy_bytes).hexdigest()[:16] == m["policy_hash"]
    if name == "default":
        k = m["keychain"]
        assert (k["argon2_memory_cost"], k["argon2_time_cost"], k["argon2_parallelism"]) == gen.DEFAULT_PARAMS
    else:
        k = m["keychain"]
        assert (k["argon2_memory_cost"], k["argon2_time_cost"], k["argon2_parallelism"]) == (
            gen.SMALL_MEMORY,
            gen.SMALL_TIME,
            gen.SMALL_PARALLELISM,
        )

    # Row counts straight from SQL, before the vault opens (opening/reading appends audit rows).
    counts = m["row_counts"]
    assert _count(db, "secrets") == counts["secrets"]
    assert _count(db, "audit_logs") == counts["audit_logs"]
    assert _count(db, "honeytokens") == counts["honeytokens"]
    conn = sqlite3.connect(db)
    try:
        meta = {k: v for k, v in conn.execute("SELECT key, value FROM metadata")}
        versions = [r[0] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]
    finally:
        conn.close()
    assert meta == m["metadata"]
    assert versions == m["migrations_applied"] == [1, 2, 3, 4, 5]

    vm = _open(d)
    assert vm.vault_id == m["vault_id"] == gen.VAULT_IDS[name]
    assert vm.key_epoch == m["key_epoch"]
    assert vm.dek.hex() == m["dek_hex"]
    assert vm.policy_hash == m["policy_hash"]
    assert vm.verify_audit_chain() is m["audit"]["verify_audit_chain"] is True
    assert vm.storage.audit_log_count() == counts["audit_logs"]

    export = (d / "export.b64").read_bytes()
    assert hashlib.sha256(export).hexdigest() == m["export"]["sha256"]
    exported = json.loads(base64.b64decode(export))
    assert exported["vault_id"] == m["vault_id"]
    assert (len(exported["secrets"]), len(exported["audit_logs"]), len(exported["honeytokens"])) == (
        m["export"]["secrets"],
        m["export"]["audit_logs"],
        m["export"]["honeytokens"],
    )

    # Every stored version: checksum, fingerprint, decryption (or the documented failure), plaintext.
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        rows = {(r["namespace"], r["name"], r["version"]): dict(r) for r in conn.execute("SELECT * FROM secrets")}
    finally:
        conn.close()
    assert set(rows) == {(s["namespace"], s["name"], s["version"]) for s in m["secrets"]}
    for s in m["secrets"]:
        key = (s["namespace"], s["name"], s["version"])
        r = rows[key]
        assert r["id"] == s["id"] and r["secret_id"] == s["secret_id"]
        assert r["status"] == s["status"] and r["dek_version"] == s["dek_version"] == 1
        assert r["note"] == s["note"] and bool(r["require_2fa"]) is s["require_2fa"]
        assert hashlib.sha256(r["ciphertext"]).hexdigest() == r["checksum"] == s["checksum"]
        assert len(r["ciphertext"]) == s["ciphertext_len"]
        aad = s["aad"].encode()
        assert aad == f"{vm.vault_id}:{s['namespace']}:{s['name']}".encode()
        if s["decrypts_with_current_dek"]:
            pt = decrypt(r["ciphertext"], vm.dek, aad)
            assert hashlib.sha256(pt).hexdigest() == s["plaintext_sha256"]
            assert len(pt) == s["plaintext_len_bytes"]
            if "plaintext" in s:
                assert pt.decode("utf-8") == s["plaintext"]
            else:
                assert pt.decode("utf-8") == gen.big_value()
        else:
            assert s["read_by_version"] == "DecryptionError"
            with pytest.raises(Exception) as ei:
                decrypt(r["ciphertext"], vm.dek, aad)
            assert type(ei.value).__name__ == "DecryptionError"

    # Public read-by-version API (ignores status; honeytoken check first; decrypt needs the CURRENT dek).
    for s in m["secrets"]:
        outcome = "ok"
        try:
            with vm.lease_secret(s["name"], "ci-bot", s["namespace"], "by-version", version=s["version"]) as buf:
                assert hashlib.sha256(bytes(buf)).hexdigest() == s["plaintext_sha256"]
        except Exception as e:
            outcome = type(e).__name__
        assert outcome == s["read_by_version"], (s["namespace"], s["name"], s["version"], outcome)

    # Public API semantics recorded in the manifest.
    seen_active = 0
    for s in m["secrets"]:
        if s["read_latest"] is None:
            continue
        ns, nm = s["namespace"], s["name"]
        if s["read_latest"] == "ok":
            seen_active += 1
            with vm.lease_secret(nm, "ci-bot", ns, "selfcheck") as buf:
                leased = bytes(buf)
            assert hashlib.sha256(leased).hexdigest() == s["plaintext_sha256"]
            assert vm.get_fingerprint(nm, ns) == s["fingerprint"]
        elif s["read_latest"] == "PermissionError":
            with pytest.raises(PermissionError):
                with vm.lease_secret(nm, "ci-bot", ns, "selfcheck"):
                    pass
        else:
            assert s["read_latest"] == "SecretNotFoundError"
            with pytest.raises(SecretNotFoundError):
                with vm.lease_secret(nm, "ci-bot", ns, "selfcheck"):
                    pass
    assert seen_active == counts["secrets_active"] - len(m["honeytokens"])

    namespaces = {s["namespace"] for s in m["secrets"]}
    for ns in namespaces:
        listed = vm.list_secrets(ns, "ci-bot")
        expect_active = [s for s in m["secrets"] if s["namespace"] == ns and s["status"] == "ACTIVE"]
        assert sorted(x["name"] for x in listed) == sorted(s["name"] for s in expect_active)
        for x in listed:
            want = next(s for s in expect_active if s["name"] == x["name"])
            assert x["note"] == want["note"] and x["require_2fa"] is want["require_2fa"]

    # The vault still works after opening: the audit chain keeps verifying after the reads above.
    assert vm.verify_audit_chain() is True

    # export.b64 round-trips: importing it back restores the manifest state (+1 IMPORT audit row).
    vm.import_vault(export)
    assert _count(db, "secrets") == counts["secrets"]
    assert _count(db, "audit_logs") == counts["audit_logs"] + 1
    assert vm.verify_audit_chain() is True
    for s in m["secrets"]:
        if s["decrypts_with_current_dek"] and s["status"] == "ACTIVE" and not s["honeytoken"]:
            with vm.lease_secret(s["name"], "ci-bot", s["namespace"], "post-import") as buf:
                assert hashlib.sha256(bytes(buf)).hexdigest() == s["plaintext_sha256"]
            break
    else:
        pytest.fail("no active non-honeytoken secret was verified after the import")


def test_epoch_rollback_and_wrong_master_are_detected(tmp_path: Path) -> None:
    small = _copy_vault("small", tmp_path)
    # keychain from the epoch-1 vault into the epoch-3 db: DB epoch 3 != keychain epoch 1
    shutil.copyfile(FIXTURES / "epoch1" / "keychain.json", small / "keychain.json")
    with pytest.raises(ValueError, match="Rollback attack detected"):
        _open(small)

    e1 = _copy_vault("epoch1", tmp_path)
    (e1 / "master.bin").write_bytes(bytes(32))
    with pytest.raises(InvalidTag):
        _open(e1)


def test_vault_dirs_have_no_stray_files() -> None:
    for name in ("small", "default", "epoch1"):
        files = sorted(p.name for p in (FIXTURES / name).iterdir())
        assert files == ["export.b64", "keychain.json", "manifest.json", "master.bin", "policy.yaml", "vault.db"], name


# ---------------------------------------------------------------------------
# Audit-chain edge databases
# ---------------------------------------------------------------------------


def test_edge_databases(tmp_path: Path) -> None:
    manifest = _load("edge/manifest.json")
    dbs = manifest["databases"]
    assert any(d["kind"] == "legacy" for d in dbs), "legacy_dek0 fixture missing"
    assert {d["file"] for d in dbs} == {p.name for p in (FIXTURES / "edge").glob("*.db")}
    verdicts = {}
    for d in dbs:
        path = tmp_path / d["file"]
        shutil.copyfile(FIXTURES / "edge" / d["file"], path)
        verdicts[d["file"]] = d["verify_audit_chain"]
        assert gen.python_verify(path) is d["verify_audit_chain"], d["file"]
        rows = gen.audit_rows(path)
        assert gen.first_bad_index(rows) == d["first_bad_index"], d["file"]
        assert len(rows) == d["row_count"] == len(d["rows"])
        prev = ""
        for stored, want in zip(rows, d["rows"]):
            assert {**stored, "expected_hash": gen.verifier_expected(prev, stored)} == want, d["file"]
            prev = stored["entry_hash"] or ""
        if d["kind"] == "legacy":
            conn = sqlite3.connect(path)
            try:
                ct, ver = conn.execute("SELECT ciphertext, dek_version FROM secrets").fetchone()
            finally:
                conn.close()
            assert ver == 0
            assert Fernet(d["fernet_key"].encode()).decrypt(ct).decode() == d["legacy_plaintext"]
    # the documented quirks
    assert verdicts["null_details_policy_ok.db"] is True
    assert verdicts["null_details_hashed_empty.db"] is False
    assert verdicts["agent_id_not_hashed.db"] is True
    assert verdicts["empty.db"] is True
    assert not any(verdicts[n] for n in ("tampered_details.db", "tampered_entry_hash.db", "deleted_middle.db"))


def test_null_rows_really_are_null(tmp_path: Path) -> None:
    path = tmp_path / "n.db"
    shutil.copyfile(FIXTURES / "edge" / "null_details_policy_ok.db", path)
    rows = gen.audit_rows(path)
    assert sum(r["details"] is None for r in rows) == 2
    assert sum(r["policy_hash"] is None for r in rows) == 2
    assert sum(r["secret_name"] is None for r in rows) >= 1
    # The storage layer itself never produces NULL details/policy_hash.
    sb = StorageBackend(path)
    assert isinstance(sb.last_audit_hash(), str)


# ---------------------------------------------------------------------------
# Vector files
# ---------------------------------------------------------------------------


def test_tokens_v2() -> None:
    v = _load("vectors/tokens_v2.json")
    assert v["key_hex"] == gen.V2_KEY.hex()
    _check(v["verify"], lambda c: gen.eval_v2_verify(c.get("key_hex", v["key_hex"]), c["token"], c["now"]))
    _check(v["sign"], lambda c: gen.eval_v2_sign(v["key_hex"], c), key="expected_token")
    errs = []
    for c in v["sign_errors"]:
        try:
            gen.eval_v2_sign(v["key_hex"], c)
        except Exception as e:
            errs.append(type(e).__name__ == c["error"])
        else:
            errs.append(False)
    assert errs and all(errs)
    _check(v["check_context"], lambda c: gen.eval_check_context(c["bindings"], c["context"]))
    assert v["is_expired"]
    for c in v["is_expired"]:
        assert gen.eval_is_expired(c["exp"], c["now"]) is c["expired"]
    _check(v["hook_v2"]["cases"], lambda c: gen.eval_hook(v["hook_v2"]["key_hex"], c["now"], c["requests"]))
    # every valid token's payload_json is exactly what the token carries
    checked = 0
    for c in v["verify"]:
        if "payload_json" in c:
            checked += 1
            body = c["token"].split(".")[0]
            assert base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("ascii") == c["payload_json"]
    assert checked >= 10


def test_tokens_v1() -> None:
    v = _load("vectors/tokens_v1.json")
    assert v["key_hex"] == gen.V1_KEY.hex()
    _check(v["cases"], lambda c: gen.eval_hook(v["key_hex"], c["now"], c["requests"]))
    # TwoFactorHook.issue().to_compact() is signed with the EMPTY key -> never verifies under the shared secret.
    case = next(c for c in v["cases"] if c["name"] == "issue_to_compact_is_signed_with_empty_key")
    assert case["expect"][0]["decision"] == "deny"
    assert case["requests"][0]["token"] == v["issue_to_compact_token"]


def test_totp() -> None:
    v = _load("vectors/totp.json")
    assert len(v["rfc6238"]) == 18
    for c in v["rfc6238"]:
        assert gen.eval_totp_generate(c) == c["code"]
        assert c["secret_ascii"].encode() == base64.b32decode(c["secret"] + "=" * (-len(c["secret"]) % 8))
    _check(v["generate"], lambda c: gen.eval_totp_generate(c), key="code")
    _check(v["verify"], gen.eval_totp_verify)
    _check(v["replay_guard"], gen.eval_totp_replay)
    _check(v["provisioning_uri"], gen.eval_totp_uri, key="uri")


def test_abac_and_fnmatch() -> None:
    v = _load("vectors/abac.json")
    assert v["policies"] == gen.ABAC_POLICIES
    assert len(v["cases"]) >= 60
    bad = []
    for i, c in enumerate(v["cases"]):
        got = gen.eval_abac(v["policies"][c["policy"]], c["agent"], c["namespace"], c["purpose"], c["action"])
        want = {k: c[k] for k in ("allowed", "reason", "matched_rule_index", "ttl")}
        if got != want:
            bad.append(
                f"[{i}] {c['policy']} {c['agent']}/{c['namespace']}/{c['purpose']}/{c['action']}: {want} != {got}"
            )
    assert not bad, "\n".join(bad[:10])
    assert v["ttl_cases"]
    for c in v["ttl_cases"]:
        assert gen.eval_ttl(v["policies"][c["policy"]], c["agent"], c["action"]) == c["ttl"], c
    _check(v["policy_shapes"], gen.eval_policy_shape)
    assert v["policy_max_bytes"] == 1024 * 1024

    f = _load("vectors/fnmatch.json")
    assert len(f["cases"]) >= 50
    for c in f["cases"]:
        assert gen.eval_fnmatch(c["value"], c["pattern"]) is c["match"], c


def test_validation() -> None:
    v = _load("vectors/validation.json")
    assert len(v["cases"]) > 200
    _check(v["cases"], gen.eval_validation)
    # the trailing-newline quirk the Go port must reproduce
    quirk = [
        c for c in v["cases"] if c["fn"] == "validate_name" and c["args"] == ["abc\n"] and c["expect"]["ok"] is True
    ]
    assert quirk


def test_timestamps() -> None:
    v = _load("vectors/timestamps.json")
    assert len(v["cases"]) >= 10
    for c in v["cases"]:
        assert gen.eval_isoformat(c) == c["isoformat"]
        dt = datetime(
            c["year"], c["month"], c["day"], c["hour"], c["minute"], c["second"], c["microsecond"], tzinfo=timezone.utc
        )
        assert (dt - datetime(1970, 1, 1, tzinfo=timezone.utc)) // timedelta(microseconds=1) == c["unix_micro"]
        assert ("." in c["isoformat"]) is (c["microsecond"] != 0)
    assert any(c["microsecond"] == 0 for c in v["cases"])


def test_audit_vectors() -> None:
    v = _load("vectors/audit_vectors.json")
    specs = [
        (
            c["input"]["action"] if isinstance(c["input"]["action"], str) else gen.dec_arg(c["input"]["action"]),
            c["input"]["secret_name"],
            c["input"]["details"] if isinstance(c["input"]["details"], str) else gen.dec_arg(c["input"]["details"]),
            c["input"]["policy_hash"],
            c["input"]["agent_id"],
        )
        for c in v["chain"]
    ]
    stamps = [c["input"]["timestamp"] for c in v["chain"]]
    rows = gen.eval_audit_chain(specs, stamps)
    assert len(rows) == len(v["chain"]) > 0
    columns = {"action", "secret_name", "timestamp", "details", "prev_hash", "entry_hash", "policy_hash", "agent_id"}
    for c, r in zip(v["chain"], rows):
        assert set(c["stored"]) == columns
        assert {k: r[k] for k in c["stored"]} == c["stored"]
    assert v["sanitize"]
    for c in v["sanitize"]:
        assert gen.eval_sanitize(c["input"]) == c["output"]
    # and the hash really is the documented formula
    prev = ""
    for r in rows:
        raw = f"{prev}|{r['timestamp']}|{r['action']}|{r['secret_name'] or ''}|{r['details']}|{r['policy_hash']}"
        assert hashlib.sha256(raw.encode("utf-8")).hexdigest() == r["entry_hash"]
        prev = r["entry_hash"]


def test_keychain_wrap_vectors() -> None:
    v = _load("vectors/keychain_wrap.json")
    for c in v["cases"]:
        got = gen.eval_keychain(c)
        for k in ("kek_hex", "nonce_hex", "aad", "binding_context", "keychain_json"):
            assert got[k] == c[k], (c["name"], k)
        kc = json.loads(c["keychain_json"])
        assert kc["key_epoch"] == c["epoch"]
        wrapped = base64.b64decode(kc["wrapped_dek"])
        assert len(wrapped) == 32 + 16  # dek + GCM tag, no nonce
