"""Regression tests for the production-readiness hardening pass.

Covers:
  * P0-1  master-secret normalization (provider returns raw bytes)
  * P0-2  execute() hands over a bytearray and zeroizes it afterwards
  * P1-4  audit hash-chain stays intact under concurrent writers
  * P2-2  cross-vault import is refused instead of silently corrupting
"""

import os
import threading

import pytest

from rgt_vault.exceptions import ValidationError
from rgt_vault.vault import VaultManager

ALLOW_ALL = """
rules:
  - effect: allow
"""


def _make_vault(tmpdir, name="vault", secret=b"\x02" * 32):
    # Inline provider returning raw bytes -> exercises _normalize_master (P0-1).
    class _Bytes:
        def get_secret(self):
            return secret

        def rotate_secret(self):
            return secret

    # keychain.json lives next to the DB, so give each vault its own subdir.
    subdir = os.path.join(tmpdir, name)
    os.makedirs(subdir, exist_ok=True)
    return VaultManager(
        db_path=os.path.join(subdir, "vault.db"),
        policy_yaml=ALLOW_ALL,
        master_provider=_Bytes(),
    )


def test_bytes_provider_is_normalized(temp_vault_dir):
    """A provider returning raw bytes must work end-to-end (P0-1)."""
    vault = _make_vault(temp_vault_dir)
    vault.set_secret("k", "v", namespace="default", agent="a")
    assert vault.execute("a", "default", "use", "k", lambda b: bytes(b)) == b"v"


def test_bad_provider_type_rejected(temp_vault_dir):
    class _Bad:
        def get_secret(self):
            return 12345  # not bytes / MasterSecret

    with pytest.raises(ValidationError, match="unsupported type"):
        VaultManager(
            db_path=os.path.join(temp_vault_dir, "bad.db"),
            policy_yaml=ALLOW_ALL,
            master_provider=_Bad(),
        )


def test_execute_passes_bytearray_and_zeroizes(temp_vault_dir):
    """Callback receives a bytearray; the vault wipes it afterwards (P0-2)."""
    vault = _make_vault(temp_vault_dir)
    vault.set_secret("k", "hunter2", namespace="default", agent="a")

    captured = {}

    def cb(buf):
        assert isinstance(buf, bytearray)
        assert bytes(buf) == b"hunter2"
        captured["buf"] = buf  # keep a reference to inspect after teardown
        return "ok"

    assert vault.execute("a", "default", "use", "k", cb) == "ok"
    # The same buffer object must be zeroized once the lease closes.
    assert bytes(captured["buf"]) == b"\x00" * len(captured["buf"])


def test_audit_chain_intact_under_concurrency(temp_vault_dir):
    """Concurrent audited operations must not fork the hash chain (P1-4)."""
    vault = _make_vault(temp_vault_dir)

    def worker(i):
        vault.set_secret(f"k{i}", "v", namespace="default", agent="a")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert vault.verify_audit_chain() is True


def test_cross_vault_import_refused(temp_vault_dir):
    """A payload exported from vault A must not import into vault B (P2-2)."""
    vault_a = _make_vault(temp_vault_dir, name="a.db", secret=b"\x0a" * 32)
    vault_a.set_secret("k", "v", namespace="default", agent="a")
    payload = vault_a.export_vault()

    vault_b = _make_vault(temp_vault_dir, name="b.db", secret=b"\x0b" * 32)
    assert vault_b.vault_id != vault_a.vault_id

    with pytest.raises(ValidationError, match="Import refused"):
        vault_b.import_vault(payload)


def test_same_vault_roundtrip_import_ok(temp_vault_dir):
    """Export/import into the same vault_id is allowed."""
    vault = _make_vault(temp_vault_dir, name="rt.db")
    vault.set_secret("k", "v", namespace="default", agent="a")
    payload = vault.export_vault()
    vault.import_vault(payload)  # same vault_id -> permitted
    assert vault.execute("a", "default", "use", "k", lambda b: bytes(b)) == b"v"
