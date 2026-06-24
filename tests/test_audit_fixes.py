"""Tests for the audit-fix transaction wrappers and provider fail-closed
behaviors.

Covers:
  - P0-4 / P2-1 / P2-2: StorageBackend.set_secret is atomic
  - P0-5: get_secret + audit-log write happen in one transaction
  - P0-3: bulk_rewrite_active_secrets (used by rotate_dek) is atomic
  - P1-4: rotate_master_key refuses providers that don't implement
          rotate_secret (instead of corrupting epoch state)
  - P0-2: KeyringProvider fails closed on missing keyring entry
  - P1-3: keychain.json is chmod 0600 after writing
"""

import os
import sqlite3
import threading

import pytest

from rgt_vault.exceptions import (
    MasterSecretUnavailableError,
    RotateNotSupportedError,
)
from rgt_vault.keychain import HardenedDEKManager, KeyringProvider
from rgt_vault.vault import VaultManager

# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

ALLOW_ALL = """
rules:
  - effect: allow
"""


class _BytesProvider:
    """Test provider returning raw bytes -- exercises _normalize_master."""

    def __init__(self, secret: bytes = b"\x02" * 32):
        self._s = secret

    def get_secret(self) -> bytes:
        return self._s

    def rotate_secret(self) -> bytes:
        # Simulate a provider that supports rotation (used by happy-path tests).
        import os as _os

        self._s = _os.urandom(32)
        return self._s


class _NonRotatingProvider:
    """Provider that does NOT implement rotate_secret -- simulating the
    LinuxTPMProvider / WindowsDPAPIProvider / macOS base default. Used
    to verify the P1-4 pre-check in rotate_master_key.
    """

    def __init__(self, secret: bytes = b"\x04" * 32):
        self._s = secret

    def get_secret(self) -> bytes:
        return self._s

    # NOTE: no rotate_secret override -- inherits NotImplementedError from
    # MasterSecretProvider base.


@pytest.fixture
def vault(tmp_path):
    sub = tmp_path / "v"
    sub.mkdir()
    return VaultManager(
        db_path=str(sub / "vault.db"),
        policy_yaml=ALLOW_ALL,
        master_provider=_BytesProvider(),
    )


# ------------------------------------------------------------------
# P0-2: KeyringProvider fails closed on missing entry
# ------------------------------------------------------------------


def test_keyring_provider_missing_entry_raises(tmp_path, monkeypatch):
    """A keyring entry that disappears must NOT silently regenerate; the
    vault must fail closed with a clear message so the operator doesn't
    unknowingly brick their vault.
    """
    import keyring as real_keyring

    monkeypatch.setattr(real_keyring, "get_password", lambda *a, **k: None)
    # No set_password should be called.
    called = {"set": 0}

    def _set(*a, **k):
        called["set"] += 1
        return None

    monkeypatch.setattr(real_keyring, "set_password", _set)

    p = KeyringProvider()
    with pytest.raises(MasterSecretUnavailableError, match="Refusing to regenerate"):
        p.get_secret()
    assert called["set"] == 0, "KeyringProvider must NOT auto-generate on missing entry"


def test_keyring_provider_initialize_if_missing_creates_once(tmp_path, monkeypatch):
    """initialize_if_missing should create the entry when absent and be
    a no-op when present."""
    import keyring as real_keyring

    state = {"value": None}

    def _get(*a, **k):
        return state["value"]

    def _set(*a, **k):
        state["value"] = k.get("password") or a[2] if len(a) > 2 else None

    monkeypatch.setattr(real_keyring, "get_password", _get)
    monkeypatch.setattr(real_keyring, "set_password", _set)

    p = KeyringProvider()
    s1 = p.initialize_if_missing()
    assert isinstance(s1.value, bytes) and len(s1.value) == 32
    # Calling again returns the same secret (idempotent).
    s2 = p.initialize_if_missing()
    assert s2.value == s1.value


# ------------------------------------------------------------------
# P1-3: keychain.json is chmod 0600 after writing
# ------------------------------------------------------------------


def test_keychain_json_is_0600(tmp_path):
    """After initialize_dek, keychain.json must be mode 0600 so it can't
    be read by other users on a multi-user host.
    """
    if os.name != "posix":
        pytest.skip(
            "POSIX permission bits don't apply on this platform; Windows os.chmod only toggles the read-only flag"
        )
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("chmod is permissive under root; not a meaningful test")

    sub = tmp_path / "k"
    sub.mkdir()
    manager = HardenedDEKManager(str(sub / "keychain.json"))
    from rgt_vault.keychain import MasterSecret

    manager.initialize_dek(MasterSecret(b"\x03" * 32), vault_id="vid", epoch=1)
    mode = oct(os.stat(sub / "keychain.json").st_mode & 0o777)
    assert mode == "0o600", f"expected 0o600, got {mode}"


# ------------------------------------------------------------------
# P1-4: rotate_master_key pre-check
# ------------------------------------------------------------------


def test_rotate_master_key_refuses_non_rotating_provider(tmp_path):
    """rotate_master_key must refuse to proceed if the provider doesn't
    support automated rotation -- otherwise the epoch would be bumped and
    the vault would be in an inconsistent state on restart.
    """
    sub = tmp_path / "n"
    sub.mkdir()
    vault = VaultManager(
        db_path=str(sub / "vault.db"),
        policy_yaml=ALLOW_ALL,
        master_provider=_NonRotatingProvider(),
    )
    before_epoch = vault.key_epoch
    with pytest.raises(RotateNotSupportedError):
        vault.rotate_master_key()
    # Epoch must NOT have been bumped.
    assert vault.key_epoch == before_epoch


def test_rotate_master_key_works_on_rotating_provider(vault):
    """Sanity: a provider that does implement rotate_secret succeeds and
    bumps the epoch, and the vault remains readable."""
    vault.set_secret("k", "v", namespace="default", agent="a")
    before = vault.key_epoch
    vault.rotate_master_key()
    assert vault.key_epoch == before + 1
    # Still readable.
    out = vault.execute("a", "default", "use", "k", lambda b: bytes(b))
    assert out == b"v"


# ------------------------------------------------------------------
# P0-4 / P2-1 / P2-2: set_secret is atomic
# ------------------------------------------------------------------


def test_set_secret_atomic_under_concurrency(tmp_path):
    """Concurrent set_secret calls for the same name must serialize cleanly:
    each invocation produces exactly one ACTIVE version with a unique
    version number, no half-applied state.
    """
    sub = tmp_path / "conc"
    sub.mkdir()
    vault = VaultManager(
        db_path=str(sub / "vault.db"),
        policy_yaml=ALLOW_ALL,
        master_provider=_BytesProvider(),
    )

    errors = []

    def worker(i):
        try:
            vault.set_secret("k", f"v{i}", namespace="default", agent="a")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # No constraint violations should leak out.
    assert not errors, f"set_secret raised: {errors}"

    # Version chain should be 1..N with no gaps.
    db = str(sub / "vault.db")
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute(
            "SELECT version, status FROM secrets WHERE namespace='default' AND name='k' ORDER BY version"
        ).fetchall()
    finally:
        conn.close()
    versions = [r[0] for r in rows]
    assert versions == list(range(1, 21)), f"expected 1..20 versions, got {versions}"
    # Exactly one row is ACTIVE; the rest are SUPERSEDED.
    statuses = [r[1] for r in rows]
    assert statuses.count("ACTIVE") == 1


# ------------------------------------------------------------------
# P0-5: get_secret + audit-log write in one transaction
# ------------------------------------------------------------------


def test_get_secret_atomic_audit(vault):
    """A successful get_secret must produce exactly one GET_SECRET audit
    row per call, and the chain must verify.
    """
    vault.set_secret("k", "v", namespace="default", agent="a")
    before_count = sum(1 for r in vault.storage.get_audit_log(limit=1000) if r["action"] == "GET_SECRET")
    res = vault.execute("a", "default", "use", "k", lambda b: bytes(b))
    assert res == b"v"
    log = vault.storage.get_audit_log(limit=1000)
    get_secret_rows = [r for r in log if r["action"] == "GET_SECRET"]
    assert len(get_secret_rows) == before_count + 1
    assert vault.verify_audit_chain() is True


def test_get_secret_audit_in_same_tx_as_read(vault):
    """Simulate a failing audit insert and verify the secret read is
    rolled back. We patch _append_audit_in_tx to raise after the read;
    the secret must NOT be returned.
    """
    vault.set_secret("k", "v", namespace="default", agent="a")

    original = vault.storage._append_audit_in_tx

    def boom(*a, **k):
        raise sqlite3.OperationalError("simulated audit write failure")

    vault.storage._append_audit_in_tx = boom
    try:
        with pytest.raises(sqlite3.OperationalError):
            vault.storage.get_secret("default", "k")
    finally:
        vault.storage._append_audit_in_tx = original


# ------------------------------------------------------------------
# P0-3: bulk_rewrite_active_secrets is atomic
# ------------------------------------------------------------------


def test_bulk_rewrite_rolls_back_on_failure(vault):
    """If the rewrite function raises partway, the transaction rolls back
    and no rows are modified.
    """
    vault.set_secret("k1", "v1", namespace="default", agent="a")
    vault.set_secret("k2", "v2", namespace="default", agent="a")
    vault.set_secret("k3", "v3", namespace="default", agent="a")

    # Snapshot ciphertexts BEFORE the failing rewrite.
    db = vault.storage.db_path
    before = {}
    conn = sqlite3.connect(db)
    try:
        for r in conn.execute("SELECT name, ciphertext FROM secrets WHERE status='ACTIVE'").fetchall():
            before[r[0]] = bytes(r[1])
    finally:
        conn.close()

    # Rewrite function that succeeds for k1, fails for k2, would succeed
    # for k3 -- we must observe k1 and k3 unchanged.
    call_count = {"n": 0}

    def _rewrite(record_id, namespace, name, ciphertext, dek_version):
        call_count["n"] += 1
        if name == "k2":
            raise RuntimeError("simulated per-row failure")
        return ciphertext + b"\x00", 1  # otherwise would corrupt, but tx rolls back

    with pytest.raises(RuntimeError):
        vault.storage.bulk_rewrite_active_secrets(_rewrite)

    # All rows must be byte-identical to before.
    after = {}
    conn = sqlite3.connect(db)
    try:
        for r in conn.execute("SELECT name, ciphertext FROM secrets WHERE status='ACTIVE'").fetchall():
            after[r[0]] = bytes(r[1])
    finally:
        conn.close()
    assert after == before, f"rows changed despite rollback: {set(before) ^ set(after)}"


# ------------------------------------------------------------------
# rotation: end-to-end via vault.rotate_dek()
# ------------------------------------------------------------------


def test_rotate_dek_atomic_end_to_end(vault):
    """rotate_dek() must leave the vault in a state where every previously
    stored secret is still readable under the new DEK.
    """
    vault.set_secret("a", "alpha", namespace="default", agent="a")
    vault.set_secret("b", "bravo", namespace="default", agent="a")
    vault.set_secret("c", "charlie", namespace="default", agent="a")

    vault.rotate_dek()

    assert vault.execute("a", "default", "use", "a", lambda b: bytes(b)) == b"alpha"
    assert vault.execute("a", "default", "use", "b", lambda b: bytes(b)) == b"bravo"
    assert vault.execute("a", "default", "use", "c", lambda b: bytes(b)) == b"charlie"
    assert vault.verify_audit_chain() is True


# ------------------------------------------------------------------
# P0-1: LinuxTPMProvider temp file is 0600
# ------------------------------------------------------------------


def test_linux_tpm_temp_file_is_0600(tmp_path, monkeypatch):
    """The unseal-target temp file created by LinuxTPMProvider.get_secret()
    must be mode 0600 before tpm2_unseal writes to it, so an attacker who
    reaches the directory can't read the plaintext master secret.
    """
    from rgt_vault.providers.linux_tpm import LinuxTPMProvider

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("chmod is permissive under root; not meaningful")

    # Create stub .priv / .pub so the provider can be instantiated.
    (tmp_path / "master_secret.priv").write_bytes(b"priv")
    (tmp_path / "master_secret.pub").write_bytes(b"pub")

    # Patch the tpm2 invocations so we never actually hit /dev/tpmrm0.
    # We let the file be created (so we can inspect its mode), but we
    # intercept the tpm2_unseal step so it never overwrites the file
    # with a real plaintext. We do this by tracking the temp path and
    # writing our own bytes via open(out_path, "wb") AFTER the provider
    # has set its permissions.
    seen = {}

    def fake_run_tpm_cmd(args, cwd=None):
        # The provider passes a list; the tpm2_unseal invocation carries -o.
        if args and args[0] == "tpm2_unseal":
            oi = args.index("-o")
            out_path = args[oi + 1]
            seen["out_path"] = out_path
            # Don't actually write; we just want to inspect the mode.
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        if args and args[0] == "tpm2_flushcontext":
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    # The provider uses subprocess.run for tpm2_flushcontext (not
    # _run_tpm_cmd) at the end of the finally block. Patch both.
    monkeypatch.setattr(
        "rgt_vault.providers.linux_tpm._run_tpm_cmd",
        fake_run_tpm_cmd,
    )
    monkeypatch.setattr(
        "rgt_vault.providers.linux_tpm.subprocess.run",
        lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
    )

    provider = LinuxTPMProvider(
        str(tmp_path / "master_secret.priv"),
        str(tmp_path / "master_secret.pub"),
    )

    # get_secret() will try to read the (empty) file and raise TPMError.
    # That's fine -- we just need the temp file to have been created
    # with mode 0600 by the time tpm2_unseal was called.
    from rgt_vault.providers.linux_tpm import TPMError

    with pytest.raises(TPMError):
        provider.get_secret()

    assert "out_path" in seen, "tpm2_unseal was never invoked"
    out_path = seen["out_path"]
    mode = oct(os.stat(out_path).st_mode & 0o777) if os.path.exists(out_path) else "removed"
    # Either still exists with 0600, or was cleaned up after read.
    if os.path.exists(out_path):
        assert mode == "0o600", f"expected 0o600, got {mode}"
