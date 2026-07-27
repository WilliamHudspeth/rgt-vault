import os
import threading
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet

from rgt_vault.crypto import decrypt
from rgt_vault.exceptions import PolicyDeniedError
from rgt_vault.keychain import run_crypto_selftest
from rgt_vault.vault import RateLimiter, VaultManager


@pytest.fixture
def policy_yaml():
    return """
    rules:
      - effect: deny
        namespace: production
      - effect: deny
        agent: test_agent
        purpose: billing
      - effect: allow
        agent: test_agent
        namespace: test_ns
        action: write
      - effect: allow
        agent: test_agent
        namespace: test_ns
        action: read
      - effect: allow
        agent: admin_agent
        namespace: "*"
        action: write
      - effect: allow
        agent: admin_agent
        namespace: "*"
        action: read
    """


@pytest.fixture
def vault(temp_vault_dir, policy_yaml, master_provider):
    db_path = os.path.join(temp_vault_dir, "vault.db")
    return VaultManager(db_path=db_path, policy_yaml=policy_yaml, master_provider=master_provider)


def test_crypto_selftest():
    # Calling it manually should not raise errors
    run_crypto_selftest()


def test_keychain_initialized(vault):
    assert os.path.exists(vault.dek_manager.keychain_path)
    assert vault.vault_id is not None
    assert vault.key_epoch >= 1
    assert len(vault.dek) == 32


def test_migrate_v2_to_v3(temp_vault_dir, policy_yaml, master_provider):
    db_path = os.path.join(temp_vault_dir, "migrate_test.db")
    import sqlite3

    # Initialize schema + keychain (reuse the same provider so the DEK matches).
    VaultManager(db_path=db_path, policy_yaml=policy_yaml, master_provider=master_provider)

    fernet_key = Fernet.generate_key()
    f = Fernet(fernet_key)
    ciphertext = f.encrypt(b"legacy_plaintext")

    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO secrets (secret_id, namespace, name, version, ciphertext, checksum, created_at, updated_at, status, dek_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("sid1", "default", "old_secret", 1, ciphertext, "chk", "now", "now", "ACTIVE", 0),
    )
    conn.commit()
    conn.close()

    # The legacy Fernet key would live in the OS keyring under
    # ("rgt_vault", "master_key"). Mock it so this test is hermetic and does not
    # depend on a real Credential Manager / Secret Service in CI.
    with patch("rgt_vault.vault.keyring.get_password", return_value=fernet_key.decode("utf-8")):
        v = VaultManager(db_path=db_path, policy_yaml=policy_yaml, master_provider=master_provider)

    # Migration happens inside __init__. Verify dek_version became 1 and decrypts correctly
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT dek_version, ciphertext FROM secrets WHERE name = 'old_secret'")
    row = cursor.fetchone()
    conn.close()

    assert row[0] == 1  # Now it's upgraded!
    aad = f"{v.vault_id}:default:old_secret".encode()
    plaintext = decrypt(row[1], v.dek, aad)
    assert plaintext == b"legacy_plaintext"


def test_deny_precedence_wins(vault):
    with pytest.raises(PolicyDeniedError):
        vault.set_secret("db_pwd", "123", namespace="test_ns", agent="test_agent", purpose="billing")


def test_honeytoken_critical_audit(vault):
    vault.storage.add_honeytoken("test_ns", "fake_key")
    with pytest.raises(PermissionError, match="Honeytoken access detected"):
        vault.get_fingerprint("fake_key", namespace="test_ns")

    logs = vault.get_audit_log(10)
    assert any(log["action"] == "HONEYTOKEN_TRIGGERED" and "critical" in log["details"] for log in logs)


def test_namespace_enumeration_protection(vault):
    with pytest.raises(PolicyDeniedError, match="Unauthorized to access namespace"):
        vault.list_secrets("test_ns", agent="unauthorized_agent")


def test_set_and_execute_secret(vault):
    vault.set_secret("MY_SECRET", "super_secret_value", namespace="test_ns", agent="test_agent", purpose="testing")

    def callback(secret_buf):
        # execute() now hands the callback the mutable bytearray, not a str.
        assert isinstance(secret_buf, bytearray)
        assert secret_buf.decode("utf-8") == "super_secret_value"
        return True

    result = vault.execute("test_agent", "test_ns", "testing", "MY_SECRET", callback)
    assert result is True


def test_rate_limiter_concurrency(vault):
    vault.rate_limiter = RateLimiter(max_requests=50, window_seconds=10)
    vault.set_secret("conc_key", "val", namespace="test_ns", agent="test_agent")

    success_count = 0
    fail_count = 0
    lock = threading.Lock()

    def worker():
        nonlocal success_count, fail_count
        try:
            vault.execute("test_agent", "test_ns", "testing", "conc_key", lambda x: True)
            with lock:
                success_count += 1
        except PermissionError:
            with lock:
                fail_count += 1

    threads = [threading.Thread(target=worker) for _ in range(60)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert success_count == 50
    assert fail_count == 10


def test_rotate_master_key(vault):
    vault.set_secret("test_rot", "val", namespace="test_ns", agent="test_agent")
    old_epoch = vault.key_epoch
    old_dek = vault.dek

    vault.rotate_master_key()

    assert vault.key_epoch == old_epoch + 1
    # DEK is the same!
    assert vault.dek == old_dek

    # Should still decrypt
    def cb(val):
        return val.decode("utf-8") == "val"

    assert vault.execute("test_agent", "test_ns", "testing", "test_rot", cb) is True


def test_rotate_dek(vault):
    vault.set_secret("test_rot2", "val", namespace="test_ns", agent="test_agent")
    old_dek = vault.dek

    vault.rotate_dek()

    assert vault.dek != old_dek

    # Should still decrypt properly using the NEW DEK
    def cb(val):
        return val.decode("utf-8") == "val"

    assert vault.execute("test_agent", "test_ns", "testing", "test_rot2", cb) is True


def test_rollback_protection(vault):
    vault.rotate_master_key()
    # Now keychain has epoch=2, and DB has epoch=2.

    # Let's forcefully downgrade the DB epoch to simulate restoring an old DB backup.
    import sqlite3

    conn = sqlite3.connect(vault.storage.db_path)
    conn.execute("UPDATE metadata SET value = '1' WHERE key = 'key_epoch'")
    conn.commit()
    conn.close()

    # Re-initializing VaultManager should fail because DB epoch (1) != Keychain epoch (2).
    # Reuse the same provider so the epoch check (not a key mismatch) is what fails.
    with pytest.raises(ValueError, match="Rollback attack detected"):
        VaultManager(db_path=vault.storage.db_path, policy_yaml="", master_provider=vault.master_provider)


# ----- RGT-219: DEK rotation counters ------------------------------------


def test_dek_usage_tallies_on_set_secret(vault):
    assert vault.storage.get_dek_usage() == (0, 0)
    vault.set_secret("s1", "hello", namespace="test_ns", agent="test_agent")
    count, nbytes = vault.storage.get_dek_usage()
    assert count == 1
    assert nbytes == len(b"hello")
    vault.set_secret("s2", "world!", namespace="test_ns", agent="test_agent")
    count, nbytes = vault.storage.get_dek_usage()
    assert count == 2
    assert nbytes == len(b"hello") + len(b"world!")


def test_dek_rotation_triggers_at_encryption_count_threshold(vault, monkeypatch):
    import rgt_vault.vault as vault_module

    monkeypatch.setattr(vault_module, "DEK_MAX_ENCRYPTIONS", 2)
    old_dek = vault.dek

    vault.set_secret("s1", "a", namespace="test_ns", agent="test_agent")
    assert vault.dek == old_dek  # 1st encryption, under threshold

    vault.set_secret("s2", "b", namespace="test_ns", agent="test_agent")
    assert vault.dek != old_dek  # 2nd encryption crossed the threshold -> rotated

    # Counters reset after rotation.
    assert vault.storage.get_dek_usage() == (0, 0)

    # Data written under the old DEK is still readable after rotation
    # (rotate_dek re-encrypts existing rows under the new DEK).
    def cb(val):
        return val.decode("utf-8") == "a"

    assert vault.execute("test_agent", "test_ns", "testing", "s1", cb) is True


def test_dek_rotation_triggers_at_byte_threshold(vault, monkeypatch):
    import rgt_vault.vault as vault_module

    monkeypatch.setattr(vault_module, "DEK_MAX_BYTES", 5)
    old_dek = vault.dek

    vault.set_secret("s1", "12345", namespace="test_ns", agent="test_agent")  # exactly at the byte cap
    assert vault.dek != old_dek
    assert vault.storage.get_dek_usage() == (0, 0)


def test_dek_usage_survives_vault_manager_restart(temp_vault_dir, policy_yaml, master_provider):
    db_path = os.path.join(temp_vault_dir, "vault.db")
    v1 = VaultManager(db_path=db_path, policy_yaml=policy_yaml, master_provider=master_provider)
    v1.set_secret("s1", "hello", namespace="test_ns", agent="test_agent")
    assert v1.storage.get_dek_usage() == (1, len(b"hello"))

    # A fresh VaultManager against the same DB sees the durable tally --
    # it isn't reset just because the in-process object was recreated.
    v2 = VaultManager(db_path=db_path, policy_yaml=policy_yaml, master_provider=master_provider)
    assert v2.storage.get_dek_usage() == (1, len(b"hello"))
