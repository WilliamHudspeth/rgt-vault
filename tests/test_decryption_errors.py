"""Tests for the cryptographic error contract.

The public ``crypto.decrypt`` and ``VaultManager.lease_secret`` paths are
contracted to raise :class:`DecryptionError` (a ``VaultError``) for *any*
decryption failure -- bad AAD, wrong key, truncated/oversized ciphertext.
This prevents callers from distinguishing "wrong key" from "tampered
ciphertext" by exception type, which would otherwise be a useful oracle to an
attacker probing the vault.
"""

import os

import pytest

from rgt_vault.exceptions import DecryptionError, ValidationError, VaultError
from rgt_vault.vault import VaultManager

# ------------------------------------------------------------------
# crypto.decrypt contract
# ------------------------------------------------------------------


def test_decrypt_truncated_raises_decryption_error():
    from rgt_vault.crypto import decrypt

    key = b"k" * 32
    # 5 bytes is below the 12 (nonce) + 16 (tag) minimum.
    with pytest.raises(DecryptionError):
        decrypt(b"short", key, b"aad")


def test_decrypt_non_bytes_token():
    from rgt_vault.crypto import decrypt

    with pytest.raises(DecryptionError, match="bytes or bytearray"):
        decrypt("not bytes", b"k" * 32, b"aad")


def test_decrypt_wrong_aad_raises_decryption_error():
    from rgt_vault.crypto import decrypt, encrypt

    key = b"k" * 32
    ct = encrypt(b"plaintext", key, b"good-aad")
    with pytest.raises(DecryptionError):
        decrypt(ct, key, b"bad-aad")


def test_decrypt_wrong_key_raises_decryption_error():
    from rgt_vault.crypto import decrypt, encrypt

    ct = encrypt(b"plaintext", b"k" * 32, b"aad")
    with pytest.raises(DecryptionError):
        decrypt(ct, b"j" * 32, b"aad")


def test_decrypt_error_is_a_vault_error():
    """All vault error types should be catchable as ``VaultError``."""
    from rgt_vault.crypto import decrypt

    with pytest.raises(VaultError):
        decrypt(b"short", b"k" * 32, b"aad")


# ------------------------------------------------------------------
# VaultManager.lease_secret surfaces DecryptionError (not InvalidTag)
# ------------------------------------------------------------------


def test_lease_secret_tampered_ciphertext_raises_decryption_error(temp_vault_dir, master_provider):
    """If the stored ciphertext is tampered with, lease_secret must raise
    ``DecryptionError`` (a ``VaultError``), not the raw ``InvalidTag`` from
    cryptography (which would be a ``cryptography`` library exception and
    leak "we use AES-GCM" via the exception type)."""
    db = os.path.join(temp_vault_dir, "v.db")
    v = VaultManager(db_path=db, policy_yaml="rules:\n  - effect: allow\n", master_provider=master_provider)
    v.set_secret("K", "v", namespace="default", agent="a")

    # Tamper: flip one byte of the stored ciphertext directly in the DB.
    # The storage layer's checksum check is the first line of defense and
    # raises ``ChecksumError``; that itself is a ``VaultError`` and prevents
    # leaking the underlying library exception type.
    import sqlite3

    conn = sqlite3.connect(db)
    row = conn.execute("SELECT id, ciphertext FROM secrets WHERE name='K'").fetchone()
    record_id, ct = row
    tampered = bytes(ct[:-1]) + bytes([ct[-1] ^ 0x01])
    conn.execute("UPDATE secrets SET ciphertext = ? WHERE id = ?", (tampered, record_id))
    conn.commit()
    conn.close()

    with pytest.raises(VaultError):
        v.execute("a", "default", "use", "K", lambda b: b"x")


def test_lease_secret_decryption_error_when_checksum_matches_tampered(temp_vault_dir, master_provider):
    """If the attacker can also recompute the checksum, the next line of
    defense is AES-GCM authentication. ``lease_secret`` must then raise
    ``DecryptionError`` (a ``VaultError``) -- never ``InvalidTag`` from
    cryptography, which would tell the attacker which library we use.
    """
    db = os.path.join(temp_vault_dir, "v.db")
    v = VaultManager(db_path=db, policy_yaml="rules:\n  - effect: allow\n", master_provider=master_provider)
    v.set_secret("K", "v", namespace="default", agent="a")

    import hashlib
    import sqlite3

    conn = sqlite3.connect(db)
    row = conn.execute("SELECT id, ciphertext FROM secrets WHERE name='K'").fetchone()
    record_id, ct = row
    tampered = bytes(ct[:-1]) + bytes([ct[-1] ^ 0x01])
    # Recompute checksum so the storage layer lets it through.
    new_checksum = hashlib.sha256(tampered).hexdigest()
    conn.execute(
        "UPDATE secrets SET ciphertext = ?, checksum = ? WHERE id = ?",
        (tampered, new_checksum, record_id),
    )
    conn.commit()
    conn.close()

    with pytest.raises(DecryptionError):
        v.execute("a", "default", "use", "K", lambda b: b"x")


def test_lease_secret_propagates_validation_error_for_unsupported_dek_version(temp_vault_dir, master_provider):
    """An unknown DEK version in the DB must raise ``ValidationError`` (a
    ``VaultError``), not a bare ``ValueError`` -- same oracle-prevention
    rationale as above."""
    db = os.path.join(temp_vault_dir, "v.db")
    v = VaultManager(db_path=db, policy_yaml="rules:\n  - effect: allow\n", master_provider=master_provider)
    v.set_secret("K", "v", namespace="default", agent="a")

    # Pin a future DEK version and try to read it back.
    import sqlite3

    conn = sqlite3.connect(db)
    conn.execute("UPDATE secrets SET dek_version = 99 WHERE name='K'")
    conn.commit()
    conn.close()

    with pytest.raises(ValidationError, match="Unsupported DEK version"):
        v.execute("a", "default", "use", "K", lambda b: b"x")
