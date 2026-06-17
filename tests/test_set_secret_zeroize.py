"""RGT-113: verify that set_secret zeroizes the plaintext buffer it uses."""
import os

import pytest

from rgt_vault.exceptions import PolicyDeniedError, ValidationError
from rgt_vault.vault import VaultManager


@pytest.fixture
def vault(temp_vault_dir, master_provider):
    db_path = os.path.join(temp_vault_dir, "vault.db")
    policy_yaml = """
    rules:
      - effect: allow
    """
    return VaultManager(db_path=db_path, policy_yaml=policy_yaml, master_provider=master_provider)


def test_set_secret_zeroizes_mutable_buffer(vault):
    """Passing a bytearray proves the buffer is wiped after encryption."""
    value = bytearray(b"burn-after-reading")
    vault.set_secret("zero", value, namespace="default", agent="a", purpose="p")
    assert all(b == 0 for b in value), "set_secret must zeroize the bytearray it encrypted"


def test_set_secret_accepts_bytearray(vault):
    value = bytearray(b"bytes-secret")
    vault.set_secret("bytes", value, namespace="default", agent="a", purpose="p")
    result = vault.execute("a", "default", "p", "bytes", lambda buf: bytes(buf))
    assert result == b"bytes-secret"


def test_set_secret_accepts_bytes(vault):
    value = b"bytes-secret"
    vault.set_secret("bytes2", value, namespace="default", agent="a", purpose="p")
    result = vault.execute("a", "default", "p", "bytes2", lambda buf: bytes(buf))
    assert result == b"bytes-secret"


def test_set_secret_still_rejects_invalid_value_types(vault):
    with pytest.raises(ValidationError):
        vault.set_secret("k", 123, namespace="default", agent="a", purpose="p")


def test_set_secret_zeroizes_even_on_policy_denial(temp_vault_dir, master_provider):
    """A denied write must still wipe the plaintext copy."""
    db_path = os.path.join(temp_vault_dir, "deny.db")
    vault_no_allow = VaultManager(
        db_path=db_path,
        policy_yaml="rules:\n  - effect: deny\n",
        master_provider=master_provider,
    )
    value = bytearray(b"denied-secret")
    with pytest.raises(PolicyDeniedError):
        vault_no_allow.set_secret("k", value, namespace="default", agent="a", purpose="p")
    assert all(b == 0 for b in value), "plaintext must be zeroized even when policy denies"
