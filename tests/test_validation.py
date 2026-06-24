import os

import pytest

from rgt_vault.exceptions import ValidationError
from rgt_vault.vault import VaultManager


@pytest.fixture
def vault(temp_vault_dir, master_provider):
    db_path = os.path.join(temp_vault_dir, "vault.db")
    policy_yaml = """
    rules:
      - effect: allow
    """
    return VaultManager(db_path=db_path, policy_yaml=policy_yaml, master_provider=master_provider)


def test_set_secret_validation(vault):
    # Test wrong types
    with pytest.raises(ValidationError):
        vault.set_secret(123, "value")
    with pytest.raises(ValidationError):
        vault.set_secret("key", 456)

    # Test empty strings
    with pytest.raises(ValidationError):
        vault.set_secret("", "value")
    with pytest.raises(ValidationError):
        vault.set_secret("key", "   ")

    # Test length limits
    long_name = "a" * 257
    with pytest.raises(ValidationError):
        vault.set_secret(long_name, "value")

    long_value = "v" * (1024 * 1024 + 1)
    with pytest.raises(ValidationError):
        vault.set_secret("key", long_value)


def test_execute_validation(vault):
    vault.set_secret("KEY", "val")

    # Test wrong types
    with pytest.raises(ValidationError):
        vault.execute(123, "ns", "purpose", "KEY", lambda x: True)

    # Test empty strings
    with pytest.raises(ValidationError):
        vault.execute("", "ns", "purpose", "KEY", lambda x: True)

    # Test non-callable callback
    with pytest.raises(ValidationError):
        vault.execute("agent", "ns", "purpose", "KEY", "not_a_function")


def test_auth_validation(temp_vault_dir, master_provider):
    db_path = os.path.join(temp_vault_dir, "vault.db")
    # Test invalid policy type
    with pytest.raises(ValidationError):
        VaultManager(db_path=db_path, policy_yaml=123, master_provider=master_provider)

    # Test massive policy YAML
    massive_yaml = "a" * (1024 * 1024 + 1)
    with pytest.raises(ValidationError):
        VaultManager(db_path=db_path, policy_yaml=massive_yaml, master_provider=master_provider)


def test_import_vault_validation(vault):
    # Test non-bytes input
    with pytest.raises(ValidationError):
        vault.import_vault("not_bytes")

    # Test massive input
    massive_payload = b"a" * (10 * 1024 * 1024 + 1)
    with pytest.raises(ValidationError):
        vault.import_vault(massive_payload)

    # Test malformed base64 / json
    with pytest.raises(ValidationError, match="Invalid import payload format"):
        vault.import_vault(b"this_is_not_base64_or_json!")


def test_sqlite_import_data_malformed(vault):
    # Since import_vault catches JSON decode errors, we bypass it to test sqlite import_data directly
    malformed_data = {
        "secrets": [
            {"id": 1, "name": "test"}  # Missing ciphertext
        ]
    }
    with pytest.raises(ValueError, match="Malformed secret entry"):
        vault.storage.import_data(malformed_data)

    malformed_data2 = {"secrets": [{"id": 1, "name": "test", "ciphertext": "invalid_base64+++"}]}
    with pytest.raises(ValueError, match="Failed to decode ciphertext"):
        vault.storage.import_data(malformed_data2)

    malformed_audit = {
        "audit_logs": [
            {"id": 1, "action": "READ"}  # Missing entry_hash
        ]
    }
    with pytest.raises(ValueError, match="Malformed audit log entry"):
        vault.storage.import_data(malformed_audit)
