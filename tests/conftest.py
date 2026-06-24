"""Shared test fixtures.

Uses an in-memory master-secret provider that returns **raw bytes**. This
deliberately exercises ``VaultManager._normalize_master`` (the bytes-vs-
MasterSecret boundary that previously crashed every default code path) and
keeps the test suite from writing into the developer's real OS keyring.
"""

import os
import tempfile

import pytest

from rgt_vault.providers.base import MasterSecretProvider


class InMemoryMasterProvider(MasterSecretProvider):
    """Test provider returning raw bytes (no OS keyring side effects)."""

    def __init__(self, secret: bytes = b"\x01" * 32):
        self._secret = secret

    def get_secret(self) -> bytes:
        return self._secret

    def rotate_secret(self) -> bytes:
        self._secret = os.urandom(32)
        return self._secret


@pytest.fixture
def master_provider():
    return InMemoryMasterProvider()


@pytest.fixture
def temp_vault_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir
