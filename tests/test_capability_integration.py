"""Integration tests for ``VaultManager.execute_capability``.

These tests exercise the full 9-step preflight through a real
``VaultManager`` with a stub keyring provider.
"""

import os
import time
import uuid

import pytest

from rgt_vault.exceptions import (
    CapabilityError,
    CapabilityNotFoundError,
    CapabilityVersionError,
    TokenExpiredError,
    TokenSignatureError,
    TokenBindingError,
    ValidationError,
)
from rgt_vault.token import HMACTokenVerifier, CapabilityV2Token


# Reuse the existing stub from test_cli.py
from tests.test_cli import _StubKeyringProvider, policy_file  # noqa: F401


_SECRET = b"k" * 32


def _make_vault(tmp_path, monkeypatch, policy_file=None):
    """Construct a minimal VaultManager for testing."""
    from rgt_vault import cli
    monkeypatch.setattr(cli, "KeyringProvider", _StubKeyringProvider)

    db = tmp_path / "v.db"
    vault = _pytest_vault(db, policy_file)
    return vault


def _pytest_vault(db_path, policy_file):
    """Build a VaultManager with the stub provider."""
    from rgt_vault.vault import VaultManager
    from rgt_vault.token import HMACTokenVerifier

    verifier = HMACTokenVerifier(_SECRET)
    policy = policy_file.read_text() if policy_file else ""
    return VaultManager(
        db_path=str(db_path),
        master_provider=_StubKeyringProvider(),
        policy_yaml=policy,
        token_verifier=verifier,
    )


def _make_token(agent_id="test-agent", capability="secrets.echo", **kw):
    """Create and sign a capability token.

    Keyword args override any token field: ``issued_at``, ``ttl`` (default 300),
    ``version`` (default 1), ``bindings`` (default {}).
    """
    verifier = HMACTokenVerifier(_SECRET)
    now = int(time.time())
    token = CapabilityV2Token(
        agent_id=agent_id,
        capability=capability,
        capability_version=kw.get("version", 1),
        context_bindings=kw.get("bindings", {}),
        expires_at=now + kw.get("ttl", 300),
        token_id=str(uuid.uuid4()),
        issued_at=kw.get("issued_at", now),
    )
    return verifier.sign(token)


# ------------------------------------------------------------------
# Happy path
# ------------------------------------------------------------------


def test_execute_capability_echo(tmp_path, policy_file):
    vault = _pytest_vault(tmp_path / "v.db", policy_file)
    token = _make_token()
    result = vault.execute_capability(
        "secrets.echo", {}, "test-agent", token,
    )
    assert result == {"ok": True}


# ------------------------------------------------------------------
# Token failure paths (steps 2-4)
# ------------------------------------------------------------------


def test_execute_capability_expired_token(tmp_path, policy_file):
    vault = _pytest_vault(tmp_path / "v.db", policy_file)
    now = int(time.time())
    token = _make_token(ttl=-10, issued_at=now - 120)
    with pytest.raises(TokenExpiredError):
        vault.execute_capability("secrets.echo", {}, "test-agent", token)


def test_execute_capability_bad_signature(tmp_path, policy_file):
    vault = _pytest_vault(tmp_path / "v.db", policy_file)
    good = _make_token()
    bad = bytearray(good)
    bad[-1] ^= 0xFF
    with pytest.raises(TokenSignatureError):
        vault.execute_capability("secrets.echo", {}, "test-agent", bytes(bad))


def test_execute_capability_agent_mismatch(tmp_path, policy_file):
    vault = _pytest_vault(tmp_path / "v.db", policy_file)
    token = _make_token(agent_id="other-agent")
    with pytest.raises(CapabilityError, match="does not match"):
        vault.execute_capability("secrets.echo", {}, "test-agent", token)


def test_execute_capability_capability_mismatch(tmp_path, policy_file):
    vault = _pytest_vault(tmp_path / "v.db", policy_file)
    token = _make_token(capability="secrets.use")
    with pytest.raises(CapabilityNotFoundError, match="Token grants"):
        vault.execute_capability("secrets.echo", {}, "test-agent", token)


def test_execute_capability_unknown_capability(tmp_path, policy_file):
    vault = _pytest_vault(tmp_path / "v.db", policy_file)
    token = _make_token(capability="nonexistent.cap")
    with pytest.raises(CapabilityNotFoundError, match="not registered"):
        vault.execute_capability("nonexistent.cap", {}, "test-agent", token)


def test_execute_capability_version_mismatch(tmp_path, policy_file):
    vault = _pytest_vault(tmp_path / "v.db", policy_file)
    token = _make_token(version=99)
    with pytest.raises(CapabilityVersionError):
        vault.execute_capability("secrets.echo", {}, "test-agent", token)


def test_execute_capability_context_binding_mismatch(tmp_path, policy_file):
    vault = _pytest_vault(tmp_path / "v.db", policy_file)
    token = _make_token(
        capability="secrets.echo",
        bindings={"repo": "org/expected"},
    )
    with pytest.raises(TokenBindingError):
        vault.execute_capability("secrets.echo", {"repo": "org/wrong"}, "test-agent", token)


def test_execute_capability_validation_error(tmp_path, policy_file):
    vault = _pytest_vault(tmp_path / "v.db", policy_file)
    # secrets.echo has no schema, so any payload is fine.
    # Use secrets.use which has required ['action', 'secret']
    token = _make_token(capability="secrets.use")
    with pytest.raises(ValidationError):
        vault.execute_capability(
            "secrets.use", {"bad": "payload"}, "test-agent", token,
        )


# ------------------------------------------------------------------
# Default token verifier (derived from master secret)
# ------------------------------------------------------------------


def test_default_verifier_roundtrip(tmp_path, policy_file):
    """When no token_verifier is provided, the vault derives one and
    behaves correctly."""
    from rgt_vault.vault import VaultManager

    db = tmp_path / "v2.db"
    vault = VaultManager(
        db_path=str(db),
        master_provider=_StubKeyringProvider(),
        policy_yaml=policy_file.read_text() if policy_file else "",
    )
    # The vault derived an HMACTokenVerifier from the master secret.
    # Make a token signed by the same verifier (since master secret is
    # deterministic from the stub).
    result = vault.execute_capability(
        "secrets.echo", {}, "cli", vault.token_verifier.sign(
            CapabilityV2Token(
                agent_id="cli",
                capability="secrets.echo",
                capability_version=1,
                context_bindings={},
                expires_at=int(time.time()) + 300,
                token_id=str(uuid.uuid4()),
                issued_at=int(time.time()),
            )
        ),
    )
    assert result == {"ok": True}
