"""Tests for the live approval broker and its integration with the vault."""

import os
import tempfile
import threading
import time

import pytest
from rgt_vault import totp
from rgt_vault.approval import (
    ApprovalBroker,
    ApprovalError,
    ApprovalRequest,
    AutoAllowGate,
)
from rgt_vault.exceptions import PolicyDeniedError
from rgt_vault.providers.base import MasterSecretProvider
from rgt_vault.vault import VaultManager


class _InMemoryProvider(MasterSecretProvider):
    def get_secret(self) -> bytes:
        return b"\x07" * 32

    def rotate_secret(self) -> bytes:
        return b"\x07" * 32


def _req(**kw):
    base = dict(agent="a", namespace="ns", secret_name="s", purpose="p")
    base.update(kw)
    return ApprovalRequest(**base)


# --- broker unit tests ------------------------------------------------------


def test_auto_allow_gate_approves():
    assert AutoAllowGate().consult(_req()).allowed is True


def test_approve_unblocks_waiting_request():
    broker = ApprovalBroker(timeout=5)
    result = {}

    def agent():
        result["decision"] = broker.consult(_req())

    t = threading.Thread(target=agent)
    t.start()
    # Wait for the request to register, then approve it.
    for _ in range(50):
        if broker.list_pending():
            break
        time.sleep(0.01)
    pending = broker.list_pending()
    assert len(pending) == 1
    broker.approve(pending[0].request_id, operator="alice")
    t.join(timeout=5)
    assert result["decision"].allowed is True
    assert result["decision"].decided_by == "alice"


def test_deny_unblocks_with_denial():
    broker = ApprovalBroker(timeout=5)
    result = {}

    def agent():
        result["decision"] = broker.consult(_req())

    t = threading.Thread(target=agent)
    t.start()
    for _ in range(50):
        if broker.list_pending():
            break
        time.sleep(0.01)
    broker.deny(broker.list_pending()[0].request_id, reason="nope")
    t.join(timeout=5)
    assert result["decision"].allowed is False
    assert "nope" in result["decision"].reason


def test_timeout_is_fail_closed():
    broker = ApprovalBroker(timeout=0.2)
    decision = broker.consult(_req())
    assert decision.allowed is False
    assert "timed out" in decision.reason


def test_2fa_required_rejects_without_code():
    secret = totp.generate_secret()
    broker = ApprovalBroker(timeout=5, totp_verifier=lambda c: totp.verify(secret, c))
    result = {}

    def agent():
        result["decision"] = broker.consult(_req(require_2fa=True))

    t = threading.Thread(target=agent)
    t.start()
    for _ in range(50):
        if broker.list_pending():
            break
        time.sleep(0.01)
    rid = broker.list_pending()[0].request_id

    with pytest.raises(ApprovalError):
        broker.approve(rid, totp_code="000000")  # wrong code (almost surely)

    # Correct code unblocks.
    broker.approve(rid, totp_code=totp.generate(secret))
    t.join(timeout=5)
    assert result["decision"].allowed is True


def test_approve_unknown_id_raises():
    broker = ApprovalBroker(timeout=1)
    with pytest.raises(ApprovalError):
        broker.approve("does-not-exist")


# --- vault integration ------------------------------------------------------


def _vault(tmp, gate=None, policy=""):
    return VaultManager(
        db_path=os.path.join(tmp, "vault.db"),
        policy_yaml=policy or "rules:\n  - effect: allow\n    agent: '*'\n",
        master_provider=_InMemoryProvider(),
        approval_gate=gate,
    )


def test_default_vault_behaviour_unchanged():
    # No gate wired -> AutoAllowGate -> execute works exactly as before.
    with tempfile.TemporaryDirectory() as tmp:
        v = _vault(tmp)
        v.set_secret("K", "value", namespace="ns", agent="admin")
        out = v.execute("agent", "ns", "p", "K", lambda buf: bytes(buf))
        assert out == b"value"


def test_gate_denial_blocks_decryption():
    with tempfile.TemporaryDirectory() as tmp:
        broker = ApprovalBroker(timeout=0.2)  # nobody approves -> timeout deny
        v = _vault(tmp, gate=broker)
        v.set_secret("K", "value", namespace="ns", agent="admin")
        with pytest.raises(PolicyDeniedError):
            v.execute("agent", "ns", "p", "K", lambda buf: bytes(buf))


def test_require_2fa_flag_survives_export_import():
    # A 2FA-gated secret must not be silently downgraded on re-import.
    with tempfile.TemporaryDirectory() as tmp:
        v = _vault(tmp)
        v.set_secret("API", "sk-1", namespace="ns", agent="admin", require_2fa=True)
        dump = v.storage.export_data()
        v.storage.import_data(dump)
        assert v.storage.requires_2fa("ns", "API") is True


def test_note_and_2fa_flag_persist_and_list():
    with tempfile.TemporaryDirectory() as tmp:
        v = _vault(tmp)
        v.set_secret("API", "sk-1", namespace="ns", agent="admin",
                     note="prod OpenAI key, billing team", require_2fa=True)
        listed = v.list_secrets("ns", agent="admin")
        assert len(listed) == 1
        assert listed[0]["name"] == "API"
        assert listed[0]["note"] == "prod OpenAI key, billing team"
        assert listed[0]["require_2fa"] is True
        # The value is never in the listing.
        assert "sk-1" not in str(listed)
        assert v.storage.requires_2fa("ns", "API") is True
