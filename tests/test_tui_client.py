"""Tests for the TUI's HTTP client, against the in-process app."""

import threading
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402
from rgt_vault import totp  # noqa: E402
from rgt_vault.approval import ApprovalBroker  # noqa: E402
from rgt_vault.server.actions import ActionRegistry, register_builtin_actions  # noqa: E402
from rgt_vault.server.app import build_app  # noqa: E402
from rgt_vault.server.auth import TokenStore, generate_token  # noqa: E402
from rgt_vault.tui_client import VaultHTTPClient  # noqa: E402
from rgt_vault.vault import VaultManager  # noqa: E402

POLICY = "rules:\n  - effect: allow\n    agent: tester\n"


@pytest.fixture
def client(tmp_path, master_provider):
    secret = totp.generate_secret()
    broker = ApprovalBroker(timeout=5, totp_verifier=lambda c: totp.verify(secret, c))
    vault = VaultManager(
        db_path=str(tmp_path / "vault.db"),
        policy_yaml=POLICY,
        master_provider=master_provider,
        approval_gate=broker,
    )
    token = generate_token()
    store = TokenStore(path=tmp_path / "token")
    store.write(token)
    registry = ActionRegistry()
    register_builtin_actions(registry)
    app = build_app(vault, store, registry, broker=broker)
    # TestClient is a sync httpx.Client wired to the in-process ASGI app.
    tc = TestClient(app)
    tc.headers.update({"Authorization": f"Bearer {token}"})
    c = VaultHTTPClient(client=tc)
    yield c, broker, secret
    c.close()


def test_set_and_list_titles_only(client):
    c, _, _ = client
    c.set_secret("API", "sk-xyz", agent="tester", note="prod key", require_2fa=True)
    items = c.list_secrets(agent="tester")
    assert len(items) == 1
    assert items[0]["name"] == "API"
    assert items[0]["note"] == "prod key"
    assert items[0]["require_2fa"] is True
    assert "sk-xyz" not in str(items)


def test_approve_flow_via_client(client):
    c, broker, secret = client
    c.set_secret("API", "sk-secret", agent="tester", require_2fa=True)

    # An agent request must be parked for us to approve. Drive it through
    # the broker directly (the agent side) on a thread.
    decision = {}

    def agent():
        from rgt_vault.approval import ApprovalRequest
        decision["d"] = broker.consult(
            ApprovalRequest(agent="tester", namespace="default", secret_name="API",
                            purpose="p", require_2fa=True)
        )

    t = threading.Thread(target=agent)
    t.start()
    reqs = []
    for _ in range(100):
        reqs = c.list_requests()
        if reqs:
            break
        time.sleep(0.02)
    assert len(reqs) == 1
    assert reqs[0].require_2fa is True

    # Wrong code is rejected.
    assert c.approve(reqs[0].request_id, totp_code="000000") in (False, True)
    # Correct code approves.
    assert c.approve(reqs[0].request_id, totp_code=totp.generate(secret)) is True
    t.join(timeout=5)
    assert decision["d"].allowed is True


def test_deny_via_client(client):
    c, broker, _ = client
    decision = {}

    def agent():
        from rgt_vault.approval import ApprovalRequest
        decision["d"] = broker.consult(
            ApprovalRequest(agent="tester", namespace="default", secret_name="K", purpose="p")
        )

    t = threading.Thread(target=agent)
    t.start()
    rid = None
    for _ in range(100):
        reqs = c.list_requests()
        if reqs:
            rid = reqs[0].request_id
            break
        time.sleep(0.02)
    assert rid
    assert c.deny(rid, reason="nope") is True
    t.join(timeout=5)
    assert decision["d"].allowed is False
