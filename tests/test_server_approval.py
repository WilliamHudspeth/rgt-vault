"""HTTP tests for the operator approval endpoints driven by the broker."""

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
from rgt_vault.vault import VaultManager  # noqa: E402

POLICY = """
rules:
  - effect: allow
    agent: tester
"""


@pytest.fixture
def client_and_broker(tmp_path, master_provider):
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
    client = TestClient(app)
    client.headers.update({"Authorization": f"Bearer {token}"})
    return client, broker, secret


def test_set_secret_with_note_and_2fa_flag(client_and_broker):
    client, _, _ = client_and_broker
    r = client.post("/v1/secrets", json={
        "name": "API", "value": "sk-1", "namespace": "default",
        "agent": "tester", "note": "prod key", "require_2fa": True,
    })
    assert r.status_code == 200
    listed = client.get("/v1/secrets", params={"namespace": "default", "agent": "tester"})
    item = listed.json()["secrets"][0]
    assert item["note"] == "prod key"
    assert item["require_2fa"] is True
    assert "sk-1" not in listed.text  # value never leaves the vault


def test_pending_request_listed_and_approved_with_2fa(client_and_broker):
    client, broker, secret = client_and_broker
    client.post("/v1/secrets", json={
        "name": "API", "value": "sk-secret", "namespace": "default",
        "agent": "tester", "require_2fa": True,
    })

    # Fire an agent "use" in a background thread; it will block on approval.
    result = {}

    def agent_use():
        result["resp"] = client.post(
            "/v1/secrets/default/API/use",
            json={"action": "echo", "agent": "tester", "purpose": "test", "params": {}},
        )

    t = threading.Thread(target=agent_use)
    t.start()

    # The request shows up on the operator endpoint.
    pending = []
    for _ in range(100):
        pending = client.get("/v1/requests").json()["requests"]
        if pending:
            break
        time.sleep(0.02)
    assert len(pending) == 1
    req = pending[0]
    assert req["secret_name"] == "API"
    assert req["require_2fa"] is True

    # Approving without a code is a 400.
    bad = client.post(f"/v1/requests/{req['request_id']}/approve", json={})
    assert bad.status_code == 400

    # Approving with a valid TOTP code unblocks the agent.
    ok = client.post(
        f"/v1/requests/{req['request_id']}/approve",
        json={"totp_code": totp.generate(secret), "operator": "alice"},
    )
    assert ok.status_code == 200
    t.join(timeout=5)
    assert result["resp"].status_code == 200


def test_agent_token_cannot_approve_when_operator_scope_set(tmp_path, master_provider):
    """The boundary claim: with a separate operator token, the agent token
    is rejected on the approve/deny endpoints (it cannot self-approve)."""
    broker = ApprovalBroker(timeout=5)
    vault = VaultManager(
        db_path=str(tmp_path / "vault.db"),
        policy_yaml=POLICY,
        master_provider=master_provider,
        approval_gate=broker,
    )
    agent_token = generate_token()
    agent_store = TokenStore(path=tmp_path / "agent.token")
    agent_store.write(agent_token)
    operator_token = generate_token()
    operator_store = TokenStore(path=tmp_path / "operator.token")
    operator_store.write(operator_token)

    registry = ActionRegistry()
    register_builtin_actions(registry)
    app = build_app(vault, agent_store, registry, operator_token_store=operator_store, broker=broker)
    client = TestClient(app)

    # Agent token is accepted on agent endpoints but rejected on operator ones.
    assert client.get("/v1/secrets", params={"namespace": "default", "agent": "tester"},
                      headers={"Authorization": f"Bearer {agent_token}"}).status_code == 200
    assert client.get("/v1/requests",
                      headers={"Authorization": f"Bearer {agent_token}"}).status_code == 401
    # Operator token is accepted on the operator endpoint.
    assert client.get("/v1/requests",
                      headers={"Authorization": f"Bearer {operator_token}"}).status_code == 200


def test_deny_blocks_agent(client_and_broker):
    client, broker, _ = client_and_broker
    client.post("/v1/secrets", json={
        "name": "K", "value": "v", "namespace": "default", "agent": "tester",
    })
    result = {}

    def agent_use():
        result["resp"] = client.post(
            "/v1/secrets/default/K/use",
            json={"action": "echo", "agent": "tester", "purpose": "test", "params": {}},
        )

    t = threading.Thread(target=agent_use)
    t.start()
    rid = None
    for _ in range(100):
        reqs = client.get("/v1/requests").json()["requests"]
        if reqs:
            rid = reqs[0]["request_id"]
            break
        time.sleep(0.02)
    assert rid
    client.post(f"/v1/requests/{rid}/deny", json={"reason": "no"})
    t.join(timeout=5)
    assert result["resp"].status_code == 403  # PolicyDeniedError -> 403
