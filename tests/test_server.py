"""End-to-end tests for the rgt-vault HTTP server via FastAPI's TestClient.

No real socket is opened. The vault uses the in-memory master provider from
conftest and a temp database, so no OS keyring / TPM / DPAPI is touched.
"""

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from rgt_vault.server.actions import ActionRegistry, register_builtin_actions  # noqa: E402
from rgt_vault.server.app import build_app  # noqa: E402
from rgt_vault.server.auth import TokenStore, generate_token  # noqa: E402
from rgt_vault.vault import VaultManager  # noqa: E402

# tester is allowed everything (missing attrs default to '*'); any other agent
# is default-denied.
POLICY = """
rules:
  - effect: allow
    agent: tester
"""


@pytest.fixture
def server(tmp_path, master_provider):
    vault = VaultManager(
        db_path=str(tmp_path / "vault.db"),
        policy_yaml=POLICY,
        master_provider=master_provider,
    )
    token = generate_token()
    store = TokenStore(tmp_path / "server.token")
    store.write(token)
    registry = ActionRegistry()
    register_builtin_actions(registry)
    app = build_app(vault, store, registry)
    return app, token


def _authed(app, token) -> TestClient:
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    return c


def test_healthz_needs_no_auth(server):
    app, _token = server
    r = TestClient(app).get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "echo" in body["actions"]


def test_missing_auth_is_401(server):
    app, _token = server
    r = TestClient(app).get("/v1/secrets", params={"namespace": "default", "agent": "tester"})
    assert r.status_code == 401


def test_bad_token_is_401(server):
    app, _token = server
    c = TestClient(app)
    c.headers["Authorization"] = "Bearer not-the-real-token"
    r = c.get("/v1/secrets", params={"namespace": "default", "agent": "tester"})
    assert r.status_code == 401


def test_set_then_list(server):
    app, token = server
    c = _authed(app, token)
    r = c.post("/v1/secrets", json={"name": "API_KEY", "value": "sk-abc", "agent": "tester"})
    assert r.status_code == 200, r.text
    r = c.get("/v1/secrets", params={"namespace": "default", "agent": "tester"})
    assert r.status_code == 200
    names = [s["name"] for s in r.json()["secrets"]]
    assert "API_KEY" in names


def test_use_echo_does_not_return_plaintext(server):
    app, token = server
    c = _authed(app, token)
    c.post("/v1/secrets", json={"name": "API_KEY", "value": "sk-secret-xyz", "agent": "tester"})
    r = c.post(
        "/v1/secrets/default/API_KEY/use",
        json={"action": "echo", "agent": "tester", "purpose": "test"},
    )
    assert r.status_code == 200, r.text
    result = r.json()["result"]
    assert result["leaked_secret"] is False
    assert result["secret_len"] == len("sk-secret-xyz")
    assert "sk-secret-xyz" not in r.text


def test_use_unknown_action_is_404(server):
    app, token = server
    c = _authed(app, token)
    c.post("/v1/secrets", json={"name": "API_KEY", "value": "sk-abc", "agent": "tester"})
    r = c.post(
        "/v1/secrets/default/API_KEY/use",
        json={"action": "no_such_action", "agent": "tester"},
    )
    assert r.status_code == 404


def test_use_bad_params_is_400(server):
    app, token = server
    c = _authed(app, token)
    c.post("/v1/secrets", json={"name": "API_KEY", "value": "sk-abc", "agent": "tester"})
    r = c.post(
        "/v1/secrets/default/API_KEY/use",
        json={"action": "echo", "agent": "tester", "params": {"bogus": 1}},
    )
    assert r.status_code == 400


def test_policy_denied_is_403(server):
    app, token = server
    c = _authed(app, token)
    c.post("/v1/secrets", json={"name": "API_KEY", "value": "sk-abc", "agent": "tester"})
    r = c.post(
        "/v1/secrets/default/API_KEY/use",
        json={"action": "echo", "agent": "intruder", "purpose": "test"},
    )
    assert r.status_code == 403


def test_set_with_unlisted_agent_is_403(server):
    app, token = server
    c = _authed(app, token)
    r = c.post("/v1/secrets", json={"name": "API_KEY", "value": "sk-abc", "agent": "intruder"})
    assert r.status_code == 403


def test_revoke(server):
    app, token = server
    c = _authed(app, token)
    c.post("/v1/secrets", json={"name": "API_KEY", "value": "sk-abc", "agent": "tester"})
    r = c.post("/v1/secrets/default/API_KEY/revoke?agent=tester")
    assert r.status_code == 200
    r = c.get("/v1/secrets", params={"namespace": "default", "agent": "tester"})
    assert "API_KEY" not in [s["name"] for s in r.json()["secrets"]]


def test_audit_records_http_calls_and_chain_verifies(server):
    app, token = server
    c = _authed(app, token)
    c.post("/v1/secrets", json={"name": "API_KEY", "value": "sk-abc", "agent": "tester"})
    r = c.get("/v1/audit", params={"limit": 100})
    assert r.status_code == 200
    actions = [e.get("action") for e in r.json()["entries"]]
    assert "HTTP_API" in actions
    r = c.post("/v1/audit/verify")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_policy_simulate(server):
    app, token = server
    c = _authed(app, token)
    allow = c.post(
        "/v1/policy/simulate",
        json={"agent": "tester", "namespace": "default", "action": "read"},
    )
    assert allow.json()["allowed"] is True
    deny = c.post(
        "/v1/policy/simulate",
        json={"agent": "intruder", "namespace": "default", "action": "read"},
    )
    assert deny.json()["allowed"] is False


def test_rotate_dek_then_use_still_works(server):
    app, token = server
    c = _authed(app, token)
    c.post("/v1/secrets", json={"name": "API_KEY", "value": "sk-rotate", "agent": "tester"})
    r = c.post("/v1/rotate", json={"target": "dek"})
    assert r.status_code == 200, r.text
    r = c.post(
        "/v1/secrets/default/API_KEY/use",
        json={"action": "echo", "agent": "tester", "purpose": "test"},
    )
    assert r.status_code == 200
    assert r.json()["result"]["secret_len"] == len("sk-rotate")
