"""End-to-end integration tests for the v0.3 capability path.

Exercises:
  * HTTP ``/v1/capabilities/execute`` end-to-end (auth + body + token).
  * HTTP ``/v1/capabilities`` (registry listing).
  * HTTP 4xx mapping for the new error types.
  * Webhook hook in ``execute_capability`` path (a stub server is
    stood up via ``http.server`` so the test does not depend on
    network access).
  * SOAR mode is no longer accepted by ``hook_from_config``.
  * Freeze via freeze file prevents capability execution.
  * Capability audit rows participate in the same hash chain as
    legacy rows.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from rgt_vault.exceptions import ValidationError
from rgt_vault.hook import (
    OffHook,
    WebhookHook,
    hook_from_config,
)
from rgt_vault.server.app import build_app
from rgt_vault.server.auth import TokenStore
from rgt_vault.token import HMACTokenVerifier
from rgt_vault.vault import VaultManager

SHARED_SECRET = b"k" * 32


class _BytesProvider:
    def __init__(self, secret: bytes = b"\x0a" * 32):
        self._s = secret

    def get_secret(self) -> bytes:
        return self._s

    def rotate_secret(self) -> bytes:
        return self._s


@pytest.fixture
def server_vault(tmp_path):
    """A vault with a token verifier, hook, and a FastAPI server."""
    sub = tmp_path / "v"
    sub.mkdir()
    vault = VaultManager(
        db_path=str(sub / "vault.db"),
        policy_yaml="rules:\n  - effect: allow\n",
        master_provider=_BytesProvider(),
        hook=OffHook(),
        token_verifier=HMACTokenVerifier(SHARED_SECRET),
    )
    token_path = sub / "tok"
    token_path.write_text("test-server-token\n")
    token_path.chmod(0o600)
    ts = TokenStore(path=token_path)
    app = build_app(vault, ts)
    return vault, TestClient(app)


# ---------------------------------------------------------------------
# HTTP: /v1/capabilities
# ---------------------------------------------------------------------


def test_http_list_capabilities(server_vault):
    _vault, client = server_vault
    r = client.get(
        "/v1/capabilities",
        headers={"Authorization": "Bearer test-server-token"},
    )
    assert r.status_code == 200
    body = r.json()
    names = {c["name"] for c in body["capabilities"]}
    assert "secrets.echo" in names
    assert "secrets.use" in names
    # Every capability has a description + versions list.
    for cap in body["capabilities"]:
        assert "description" in cap
        assert isinstance(cap["supported_versions"], list)


def test_http_list_capabilities_requires_bearer(server_vault):
    _vault, client = server_vault
    r = client.get("/v1/capabilities")
    assert r.status_code == 401


# ---------------------------------------------------------------------
# HTTP: /v1/capabilities/execute
# ---------------------------------------------------------------------


def test_http_execute_capability_happy_path(server_vault):
    _vault, client = server_vault
    verifier = HMACTokenVerifier(SHARED_SECRET)
    tok = verifier.sign(
        "agent-1",
        "secrets.echo",
        capability_version=1,
        ttl_seconds=60,
    )
    r = client.post(
        "/v1/capabilities/execute",
        headers={"Authorization": "Bearer test-server-token"},
        json={
            "capability": "secrets.echo",
            "agent_id": "agent-1",
            "capability_token": tok,
            "payload": {"message": "via http"},
            "capability_version": 1,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["capability"] == "secrets.echo"
    assert body["result"]["message"] == "via http"


def test_http_execute_capability_denied_on_token_mismatch(server_vault):
    _vault, client = server_vault
    verifier = HMACTokenVerifier(SHARED_SECRET)
    tok = verifier.sign("agent-1", "secrets.echo", capability_version=1, ttl_seconds=60)
    # Caller claims to be a different agent than the token binds to.
    r = client.post(
        "/v1/capabilities/execute",
        headers={"Authorization": "Bearer test-server-token"},
        json={
            "capability": "secrets.echo",
            "agent_id": "agent-ATTACKER",
            "capability_token": tok,
            "payload": {},
            "capability_version": 1,
        },
    )
    assert r.status_code == 403
    assert "agent" in r.json()["detail"].lower()


def test_http_execute_capability_404_on_unknown_capability(server_vault):
    _vault, client = server_vault
    verifier = HMACTokenVerifier(SHARED_SECRET)
    # Mint a token for a name that does not exist in the registry.
    tok = verifier.sign("agent-1", "missing.cap", capability_version=1, ttl_seconds=60)
    r = client.post(
        "/v1/capabilities/execute",
        headers={"Authorization": "Bearer test-server-token"},
        json={
            "capability": "missing.cap",
            "agent_id": "agent-1",
            "capability_token": tok,
            "payload": {},
            "capability_version": 1,
        },
    )
    assert r.status_code == 404


def test_http_execute_capability_403_on_bad_signature(server_vault):
    _vault, client = server_vault
    r = client.post(
        "/v1/capabilities/execute",
        headers={"Authorization": "Bearer test-server-token"},
        json={
            "capability": "secrets.echo",
            "agent_id": "agent-1",
            "capability_token": "this-is-not-a-real-token",
            "payload": {},
            "capability_version": 1,
        },
    )
    assert r.status_code == 403


def test_http_execute_capability_400_on_malformed_body(server_vault):
    _vault, client = server_vault
    r = client.post(
        "/v1/capabilities/execute",
        headers={"Authorization": "Bearer test-server-token"},
        json={"capability": "secrets.echo"},  # missing required fields
    )
    # Pydantic validation surfaces as 422; we accept either 400
    # (Pydantic is configured to re-raise) or 422.
    assert r.status_code in (400, 422)


# ---------------------------------------------------------------------
# HTTP: legacy /v1/secrets/{ns}/{name}/use still works
# ---------------------------------------------------------------------


def test_http_legacy_use_endpoint_still_works(server_vault):
    _vault, client = server_vault
    # Set a secret via the legacy endpoint.
    r = client.post(
        "/v1/secrets",
        headers={"Authorization": "Bearer test-server-token"},
        json={
            "name": "k",
            "value": "v",
            "namespace": "default",
            "agent": "cli",
            "purpose": "test",
        },
    )
    assert r.status_code == 200, r.text
    # Lease it via the legacy /use endpoint.
    r = client.post(
        "/v1/secrets/default/k/use",
        headers={"Authorization": "Bearer test-server-token"},
        json={"action": "echo", "agent": "cli", "purpose": "test", "params": {}},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    # The echo action explicitly does NOT leak the secret.
    assert body["result"]["leaked_secret"] is False


# ---------------------------------------------------------------------
# Webhook hook integration with execute_capability
# ---------------------------------------------------------------------


class _AllowingHarness(BaseHTTPRequestHandler):
    """Minimal harness that allows every request."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        body = json.dumps({"decision": "allow", "reason": "test harness allow"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # silence stderr
        return


@pytest.fixture
def harness_server():
    server = HTTPServer(("127.0.0.1", 0), _AllowingHarness)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    yield f"http://{host}:{port}/"
    server.shutdown()
    thread.join(timeout=2)


def test_webhook_hook_runs_on_capability_path(tmp_path, harness_server):
    sub = tmp_path / "v"
    sub.mkdir()
    hook = WebhookHook(harness_server, timeout_seconds=5.0)
    vault = VaultManager(
        db_path=str(sub / "vault.db"),
        policy_yaml="rules:\n  - effect: allow\n",
        master_provider=_BytesProvider(),
        hook=hook,
        token_verifier=HMACTokenVerifier(SHARED_SECRET),
    )
    verifier = HMACTokenVerifier(SHARED_SECRET)
    tok = verifier.sign("agent-1", "secrets.echo", capability_version=1, ttl_seconds=60)
    result = vault.execute_capability(
        "secrets.echo",
        {},
        "agent-1",
        tok,
        capability_version=1,
    )
    assert result["ok"] is True
    # The HOOK_CAPABILITY audit row recorded the webhook's decision.
    audit = vault.get_audit_log(limit=20)
    rows = [r for r in audit if r.get("action") == "HOOK_CAPABILITY"]
    assert rows
    details = json.loads(rows[-1]["details"])
    assert details["decision"] == "allow"
    assert details["hook_id"].startswith("webhook:")


# ---------------------------------------------------------------------
# SOAR mode is no longer accepted
# ---------------------------------------------------------------------


def test_soar_mode_rejected_by_hook_from_config():
    with pytest.raises(ValidationError) as exc:
        hook_from_config({"mode": "soar", "webhook": {"url": "http://x"}})
    assert "soar" in str(exc.value).lower()


# ---------------------------------------------------------------------
# Freeze integration: freeze file prevents capability execution
# ---------------------------------------------------------------------


def test_freeze_file_blocks_capability_execution(tmp_path):
    sub = tmp_path / "v"
    sub.mkdir()
    freeze_path = sub / "freeze"
    hook = OffHook()
    hook.freeze_file = freeze_path
    # Pre-create the freeze file BEFORE the vault is constructed so
    # the very first ``frozen`` check returns True.
    freeze_path.touch()
    vault = VaultManager(
        db_path=str(sub / "vault.db"),
        policy_yaml="rules:\n  - effect: allow\n",
        master_provider=_BytesProvider(),
        hook=hook,
        token_verifier=HMACTokenVerifier(SHARED_SECRET),
    )
    verifier = HMACTokenVerifier(SHARED_SECRET)
    tok = verifier.sign("agent-1", "secrets.echo", capability_version=1, ttl_seconds=60)
    with pytest.raises(Exception) as exc:
        vault.execute_capability("secrets.echo", {}, "agent-1", tok, capability_version=1)
    assert "frozen" in str(exc.value).lower()


# ---------------------------------------------------------------------
# Audit chain integrity across capability + legacy rows
# ---------------------------------------------------------------------


def test_audit_chain_verifies_after_capability_and_legacy(server_vault):
    vault, client = server_vault
    # Capability execution
    verifier = HMACTokenVerifier(SHARED_SECRET)
    tok = verifier.sign("agent-1", "secrets.echo", capability_version=1, ttl_seconds=60)
    client.post(
        "/v1/capabilities/execute",
        headers={"Authorization": "Bearer test-server-token"},
        json={
            "capability": "secrets.echo",
            "agent_id": "agent-1",
            "capability_token": tok,
            "payload": {},
            "capability_version": 1,
        },
    )
    # Legacy write
    client.post(
        "/v1/secrets",
        headers={"Authorization": "Bearer test-server-token"},
        json={
            "name": "k",
            "value": "v",
            "namespace": "default",
            "agent": "cli",
            "purpose": "test",
        },
    )
    # Chain still verifies: capability + legacy rows are interleaved
    # but each one was appended in a single transaction.
    assert vault.verify_audit_chain() is True


# ---------------------------------------------------------------------
# RGT-277: brute-force / credential-guessing cap on execute_capability
# ---------------------------------------------------------------------


def test_auth_failure_limiter_record_and_count_dont_interact_with_allow():
    from rgt_vault.vault import RateLimiter

    rl = RateLimiter(max_requests=2, window_seconds=3600)
    assert rl.count("a1") == 0
    rl.record("a1")
    rl.record("a1")
    assert rl.count("a1") == 2
    # record() never enforces the cap -- that's the caller's job via count().
    rl.record("a1")
    assert rl.count("a1") == 3
    # allow() is a fully independent bucket/method on the same instance.
    assert rl.allow("a2") is True


def test_execute_capability_locks_out_after_repeated_bad_tokens(server_vault):
    vault, _client = server_vault
    # Small cap so the test doesn't need 100 iterations.
    vault.auth_failure_limiter = type(vault.auth_failure_limiter)(max_requests=2, window_seconds=3600)

    for _ in range(2):
        with pytest.raises(Exception):  # PolicyDeniedError: capability token rejected
            vault.execute_capability("secrets.echo", {}, "attacker", "not-a-real-token", capability_version=1)

    # 3rd attempt is refused for being locked out, WITHOUT even attempting
    # to verify the token -- confirmed by using an equally-bad token and
    # checking the audit log records the lockout reason, not a token error.
    with pytest.raises(Exception, match="locked out"):
        vault.execute_capability("secrets.echo", {}, "attacker", "not-a-real-token", capability_version=1)

    log = vault.storage.get_audit_log(limit=1)
    assert "too many failed credential verifications" in log[0]["details"]

    # A different agent is unaffected -- the cap is per-agent.
    with pytest.raises(Exception):
        vault.execute_capability("secrets.echo", {}, "someone-else", "not-a-real-token", capability_version=1)
    log2 = vault.storage.get_audit_log(limit=1)
    assert "locked out" not in log2[0]["details"] and "too many failed" not in log2[0]["details"]


def test_execute_capability_valid_token_never_counts_as_failure(server_vault):
    vault, _client = server_vault
    vault.auth_failure_limiter = type(vault.auth_failure_limiter)(max_requests=2, window_seconds=3600)
    verifier = HMACTokenVerifier(SHARED_SECRET)
    tok = verifier.sign("agent-good", "secrets.echo", capability_version=1, ttl_seconds=60)

    for _ in range(5):
        vault.execute_capability("secrets.echo", {"message": "hi"}, "agent-good", tok, capability_version=1)

    assert vault.auth_failure_limiter.count("agent-good") == 0
