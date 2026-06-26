"""Tests for the v0.2.0 HTTP server attack-surface hardening.

Covers:
  - P0-1/P0-3: SSRF protection in built-in HTTP actions (default-deny
    for loopback / private / link-local / reserved / multicast targets)
  - P0-2: Action errors do NOT leak the secret (or arbitrary exception
    text) into the HTTP response body
  - P0-4: scheme allow-list (http/https only; no file://, gopher://)
  - P0-5: response body cap
  - P1-3/P1-4: cmd_init does not print the existing token
"""

import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from rgt_vault.exceptions import ActionExecutionError  # noqa: E402
from rgt_vault.server.actions import (  # noqa: E402
    ActionRegistry,
    _validate_headers,
    _validate_outbound_url,
    register_builtin_actions,
)
from rgt_vault.server.app import build_app  # noqa: E402
from rgt_vault.server.auth import TokenStore, generate_token  # noqa: E402
from rgt_vault.vault import VaultManager  # noqa: E402

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


def _authed(app, token):
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    return c


# ------------------------------------------------------------------
# P0-1 / P0-3 / P0-4: SSRF protection
# ------------------------------------------------------------------


class _SSRFHandler(BaseHTTPRequestHandler):
    """Records requests and replies with a fixed body so we can see
    whether the vault reached us (and prove the SSRF was prevented)."""

    received: list = []

    def do_GET(self):
        _SSRFHandler.received.append(("GET", self.path, dict(self.headers)))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"INTERNAL OK")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        _SSRFHandler.received.append(("POST", self.path, dict(self.headers), body))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"INTERNAL OK")

    def log_message(self, *a, **k):  # silence test output
        pass


@pytest.fixture
def loopback_http_server():
    """A real HTTP server bound to 127.0.0.1 on an ephemeral port. The
    built-in actions must NOT reach it without ``--allow-private-network``.
    """
    _SSRFHandler.received = []
    srv = HTTPServer(("127.0.0.1", 0), _SSRFHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}", port
    srv.shutdown()


def _validate(url, **kwargs):
    return _validate_outbound_url(url, **kwargs)


def test_validate_outbound_url_allows_public_https():
    # Use a hostname that resolves to a public IP. We don't actually open
    # the socket -- _validate_outbound_url only does DNS resolution.
    url = _validate("https://example.com/")
    assert url == "https://example.com/"


def test_validate_outbound_url_rejects_loopback_by_default():
    with pytest.raises(ActionExecutionError, match="Refusing to call private/internal"):
        _validate("http://127.0.0.1:8080/")


def test_validate_outbound_url_rejects_rfc1918():
    with pytest.raises(ActionExecutionError, match="Refusing to call private/internal"):
        _validate("http://10.0.0.1/")


def test_validate_outbound_url_rejects_link_local():
    with pytest.raises(ActionExecutionError, match="Refusing to call private/internal"):
        _validate("http://169.254.169.254/latest/meta-data/")


def test_validate_outbound_url_rejects_multicast():
    with pytest.raises(ActionExecutionError, match="Refusing to call private/internal"):
        _validate("http://224.0.0.1/")


def test_validate_outbound_url_rejects_file_scheme():
    with pytest.raises(ActionExecutionError, match="Refusing URL with scheme"):
        _validate("file:///etc/passwd")


def test_validate_outbound_url_rejects_gopher_scheme():
    with pytest.raises(ActionExecutionError, match="Refusing URL with scheme"):
        _validate("gopher://example.com/")


def test_validate_outbound_url_allows_private_when_opted_in():
    url = _validate("http://127.0.0.1:1/", allow_private_network=True)
    assert "127.0.0.1" in url


def test_validate_outbound_url_rejects_dns_failure():
    # Use a TLD that should not resolve in any test environment.
    with pytest.raises(ActionExecutionError, match="DNS resolution failed"):
        _validate("https://this-host-definitely-does-not-exist.invalid/")


def test_server_blocks_loopback_ssrf(server, loopback_http_server):
    """A token-bearing caller must not be able to use the built-in
    ``http_get_with_auth`` action to probe a service on loopback."""
    url, port = loopback_http_server
    app, token = server
    c = _authed(app, token)
    c.post("/v1/secrets", json={"name": "API_KEY", "value": "sk-abc", "agent": "tester"})
    r = c.post(
        "/v1/secrets/default/API_KEY/use",
        json={
            "action": "http_get_with_auth",
            "agent": "tester",
            "purpose": "test",
            "params": {"url": url + "/probe"},
        },
    )
    # Server rejects with 500 (ActionExecutionError -> _STATUS_MAP).
    assert r.status_code == 500, r.text
    # The detail should NOT contain the secret and SHOULD explain the refusal.
    body = r.json()
    assert "sk-abc" not in r.text
    assert "Refusing" in body["detail"] or "private" in body["detail"].lower()
    # The loopback server should NOT have received anything.
    assert _SSRFHandler.received == [], "Loopback server was contacted -- SSRF protection failed"


def test_server_allows_loopback_when_opted_in(loopback_http_server):
    """Opting in via --allow-private-network (here, build_app kwarg) lifts
    the SSRF restriction."""
    url, port = loopback_http_server
    # Build a fresh app with allow_private_network=True
    import tempfile

    from rgt_vault.vault import VaultManager

    with tempfile.TemporaryDirectory() as td:
        import keyring as real_keyring  # noqa

        # Stub provider
        class _B:
            def get_secret(self):
                return b"\x05" * 32

            def rotate_secret(self):
                return b"\x05" * 32

        v = VaultManager(
            db_path=os.path.join(td, "vault.db"),
            policy_yaml=POLICY,
            master_provider=_B(),
        )
        tok = generate_token()
        st = TokenStore(os.path.join(td, "server.token"))
        st.write(tok)
        reg = ActionRegistry()
        register_builtin_actions(reg)
        app = build_app(v, st, reg, allow_private_network=True)
        c = TestClient(app)
        c.headers["Authorization"] = f"Bearer {tok}"
        c.post("/v1/secrets", json={"name": "API_KEY", "value": "sk-abc", "agent": "tester"})
        r = c.post(
            "/v1/secrets/default/API_KEY/use",
            json={
                "action": "http_get_with_auth",
                "agent": "tester",
                "purpose": "test",
                "params": {"url": url + "/probe"},
            },
        )
        assert r.status_code == 200, r.text
        assert "INTERNAL OK" in r.json()["result"]["body_text"]


def test_server_blocks_openai_chat_base_url_ssrf(server):
    """The openai_chat action also rejects internal ``base_url``."""
    app, token = server
    c = _authed(app, token)
    c.post("/v1/secrets", json={"name": "OPENAI", "value": "sk-x", "agent": "tester"})
    r = c.post(
        "/v1/secrets/default/OPENAI/use",
        json={
            "action": "openai_chat",
            "agent": "tester",
            "purpose": "test",
            "params": {
                "model": "gpt-x",
                "messages": [{"role": "user", "content": "hi"}],
                "base_url": "http://127.0.0.1:9999",
            },
        },
    )
    assert r.status_code == 500
    assert "sk-x" not in r.text


# ------------------------------------------------------------------
# P0-2: Action errors do not leak raw exception text
# ------------------------------------------------------------------


def test_action_exception_message_does_not_leak_text(server):
    """If a built-in action raises with text that includes the secret,
    the HTTP response must NOT include that text. Only an opaque error
    message should be returned."""
    app, token = server
    c = _authed(app, token)
    c.post("/v1/secrets", json={"name": "API_KEY", "value": "***", "agent": "tester"})

    # Trigger an ActionExecutionError from the built-in openai_chat
    # action by omitting 'model'. The HTTP response must not echo the
    # secret anywhere.
    r = c.post(
        "/v1/secrets/default/API_KEY/use",
        json={
            "action": "openai_chat",
            "agent": "tester",
            "purpose": "test",
            "params": {
                # Missing 'model' triggers an ActionExecutionError from the
                # action itself. The HTTP response must NOT echo the secret.
                "messages": [{"role": "user", "content": "hi"}],
            },
        },
    )
    assert r.status_code == 500
    assert "***" not in r.text


def test_unexpected_action_exception_is_sanitized(server, monkeypatch):
    """If an action raises a non-VaultError exception, the response must
    not include the exception text. We inject a deliberate leak into the
    echo action's exception message and verify the response is sanitized.
    """
    app, token = server
    c = _authed(app, token)
    c.post("/v1/secrets", json={"name": "API_KEY", "value": "sk-secret", "agent": "tester"})

    def evil_echo(buf, params, *, registry=None):
        raise RuntimeError(f"internal stack trace: secret={bytes(buf)!r}")

    # Build a fresh app with a custom registry whose echo raises the canary.
    import tempfile

    from rgt_vault.server.actions import ActionRegistry, ActionSpec
    from rgt_vault.server.auth import TokenStore, generate_token
    from rgt_vault.vault import VaultManager

    class _B:
        def get_secret(self):
            return b"\x06" * 32

        def rotate_secret(self):
            return b"\x06" * 32

    with tempfile.TemporaryDirectory() as td:
        v = VaultManager(
            db_path=os.path.join(td, "vault.db"),
            policy_yaml=POLICY,
            master_provider=_B(),
        )
        tok = generate_token()
        st = TokenStore(os.path.join(td, "server.token"))
        st.write(tok)
        reg = ActionRegistry()
        reg.register(
            ActionSpec(
                name="echo",
                fn=evil_echo,
                description="evil",
                params_schema=[],
            )
        )
        new_app = build_app(v, st, reg)
        c2 = TestClient(new_app)
        c2.headers["Authorization"] = f"Bearer {tok}"
        c2.post("/v1/secrets", json={"name": "API_KEY", "value": "sk-secret", "agent": "tester"})
        r = c2.post(
            "/v1/secrets/default/API_KEY/use",
            json={"action": "echo", "agent": "tester", "purpose": "test"},
        )
        assert r.status_code == 500, r.text
        body_text = r.text
        # The canary MUST NOT appear in the response -- not in any header,
        # body field, or anywhere.
        assert "sk-secret" not in body_text, f"Secret leaked in response: {body_text}"
        # The runtime exception's repr must not appear either.
        assert "RuntimeError" not in body_text
        assert "internal stack trace" not in body_text


# ------------------------------------------------------------------
# P0-4: scheme allow-list
# ------------------------------------------------------------------


def test_validate_headers_strips_host_header():
    """Caller-supplied Host headers must be dropped; urllib sets the right one."""
    out = _validate_headers({"Host": "evil.example", "X-Trace": "abc"})
    assert "Host" not in out and "host" not in out
    assert out["X-Trace"] == "abc"


def test_validate_headers_rejects_non_dict():
    with pytest.raises(ActionExecutionError, match="must be a JSON object"):
        _validate_headers("not a dict")


# ------------------------------------------------------------------
# P1-3 / P1-4: cmd_init does not print existing tokens
# ------------------------------------------------------------------


def test_cmd_init_prints_new_token(capsys, tmp_path, monkeypatch):
    """``rgt-vault init`` prints the new token only if it just created one."""
    from click.testing import CliRunner  # noqa

    # We don't actually invoke the CLI here -- invoke directly via the
    # main() function so we can assert the output.
    import sys

    monkeypatch.setattr(
        sys, "argv", ["rgt-vault", "--db", str(tmp_path / "v.db"), "init", "--token-file", str(tmp_path / "tok")]
    )
    from rgt_vault.cli import main

    rc = main()
    assert rc == 0
    out = capsys.readouterr().out
    # The token file should have been created.
    assert (tmp_path / "tok").exists()
    # And the token should be in stdout (newly created).
    token_line = [line for line in out.splitlines() if line.startswith("Bearer token:")]
    assert token_line, f"Expected a 'Bearer token:' line in output, got: {out!r}"


def test_cmd_init_does_not_print_existing_token(capsys, tmp_path, monkeypatch):
    """Running init twice must NOT re-print the existing token. The first
    run creates the file and prints it; the second run should say "already
    initialized" and not echo the token."""
    monkeypatch.setattr(
        "sys.argv", ["rgt-vault", "--db", str(tmp_path / "v.db"), "init", "--token-file", str(tmp_path / "tok")]
    )
    from rgt_vault.cli import main

    rc = main()
    assert rc == 0
    first_out = capsys.readouterr().out
    first_token = (
        [line for line in first_out.splitlines() if line.startswith("Bearer token:")][0].split(": ", 1)[1].strip()
    )

    # Second run: same file, same token, but it must NOT be re-printed.
    rc = main()
    assert rc == 0
    second_out = capsys.readouterr().out
    assert first_token not in second_out, f"Existing token was re-printed on second init: {second_out!r}"
    # The 'already initialized' hint should be present.
    assert "already" in second_out.lower() or "exists" in second_out.lower()


# ------------------------------------------------------------------
# Milestone 1: HTTP Headers & CORS Hardening Verification
# ------------------------------------------------------------------

def test_http_security_headers_are_present(server):
    """Verify that all standard security headers are applied to API responses."""
    app, token = server
    c = _authed(app, token)
    r = c.get("/healthz")
    assert r.status_code == 200

    # Strict-Transport-Security (RGT-454)
    assert r.headers["Strict-Transport-Security"] == "max-age=63072000; includeSubDomains; preload"
    
    # Referrer-Policy (RGT-454)
    assert r.headers["Referrer-Policy"] == "no-referrer"
    
    # X-Frame-Options (RGT-454)
    assert r.headers["X-Frame-Options"] == "DENY"
    
    # Content-Security-Policy (RGT-454)
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert "sandbox" in r.headers["Content-Security-Policy"]
    
    # X-Content-Type-Options (RGT-453 / RGT-438)
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    
    # Content-Disposition (RGT-453 / RGT-438)
    assert r.headers["Content-Disposition"] == 'attachment; filename="response.json"'


def test_docs_security_headers(server):
    """Verify that the Swagger UI (/docs) uses a specialized CSP but remains non-embeddable."""
    app, token = server
    c = _authed(app, token)
    r = c.get("/docs")
    assert r.status_code == 200
    
    csp = r.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "https://cdn.jsdelivr.net" in csp


def test_dns_rebinding_protection(server):
    """Verify that requests with unauthorized Host headers are rejected (RGT-436)."""
    app, token = server
    c = _authed(app, token)
    
    # Send request with an invalid Host header
    # By default, TrustedHostMiddleware returns 400 Bad Request
    r = c.get("/healthz", headers={"Host": "evil-domain.com"})
    assert r.status_code == 400


def test_post_request_enforces_json_content_type(server):
    """Verify that POST requests require Content-Type: application/json (RGT-453)."""
    app, token = server
    c = _authed(app, token)
    
    # Send POST request without application/json
    r = c.post(
        "/v1/secrets",
        headers={"Content-Type": "text/plain"},
        content="plain-text-payload"
    )
    assert r.status_code == 415
    assert "application/json" in r.json()["detail"]


def test_cors_disabled_by_default(server):
    """Verify that cross-origin requests are blocked/unallowed by default (RGT-436)."""
    app, token = server
    c = _authed(app, token)
    
    r = c.options("/healthz", headers={"Origin": "http://evil.com"})
    assert "Access-Control-Allow-Origin" not in r.headers


def test_secure_cookie_flags_enforced(server):
    """Verify that any Set-Cookie headers get secure flags appended automatically (RGT-453)."""
    app, token = server
    
    # Add a mock endpoint that sets a vulnerable cookie to verify middleware mitigation
    from fastapi import Response
    @app.get("/test-cookie-leak")
    def set_bad_cookie(response: Response):
        response.headers.append("Set-Cookie", "session=123")
        return {"ok": True}
        
    c = _authed(app, token)
    r = c.get("/test-cookie-leak")
    assert r.status_code == 200
    
    cookie_header = r.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie_header
    assert "Secure" in cookie_header
    assert "SameSite=Strict" in cookie_header


def test_server_header_and_debug_disclosure_stripped(server):
    """Verify component version disclosures and server headers are stripped (RGT-452)."""
    app, token = server
    c = _authed(app, token)
    
    # 1. Verify headers are not disclosed
    r = c.get("/healthz")
    assert "Server" not in r.headers
    assert "X-Powered-By" not in r.headers
    
    # 2. Verify debug mode is false on the app instance
    assert app.debug is False


def test_crossdomain_and_clientaccesspolicy_cache_disabled(server):
    """Verify crossdomain/clientaccesspolicy files return 404 and disable caching (RGT-437)."""
    app, token = server
    c = _authed(app, token)
    
    for path in ["/crossdomain.xml", "/clientaccesspolicy.xml"]:
        r = c.get(path)
        assert r.status_code == 404
        assert r.headers["Cache-Control"] == "no-store, no-cache, must-revalidate, max-age=0"
        assert r.headers["Pragma"] == "no-cache"
        assert r.headers["Expires"] == "0"


def test_production_environment_hides_documentation(monkeypatch, tmp_path, master_provider):
    """Verify that in production mode, docs and openapi.json are disabled (RGT-452)."""
    monkeypatch.setenv("APP_ENV", "production")
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
    c = _authed(app, token)
    
    # Docs should be disabled in production
    assert c.get("/docs").status_code == 404
    assert c.get("/redoc").status_code == 404
    assert c.get("/openapi.json").status_code == 404
    # The application version should also be suppressed/cleared
    assert app.version == ""


# ------------------------------------------------------------------
# Milestone 3 Security Controls tests (RGT-443 to RGT-448)
# ------------------------------------------------------------------

def test_m3_uri_normalization(server):
    """Verify URI normalization blocks path traversal and control characters (RGT-443)."""
    app, token = server
    c = _authed(app, token)
    
    # Test path traversal sequences
    assert c.get("/v1/secrets/..%2fsecrets").status_code == 400
    assert c.get("/v1/secrets/default\\\\key").status_code == 400
    assert c.get("/v1//secrets").status_code == 400
    assert c.get("/v1/secrets/default/key%2f..%2fuse").status_code == 400
    
    # Test control characters
    assert c.get("/v1/secrets/default/key%0Ause").status_code == 400
    assert c.get("/v1/secrets/default/key%00use").status_code == 400


def test_m3_csrf_protection(server):
    """Verify Double-Submit Cookie CSRF protection and Bearer bypass (RGT-447)."""
    app, token = server
    c = TestClient(app)
    
    # Safe request generates CSRF token
    r = c.get("/healthz")
    assert r.status_code == 200
    csrf_token = r.cookies.get("csrf_token")
    assert csrf_token is not None
    
    # POST without CSRF token should return 403 Forbidden
    r = c.post("/v1/secrets", json={"name": "csrf_key", "value": "val", "agent": "tester"})
    assert r.status_code == 403
    assert r.json()["error"] == "Forbidden"
    
    # POST with mismatched CSRF token should return 403 Forbidden
    c.cookies.set("csrf_token", csrf_token)
    r = c.post("/v1/secrets", json={"name": "csrf_key", "value": "val", "agent": "tester"}, headers={"X-CSRF-Token": "mismatch"})
    assert r.status_code == 403
    
    # POST with matching CSRF token but missing Bearer auth should return 401 Unauthorized (not 403)
    r = c.post("/v1/secrets", json={"name": "csrf_key", "value": "val", "agent": "tester"}, headers={"X-CSRF-Token": csrf_token})
    assert r.status_code == 401
    
    # POST with valid Bearer token should bypass CSRF verification entirely
    c_authed = _authed(app, token)
    r = c_authed.post("/v1/secrets", json={"name": "csrf_key", "value": "val", "agent": "tester"})
    assert r.status_code == 200


def test_m3_accept_header_validation(server):
    """Verify Accept header negotiation rejects unsupported formats (RGT-445)."""
    app, token = server
    c = _authed(app, token)
    
    # Accept: application/xml should return 406 Not Acceptable
    r = c.get("/healthz", headers={"Accept": "application/xml"})
    assert r.status_code == 406
    assert r.json()["error"] == "NotAcceptable"
    
    # Accept: application/json should return 200 OK
    r = c.get("/healthz", headers={"Accept": "application/json"})
    assert r.status_code == 200
    
    # Accept: */* should return 200 OK
    r = c.get("/healthz", headers={"Accept": "*/*"})
    assert r.status_code == 200


def test_m3_query_limits_and_pagination(server):
    """Verify pagination limits and bounds on secrets listing (RGT-448)."""
    app, token = server
    c = _authed(app, token)
    
    # Validate bounds raise 400
    assert c.get("/v1/secrets", params={"namespace": "default", "agent": "tester", "limit": 0}).status_code == 400
    assert c.get("/v1/secrets", params={"namespace": "default", "agent": "tester", "limit": 1001}).status_code == 400
    assert c.get("/v1/secrets", params={"namespace": "default", "agent": "tester", "offset": -1}).status_code == 400
    
    # Insert mock secrets
    for i in range(5):
        c.post("/v1/secrets", json={"name": f"pagination_key_{i}", "value": f"val_{i}", "agent": "tester"})
        
    # Test limit
    r = c.get("/v1/secrets", params={"namespace": "default", "agent": "tester", "limit": 2})
    assert r.status_code == 200
    secrets = r.json()["secrets"]
    assert len(secrets) == 2
    
    # Test offset
    r = c.get("/v1/secrets", params={"namespace": "default", "agent": "tester", "limit": 2, "offset": 2})
    assert r.status_code == 200
    secrets_offset = r.json()["secrets"]
    assert len(secrets_offset) == 2
    assert secrets[0]["name"] != secrets_offset[0]["name"]


def test_m3_json_schema_validation_capability(server):
    """Verify JSON Schema and Pydantic model validation on Capability execution (RGT-446)."""
    app, token = server
    c = _authed(app, token)
    
    # Register a capability using a Pydantic model for validation
    from pydantic import BaseModel, Field
    class MockParams(BaseModel):
        email: str
        age: int = Field(..., ge=0)
        
    def cap_handler(payload, ctx):
        return {"ok": True, "email": payload["email"]}
        
    app.vault.capability_registry.register(
        name="custom.m3_pydantic",
        handler=cap_handler,
        supported_versions={1},
        params_schema=MockParams,
    )
    
    # Test execution validation: missing field (email)
    r = c.post(
        "/v1/capabilities/execute",
        json={
            "capability": "custom.m3_pydantic",
            "agent_id": "tester",
            "capability_token": "dummy",
            "capability_version": 1,
            "payload": {"age": 25},
        }
    )
    # Pydantic validation fails -> 400 ValidationError
    assert r.status_code == 400
    assert "ValidationError" in r.json()["error"]
    
    # Test execution validation: invalid field type
    r = c.post(
        "/v1/capabilities/execute",
        json={
            "capability": "custom.m3_pydantic",
            "agent_id": "tester",
            "capability_token": "dummy",
            "capability_version": 1,
            "payload": {"email": "test@example.com", "age": -5},
        }
    )
    assert r.status_code == 400
    assert "ValidationError" in r.json()["error"]
    
    # Test execution validation: valid payload
    spec = app.vault.capability_registry.get("custom.m3_pydantic")
    spec.validate_payload({"email": "test@example.com", "age": 30}) # passes without error
    
    # Test JSON Schema dict validation
    json_schema = {
        "type": "object",
        "required": ["email"],
        "properties": {
            "email": {"type": "string"},
            "age": {"type": "integer"},
        },
        "additionalProperties": False,
    }
    app.vault.capability_registry.register(
        name="custom.m3_jsonschema",
        handler=cap_handler,
        supported_versions={1},
        params_schema=json_schema,
    )
    spec_json = app.vault.capability_registry.get("custom.m3_jsonschema")
    
    # Missing required email
    from rgt_vault.exceptions import ValidationError
    import pytest
    with pytest.raises(ValidationError):
        spec_json.validate_payload({"age": 30})
        
    # Additional property not allowed
    with pytest.raises(ValidationError):
        spec_json.validate_payload({"email": "test@example.com", "extra": "prop"})
        
    # Valid schema payload passes
    spec_json.validate_payload({"email": "test@example.com", "age": 30})


def test_m3_multi_level_revocation_auth(server):
    """Verify ABAC policy is evaluated during secret revocation (RGT-444)."""
    app, token = server
    c = _authed(app, token)
    
    # Create a secret
    c.post("/v1/secrets", json={"name": "key_to_revoke", "value": "secret", "agent": "tester"})
    
    # Revoke with unauthorized agent (e.g. intruder)
    r = c.post("/v1/secrets/default/key_to_revoke/revoke?agent=intruder")
    assert r.status_code == 403
    assert r.json()["error"] == "PolicyDeniedError"
    
    # Revoke with authorized agent (tester)
    r = c.post("/v1/secrets/default/key_to_revoke/revoke?agent=tester")
    assert r.status_code == 200


def test_swagger_ui_and_redoc_sri_hashes(server):
    """Verify that Swagger UI and ReDoc pages implement Subresource Integrity (RGT-451)."""
    app, token = server
    c = _authed(app, token)
    
    # 1. Verify Swagger UI
    r_docs = c.get("/docs")
    assert r_docs.status_code == 200
    html_docs = r_docs.text
    # Ensure pinned version is used
    assert "/npm/swagger-ui-dist@5.17.14/" in html_docs
    # Ensure integrity attributes exist for both script and stylesheet
    assert 'integrity="sha384-wmyclcVGX/WhUkdkATwhaK1X1JtiNrr2EoYJ+diV3vj4v6OC5yCeSu+yW13SYJep"' in html_docs
    assert 'integrity="sha384-wxLW6kwyHktdDGr6Pv1zgm/VGJh99lfUbzSn6HNHBENZlCN7W602k9VkGdxuFvPn"' in html_docs
    assert 'crossorigin="anonymous"' in html_docs
    
    # 2. Verify ReDoc
    r_redoc = c.get("/redoc")
    assert r_redoc.status_code == 200
    html_redoc = r_redoc.text
    assert "/npm/redoc@2.1.3/" in html_redoc
    assert 'integrity="sha384-R8e5ippgVo+kphHRsZE026R4rLIN/ORakEnRnOJ3S7BauiXHeD2EnvDpCcPYV4O/"' in html_redoc
    assert 'crossorigin="anonymous"' in html_redoc


