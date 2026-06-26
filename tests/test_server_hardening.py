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
