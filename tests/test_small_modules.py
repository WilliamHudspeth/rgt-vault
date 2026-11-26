"""Behavioural tests for small, previously untested modules (RGT-261 coverage gate).

Covers: FreezeWatcher, the LLM guide text, the Postgres read-only PoC (with a
fake ``psycopg2``), the audit/log-redaction hooks, and the MCP server shim (with
a fake ``fastmcp``). The hook/MCP modules use PEP 604 syntax at runtime and so
need Python >= 3.10.
"""

import asyncio
import hashlib
import importlib
import logging
import sys
import tempfile
import threading
import time
import types
from pathlib import Path
from unittest import mock

import pytest

needs_py310 = pytest.mark.skipif(sys.version_info < (3, 10), reason="module uses X | Y annotations / slots=True")


# --------------------------------------------------------------------------- #
# FreezeWatcher
# --------------------------------------------------------------------------- #


def test_freeze_watcher_fires_callback_when_signal_file_appears():
    from rgt_vault.watcher import FreezeWatcher

    fired = threading.Event()
    with tempfile.TemporaryDirectory() as d:
        signal = Path(d) / "freeze"
        w = FreezeWatcher(str(signal), interval=0.01, callback=fired.set)
        w.start()
        time.sleep(0.05)
        assert not w.is_frozen
        signal.write_text("x")
        assert fired.wait(timeout=5)
        w.join(timeout=5)
        assert w.is_frozen


def test_freeze_watcher_swallows_callback_errors_and_stops():
    from rgt_vault.watcher import FreezeWatcher

    with tempfile.TemporaryDirectory() as d:
        signal = Path(d) / "freeze"
        signal.write_text("x")

        def boom():
            raise RuntimeError("nope")

        w = FreezeWatcher(str(signal), interval=0.01, callback=boom)
        w.start()
        w.join(timeout=5)
        assert w.is_frozen
        assert not w.is_alive()

    idle = FreezeWatcher("/nonexistent/rgt-freeze-signal", interval=0.01)
    idle.start()
    idle.stop()
    idle.join(timeout=5)
    assert not idle.is_frozen


# --------------------------------------------------------------------------- #
# llm_guide
# --------------------------------------------------------------------------- #


def test_llm_guide_contains_docstring_and_instructions():
    from rgt_vault import llm_guide

    text = llm_guide.get_llm_guide()
    assert text.startswith("#!/usr/bin/env python3") or "LLM Knowledge Guide" in text
    assert "Secure Vault Manager" in text
    assert llm_guide.LLM_INSTRUCTIONS in text


# --------------------------------------------------------------------------- #
# Postgres read-only PoC (fake psycopg2)
# --------------------------------------------------------------------------- #


@pytest.fixture
def postgres_backend(monkeypatch):
    fake_pool_mod = types.ModuleType("psycopg2.pool")
    fake_pool_mod.ThreadedConnectionPool = mock.MagicMock()
    fake_pg = types.ModuleType("psycopg2")
    fake_pg.pool = fake_pool_mod
    monkeypatch.setitem(sys.modules, "psycopg2", fake_pg)
    monkeypatch.setitem(sys.modules, "psycopg2.pool", fake_pool_mod)
    monkeypatch.delitem(sys.modules, "rgt_vault.storage.postgres", raising=False)
    mod = importlib.import_module("rgt_vault.storage.postgres")
    backend = mod.PostgresStorageBackendPoC("dbname=test")
    conn = backend.pool.getconn.return_value
    cursor = conn.cursor.return_value.__enter__.return_value
    yield mod, backend, conn, cursor
    sys.modules.pop("rgt_vault.storage.postgres", None)


def test_postgres_poc_active_version_query(postgres_backend):
    _, backend, _, cursor = postgres_backend
    ct = b"ciphertext-bytes"
    cursor.fetchone.return_value = (ct, hashlib.sha256(ct).hexdigest(), 3)
    assert backend.get_secret("ns", "name") == (ct, 3)
    sql = cursor.execute.call_args[0][0]
    assert "status = 'ACTIVE'" in sql
    backend.pool.putconn.assert_called_once()


def test_postgres_poc_pinned_version_and_memoryview(postgres_backend):
    _, backend, _, cursor = postgres_backend
    ct = b"abc123"
    cursor.fetchone.return_value = (memoryview(ct), hashlib.sha256(ct).hexdigest(), 7)
    assert backend.get_secret("ns", "name", version=2) == (ct, 7)
    sql, params = cursor.execute.call_args[0]
    assert "version = %s" in sql
    assert params == ("ns", "name", 2)


def test_postgres_poc_missing_row_returns_none(postgres_backend):
    _, backend, _, cursor = postgres_backend
    cursor.fetchone.return_value = None
    assert backend.get_secret("ns", "name") is None
    backend.pool.putconn.assert_called_once()


def test_postgres_poc_checksum_mismatch_raises_and_releases_connection(postgres_backend):
    from rgt_vault.exceptions import ChecksumError

    _, backend, _, cursor = postgres_backend
    cursor.fetchone.return_value = (b"tampered", "0" * 64, 1)
    with pytest.raises(ChecksumError):
        backend.get_secret("ns", "name")
    backend.pool.putconn.assert_called_once()


# --------------------------------------------------------------------------- #
# hooks: audit.RequestContext + log_redaction
# --------------------------------------------------------------------------- #


@needs_py310
def test_request_context_hash_is_deterministic_and_input_sensitive():
    from rgt_vault.hooks import RequestContext

    base = dict(agent_id="a", capability_id="c", version="1", timestamp_ns=1, nonce=b"n")
    h1 = RequestContext(**base).context_hash()
    assert h1 == RequestContext(**base).context_hash()
    assert len(h1) == 64
    for field, value in (
        ("agent_id", "b"),
        ("capability_id", "d"),
        ("version", "2"),
        ("timestamp_ns", 2),
        ("nonce", b"m"),
    ):
        assert RequestContext(**{**base, field: value}).context_hash() != h1


@needs_py310
def test_audit_hook_is_abstract():
    from rgt_vault.hooks import AuditHook

    with pytest.raises(TypeError):
        AuditHook()


@needs_py310
def test_redact_masks_sensitive_keys_recursively_and_high_entropy_strings():
    from rgt_vault.hooks.log_redaction import redact

    out = redact(
        {
            "user": "alice",
            "password": "hunter2",
            "nested": {"api_key": "k", "note": "fine"},
            "items": [{"token": "t"}, "short"],
            "blob": b"\x00\x01\x02",
            "long": "A" * 30,
            "n": 5,
        }
    )
    assert out["user"] == "alice"
    assert out["password"] == "[REDACTED]"
    assert out["nested"] == {"api_key": "[REDACTED]", "note": "fine"}
    assert out["items"] == [{"token": "[REDACTED]"}, "short"]
    assert out["blob"] == "<3 bytes redacted>"
    assert out["long"] == "AAAA...[REDACTED]"
    assert out["n"] == 5


@needs_py310
def test_log_redaction_hook_never_logs_raw_secret_material(caplog):
    from rgt_vault.hooks import RequestContext
    from rgt_vault.hooks.log_redaction import LogRedactionHook

    logger = logging.getLogger("rgt_vault.test_audit")
    hook = LogRedactionHook(logger)
    assert logger.propagate is False
    ctx = RequestContext("agent-1", "cap-1", "1.0", 42, b"nonce")

    records = []

    class _Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    logger.addHandler(_Capture())
    logger.setLevel(logging.INFO)

    hook.on_capability_request(ctx, {"parameters": {"password": "s3cr3t-value", "region": "eu"}})
    hook.on_capability_grant(ctx, 60)
    hook.on_secret_access(ctx, "secret-id", "read")
    hook.on_capability_complete(ctx, True, None)
    hook.on_capability_complete(ctx, False, "bad token supplied")
    hook.on_capability_complete(ctx, False, "timeout")
    hook.on_hook_error("x", RuntimeError("boom"))  # default no-op

    joined = "\n".join(records)
    assert "s3cr3t-value" not in joined
    assert "[REDACTED]" in joined
    assert "region" in joined and "eu" in joined
    assert "capability_grant" in joined and "ttl=60" in joined
    assert "secret_access: agent=agent-1 secret_id=secret-id op=read" in joined
    assert "error=timeout" in joined
    assert "bad token supplied" not in joined
    assert ctx.context_hash() in joined


@needs_py310
def test_log_redaction_hook_defaults_to_audit_logger():
    from rgt_vault.hooks.log_redaction import LogRedactionHook

    assert LogRedactionHook().log.name == "rgt_vault.audit"


# --------------------------------------------------------------------------- #
# MCP server shim (fake fastmcp)
# --------------------------------------------------------------------------- #


@pytest.fixture
def mcp_module(monkeypatch):
    class _Ctx:
        def __init__(self):
            self.infos, self.errors = [], []

        async def info(self, msg):
            self.infos.append(msg)

        async def error(self, msg):
            self.errors.append(msg)

    class _FastMCP:
        def __init__(self, name):
            self.name = name

        def tool(self):
            return lambda fn: fn

        def resource(self, uri):
            return lambda fn: fn

        def run(self):  # pragma: no cover - never invoked
            raise AssertionError

    fake = types.ModuleType("fastmcp")
    fake.Context = _Ctx
    fake.FastMCP = _FastMCP
    monkeypatch.setitem(sys.modules, "fastmcp", fake)
    monkeypatch.delitem(sys.modules, "rgt_vault.server.mcp_server", raising=False)
    mod = importlib.import_module("rgt_vault.server.mcp_server")
    yield mod, _Ctx
    sys.modules.pop("rgt_vault.server.mcp_server", None)


@needs_py310
def test_mcp_vault_execute_success_and_error_mapping(mcp_module, monkeypatch):
    mod, Ctx = mcp_module
    vault = mock.MagicMock()
    vault.execute_capability.return_value = {"done": True}
    monkeypatch.setattr(mod, "get_vault", lambda: vault)

    ctx = Ctx()
    out = asyncio.run(mod.vault_execute("agent", "cap", parameters={"a": 1}, ctx=ctx))
    assert out == {"ok": True, "result": {"done": True}}
    assert ctx.infos and "cap" in ctx.infos[0]
    vault.execute_capability.assert_called_once_with(
        agent_id="agent", capability_id="cap", version="1.0", parameters={"a": 1}
    )

    vault.execute_capability.side_effect = PermissionError("denied: details")
    ctx = Ctx()
    assert asyncio.run(mod.vault_execute("agent", "cap", ctx=ctx)) == {"ok": False, "error": "unauthorized"}
    assert ctx.errors == ["denied: details"]

    vault.execute_capability.side_effect = ValueError("internal detail")
    ctx = Ctx()
    res = asyncio.run(mod.vault_execute("agent", "cap", ctx=ctx))
    assert res == {"ok": False, "error": "execution_failed"}
    # the exception message must not leak to the caller or the MCP context
    assert ctx.errors == ["ValueError"]

    # no ctx is fine too
    assert asyncio.run(mod.vault_execute("agent", "cap")) == {"ok": False, "error": "execution_failed"}


@needs_py310
def test_mcp_helpers(mcp_module, monkeypatch, tmp_path, master_provider):
    mod, _ = mcp_module
    from rgt_vault.hooks.log_redaction import LogRedactionHook
    from rgt_vault.vault import VaultManager

    real = VaultManager

    def _factory(policy_yaml=""):
        return real(db_path=str(tmp_path / "v.db"), master_provider=master_provider, policy_yaml=policy_yaml)

    monkeypatch.setattr(mod, "VaultManager", _factory)
    vault = mod.get_vault()
    assert isinstance(vault.hook, LogRedactionHook)
    assert mod.vault_list_capabilities() == []
    summary = mod.get_policy_summary()
    assert summary["default_ttl"] == 300
    assert summary["rules"] == len(vault.auth.rules)
