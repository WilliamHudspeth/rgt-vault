"""RGT-161 dual-write shadow tests.

Two layers:
  * Unit tests for rgt_vault.shadow (drafted via Groq, reviewed): the
    ShadowWriter/NullShadowWriter/shadow_from_env API with _http monkeypatched
    so no real network is used.
  * Integration tests for the VaultManager wiring: an enabled shadow writer
    emits SHADOW_WRITE / SHADOW_DIVERGENCE audit rows, the default (disabled)
    path stays byte-for-byte unchanged, and a shadow failure never breaks the
    authoritative Python write (chaos invariant).
"""

import os
import threading
import urllib.error

import pytest

from rgt_vault import shadow
from rgt_vault.shadow import ShadowWriter
from rgt_vault.vault import VaultManager

# ---------------------------------------------------------------------------
# Unit tests: rgt_vault.shadow in isolation (_http monkeypatched)
# ---------------------------------------------------------------------------


def fake_http_set_get(method, url, token, body, timeout=2.0):
    if method == "POST":
        return 201, b"{}"
    elif method == "GET":
        return 200, b'{"namespace":"ns","secrets":[{"name":"k","value":"v"}]}'


def fake_http_set_get_mismatch(method, url, token, body, timeout=2.0):
    if method == "POST":
        return 201, b"{}"
    elif method == "GET":
        return 200, b'{"namespace":"ns","secrets":[{"name":"k","value":"WRONG"}]}'


def fake_http_post_non_2xx(method, url, token, body, timeout=2.0):
    if method == "POST":
        return 500, b"err"
    elif method == "GET":
        return 200, b"{}"


def fake_http_revoke_success(method, url, token, body, timeout=2.0):
    return 200, b"{}"


def fake_http_connection_refused(method, url, token, body, timeout=2.0):
    raise urllib.error.URLError("connection refused")


@pytest.fixture
def shadow_writer():
    return shadow.ShadowWriter("http://example.com", "token")


def test_null_shadow_writer_is_noop():
    writer = shadow.NullShadowWriter()
    assert writer.mirror_set("ns", "k", "v") is True
    assert writer.mirror_revoke("ns", "k") is True
    assert writer.divergence_count() == 0
    assert writer.enabled is False


def test_shadow_from_env_unset_returns_null(monkeypatch):
    monkeypatch.delenv("RGT_VAULT_SHADOW_URL", raising=False)
    monkeypatch.delenv("RGT_VAULT_SHADOW_TOKEN", raising=False)
    writer = shadow.shadow_from_env()
    assert isinstance(writer, shadow.NullShadowWriter)


def test_shadow_from_env_set_returns_shadow(monkeypatch):
    monkeypatch.setenv("RGT_VAULT_SHADOW_URL", "http://example.com")
    monkeypatch.setenv("RGT_VAULT_SHADOW_TOKEN", "token")
    writer = shadow.shadow_from_env()
    assert isinstance(writer, shadow.ShadowWriter)
    assert writer.base_url == "http://example.com"


def test_mirror_set_success(monkeypatch, shadow_writer):
    monkeypatch.setattr(shadow, "_http", fake_http_set_get)
    assert shadow_writer.mirror_set("ns", "k", "v") is True
    assert shadow_writer.divergence_count() == 0


def test_mirror_set_value_mismatch_records_divergence(monkeypatch, shadow_writer):
    monkeypatch.setattr(shadow, "_http", fake_http_set_get_mismatch)
    assert shadow_writer.mirror_set("ns", "k", "v") is False
    assert shadow_writer.divergence_count() == 1
    divergences = shadow_writer.divergences()
    assert len(divergences) == 1
    assert divergences[0].op == "set"


def test_mirror_set_post_non_2xx_records_divergence(monkeypatch, shadow_writer):
    monkeypatch.setattr(shadow, "_http", fake_http_post_non_2xx)
    assert shadow_writer.mirror_set("ns", "k", "v") is False
    assert shadow_writer.divergence_count() == 1


def test_mirror_revoke_success(monkeypatch, shadow_writer):
    monkeypatch.setattr(shadow, "_http", fake_http_revoke_success)
    assert shadow_writer.mirror_revoke("ns", "k") is True
    assert shadow_writer.divergence_count() == 0


def test_mirror_set_connection_refused_never_raises(monkeypatch, shadow_writer):
    monkeypatch.setattr(shadow, "_http", fake_http_connection_refused)
    assert shadow_writer.mirror_set("ns", "k", "v") is False
    assert shadow_writer.divergence_count() == 1


# ---------------------------------------------------------------------------
# Integration tests: VaultManager dual-write wiring
# ---------------------------------------------------------------------------

_POLICY = """
rules:
  - effect: allow
    agent: system
    namespace: "*"
    action: write
  - effect: allow
    agent: system
    namespace: "*"
    action: read
"""


class _FakeShadow(ShadowWriter):
    """In-memory shadow stand-in: records calls, can be forced to fail."""

    enabled = True

    def __init__(self, fail: bool = False):
        self.fail = fail
        self.sets = []
        self.revokes = []
        self._divergences = []
        self._lock = threading.Lock()

    def mirror_set(self, namespace, name, value, agent="system", purpose=""):
        self.sets.append((namespace, name, value))
        return not self.fail

    def mirror_revoke(self, namespace, name):
        self.revokes.append((namespace, name))
        return not self.fail


def _build_vault(tmpdir, master_provider, shadow_writer=None):
    return VaultManager(
        db_path=os.path.join(tmpdir, "vault.db"),
        policy_yaml=_POLICY,
        master_provider=master_provider,
        shadow_writer=shadow_writer,
    )


def _audit_actions(vault):
    return [e.get("action") for e in vault.get_audit_log(limit=200)]


def test_default_vault_emits_no_shadow_audit(temp_vault_dir, master_provider):
    """Disabled (default) path must add zero SHADOW_* audit rows."""
    vault = _build_vault(temp_vault_dir, master_provider)
    vault.set_secret("k", "v", namespace="ns")
    actions = _audit_actions(vault)
    assert not any(a and a.startswith("SHADOW_") for a in actions)


def test_enabled_shadow_logs_write_and_forwards(temp_vault_dir, master_provider):
    fake = _FakeShadow()
    vault = _build_vault(temp_vault_dir, master_provider, shadow_writer=fake)
    vault.set_secret("k", "v", namespace="ns")
    assert ("ns", "k", "v") in fake.sets
    assert "SHADOW_WRITE" in _audit_actions(vault)


def test_shadow_failure_logs_divergence_but_set_succeeds(temp_vault_dir, master_provider):
    """Chaos invariant: Go shadow failing must NOT break the Python write."""
    fake = _FakeShadow(fail=True)
    vault = _build_vault(temp_vault_dir, master_provider, shadow_writer=fake)
    # Must not raise even though the shadow reports failure.
    vault.set_secret("k", "v", namespace="ns")
    actions = _audit_actions(vault)
    assert "SHADOW_DIVERGENCE" in actions
    # Authoritative Python read still returns the value.
    with vault.lease_secret("k", agent="system", namespace="ns", purpose="t") as buf:
        assert bytes(buf) == b"v"


def test_enabled_shadow_logs_revoke(temp_vault_dir, master_provider):
    fake = _FakeShadow()
    vault = _build_vault(temp_vault_dir, master_provider, shadow_writer=fake)
    vault.set_secret("k", "v", namespace="ns")
    vault.revoke_secret("ns", "k")
    assert ("ns", "k") in fake.revokes
