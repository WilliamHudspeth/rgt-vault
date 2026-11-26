"""Tests for internal/llm maintainer tooling: RGT-86, RGT-90, RGT-91.

internal/ is not part of the shipped package, but it is importable from the
repo root (pytest rootdir), so these run in CI with the rest of tests/.
"""

from __future__ import annotations

import logging
import os
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from internal.llm import kanban_loop  # noqa: E402
from internal.llm.router import DEFAULT_ROUTES_PATH, RouteConfig, Router  # noqa: E402
from internal.llm.types import Reply  # noqa: E402


class _Provider:
    """Provider that counts is_available()/complete() calls."""

    def __init__(self, name, reply=None, exc=None):
        self.name = name
        self.model = f"{name}-model"
        self._reply = reply or Reply(text="ok", provider=name, model=self.model)
        self._exc = exc
        self.available_calls = 0
        self.complete_calls = 0

    def is_available(self):
        self.available_calls += 1
        return True

    def complete(self, prompt, **kw):
        self.complete_calls += 1
        if self._exc:
            raise self._exc
        return self._reply


def _router(providers: dict, chain: list) -> Router:
    r = Router(RouteConfig(chains={"t": chain}))
    setattr(r, "_get", lambda spec: providers[spec])
    return r


# ---- RGT-86: single complete() call, failure == unavailable ----------------


def test_call_does_not_probe_is_available():
    p = _Provider("a")
    reply = _router({"a": p}, ["a"]).call("t", "hi")
    assert reply.ok
    assert p.complete_calls == 1
    assert p.available_calls == 0


def test_call_unavailable_reply_falls_through_to_next_provider():
    down = _Provider("down", reply=Reply(text="", provider="down", model="m", error="binary not on PATH"))
    up = _Provider("up")
    reply = _router({"down": down, "up": up}, ["down", "up"]).call("t", "hi")
    assert reply.ok and reply.provider == "up"
    assert (down.complete_calls, down.available_calls) == (1, 0)
    assert reply.raw["_router_skipped"] == [("down", "binary not on PATH")]


def test_call_exception_counts_as_unavailable_and_chain_continues():
    boom = _Provider("boom", exc=RuntimeError("gone"))
    up = _Provider("up")
    reply = _router({"boom": boom, "up": up}, ["boom", "up"]).call("t", "hi")
    assert reply.ok and reply.provider == "up"
    assert (boom.complete_calls, boom.available_calls, up.available_calls) == (1, 0, 0)
    assert reply.raw["_router_skipped"][0][0] == "boom"


def test_call_dry_run_probes_but_never_completes():
    p = _Provider("a")
    reply = _router({"a": p}, ["a"]).call("t", "", dry_run=True)
    assert reply.error and reply.error.startswith("dry-run")
    assert p.available_calls == 1 and p.complete_calls == 0


def test_call_parallel_calls_complete_once_without_probe():
    a, b = _Provider("a"), _Provider("b", reply=Reply(text="", provider="b", model="m", error="unavailable"))
    out = _router({"a": a, "b": b}, ["a", "b"]).call_parallel(["a", "b"], "hi", timeout=5)
    by_spec = dict(out)
    assert by_spec["a"].ok and not by_spec["b"].ok
    for p in (a, b):
        assert p.complete_calls == 1 and p.available_calls == 0


def test_dispatch_exception_becomes_error_reply():
    p = _Provider("a", exc=ConnectionError("x"))
    out = _router({"a": p}, ["a"]).call_parallel(["a"], "hi", timeout=5)
    assert out[0][1].error.startswith("exception: ConnectionError")
    assert (p.complete_calls, p.available_calls) == (1, 0)


def test_dry_run_skips_unavailable_and_probe_exceptions():
    down, boom, up = _Provider("down"), _Provider("boom"), _Provider("up")
    setattr(down, "is_available", lambda: False)

    def _raise():
        raise RuntimeError("probe broke")

    setattr(boom, "is_available", _raise)
    reply = _router({"down": down, "boom": boom, "up": up}, ["down", "boom", "up"]).call("t", "", dry_run=True)
    assert reply.provider == "up" and reply.error.startswith("dry-run")
    assert up.complete_calls == 0


def test_chain_exhaustion_calls_each_provider_once_without_probe():
    a = _Provider("a", reply=Reply(text="", provider="a", model="m", error="e1"))
    b = _Provider("b", exc=RuntimeError("e2"))
    reply = _router({"a": a, "b": b}, ["a", "b"]).call("t", "hi")
    assert not reply.ok and reply.provider == "<chain-exhausted>"
    assert [(p.complete_calls, p.available_calls) for p in (a, b)] == [(1, 0), (1, 0)]


# ---- RGT-91: default() matches routes.yaml; missing file is loud ----------


def test_default_security_review_is_claude_first_without_groq():
    d = RouteConfig.default()
    assert d.chains["security-review"][0] == "claude-cli"
    assert "groq" not in d.chains["security-review"]


def test_default_matches_routes_yaml():
    data = yaml.safe_load(DEFAULT_ROUTES_PATH.read_text())
    d = RouteConfig.default()
    assert d.chains == data["chains"]
    assert d.pairs == data["pairs"]
    assert d.writers == data["writers"]


def test_missing_routes_file_logs_error_and_uses_default(tmp_path, caplog):
    missing = tmp_path / "nope.yaml"
    with caplog.at_level(logging.ERROR, logger="internal.llm.router"):
        cfg = RouteConfig.load(missing, load_env=False)
    default = RouteConfig.default()
    assert (cfg.chains, cfg.pairs, cfg.writers) == (default.chains, default.pairs, default.writers)
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and str(missing) in errors[0].getMessage()


def test_existing_routes_file_does_not_log_error(caplog):
    with caplog.at_level(logging.ERROR, logger="internal.llm.router"):
        RouteConfig.load(DEFAULT_ROUTES_PATH, load_env=False)
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


# ---- RGT-90: private state dir + atomic 0600 write ----------------------


def test_default_state_path_is_not_in_tmp_and_follows_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    assert kanban_loop.default_state_dir() == tmp_path / "xdg" / "rgt-vault"
    monkeypatch.delenv("XDG_STATE_HOME")
    assert kanban_loop.default_state_dir() == Path.home() / ".local" / "state" / "rgt-vault"
    monkeypatch.setenv("XDG_STATE_HOME", "relative/dir")  # non-absolute is ignored per XDG spec
    assert kanban_loop.default_state_dir() == Path.home() / ".local" / "state" / "rgt-vault"
    assert kanban_loop.DEFAULT_STATE_PATH == kanban_loop.default_state_dir() / "kanban_loop_state.json"


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_save_state_creates_0700_dir_and_0600_file(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    old_umask = os.umask(0o022)  # permissive umask must not leak through
    try:
        path = kanban_loop.default_state_dir() / "kanban_loop_state.json"
        kanban_loop.save_state({"processed": {"a": 1}, "last_run": None}, path)
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert kanban_loop.load_state(path)["processed"] == {"a": 1}
    assert [p.name for p in path.parent.iterdir()] == [path.name]  # no temp leftovers


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_save_state_tightens_loose_default_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    d = kanban_loop.default_state_dir()
    d.mkdir(parents=True, mode=0o755)
    d.chmod(0o755)
    kanban_loop.save_state({"processed": {}, "last_run": None}, d / "s.json")
    assert stat.S_IMODE(d.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_save_state_overwrites_existing_loose_file_as_0600(tmp_path):
    path = tmp_path / "s.json"
    path.write_text("{}")
    path.chmod(0o666)
    kanban_loop.save_state({"processed": {"x": 2}, "last_run": None}, path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert kanban_loop.load_state(path)["processed"] == {"x": 2}


def test_write_is_atomic_original_survives_failed_write(monkeypatch, tmp_path):
    path = tmp_path / "s.json"
    path.write_text('{"processed": {"keep": 1}, "last_run": null}')
    monkeypatch.setattr(kanban_loop.os, "replace", MagicMock(side_effect=OSError("disk")))
    with pytest.raises(OSError):
        kanban_loop.save_state({"processed": {}, "last_run": None}, path)
    assert kanban_loop.load_state(path)["processed"] == {"keep": 1}
    assert [p.name for p in tmp_path.iterdir()] == ["s.json"]  # temp file cleaned up


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks/uid")
def test_write_private_text_does_not_follow_planted_symlink(tmp_path):
    """A pre-planted symlink at the target is replaced, not written through."""
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched")
    link = tmp_path / "s.json"
    link.symlink_to(victim)
    kanban_loop.write_private_text(link, "new")
    assert victim.read_text() == "untouched"
    assert not link.is_symlink() and link.read_text() == "new"


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_default_state_dir_symlink_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    victim = tmp_path / "victim"
    victim.mkdir(mode=0o755)
    kanban_loop.default_state_dir().symlink_to(victim)
    with pytest.raises(PermissionError, match="symlink"):
        kanban_loop.save_state({"processed": {}, "last_run": None}, kanban_loop.default_state_dir() / "s.json")
    assert stat.S_IMODE(victim.stat().st_mode) == 0o755 and not list(victim.iterdir())


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_default_state_dir_with_special_bits_is_reset_to_0700(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    d = kanban_loop.default_state_dir()
    d.mkdir(parents=True)
    d.chmod(0o2700)  # setgid, otherwise no group/other bits
    kanban_loop.save_state({"processed": {}, "last_run": None}, d / "s.json")
    assert stat.S_IMODE(d.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks/uid")
def test_default_state_dir_owned_by_someone_else_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setattr(kanban_loop.os, "getuid", lambda: os.stat(tmp_path).st_uid + 1)
    with pytest.raises(PermissionError, match="not owned"):
        kanban_loop.save_state({"processed": {}, "last_run": None}, kanban_loop.default_state_dir() / "s.json")


def test_failed_temp_cleanup_does_not_mask_original_error(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(kanban_loop.os, "replace", MagicMock(side_effect=OSError("replace failed")))
    monkeypatch.setattr(kanban_loop.os, "unlink", MagicMock(side_effect=PermissionError("cannot unlink")))
    with caplog.at_level(logging.DEBUG, logger="internal.llm.kanban_loop"):
        with pytest.raises(OSError, match="replace failed"):
            kanban_loop.write_private_text(tmp_path / "s.json", "x")
    assert any("could not remove temp state file" in r.getMessage() for r in caplog.records)
