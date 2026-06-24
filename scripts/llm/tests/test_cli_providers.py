"""Tests for providers/cli.py timeout + killpg behavior.

OPUS-8 originally claimed to killpg on subprocess timeout but used
subprocess.run, which doesn't expose a handle, so _kill_pg() was never
reachable. These tests pin the fix: Popen + start_new_session=True,
killpg on timeout, scrub before trunc, --model on gemini.
"""

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest


def _make_fake_binary(path: Path, body: str) -> None:
    # Use `exec < /dev/null` to detach stdin so the subprocess doesn't
    # block waiting for input the parent never sends. Real CLIs read
    # stdin once and exit; without this our fake stays alive forever.
    path.write_text(f"#!/bin/bash\nexec < /dev/null\n{body}\n")
    path.chmod(0o755)


def _force_which(name: str, body: str) -> "callable":
    """Create a fake binary named `name` on PATH and patch shutil.which.

    `name` is the binary name (e.g. "gemini"); `body` is the bash body
    the fake will run. We create a temp file named `name` in a temp dir
    and prepend that dir to PATH, so subprocess.Popen(['name', ...])
    resolves to our fake via the env (not via shutil.which).
    """
    import tempfile

    tmpdir = tempfile.mkdtemp(prefix="rgt_fakebin_")
    target = Path(tmpdir) / name
    target.write_text(f"#!/bin/bash\nexec < /dev/null\n{body}\n")
    target.chmod(0o755)
    orig_path = os.environ.get("PATH", "")
    os.environ["PATH"] = str(tmpdir) + os.pathsep + orig_path

    def restore():
        os.environ["PATH"] = orig_path
        try:
            target.unlink()
            Path(tmpdir).rmdir()
        except Exception:
            pass

    return restore


def test_claude_timeout_killpg(tmp_path):
    """A real Popen-backed timeout must kill the whole process group."""
    import tempfile

    tmpdir = tempfile.mkdtemp(prefix="rgt_fakebin_")
    fake = Path(tmpdir) / "claude"
    fake.write_text("#!/bin/bash\nexec < /dev/null\nsleep 60\n")
    fake.chmod(0o755)
    orig_path = os.environ.get("PATH", "")
    os.environ["PATH"] = str(tmpdir) + os.pathsep + orig_path

    from scripts.llm.providers import cli

    try:
        p = cli.ClaudeCLIProvider()
        t0 = time.time()
        r = p.complete("hi", timeout=2)
        elapsed = time.time() - t0
    finally:
        os.environ["PATH"] = orig_path

    assert not r.ok
    assert "timeout" in r.error
    # killpg should interrupt long before 60s. Allow generous headroom
    # for CI noise, but if this ever takes > 10s, killpg regressed.
    assert elapsed < 10, f"timeout took {elapsed:.1f}s — killpg didn't interrupt"


def test_gemini_construction_accepts_model():
    """GeminiCLIProvider had no __init__, so build_provider(spec, args)
    would TypeError when args was non-empty."""
    from scripts.llm.providers.cli import GeminiCLIProvider

    g_default = GeminiCLIProvider()
    assert g_default.model == "default"

    g_pro = GeminiCLIProvider(model="pro")
    assert g_pro.model == "pro"

    # Replicates the production path: build_provider("gemini-cli", {"model": "x"})
    g_kwargs = GeminiCLIProvider(**{"model": "flash"})
    assert g_kwargs.model == "flash"


def test_gemini_passes_model_flag():
    """When a model is configured, gemini must be invoked with --model."""
    argv_file = "/tmp/rgt_gemini_argv_test"
    if os.path.exists(argv_file):
        os.unlink(argv_file)
    restore = _force_which(
        "gemini",
        f'echo "$@" > {argv_file}\necho "fake response"',
    )

    from scripts.llm.providers import cli

    try:
        p = cli.GeminiCLIProvider(model="pro")
        r = p.complete("hi", timeout=5)
    finally:
        restore()

    assert r.ok, f"r.error={r.error!r}"
    captured = Path(argv_file).read_text().strip()
    assert "--model" in captured, f"--model not in argv: {captured!r}"
    assert "pro" in captured, f"pro not in argv: {captured!r}"


def test_gemini_no_model_flag_when_default():
    """When model is the placeholder 'default', don't pass --model
    (let the CLI pick its own)."""
    argv_file = "/tmp/rgt_gemini_argv_test_default"
    if os.path.exists(argv_file):
        os.unlink(argv_file)
    restore = _force_which(
        "gemini",
        f'echo "$@" > {argv_file}\necho "fake response"',
    )

    from scripts.llm.providers import cli

    try:
        p = cli.GeminiCLIProvider()  # default model
        r = p.complete("hi", timeout=5)
    finally:
        restore()

    assert r.ok, r.error
    captured = Path(argv_file).read_text().strip()
    assert "--model" not in captured, f"--model leaked when default: {captured!r}"


def test_scrub_before_truncate():
    """OPUS-11 was truncating stderr to 300 chars BEFORE scrubbing, so a
    secret that straddled the cut could leave a partial token in the
    output. Verify the new order: scrub first, then truncate."""
    from scripts.llm.providers.cli import _scrub

    # A fake "API key" that would be cut in half by a 300-char truncate
    # BEFORE scrubbing, leaving a 50-char dangling prefix in the output.
    long_filler = "x" * 280
    dangling_key = "sk-" + "A" * 60
    bad = long_filler + dangling_key

    scrubbed = _scrub(bad)
    truncated = scrubbed[:300]
    assert "sk-" not in truncated, f"partial secret leaked: {truncated[-80:]!r}"


def test_killpg_terminates_grandchildren():
    """Direct unit test of _kill_pg with a pg that contains a sleeper."""
    marker = "/tmp/rgt_killpg_test_marker_pytest"
    if os.path.exists(marker):
        os.unlink(marker)

    proc = subprocess.Popen(
        ["setsid", "bash", "-c", f"sleep 60; touch {marker}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    pid = proc.pid
    from scripts.llm.providers.cli import _kill_pg

    t0 = time.time()
    _kill_pg(proc)
    elapsed = time.time() - t0

    assert elapsed < 3, f"killpg took {elapsed:.1f}s"
    time.sleep(0.3)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    # The sleep must have been interrupted; the marker must NOT exist.
    time.sleep(0.2)
    assert not os.path.exists(marker), "sleeper survived killpg"
