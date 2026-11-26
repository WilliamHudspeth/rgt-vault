"""RGT-262: the shipped systemd unit keeps its sandboxing and loopback bind."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
UNIT = ROOT / "deploy" / "rgt-vault.service"
SCRIPT = ROOT / "scripts" / "check_deploy_unit.py"

if not UNIT.exists() or not SCRIPT.exists():  # e.g. tests run from an installed sdist
    pytest.skip("repo deploy/ and scripts/ not available", allow_module_level=True)

_spec = importlib.util.spec_from_file_location("check_deploy_unit", SCRIPT)
assert _spec is not None and _spec.loader is not None
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)


def test_shipped_unit_passes():
    assert check.check_unit_text(UNIT.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    "needle,replacement,expected",
    [
        ("NoNewPrivileges=true", "NoNewPrivileges=false", "NoNewPrivileges"),
        ("ProtectSystem=strict", "", "ProtectSystem"),
        ("User=rgtvault", "User=root", "User"),
        ("--host 127.0.0.1", "--host 0.0.0.0", "wildcard"),
        ("ReadWritePaths=/var/lib/rgt-vault", "", "ReadWritePaths"),
        ("MemoryDenyWriteExecute=true", "MemoryDenyWriteExecute=no", "MemoryDenyWriteExecute"),
    ],
)
def test_regressions_are_detected(needle, replacement, expected):
    text = UNIT.read_text(encoding="utf-8")
    assert needle in text
    problems = check.check_unit_text(text.replace(needle, replacement))
    assert any(expected in p for p in problems), problems


def test_garbage_is_rejected():
    assert check.check_unit_text("not a unit file") != []


def test_verify_copy_replaces_exec_start_and_flattens_continuations():
    out = check.verify_copy(UNIT.read_text(encoding="utf-8"))
    assert "ExecStart=/bin/true" in out
    assert "/opt/rgt-vault" not in out


def test_main_ok_and_failure(tmp_path, capsys):
    copy = tmp_path / "v.service"
    assert check.main([str(UNIT), "--write-verify-copy", str(copy)]) == 0
    assert "ExecStart=/bin/true" in copy.read_text(encoding="utf-8")
    bad = tmp_path / "bad.service"
    bad.write_text(UNIT.read_text(encoding="utf-8").replace("PrivateTmp=true", ""), encoding="utf-8")
    assert check.main([str(bad)]) == 1
    assert "PrivateTmp" in capsys.readouterr().err
