"""Tests for _common.get_issue + release_gate + dashboard O(N^2) bugs.

OPUS deep audit 2026-06-17, headline #3:
- get_issue(limit=200 default) silently dropped tickets ranked >200.
  Callers passed limit=300 in the outer list but get_issue's inner
  scan only saw 200, so an identifier that sorted after #200 returned
  None. release_gate false-PASSed when a blocker sorted after #200.
- The pattern `for i in issues: get_issue(i["identifier"], ...)` is
  O(N) HTTP calls per caller (dashboard, wip_audit, release_gate),
  and each get_issue re-list-ed 200 issues, so the whole thing is
  O(N * 200) round-trips. We replace the re-fetch with a single
  list call (the list response already has status, project_id,
  labels, identifier, priority — everything the callers use).
- release_gate gates 5, 8, 9, 10, 11 were hardcoded `True` and
  printed "PASS" even when the corresponding control had never
  actually run. Now they report "skipped" which fails the gate by
  default (the human must explicitly override).
"""

import importlib.util
import sys
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def _import_program_module(name):
    """Import scripts.program.<name> by file path. Works around pytest's
    import-resolution edge cases for namespace packages without __init__.py."""
    import importlib.util

    mod_path = ROOT / "program" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"scripts.program.{name}", mod_path)
    if spec is None:
        raise ImportError(f"cannot import scripts.program.{name} from {mod_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[f"scripts.program.{name}"] = mod
    spec.loader.exec_module(mod)
    return mod


_common = _import_program_module("_common")
dashboard = _import_program_module("dashboard")
wip_audit = _import_program_module("wip_audit")
release_gate = _import_program_module("release_gate")


# ----- _common.get_issue: direct endpoint, no truncation -----------------


def test_get_issue_resolves_via_list_then_direct(monkeypatch):
    """get_issue must call list_issues(limit=1000) (not 200), then hit
    the direct /api/issues/{uuid} endpoint, not another list call."""
    _common = sys.modules["scripts.program._common"]

    calls = []

    def fake_list_issues(workspace_id, limit=200):
        calls.append(("list", workspace_id, limit))
        return [
            {"id": "uuid-1", "identifier": "RGT-1"},
            {"id": "uuid-2", "identifier": "RGT-2"},
            {"id": "uuid-3", "identifier": "RGT-3"},
        ]

    def fake_get(path):
        calls.append(("get", path))
        # Confirm we resolve by uuid, not by identifier
        if "uuid-2" in path:
            return {"id": "uuid-2", "identifier": "RGT-2", "full": True}
        raise AssertionError(f"unexpected GET path: {path}")

    monkeypatch.setattr(_common, "list_issues", fake_list_issues)
    monkeypatch.setattr(_common, "_get", fake_get)

    got = _common.get_issue("RGT-2", workspace_id="ws-x")
    assert got == {"id": "uuid-2", "identifier": "RGT-2", "full": True}

    # Must have used limit >= 1000 (was 200 before the fix).
    list_calls = [c for c in calls if c[0] == "list"]
    assert len(list_calls) == 1
    assert list_calls[0][2] >= 1000, f"list_issues called with limit={list_calls[0][2]}, expected >= 1000"

    # Must have hit the direct endpoint, not another list.
    get_calls = [c for c in calls if c[0] == "get"]
    assert len(get_calls) == 1, f"expected 1 direct GET, got {len(get_calls)}"
    assert "uuid-2" in get_calls[0][1]


def test_get_issue_unknown_returns_none(monkeypatch):
    _common = sys.modules["scripts.program._common"]

    monkeypatch.setattr(
        _common,
        "list_issues",
        lambda workspace_id, limit=200: [{"id": "u1", "identifier": "RGT-1"}],
    )
    assert _common.get_issue("RGT-99") is None


# ----- release_gate: no O(N^2) + skipped gates not PASS -----------------


def _load_release_gate():
    spec = importlib.util.spec_from_file_location("release_gate", ROOT / "program" / "release_gate.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_release_gate_uses_list_response_directly(monkeypatch):
    """release_gate must NOT call get_issue per ticket. The list
    response has everything it needs."""
    rg = _load_release_gate()
    calls = []

    def fake_list_projects(workspace_id):
        return [{"id": "ms-1", "title": "v0.3.0 - something"}]

    def fake_list_issues(workspace_id, limit=200):
        calls.append(("list", limit))
        # Two tickets in this milestone, one is a blocker.
        return [
            {
                "id": "u-1",
                "identifier": "RGT-1",
                "project_id": "ms-1",
                "status": "todo",
                "labels": [{"name": "pri:blocker"}],
            },
            {
                "id": "u-2",
                "identifier": "RGT-2",
                "project_id": "ms-1",
                "status": "done",
                "labels": [],
            },
        ]

    fake_get_issue = mock.MagicMock()
    monkeypatch.setattr(rg, "list_projects", fake_list_projects)
    monkeypatch.setattr(rg, "list_issues", fake_list_issues)
    monkeypatch.setattr(rg, "get_issue", fake_get_issue)

    gates = rg.check_milestone("v0.3.0", workspace_id="ws-x")
    fake_get_issue.assert_not_called()

    # The blocker gate must have failed.
    no_blocker_issues = [g for g in gates if g[0] == "no_blocker_issues"]
    assert no_blocker_issues, f"no_blocker_issues gate missing from {gates}"
    assert no_blocker_issues[0][1] is False
    assert "RGT-1" in no_blocker_issues[0][2]

    # All "skipped" gates must NOT be True.
    skipped = [g for g in gates if g[1] == "skipped"]
    assert skipped, "expected some gates to be skipped"
    for name, _, _ in skipped:
        assert name in {
            "changelog_updated",
            "threat_model_current",
            "dependency_audit",
            "secret_scan",
            "sbom_generated",
        }


def test_release_gate_uses_generous_list_limit(monkeypatch):
    """The list_issues call inside check_milestone must use a high
    limit (was 300, must be >= 1000) so a blocker ranked >200 isn't
    dropped."""
    rg = _load_release_gate()
    seen_limits = []

    monkeypatch.setattr(rg, "list_projects", lambda w: [{"id": "ms-1", "title": "v1 - x"}])

    def fake_list(workspace_id, limit=200):
        seen_limits.append(limit)
        return []

    monkeypatch.setattr(rg, "list_issues", fake_list)

    rg.check_milestone("v1", workspace_id="ws-x")
    assert seen_limits, "list_issues not called"
    assert max(seen_limits) >= 1000, f"limit was {seen_limits[0]}, expected >= 1000"


# ----- dashboard: no O(N^2) -------------------------------------------


def test_dashboard_uses_list_response_directly(monkeypatch):
    """dashboard.compute_dashboard must NOT call get_issue per ticket."""
    dashboard = sys.modules["scripts.program.dashboard"]

    fake_list_issues = mock.MagicMock(
        return_value=[
            {
                "id": "u-1",
                "identifier": "RGT-1",
                "project_id": "ms-1",
                "status": "todo",
                "labels": [],
                "priority": "medium",
            },
        ]
    )
    fake_get_issue = mock.MagicMock(side_effect=AssertionError("get_issue must not be called"))

    monkeypatch.setattr(dashboard, "list_issues", fake_list_issues)
    monkeypatch.setattr(dashboard, "get_issue", fake_get_issue)
    monkeypatch.setattr(dashboard, "list_projects", lambda w: [])

    out = dashboard.compute_dashboard(workspace_id="ws-x")
    fake_get_issue.assert_not_called()
    assert out["totals"]["issues"] == 1


def test_wip_audit_uses_list_response_directly(monkeypatch):
    wip_audit = sys.modules["scripts.program.wip_audit"]

    fake_list_issues = mock.MagicMock(
        return_value=[
            {
                "id": "u-1",
                "identifier": "RGT-1",
                "status": "todo",
                "labels": [{"name": "effort:M"}],
                "assignee_id": "m1",
                "assignee_type": "member",
                "created_at": "2026-06-15T00:00:00Z",
                "updated_at": "2026-06-15T00:00:00Z",
            },
        ]
    )
    fake_get_issue = mock.MagicMock(side_effect=AssertionError("get_issue must not be called"))

    monkeypatch.setattr(wip_audit, "list_issues", fake_list_issues)
    monkeypatch.setattr(wip_audit, "get_issue", fake_get_issue)
    monkeypatch.setattr(wip_audit, "member_lookup", lambda: {"m1": "Alice"})

    # Run main with --json to /tmp/wip_audit_test.json
    import json

    out = Path("/tmp/wip_audit_test.json")
    if out.exists():
        out.unlink()
    monkeypatch.setattr(sys, "argv", ["wip_audit", "--json", str(out)])
    wip_audit.main()
    data = json.loads(out.read_text())
    fake_get_issue.assert_not_called()
    # Alice should have 1 active ticket
    assert "m1" in data["by_engineer"]
    assert data["by_engineer"]["m1"]["active_count"] == 1
