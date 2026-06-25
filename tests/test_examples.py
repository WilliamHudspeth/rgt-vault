"""Smoke tests: the runnable example demos actually run and stay honest.

These guard the interview-facing demos against silent breakage and assert
the core invariant — the stored secret value never appears in what the
agent gets back.
"""

import importlib
import sys
from pathlib import Path

import pytest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


@pytest.fixture(autouse=True)
def _examples_on_path():
    sys.path.insert(0, str(EXAMPLES))
    try:
        yield
    finally:
        if str(EXAMPLES) in sys.path:
            sys.path.remove(str(EXAMPLES))


@pytest.mark.parametrize("module", ["github_issue_demo", "openai_demo", "slack_demo"])
def test_scenario_demo_runs_and_keeps_secret(module, capsys):
    mod = importlib.import_module(module)
    rc = mod.run(mod.SCENARIO)
    assert rc == 0
    out = capsys.readouterr().out
    # The secret value must never appear in anything printed to the agent/user.
    assert mod.SCENARIO.secret_value not in out
    # The story beats are present.
    assert "Approval Center" in out
    assert "never" in out.lower()


def test_policy_demo_runs():
    demo = importlib.import_module("demo_policy")
    assert demo.main() == 0
