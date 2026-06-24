import pytest

from rgt_vault.auth import ABACPolicyEngine

POLICY = """
rules:
  - agent: "*"
    action: "read_secret"
    ttl: 300
    effect: allow
  - agent: "agent-ops"
    action: "sign_transaction"
    ttl: 900
    effect: allow
  - agent: "agent-llm-01"
    action: "decrypt"
    ttl: 60
    effect: allow
"""


@pytest.fixture
def engine():
    return ABACPolicyEngine(policy_yaml=POLICY)


def test_default_ttl(engine):
    assert engine.get_lease_ttl("any-agent", "read_secret") == 300


def test_exact_match_ops(engine):
    assert engine.get_lease_ttl("agent-ops", "sign_transaction") == 900


def test_fallback_to_default(engine):
    # no rule for this capability — should return 300
    assert engine.get_lease_ttl("agent-llm-01", "unknown_cap") == 300


def test_wildcard_agent(engine):
    # agent not listed falls back to wildcard rule
    assert engine.get_lease_ttl("random", "read_secret") == 300
