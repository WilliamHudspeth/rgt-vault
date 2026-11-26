"""Guards that documentation claims stay honest (RGT-133, RGT-224..231).

Earlier docs said the hash-chained audit log made it "impossible to modify or
delete entries without detection". It does not: the chain detects edits,
insertions and head/middle deletions, but not tail truncation, an emptied
table, a rebuilt (unkeyed) chain, or an edit to a column outside the hash
input. These are documentation guards only: they read text files and do not
exercise the legacy Python vault, which is end-of-life.

They check that (1) ``llm_guide`` and SECURITY.md no longer over-claim,
(2) relative links in the docs touched by the SDLC/architecture work resolve,
(3) test files named in the ADRs and the ASVS V1 evidence table exist, and
(4) the threat model still covers the required topics and has a data-flow
diagram.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List

import pytest

from rgt_vault.llm_guide import get_llm_guide

REPO = Path(__file__).resolve().parents[1]

# Phrases that over-state what the audit chain does.
OVERCLAIMS = [
    r"impossible\s+to\s+(modify|delete)",
    r"without\s+detection",
    r"cannot\s+be\s+(modified|altered|tampered)",
    r"cryptographically\s+protected\s+against\s+modification",
]


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).lower()


# ---------------------------------------------------------------------------
# llm_guide / SECURITY.md wording
# ---------------------------------------------------------------------------


def test_llm_guide_does_not_claim_audit_log_is_unmodifiable():
    guide = _norm(get_llm_guide())
    for pattern in OVERCLAIMS:
        for m in re.finditer(pattern, guide):
            # The guide may *quote* a phrase only to tell the model not to say it.
            window = guide[max(0, m.start() - 80) : m.end() + 40]
            assert "do not tell" in window, f"llm_guide over-claims the audit log: {m.group(0)!r} in ...{window}..."


def test_llm_guide_states_the_audit_chain_limits():
    guide = _norm(get_llm_guide())
    assert "most recent entries" in guide
    assert "does not detect" in guide
    assert "tamper-*proofing*" in guide  # "tamper-evidence, not tamper-proofing"


def test_security_md_states_tail_truncation_is_not_detected():
    text = _norm((REPO / ".github" / "SECURITY.md").read_text(encoding="utf-8"))
    assert "tail truncation" in text
    assert "are not detected" in text or "does **not** detect" in text
    # The old unqualified sentence must be gone.
    assert "detects insertion, deletion, or edits" not in text


# ---------------------------------------------------------------------------
# Link and reference hygiene in the docs this change owns
# ---------------------------------------------------------------------------

OWNED_DOCS = [
    "docs/security/threat-model.md",
    "docs/security/asvs/V1.md",
    "docs/concepts/trust-boundary.md",
    "docs/concepts/security-model.md",
    "docs/concepts/capabilities.md",
    "docs/architecture/overview.md",
    "docs/architecture/execution-flow.md",
    "docs/adr/ADR-0002-abac-over-rbac.md",
    "docs/adr/ADR-0003-audit-chain-design.md",
    "docs/adr/ADR-0004-agent-capability-model.md",
    "docs/guides/api.md",
    ".github/CONTRIBUTING.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/SECURITY.md",
    ".github/ISSUE_TEMPLATE/bug_report.md",
    ".github/ISSUE_TEMPLATE/feature_request.md",
]

LINK_RE = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)\)")
TEST_REF_RE = re.compile(r"tests/(test_[A-Za-z0-9_]+\.py)")


def _links(path: Path) -> Iterable[str]:
    text = path.read_text(encoding="utf-8")
    # Ignore fenced code blocks: they may hold example links.
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    return LINK_RE.findall(text)


@pytest.mark.parametrize("rel", OWNED_DOCS)
def test_relative_links_resolve(rel):
    path = REPO / rel
    assert path.exists(), f"{rel} is missing"
    broken: List[str] = []
    for target in _links(path):
        if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
            continue  # http(s), mailto, in-page anchor
        file_part = target.split("#", 1)[0]
        if not file_part:
            continue
        resolved = (path.parent / file_part).resolve()
        if not resolved.exists():
            broken.append(target)
    assert not broken, f"{rel} has broken relative links: {broken}"


@pytest.mark.parametrize(
    "rel",
    [
        "docs/adr/ADR-0002-abac-over-rbac.md",
        "docs/adr/ADR-0003-audit-chain-design.md",
        "docs/adr/ADR-0004-agent-capability-model.md",
        "docs/security/asvs/V1.md",
    ],
)
def test_test_files_named_in_docs_exist(rel):
    text = (REPO / rel).read_text(encoding="utf-8")
    missing = sorted({name for name in TEST_REF_RE.findall(text) if not (REPO / "tests" / name).exists()})
    assert not missing, f"{rel} references test files that do not exist: {missing}"


# ---------------------------------------------------------------------------
# Threat model content (RGT-224)
# ---------------------------------------------------------------------------

THREAT_TOPICS = {
    "nonce reuse": ("nonce reuse",),
    "privilege escalation": ("privilege escalation",),
    "malicious admin": ("malicious administrator",),
    "supply chain": ("supply chain",),
    "go server": ("the go server",),
    "gateway": ("the cutover gateway",),
    "mcp": ("mcp servers",),
    "outbound providers": ("outbound providers",),
    "offline database theft": ("stolen backups", "stolen disk", "committed `vault.db`"),
    "data flow": ("data-flow diagram",),
    "parity gaps": ("gap (go)",),
}


def test_threat_model_covers_required_topics_and_has_a_diagram():
    text = (REPO / "docs/security/threat-model.md").read_text(encoding="utf-8")
    low = text.lower()
    for topic, options in THREAT_TOPICS.items():
        assert any(o in low for o in options), f"threat model lacks section/topic: {topic!r}"
    assert "```mermaid" in text, "threat model has no data-flow diagram"
