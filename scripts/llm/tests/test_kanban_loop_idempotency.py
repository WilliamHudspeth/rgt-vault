"""Tests for kanban_loop signature/ticket_changed idempotency.

OPUS-16 was supposed to fix the infinite-re-comment bug. It half-fixed
it: signature() no longer includes updated_at, but ticket_changed() did.
This test pins the contract: ticket_changed() must use the same field
set as signature() so equality is well-defined.
"""

import importlib.util
from pathlib import Path

# Import the module under test. It lives in scripts/llm/kanban_loop.py,
# which is a standalone script with `if __name__ == "__main__":` at the
# bottom, so we load it by file path.
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("kanban_loop", ROOT / "kanban_loop.py")
assert SPEC is not None and SPEC.loader is not None
kanban_loop = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kanban_loop)


def _ticket(description="d", labels=None, updated_at="2026-06-17T00:00:00Z"):
    return {
        "id": "i1",
        "description": description,
        "labels": [{"name": n} for n in (labels or [])],
        "updated_at": updated_at,
    }


def test_signature_excludes_updated_at():
    """OPUS-16: signature must not include updated_at (comment-post bumps it)."""
    t1 = _ticket(updated_at="2026-06-17T00:00:00Z")
    t2 = _ticket(updated_at="2099-12-31T23:59:59Z")  # wildly different
    assert kanban_loop.signature(t1) == kanban_loop.signature(t2)


def test_signature_includes_description_and_labels():
    t1 = _ticket(description="a", labels=["x"])
    t2 = _ticket(description="b", labels=["x"])
    assert kanban_loop.signature(t1) != kanban_loop.signature(t2)
    t3 = _ticket(description="a", labels=["y"])
    assert kanban_loop.signature(t1) != kanban_loop.signature(t3)


def test_ticket_changed_uses_signature_field_set():
    """The bug: ticket_changed() built its own dict with updated_at, while
    signature() omitted it. The two JSON strings can never be equal, so
    ticket_changed() always returns True and the skip predicate at the
    call site never fires."""
    ticket = _ticket(description="d", labels=["x"], updated_at="2026-06-17T00:00:00Z")
    prev = kanban_loop.signature(ticket)
    # After we post a comment, the API returns the same ticket but with
    # an updated_at bump. The signature must NOT change, so ticket_changed
    # must return False.
    after_comment = _ticket(description="d", labels=["x"], updated_at="2099-01-01T00:00:00Z")
    assert kanban_loop.ticket_changed(after_comment, prev) is False


def test_ticket_changed_true_on_real_change():
    ticket = _ticket(description="d", labels=["x"])
    prev = kanban_loop.signature(ticket)
    changed = _ticket(description="D", labels=["x"])  # case-only diff
    assert kanban_loop.ticket_changed(changed, prev) is True


def test_ticket_changed_empty_prev_means_changed():
    """An empty prev_signature should always count as changed (first time
    the loop sees this ticket)."""
    ticket = _ticket()
    assert kanban_loop.ticket_changed(ticket, "") is True
