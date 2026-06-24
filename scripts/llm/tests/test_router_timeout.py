"""Tests for router OPUS-3 + OPUS-AFK-4: non-blocking executor timeout.

OPUS-3: future.result(timeout=) was always called, but the
`with ThreadPoolExecutor(...)` block did shutdown(wait=True) at exit,
which would join any still-running worker. So if a provider ignored
its own timeout, the loop hung at the with-block exit.

OPUS-AFK-4: review_pair's duplicate-spec branch (primary ==
secondary) called provider.complete() directly with no executor
timeout at all. A hung provider blocked the loop indefinitely.

Fix:
- Both call_parallel and the dup-spec branch now use
  ThreadPoolExecutor.shutdown(wait=False) so a hung worker doesn't
  block the caller.
- The dup-spec branch routes through _run_with_timeout.
"""

import threading
import time
from unittest.mock import MagicMock

from scripts.llm.router import TASK_CODE_REVIEW, RouteConfig, Router
from scripts.llm.types import Reply


class _HangingProvider:
    """A provider whose complete() blocks for longer than its timeout."""

    def __init__(self, name="hang"):
        self._name = name
        self.completed = threading.Event()

    @property
    def name(self):
        return self._name

    def is_available(self) -> bool:
        return True

    def complete(self, prompt, **kwargs):
        # Honor the provider's timeout = 1s, then sleep for 10s, so the
        # provider-level timeout is ignored.
        timeout = kwargs.get("timeout", 60)
        time.sleep(timeout + 10)
        return Reply(text="hung", provider=self._name, model="?")


def test_run_with_timeout_returns_quickly_on_hung_provider():
    """_run_with_timeout must return within seconds even if the
    provider ignores its own timeout."""
    r = Router(RouteConfig.default())
    # Patch the dispatch to return a hanging provider.
    hanging = _HangingProvider("hang")
    r._get = MagicMock(return_value=hanging)

    t0 = time.time()
    reply = r._run_with_timeout("hang", "hi", timeout=1)
    elapsed = time.time() - t0

    # Should return after executor_timeout = timeout + 5 = 6s, NOT 11s.
    assert elapsed < 8, f"elapsed={elapsed:.1f}s, expected < 8s"
    assert not reply.ok
    assert "executor timeout" in reply.error


def test_call_parallel_does_not_block_on_hung_provider():
    """call_parallel must not block the caller on a hung worker."""
    r = Router(RouteConfig.default())
    hanging = _HangingProvider("hang")
    r._get = MagicMock(return_value=hanging)

    t0 = time.time()
    results = r.call_parallel(["hang"], "hi", timeout=1)
    elapsed = time.time() - t0

    assert elapsed < 8, f"elapsed={elapsed:.1f}s, expected < 8s"
    assert len(results) == 1
    spec, reply = results[0]
    assert spec == "hang"
    assert not reply.ok
    assert "executor timeout" in reply.error


def test_review_pair_dup_spec_uses_executor_timeout():
    """When primary_spec == secondary_spec, review_pair must still
    enforce the executor timeout (OPUS-AFK-4)."""
    cfg = RouteConfig(
        chains={},
        pairs={TASK_CODE_REVIEW: {"primary": "hang", "secondary": "hang"}},
    )
    r = Router(cfg)
    hanging = _HangingProvider("hang")
    r._get = MagicMock(return_value=hanging)

    t0 = time.time()
    out = r.review_pair(TASK_CODE_REVIEW, "hi", timeout=1)
    elapsed = time.time() - t0

    assert elapsed < 8, f"elapsed={elapsed:.1f}s, expected < 8s"
    primary_spec, primary_reply = out["primary"]
    secondary_spec, secondary_reply = out["secondary"]
    assert primary_spec == "hang"
    assert secondary_spec == "hang"
    # Same reply returned for both roles (dup-spec collapse).
    assert primary_reply is secondary_reply
    # That reply should be the executor timeout (provider was hung).
    assert not primary_reply.ok
    assert "executor timeout" in primary_reply.error


def test_run_with_timeout_success_returns_reply():
    """_run_with_timeout returns the provider's Reply on success."""
    r = Router(RouteConfig.default())
    ok_provider = MagicMock()
    ok_provider.is_available.return_value = True
    ok_provider.complete.return_value = Reply(
        text="hello",
        provider="good",
        model="g",
    )
    r._get = MagicMock(return_value=ok_provider)

    reply = r._run_with_timeout("good", "hi", timeout=10)
    assert reply.ok
    assert reply.text == "hello"


def test_call_parallel_multiple_specs_all_return():
    r = Router(RouteConfig.default())

    def mk(name, text):
        p = MagicMock()
        p.is_available.return_value = True
        p.complete.return_value = Reply(text=text, provider=name, model=name)
        return p

    providers = {"a": mk("a", "from-a"), "b": mk("b", "from-b")}
    r._get = MagicMock(side_effect=lambda s: providers[s])

    results = r.call_parallel(["a", "b"], "hi", timeout=10)
    assert len(results) == 2
    assert {s for s, _ in results} == {"a", "b"}
    for spec, reply in results:
        assert reply.ok
        assert reply.text == f"from-{spec}"
