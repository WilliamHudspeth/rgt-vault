"""Unit tests for the router. Offline — no real provider calls."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from scripts.llm.router import (
    TASK_CODE_REVIEW,
    TASK_GENERAL,
    RouteConfig,
    Router,
    build_provider,
)
from scripts.llm.types import Reply


class _FakeProvider:
    """Test double that records calls and returns scripted replies."""

    def __init__(self, name="fake", model="fake-model", reply=None, available=True):
        self.name = name
        self.model = model
        self.reply = reply or Reply(text="ok", provider=name, model=model)
        self.available = available
        self.calls = []

    def is_available(self):
        return self.available

    def complete(self, prompt, *, system=None, max_tokens=600, temperature=0.2, timeout=60):
        self.calls.append({"prompt": prompt, "system": system, "max_tokens": max_tokens})
        return self.reply


class BuildProviderTests(unittest.TestCase):
    def test_known_specs(self):
        for spec, cls_name in [
            ("groq", "GroqProvider"),
            ("mistral", "MistralProvider"),
            ("cohere", "CohereProvider"),
            ("claude-cli", "ClaudeCLIProvider"),
            ("gemini-cli", "GeminiCLIProvider"),
            ("ollama:qwen2.5:7b", "OllamaProvider"),
        ]:
            with self.subTest(spec=spec):
                p = build_provider(spec)
                self.assertEqual(cls_name, type(p).__name__)

    def test_ollama_strips_prefix(self):
        from scripts.llm.providers.ollama import OllamaProvider

        p = build_provider("ollama:llama3.2:3b")
        self.assertIsInstance(p, OllamaProvider)
        self.assertEqual(p.model, "llama3.2:3b")

    def test_unknown_spec_raises(self):
        with self.assertRaises(ValueError):
            build_provider("not-a-real-spec")


class ChainConfigTests(unittest.TestCase):
    def test_default_config_has_all_tasks(self):
        c = RouteConfig.default()
        for t in [
            TASK_CODE_REVIEW,
            TASK_GENERAL,
        ]:
            self.assertIn(t, c.chains)
            self.assertGreater(len(c.chains[t]), 0)

    def test_yaml_roundtrip(self, tmp_path=None):
        # default has no yaml — write it, read it back

        import yaml

        d = RouteConfig.default()
        with tempfile_patch() as p:
            p.write_text(yaml.safe_dump({"chains": d.chains}))
            loaded = RouteConfig.load(p)
            self.assertEqual(loaded.chains, d.chains)

    def test_empty_yaml_file_falls_back_to_default(self, capsys=None):
        """A file that exists but is empty (or has no chains) must NOT
        return an empty config that makes every call() return 'no
        providers configured'. It must fall back to the default."""
        with tempfile_patch() as p:
            p.write_text("")  # totally empty
            loaded = RouteConfig.load(p)
        # The chains dict must be populated.
        self.assertGreater(len(loaded.chains), 0, "empty yaml should fall back to default chains")
        # Specifically, the default code-review chain should be present.
        from scripts.llm.router import TASK_CODE_REVIEW

        self.assertIn(TASK_CODE_REVIEW, loaded.chains)

    def test_yaml_with_only_other_keys_falls_back(self):
        """A yaml that has env_path or providers but no chains: same fallback."""
        import yaml

        with tempfile_patch() as p:
            p.write_text(yaml.safe_dump({"providers": {"groq": {"model": "x"}}}))
            loaded = RouteConfig.load(p)
        from scripts.llm.router import TASK_CODE_REVIEW

        self.assertIn(TASK_CODE_REVIEW, loaded.chains, "providers-only yaml should still get default chains")
        # The providers section should be preserved.
        self.assertEqual(loaded.provider_args, {"groq": {"model": "x"}})

    def test_yaml_with_empty_chains_falls_back(self):
        """A yaml that has chains: {} (explicitly empty) also falls back."""
        import yaml

        with tempfile_patch() as p:
            p.write_text(yaml.safe_dump({"chains": {}}))
            loaded = RouteConfig.load(p)
        from scripts.llm.router import TASK_CODE_REVIEW

        self.assertIn(TASK_CODE_REVIEW, loaded.chains, "explicit empty chains should fall back")


def tempfile_patch():
    """Tiny helper: write to a temp yaml path and return it."""
    import tempfile
    from pathlib import Path

    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    f.close()
    return Path(f.name)


class RouterFallbackTests(unittest.TestCase):
    def test_first_available_wins(self):
        good = _FakeProvider(
            name="good",
            reply=Reply(text="from-good", provider="good", model="g"),
        )
        bad = _FakeProvider(
            name="bad",
            reply=Reply(text="", provider="bad", model="b", error="HTTP 500"),
        )
        cfg = RouteConfig(
            chains={TASK_CODE_REVIEW: ["bad", "good", "unused"]},
        )
        router = Router(cfg)
        with patch.object(
            router, "_get", side_effect=lambda s: {"bad": bad, "good": good, "unused": _FakeProvider(name="u")}[s]
        ):
            reply = router.call(TASK_CODE_REVIEW, "hi")
        self.assertTrue(reply.ok)
        self.assertEqual(reply.provider, "good")
        self.assertEqual(len(bad.calls), 1)
        self.assertEqual(len(good.calls), 1)

    def test_unavailable_providers_skipped(self):
        good = _FakeProvider(name="good", reply=Reply(text="ok", provider="good", model="g"))
        unavailable = _FakeProvider(name="u", available=False)
        cfg = RouteConfig(
            chains={TASK_CODE_REVIEW: ["u", "good"]},
        )
        router = Router(cfg)
        with patch.object(router, "_get", side_effect=lambda s: {"u": unavailable, "good": good}[s]):
            reply = router.call(TASK_CODE_REVIEW, "hi")
        self.assertEqual(reply.provider, "good")
        self.assertEqual(unavailable.calls, [])

    def test_chain_exhaustion_returns_error(self):
        bad1 = _FakeProvider(name="b1", reply=Reply(text="", provider="b1", model="b1", error="e1"))
        bad2 = _FakeProvider(name="b2", reply=Reply(text="", provider="b2", model="b2", error="e2"))
        cfg = RouteConfig(chains={TASK_CODE_REVIEW: ["b1", "b2"]})
        router = Router(cfg)
        with patch.object(router, "_get", side_effect=lambda s: {"b1": bad1, "b2": bad2}[s]):
            reply = router.call(TASK_CODE_REVIEW, "hi")
        self.assertFalse(reply.ok)
        self.assertEqual(reply.provider, "<chain-exhausted>")
        self.assertIsNotNone(reply.error)
        assert reply.error is not None
        self.assertIn("b1", reply.error)
        self.assertIn("b2", reply.error)

    def test_dry_run_returns_first_available(self):
        good = _FakeProvider(name="good")
        cfg = RouteConfig(chains={TASK_CODE_REVIEW: ["good"]})
        router = Router(cfg)
        with patch.object(router, "_get", return_value=good):
            reply = router.call(TASK_CODE_REVIEW, "hi", dry_run=True)
        self.assertEqual(reply.provider, "good")
        self.assertIn("dry-run", reply.error)
        self.assertEqual(good.calls, [])

    def test_unknown_task_falls_back_to_general(self):
        good = _FakeProvider(name="good")
        cfg = RouteConfig(
            chains={TASK_GENERAL: ["good"]},
        )
        router = Router(cfg)
        with patch.object(router, "_get", return_value=good):
            reply = router.call("nonexistent-task", "hi")
        self.assertEqual(reply.provider, "good")

    def test_no_chain_returns_error(self):
        cfg = RouteConfig(chains={})
        router = Router(cfg)
        reply = router.call(TASK_CODE_REVIEW, "hi")
        self.assertFalse(reply.ok)
        self.assertIsNotNone(reply.error)
        assert reply.error is not None
        self.assertIn("no providers configured", reply.error)

    def test_skipped_providers_audited_in_raw(self):
        bad = _FakeProvider(name="bad", reply=Reply(text="", provider="bad", model="b", error="e"))
        good = _FakeProvider(name="good", reply=Reply(text="ok", provider="good", model="g"))
        cfg = RouteConfig(chains={TASK_CODE_REVIEW: ["bad", "good"]})
        router = Router(cfg)
        with patch.object(router, "_get", side_effect=lambda s: {"bad": bad, "good": good}[s]):
            reply = router.call(TASK_CODE_REVIEW, "hi")
        self.assertTrue(reply.ok)
        self.assertIsNotNone(reply.raw)
        assert reply.raw is not None
        self.assertIn("_router_skipped", reply.raw)
        self.assertEqual(reply.raw["_router_skipped"][0][0], "bad")


class AvailableChainTests(unittest.TestCase):
    def test_filters_unavailable(self):
        ok1 = _FakeProvider(name="ok1", available=True)
        u = _FakeProvider(name="u", available=False)
        ok2 = _FakeProvider(name="ok2", available=True)
        cfg = RouteConfig(chains={TASK_CODE_REVIEW: ["ok1", "u", "ok2"]})
        router = Router(cfg)
        with patch.object(router, "_get", side_effect=lambda s: {"ok1": ok1, "u": u, "ok2": ok2}[s]):
            chain = router.available_chain(TASK_CODE_REVIEW)
        names = [p.name for p in chain]
        self.assertEqual(names, ["ok1", "ok2"])


class ParallelCallTests(unittest.TestCase):
    def test_returns_one_reply_per_spec(self):
        a = _FakeProvider(name="a", reply=Reply(text="from-a", provider="a", model="ma"))
        b = _FakeProvider(name="b", reply=Reply(text="from-b", provider="b", model="mb"))
        cfg = RouteConfig(chains={})
        router = Router(cfg)
        with patch.object(router, "_get", side_effect=lambda s: {"a": a, "b": b}[s]):
            replies = router.call_parallel(["a", "b"], "hi", max_tokens=10, timeout=30)
        self.assertEqual(len(replies), 2)
        self.assertEqual([s for s, _ in replies], ["a", "b"])
        self.assertEqual([r.text for _, r in replies], ["from-a", "from-b"])

    def test_continues_on_failure(self):
        bad = _FakeProvider(name="bad", reply=Reply(text="", provider="bad", model="mb", error="oops"))
        good = _FakeProvider(name="good", reply=Reply(text="ok", provider="good", model="mg"))
        cfg = RouteConfig(chains={})
        router = Router(cfg)
        with patch.object(router, "_get", side_effect=lambda s: {"bad": bad, "good": good}[s]):
            replies = router.call_parallel(["bad", "good"], "hi", max_tokens=10, timeout=30)
        self.assertEqual(replies[0][1].error, "oops")
        self.assertTrue(replies[1][1].ok)

    def test_empty_specs_returns_empty(self):
        router = Router(RouteConfig(chains={}))
        self.assertEqual(router.call_parallel([], "hi"), [])


class ReviewPairTests(unittest.TestCase):
    def test_returns_both_replies_and_agreement(self):
        agree_a = _FakeProvider(name="a", reply=Reply(text="no issues", provider="a", model="ma"))
        agree_b = _FakeProvider(name="b", reply=Reply(text="looks good", provider="b", model="mb"))
        cfg = RouteConfig(
            pairs={TASK_CODE_REVIEW: {"primary": "a", "secondary": "b"}},
        )
        router = Router(cfg)
        with patch.object(router, "_get", side_effect=lambda s: {"a": agree_a, "b": agree_b}[s]):
            result = router.review_pair(TASK_CODE_REVIEW, "hi", max_tokens=10, timeout=30)
        self.assertEqual(result["agreement"], "agree")
        self.assertEqual(result["primary"][0], "a")
        self.assertEqual(result["secondary"][0], "b")

    def test_partial_agreement_on_disagreement_marker(self):
        # OPUS-5: word-boundary regex now catches "this is wrong" as a
        # clear disagreement signal and returns "disagree" (not "partial").
        disagree = _FakeProvider(name="a", reply=Reply(text="However, this is wrong", provider="a", model="ma"))
        plain = _FakeProvider(name="b", reply=Reply(text="fine", provider="b", model="mb"))
        cfg = RouteConfig(
            pairs={TASK_CODE_REVIEW: {"primary": "a", "secondary": "b"}},
        )
        router = Router(cfg)
        with patch.object(router, "_get", side_effect=lambda s: {"a": disagree, "b": plain}[s]):
            result = router.review_pair(TASK_CODE_REVIEW, "hi", max_tokens=10, timeout=30)
        self.assertEqual(result["agreement"], "disagree")

    def test_word_boundary_avoid_substring_match(self):
        # OPUS-5: substring matching used to wrongly match "fine" inside
        # "define/refined" or similar. Word-boundary regex now avoids that.
        # "I am fine" and "I am fine" (literal duplicate) — should agree.
        a = _FakeProvider(name="a", reply=Reply(text="I am fine with this", provider="a", model="ma"))
        b = _FakeProvider(name="b", reply=Reply(text="this is fine for me", provider="b", model="mb"))
        cfg = RouteConfig(
            pairs={TASK_CODE_REVIEW: {"primary": "a", "secondary": "b"}},
        )
        router = Router(cfg)
        with patch.object(router, "_get", side_effect=lambda s: {"a": a, "b": b}[s]):
            result = router.review_pair(TASK_CODE_REVIEW, "hi", max_tokens=10, timeout=30)
        # Both contain the word "fine" as a full word (word-boundary match).
        # Old substring heuristic would also match these; this is the
        # trivial case. The interesting bug was the false-positive on
        # "fine" inside "refined"; tested separately below.
        self.assertEqual(result["agreement"], "agree")

    def test_word_boundary_rejects_substring(self):
        # OPUS-5: "fine" inside "refined" / "define" must NOT trigger agree.
        # Only one reply contains the standalone word "fine" — so no
        # shared agreement marker -> partial (or disagree if disagreement
        # is signaled, but neither is).
        a = _FakeProvider(name="a", reply=Reply(text="the design is refined", provider="a", model="ma"))
        b = _FakeProvider(name="b", reply=Reply(text="this is fine", provider="b", model="mb"))
        cfg = RouteConfig(
            pairs={TASK_CODE_REVIEW: {"primary": "a", "secondary": "b"}},
        )
        router = Router(cfg)
        with patch.object(router, "_get", side_effect=lambda s: {"a": a, "b": b}[s]):
            result = router.review_pair(TASK_CODE_REVIEW, "hi", max_tokens=10, timeout=30)
        # "fine" only in b. No shared marker. Result: partial.
        self.assertEqual(result["agreement"], "partial")

    def test_word_boundary_agree_marker(self):
        # Both replies use full-word "agree" markers.
        a = _FakeProvider(name="a", reply=Reply(text="I agree, looks good", provider="a", model="ma"))
        b = _FakeProvider(name="b", reply=Reply(text="no issues found", provider="b", model="mb"))
        cfg = RouteConfig(
            pairs={TASK_CODE_REVIEW: {"primary": "a", "secondary": "b"}},
        )
        router = Router(cfg)
        with patch.object(router, "_get", side_effect=lambda s: {"a": a, "b": b}[s]):
            result = router.review_pair(TASK_CODE_REVIEW, "hi", max_tokens=10, timeout=30)
        self.assertEqual(result["agreement"], "agree")

    def test_falls_back_to_chain_when_no_pair(self):
        only = _FakeProvider(name="only", reply=Reply(text="ok", provider="only", model="m"))
        cfg = RouteConfig(
            chains={TASK_CODE_REVIEW: ["only"]},
            pairs={},
        )
        router = Router(cfg)
        with patch.object(router, "_get", return_value=only):
            result = router.review_pair(TASK_CODE_REVIEW, "hi", max_tokens=10, timeout=30)
        self.assertEqual(result["primary"][0], "only")
        self.assertIsNone(result["secondary"])
        self.assertEqual(result["agreement"], "unknown")


if __name__ == "__main__":
    unittest.main()
