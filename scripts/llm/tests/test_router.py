"""Unit tests for the router. Offline — no real provider calls."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from scripts.llm.router import (
    Router,
    RouteConfig,
    TASK_CODE_REVIEW,
    TASK_GENERAL,
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
        from pathlib import Path

        d = RouteConfig.default()
        with tempfile_patch() as p:
            p.write_text(yaml.safe_dump({"chains": d.chains}))
            loaded = RouteConfig.load(p)
            self.assertEqual(loaded.chains, d.chains)


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
            reply=Reply(
                text="", provider="bad", model="b", error="HTTP 500"
            ),
        )
        cfg = RouteConfig(
            chains={TASK_CODE_REVIEW: ["bad", "good", "unused"]},
        )
        router = Router(cfg)
        with patch.object(router, "_get", side_effect=lambda s: {"bad": bad, "good": good, "unused": _FakeProvider(name="u")}[s]):
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


if __name__ == "__main__":
    unittest.main()
