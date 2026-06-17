"""Unit tests for scripts/llm/usage.py.

Offline. Uses a temp CSV path so the global /tmp/rgt_llm_usage.csv
is never touched.
"""
import unittest
import tempfile
from pathlib import Path

from scripts.llm import usage


class UsageLogTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path = Path(self.tmpdir) / "usage.csv"

    def test_log_creates_header(self):
        usage.log(provider="p1", model="m1", path=self.path, ok=True)
        text = self.path.read_text()
        self.assertIn("ts,provider,model", text)
        self.assertIn("p1,m1", text)

    def test_multiple_calls_aggregate(self):
        usage.log(provider="p1", model="m1", input_tokens=10, output_tokens=20,
                  latency_ms=100, ok=True, path=self.path)
        usage.log(provider="p1", model="m1", input_tokens=5, output_tokens=15,
                  latency_ms=200, ok=True, path=self.path)
        usage.log(provider="p2", model="m2", input_tokens=1, output_tokens=1,
                  latency_ms=50, ok=True, path=self.path)
        agg = usage.totals(self.path)
        self.assertEqual(agg[("p1", "m1")]["calls"], 2)
        self.assertEqual(agg[("p1", "m1")]["input_tokens"], 15)
        self.assertEqual(agg[("p1", "m1")]["output_tokens"], 35)
        self.assertEqual(agg[("p1", "m1")]["latency_ms_total"], 300)
        self.assertEqual(agg[("p2", "m2")]["calls"], 1)

    def test_thread_safety(self):
        import threading
        def worker():
            for _ in range(50):
                usage.log(provider="p1", model="m1", input_tokens=1,
                          output_tokens=1, latency_ms=1, ok=True, path=self.path)
        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads: t.start()
        for t in threads: t.join()
        agg = usage.totals(self.path)
        self.assertEqual(agg[("p1", "m1")]["calls"], 200)

    def test_summary_includes_all_rows(self):
        usage.log(provider="a", model="x", input_tokens=1, output_tokens=1,
                  latency_ms=10, ok=True, path=self.path)
        usage.log(provider="b", model="y", input_tokens=2, output_tokens=2,
                  latency_ms=20, ok=False, error="boom", path=self.path)
        s = usage.summary(self.path)
        self.assertIn("a", s)
        self.assertIn("b", s)
        self.assertIn("x", s)
        self.assertIn("y", s)

    def test_totals_empty_file(self):
        agg = usage.totals(self.path)
        self.assertEqual(agg, {})


if __name__ == "__main__":
    unittest.main()
