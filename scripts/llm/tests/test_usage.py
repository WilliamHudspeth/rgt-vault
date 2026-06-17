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

    def test_header_written_once_under_concurrent_processes(self):
        """OPUS-AFK-5: under multi-process concurrent writers, the header
        must be written exactly once and every row must be intact."""
        import multiprocessing as mp
        import csv as _csv

        def worker(pid: int, path: str, n: int) -> None:
            import sys
            sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
            from scripts.llm import usage as u
            for i in range(n):
                u.log(
                    provider=f"p{pid}", model=f"m{pid}",
                    input_tokens=1, output_tokens=1, latency_ms=1, ok=True,
                    path=Path(path),
                )

        # 3 processes, 20 rows each — enough to race the header
        # detection if fcntl locking isn't in place.
        n_per = 20
        procs = [mp.Process(target=worker, args=(i, str(self.path), n_per)) for i in range(3)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=30)
        for p in procs:
            self.assertEqual(p.exitcode, 0, f"process {p.pid} exited with {p.exitcode}")

        with open(self.path) as f:
            rows = list(_csv.DictReader(f))
        # Exactly n_per * 3 data rows, no duplicates, no interleaved header.
        self.assertEqual(len(rows), 3 * n_per, f"expected {3*n_per} rows, got {len(rows)}")
        # All rows must have all 10 fields.
        for r in rows:
            self.assertEqual(set(r.keys()), {
                "ts", "provider", "model", "task_type", "spec",
                "input_tokens", "output_tokens", "latency_ms", "ok", "error",
            }, f"row has wrong fields: {r.keys()}")
        # Count per (provider, model) must be exactly n_per.
        from collections import Counter
        c = Counter((r["provider"], r["model"]) for r in rows)
        for i in range(3):
            self.assertEqual(c[(f"p{i}", f"m{i}")], n_per,
                             f"provider p{i} got {c[(f'p{i}', f'm{i}')]} rows, want {n_per}")

    def test_log_always_writes_even_on_zero_tokens(self):
        """OPUS-AFK-5: the old docstring said no-op on all-zero numeric
        fields; the code always wrote. Confirm the actual behavior
        (always write) and the docstring now match."""
        usage.log(provider="p", model="m", path=self.path, ok=False, error="boom")
        text = self.path.read_text()
        # Even with 0 tokens and an error, the row must be recorded.
        self.assertIn("boom", text)


if __name__ == "__main__":
    unittest.main()
