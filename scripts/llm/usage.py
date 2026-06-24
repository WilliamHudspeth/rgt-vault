"""Usage tracking for the multi-LLM router.

Logs every provider call (input_tokens, output_tokens, latency_ms,
task_type) to a CSV file so we can:
  - see which providers are actually being used
  - estimate cost
  - monitor the Gemini OAuth-personal quota burn rate

The CSV is append-only. Safe to import from any provider.

Multi-process safety (OPUS-AFK-5): healthcheck.py runs loops A/B/C
as separate processes (per CLAUDE.md / honcho design) that all
append to the same /tmp/rgt_llm_usage.csv. The threading.Lock here
is per-process only — three concurrent writers can interleave rows
once the per-line write exceeds PIPE_BUF (4 KiB on Linux). We hold
an fcntl advisory lock around the append+header-check section so
the file is written atomically per row across processes.
"""

from __future__ import annotations

import csv
import fcntl
import os
import threading
import time
from pathlib import Path

# Default location. Override via RGT_USAGE_LOG env var.
DEFAULT_LOG_PATH = Path(os.environ.get("RGT_USAGE_LOG", "/tmp/rgt_llm_usage.csv"))

# In-process serialization (cheap, always taken).
# Cross-process serialization is via fcntl below.
_lock = threading.Lock()


def _append_row(p: Path, row: list) -> None:
    """Append a single row to the CSV under an advisory file lock.

    OPUS-AFK-5: three healthcheck loops (A/B/C) write concurrently to
    the same CSV from separate processes. A threading.Lock only
    guards threads within one process, so concurrent processes can
    interleave writes and corrupt the CSV. fcntl.flock gives us
    cross-process POSIX advisory locking.

    Two passes under the lock:
      1. If the file doesn't exist, create it with the header.
      2. Append the row.
    The header-check + append is a single critical section so two
    processes can't both observe "no file" and write the header twice.
    """
    with _lock:  # in-process: serialize threads
        # Open for read+write+create, append mode. text mode for csv module.
        # newline="" is required for csv writer per Python docs.
        with open(p, "a", newline="") as f:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            except (OSError, AttributeError):
                # fcntl isn't available on Windows. We accept the
                # risk that a Windows healthcheck won't be safe; the
                # production deployment is Linux only.
                pass
            try:
                w = csv.writer(f)
                # Header check: if we're at byte 0 (or first write to
                # an empty file just opened in 'a' mode would have us
                # at byte 0), write the header. We use f.tell() to
                # detect this without an extra stat() call. The
                # check+write+append is one critical section.
                if f.tell() == 0:
                    w.writerow(
                        [
                            "ts",
                            "provider",
                            "model",
                            "task_type",
                            "spec",
                            "input_tokens",
                            "output_tokens",
                            "latency_ms",
                            "ok",
                            "error",
                        ]
                    )
                w.writerow(row)
            finally:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                except (OSError, AttributeError):
                    pass


def log(
    *,
    provider: str,
    model: str,
    task_type: str = "",
    spec: str = "",
    input_tokens: int = 0,
    output_tokens: int = 0,
    latency_ms: int = 0,
    ok: bool = True,
    error: str = "",
    path: Path | None = None,
) -> None:
    """Append one usage row.

    OPUS-AFK-5 (fix): the old docstring said "no-op if all numeric
    fields are 0 AND no error", but the code always wrote. Either
    the contract or the behavior was wrong. The behavior (always
    write) is more useful — we want to see failed calls — so the
    code stays, and the docstring is corrected.
    """
    p = path or DEFAULT_LOG_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    _append_row(
        p,
        [
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            provider,
            model,
            task_type,
            spec,
            input_tokens,
            output_tokens,
            latency_ms,
            int(ok),
            error[:200] if error else "",
        ],
    )


def totals(path: Path | None = None) -> dict:
    """Aggregate totals per (provider, model). Returns a dict."""
    p = path or DEFAULT_LOG_PATH
    if not p.exists():
        return {}
    agg: dict = {}
    with open(p) as f:
        for row in csv.DictReader(f):
            key = (row["provider"], row["model"])
            if key not in agg:
                agg[key] = {
                    "calls": 0,
                    "ok": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "latency_ms_total": 0,
                }
            a = agg[key]
            a["calls"] += 1
            if row["ok"] == "1":
                a["ok"] += 1
            try:
                a["input_tokens"] += int(row["input_tokens"] or 0)
                a["output_tokens"] += int(row["output_tokens"] or 0)
                a["latency_ms_total"] += int(row["latency_ms"] or 0)
            except ValueError:
                pass
    return agg


def summary(path: Path | None = None) -> str:
    """Render a human-readable summary."""
    p = path or DEFAULT_LOG_PATH
    agg = totals(p)
    if not agg:
        return f"no usage data at {p}"
    lines = [f"Usage summary from {p}:", ""]
    lines.append(f"{'provider':<28} {'model':<28} {'calls':>6} {'ok':>4} {'in_tok':>10} {'out_tok':>10} {'avg_ms':>8}")
    lines.append("-" * 100)
    for (provider, model), a in sorted(agg.items()):
        avg_ms = a["latency_ms_total"] / max(a["calls"], 1)
        lines.append(
            f"{provider:<28} {model:<28} {a['calls']:>6} {a['ok']:>4} "
            f"{a['input_tokens']:>10} {a['output_tokens']:>10} {avg_ms:>8.0f}"
        )
    return "\n".join(lines)
