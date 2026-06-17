"""Usage tracking for the multi-LLM router.

Logs every provider call (input_tokens, output_tokens, latency_ms,
task_type) to a CSV file so we can:
  - see which providers are actually being used
  - estimate cost
  - monitor the Gemini OAuth-personal quota burn rate

The CSV is append-only. Safe to import from any provider.
"""
from __future__ import annotations

import csv
import os
import threading
import time
from pathlib import Path

# Default location. Override via RGT_USAGE_LOG env var.
DEFAULT_LOG_PATH = Path(os.environ.get("RGT_USAGE_LOG", "/tmp/rgt_llm_usage.csv"))

# Thread-safe single-writer lock for the CSV.
_lock = threading.Lock()


def _ensure_header(path: Path) -> None:
    """Create the CSV with header if it doesn't exist yet."""
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow([
            "ts", "provider", "model", "task_type", "spec",
            "input_tokens", "output_tokens", "latency_ms",
            "ok", "error",
        ])


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
    """Append one usage row. No-op if all numeric fields are 0 AND no error.

    Useful for failed calls where we never got a response — we still
    want to record the attempt.
    """
    p = path or DEFAULT_LOG_PATH
    with _lock:
        _ensure_header(p)
        with open(p, "a", newline="") as f:
            csv.writer(f).writerow([
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
            ])


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
    lines.append(f"{'provider':<28} {'model':<28} {'calls':>6} {'ok':>4} "
                 f"{'in_tok':>10} {'out_tok':>10} {'avg_ms':>8}")
    lines.append("-" * 100)
    for (provider, model), a in sorted(agg.items()):
        avg_ms = a["latency_ms_total"] / max(a["calls"], 1)
        lines.append(
            f"{provider:<28} {model:<28} {a['calls']:>6} {a['ok']:>4} "
            f"{a['input_tokens']:>10} {a['output_tokens']:>10} {avg_ms:>8.0f}"
        )
    return "\n".join(lines)
