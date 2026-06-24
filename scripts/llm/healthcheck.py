"""Health check for the multi-LLM router + running background loops.

Reports:
  - Provider availability (which providers are usable right now)
  - Background loop liveness (PIDs running, last_run timestamps)
  - Multica reachability
  - Token burn rate (last hour, by provider)

Exit code:
  0 - everything healthy
  1 - warnings (some loops stuck)
  2 - critical (no providers available, multica unreachable)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.llm.router import Router


def check_providers(router: Router) -> dict:
    """Return {task_type: [available_provider_names]}."""
    out = {}
    for task in ["code-review", "design-review", "security-review", "fast-qa", "general"]:
        out[task] = [p.name for p in router.available_chain(task)]
    return out


def check_loop_state(state_path: Path, label: str) -> dict:
    """Read a kanban_loop state file and report its health."""
    if not state_path.exists():
        return {"label": label, "state": "missing", "processed": 0}
    try:
        d = json.loads(state_path.read_text())
    except Exception as e:
        return {"label": label, "state": f"unreadable: {e}", "processed": 0}
    last_run = d.get("last_run")
    processed = len(d.get("processed", {}))
    if last_run:
        # Age of last_run
        try:
            last = time.mktime(time.strptime(last_run, "%Y-%m-%dT%H:%M:%SZ"))
            age_min = (time.time() - last) / 60
        except Exception:
            age_min = None
    else:
        age_min = None
    return {
        "label": label,
        "state": "ok",
        "processed": processed,
        "last_run": last_run,
        "last_run_age_min": age_min,
    }


def check_multica(workspace_id: str) -> tuple:
    """Check Multica reachability + comment count."""
    try:
        cfg = Path.home() / ".multica" / "config.json"
        if not cfg.exists():
            return False, "no ~/.multica/config.json"
        token = json.load(open(cfg))["token"]
        req = urllib.request.Request(
            f"http://10.10.88.88:8080/api/issues?workspace_id={workspace_id}&limit=10",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        return True, f"Multica OK, {len(data.get('issues', []))} issues sampled"
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        return False, f"Multica: {e}"


def check_burn_rate(log_path: Path) -> dict:
    """Compute tokens used in the last hour per provider."""
    if not log_path.exists():
        return {}
    cutoff = time.time() - 3600
    out: dict = {}
    with open(log_path) as f:
        next(f)  # skip header
        for line in f:
            parts = line.strip().split(",")
            if len(parts) < 7:
                continue
            try:
                ts = parts[0]
                provider = parts[1]
                in_tok = int(parts[5]) if parts[5] else 0
                out_tok = int(parts[6]) if parts[6] else 0
                t = time.mktime(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
            except (ValueError, IndexError):
                continue
            if t < cutoff:
                continue
            out.setdefault(provider, {"calls": 0, "in_tok": 0, "out_tok": 0})
            out[provider]["calls"] += 1
            out[provider]["in_tok"] += in_tok
            out[provider]["out_tok"] += out_tok
    return out


def main() -> int:
    router = Router()

    print("=" * 70)
    print(f"MULTI-LLM HEALTH CHECK @ {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print("=" * 70)

    # Providers
    print("\n[1] PROVIDER AVAILABILITY")
    prov = check_providers(router)
    for task, names in prov.items():
        if names:
            print(f"  {task:>15}: {' '.join(names)}")
        else:
            print(f"  {task:>15}: (NO PROVIDERS AVAILABLE)")

    # Multica
    print("\n[2] MULTICA REACHABILITY")
    from scripts.program._common import WORKSPACE_ID

    ok, msg = check_multica(WORKSPACE_ID)
    print(f"  {'OK' if ok else 'FAIL'}: {msg}")

    # Background loops
    print("\n[3] BACKGROUND LOOPS")
    for state_file, label in [
        ("/tmp/rgt_kanban_loop_state.json", "loop A (standard)"),
        ("/tmp/rgt_kanban_loop_state_b.json", "loop B (deep-dive)"),
        ("/tmp/rgt_kanban_loop_state_c.json", "loop C (maxed-out)"),
    ]:
        info = check_loop_state(Path(state_file), label)
        if info["state"] == "ok":
            age = info.get("last_run_age_min")
            age_s = f"{age:.1f}min ago" if age is not None else "never"
            print(f"  {label:<25} processed={info['processed']:>3d}  last_run={info['last_run']} ({age_s})")
        else:
            print(f"  {label:<25} {info['state']}")

    # Burn rate
    print("\n[4] BURN RATE (last 1h)")
    burn = check_burn_rate(Path("/tmp/rgt_llm_usage.csv"))
    if burn:
        for provider, stats in sorted(burn.items()):
            print(f"  {provider:<28} calls={stats['calls']:>4d}  in={stats['in_tok']:>6d}  out={stats['out_tok']:>6d}")
    else:
        print("  (no calls in last hour)")

    # Process liveness
    print("\n[5] PROCESS LIVENESS")
    r = subprocess.run(["ps", "-ef"], capture_output=True, text=True)
    pids = []
    for line in r.stdout.splitlines():
        if ("kanban_loop" in line or "scripts/llm/cli.py burn" in line) and "grep" not in line:
            pid = line.split()[1]
            pids.append(pid)
    print(f"  {len(pids)} background python processes running")
    if pids:
        print(f"  PIDs: {', '.join(pids)}")

    print("\n" + "=" * 70)

    # Exit code: 0 if at least one provider works AND multica reachable
    any_provider = any(prov[t] for t in prov)
    if not ok:
        return 2  # critical
    if not any_provider:
        return 1  # warning
    return 0


if __name__ == "__main__":
    sys.exit(main())
