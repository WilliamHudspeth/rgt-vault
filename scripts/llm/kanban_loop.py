#!/usr/bin/env python3
"""AFK kanban processor for rgt-vault.

Scans the Multica workspace, picks tickets in scope (todo/in_progress),
runs the multi-model review via the router, posts a synthesis comment,
and records which tickets have been processed so the loop is idempotent.

State is kept in /tmp (or a configurable path) so each invocation is
independent — the AFK cron just calls this script repeatedly and it does
the right thing.

Routing (delegated to Router.pair_for):
  code-review    -> gemini-cli + ollama-coder cross-check
  design-review  -> gemini-cli + claude-cli cross-check
  security-review-> claude-cli + gemini-cli cross-check
  fast-qa        -> groq + ollama-0.5b cross-check

Usage:
  python3 scripts/llm/kanban_loop.py --dry-run                 # plan only
  python3 scripts/llm/kanban_loop.py --once                    # one pass
  python3 scripts/llm/kanban_loop.py --once --limit 5          # cap batch size
  python3 scripts/llm/kanban_loop.py --once --milestone v0.2.0 # scope to milestone
  python3 scripts/llm/kanban_loop.py --reset-state            # reprocess all
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.program._common import list_issues, get_issue, WORKSPACE_ID, label_set
from scripts.llm.router import Router
from scripts.llm.kanban_review import pick_task_type, build_prompt, post_comment


DEFAULT_STATE_PATH = Path("/tmp/rgt_kanban_loop_state.json")


def load_state(path: Path) -> dict:
    if not path.exists():
        return {"processed": {}, "last_run": None}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {"processed": {}, "last_run": None}


def save_state(state: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True))


def ticket_changed(ticket: dict, prev_signature: str) -> bool:
    """Has the ticket changed since we last processed it?

    Signature is a hash of (updated_at, labels, description). If any of
    those change, we re-process.
    """
    sig = {
        "updated_at": ticket.get("updated_at"),
        "description": ticket.get("description") or "",
        "labels": sorted(label_set(ticket)),
    }
    return json.dumps(sig, sort_keys=True) != prev_signature


def signature(ticket: dict) -> str:
    sig = {
        "updated_at": ticket.get("updated_at"),
        "description": ticket.get("description") or "",
        "labels": sorted(label_set(ticket)),
    }
    return json.dumps(sig, sort_keys=True)


def _safe_id(resp_body: str) -> str:
    """Extract an id field from a JSON response body, returning '' on failure.

    The Multica response body may be truncated to 300 chars by the
    kanban_review.post_comment helper; tolerate that.
    """
    if not resp_body:
        return ""
    try:
        d = json.loads(resp_body)
        return d.get("id", "") if isinstance(d, dict) else ""
    except Exception:
        return ""


def main() -> int:
    p = argparse.ArgumentParser(description="AFK kanban processor")
    p.add_argument("--dry-run", action="store_true",
                   help="plan the loop, don't call LLMs or post comments")
    p.add_argument("--once", action="store_true",
                   help="run one pass and exit (default for cron use)")
    p.add_argument("--loop", action="store_true",
                   help="keep running indefinitely (sleep between passes)")
    p.add_argument("--sleep", type=int, default=60,
                   help="seconds between passes when --loop is set")
    p.add_argument("--limit", type=int, default=10,
                   help="max tickets per pass")
    p.add_argument("--status", default="todo,in_progress",
                   help="comma-separated statuses to include")
    p.add_argument("--milestone", default=None,
                   help="filter to tickets in this milestone project (e.g. v0.2.0)")
    p.add_argument("--state", default=str(DEFAULT_STATE_PATH),
                   help="path to state file (default /tmp/rgt_kanban_loop_state.json)")
    p.add_argument("--reset-state", action="store_true",
                   help="ignore previous state and re-process all in-scope tickets")
    p.add_argument("--workspace-id", default=WORKSPACE_ID)
    p.add_argument("--max-tokens", type=int, default=600)
    p.add_argument("--timeout", type=int, default=180)
    p.add_argument("--quiet", action="store_true",
                   help="suppress per-ticket output (only summary)")
    args = p.parse_args()

    if not args.once and not args.loop:
        # Default to --once for safety. Cron-friendly.
        args.once = True

    state_path = Path(args.state)
    if args.reset_state and state_path.exists():
        state_path.unlink()
    state = load_state(state_path)
    processed = state.setdefault("processed", {})

    statuses = set(s.strip() for s in args.status.split(",") if s.strip())
    router = Router()

    pass_count = 0
    while True:
        pass_count += 1
        if not args.quiet:
            print(f"\n=== PASS {pass_count} @ {time.strftime('%Y-%m-%d %H:%M:%S')} ===",
                  file=sys.stderr)

        issues = list_issues(args.workspace_id, limit=300)

        # Resolve project_id for milestone filter (we need to look up
        # the project's id by its title prefix)
        milestone_project_id = None
        if args.milestone:
            from scripts.program._common import list_projects
            projects = list_projects(args.workspace_id)
            for p_obj in projects:
                title = p_obj.get("title", "")
                if title.startswith(args.milestone + " ") or title.startswith(args.milestone + "-"):
                    milestone_project_id = p_obj["id"]
                    break
            if not milestone_project_id:
                print(f"WARNING: milestone {args.milestone!r} not found", file=sys.stderr)

        # Select tickets
        selected = []
        for i in issues:
            if statuses and i.get("status") not in statuses:
                continue
            if milestone_project_id and i.get("project_id") != milestone_project_id:
                continue
            selected.append(i)
        selected = selected[: args.limit]

        processed_this_pass = 0
        for i in selected:
            tid = i.get("identifier", i.get("id"))
            full = get_issue(tid, args.workspace_id) or i

            # Skip if already processed and unchanged
            sig = signature(full)
            prev = processed.get(tid)
            if prev and not args.reset_state and not ticket_changed(full, prev.get("signature", "")):
                if not args.quiet:
                    print(f"  [skip] {tid} already processed @ {prev.get('at','?')}",
                          file=sys.stderr)
                continue

            task = pick_task_type(full)
            pair = router.pair_for(task)
            prompt = build_prompt(full)

            if args.dry_run:
                print(json.dumps({
                    "ticket": tid,
                    "title": full.get("title"),
                    "task": task,
                    "labels": sorted(label_set(full)),
                    "status": full.get("status"),
                    "pair": pair,
                }, indent=2))
                continue

            if not args.quiet:
                print(f"\n  [{tid}] {task} via {pair.get('primary')} + {pair.get('secondary')}",
                      file=sys.stderr)

            specs = [s for s in (pair.get("primary"), pair.get("secondary")) if s]
            t0 = time.time()
            replies = router.call_parallel(
                specs, prompt,
                max_tokens=args.max_tokens,
                timeout=args.timeout,
            )
            wall = int((time.time() - t0) * 1000)

            ok = [(s, r) for s, r in replies if r.ok]
            errs = [(s, r) for s, r in replies if not r.ok]

            if not ok:
                if not args.quiet:
                    print(f"  [{tid}] all models failed, skipping comment post",
                          file=sys.stderr)
                continue

            # Build synthesis comment
            lines = [
                f"**AFK multi-model review** (Hermes kanban_loop)",
                f"Ticket: {tid} ({full.get('title')})",
                f"Task type: `{task}`",
                f"Models: {', '.join(s for s, _ in ok)}",
                f"Wall time: {wall}ms",
                "",
            ]
            for spec, r in ok:
                lines.append(f"---\n**{spec}** ({r.provider}/{r.model}, "
                             f"{r.latency_ms}ms, in={r.input_tokens} out={r.output_tokens}):\n")
                lines.append(r.text)
                lines.append("")
            if errs:
                lines.append("---")
                lines.append("Errors:")
                for spec, r in errs:
                    lines.append(f"- {spec}: {r.error}")
                lines.append("")

            comment = "\n".join(lines)
            status_code, resp = post_comment(full, comment, args.workspace_id)
            if 200 <= status_code < 300:
                if not args.quiet:
                    print(f"  [{tid}] posted synthesis (HTTP {status_code})",
                          file=sys.stderr)
                processed[tid] = {
                    "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "signature": sig,
                    "task": task,
                    "models": [s for s, _ in ok],
                    "comment_id": _safe_id(resp),
                }
                processed_this_pass += 1
            else:
                if not args.quiet:
                    print(f"  [{tid}] comment post failed: HTTP {status_code}: {resp[:200]}",
                          file=sys.stderr)

        state["last_run"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        save_state(state, state_path)

        if not args.quiet:
            print(f"\n=== PASS {pass_count} done. Processed {processed_this_pass} tickets. "
                  f"State: {state_path}", file=sys.stderr)

        if args.once:
            return 0

        time.sleep(args.sleep)


if __name__ == "__main__":
    sys.exit(main())
