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

    MUST use the same field set as `signature()` so the comparison is
    well-defined. See OPUS-16: updated_at is excluded because posting
    a comment bumps it. Computing the signature with a *different* set
    of fields than `signature()` means the two JSON strings can never
    be equal, the function always returns True, and every ticket is
    re-processed and re-commented on every pass.
    """
    return signature(ticket) != prev_signature


def signature(ticket: dict) -> str:
    """Compute a stable signature for a ticket.

    NOTE (OPUS-16): we deliberately exclude `updated_at` from the
    signature. Posting a comment to Multica bumps `updated_at` on the
    ticket, which would otherwise cause the next pass of the kanban loop
    to re-process (and re-comment) every ticket we just touched, forever.
    Use content-only fields: description + labels.
    """
    sig = {
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


def _backoff_minutes(fail_count: int) -> int:
    """Exponential backoff schedule for retried tickets.

    Pattern: 1, 5, 25, 120, 720, 1440 (capped at 24h).
    """
    schedule = [1, 5, 25, 120, 720, 1440]
    if fail_count <= 0:
        return 1
    if fail_count > len(schedule):
        return schedule[-1]
    return schedule[fail_count - 1] if fail_count <= len(schedule) else schedule[-1]  # never reached


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
    # OPUS-15: reset_state must be a one-shot, not a persistent flag.
    # If we keep it as a flag, the skip predicate (`not args.reset_state`)
    # will never fire in --loop mode and every ticket will be re-processed.
    # Fix: set a one-shot `reset_state_run` flag, clear reset_state after
    # the unlink, and use reset_state_run in the skip predicate.
    args.reset_state_run = False
    if args.reset_state and state_path.exists():
        state_path.unlink()
        args.reset_state_run = True
        # Clear the CLI flag so it doesn't keep triggering.
        args.reset_state = False
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
            tid = i.get("identifier") or i.get("id") or "<unknown>"
            # OPUS-13: wrap each ticket in try/except so one bad ticket
            # doesn't crash the loop and lose state for everything else.
            try:
                _process_one_ticket(
                    i, tid, args, router, processed,
                    state, state_path,
                )
                processed_this_pass += 1
            except Exception as e:
                # Don't mark as processed (so we retry next pass); but
                # don't kill the loop. Log + continue.
                if not args.quiet:
                    print(f"  [{tid}] EXCEPTION: {type(e).__name__}: {e}",
                          file=sys.stderr)

        state["last_run"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        save_state(state, state_path)

        if not args.quiet:
            print(f"\n=== PASS {pass_count} done. Processed {processed_this_pass} tickets. "
                  f"State: {state_path}", file=sys.stderr)

        if args.once:
            return 0

        time.sleep(args.sleep)


def _process_one_ticket(issue_summary, tid, args, router, processed, state, state_path):
    """Process a single ticket: skip-if-processed, dispatch, post comment.

    Extracted to enable OPUS-13 exception isolation per ticket.
    """
    full = get_issue(tid, args.workspace_id) or issue_summary

    # OPUS-14: back off retries for tickets that have failed recently.
    # Check the per-state-file failures JSON; skip if last attempt was
    # within the cooldown window. Exponential: 1m, 5m, 25m, 2h, 12h.
    failure_path = state_path.with_suffix(".failures.json")
    failures = {}
    if failure_path.exists():
        try:
            failures = json.loads(failure_path.read_text())
        except Exception:
            pass
    fail_info = failures.get(tid)
    if fail_info and not args.reset_state_run:
        cooldown_min = _backoff_minutes(fail_info.get("count", 1))
        last_attempt = fail_info.get("last_attempt")
        if last_attempt:
            try:
                last_t = time.mktime(time.strptime(last_attempt, "%Y-%m-%dT%H:%M:%SZ"))
                age_min = (time.time() - last_t) / 60
                if age_min < cooldown_min:
                    if not args.quiet:
                        print(f"  [skip-fail] {tid} failed {fail_info['count']}x, "
                              f"cooldown {cooldown_min}m, only {age_min:.1f}m ago",
                              file=sys.stderr)
                    return
            except Exception:
                pass

    # Skip if already processed and unchanged
    sig = signature(full)
    prev = processed.get(tid)
    if prev and not args.reset_state_run and not ticket_changed(full, prev.get("signature", "")):
        if not args.quiet:
            print(f"  [skip] {tid} already processed @ {prev.get('at','?')}",
                  file=sys.stderr)
        return

    task = pick_task_type(full)
    pair = router.pair_for(task)
    prompt = build_prompt(full)

    if args.dry_run:
        print(json.dumps({
            "ticket": tid,
            "title": full.get("title"),
            "task_type": task,
            "labels": sorted(label_set(full)),
            "status": full.get("status"),
            "pair": pair,
        }, indent=2))
        return

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
        # OPUS-14: don't mark as processed; record failure so we can
        # back off. The retry counter is stored in a sidecar failures
        # file, not the main state file (so failure noise doesn't dirty
        # the "successful processed" set).
        info = failures.get(tid, {"count": 0, "last_attempt": None, "last_error": None})
        info["count"] = info.get("count", 0) + 1
        info["last_attempt"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        info["last_error"] = errs[0][1].error if errs else "all models failed"
        failures[tid] = info
        failure_path.write_text(json.dumps(failures, indent=2, sort_keys=True))
        if not args.quiet:
            cooldown = _backoff_minutes(info["count"])
            print(f"  [{tid}] all models failed (attempt #{info['count']}), "
                  f"skipping comment post; cooldown {cooldown}m",
                  file=sys.stderr)
        return

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
    else:
        if not args.quiet:
            print(f"  [{tid}] comment post failed: HTTP {status_code}: {resp[:200]}",
                  file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
