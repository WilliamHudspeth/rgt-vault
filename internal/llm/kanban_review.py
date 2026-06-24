#!/usr/bin/env python3
"""Kanban dispatch: scan Multica tickets, route reviews through the LLM router.

Reads tickets from the rgt-vault Multica workspace, picks a review task
based on the ticket's labels, calls the appropriate provider via the
router, and posts the result back as a comment on the ticket.

Routing rules (label -> task type):
  comp:crypto / security:crypto / pri:blocker   -> security-review
  effort:L / effort:XL / type:design            -> design-review
  comp:*                                        -> code-review
  (default)                                     -> code-review

Usage:
  python3 scripts/llm/kanban_review.py --dry-run           # scan, show plan, don't post
  python3 scripts/llm/kanban_review.py --limit 3           # process N tickets
  python3 scripts/llm/kanban_review.py --identifier RGT-26 # process one ticket
  python3 scripts/llm/kanban_review.py --status todo,in_progress
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Allow running as a script without install
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.llm.router import (
    TASK_CODE_REVIEW,
    TASK_DESIGN_REVIEW,
    TASK_SECURITY_REVIEW,
    Router,
)
from scripts.program._common import WORKSPACE_ID, get_issue, list_issues


def label_set(ticket: dict) -> set:
    """Pull all label names out of a Multica ticket dict."""
    out = set()
    for lab in ticket.get("labels") or []:
        if isinstance(lab, dict):
            n = lab.get("name")
        else:
            n = lab
        if n:
            out.add(n)
    return out


def pick_task_type(ticket: dict) -> str:
    """Decide which router task type to use for a ticket."""
    labels = label_set(ticket)
    # Security-critical first
    if "comp:crypto" in labels or any(lbl.startswith("security:") for lbl in labels) or "pri:blocker" in labels:
        return TASK_SECURITY_REVIEW
    # Architecture / design
    if "effort:L" in labels or "effort:XL" in labels or "type:design" in labels:
        return TASK_DESIGN_REVIEW
    # Default: code review for any component-tagged ticket
    return TASK_CODE_REVIEW


def build_prompt(ticket: dict) -> str:
    """Build the prompt for the LLM call from the ticket content."""
    title = ticket.get("title", "(no title)")
    desc = ticket.get("description") or ticket.get("body") or ""
    tid = ticket.get("identifier", "?")
    labels = sorted(label_set(ticket))
    return (
        f"Review the following ticket for the rgt-vault project.\n\n"
        f"Ticket: {tid}\n"
        f"Title: {title}\n"
        f"Labels: {', '.join(labels)}\n"
        f"Status: {ticket.get('status', '?')}\n\n"
        f"Description:\n{desc}\n\n"
        f"Reply with concrete, actionable findings. "
        f"If the ticket is well-defined and you have no concerns, say so explicitly."
    )


def post_comment(ticket: dict, body: str, workspace_id: str) -> tuple:
    """Post a comment to Multica. Returns (status, body)."""
    import urllib.error
    import urllib.request

    url = f"http://10.10.88.88:8080/api/issues/{ticket['id']}/comments?workspace_id={workspace_id}"
    cfg_path = Path.home() / ".multica" / "config.json"
    if not cfg_path.exists():
        return 0, "no token"
    token = json.load(open(cfg_path))["token"]
    data = json.dumps({"content": body}).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()[:300].decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:300].decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def main() -> int:
    p = argparse.ArgumentParser(description="Kanban review dispatcher")
    p.add_argument("--dry-run", action="store_true", help="plan the dispatch but do not call LLMs or post comments")
    p.add_argument("--limit", type=int, default=5, help="max tickets to process (default 5)")
    p.add_argument("--identifier", help="process a single ticket by RGT-N")
    p.add_argument(
        "--status", default="todo,in_progress", help="comma-separated statuses to include (default 'todo,in_progress')"
    )
    p.add_argument("--workspace-id", default=WORKSPACE_ID)
    p.add_argument("--max-tokens", type=int, default=600)
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("--json", action="store_true", help="emit JSON envelope per ticket")
    args = p.parse_args()

    statuses = set(s.strip() for s in args.status.split(",") if s.strip())
    issues = list_issues(args.workspace_id, limit=300)
    if args.identifier:
        issues = [i for i in issues if i.get("identifier") == args.identifier]

    selected = []
    for i in issues:
        if statuses and i.get("status") not in statuses:
            continue
        if args.identifier:
            selected.append(i)
        elif len(selected) < args.limit:
            selected.append(i)

    if not selected:
        print("no tickets matched", file=sys.stderr)
        return 1

    router = Router()

    for i in selected:
        tid = i.get("identifier", i.get("id"))
        # Hydrate full ticket for description / labels
        full = get_issue(tid, args.workspace_id) or i
        task = pick_task_type(full)
        prompt = build_prompt(full)

        if args.dry_run:
            pair = router.pair_for(task)
            print(
                json.dumps(
                    {
                        "ticket": tid,
                        "title": full.get("title"),
                        "task_type": task,
                        "labels": sorted(label_set(full)),
                        "status": full.get("status"),
                        "pair": pair,
                        "chain": router.chain_for(task),
                    },
                    indent=2,
                )
            )
            print()
            continue

        print(f"[{tid}] {task} review-pair -> {router.pair_for(task)}", file=sys.stderr)
        pair = router.pair_for(task)
        specs = [s for s in (pair.get("primary"), pair.get("secondary")) if s]
        if not specs:
            specs = router.chain_for(task)

        t0 = time.time()
        replies = router.call_parallel(
            specs,
            prompt,
            max_tokens=args.max_tokens,
            timeout=args.timeout,
        )
        wall = int((time.time() - t0) * 1000)

        if args.json:
            print(
                json.dumps(
                    {
                        "ticket": tid,
                        "task": task,
                        "wall_ms": wall,
                        "replies": [
                            {
                                "spec": spec,
                                "ok": r.ok,
                                "provider": r.provider,
                                "model": r.model,
                                "latency_ms": r.latency_ms,
                                "input_tokens": r.input_tokens,
                                "output_tokens": r.output_tokens,
                                "text": r.text,
                                "error": r.error,
                            }
                            for spec, r in replies
                        ],
                    },
                    indent=2,
                )
            )
            print()
        else:
            print(f"\n{'=' * 70}\n{tid} [{task}] multi-model review\n{'=' * 70}")
            ok_count = 0
            for spec, r in replies:
                if r.ok:
                    ok_count += 1
                    print(
                        f"\n--- {spec} ({r.provider}/{r.model}) "
                        f"{r.latency_ms}ms  in={r.input_tokens} out={r.output_tokens}"
                    )
                    print(r.text)
                else:
                    print(f"\n--- {spec}: ERROR {r.error}")
            print(f"\n# {ok_count}/{len(replies)} models replied, {wall}ms wall", file=sys.stderr)

            # Post the synthesis back as a Multica comment
            ok_replies = [(s, r) for s, r in replies if r.ok]
            if ok_replies:
                lines = [
                    f"**Automated multi-model review ({len(ok_replies)} models)**",
                    f"Task: {task}  |  Models: {', '.join(s for s, _ in ok_replies)}",
                    "",
                ]
                for spec, r in ok_replies:
                    lines.append(f"---\n**{spec}** ({r.provider}/{r.model}, {r.latency_ms}ms):\n")
                    lines.append(r.text)
                    lines.append("")
                comment = "\n".join(lines)
                status, resp = post_comment(full, comment, args.workspace_id)
                if 200 <= status < 300:
                    print(f"# posted synthesis (HTTP {status})", file=sys.stderr)
                else:
                    print(f"# comment post failed: HTTP {status}: {resp[:200]}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
