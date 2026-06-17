#!/usr/bin/env python3
"""WIP audit for the rgt-vault program.

Rules:
  - Maximum 1 XL issue assigned per engineer
  - Maximum 3 active issues assigned per engineer
  - No Ready issue older than 30 days
  - No Code Review issue older than 7 days

Exit code:
  0 - all rules pass
  1 - at least one violation

Output:
  - text to stdout (table of violations + summary)
  - JSON to --json flag output path (if specified)

Usage:
  python3 wip_audit.py
  python3 wip_audit.py --json /tmp/wip.json
"""
import argparse
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import list_issues, get_issue, label_set, is_active, effort_size, WORKSPACE_ID


def member_lookup():
    """Best-effort: get member id -> name. Returns {} if API doesn't support it."""
    # The list endpoint doesn't always include assignee_name; this is a placeholder.
    # The dashboard uses assignee_id which is sufficient for violation reporting.
    return {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", help="Write JSON report to path")
    parser.add_argument("--workspace-id", default=WORKSPACE_ID)
    args = parser.parse_args()

    issues = list_issues(args.workspace_id, limit=1000)
    # The list endpoint already returns everything wip_audit needs
    # (status, project_id, labels, identifier, priority, assignee).
    # See dashboard.py for the O(N^2) + 200-truncation rationale.
    full_issues = [i for i in issues if i.get("status") or i.get("labels")]

    now = datetime.now(timezone.utc)

    # Per-engineer buckets
    by_assignee = {}  # member_id -> list of active tickets
    by_assignee_xl = {}  # member_id -> count of XL active

    # Age-based buckets
    ready_old = []  # status=Ready/Backlog older than 30 days
    code_review_old = []  # status=Code Review (in_review) older than 7 days

    for t in full_issues:
        status = t.get("status")
        labels = label_set(t)
        assignee_id = t.get("assignee_id")
        assignee_type = t.get("assignee_type")
        created = t.get("created_at")
        updated = t.get("updated_at")
        try:
            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00")) if created else None
            updated_dt = datetime.fromisoformat(updated.replace("Z", "+00:00")) if updated else None
        except Exception:
            created_dt = updated_dt = None

        # Per-engineer (only count human-assigned; agents don't have WIP limits)
        if is_active(t) and assignee_type == "member" and assignee_id:
            by_assignee.setdefault(assignee_id, []).append(t)
            if "effort:XL" in labels:
                by_assignee_xl.setdefault(assignee_id, 0)
                by_assignee_xl[assignee_id] += 1

        # Ready issues older than 30 days
        # "Ready" in our workflow is status=todo+priority labels. Or status=backlog.
        if status in ("todo", "backlog") and created_dt and (now - created_dt).days > 30:
            ready_old.append((t, (now - created_dt).days))

        # Code Review older than 7 days (in_review status)
        if status == "in_review" and updated_dt and (now - updated_dt).days > 7:
            code_review_old.append((t, (now - updated_dt).days))

    violations = []

    # Check per-engineer WIP
    for member_id, tickets in by_assignee.items():
        active_count = len(tickets)
        if active_count > 3:
            violations.append({
                "type": "wip_overflow",
                "rule": "max 3 active issues per engineer",
                "assignee_id": member_id,
                "actual": active_count,
                "limit": 3,
                "tickets": [t["identifier"] for t in tickets],
            })
        xl_count = by_assignee_xl.get(member_id, 0)
        if xl_count > 1:
            violations.append({
                "type": "xl_overflow",
                "rule": "max 1 XL issue per engineer",
                "assignee_id": member_id,
                "actual": xl_count,
                "limit": 1,
                "tickets": [t["identifier"] for t in tickets if "effort:XL" in label_set(t)],
            })

    # Check age violations
    for t, days in ready_old:
        violations.append({
            "type": "ready_stale",
            "rule": "Ready/Backlog issues older than 30 days",
            "ticket": t["identifier"],
            "days_old": days,
            "limit_days": 30,
            "title": t["title"][:60],
        })

    for t, days in code_review_old:
        violations.append({
            "type": "code_review_stale",
            "rule": "Code Review issues older than 7 days",
            "ticket": t["identifier"],
            "days_in_review": days,
            "limit_days": 7,
            "title": t["title"][:60],
        })

    # Output
    print(f"WIP audit — {now.strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  active tickets: {sum(len(t) for t in by_assignee.values())}")
    print(f"  engineers with active WIP: {len(by_assignee)}")
    print(f"  violations: {len(violations)}")
    print()

    if violations:
        print("VIOLATIONS:")
        for v in violations:
            print(f"  [{v['type']}] {v.get('rule')}")
            for k, val in v.items():
                if k not in ("type", "rule"):
                    print(f"      {k}: {val}")
        print()

    # JSON output
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps({
            "audit_time": now.isoformat(),
            "violations": violations,
            "by_engineer": {
                member_id: {
                    "active_count": len(tickets),
                    "active": [t["identifier"] for t in tickets],
                    "xl_count": by_assignee_xl.get(member_id, 0),
                }
                for member_id, tickets in by_assignee.items()
            },
            "ready_stale": [{"ticket": t["identifier"], "days": d} for t, d in ready_old],
            "code_review_stale": [{"ticket": t["identifier"], "days": d} for t, d in code_review_old],
        }, indent=2))
        print(f"JSON written: {args.json}")

    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())