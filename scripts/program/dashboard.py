#!/usr/bin/env python3
"""Engineering dashboard for the rgt-vault program.

Computes:
  - Open blockers (pri:blocker, not done)
  - Open critical security (security:* AND pri:critical/blocker, not done)
  - Milestone burndown (active vs done per milestone)
  - Lead time (median days from created to done, last 30d)
  - Cycle time (median days from first in_progress to done, last 30d)
  - Review queue size (status=in_review by type)
  - Security review queue size (has security: AND status=in_review)
  - Average review age (days in_review per ticket)
  - Test coverage trend (placeholder — requires CI integration)

Output:
  - Markdown (default, human-readable)
  - JSON (--json flag)
  - Terminal table (--table flag)

Usage:
  python3 dashboard.py
  python3 dashboard.py --json /tmp/dash.json
  python3 dashboard.py --table
"""
import argparse
import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import (
    list_issues, get_issue, label_set, list_projects,
    is_active, effort_size, WORKSPACE_ID
)


def compute_dashboard(workspace_id=WORKSPACE_ID):
    issues = list_issues(workspace_id, limit=300)
    full_issues = []
    for i in issues:
        full = get_issue(i["identifier"], workspace_id)
        if full:
            full_issues.append(full)

    now = datetime.now(timezone.utc)

    # Per-milestone burndown
    projects = list_projects(workspace_id)
    proj_by_short = {p["title"].split(" - ")[0]: p for p in projects}
    by_milestone = defaultdict(lambda: {"total": 0, "done": 0, "active": 0, "backlog": 0})
    for t in full_issues:
        pid = t.get("project_id")
        if not pid:
            continue
        ms = None
        for short, p in proj_by_short.items():
            if p["id"] == pid:
                ms = short
                break
        if not ms:
            continue
        by_milestone[ms]["total"] += 1
        if t["status"] == "done":
            by_milestone[ms]["done"] += 1
        elif is_active(t):
            by_milestone[ms]["active"] += 1
        elif t["status"] == "backlog":
            by_milestone[ms]["backlog"] += 1

    # Open blockers
    open_blockers = [
        t for t in full_issues
        if is_active(t) and "pri:blocker" in label_set(t)
    ]

    # Open critical security
    open_critical_security = [
        t for t in full_issues
        if is_active(t)
        and any(l.startswith("security:") for l in label_set(t))
        and any(l in ("pri:critical", "pri:blocker") for l in label_set(t))
    ]

    # Review queue
    review_queue = [t for t in full_issues if t["status"] == "in_review"]
    security_review_queue = [
        t for t in review_queue if any(l.startswith("security:") for l in label_set(t))
    ]

    # Lead / cycle time (last 30 days, done)
    lead_times = []
    cycle_times = []
    review_ages = []
    for t in full_issues:
        try:
            created_dt = datetime.fromisoformat(t["created_at"].replace("Z", "+00:00"))
            updated_dt = datetime.fromisoformat(t["updated_at"].replace("Z", "+00:00"))
        except Exception:
            continue
        if t["status"] == "done" and (now - updated_dt).days <= 30:
            lead_times.append((updated_dt - created_dt).days)
        if t["status"] == "in_review":
            review_ages.append((now - updated_dt).days)

    avg_review_age = statistics.mean(review_ages) if review_ages else None
    median_lead_time = statistics.median(lead_times) if lead_times else None
    mean_lead_time = statistics.mean(lead_times) if lead_times else None

    return {
        "computed_at": now.isoformat(),
        "totals": {
            "issues": len(full_issues),
            "active": sum(1 for t in full_issues if is_active(t)),
            "done": sum(1 for t in full_issues if t["status"] == "done"),
            "backlog": sum(1 for t in full_issues if t["status"] == "backlog"),
            "in_review": len(review_queue),
        },
        "open_blockers": len(open_blockers),
        "open_critical_security": len(open_critical_security),
        "review_queue_size": len(review_queue),
        "security_review_queue_size": len(security_review_queue),
        "average_review_age_days": round(avg_review_age, 1) if avg_review_age else None,
        "lead_time_median_days": round(median_lead_time, 1) if median_lead_time else None,
        "lead_time_mean_days": round(mean_lead_time, 1) if mean_lead_time else None,
        "milestone_burndown": dict(by_milestone),
        "open_blockers_detail": [t["identifier"] for t in open_blockers],
        "open_critical_security_detail": [t["identifier"] for t in open_critical_security],
        "test_coverage_trend": "N/A — requires CI integration",
    }


def render_markdown(d):
    lines = [
        f"# RGT Vault Engineering Dashboard",
        f"_{d['computed_at']}_",
        "",
        "## Health",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Open blockers | **{d['open_blockers']}** {'🔴' if d['open_blockers'] else '✓'} |",
        f"| Open critical security | **{d['open_critical_security']}** {'🔴' if d['open_critical_security'] else '✓'} |",
        f"| Review queue size | {d['review_queue_size']} |",
        f"| Security review queue | {d['security_review_queue_size']} |",
        f"| Avg review age | {d['average_review_age_days']} days |",
        "",
        "## Throughput (last 30 days)",
        "",
        f"- Median lead time: **{d['lead_time_median_days']} days**" if d["lead_time_median_days"] is not None else "- Median lead time: N/A (no tickets completed in last 30 days)",
        f"- Mean lead time: {d['lead_time_mean_days']} days" if d["lead_time_mean_days"] is not None else "",
        "",
        "## Milestone Burndown",
        "",
        "| Milestone | Total | Active | Done | Backlog |",
        "|-----------|-------|--------|------|---------|",
    ]
    for ms in sorted(d["milestone_burndown"].keys()):
        b = d["milestone_burndown"][ms]
        lines.append(f"| {ms} | {b['total']} | {b['active']} | {b['done']} | {b['backlog']} |")
    lines.append("")

    if d["open_blockers_detail"]:
        lines.append("## Open Blockers")
        for tid in d["open_blockers_detail"]:
            lines.append(f"- {tid}")
        lines.append("")

    if d["open_critical_security_detail"]:
        lines.append("## Open Critical Security")
        for tid in d["open_critical_security_detail"]:
            lines.append(f"- {tid}")
        lines.append("")

    lines.append("## Notes")
    lines.append("- Test coverage trend: requires CI integration (currently N/A)")
    lines.append("- Lead time: time from issue creation to last update on done tickets (proxy)")
    lines.append("- Review queue: tickets currently in `in_review` status")
    return "\n".join(lines)


def render_table(d):
    rows = [
        ("Open blockers", d["open_blockers"]),
        ("Open critical security", d["open_critical_security"]),
        ("Review queue", d["review_queue_size"]),
        ("Security review queue", d["security_review_queue_size"]),
        ("Avg review age (days)", d["average_review_age_days"]),
        ("Median lead time (days)", d["lead_time_median_days"]),
        ("Total active", d["totals"]["active"]),
        ("Total done", d["totals"]["done"]),
        ("Total backlog", d["totals"]["backlog"]),
    ]
    width_label = max(len(k) for k, _ in rows)
    print(f"{'Metric':<{width_label}}  Value")
    print(f"{'-' * width_label}  {'-' * 8}")
    for k, v in rows:
        print(f"{k:<{width_label}}  {v}")
    print()
    print("Milestone burndown:")
    print(f"  {'milestone':12s}  {'total':>5}  {'active':>6}  {'done':>5}  {'backlog':>7}")
    for ms, b in sorted(d["milestone_burndown"].items()):
        print(f"  {ms:12s}  {b['total']:>5}  {b['active']:>6}  {b['done']:>5}  {b['backlog']:>7}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", help="Write JSON to path")
    parser.add_argument("--table", action="store_true", help="Render terminal table")
    parser.add_argument("--workspace-id", default=WORKSPACE_ID)
    args = parser.parse_args()

    d = compute_dashboard(args.workspace_id)

    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(d, indent=2))
        print(f"JSON written: {args.json}")
        return 0

    if args.table:
        render_table(d)
    else:
        print(render_markdown(d))
    return 0


if __name__ == "__main__":
    sys.exit(main())