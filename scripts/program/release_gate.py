#!/usr/bin/env python3
"""Release gate for the rgt-vault program.

Checks (against a specific milestone or 'all'):
  1. No blocker issues (pri:blocker, not done)
  2. No critical security issues (security:* AND pri:critical/blocker, not done)
  3. All tickets in the milestone satisfy DoD
  4. Security reviews completed (all security:* tickets have review:security label added)
  5. Changelog updated (placeholder — manual check)

Exit codes:
  0 - PASS (all gates green)
  1 - FAIL (one or more gates violated)

Output:
  - "PASS" or "FAIL" headline
  - Reasons for any failure
  - Summary table

Usage:
  python3 release_gate.py                              # check all milestones
  python3 release_gate.py --milestone v1.0.0          # check specific milestone
  python3 release_gate.py --json /tmp/gate.json      # machine-readable
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import list_issues, get_issue, label_set, list_projects, is_active, WORKSPACE_ID


def check_milestone(milestone_short, workspace_id=WORKSPACE_ID):
    """Return list of (gate_name, passed, reason) tuples for a milestone."""
    gates = []

    projects = list_projects(workspace_id)
    proj = next((p for p in projects if p["title"].startswith(milestone_short + " ") or p["title"].startswith(milestone_short + "-")), None)
    if not proj:
        return [("milestone_lookup", False, f"Milestone '{milestone_short}' not found")]

    # Pull all tickets in this milestone. Use a generous limit so a
    # ticket ranked >200 isn't silently dropped (this was a real bug
    # where get_issue only searched the first 200 of the response, so
    # release_gate false-PASSed when a blocker sorted after #200).
    issues = list_issues(workspace_id, limit=1000)
    full = [i for i in issues if i.get("project_id") == proj["id"]]

    # Gate 1: No blockers
    blockers = [t for t in full if is_active(t) and "pri:blocker" in label_set(t)]
    if blockers:
        gates.append(("no_blockers", False, f"{len(blockers)} blocker issue(s): {[t['identifier'] for t in blockers]}"))
    else:
        gates.append(("no_blockers", True, "0 blocker issues"))

    # Gate 2: No critical security
    crit_sec = [t for t in full
                if is_active(t)
                and any(l.startswith("security:") for l in label_set(t))
                and any(l in ("pri:critical", "pri:blocker") for l in label_set(t))]
    if crit_sec:
        gates.append(("no_critical_security", False,
                      f"{len(crit_sec)} critical security issue(s) open: {[t['identifier'] for t in crit_sec]}"))
    else:
        gates.append(("no_critical_security", True, "0 critical security issues"))

    # Gate 3: All done tickets satisfy DoD
    # DoD = status=done AND (no security:* OR has review:security label)
    # For non-security tickets, just status=done implies DoD
    dod_failures = []
    for t in full:
        if t["status"] != "done":
            continue
        labels = label_set(t)
        if any(l.startswith("security:") for l in labels) and "review:security" not in labels:
            dod_failures.append(t["identifier"])
    if dod_failures:
        gates.append(("dod_compliance", False,
                      f"{len(dod_failures)} done ticket(s) missing review:security: {dod_failures}"))
    else:
        gates.append(("dod_compliance", True, "all done tickets satisfy DoD"))

    # Gate 4: Security reviews completed
    sec_no_review = []
    for t in full:
        labels = label_set(t)
        if any(l.startswith("security:") for l in labels) and t["status"] != "done":
            if "review:security" not in labels:
                sec_no_review.append(t["identifier"])
    if sec_no_review:
        gates.append(("security_reviews", False,
                      f"{len(sec_no_review)} active security ticket(s) without review:security: {sec_no_review}"))
    else:
        gates.append(("security_reviews", True, "all active security tickets have review:security"))

    # Gate 5: Changelog updated — manual placeholder
    # (could check git log for [Unreleased] entries, but that's heuristic)
    # OPUS-FIX: was hardcoded `True`, so the gate always reported PASS
    # even when the changelog had never been updated. Now it reports
    # SKIPPED so a human must explicitly override.
    gates.append(("changelog_updated", "skipped", "manual check required (no programmatic verification)"))

    # Gate 6: No open blocker issues (sev:blocker OR pri:blocker, per release-security-gates.md)
    blockers = [t for t in full if is_active(t) and (
        "sev:blocker" in label_set(t) or "pri:blocker" in label_set(t)
    )]
    if blockers:
        gates.append(("no_sev_blocker", False,
                      f"{len(blockers)} sev:blocker issue(s) open: {[t['identifier'] for t in blockers]}"))
    else:
        gates.append(("no_sev_blocker", True, "0 sev:blocker issues"))

    # Gate 7: No open critical security (sev:critical AND security:*)
    crit_sec_sev = [t for t in full
                    if is_active(t)
                    and "sev:critical" in label_set(t)
                    and any(l.startswith("security:") for l in label_set(t))]
    if crit_sec_sev:
        gates.append(("no_sev_critical_security", False,
                      f"{len(crit_sec_sev)} sev:critical security issue(s) open: {[t['identifier'] for t in crit_sec_sev]}"))
    else:
        gates.append(("no_sev_critical_security", True, "0 sev:critical security issues"))

    # Gate 8: Threat model current — manual placeholder
    # Could be automated by checking the file's mtime vs last review date
    gates.append(("threat_model_current", "skipped", "manual check required (no programmatic verification)"))

    # Gate 9: Dependency audit — manual placeholder
    # Could be automated by running pip-audit on requirements*.txt
    gates.append(("dependency_audit", "skipped", "manual check required (run pip-audit)"))

    # Gate 10: Secret scan — manual placeholder
    # Could be automated by running gitleaks/trufflehog
    gates.append(("secret_scan", "skipped", "manual check required (run gitleaks)"))

    # Gate 11: SBOM generated — manual placeholder
    gates.append(("sbom_generated", "skipped", "manual check required (run scripts/build_sbom.py)"))

    return gates


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--milestone", help="Specific milestone short-name (e.g. v0.2.0). Default: all.")
    parser.add_argument("--json", help="Write JSON report to path")
    parser.add_argument("--workspace-id", default=WORKSPACE_ID)
    args = parser.parse_args()

    if args.milestone:
        milestones = [args.milestone]
    else:
        projects = list_projects(args.workspace_id)
        milestones = [p["title"].split(" - ")[0] for p in projects]

    all_results = {}
    for ms in milestones:
        gates = check_milestone(ms, args.workspace_id)
        all_results[ms] = gates

    # Output
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(all_results, indent=2))
        print(f"JSON written: {args.json}")

    overall_pass = True
    for ms, gates in all_results.items():
        # A milestone passes only if every gate is True. "skipped" gates
        # fail the milestone by default — the human must explicitly
        # decide to override a skipped gate (out of scope for the
        # automated check, but at least the gate doesn't false-PASS).
        all_pass = all(g[1] is True for g in gates)
        if not all_pass:
            overall_pass = False
        verdict = "PASS" if all_pass else "FAIL"
        print(f"\n{ms}: {verdict}")
        for name, passed, reason in gates:
            if passed is True:
                mark = "✓"
            elif passed == "skipped":
                mark = "?"
            else:
                mark = "✗"
            print(f"  [{mark}] {name}: {reason}")

    print()
    print(f"OVERALL: {'PASS' if overall_pass else 'FAIL'}")
    return 0 if overall_pass else 1


if __name__ == "__main__":
    sys.exit(main())