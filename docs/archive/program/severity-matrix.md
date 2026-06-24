# Severity Matrix

Defines the security severity levels used to label and triage issues in the rgt-vault project. Severity drives release-gate decisions: a `severity:blocker` open issue blocks milestone close; `severity:critical` blocks v1.0.0 release.

## Levels

| Severity | Label | Meaning | Examples | Release impact |
|----------|-------|---------|----------|----------------|
| Blocker | `sev:blocker` | Release cannot ship. Active exploitation or guaranteed compromise in default configuration. | Unauthenticated remote code execution; full key disclosure; audit-log tampering that goes undetected. | Blocks every milestone close. No exceptions. |
| Critical | `sev:critical` | Secret disclosure, authentication bypass, or integrity loss of audit/keys. Not currently exploited but trivially exploitable. | Auth bypass via type confusion; nonce reuse in encryption path; ability to forge audit rows; default credential hardcoded. | Blocks release. v0.x milestones may defer with explicit security-lead sign-off. |
| Major | `sev:major` | Security degradation. Some preconditions required (specific config, specific user behavior). | Information disclosure to a co-tenant; DoS that requires large resource consumption; signature stripping attack that requires a malicious intermediary. | Must be fixed before next minor release, or explicitly waived in writing. |
| Minor | `sev:minor` | Hardening opportunity. Theoretical or requires multiple chained conditions. | Side-channel timing leak that requires local co-residency; weak key derivation parameters that are still above brute-force threshold; missing security headers on admin UI. | Tracked but does not block release. |
| Info | `sev:info` | Cosmetic or low-risk issue. Best-practice deviation. | Verbose error message revealing library version; log message could include request size in addition to status code. | No release impact. |

## Relationship to Priority

The Multica `pri:*` label is a separate axis — *urgency* of fixing, not *severity* of the issue. A `sev:minor` finding can be `pri:blocker` (e.g. it's blocking a release because the customer audit team requires it), and a `sev:critical` can be `pri:minor` (because no customer is exposed yet).

| When severity is... | ...minimum priority is |
|---------------------|------------------------|
| Blocker | `pri:blocker` |
| Critical | `pri:critical` |
| Major | `pri:major` |
| Minor | `pri:minor` |
| Info | `pri:minor` (or none) |

If priority is lower than the minimum, the ticket is misclassified — escalate.

## Triage SLA

| Severity | Initial response | Fix landed |
|----------|------------------|------------|
| Blocker | 1 hour | 24 hours (hotfix branch) |
| Critical | 4 hours | 7 days |
| Major | 1 business day | Next minor release |
| Minor | 1 week | Next minor release (best effort) |
| Info | next triage cycle | backlog |

## How to apply

1. File the ticket with the highest `sev:*` label that matches the worst plausible impact.
2. Apply the minimum `pri:*` from the table above.
3. Add `security:*` label for `sev:blocker` and `sev:critical`.
4. The Security Champion (`docs/program/security-champion.md`) is automatically added as a watcher for any `sev:blocker` or `sev:critical` ticket.

## Disputes

If a reporter and reviewer disagree on severity, the higher severity wins until a Security Champion or external reviewer downgrades in writing. Disputes are tracked by adding the `needs-repro` label if reproduction is contested, or by escalating to the Security Champion with both perspectives in comments.
