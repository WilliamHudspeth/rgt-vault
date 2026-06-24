# Reviewer Assignment Matrix

Maps component labels to designated reviewers. No self-approval for security-critical components.

## Primary Mapping

| Component | Reviewer Role | Notes |
|-----------|---------------|-------|
| `comp:crypto` | Crypto Reviewer | No self-approval |
| `comp:auth` | Security Reviewer | No self-approval |
| `comp:abac` | Security Reviewer | Auth-adjacent |
| `comp:keyring` | Security Reviewer | No self-approval |
| `comp:audit` | Security Reviewer | No self-approval |
| `comp:storage` | Core Maintainer | SQLite schema, migrations |
| `comp:server` | Core Maintainer | HTTP API surface |
| `comp:api` | Core Maintainer | Public API surface |
| `comp:leases` | Core Maintainer | Lease / zeroization logic |
| `comp:cli` | UX Reviewer | CLI ergonomics |
| `comp:ci` | DevOps Maintainer | GitHub Actions, build system |
| `comp:docs` | Documentation Reviewer | README, ARCHITECTURE, threat model |
| `comp:honeytokens` | Security Reviewer | Detection traps |
| `comp:supply-chain` | Core Maintainer + Security Reviewer | Dependencies, SBOM, vendoring |

## Multi-Reviewer Tickets

Tickets with multiple component labels require ALL applicable reviewers. Example:

- A ticket with `comp:crypto` + `comp:storage` needs **Crypto Reviewer AND Core Maintainer**.
- A ticket with `comp:auth` + `comp:api` needs **Security Reviewer AND Core Maintainer**.

## No Self-Approval

For these components, the **author cannot be the final reviewer**:

- `comp:crypto`
- `comp:auth`
- `comp:keyring`
- `comp:audit`

Rationale: most severe vulnerabilities survive precisely when the implementer reviews their own security-critical code. This rule is enforced by the CI process — PRs touching these files require a second human review.

## Security Champion

For a small project, ownership of security work is consolidated into a single named **Security Champion** (see `docs/program/security-champion.md`). The Champion:

- Has final review authority on all `comp:crypto`, `comp:auth`, `comp:abac`, `comp:keyring`, `comp:audit`, and `comp:supply-chain` PRs.
- Runs the release security review (`python3 scripts/program/release_gate.py --milestone <X>`) before any milestone close.
- Owns `docs/threat-model.md` and the `docs/adr/` directory.
- Coordinates external audits in v1.0.0.

The Champion cannot self-approve `comp:crypto`, `comp:auth`, `comp:keyring`, or `comp:audit` PRs — they recuse to the next reviewer. A named backup covers absences longer than 5 business days.

## Reviewer Label Mapping

The Multica label `reviewer:<role>` corresponds to:

| Label | Role | Required for |
|-------|------|--------------|
| `reviewer:crypto-maintainer` | Crypto Reviewer | `comp:crypto` |
| `reviewer:security-maintainer` | Security Reviewer | `comp:auth`, `comp:abac`, `comp:keyring`, `comp:audit` |
| `reviewer:core-maintainer` | Core Maintainer | `comp:storage`, `comp:server`, `comp:api`, `comp:leases` |
| `reviewer:docs-maintainer` | Documentation Reviewer | `comp:docs` |

## Self-Approval Audit

The script `scripts/program/wip_audit.py` flags tickets where:
- The author and the reviewer are the same user
- The ticket has any of the no-self-approval components

Audit this weekly.

## Escalation

If the designated reviewer for a component is unavailable:
1. Wait up to 48 hours
2. If still unavailable, escalate to the next-most-relevant reviewer
3. If none available, escalate to the project maintainer

If no reviewer can be found, the PR is **blocked** (add `review:blocked` label).