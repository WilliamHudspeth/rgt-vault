# Software Security Controls Inventory

A catalogue of the security controls that exist in `rgt-vault`, grouped by the
governance objectives in [GOVERNANCE.md](GOVERNANCE.md) (objectives 1.1 to
10.1 of tracker epic RGT-488; these are **not** OWASP ASVS identifiers).

Every row names a place in the repository where the control can be checked.
Controls that do not exist are listed as `Gap` or `N/A - single maintainer`
rather than omitted, so the inventory does not look healthier than it is.

- **Verified against:** commit `c3b090b` on `master`, checked 2026-11-26.
- **Owner of every control:** the project maintainer (single maintainer; there
  are no teams). The old per-team "Owner" column has been dropped.
- **Review cadence:** none scheduled. The inventory is edited when a control
  changes. The "Last Review" dates in the earlier draft were not real reviews
  and are removed.

## Status vocabulary

| Status | Meaning |
|---|---|
| Implemented | Exists and was checked in code or configuration. This does not say it is complete or tested to any standard; see the notes. |
| Partial | Exists with a named limitation. |
| Gap | Does not exist. A tracking issue or document is named where one exists. |
| N/A - single maintainer | Presumes an organisation the project does not have. |

"Python line" means `rgt_vault/`. "Go line" means `go/`; the Go `go/cmd/server`
is a skeleton (in-memory store, policy stub) and its controls are called out
separately because they differ from the Python line.

---

## 1. Leadership Accountability and Responsibility (1.1 to 1.3)

| ID | Control | Status | Where | Notes |
|---|---|---|---|---|
| C-LEAD-001 | Maintainer holds accountability for security decisions | Implemented | One GitHub collaborator; `.github/SECURITY.md` | No separate security role exists. |
| C-LEAD-002 | Reporting of security status to leadership | N/A - single maintainer | none | The maintainer is the leadership. No quarterly or annual report exists. |
| C-LIFE-001 | Contributor security expectations | Partial | `.github/CONTRIBUTING.md`, `.github/PULL_REQUEST_TEMPLATE.md` | Self-attested checklist; not enforced; no design-review step. |
| C-SKILL-001 | Skills management programme | N/A - single maintainer | none | No training or review programme exists. |
| C-SKILL-002 | Training and certification records | N/A - single maintainer | none | None kept. Listed as "Planned" in the earlier draft; it is not planned. |

## 2. Compliance and Security Policy Framework (2.1 to 2.6)

| ID | Control | Status | Where | Notes |
|---|---|---|---|---|
| C-COMP-001 | Inventory of external requirements | Partial | `GOVERNANCE.md` section 2.1 | Applicability table; reviewed only when edited. No licence scan; export-control not assessed. |
| C-COMP-002 | Scheduled monitoring of regulatory change | Gap | none | The earlier "quarterly OWASP Top 10 review" never existed. |
| C-POLICY-001 | Written security policy | Implemented | `.github/SECURITY.md` | Guarantees, non-goals, reporting. The maintainer is author and approver. |
| C-POLICY-002 | Policy communicated to contributors | Implemented | `.github/CONTRIBUTING.md` links `SECURITY.md` | No onboarding process beyond the repository docs. |
| C-STRAT-001 | Security roadmap | Partial | `docs/ROADMAP.md`, epics RGT-488, RGT-489, RGT-492 | No adoption of ISO/IEC 27034, BSIMM, SAMM or NIST SP 800-160; no annual review. |
| C-ASSUR-001 | Assurance processes in CI | Implemented | `.github/workflows/ci.yml`, `.github/workflows/review-gate.yml`, `.github/workflows/codeql.yml`, `.github/workflows/scorecard.yml`, `.github/workflows/release.yml` | CI is currently failing on `master`; CodeQL and Scorecard PR triggers name `main`, not `master`. See `GOVERNANCE.md` 2.4 and 2.6. |
| C-ASSUR-002 | Inventory of assurance processes | Implemented | This document; `GOVERNANCE.md` 2.4 | |
| C-EVIDENCE-001 | Evidence collection | Partial | git history, `tests/`, CI runs and artifacts, `docs/archive/audits/` | No retention period; CI logs expire on GitHub's schedule. The earlier "3-year minimum" was not implemented. |
| C-EVIDENCE-002 | Evidence accessibility | Implemented | Public repository (code, docs, CI results) | The internal tracker is not public. |
| C-MONITOR-001 | Process-effectiveness metrics | Gap | none | Reactive only: CI failures and ad-hoc audits. Tracked: RGT-468. |
| C-MONITOR-002 | Process improvement when ineffective | Gap | none | Same as above. |

## 3. Asset Classification and Threat Management (3.1 to 3.4)

| ID | Control | Status | Where | Notes |
|---|---|---|---|---|
| C-ASSET-001 | Asset classification | Implemented | `GOVERNANCE.md` 3.1 | Two tiers (critical, important), not the four tiers of the earlier draft. |
| C-ASSET-002 | Asset inventory | Implemented | `GOVERNANCE.md` 3.1 | Maintained by hand. |
| C-ASSET-003 | Protection scaled to tier | Partial | `rgt_vault/keychain.py`, `rgt_vault/crypto.py`, `rgt_vault/vault.py` | Strongest protections on secret values and keys; bearer, operator and TOTP credentials are plaintext files. |
| C-THREAT-001 | Threat modelling | Partial | `docs/security/threat-model.md` | Written by hand; no recurring trigger; Go server, gateway, MCP and outbound providers not yet modelled. |
| C-THREAT-002 | Threat inventory | Implemented | `THREAT_INVENTORY.md` | Rewritten to match code; lists gaps. |
| C-THREAT-003 | Open-source component management | Partial | `.github/dependabot.yml`, `.github/workflows/ci.yml` (`pip-audit`, `govulncheck`, `sbom`), `go/go.sum` | Python deps are version ranges, no lockfile. Dependabot PRs are manual-merge and several are open. The earlier draft named "OWASP Dependency-Check"; it is not used. |
| C-CONTROL-001 | Control definition and decisions | Partial | This inventory, `docs/adr/`, `.github/SECURITY.md` non-goals | Some ADRs cite files that do not exist. |
| C-CONTROL-002 | Controls implemented in code | Partial | See sections 4 to 9 below | Authorization and transport gaps in `THREAT_INVENTORY.md`. |
| C-CONTROL-003 | Control effectiveness monitoring | Gap | none | Tests exist; no review of whether controls have weakened. Tracked: RGT-472. |
| C-CONTROL-004 | Upgrading weak controls | Gap | none | Done ad hoc when a weakness is found. |

## 4. Security Testing and Vulnerability Management (4.1 to 4.2)

| ID | Control | Status | Where | Notes |
|---|---|---|---|---|
| C-TEST-001 | Static analysis (Python) | Implemented | `.github/workflows/ci.yml`, `.github/workflows/review-gate.yml` (bandit); `.github/workflows/codeql.yml` (CodeQL, python) | bandit thresholds differ between workflows (medium vs high). CodeQL PR trigger names `main`. |
| C-TEST-001G | Static analysis (Go) | Gap | `.github/workflows/ci.yml` has `govulncheck` only | No CodeQL for Go; `go vet` and `go test` are not run on pull requests (`go test` runs in `.github/workflows/release.yml`). |
| C-TEST-002 | Dependency vulnerability scanning | Implemented | `pip-audit` and `govulncheck` in CI; Dependabot | Currently failing in CI for the Go standard-library version. |
| C-TEST-003 | Dynamic security testing | Gap | none | No DAST. The earlier draft's "Roadmap" label overstated it. |
| C-TEST-004 | Secret scanning | Implemented | `.github/workflows/review-gate.yml` job `gitleaks` | Added here because the earlier "security-focused code review" row described a review step that is not enforced. |
| C-TEST-005 | Automated test suite with coverage gate | Implemented | `tests/`, `.github/workflows/review-gate.yml` (80% gate), `.github/workflows/ci.yml` | Property/fuzz tests in `tests/test_fuzz.py`. Some security tests assert docs or grep source; being strengthened (RGT-492 children). |
| C-TEST-006 | Independent / third-party security review | N/A - single maintainer | none | Ad-hoc multi-model review passes appear in history; they are not independent testing. |
| C-VULN-001 | Vulnerability intake | Implemented | `.github/SECURITY.md`; GitHub private vulnerability reporting enabled | Ack within 5 business days; plan within 30 days. |
| C-VULN-002 | Severity classification | Gap | `docs/archive/program/severity-matrix.md` is archived | No CVSS or severity policy in force. The earlier draft's CVSS table was not a practice. |
| C-VULN-003 | Vulnerability tracking | Partial | Internal tracker (`RGT-n`); `docs/archive/audits/` | No public register. |
| C-VULN-004 | Regression tests for fixed issues | Implemented | `tests/test_audit_fixes.py`, `tests/test_audit_v2_hardening.py`, `tests/test_hardening.py`, `tests/test_server_hardening.py` | Required by `CONTRIBUTING.md` for crypto, authorization, audit and storage. |

## 5. Change Management and Version Control (5.1 to 5.2)

| ID | Control | Status | Where | Notes |
|---|---|---|---|---|
| C-CHANGE-001 | Change records | Implemented | git history; commit messages name `RGT-n` | Most commits go directly to `master`; 5 merged pull requests. |
| C-CHANGE-002 | Security checklist on PRs | Partial | `.github/PULL_REQUEST_TEMPLATE.md` | Self-attested; no threat-model-impact item. |
| C-CHANGE-003 | Change authorization / required review | Gap | none verified | One collaborator, no CODEOWNERS; branch protection could not be verified (API 403, no rulesets). The earlier "approval workflow" claim is removed. |
| C-CHANGE-004 | Change inventory (who and when) | Implemented | git log; `CHANGELOG.md` | Author identities include the maintainer, dependabot and agent-style identities. |
| C-VERSION-001 | Unique versioning | Implemented | `pyproject.toml`, `CHANGELOG.md` (SemVer), tags `v0.1.0`, `v0.2.0`, `v0.3.0` | |
| C-VERSION-002 | Version tracking per release | Partial | `CHANGELOG.md`; Go: `go.sum` and goreleaser SBOM | No Python lockfile. |
| C-VERSION-003 | Version support policy | Partial | `.github/SECURITY.md`: only the latest release gets fixes | Python end-of-life timing is an open decision (RGT-165). |

## 6. Software Integrity and Delivery (6.1 to 6.2)

| ID | Control | Status | Where | Notes |
|---|---|---|---|---|
| C-INTEGRITY-001 | Commit signing | Gap | `git log --format=%G?`: none verified-signed | The earlier draft said GPG signing was a policy; it is not. |
| C-INTEGRITY-002 | Repository access control | Partial | One GitHub collaborator; branch protection not verified | |
| C-INTEGRITY-003 | Build integrity | Partial | `.github/workflows/ci.yml` `build` job (wheel, migrations check); `.github/workflows/release.yml` | Actions pinned by tag (Scorecard `@main`), not SHA. No reproducible-build claim. |
| C-INTEGRITY-004 | Repo hygiene for secrets | Implemented | `.gitignore` (vault runtime files); gitleaks | |
| C-DELIVERY-001 | Delivery channel | Implemented | GitHub releases over HTTPS; `.github/workflows/release.yml` | `v0.3.0` is a draft; `v0.2.0` has no release. Python package not published. |
| C-DELIVERY-002 | Integrity verification of downloads | Partial | `checksums.txt` (SHA-256) and SBOMs from `go/.goreleaser.yaml`; steps in `docs/getting-started/installation.md` | No signatures (cosign block commented out). |
| C-DELIVERY-003 | Release process | Partial | `.github/workflows/release.yml` (tests, then GoReleaser, draft release) | Python release steps live only in the archived `docs/archive/program/release-checklist.md`. |

## 7. Data Protection (7.1 to 7.2)

| ID | Control | Status | Where | Notes |
|---|---|---|---|---|
| C-DATA-001 | Collection authorization | N/A - single maintainer | no telemetry in `rgt_vault/` or `go/` | The project collects no production data. |
| C-DATA-002 | Data minimisation / retention | Gap | `audit_logs` kept indefinitely | No configurable retention. Audit rows include client IP for HTTP requests. |
| C-DATA-003 | Encryption at rest | Implemented | `rgt_vault/crypto.py`, `rgt_vault/keychain.py`, `rgt_vault/vault.py` | AES-256-GCM, per-secret AAD, DEK wrapped by Argon2id + HKDF-SHA512 KEK. Secret names and namespaces are not encrypted. |
| C-DATA-004 | Encryption in transit | **Gap** | none | The earlier draft marked this Implemented. No TLS exists in `rgt_vault/` or `go/`. Loopback bind is the only mitigation (Python default); the Go server binds all interfaces. Tracked: RGT-251, RGT-455, RGT-456. |
| C-DATA-005 | Access control to secrets | Partial | Python: default-deny ABAC (`rgt_vault/vault.py`), bearer and operator tokens (`rgt_vault/server/`) | It is ABAC, not RBAC. All agents share one bearer token and the ABAC subject is the caller-supplied `agent` field. Tracked: RGT-236, RGT-343, RGT-346. Go: policy is an allow-all stub. |
| C-DATA-006 | Secure deletion | Gap | `revoke_secret` sets `status = 'REVOKED'` | Ciphertext is retained; no hard delete, no SQLite `secure_delete`. |
| C-DATA-007 | Memory handling | Partial | `rgt_vault/crypto.py` (`zeroize_bytearray`, `SecureBuffer`) | Best effort; copies into `bytes`/`str` are not wiped (`.github/SECURITY.md`). |
| C-DATA-008 | Key rotation | Implemented | `rotate_master_key`, `rotate_dek` in `rgt_vault/vault.py`; automatic DEK rotation on usage thresholds (see `CHANGELOG.md`) | Bearer token, TOTP secret and capability HMAC key have no rotation lifecycle. |

## 8. Configuration and Guidance (8.1 to 8.3)

| ID | Control | Status | Where | Notes |
|---|---|---|---|---|
| C-CONFIG-001 | Security guidance documents | Partial | `README.md`, `docs/guides/`, `docs/concepts/security-model.md`, `.github/SECURITY.md` | No consolidated hardening checklist. |
| C-CONFIG-002 | Secure defaults | Partial | Python `serve` binds `127.0.0.1`, random tokens, mode 0600 (`rgt_vault/cli.py`, `rgt_vault/server/auth.py`) | Go server binds all interfaces, prints its token, no policy. |
| C-CONFIG-003 | Startup warnings for insecure settings | Partial | `rgt_vault/cli.py` warns on non-loopback bind; `rgt_vault/server/app.py` warns on operator-token fallback in production | Limited to those two cases. |
| C-CONFIG-004 | Hardened daemon deployment | Implemented | `deploy/rgt-vault.service`, `deploy/setup-daemon.sh` | Linux/systemd only. No equivalent unit for the Go server. |
| C-INSTALL-001 | Installation instructions | Partial | `docs/getting-started/installation.md`, `docs/getting-started/quickstart.md`, `README.md` | Installation page describes a Homebrew tap that does not exist (RGT-163). The earlier draft cited `PYTHON_INSTALLATION.md` and `GO_INSTALLATION.md`, which do not exist. |
| C-INSTALL-002 | Verification after install | Partial | `docs/getting-started/installation.md` (`verify-audit`, checksum) | |
| C-GUIDE-001 | Guidance kept in step with releases | Partial | PR template docs checkbox; `CONTRIBUTING.md` | No annual review; drift exists. |

## 9. Security Communication and Incident Response (9.1 to 9.3)

| ID | Control | Status | Where | Notes |
|---|---|---|---|---|
| C-COMM-001 | Private reporting channels | Implemented | `.github/SECURITY.md` (email); GitHub private vulnerability reporting; `.github/ISSUE_TEMPLATE/config.yml` | No bug bounty. |
| C-COMM-002 | Response commitments | Implemented | `.github/SECURITY.md`: acknowledgement 5 business days, plan within 30 days | These are the only response commitments; earlier text (24 hours) was wrong. |
| C-COMM-003 | Public feedback channel | Implemented | GitHub issues; templates in `.github/ISSUE_TEMPLATE/` | GitHub Discussions and a mailing list are not set up. |
| C-NOTIF-001 | Security update notification | Gap | none beyond GitHub release notifications and `CHANGELOG.md` | No mailing list or announcement channel. Tracked: RGT-485. |
| C-NOTIF-002 | Release announcements | Partial | GitHub releases (draft for `v0.3.0`), `CHANGELOG.md` | |
| C-ADVISORY-001 | Advisory process | Gap | `SECURITY_ADVISORIES.md` (empty register) | No advisory has been published. Tracked: RGT-486. |
| C-ADVISORY-002 | Mitigation guidance for unpatched issues | Partial | `.github/SECURITY.md` non-goals and audit-chain limitations; `docs/ROADMAP.md` | Static known-limitations text only. |

## 10. Release Management (10.1)

| ID | Control | Status | Where | Notes |
|---|---|---|---|---|
| C-RELEASE-001 | Release notes | Implemented | `CHANGELOG.md` per release plus `[Unreleased]` | |
| C-RELEASE-002 | Security content in notes | Implemented | `### Security` sections in `CHANGELOG.md` | Describe controls affected. |
| C-RELEASE-003 | Generated change list on GitHub release | Implemented | `go/.goreleaser.yaml` `changelog:` block | Release is created as a draft. |

---

## Control status summary

Counted from the tables above (a row with a differing `G` Go variant counts as
its own row).

| Status | Count |
|---|---|
| Implemented | 29 |
| Partial | 27 |
| Gap | 15 |
| N/A - single maintainer | 5 |
| **Total** | **76** |

The earlier draft reported 61 of 64 controls implemented (78 percent
"coverage"). That figure is withdrawn: it counted documents and intentions as
controls. Do not compare the two numbers.

## Known follow-up work for this inventory

- Wire the inventory to the ASVS verification output (RGT-492 children) once
  those documents land.
- Re-check statuses after the CI repair (`.github/workflows/ci.yml`, `.github/workflows/review-gate.yml`,
  `.github/workflows/codeql.yml`, `.github/workflows/scorecard.yml` are owned by the CI-green work, not this
  document) and after the agent-identity work (RGT-236 family).
