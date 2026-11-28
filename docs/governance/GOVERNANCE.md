# RGT Vault: Software Security Governance

This document states, objective by objective, what software-security governance
actually exists for `rgt-vault` today. It replaces an earlier draft that
described teams, reviews, mailing lists and release notes that did not exist.

**Rule for this document:** it only describes things that can be checked in this
repository or on its GitHub project. Where something does not exist it says
`Gap` (with a tracking issue) or `N/A - single maintainer`. It does not describe
intended or aspirational processes as if they were operating.

- **Verified against:** commit `c3b090b` on `master` (state of CI and GitHub
  settings checked 2026-11-26).
- **Owner:** the project maintainer (see 1.1).
- **Companion documents:** [CONTROLS_INVENTORY.md](CONTROLS_INVENTORY.md),
  [THREAT_INVENTORY.md](THREAT_INVENTORY.md),
  [SECURITY_ADVISORIES.md](SECURITY_ADVISORIES.md),
  [`.github/SECURITY.md`](../../.github/SECURITY.md) (the authoritative security
  policy: guarantees, non-goals, reporting).

## How to read this document

Status vocabulary used in every section:

| Status | Meaning |
|---|---|
| **Exists** | The objective is met by something real in the repo or on GitHub. |
| **Partial** | Something real exists but a named part of the objective is not met. |
| **Gap** | The objective is not met. A tracking issue is named. |
| **N/A - single maintainer** | The objective presumes an organisation (leadership, teams, training programme) that this project does not have. Not applicable at this scale; nothing is claimed. |

Objective numbers (1.1 to 10.1) are the ones used in the tracker epic
RGT-488 "Software Security Governance" (issues RGT-460 to RGT-487). They are
**not OWASP ASVS identifiers**. The wording (software vendor, "mature process",
control objectives for the secure software lifecycle) follows the style of
secure-software-lifecycle standards for software vendors, but this repository
does not cite or claim conformance to a specific standard, and the mapping to
one has not been verified. ASVS verification is tracked separately under
RGT-492.

## Project facts that the rest of the document relies on

| Fact | Value | How to check |
|---|---|---|
| Maintainer | One person (GitHub account `WilliamHudspeth`) is the only repository collaborator and the only person with decision authority. | `gh api repos/WilliamHudspeth/rgt-vault/collaborators` |
| What it is | A local, encrypted secrets manager for AI agents. Not a hosted service; the project operates no infrastructure and receives no data from users. | `README.md`, `.github/SECURITY.md` |
| Languages | Python line (`rgt_vault/`, version 0.3.0 in `pyproject.toml`) with real storage and cryptography; Go line (`go/`) whose `go/cmd/server` is currently a skeleton (in-memory store, no persistence or crypto, policy stub). | `go/README.md` "Status", `go/internal/server/handlers/handlers.go` |
| Releases | Git tags `v0.1.0`, `v0.2.0`, `v0.3.0`. GitHub releases exist for `v0.1.0` (pre-release) and `v0.3.0` (still a **draft**); `v0.2.0` is a tag only. | `git tag`, `gh release list` |
| Change history | About 100 commits between 2026-06-16 and 2026-07-27, mostly pushed directly to `master`; 5 merged pull requests. Several author identities appear (maintainer, dependabot, and agent-style identities). | `git shortlog -sn`, `gh pr list --state merged` |
| CI | Five workflows in `.github/workflows/`: `.github/workflows/ci.yml`, `.github/workflows/review-gate.yml`, `.github/workflows/codeql.yml`, `.github/workflows/scorecard.yml`, `.github/workflows/release.yml`. | Described in 2.4. **As of 2026-11-26 the `CI` and `review-gate` runs on `master` are failing**; fixing that is tracked outside this batch. |
| Security contact | Email address in `.github/SECURITY.md`; GitHub private vulnerability reporting is also enabled on the repository. | `gh api repos/WilliamHudspeth/rgt-vault/private-vulnerability-reporting` returns `enabled: true` |
| Issue tracking | Internal tracker (Multica, workspace `rgt-vault`, `RGT-n` ids) referenced from commit messages and pull requests. It is not a public tracker. | `git log --grep RGT-` |

---

## 1. Governance Structure and Leadership Accountability

### 1.1 Security Responsibility and Leadership Accountability (RGT-460)

**Status: Exists (role assigned) / N/A - single maintainer (leadership reporting).**

- **Accountability.** The maintainer is accountable for the security of the
  project. This is not delegated: there is no security team, committee or
  separate security officer. The maintainer accepts vulnerability reports
  (9.1), decides on fixes, and approves releases.
- **Communication to "senior leadership".** N/A - single maintainer. The
  maintainer is the leadership, so there is no separate audience to inform.
- **Annual security update to leadership.** N/A - single maintainer. No annual
  report is produced and none is claimed. The nearest real equivalents are the
  `CHANGELOG.md` Security sections and the audit write-ups archived under
  `docs/archive/audits/`.

Evidence: GitHub collaborator list (one collaborator); `.github/SECURITY.md`
(the single reporting contact, which reaches the maintainer).

### 1.2 Lifecycle Software Security Responsibilities (RGT-461)

**Status: Partial.**

- All lifecycle phases (design, development, testing, release, maintenance)
  are the maintainer's responsibility. There are no separate roles, no job
  descriptions and no employee agreements (N/A - single maintainer).
- Contributor expectations are written down in `.github/CONTRIBUTING.md`:
  tests are required for crypto, authorization, audit and storage changes;
  secret plaintext must never be logged or placed in exceptions or audit
  records; `os.urandom` for salts, nonces and keys; documentation must not
  overstate guarantees; a `CHANGELOG.md` entry is required.
- Pull requests carry a security checklist in
  `.github/PULL_REQUEST_TEMPLATE.md`. It is a self-attested checklist, not an
  enforced gate.
- Third-party contributors acknowledge no agreement beyond the Apache-2.0
  `LICENSE` and the Code of Conduct (`.github/CODE_OF_CONDUCT.md`).
- Gap: there is no step that requires a design-level security review before
  implementation (see 3.2).

Evidence: `.github/CONTRIBUTING.md`, `.github/PULL_REQUEST_TEMPLATE.md`.

### 1.3 Software Security Skills Management and Review (RGT-462)

**Status: N/A - single maintainer.**

There is no skills framework, no role-based skill definitions, no training
catalogue, no annual skills review and no training or certification records.
Those mechanisms presuppose a team of developers. The compensating controls
that exist are automated: static analysis, dependency scanning and secret
scanning run in CI regardless of who writes the change (see 2.4 and 4.1).
Nothing in this repository records the maintainer's training or
certifications, and this document does not invent such records.

Evidence: absence confirmed by search of `docs/` and `.github/` for training,
skills or certification records; automated checks in `.github/workflows/`.

---

## 2. Security Policy and Compliance Framework

### 2.1 Identification and Monitoring of Compliance Requirements (RGT-463)

**Status: Partial.**

`rgt-vault` is a local tool. The project does not run a service, collect
telemetry or process other people's personal data (searched `rgt_vault/` and
`go/` for telemetry, analytics and error-reporting clients: none). Each user
holds their own vault on their own machine.

| Requirement source | Applicability to the project | Current position |
|---|---|---|
| GDPR / personal-data law | The project holds no user data. Users who store personal data in a vault are the controllers of that data. | N/A for the project; not assessed for individual deployments. |
| PCI DSS, HIPAA | Not a payment or health-data processor. | N/A; no claim of compliance is made anywhere in the repo. |
| Cryptography guidance | Design is informed by NIST SP 800-57 (key management; see `docs/architecture/crypto.md`) and NIST SP 800-38D limits (see the DEK-rotation entry in `CHANGELOG.md`). Alignment with BSI TR-02102-1 is a tracked goal, not a claim (epic RGT-489). | Informal alignment only; no conformance assessment. |
| Open-source licensing | Apache-2.0 (`LICENSE`). Dependency licences are not systematically checked. | Gap: no licence scan in CI. |
| Export controls on cryptography | Software contains strong cryptography. | Not assessed. |
| ASVS | Verification effort tracked in RGT-492. | In progress, not part of this document. |

- Monitoring: there is no scheduled review of external requirements. The list
  above is reviewed only when this document is edited (Gap; no annual review
  exists).

Evidence: `LICENSE`; `docs/architecture/crypto.md`; this table.

### 2.2 Software Security Policy Definition and Approval (RGT-464)

**Status: Exists (policy) / N/A - single maintainer (separate approval).**

- The security policy is `.github/SECURITY.md`. It states the threat
  assumptions, the guarantees, the explicit non-goals (not an HSM, best-effort
  zeroization, backup rollback not fully mitigated, no protection against a
  malicious operator, audit-chain limitations), supported versions and the
  reporting process.
- Rules that developers must follow are in `.github/CONTRIBUTING.md` and the
  pull-request checklist.
- Measurability: some rules are enforced mechanically (ruff, mypy, bandit at
  medium severity, pip-audit, govulncheck, gitleaks, an 80% coverage gate; see
  2.4). Most guarantees are verified by tests in `tests/` rather than by metrics.
- Approval: the maintainer wrote and approves the policy; there is no
  separate leadership approval step (N/A - single maintainer).
- Communication: the policy is published in the repository (`.github/SECURITY.md`)
  and linked from `.github/CONTRIBUTING.md`.

Evidence: `.github/SECURITY.md`, `.github/CONTRIBUTING.md`.

### 2.3 Software Security Strategy and Industry Alignment (RGT-465)

**Status: Partial.**

- A roadmap of known gaps and planned work exists in `docs/ROADMAP.md`;
  open work is tracked as `RGT-n` issues, including epics RGT-488 (governance),
  RGT-489 (cryptography and TLS) and RGT-492 (ASVS verification).
- Alignment with an industry methodology (ISO/IEC 27034, BSIMM, OWASP SAMM,
  NIST SP 800-160) has **not** been adopted or assessed. Referenced inputs that
  actually shape the work are OWASP ASVS (verification, RGT-492), the OpenSSF
  Scorecard workflow, and NIST SP 800-57 / 800-38D for key management.
- Annual strategy review: none (N/A - single maintainer). The roadmap is
  updated when work lands.
- Communication to developers: N/A - single maintainer.
- Open question recorded in the tracker: the Python line is described as
  maintenance-mode and the Go line as primary, but the Go server is currently a
  skeleton. This affects the strategy and is a human decision (RGT-165).

Evidence: `docs/ROADMAP.md`, `go/README.md`.

### 2.4 Software Security Assurance Processes and Inventory (RGT-466)

**Status: Exists.**

The assurance processes are the CI workflows below plus the tests in `tests/`.
This table is the inventory; [CONTROLS_INVENTORY.md](CONTROLS_INVENTORY.md)
lists the product controls themselves.

| Process | Where | Runs on | Blocks? |
|---|---|---|---|
| Unit/integration tests across OS and Python versions (ubuntu, macos, windows; py3.9 to 3.13) with coverage report | `.github/workflows/ci.yml` job `test` | push to `master`/`main`, every pull request | CI job result |
| ruff lint, ruff format check, mypy | `.github/workflows/ci.yml` job `lint`; `.github/workflows/review-gate.yml` jobs `lint`, `typecheck` | same | CI job result |
| bandit (Python SAST) | `.github/workflows/ci.yml` (`--severity-level medium`), `.github/workflows/review-gate.yml` (`-lll`) | same | CI job result |
| pip-audit (Python dependency CVEs) | `.github/workflows/ci.yml`, `.github/workflows/review-gate.yml` | same | CI job result |
| govulncheck (Go dependency/stdlib CVEs) | `.github/workflows/ci.yml` job `security` | same | CI job result |
| gitleaks (secret scan of history) | `.github/workflows/review-gate.yml` job `gitleaks` | same | CI job result |
| 80% coverage gate | `.github/workflows/review-gate.yml` job `coverage` | same | CI job result |
| Wheel build and migrations-shipped check | `.github/workflows/ci.yml` job `build` | same | CI job result |
| SBOM (CycloneDX) generation | `.github/workflows/ci.yml` job `sbom` | same | CI job result |
| CodeQL (Python only, `security-and-quality`) | `.github/workflows/codeql.yml` | weekly schedule; push/PR triggers name branch `main` | Reporting only; see weaknesses |
| OpenSSF Scorecard | `.github/workflows/scorecard.yml` | weekly schedule; push trigger names branch `main` | Reporting only |
| Release build, `go test ./...`, SBOM, checksums | `.github/workflows/release.yml` | tag push `v*` | Release job result |
| Dependency update PRs (pip, gomod, github-actions) | `.github/dependabot.yml` | weekly | Opens PRs only |

Known weaknesses of this set (also see 2.6):

- The default branch is `master`, but `.github/workflows/codeql.yml` and `.github/workflows/scorecard.yml` trigger
  on pushes/PRs to `main`, so on pull requests they do not run; only the weekly
  schedule (and manual runs) execute them.
- No required-status-check or review requirement could be verified: the
  branch-protection API returned 403 to the account used for this check and no
  repository rulesets exist. Treat branch protection as **not verified**
  (see 6.1).
- Go code is not covered by CodeQL and `go test`/`go vet` do not run on pull
  requests (`go test ./...` runs only in `.github/workflows/release.yml`).
- Missing checkpoint: a per-design threat review step does not exist (Gap).

Ownership: the maintainer owns every process. Outcomes are monitored by reading
CI results (see 2.6).

Evidence: `.github/workflows/ci.yml`, `.github/workflows/review-gate.yml`,
`.github/workflows/codeql.yml`, `.github/workflows/scorecard.yml`,
`.github/workflows/release.yml`, `.github/dependabot.yml`.

### 2.5 Security Assurance Evidence Collection and Retention (RGT-467)

**Status: Partial.**

Evidence that exists and where to find it:

| Evidence | Location | Retention |
|---|---|---|
| Source history and who changed what | Git history on GitHub | Permanent (git) |
| Test suite and regression tests | `tests/` | Permanent (git) |
| Test, scan and coverage results | GitHub Actions runs; coverage and SBOM artifacts from `.github/workflows/ci.yml`/`review-gate.yml` | GitHub's default artifact/log retention; **not** separately archived |
| Threat model and threat inventory | `docs/security/threat-model.md`, [THREAT_INVENTORY.md](THREAT_INVENTORY.md) | Permanent (git) |
| Past audits and checklists | `docs/archive/audits/`, `docs/archive/reviews/` | Permanent (git); archived, not a live process |
| Work and decision log | Internal tracker (`RGT-n`), not public | Held in the tracker, outside this repository |
| Release content | `CHANGELOG.md`, GitHub releases | Permanent |
| Accepted risks and non-goals | `.github/SECURITY.md` | Permanent (git) |

- Gap: there is no stated retention period and no process that gathers a
  per-release evidence bundle. CI logs expire on GitHub's schedule.
- Gap: no outcome metrics (e.g. vulnerabilities found per release) are kept.

Evidence: `docs/archive/audits/`, `tests/`, `.github/workflows/ci.yml` (artifact uploads).

### 2.6 Monitoring and Remediation of Ineffective Processes (RGT-468)

**Status: Gap.**

There is no metrics programme and no periodic process review. Weak processes
are found reactively, when a CI job fails or an audit finds a problem. Known
weak or ineffective processes right now, found while writing this document:

| Weakness | Evidence |
|---|---|
| CI is red on `master`: in the latest runs of `.github/workflows/ci.yml` the Windows jobs, the py3.9 jobs, `lint & type-check`, `security scan` and `Generate SBOM` fail; in `.github/workflows/review-gate.yml` `ruff`, `mypy` and the 80% coverage gate fail, so the aggregate `required-status-checks` job fails. The gates therefore do not currently give a trustworthy signal | `gh run list --branch master --workflow ci.yml` (and `.github/workflows/review-gate.yml`); run ids 30248546632 and 30248546671 at the time of writing |
| `.github/workflows/codeql.yml` and `.github/workflows/scorecard.yml` trigger on `main`, but the default branch is `master` | `.github/workflows/codeql.yml`, `.github/workflows/scorecard.yml` |
| `.github/workflows/review-gate.yml` bandit step is labelled "low+ severity" but runs with `-lll` (high only) and differs from `.github/workflows/ci.yml` (medium and above) | `.github/workflows/review-gate.yml`, `.github/workflows/ci.yml` |
| Third-party actions are pinned by tag (or `@main` for Scorecard), not by commit SHA; `gitleaks-action` carries a "pin to SHA in production" comment | `.github/workflows/` |
| Several security tests assert documents or grep source rather than exercise behaviour | being strengthened under the ASVS verification work (RGT-492 children) |

There are no defined criteria for when a process counts as ineffective and no
scheduled review. This objective stays open as a Gap (RGT-468).

Evidence: `.github/workflows/*.yml`; `git log --grep "review pass"` shows that
ad-hoc multi-model code review passes are used after larger fixes (for example
commit `c3b090b`).

---

## 3. Asset Classification and Control Definition

### 3.1 Critical Asset Identification and Classification (RGT-469)

**Status: Exists.**

Assets of the Python line, ranked by impact if confidentiality or integrity is
lost. Tier 1 is critical, tier 2 is important.

| Asset | Type | Tier | Stored where | Protection that exists |
|---|---|---|---|---|
| Secret plaintext (API keys, tokens) | Sensitive data | 1 | Memory only while in use | AES-256-GCM at rest; leased in a `bytearray` that is wiped (best effort) |
| Master secret | Sensitive data | 1 | OS-native store (DPAPI, macOS Keychain, Linux TPM, or `keyring`) | OS store protection; never written to the vault DB |
| Data Encryption Key (DEK) | Sensitive data | 1 | Wrapped in `keychain.json` (Argon2id + HKDF-SHA512 KEK); plaintext only in process memory | Mode 0600 on `keychain.json`; wrapped; epoch-checked |
| Ciphertext in `vault.db` | Sensitive data | 2 | SQLite file | Per-secret AAD (`vault_id:namespace:name`); tamper fails authentication |
| Audit log | Integrity asset | 1 | `audit_logs` table | SHA-256 hash chain (unkeyed; see limits in `.github/SECURITY.md`) |
| ABAC policy file | Sensitive function | 1 | YAML file chosen by the operator | Default-deny; explicit deny wins; no protection against a malicious operator |
| Agent bearer token and operator token | Credentials | 1 | `~/.config/rgt-vault/server.token` (default), plus operator token file | File mode 0600 on POSIX; constant-time compare; stored in plaintext, no expiry, one token shared by all agents |
| TOTP secret for human approval | Credential | 1 | File passed with `--totp-secret-file` | Replay-guarded verifier; file mode set after write |
| Capability token HMAC key | Credential | 1 | Supplied to the token verifier by the integrator | `rgt_vault/token.py`; the shipped `serve` command does not currently wire a verifier |
| Approval/rotate/revoke/audit/export endpoints | Sensitive functions | 1 | `rgt_vault/server/app.py` | Bearer or operator token; see THREAT_INVENTORY for the authorization gaps |
| Go server's in-memory secret store | Sensitive data | n/a | Process memory, plaintext | None; the Go server is a skeleton and not for real secrets |

Classification criteria used: tier 1 = disclosure or tampering defeats the
product's purpose (reads or alters secrets, keys, credentials, policy or audit
evidence); tier 2 = disclosed without the keys it reveals only ciphertext and
metadata. Secret names and namespaces are stored unencrypted in `vault.db`.

There is no Mission Impact Analysis process; the table above is maintained by
hand and updated when the code changes.

Evidence: `rgt_vault/keychain.py`, `rgt_vault/storage/sqlite.py`,
`rgt_vault/server/auth.py`, `.github/SECURITY.md`.

### 3.2 Continuous Threat Modeling and Design Assessment (RGT-470)

**Status: Partial.**

- A threat model exists in `docs/security/threat-model.md` (protects against,
  partially protects against, does not protect against, attacker scenarios) and
  a STRIDE-organised inventory in [THREAT_INVENTORY.md](THREAT_INVENTORY.md).
  Both are written and updated by hand; there is no recurring threat-modelling
  session or trigger (Gap). The PR template has no threat-model-impact item.
- Open-source component management:
  - Inventory: `pyproject.toml` / `requirements.txt` (Python, version ranges,
    no lockfile) and `go/go.mod` + `go/go.sum` (Go, pinned); a CycloneDX SBOM is
    generated in `.github/workflows/ci.yml`, and goreleaser emits SBOMs for release archives.
  - Monitoring: `pip-audit`, `govulncheck` and Dependabot (weekly, pip, gomod
    and github-actions).
  - Patching: Dependabot pull requests are merged by the maintainer; several
    were open and unmerged at the time of writing. No SLA exists beyond the
    30-day remediation target for reported vulnerabilities (4.2).
- Known unmodelled areas (tracked under the documentation work): Go server,
  cutover gateway, MCP server and outbound provider calls are not yet in the
  threat model.

Evidence: `docs/security/threat-model.md`, `docs/governance/THREAT_INVENTORY.md`,
`.github/dependabot.yml`, `.github/workflows/ci.yml` (`security`, `sbom` jobs).

### 3.3 Software Security Control Definition and Implementation (RGT-471)

**Status: Partial.**

- Controls are catalogued in [CONTROLS_INVENTORY.md](CONTROLS_INVENTORY.md) with
  their real implementation location and status. Threats map to controls in
  [THREAT_INVENTORY.md](THREAT_INVENTORY.md).
- Design decisions are recorded in `docs/adr/` (key hierarchy, ABAC over RBAC,
  audit chain design, agent capability model). Some ADRs reference files that
  do not exist and are being corrected under the architecture documentation work.
- Residual risk is recorded in `.github/SECURITY.md` ("Non-goals" and "Audit
  Chain Limitations") and `docs/ROADMAP.md` ("Known limitations").
- Approval of mitigation and residual-risk decisions is by the maintainer
  alone; no second approver exists (N/A - single maintainer).
- Gap: controls that the old governance draft listed as implemented but that
  are not: TLS on any listener, user passwords, MFA for users (there are no
  user accounts; TOTP is used only for the human approval of a secret use).

Evidence: `docs/governance/CONTROLS_INVENTORY.md`, `docs/adr/`,
`.github/SECURITY.md`.

### 3.4 Control Effectiveness Monitoring and Upgrades (RGT-472)

**Status: Gap.**

No process exists to review whether controls have become weak, and there are no
criteria for "weak". Controls are tested by the suite in `tests/` (for example
`tests/test_asvs_crypto.py`, `tests/test_hardening.py`,
`tests/test_server_hardening.py`), and weaknesses have been found by ad-hoc
audits (`docs/archive/audits/`) and multi-model review passes, not by a
scheduled review.

Known weak controls today (all stated elsewhere in the repo, repeated here so
this document does not hide them):

- No transport encryption: nothing in `rgt_vault/` or `go/` configures TLS; the
  daemon is loopback-only by default (`rgt-vault serve --host 127.0.0.1`),
  with a warning when bound elsewhere. Tracked: RGT-251, RGT-455, RGT-456.
- Agent identity: all agents share one bearer token and the ABAC subject is the
  caller-supplied `agent` field. Tracked: RGT-236, RGT-343, RGT-346.
- Audit chain is unkeyed SHA-256; root-level replacement is not detected
  (`.github/SECURITY.md`).
- Go server stubs policy to allow-all and prints its bearer token on start.

Evidence: `rgt_vault/server/app.py`, `rgt_vault/cli.py` (`serve`),
`go/cmd/server/main.go`, `go/internal/server/handlers/handlers.go`.

---

## 4. Secure Development and Testing

### 4.1 Security Testing and Vulnerability Detection (RGT-473)

**Status: Partial.**

What runs (details in 2.4): pytest (including property/fuzz tests marked
`fuzz`, in `tests/test_fuzz.py`), bandit, CodeQL (Python), pip-audit,
govulncheck, gitleaks, coverage gate, OpenSSF Scorecard. Third-party and
open-source libraries are covered by pip-audit, govulncheck and Dependabot.

What does not exist:

- No dynamic application security testing (DAST) and no end-to-end security
  scan of the running server.
- No independent or third-party testing. The maintainer is the only tester;
  objectivity and independence (N/A - single maintainer) are not met.
- No pre-commit hooks (no `.pre-commit-config.yaml`).
- CodeQL does not analyse Go and, as noted in 2.4, its PR trigger names the
  wrong branch. `go test`/`go vet` do not run on pull requests.
- CI on `master` is currently failing, so detection results are not a reliable
  release gate until that is fixed.
- Vulnerability inventory: findings are tracked as `RGT-n` issues (internal) and
  in archived audit reports; there is no public vulnerability inventory and no
  stored tool configuration beyond the workflow files.

Evidence: `.github/workflows/ci.yml`, `.github/workflows/review-gate.yml`,
`.github/workflows/codeql.yml`, `tests/test_fuzz.py`.

### 4.2 Vulnerability Remediation and Prevention of Reintroduction (RGT-474)

**Status: Partial.**

- Remediation timing: `.github/SECURITY.md` promises acknowledgement within 5
  business days and a remediation plan or assessment within 30 days. There is
  no per-severity fix deadline in force. A severity matrix exists only in
  `docs/archive/program/severity-matrix.md` (archived; not an operating policy).
- Only the latest release receives security fixes (`.github/SECURITY.md`,
  "Supported versions").
- Regression protection: fixes come with tests (for example
  `tests/test_audit_fixes.py`, `tests/test_audit_v2_hardening.py`,
  `tests/test_hardening.py`); `CONTRIBUTING.md` requires tests for crypto,
  authorization, audit and storage changes. CI runs them on every push and pull
  request.
- Decision not to fix: recorded as non-goals or limitations in
  `.github/SECURITY.md`; the maintainer is the sole approver (N/A - single
  maintainer).

Evidence: `.github/SECURITY.md`, `tests/test_audit_fixes.py`,
`.github/CONTRIBUTING.md`.

---

## 5. Software Change Management

### 5.1 Software Change Management and Security Impact Analysis (RGT-475)

**Status: Partial.**

- All changes are recorded in git with author, committer and timestamp; commit
  messages usually name the tracker issue (`RGT-n`). That is the change
  inventory.
- Only 5 pull requests have been merged; most history is direct commits to
  `master`. The pull-request template's security checklist therefore covers
  only the minority of changes that use it.
- Authorization: the maintainer. No second reviewer is required or configured
  (no CODEOWNERS file, one collaborator). Whether `master` is protected on
  GitHub could not be verified (see 6.1).
- Security impact analysis: the PR checklist asks whether secrets are logged,
  whether tests were added, whether nonces use `os.urandom` and whether docs
  overstate guarantees. There is no further impact-analysis step.
- Decisions and justifications are recorded in commit messages, PR
  descriptions, ADRs and the internal tracker.
- `CHANGELOG.md` is updated per change (CONTRIBUTING requirement).

Evidence: `git log`, `.github/PULL_REQUEST_TEMPLATE.md`,
`.github/CONTRIBUTING.md`, `CHANGELOG.md`.

### 5.2 Unique Version Identification and Tracking (RGT-476)

**Status: Exists.**

- Scheme: Semantic Versioning, stated at the top of `CHANGELOG.md`; format is
  Keep a Changelog.
- Python version is set in `pyproject.toml` (`0.3.0`). Go binaries embed
  version, commit and date through ldflags in `go/.goreleaser.yaml`.
- Tags `v0.1.0`, `v0.2.0` and `v0.3.0` identify releases; `CHANGELOG.md` has a
  section for each.
- Component tracking per release: `go/go.mod`/`go.sum` pin Go dependencies;
  goreleaser attaches an SBOM to release archives. Python dependencies are
  declared as ranges without a lockfile, so a Python release does not pin its
  transitive dependencies (Gap; the CI SBOM is generated from the checkout, not
  from a locked build).
- Minor inconsistency to be aware of: the Go server reports its own version
  string separately from the tag.

Evidence: `pyproject.toml`, `CHANGELOG.md`, `go/.goreleaser.yaml`, `git tag`.

---

## 6. Software Integrity and Delivery

### 6.1 Software Code Integrity Maintenance (RGT-477)

**Status: Gap (partial protections exist).**

What exists:

- Source is hosted on GitHub with one collaborator, so only that account can
  push.
- `.gitignore` excludes vault runtime data (`*.db`, `keychain.json`, `*.priv`).
- gitleaks scans history on every push and pull request (`.github/workflows/review-gate.yml`).
- Dependabot keeps actions and dependencies current.

What is missing:

- **No commit signing.** Of the commits in history, none is verified-signed
  (`git log --format=%G?` shows `N` for 98 and `E` for 4, i.e. unverifiable).
  The previous draft stated that GPG signing was required; that was untrue.
- **Branch protection not verified.** The API call returned 403 and no
  rulesets exist, so enforcement of reviews or status checks on `master`
  cannot be claimed.
- **Actions not pinned by SHA** (tags, and `ossf/scorecard-action@main`).
- No detection of unauthorized tampering beyond GitHub's own audit log, which is
  not monitored by this project.

Evidence: `git log --format=%G?`, `.gitignore`, `.github/workflows/review-gate.yml`,
`.github/workflows/*.yml` (action references).

### 6.2 Secure Delivery and Integrity Verification of Updates (RGT-478)

**Status: Partial.**

- **Go releases.** Tag push `v*` runs `.github/workflows/release.yml`: `go test
  ./...`, then GoReleaser (`go/.goreleaser.yaml`) builds linux/darwin/windows
  archives for amd64 and arm64, writes `checksums.txt` (SHA-256), generates
  SBOMs with Syft, and creates a **draft** GitHub release. Delivery is over
  HTTPS from GitHub. `docs/getting-started/installation.md` shows how to verify
  the checksum.
- **No digital signatures.** The cosign `signs:` block in `go/.goreleaser.yaml`
  is commented out. Checksums prove integrity only if the user obtained
  `checksums.txt` from a trusted channel; they do not prove authenticity.
- **Python line.** No package is published to PyPI by any workflow. CI builds a
  wheel and stores it as a CI artifact; users install from a source checkout.
- **Draft release.** `v0.3.0` is still a draft GitHub release.
- The tools have no auto-update mechanism (none found in `rgt_vault/` or `go/`),
  so "updates" are new releases the user chooses to download.
- Package-manager channels (Homebrew tap, winget, apt) are not set up: the
  `brews:` block in `go/.goreleaser.yaml` is commented out (RGT-163).

Evidence: `.github/workflows/release.yml`, `go/.goreleaser.yaml`,
`docs/getting-started/installation.md`.

---

## 7. Data Protection and Secure Configuration

### 7.1 Sensitive Production Data Collection and Authorization (RGT-479)

**Status: N/A for project-operated systems; Exists for local data (inventory).**

The project operates no production systems and collects nothing from users, so
there is no vendor-side production data to authorize. Data that exists locally
on a user's machine (their data, under their control):

| Data | Where | Sensitivity | Notes |
|---|---|---|---|
| Secret values | `vault.db` (encrypted) | High | Never returned to general callers in plaintext by the API |
| Secret names, namespaces, versions, status, timestamps | `vault.db` (unencrypted) | Medium | Metadata is visible to anyone who can read the file |
| Audit rows: action, secret name, details, agent id, hashes; HTTP rows include token id (8 characters), client IP, method and path | `audit_logs` | Medium | No retention limit; rows are never purged except by a full import, which replaces them |
| Wrapped DEK and KDF parameters | `keychain.json` | High | Mode 0600 |

Collection and retention are not configurable beyond what the vault stores.
There is no telemetry. Retention of audit logs is unlimited and has no
configured rotation (logging-policy work is tracked separately).

Evidence: `rgt_vault/storage/migrations/0001_initial.sql`,
`rgt_vault/server/app.py` (HTTP audit rows), absence of telemetry (search of
`rgt_vault/` and `go/`).

### 7.2 Protection and Secure Deletion of Production Data (RGT-480)

**Status: Gap (protection partial, deletion missing).**

Protection that exists:

- Secrets encrypted at rest with AES-256-GCM under a DEK wrapped by an
  Argon2id/HKDF-derived key; ciphertext bound to `vault_id:namespace:name`.
- Default-deny ABAC for reads and writes; every access is audited.
- File mode 0600 on `keychain.json` and on bearer token files (POSIX).
- Master and data-key rotation exist (`rotate_master_key`, `rotate_dek` in
  `rgt_vault/vault.py`).

Not met:

- **No secure deletion.** `revoke_secret` only sets `status = 'REVOKED'`; the
  ciphertext row remains in `vault.db`. There is no hard-delete command, SQLite
  `secure_delete` is not set, and database free pages, journals and backups are
  not scrubbed. A revoked secret is protected by encryption, not erased.
- **No encryption in transit.** There is no TLS anywhere in the code. The daemon
  binds to loopback by default; the Go skeleton server binds all interfaces.
  Earlier governance text marked this "Implemented"; it is not (RGT-251,
  RGT-455, RGT-456).
- Memory zeroization is best effort and partial (`.github/SECURITY.md`).

Evidence: `rgt_vault/storage/sqlite.py` (`revoke_secret`), `rgt_vault/crypto.py`,
`rgt_vault/vault.py`, `.github/SECURITY.md`.

---

## 8. Secure Configuration and Implementation Guidance

### 8.1 Secure Implementation and Configuration Guidance (RGT-481)

**Status: Partial.**

Guidance that exists:

- `README.md` (Security Goals), `.github/SECURITY.md` (assumptions, guarantees,
  non-goals), `docs/concepts/security-model.md`, `docs/concepts/trust-boundary.md`.
- `docs/guides/policies.md` (writing ABAC policies, default-deny),
  `docs/guides/cli.md`, `docs/guides/api.md`, `docs/guides/mcp.md`,
  `docs/guides/secure-buffer-patterns.md`.
- A hardened deployment: `deploy/rgt-vault.service` (dedicated user, loopback
  bind, separate agent and operator token files, `--require-approval`,
  systemd sandboxing options) installed by `deploy/setup-daemon.sh`.
- Secure defaults in code: `serve` binds `127.0.0.1` and warns when bound
  elsewhere; there are no default credentials (tokens are generated randomly on
  first run, mode 0600).

Not met:

- No single consolidated hardening checklist listing every security-relevant
  option.
- The Go server's defaults are not secure (binds all interfaces, prints its
  token, allow-all policy stub) and nothing in the Go README says not to use it
  with real secrets.

Evidence: `deploy/rgt-vault.service`, `deploy/setup-daemon.sh`,
`rgt_vault/cli.py` (`serve`), `docs/guides/`, `docs/concepts/security-model.md`.

### 8.2 Detailed Component and Platform Installation Instructions (RGT-482)

**Status: Partial.**

- `docs/getting-started/installation.md` covers the Go release tarball with
  checksum verification, building from source, and a quickstart.
- `docs/getting-started/quickstart.md` and `README.md` cover the Python install.
- Platform key custody (DPAPI, macOS Keychain, Linux TPM, `keyring`) is
  described in the provider documentation and `docs/architecture/crypto.md`.
- `deploy/setup-daemon.sh` is the documented Linux daemon install.

Not met:

- `docs/getting-started/installation.md` describes a Homebrew install, but no
  tap exists and the `brews:` block of the GoReleaser config is commented out
  (RGT-163). The instructions are not fully accurate.
- No instructions exist for macOS or Windows daemon deployment beyond the
  README's Windows notes.
- The installation page is titled "Go", but the Go server is a skeleton; a
  reader following it does not get a secure vault.

Evidence: `docs/getting-started/installation.md`, `go/.goreleaser.yaml`,
`deploy/setup-daemon.sh`.

### 8.3 Alignment of Guidance with Software Updates (RGT-483)

**Status: Partial.**

- The pull-request template asks the author to confirm docs are updated, and
  `CONTRIBUTING.md` requires docs, `SECURITY.md` and the LLM guide
  (`rgt_vault/llm_guide.py`) to change with behaviour.
- `CHANGELOG.md` is updated with each change.
- Annual review: none (N/A - single maintainer). No scheduled accuracy review
  exists, and drift has occurred (for example 8.2 above, and links in older
  documents that point to files that have moved to `docs/archive/`).
- This governance suite is itself verified against a specific commit (see the
  header) so that readers can tell when it was last accurate.

Evidence: `.github/PULL_REQUEST_TEMPLATE.md`, `.github/CONTRIBUTING.md`.

---

## 9. Security Communication and Incident Response

### 9.1 Bi-directional Security Communication Channels (RGT-484)

**Status: Exists.**

- **Channel 1:** a private email address published in `.github/SECURITY.md`.
- **Channel 2:** GitHub private vulnerability reporting is enabled on the
  repository (checked via the GitHub API), and `.github/ISSUE_TEMPLATE/config.yml`
  disables blank issues and points reporters to GitHub security advisories.
  (`.github/SECURITY.md` itself mentions only the email channel.)
- **Response targets (authoritative, from `.github/SECURITY.md`):**
  acknowledgement within **5 business days**; a remediation plan or assessment
  within **30 days**; coordinated disclosure preferred. Earlier drafts of this
  document promised a 24-hour response; that was never in force.
- **Resources:** the maintainer alone. No on-call rota, no bug-bounty programme
  (N/A - single maintainer).
- Public issues are for non-sensitive matters; templates are in
  `.github/ISSUE_TEMPLATE/`.

Evidence: `.github/SECURITY.md`, `.github/ISSUE_TEMPLATE/config.yml`.

### 9.2 Timely Stakeholder Update Notifications (RGT-485)

**Status: Gap.**

There is no mailing list, no announcement channel and no commitment to notify
users "immediately" of a security release. What exists is passive:

- Releases are published on GitHub (`v0.3.0` is still a draft) and users who
  watch the repository receive GitHub's release notifications.
- Security-relevant fixes are described in `CHANGELOG.md` under `### Security`
  headings, and GitHub security advisories could be published for the project
  (none have been).
- Dependabot and the CI scanners notify the maintainer, not users.

Evidence: `CHANGELOG.md`, `.github/workflows/release.yml`; no advisories
published (see [SECURITY_ADVISORIES.md](SECURITY_ADVISORIES.md)).

### 9.3 Vulnerability Mitigation Advisory Process (RGT-486)

**Status: Gap.**

- No security advisory has ever been published. There is no CVE-assignment
  process and no record of issuing a workaround ahead of a patch.
- Known limitations and mitigation guidance for the weaknesses that are already
  public are written in `.github/SECURITY.md` ("Non-goals", "Audit Chain
  Limitations", with the hardened-deployment advice) and `docs/ROADMAP.md`.
- [SECURITY_ADVISORIES.md](SECURITY_ADVISORIES.md) holds the (empty) advisory
  register and the fields an advisory should carry. GitHub's repository
  security-advisory feature is the available vehicle; it has not been used.

Evidence: `.github/SECURITY.md`, `docs/ROADMAP.md`,
`docs/governance/SECURITY_ADVISORIES.md`.

---

## 10. Release Management and Support

### 10.1 Release Notes and Change Summaries (RGT-487)

**Status: Exists.**

- `CHANGELOG.md` (Keep a Changelog) has a section per release (`0.1.0`,
  `0.2.0`, `0.3.0`) and an `[Unreleased]` section, with `### Security`,
  `### Added`, `### Changed`, `### Fixed` and `### Removed` headings that name
  affected functionality and controls.
- GoReleaser generates a categorised change list (features, bug fixes, other)
  from conventional-commit prefixes for each GitHub release, which is created
  as a draft so the maintainer can edit it before publishing.
- No invented release notes are kept in this repository. The earlier draft
  contained notes for a "RGT Vault 1.2.0" that was never released and has been
  removed; the project is pre-1.0 (`.github/SECURITY.md`).
- Gap: the `v0.2.0` tag has no GitHub release and the `v0.3.0` release is a
  draft, so GitHub release pages are incomplete.

Evidence: `CHANGELOG.md`, `go/.goreleaser.yaml`.

---

## Summary of objective status

| Objective | Issue | Status |
|---|---|---|
| 1.1 Security responsibility | RGT-460 | Exists / N/A - single maintainer |
| 1.2 Lifecycle responsibilities | RGT-461 | Partial |
| 1.3 Skills management | RGT-462 | N/A - single maintainer |
| 2.1 Compliance requirements | RGT-463 | Partial |
| 2.2 Security policy | RGT-464 | Exists |
| 2.3 Strategy | RGT-465 | Partial |
| 2.4 Assurance processes | RGT-466 | Exists |
| 2.5 Evidence | RGT-467 | Partial |
| 2.6 Ineffective processes | RGT-468 | Gap |
| 3.1 Critical assets | RGT-469 | Exists |
| 3.2 Threat modeling and OSS | RGT-470 | Partial |
| 3.3 Control definition | RGT-471 | Partial |
| 3.4 Control effectiveness | RGT-472 | Gap |
| 4.1 Security testing | RGT-473 | Partial |
| 4.2 Remediation | RGT-474 | Partial |
| 5.1 Change management | RGT-475 | Partial |
| 5.2 Versioning | RGT-476 | Exists |
| 6.1 Code integrity | RGT-477 | Gap |
| 6.2 Delivery integrity | RGT-478 | Partial |
| 7.1 Data collection | RGT-479 | N/A for project; inventory exists |
| 7.2 Data protection and deletion | RGT-480 | Gap |
| 8.1 Secure configuration guidance | RGT-481 | Partial |
| 8.2 Installation instructions | RGT-482 | Partial |
| 8.3 Guidance vs updates | RGT-483 | Partial |
| 9.1 Reporting channels | RGT-484 | Exists |
| 9.2 Update notifications | RGT-485 | Gap |
| 9.3 Mitigation advisories | RGT-486 | Gap |
| 10.1 Release notes | RGT-487 | Exists |

## Review and change control for this document

There is no annual governance review and no governance committee. This document
is updated by the maintainer when a process changes, and each update should
re-check the "Verified against" commit in the header. If a claim here conflicts
with `.github/SECURITY.md`, `SECURITY.md` governs.

## Appendix A: Related documentation

All paths are relative to the repository root.

- `.github/SECURITY.md`, `.github/CONTRIBUTING.md`,
  `.github/PULL_REQUEST_TEMPLATE.md`, `.github/CODE_OF_CONDUCT.md`,
  `.github/ISSUE_TEMPLATE/`
- `docs/security/threat-model.md`, `docs/concepts/security-model.md`,
  `docs/concepts/trust-boundary.md`
- `docs/architecture/crypto.md`, `docs/architecture/logging-policy.md`,
  `docs/architecture/memory-safety.md`, `docs/adr/`
- `docs/ROADMAP.md`, `CHANGELOG.md`
- `docs/archive/` (audits, review checklists, and an earlier programme
  description; archived material is history, not an operating process)

## Appendix B: Relationship to external frameworks

- The objective numbers 1.1 to 10.1 are the tracker's (epic RGT-488); they are
  not OWASP ASVS requirement identifiers and must not be cited as such.
- The earlier draft of this appendix mapped these objectives to "OWASP ASVS
  Level 3 V1.1 to V10.1" and claimed full coverage. That mapping was incorrect
  and has been removed. No conformance to ASVS, PCI Secure SLC, ISO/IEC 27034,
  BSIMM, OWASP SAMM or NIST SP 800-160 is claimed.
- ASVS verification against the actual code is tracked under RGT-492 and is
  documented separately from this governance document.
