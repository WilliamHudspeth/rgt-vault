# Threat Modeling and Mitigation Inventory

A STRIDE-organised list of the threats that apply to `rgt-vault`, the
mitigations that exist in code today, and the gaps. Written to match the code
as it is, not as it is intended to be. It supports objective 3.2 of
[GOVERNANCE.md](GOVERNANCE.md).

- **Verified against:** commit `c3b090b` on `master`, checked 2026-11-26.
- **Authoritative related documents:** [`.github/SECURITY.md`](../../.github/SECURITY.md)
  (guarantees and non-goals) and [`docs/security/threat-model.md`](../security/threat-model.md)
  (narrative threat model). If this file disagrees with `SECURITY.md`,
  `SECURITY.md` governs.
- **Earlier draft:** the previous version of this file listed password
  policies, MFA, account lockout, TLS 1.2+ and RBAC roles as implemented
  mitigations. None of those exist. This version removes them.
- **Severity numbers removed.** The earlier CVSS scores were not computed from
  anything; severity here is a rough High/Medium/Low judgement by the
  maintainer.

## Scope

**Python line (`rgt_vault/`), the product that actually protects secrets:**

- Library and CLI: `VaultManager` (`rgt_vault/vault.py`), SQLite storage
  (`rgt_vault/storage/sqlite.py`), crypto (`rgt_vault/crypto.py`,
  `rgt_vault/keychain.py`), ABAC policy engine, audit hash chain, honeytokens, rate
  limiter, TTL leases.
- Local HTTP daemon (`rgt-vault serve`, `rgt_vault/server/`): bearer token,
  operator token, human approval with TOTP, capability execution, outbound
  actions.
- MCP stdio server (`rgt_vault/server/mcp_server.py`) and TUI client.
- OS-native key custody providers (`rgt_vault/providers/`).

**Go line (`go/`):** `go/cmd/server` is a skeleton (in-memory plaintext store,
policy stub, no persistence or crypto); `go/cmd/rgt-vault` is a CLI client;
`go/internal/gateway` is a cutover reverse proxy; `go/internal/mcp` is an MCP server;
`go/internal/netguard` is an outbound-address guard. Do not treat the Go server as
a secure vault.

**Trust boundaries:**

- Offline copies of `vault.db`, `keychain.json` and backups are untrusted
  storage; the master secret and live process memory are trusted
  (`.github/SECURITY.md`).
- The loopback HTTP interface separates the daemon from agents. Whoever holds
  the bearer token is trusted as "an agent"; whoever holds the operator token is
  trusted as the human operator.
- Outbound network calls made by server-side actions leave the machine.

**Out of scope, per `.github/SECURITY.md`:** root or kernel compromise of the
host, memory scraping by a privileged attacker, extraction attacks on the OS
secret store, side channels, and a malicious operator.

## Status vocabulary

| Status | Meaning |
|---|---|
| Mitigated | A control exists in code and has tests. |
| Partial | A control exists with a named limitation. |
| Gap | No effective mitigation. A tracking issue is named where one exists. |
| Accepted | A documented non-goal in `.github/SECURITY.md`. |

---

## S: Spoofing

### T-SPOOF-001: One agent acts as another (agent identity spoofing)

- **Threat:** any caller with the shared bearer token can claim to be any agent.
- **Why it matters:** ABAC decisions are made for the `agent` named in the
  request, so a spoofed name defeats per-agent policy.
- **Current state:** the daemon has one agent bearer token shared by every
  agent. The `agent` value used for policy evaluation is a field in the request
  body (`rgt_vault/server/app.py`, `vault.execute(body.agent, ...)`); it is not
  derived from the token. Approval and operator routes use a separate operator
  token, but when none is configured the agent token store is used as the
  operator store (`rgt_vault/server/app.py`, `_operator_store = operator_token_store or
  token_store`; a warning is logged in production mode).
- **Status: Gap.** Tracked: RGT-236, RGT-343, RGT-346, RGT-235.
- **Evidence:** `rgt_vault/server/app.py`, `rgt_vault/server/auth.py`.

### T-SPOOF-002: Bearer, operator or TOTP credential theft

- **Threat:** an attacker who can read the token files or the TOTP secret file
  gains the corresponding access.
- **Mitigations that exist:** tokens are 256-bit random values
  (`secrets.token_urlsafe(32)` in `rgt_vault/server/auth.py`); files are chmod
  0600 on POSIX; comparison is constant-time; only an 8-character token id is
  logged by the Python server; the hardened unit runs the daemon as a separate
  user so agents cannot read the files (`deploy/rgt-vault.service`).
- **Limits:** tokens are stored in plaintext and never expire; rotation means
  replacing the file; the same token is used by every agent. The Go server
  prints the full bearer token to stdout and its log on start
  (`go/cmd/server/main.go`). TOTP secret is a plaintext file.
- **Status: Partial** (Python), **Gap** (Go server logging). Tracked: RGT-318,
  RGT-320, RGT-409.
- **Evidence:** `rgt_vault/server/auth.py`, `deploy/rgt-vault.service`,
  `go/cmd/server/main.go`.

### T-SPOOF-003: Network interception (MITM) of agent-to-daemon traffic

- **Threat:** traffic between agent and daemon is read or altered on the
  network.
- **Current state:** **there is no TLS anywhere in the code.** `rgt-vault serve`
  starts uvicorn without certificates and the Go server uses `ListenAndServe`
  without TLS. The only mitigation is that the Python daemon binds `127.0.0.1`
  by default and prints a warning if bound elsewhere; the systemd unit says to
  put a TLS reverse proxy in front if exposure is required (no example proxy
  configuration ships). The Go server binds `:8080` on all interfaces.
- **Status: Gap.** Tracked: RGT-251, RGT-455, RGT-456, RGT-458 (mTLS evaluation).
- **Evidence:** `rgt_vault/cli.py` (`serve`), `deploy/rgt-vault.service`,
  `go/cmd/server/main.go`.

### T-SPOOF-004: Capability token forgery or replay

- **Threat:** a forged or replayed capability token executes an action.
- **Current state:** capability tokens are HMAC-signed with expiry
  (`rgt_vault/token.py`, tests in `tests/test_token.py`); failed verification is
  rate-limited per agent (`auth_failure_limiter` in `rgt_vault/vault.py`).
  However `rgt-vault serve` does not configure a token verifier, so
  `/v1/capabilities/execute` currently fails closed through the server; the
  replay cache applies only when the two-factor hook is configured; an
  Ed25519 verifier is a stub.
- **Status: Partial.** Tracked: RGT-337, RGT-338, RGT-35, RGT-46.
- **Evidence:** `rgt_vault/token.py`, `rgt_vault/cli.py`, `tests/test_token.py`.

---

## T: Tampering

### T-TAMP-001: Modifying or swapping stored ciphertext

- **Mitigations:** AES-256-GCM with the AAD `vault_id:namespace:name`, so edited
  or swapped ciphertext and a `keychain.json` from another vault fail
  authenticated decryption; key epoch check rejects mismatched
  `vault.db`/`keychain.json` pairs.
- **Limits:** restoring a matched old pair is not detected (backup rollback;
  `.github/SECURITY.md`; design note for an anchor in `docs/ROADMAP.md`).
- **Status: Mitigated** (tamper and swap), **Accepted** (matched rollback).
- **Evidence:** `rgt_vault/crypto.py`, `rgt_vault/keychain.py`,
  `tests/test_asvs_crypto.py`, `tests/test_fuzz.py` (wrong key, wrong AAD).

### T-TAMP-002: Injection through API or CLI input

- **Mitigations:** SQLite access uses parameterised queries
  (`rgt_vault/storage/sqlite.py`); names, namespaces and agent ids are checked
  against allow-list patterns (`rgt_vault/input_validation.py`); request
  bodies are Pydantic models; `Content-Type: application/json` is required on
  `/v1/` POSTs; no `eval`, `exec` or `pickle` in the shipped packages; no
  `shell=True` in `rgt_vault/` or `go/`.
- **Limits:** Pydantic models do not forbid extra fields; the Go server does not
  reject unknown fields; query-parameter duplicate handling differs between the
  Python and Go servers.
- **Status: Mitigated** (injection into SQL/commands), **Partial** (strict
  schemas). Tracked: RGT-352, RGT-351.
- **Evidence:** `rgt_vault/input_validation.py`, `tests/test_input_validation_epic.py`,
  `tests/test_validation.py`.

### T-TAMP-003: Server-side request forgery through outbound actions

- **Threat:** an agent uses an action such as an authenticated HTTP request to
  reach internal services or cloud metadata.
- **Mitigations:** `_validate_outbound_url` in `rgt_vault/server/actions.py`
  blocks non-http(s) schemes, loopback, link-local and private ranges unless the
  operator passes `--allow-private-network`; the Go `go/internal/netguard` package
  rejects link-local and metadata addresses and, by default, non-loopback
  addresses unless remote access is allowed. Both guards have tests.
- **Limits:** the Python check resolves the host before the request (a small
  rebinding window); redirects are followed by `urllib` without re-checking
  each hop; plain `http://` is allowed.
- **Status: Partial.** Tracked: RGT-252, RGT-355, RGT-361.
- **Evidence:** `rgt_vault/server/actions.py`, `go/internal/netguard/`,
  `tests/test_actions.py`, `tests/test_server_hardening.py`.

### T-TAMP-004: Dependency or build-chain compromise

- **Mitigations:** Dependabot (pip, gomod, github-actions, weekly); `pip-audit`
  and `govulncheck` in CI; gitleaks; CycloneDX SBOM in CI and Syft SBOMs in
  Go releases; Go modules pinned in `go.sum`.
- **Limits:** Python dependencies are ranges without a lockfile; GitHub Actions
  are pinned by tag, not commit SHA; no release signing (cosign block in
  `go/.goreleaser.yaml` is commented out); no commit signing; CI currently
  fails on `master`, so the scanners are not a reliable gate right now.
- **Status: Partial.** Tracked: RGT-261, RGT-260, RGT-163.
- **Evidence:** `.github/dependabot.yml`, `.github/workflows/`,
  `go/.goreleaser.yaml`.

### T-TAMP-005: Tampering with policy or configuration

- **Mitigations:** the hardened systemd unit runs the daemon as a dedicated user
  with `ProtectSystem=strict`, `NoNewPrivileges` and a single writable path
  (`deploy/rgt-vault.service`); the policy hash is recorded in audit rows.
- **Limits:** whoever controls the policy file, the master secret or the audit
  database can change behaviour. This is a stated non-goal.
- **Status: Accepted** (malicious operator), **Partial** (accidental or
  non-root tampering).
- **Evidence:** `.github/SECURITY.md`, `deploy/rgt-vault.service`.

### T-TAMP-006: Rewriting the audit log

- **Mitigations:** each audit row includes a SHA-256 hash of the previous row;
  `verify_audit_chain()` detects insertion, edits and mid-chain deletion
  (`tests/test_audit_v2_hardening.py`).
- **Limits:** the chain is unkeyed. Someone with write access to `vault.db` can
  rebuild a consistent chain, and tail truncation or full replacement is not
  detected. There is no external anchor for the tail hash.
- **Status: Partial / Accepted** for root-level replacement
  (`.github/SECURITY.md`, "Audit Chain Limitations"). A keyed chain is a
  follow-up idea.
- **Evidence:** `rgt_vault/storage/sqlite.py`, `rgt_vault/vault.py`
  (`verify_audit_chain`), `tests/test_audit_v2_hardening.py`.

---

## R: Repudiation

### T-REP-001: An agent or operator denies an action

- **Mitigations:** reads, writes, approvals, revocations, policy denials and
  honeytoken hits are written to the hash-chained audit log; authenticated HTTP
  requests write an `HTTP_API` row with token id, client IP, method and path.
- **Limits:** attribution is weak while all agents share one token and the
  agent name is self-declared (T-SPOOF-001). Failed authentication attempts are
  not audited. `HTTP_API` rows are written before the handler runs and do not
  record the response status. The log gives tamper-evidence, not
  non-repudiation (no signatures).
- **Status: Partial.** Tracked: RGT-413, RGT-414, RGT-432.
- **Evidence:** `rgt_vault/server/app.py` (`require_token`),
  `rgt_vault/storage/sqlite.py`.

---

## I: Information disclosure

### T-INFO-001: Secrets or tokens in logs and error messages

- **Mitigations:** the Python server logs token ids, not tokens; audit
  details avoid secret values; `CONTRIBUTING.md` and the PR checklist forbid
  logging secret plaintext; an error path returns an incident id for unexpected
  exceptions.
- **Limits:** the Go server prints its bearer token (see T-SPOOF-002); registered
  validation error handlers can echo exception text; there is no automated test
  that asserts tokens and secrets are absent from every log path.
- **Status: Partial.** Tracked: RGT-409, RGT-428, RGT-418 to RGT-421.
- **Evidence:** `rgt_vault/server/app.py`, `go/cmd/server/main.go`,
  `.github/CONTRIBUTING.md`.

### T-INFO-002: Theft of the database file

- **Mitigations:** secret values are AES-256-GCM ciphertext; the DEK is wrapped
  under an Argon2id-derived key and the master secret is held by the OS store.
  Without the master secret an attacker with `vault.db` and `keychain.json`
  cannot recover plaintext.
- **Limits:** secret names, namespaces, versions, timestamps, status and audit
  rows are stored unencrypted, so metadata is visible. Revoked secrets are
  retained as ciphertext.
- **Status: Mitigated** (values), **Gap** (metadata confidentiality; not a
  stated goal).
- **Evidence:** `rgt_vault/storage/migrations/0001_initial.sql`,
  `rgt_vault/keychain.py`.

### T-INFO-003: Disclosure through backups and exports

- **Current state:** exports are bound to a vault id and DEK and only restore
  into the same vault (`.github/SECURITY.md`). The export envelope itself has no
  integrity MAC and import trusts the contents of audit rows and status fields.
- **Status: Partial.** Tracked: RGT-377.
- **Evidence:** `rgt_vault/vault.py` (`export_vault`, `import_vault`).

### T-INFO-004: Plaintext lingering in memory

- **Mitigations:** the vault leases a `bytearray` and wipes it after use
  (`zeroize_bytearray`, `SecureBuffer`); the DEK is not stored in the
  database.
- **Limits:** best effort and partial: copies made into `bytes` or `str`, the
  master secret (immutable bytes) and the DEK in process memory are not wiped.
- **Status: Accepted** (documented non-goal; `.github/SECURITY.md`,
  `docs/architecture/memory-safety.md`). Tracked: RGT-32 (design work).
- **Evidence:** `rgt_vault/crypto.py`, `tests/test_set_secret_zeroize.py`.

### T-INFO-005: Go skeleton server holds plaintext secrets

- **Current state:** `go/internal/server/handlers/handlers.go` keeps secrets in a
  process-memory map with no encryption or persistence, and the
  `GET /v1/secrets` listing returns the full `Secret` structs, including the
  `value` field.
- **Status: Gap** (the Go server is not a secure store). Tracked: RGT-259
  (bind and CORS defaults), RGT-342 (policy stub).
- **Evidence:** `go/internal/server/handlers/handlers.go`, `go/README.md`.

---

## D: Denial of service

### T-DOS-001: Resource exhaustion

- **Mitigations:** per-agent rate limiter on secret use (`RateLimiter` in
  `rgt_vault/vault.py`); a failure limiter on capability-token verification;
  secret value size cap (1 MiB); query limits on list endpoints.
- **Limits:** limiters are in memory and reset on restart; the Python HTTP layer
  has no request-body size cap and trusts `Content-Length` parsing; an unbounded
  `offset` can raise an error; the Go server has no body cap.
- **Status: Partial.** Tracked: RGT-357, RGT-376, RGT-256, RGT-257.
- **Evidence:** `rgt_vault/vault.py`, `rgt_vault/server/app.py`,
  `tests/test_hardening.py`.

### T-DOS-002: Crash or fail-open under error

- **Mitigations:** policy and approval paths fail closed (timeout is denial);
  unexpected exceptions return a generic body with an incident id; migrations
  are transactional (`tests/test_migration_atomicity.py`); key rotation is
  atomic (single transaction).
- **Limits:** `RGT_VAULT_DEBUG=1` enables FastAPI debug output; the systemd unit
  does not set `APP_ENV=production`.
- **Status: Partial.** Tracked: RGT-345, RGT-427.
- **Evidence:** `rgt_vault/server/app.py`, `tests/test_approval.py`,
  `tests/test_migration_atomicity.py`.

---

## E: Elevation of privilege

### T-ELEV-001: Policy bypass

- **Mitigations:** Python ABAC is default-deny, explicit deny wins, and every
  read and write is checked (`rgt_vault/vault.py`); ABAC rather than RBAC is a
  recorded decision (`docs/adr/ADR-0002-abac-over-rbac.md`); namespace
  enumeration protection is tested; freeze (kill switch) state is consulted
  before execution.
- **Limits:** policy subject is self-declared (T-SPOOF-001); in the Go server
  the policy decision is hard-coded to allow.
- **Status: Mitigated** (engine, Python), **Gap** (Go).
- **Evidence:** `rgt_vault/vault.py`, `tests/test_vault_v2.py`,
  `go/internal/server/handlers/handlers.go`.

### T-ELEV-002: Agent token used for operator actions

- **Threat:** the agent token reaches `/v1/rotate`, `/v1/audit`,
  `/v1/audit/verify`, `/v1/policy/simulate`, or set/revoke; any agent token can
  read the full audit log.
- **Mitigations:** approval routes require the operator token and a separate
  test confirms an agent token cannot approve a request
  (`tests/test_server_approval.py`); human approval with TOTP gates secrets
  marked `require_2fa`.
- **Limits:** rotation, audit and policy routes accept the agent bearer token;
  setting a new secret version without `require_2fa` removes the approval gate.
- **Status: Partial.** Tracked: RGT-237, RGT-344, RGT-431, RGT-423, RGT-350.
- **Evidence:** `rgt_vault/server/app.py`, `tests/test_server_approval.py`.

### T-ELEV-003: Prompt-injected agent exfiltrates secrets

- **Mitigations:** capability model (agents receive the result of an action, not
  the secret), ABAC limits per agent and purpose, honeytokens that raise a
  critical `HONEYTOKEN_TRIGGERED` audit row, per-agent rate limit, and the
  optional human approval gate.
- **Limits:** none of this holds if an agent can impersonate another
  (T-SPOOF-001) or holds the operator token.
- **Status: Partial.**
- **Evidence:** `docs/concepts/capabilities.md`, `rgt_vault/vault.py`,
  `tests/test_capabilities.py`.

---

## Design flaws and open design items

| ID | Item | Status | Tracking / evidence |
|---|---|---|---|
| DF-001 | Cryptographic design: AES-256-GCM, Argon2id, HKDF-SHA512, random nonces, DEK rotation thresholds | Mitigated; some KDF and key-hierarchy changes deliberately held for sign-off | `rgt_vault/crypto.py`, `rgt_vault/keychain.py`, `docs/architecture/crypto.md`, RGT-217, RGT-218 |
| DF-002 | Input validation and schema strictness | Partial (see T-TAMP-002) | `rgt_vault/input_validation.py` |
| DF-003 | Single shared bearer token, self-declared agent | Gap | RGT-236, RGT-343, RGT-346 |
| DF-004 | Logging and audit completeness (failed auth, response status) | Partial | RGT-413, RGT-414, RGT-432 |
| DF-005 | No transport encryption | Gap | RGT-251, RGT-455, RGT-456 |
| DF-006 | Go line is labelled primary but is a skeleton | Open decision | RGT-165; `go/README.md` |

## Summary

| Category | Mitigated | Partial | Gap | Accepted |
|---|---|---|---|---|
| Spoofing (4) | 0 | 1 | 3 | 0 |
| Tampering (6) | 1 | 4 | 0 | 1 |
| Repudiation (1) | 0 | 1 | 0 | 0 |
| Information disclosure (5) | 1 | 2 | 1 | 1 |
| Denial of service (2) | 0 | 2 | 0 | 0 |
| Elevation of privilege (3) | 0 | 2 | 1 | 0 |
| **Total (21)** | **2** | **12** | **5** | **2** |

Counting rule: each threat is counted under its weakest component, except
where the weaker component is an explicit non-goal in `.github/SECURITY.md`
(matched-pair backup rollback in T-TAMP-001, metadata visibility in
T-INFO-002), in which case the stronger status is used. T-SPOOF-002 and
T-ELEV-001 therefore count as Gap because of the Go server.

## Maintenance

There is no scheduled review. This file should be updated when the daemon's
authentication, authorization or transport changes, when a new network-facing
component is added (Go server, gateway, MCP), and after any vulnerability
report. Re-check the "Verified against" commit each time.
