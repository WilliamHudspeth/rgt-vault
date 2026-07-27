# Changelog
All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **DEK auto-rotation on usage thresholds (RGT-219)**: The Data Encryption Key now rotates automatically once it crosses `DEK_MAX_ENCRYPTIONS` (100M) or `DEK_MAX_BYTES` (512 GiB) — both far below the AES-256-GCM bounds in NIST SP 800-38D. Counters are durable (persisted in the `metadata` table via `get/increment/reset_dek_usage`) and survive restarts. Tallied on the `set_secret` write path only; the one-time legacy-migration bulk rewrite is deliberately excluded to avoid SQLite write-lock contention (documented in `python/vault.py`).
- **SSRF guard for outbound HTTP (RGT-109 Python, RGT-197 Go)**: The Ollama provider (`internal/llm/providers/ollama.py`) validates its `base_url`, and a new `go/internal/netguard` package guards the Go server/MCP/TUI HTTP clients. Both reject link-local / cloud-metadata addresses (169.254.0.0/16, fe80::/10) unconditionally, and non-loopback addresses unless remote access is explicitly opted in. The Go guard enforces at `net.Dialer.Control` (post-DNS, closing the DNS-rebinding window); the Python guard is a resolve-then-connect check with a documented residual TOCTOU gap.
- **Brute-force cap on capability-token verification (RGT-277)**: `execute_capability` now tracks failed credential verifications per agent in a dedicated `auth_failure_limiter` (100/hour). An agent at the cap is refused with `CAPABILITY_DENIED` before any further verification is attempted. Adds `RateLimiter.count()`/`record()` alongside the existing `allow()`.

### Changed
- **Storage**: Optimized `VaultManager._migrate_legacy_secrets` to avoid loading all records into memory, significantly improving startup time for vaults with large numbers of secrets.
- **Kanban tooling (RGT-89)**: `internal/program/_common.list_issues()` now paginates against the live Multica API (`offset`/`total`, bounded by `max_pages`) instead of a single capped fetch, so `get_issue` no longer returns `None` for identifiers sorting past the first page. Added `list_members()`.
- **WIP audit (RGT-99)**: Ready-staleness now excludes backlog and falls back to `updated_at` (Multica exposes no status-transition history — documented limitation); violation reports resolve real member names via `member_lookup()`.

### Fixed
- **LLM providers (RGT-107)**: `_http.post_json()` gained retry/backoff — Retry-After-aware on HTTP 429, bounded exponential backoff on 5xx/`URLError`. Groq opts in with `retries=3`.
- **LLM providers**: Mistral, Cohere, and Groq now guard against JSON-null response content producing a `Reply(text=None)`, returning a failed `Reply` with a logged error instead. Cohere now scans content blocks for the first `type=="text"` block rather than assuming `content[0]`.
- **Ollama provider**: `is_available()` narrowed its bare `except` to specific network/parse exceptions and now logs probe failures.
- **Import paths**: Fixed stale `scripts.*` imports (pre-dating the `scripts/`→`internal/` rename) in `internal/llm/{cli,healthcheck,kanban_review,pricing}.py` that had left those modules non-importable.

### Added
- **Docs**: Added Postgres storage backend evaluation and design doc (`docs/architecture/postgres_storage.md`) with a read-only PoC in `python/storage/postgres.py`.
- **DPAPI Provider**: Implemented `rotate_secret()` to automate Windows DPAPI re-sealing for master key rotation.
- **Server API**: Added `GET /v1/capabilities/list` endpoint to allow agents to discover which capabilities they are authorized for under the current ABAC policy.
- **TPM Provider**: Automated `.priv`/`.pub` swap during master key rotation (`rotate_secret` implemented in `LinuxTPMProvider`).
- **Docs**: Added developer guidelines for SecureBuffer patterns (`docs/guides/secure-buffer-patterns.md`) to document partial zeroization best practices.
- **TUI Live Audit Log Streamer**: Added a real-time audit log viewer to the Go TUI (`modeAudit`). Press `a` from the dashboard to stream audit events directly from the server.
- **TUI Search-as-you-type secret browser**: Added interactive search filtering to the Go TUI (`modeSearch`). Press `/` from the dashboard to instantly filter secrets by name.

## [0.3.0] — 2026-06-24

Status: Capability security refactor merged to master.
See `capability-security.md`, `migration.md`, and
`BRANCH_SUMMARY.md` for the full design.

### Maintenance mode (Go-migration cutover, RGT-164)

- **Python line is now in maintenance mode (RGT-164).** The top-level
  `README.md` carries a prominent banner stating that the Python v0.2.x
  line receives bugfixes and security patches only; all new feature work
  lands in the [Go rewrite](go/) (`rgt-vault-server`, v0.3.0). The Go
  side now ships its own `go/README.md` declaring it the primary install
  path with a cutover plan (RGT-161 → RGT-165). Tracked by RGT-165 for
  the eventual EOL archive notice 6 months after v0.3.0 ships.

### End-of-life notice (RGT-165)

- **`eol.md` published at the repo root (RGT-165).** Sets the Python
  line's EOL date at **2026-12-22** (6-month soak from the maintenance
  notice on 2026-06-22). Documents the migration path, the
  [crypto parity gaps](docs/program/eol.md#crypto-parity-gaps) that the Go line must
  close before `v0.3.0` ships, and the "what users should do today"
  table (pin to `v0.2.x`; plan to migrate to the Go line once
  crypto-integration and persistence land).
- **Go line version bumped from `0.2.0` → `0.3.0`** in
  `go/internal/server/handlers/handlers.go` HealthCheck response. The
  Go line is now on its own version track (`0.3.x+`), distinct from
  the Python `0.2.x` line. (Bumped to `0.3.0`, not `1.0.0`, because
  the Store still doesn't encrypt-at-rest and the keychain manager
  is not yet ported from Python; `v1.0.0` should be reserved for a
  tagged release that closes those gaps.)
- **Top-level `README.md` maintenance banner now links to `eol.md`**
  so the EOL date is reachable from the repo root, not just from the
  Go line's README.
- **What this PR does NOT do** (intentionally — these are terminal-state
  ops that the user should approve explicitly):
  - The repo is **not yet archived** on GitHub. Archiving is
    irreversible and the Go line is not yet production-ready; the EOL
    date is 6 months out, so there's time.
  - **No `v0.3.0` git tag** has been created. Tagging should happen
    once Store crypto integration lands (RGT-145 / RGT-146).
  - The RGT-165 ticket's referenced doc
    `docs/architecture/agentic-patterns-and-go-migration.md` does not
    exist in the repo; the new `eol.md` is the canonical reference
    until the architecture doc is regenerated.

### Added

- **v2 capability tokens** in `rgt_vault/token.py`. JSON payload
  (`agent_id`, `capability`, `capability_version`,
  `context_bindings`, `exp`), HMAC-SHA256 signed, base64url
  envelope. Wire format versioned (`v: 2`) so future format
  versions can be detected and rejected by older verifiers.
- **`TokenVerifier` ABC** with `sign` and `verify`. The
  `HMACTokenVerifier` is the v1 implementation (shared secret
  trust anchor, min 32 bytes). `Ed25519TokenVerifier` is an
  architectural stub (`NotImplementedError`) for future
  deployment; the abstraction is in place so call sites do not
  change when Ed25519 verification lands.
- **`CapabilityRegistry`** in `rgt_vault/capabilities.py`.
  `register(name, handler, supported_versions, params_schema)`,
  `get`, `has`, `list`, `unregister`. Re-registration refuses
  loudly. Built-in capabilities registered automatically on a
  fresh `VaultManager`: `secrets.echo` (diagnostic) and
  `secrets.use` (lease a stored secret and run a v0.2 action
  against it — bridge for backwards compatibility).
- **`VaultManager.execute_capability(capability_name, payload,
  agent_id, capability_token, capability_version=1)`** — the new
  primary enforcement point. Pre-flight: freeze → token verify →
  agent/capability/version match → context binding → hook
  consult (capability path) → registry + version → payload
  validation → rate limit → handler invocation. All checks
  fail-closed. Writes `CAPABILITY_EXECUTED` /
  `CAPABILITY_DENIED` / `CAPABILITY_FAILED` audit rows that
  participate in the same hash chain as legacy rows.
- **`POST /v1/capabilities/execute`** HTTP endpoint. Body:
  `{capability, agent_id, capability_token, payload,
  capability_version}`. Bearer-token gated. 4xx/5xx mappings
  documented in the endpoint docstring and in
  `capability-security.md`. Handler exceptions are sanitized
  the same way `/use` does.
- **`GET /v1/capabilities`** HTTP endpoint. Read-only listing
  of the registered capabilities (name, description, supported
  versions, params schema). No handler bodies or secret
  material exposed.
- **Capability-shaped `HookRequest`** in `rgt_vault/hook.py`.
  New fields (`capability`, `capability_version`, `payload`,
  `token_metadata`) on the existing `HookRequest` dataclass;
  legacy secret-access calls still produce the old shape.
  `req.is_capability` is the canonical branch point.
- **TwoFactorHook v1/v2 token dispatch.** `TwoFactorHook.consult`
  peeks the payload's `v` field and dispatches to `_consult_v1`
  (legacy namespace-scoped tokens) or `_consult_v2` (new
  capability-scoped tokens). The shared secret and the
  replay-protection cache are shared between the two paths.
- **Capability audit row in the hash chain.** Every
  `execute_capability` call writes a `CAPABILITY_EXECUTED` row
  with `agent`, `capability`, `capability_version`, `hook`,
  `context_hash` (sha256 of the canonical payload, 16 chars).
  `context_hash` lets an operator correlate a row with a
  specific request without recording the payload contents.

### Changed

- **`VaultManager` constructor** takes two new optional
  parameters: `capability_registry` (defaults to a fresh
  registry with built-ins registered) and `token_verifier`
  (defaults to `None`; `execute_capability` raises if not
  configured — fail closed).
- **`VaultManager` now owns an `action_registry`.** The v0.2
  `ActionRegistry` (with `openai_chat`, `http_get_with_auth`,
  `http_post_with_auth`, `echo`) is built into the vault so
  the `secrets.use` bridge works in-process. The HTTP
  server's `build_app` may replace it with a larger registry.
- **`HookRequest`** extended with the new capability fields.
  Existing custom hooks that ignore the new fields continue
  to work for legacy secret-access calls. Hooks that want to
  gate the capability path branch on `req.is_capability`.
- **Webhook envelope** is uniform across both paths;
  capability requests add `capability`, `capability_version`,
  `payload`, and `token_metadata` fields.

### Deprecated

- **`VaultManager.set_secret`** docstring now carries a
  `.. deprecated::` directive pointing operators at the
  capability path. The method still works; it is removed in
  v0.4.
- **`VaultManager.lease_secret`** and **`VaultManager.execute`**
  are similarly marked in their docstrings. New code should
  register a capability and call `execute_capability`.

### Removed

- **`hook_from_config({"mode": "soar"})`** raises
  `ValidationError`. The `soar` mode is no longer accepted.
  SOAR products integrate through `webhook` mode (stand up a
  small fronting service that translates the SOAR's response
  shape to the vault's `{"decision": "allow"|"deny"|"freeze"}`
  JSON).
- **`WebhookHook(mode=...)`** parameter is gone. The hook
  always operates in the (only) webhook mode.

### Fixed

- **Duplicate `revoke_secret` method on `VaultManager`**
  (pre-existing bug; the second definition shadowed the
  hook-consulting one). Removed the dead second definition.

### Security

- **Default deny on the capability path.** A vault constructed
  with no `token_verifier` refuses every `execute_capability`
  call with `ValidationError("execute_capability requires a
  configured token_verifier; ...")`. Operators must
  intentionally wire a verifier.
- **Context binding enforcement.** Every key the token pins
  must appear in the request payload with the same value.
  A token with `context_bindings={"repo": "org/research"}`
  cannot be replayed against `{"repo": "org/PRODUCTION"}`.
- **Capability token replay protection.** `TwoFactorHook` (when
  configured) records the `token_id` (sha256 of the canonical
  payload) and refuses the same token twice. Bounded LRU;
  same trade-off as v0.2.
- **Capability audit rows never include plaintext secrets.**
  The `context_hash` is a sha256 of the canonical payload
  (so an operator can correlate without recording the
  payload contents), and the row never includes the secret
  material or the raw capability token.
- **Freeze (kill switch) applies to the capability path.**
  `execute_capability` checks `self.hook.frozen` before any
  token verification — a frozen vault refuses every
  capability call immediately, and the `freeze_file` +
  USR1 signal + admin-endpoint mechanisms from v0.2 all
  work without modification.

### Tests

- **`tests/test_token.py`** (20 tests): verifier unit tests
  (round-trip, expiration, signature tampering, context
  binding, malformed envelopes, HMAC vs wrong secret, Ed25519
  stub, error hierarchy).
- **`tests/test_capabilities.py`** (31 tests): registry +
  `execute_capability` unit tests (happy path, agent/cap/
  version mismatch, expired token, signature failure, context
  binding, payload validation, rate limit, handler exception
  path, freeze, hook consults, legacy compat, `secrets.use`
  bridge).
- **`tests/test_capability_integration.py`** (12 tests):
  end-to-end through the HTTP surface (auth, body, token,
  4xx mappings, registry listing), webhook hook integration
  with a stub harness, `soar` mode rejection, freeze file
  blocking capability execution, audit chain integrity
  across capability + legacy rows.

193 passed, 4 skipped in 149.65s (130 pre-existing + 63 new).

### Security (v0.2.1 hardening pass — see [AUDIT-v3.md](AUDIT-v3.md))

- **RGT-113: `VaultManager.set_secret` zeroizes the plaintext buffer
  immediately after encryption.** The value is copied into a mutable
  ``bytearray`` before encryption; the bytearray is wiped in a
  ``finally`` block so policy denials and exceptions cannot leave the
  plaintext in memory. The CLI ``set`` subcommand now reads stdin and
  ``--value-file`` into a bytearray and zeroizes it after the call.
- **P0-1 (v3): `MacOSKeychainProvider.seal_master_secret` no longer writes
  the master secret to a world-readable temp file and no longer crashes
  on non-UTF-8 random secrets.** The previous implementation used
  `tempfile.NamedTemporaryFile(delete=False)` (default umask = `0o644`)
  in the system temp dir, and called `master_secret.decode("utf-8")`
  which raised `UnicodeDecodeError` on the ~99 % of random 32-byte
  buffers that are not valid UTF-8. The seal-side fix mirrors the
  Linux TPM fix from the v0.2.0 audit: `tempfile.mkstemp` + explicit
  `chmod 0o600`, with the scratch dir pinned to a vault-controlled
  location and a fail-closed `PermissionError` if `chmod` is denied.
- **P1-1 (v3): HTTP server body-size cap.** A new
  `_BodySizeLimitMiddleware` rejects requests whose `Content-Length`
  exceeds 1 MiB (matching the existing 1 MiB response cap and the 1 MiB
  cap on stored secret values) with HTTP 413 *before* the bearer-token
  check runs, so an unauthenticated local user cannot OOM the loopback
  server with a multi-GB POST.
- **P2-1 (v3): `list_secrets` writes the `LIST_SECRETS` audit row
  inside the same transaction as the listing.** v0.2.0 explicitly
  deferred this (`P2-2`); v0.2.1 closes the gap so a crash between
  the listing and the audit call can no longer leave a list-unlogged.
  The audit chain stays consistent with the data view.

### Test
- RGT-1: open a test PR to verify Multica GitHub integration auto-links to this issue.

## [0.2.0] — 2026-06-16

### Security (v0.2.0 hardening pass — see [audit-v0.2.md](docs/audits/audit-v0.2.md))

- **P0-1: SSRF in built-in HTTP actions closed.** A new
  `_validate_outbound_url` gates every outbound HTTP request made by
  `http_get_with_auth`, `http_post_with_auth`, and the `base_url`
  parameter of `openai_chat`. Default-deny for loopback / link-local /
  RFC1918 / multicast / reserved addresses and any non-http(s) scheme.
  Operators who need to call a self-hosted LLM on a private network
  start the server with `--allow-private-network` (the CLI prints an
  explicit warning when this flag is enabled).
- **P0-2: Action exception messages no longer leak into HTTP responses.**
  The `/use` endpoint catches non-VaultError exceptions, logs the full
  traceback server-side, and returns an opaque error message. If a
  future action ever raises with the plaintext secret in its message,
  the secret no longer crosses the HTTP boundary in the response.
- **P0-4: Scheme allow-list and Host-header stripping.** `file://`,
  `gopher://`, etc. are now rejected. `_validate_headers` drops
  caller-supplied `Host:` headers so urllib sets the correct one.
- **P0-5: Response body cap.** Upstream responses are truncated at
  1 MiB and flagged with `truncated: true` in the result.
- **P1-1: `verify_audit_chain` now distinguishes empty from verified.**
  Empty log is vacuously verified; tamper still detected.
- **P1-2: `verify_audit_chain` walks the entire log.** Replaced the
  silent 10,000-row cap with a full-log walk via the new
  `StorageBackend.iter_audit_log()`. Verified by a 10,005-row test that
  tampers with the last entry.
- **P1-3/P1-4: `cmd_init` no longer prints existing bearer tokens.**
  First run prints; subsequent runs say "already exists, not
  re-printing" with an audit-id helper.
- **P1-5: `LinuxTPMProvider.seal_master_secret` uses `mkstemp` + `chmod 0600`**
  for the seal scratch file (matches the unseal-side fix from the prior
  pass).
- **P2-1: `revoke_secret` writes the audit row inside the same transaction**
  as the revoke. (Was: separate connection.)
- **P2-3: HTTP `/v1/audit?limit=N` capped at 1000** to prevent authenticated
  memory DoS.
- **P2-4: `set_secret` writes the audit row inside the same transaction**
  as the secret insert. Closes the orphan-write gap.

### Added
- **`_validate_outbound_url`, `_validate_headers`, `_effective_allow_private`**
  helpers in `rgt_vault/server/actions.py`.
- **`StorageBackend.iter_audit_log()`** for full-log audit verification.
- **`--allow-private-network` flag** on `rgt-vault serve` (with explicit
  stderr warning at startup).
- **`tests/test_server_hardening.py`** (18 tests): SSRF, exception
  sanitization, scheme allow-list, header Host stripping,
  `cmd_init` idempotency.
- **`tests/test_audit_v2_hardening.py`** (6 tests): chain verify on
  tamper, verify on orphan insert, verify walks the full log,
  `set_secret` atomic audit, `revoke_secret` atomic audit.
- **`audit-v0.2.md`** — the v0.2.0 audit document.

### Security (prior audit pass — see [audit-v0.1.md](docs/audits/audit-v0.1.md))

### Fixed
- **Audit-chain verification mismatch on null `secret_name`.** `log_audit`
  hashed a missing secret name as `''`, but `verify_audit_chain` reconstructed
  it as the string `"None"`, so any entry without a secret name
  (`SIMULATION_RUN`, list denials, and the new per-request `HTTP_API` lines)
  failed verification. The verifier now coerces `None -> ''` to match the
  writer.
- **LinuxTPMProvider was non-functional on modern tpm2-tools.** Found by
  running the suite against a real `/dev/tpmrm0`. Three concrete bugs
  were blocking end-to-end use:
  1. `tpm2_createpolicy -l sha256:0,sha256:7` was rejected with
     `Failed to parse PCR string` -- the tool requires `+` as the
     separator between `<bank>:<pcr>` items.
  2. `tpm2_create` / `tpm2_load` with the legacy transient handle
     `0x40000001` (no explicit primary) failed with
     `tpm:handle(1):value is out of range or is not correct for the
     context`. Replaced with an explicit `tpm2_createprimary -C o -G rsa
     -c primary.ctx` then `tpm2_create -C primary.ctx ...`.
  3. `tpm2_unseal -p pcr:sha256:0,7` (the multi-PCR shorthand) failed
     with `policy check failed` even when the PCR values had not drifted.
     Switched to the explicit policy-session pattern:
     `tpm2_startauthsession --policy-session` -> `tpm2_policypcr -l
     sha256:0+sha256:7` -> `tpm2_unseal -p session:...`.
- **`-G aes` removed from `tpm2_create`.** Modern tpm2-tools refuses the
  `-G` + `-i` combination; the algorithm is inferred from the input
  payload.
- **`-T /dev/tpmrm0` removed from all tpm2 invocations.** The explicit
  TCTI form occasionally fails to instantiate when invoked via
  `subprocess.run`; tpm2-tools' built-in TCTI auto-discovery is more
  reliable.
- **PCR list is now persisted alongside the sealed blobs** as
  `<basename>.pcrs` so the unseal path can reconstruct the same policy
  the seal path used. Without this, any change to the provider's
  hardcoded PCR list would silently break previously-sealed blobs.

### Security (audit pass — see [audit-v0.1.md](docs/audits/audit-v0.1.md))

- **P0-1: LinuxTPMProvider no longer exposes plaintext master secret via
  the temp file written by `tpm2_unseal`.** The unseal target file is now
  created via `tempfile.mkstemp` in the same directory as the sealed blobs
  and chmod-ed to 0600 explicitly. Previously, `NamedTemporaryFile` left
  the file at the process umask (typically 022 → 0644), world-readable
  during the window between `tpm2_unseal` writing and Python reading it.
- **P0-2: `KeyringProvider` fails closed on missing keyring entry.**
  Previously, a missing master-secret entry caused the provider to
  *silently generate* a new one — which would render the existing vault
  permanently unreadable, since the DEK is wrapped under the previous
  master. Now raises `MasterSecretUnavailableError` with recovery
  guidance. The bootstrap path is moved to an explicit
  `bootstrap_master_secret` step that runs only on first-time init (no
  keychain.json present).
- **P0-3: `rotate_dek` is atomic.** A new
  `StorageBackend.bulk_rewrite_active_secrets` helper wraps the entire
  multi-row re-encryption in a single SQLite transaction. A crash
  mid-rotation leaves either the old DEK or the new DEK in effect; never
  a mix.
- **P0-4: `StorageBackend.set_secret` is atomic.** The
  UPDATE-supersede-INSERT sequence is wrapped in `BEGIN IMMEDIATE` so
  concurrent writers for the same name serialize cleanly.
- **P0-5: `StorageBackend.get_secret` is atomic with its audit-log
  write.** A new `_append_audit_in_tx` helper writes the audit entry
  inside the same transaction as the read; if the audit write fails,
  the read rolls back too.
- **P1-1: CLI plaintext from stdin / `--value-file`, never from argv.**
  `rgt-vault set NAME` no longer accepts the plaintext value as a
  positional argument — it must come from stdin
  (`echo SECRET | rgt-vault set NAME -`) or from `--value-file PATH`.
  Argv is visible to other local users via `/proc/<pid>/cmdline`.
- **P1-2: `_migrate_legacy_secrets` is atomic.** Same bulk-rewrite
  pattern as `rotate_dek`; a mid-migration crash leaves no
  half-upgraded rows.
- **P1-3: `keychain.json` is chmod 0600 after writing.** Both
  `initialize_dek` and `rewrap_dek` lock the file down explicitly.
- **P1-4: `rotate_master_key` refuses providers that don't implement
  `rotate_secret`.** Pre-checks capability *before* incrementing the
  key epoch, raising `RotateNotSupportedError`. Previously, a rotation
  on DPAPI/TPM/Keychain would bump the epoch and leave the vault in an
  inconsistent state on restart.
- **P1-5: `cmd_get` emits a zeroization-bypass warning to stderr**, and
  `llm_guide.py` no longer overstates the zeroization guarantee when
  the caller uses the `get` subcommand.
- **P2-6: Migration 0002 no longer manipulates `PRAGMA foreign_keys`**.
  Connection-level PRAGMAs belong in the storage layer's per-connection
  setup, not in migration files.

### Added

- **Local HTTP server (`rgt-vault serve`).** A new optional `[server]` extra
  (FastAPI + uvicorn) exposes the vault over loopback HTTP so non-Python
  clients — LLM agents in Ollama/llama.cpp/vLLM, scripts — can use it.
  Bearer-token auth (loopback-only `127.0.0.1:8765` by default); every request
  is gated through the existing ABAC engine / rate limiter / honeytokens and
  recorded (token id, never the token) in the hash-chained audit log.
  Endpoints: set, list, use, revoke, rotate, audit, audit/verify,
  policy/simulate. **Plaintext never crosses the HTTP boundary** — `/use` runs
  a registered server-side action (`openai_chat`, `http_get_with_auth`,
  `http_post_with_auth`, `echo`) against the leased buffer and returns only the
  result. New `rgt-vault init` mints the token file. Importing `rgt_vault` does
  not require FastAPI; the server layer raises a clear `ImportError` with
  install instructions if the extra is missing. `tests/test_server.py` and
  `tests/test_actions.py` add 20 hermetic tests (FastAPI TestClient, no socket).
- **`MasterSecretUnavailableError`**, **`RotateNotSupportedError`**,
  **`VaultImportError`** exception subclasses (all `VaultError`) for
  caller-friendly error handling.
- **`MasterSecretProvider.bootstrap_master_secret()`** — explicit
  create-if-missing hook for providers whose backing store supports it.
- **`StorageBackend.bulk_rewrite_active_secrets(rewrite_fn)`** —
  atomic multi-row re-encryption helper used by `rotate_dek` and the
  legacy migration.
- **`tests/test_audit_fixes.py`** — 11 new tests covering each P0/P1
  finding above (provider fail-closed, transaction wrappers, atomic
  rotation, keychain 0600, rotate-master-key pre-check, LinuxTPM temp
  file 0600).
- **`tests/test_cli.py`** — 4 new tests for stdin / `--value-file`
  value sources and the `cmd_get` zeroization-bypass warning.
- **`audit-v0.1.md`** — the full production-readiness audit (P0–P3
  findings, dependency map, security-boundary map, call graph, grading).
- **CLI parity.** `rgt-vault` now exposes `set`, `get`, `list`, `revoke`,
  `fingerprint`, `rotate {master,dek}`, `verify-audit`, `audit`, and
  `simulate` subcommands with a `--provider {keyring,platform}` selector
  (closes the "CLI parity" roadmap item). `--db` and `--policy` are global
  options. The default provider is `keyring` (Secret Service / Credential
  Manager) for local development convenience; production deployments
  should pass `--provider platform` to use the sealed TPM/DPAPI/Keychain
  backend.
- **`RGT_VAULT_DEBUG=1` env var** dumps a full Python traceback to stderr
  when the CLI catches an unexpected error, on top of the always-printed
  `<ExceptionType>: <message>` summary.
- **`tests/test_cli.py`** with 16 hermetic tests for every subcommand
  (uses a stub `KeyringProvider` so the test suite never touches the
  developer's real OS keyring).
- **`tests/test_decryption_errors.py`** (8 tests) enforcing that the public
  crypto and vault paths raise only `DecryptionError` /
  `ValidationError` / `ChecksumError` (all `VaultError` subclasses) for any
  failure mode -- never the raw `cryptography.exceptions.InvalidTag` or a
  bare `ValueError`, so callers can't distinguish "wrong key" from
  "tampered ciphertext" via the exception type.
- **`tests/test_migration_atomicity.py`** verifying that a failing
  migration file rolls back its bookkeeping row (the migration will be
  retried on next startup rather than silently skipped).
- **`tests/test_tpm_live.py`** with 4 hermetic-ish integration tests
  against a real `/dev/tpmrm0` (auto-skipped if the device is not
  readable). Covers seal/unseal round-trip, PCR-list persistence, full
  `VaultManager.set_secret` / `.execute` / `verify_audit_chain`, and
  `rotate_dek` through the TPM provider.

### Fixed

- **LinuxTPMProvider was non-functional on modern tpm2-tools.** Found by
  running the suite against a real `/dev/tpmrm0`. Three concrete bugs
  were blocking end-to-end use:
  1. `tpm2_createpolicy -l sha256:0,sha256:7` was rejected with
     `Failed to parse PCR string` -- the tool requires `+` as the
     separator between `<bank>:<pcr>` items.
  2. `tpm2_create` / `tpm2_load` with the legacy transient handle
     `0x40000001` (no explicit primary) failed with
     `tpm:handle(1):value is out of range or is not correct for the
     context`. Replaced with an explicit `tpm2_createprimary -C o -G rsa
     -c primary.ctx` then `tpm2_create -C primary.ctx ...`.
  3. `tpm2_unseal -p pcr:sha256:0,7` (the multi-PCR shorthand) failed
     with `policy check failed` even when the PCR values had not drifted.
     Switched to the explicit policy-session pattern:
     `tpm2_startauthsession --policy-session` -> `tpm2_policypcr -l
     sha256:0+sha256:7` -> `tpm2_unseal -p session:...`.
- **`-G aes` removed from `tpm2_create`.** Modern tpm2-tools refuses the
  `-G` + `-i` combination; the algorithm is inferred from the input
  payload.
- **`-T /dev/tpmrm0` removed from all tpm2 invocations.** The explicit
  TCTI form occasionally fails to instantiate when invoked via
  `subprocess.run`; tpm2-tools' built-in TCTI auto-discovery is more
  reliable.
- **PCR list is now persisted alongside the sealed blobs** as
  `<basename>.pcrs` so the unseal path can reconstruct the same policy
  the seal path used. Without this, any change to the provider's
  hardcoded PCR list would silently break previously-sealed blobs.

### Changed

- **`crypto.decrypt` is now a single, type-stable entry point.** It
  raises :class:`DecryptionError` (a `VaultError`) for *any* failure --
  truncated token, wrong AAD, wrong key, tampering -- and validates that
  the `dek` is exactly 32 bytes and the `aad` is bytes/bytearray. The
  internal `AES256GCMWrapper.unwrap` still raises `InvalidTag` (it's the
  low-level helper); the public path no longer leaks the underlying
  library's exception type to callers.
- **Storage `ChecksumError` is now a `VaultError` subclass.** Previously
  `StorageBackend.get_secret` raised a bare `ValueError` on checksum
  mismatch; now it raises `ChecksumError`, which the CLI / API surface
  can map to a single error category.
- **Migration runner is transactional.** Each migration's `executescript`
  + bookkeeping INSERT now run inside a `BEGIN` / `COMMIT` pair with a
  `ROLLBACK` on exception. A failed migration leaves the database in the
  same state as before the attempt (closes the "Migration atomicity"
  roadmap item).
- **`get_fingerprint` docstring** documents the deliberate decision to
  *not* policy-gate fingerprint reads (the ciphertext fingerprint leaks
  no plaintext) and *not* rate-limit them (per the "Audit log noise
  reduction" roadmap item).
- **`Unsupported DEK version` now raises `ValidationError`** instead of a
  bare `ValueError`, consistent with the other public-API error types.

### Removed

- The `PRAGMA foreign_keys=off` / `=on` directives embedded in
  migration `0002_namespace.sql` (P2-6).

## [0.1.0] — 2026-06-16

### Fixed
- **Default vault path crashed.** Platform providers return raw `bytes` while
  the KDF expected a `MasterSecret`; `VaultManager` now normalizes either form
  (`_normalize_master`). The default `VaultManager()` and the CLI now run.
- **`execute()` leaked a plaintext `str`.** Callbacks now receive the mutable
  `bytearray` the vault zeroizes, instead of an immutable `str` copy that
  lingered in memory. **Breaking:** callback signature is now `(bytearray)`.
- **Wheel installs shipped no migrations.** Added `package-data`/`MANIFEST.in`
  so `*.sql` migration files are included; `pip install .` now works (not only
  editable installs).
- **CLI `simulate` was broken** (missing `action` argument; always printed
  ALLOWED). It now evaluates correctly, prints the reason, and runs without a
  master-secret provider. Added `--action`.
- **Audit hash-chain write race.** Read-previous-hash and insert are now a
  single `BEGIN IMMEDIATE` transaction, serialized by a process lock, so
  concurrent writers cannot fork the chain.
- Replaced deprecated `datetime.utcnow()` with timezone-aware UTC.
- **`llm_guide.py` was a latent `SyntaxError`** — a nested `"` in an example
  terminated the guide string early. The module now imports.
- **`import_data` raised an unhandled `TypeError`** on non-list collections
  (e.g. `{"secrets": None}`), found by fuzzing; it now raises `ValueError`.

### Added
- `cross-vault import guard`: exports carry their `vault_id`; importing into a
  different vault is refused instead of silently producing undecryptable data.
- `MasterSecretProvider.rotate_secret()` in the base ABC (raises
  `NotImplementedError` for providers without automated rotation).
- Apache-2.0 `LICENSE`, `SECURITY.md` (threat model + disclosure),
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.gitignore`, issue/PR templates.
- `tests/conftest.py` with a keyring-free in-memory provider; new
  `tests/test_hardening.py` covering normalization, zeroization, audit-chain
  concurrency, and the cross-vault import guard.
- **CI/CD & supply chain:** GitHub Actions matrix (Ubuntu/macOS/Windows ×
  Python 3.9/3.11/3.12/3.13) running tests+coverage, ruff, mypy, bandit, a
  wheel build that asserts migrations are packaged, plus CodeQL, OpenSSF
  Scorecard, and Dependabot.
- **Property/fuzz tests** (`tests/test_fuzz.py`, Hypothesis) over `decrypt`,
  DEK unwrap, and `import_vault`.
- **Benchmarks** (`benchmarks/bench.py`) and a Performance table in the README.
- **Formal threat model** (`docs/threat-model.md`) and Mermaid architecture
  diagrams; `ROADMAP.md` and `release-checklist.md`.
- Tooling config in `pyproject.toml` (ruff/mypy/bandit/pytest/coverage) and a
  richer `[dev]` extra; project URLs.

### Changed
- Pinned dependencies (`cryptography>=44.0.0`, `keyring>=24`, `PyYAML>=6`);
  added project metadata, classifiers, and a `rgt-vault` console entry point.
- Documentation corrected to match the implementation: AES-256-GCM (not
  AES-128/Fernet), accurate rotation semantics, partial-zeroization and
  partial-rollback caveats, working quickstart and examples.
- Positioned the first release as **`v0.1.0` Security Preview** (not production)
  and removed any maturity overstatement.
- The legacy-migration test is now hermetic (mocks the keyring) so it no longer
  writes to the real OS credential store / requires it in CI.

### Removed
- Dead `refactor.py` (a no-op that leaked a hardcoded local path).
- Committed build/cache artifacts (`agent_vault.egg-info/`, `.pytest_cache/`).- **Local freeze signal (kill switch).** Touching `~/.config/rgt-vault/freeze` immediately blocks all secret access and capability execution.
- **Background FileWatcher (RGT-45).** A daemon thread now monitors the freeze kill switch and proactively wipes the DEK from memory upon detection.
- **SecureBuffer & AuditHook (RGT-112, RGT-33, RGT-44).** Refactored legacy secret migration to use mlock pinned memory (SecureBuffer) and defined the stable AuditHook abstract base class.
- **Audit Hooks & Redaction (RGT-114, RGT-28).** execute_capability is now wrapped in a strict policy enforcer, and LogRedactionHook strips all secrets from agent memory logs.
- **TTL-based Capability Leases (RGT-29).** ABAC policies now support a `ttl` field for execute grants, controlling the lifetime of the capability authorization.
- **MCP Server (RGT-27).** Added a Model Context Protocol (MCP) server that securely wraps VaultManager and exposes capabilities as LLM tools.
