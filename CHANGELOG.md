# Changelog
All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-06-16

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

### Security (audit pass — see [AUDIT.md](AUDIT.md))

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
- **`AUDIT.md`** — the full production-readiness audit (P0–P3
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
  diagrams; `ROADMAP.md` and `RELEASE_CHECKLIST.md`.
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
- Committed build/cache artifacts (`agent_vault.egg-info/`, `.pytest_cache/`).