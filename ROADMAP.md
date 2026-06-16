# Roadmap

Status of known gaps and planned work. Items reference findings from the
production-readiness audit.

## Known limitations (documented, not yet fixed)

- **Full-backup rollback (SECURITY non-goal).** The key epoch lives in the
  rollback-able database, so restoring a matched old `vault.db` + `keychain.json`
  pair is not detected. *Plan:* anchor the epoch in an append-only or
  hardware-monotonic store (e.g. TPM NV counter) outside the DB.
- **Partial zeroization.** Python cannot guarantee plaintext copies (`str`,
  `bytes`) are unrecoverable. *Plan:* document patterns; investigate
  `memoryview`-only callback ergonomics.
- **Master secret in memory.** `MasterSecret` wraps immutable `bytes` and cannot
  be wiped. *Plan:* evaluate a mutable-buffer master representation.

## Planned

- **Local HTTP server for LLM/agent clients.** ~~A loopback FastAPI surface with
  bearer-token auth and server-side actions so non-Python clients can use the
  vault without plaintext crossing the wire.~~ **DONE** in `rgt_vault/server/`
  (`rgt-vault serve`); covered by `tests/test_server.py` and
  `tests/test_actions.py`.
- **Migration atomicity.** ~~Wrap each migration file + its bookkeeping row in a
  single transaction; verify with `PRAGMA integrity_check`.~~ **DONE** in
  `rgt_vault/storage/sqlite.py::_apply_migrations`; covered by
  `tests/test_migration_atomicity.py`.
- **Automated rotation for platform providers.** DPAPI/TPM re-seal helpers
  invoked through `rotate_secret()`. (The Linux TPM provider now uses an
  explicit `tpm2_createprimary` flow that *can* be re-sealed by re-running
  `seal_master_secret` with a new secret and swapping the .priv/.pub
  files; this is the building block but the high-level API is still TODO.)
- **CLI parity.** ~~`get`/`lease`/`list`/`rotate`/`audit verify` subcommands with a
  selectable provider (`--provider keyring|dpapi|tpm`).~~ **DONE** in
  `rgt_vault/cli.py`; covered by `tests/test_cli.py`.
- **Linux TPM live integration tests** (previously only mocked). **DONE**
  in `tests/test_tpm_live.py`; auto-skipped when `/dev/tpmrm0` is
  unreadable.
- **Audit log noise reduction.** Separate storage-layer and policy-layer events;
  avoid logging debug reads (e.g. `get_fingerprint`).
- **CI.** GitHub Actions matrix (Linux/macOS/Windows × Python 3.9–3.12) running
  `pytest`, `ruff`, and a wheel-build smoke test.
- **Foreign keys / referential integrity** across `secrets`/`audit_logs`.

## Under consideration

- Pluggable storage backends (Postgres) for multi-process deployments.
- Optional envelope re-encryption to enable cross-vault backup restore.
- **Egress-proxy `/use` model.** Today `/use` returns the action result over
  authenticated loopback; a future mode would make the vault perform the
  outbound call itself for arbitrary registered upstreams (request templating),
  keeping plaintext off localhost entirely. Per-agent tokens (rather than one
  shared token) would land alongside it.
