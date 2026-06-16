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

- **Migration atomicity.** Wrap each migration file + its bookkeeping row in a
  single transaction; verify with `PRAGMA integrity_check`.
- **Automated rotation for platform providers.** DPAPI/TPM re-seal helpers
  invoked through `rotate_secret()`.
- **CLI parity.** `get`/`lease`/`list`/`rotate`/`audit verify` subcommands with a
  selectable provider (`--provider keyring|dpapi|tpm`).
- **Audit log noise reduction.** Separate storage-layer and policy-layer events;
  avoid logging debug reads (e.g. `get_fingerprint`).
- **CI.** GitHub Actions matrix (Linux/macOS/Windows × Python 3.9–3.12) running
  `pytest`, `ruff`, and a wheel-build smoke test.
- **Foreign keys / referential integrity** across `secrets`/`audit_logs`.

## Under consideration

- Pluggable storage backends (Postgres) for multi-process deployments.
- Optional envelope re-encryption to enable cross-vault backup restore.
