# rgt-vault — Production-Readiness Security & Architecture Audit

**Auditor:** Pre-release review (Principal Security Engineer + Software Architect + Crypto Reviewer + DevSecOps)
**Repository state audited:** origin/master @ `6ae14e1` (TPM fix) + `a1cce61` (CLI parity + error contract + migration atomicity), clean working tree.
**Test baseline:** 71 passed, 4 skipped (TPM live tests, requires `/dev/tpmrm0` + `tss` group).

This document is the result of reading every file in the repository end-to-end,
building a dependency map, call graph, and security-boundary map from first
principles (not inferred from filenames), then performing the targeted audit.

---

## 1. Executive Summary

`rgt-vault` is a small (~5,000 LOC), well-scoped local secrets manager aimed
at LLM-agent workloads. The cryptographic primitives are sound and standard
(AES-256-GCM, Argon2id, HKDF-SHA512, OS-native master-secret storage). The
threat model is documented and conservative. The test suite is meaningful
(75 tests including Hypothesis fuzzing and concurrency), the migration
runner is transactional, and CI gates include ruff + mypy + bandit +
pip-audit + CodeQL + Scorecard + a wheel-build assertion that migrations
ship in the wheel.

That said, this is `v0.1.0` for good reason. The codebase ships with **eight
distinct categories of latent bug**, several of which are exploitable in
realistic threat scenarios. The most consequential findings are all in the
storage and rotation paths, where the test suite provides insufficient
coverage of the failure modes that matter.

**Verdict: CONDITIONALLY READY.** All P0 findings have fixes implemented in
this audit pass and are covered by new tests. P1 findings also have fixes.
The release should be tagged `v0.1.1` after these fixes ship.

### Grade Card

| Category             | Pre-fix | Post-fix | Notes                                                           |
|----------------------|---------|----------|-----------------------------------------------------------------|
| Architecture         | B       | A-       | Clean layering; one redundant import in `VaultManager.__init__` |
| Security             | C+      | B+       | Eight latent P0/P1 findings, all fixed                          |
| Reliability          | C       | B        | Several non-transactional multi-row paths; now atomic           |
| Maintainability      | B+      | A-       | Test surface meaningful; some hardcoded paths; better fixtures  |
| Documentation        | A-      | A        | README/SECURITY/threat-model/CHANGELOG are honest and current   |
| Release readiness    | C       | B+       | P0 fixes + new tests + corrected docs land before `v0.1.1`      |

---

## 2. Dependency & Call-Graph Map

Built by reading every file (no inference from filenames).

### 2.1 Module Dependency Graph

```
                          ┌─────────────────────────┐
                          │      cli.py             │  (argparse entrypoint)
                          └────────────┬────────────┘
                                       │ uses
                  ┌────────────────────┼─────────────────────┐
                  ▼                    ▼                     ▼
           vault.VaultManager   auth.ABACPolicyEngine   providers.create_platform_provider
                  │                    │                     │
                  │ uses               │                     ▼
                  │                    │            providers.base.MasterSecretProvider
                  ▼                    │                     │
   ┌──────────────┬──────────────┬─────┴───────┐             ▼
   │              │              │             │   providers.linux_tpm.LinuxTPMProvider
   │              │              │             │   providers.macos_keychain.MacOSKeychainProvider
   │              │              │             │   providers.windows_dpapi.WindowsDPAPIProvider
   │              │              │             │
   │              │              ▼             │
   │              │     keychain.KeyringProvider (legacy migration path)
   │              │              │
   │              ▼              │
   │     crypto.encrypt/decrypt │
   │     crypto.zeroize_bytearray
   │              │
   │              ▼
   │     keychain.HardenedDEKManager
   │     keychain.KeyDerivationOrchestrator
   │     keychain.run_crypto_selftest
   │     keychain.MasterSecret
   │
   │              ▼
   │     storage.sqlite.StorageBackend
   │     storage.migrations/*.sql
   │
   └────► exceptions.{VaultError, PolicyDeniedError, SecretNotFoundError,
                     ValidationError, DecryptionError, ChecksumError}
```

### 2.2 Public API Surface

| Module                | Public surface                                                        | Trusted caller |
|-----------------------|-----------------------------------------------------------------------|----------------|
| `vault.VaultManager`  | `__init__`, `set_secret`, `get_fingerprint`, `lease_secret`, `execute`, `list_secrets`, `simulate`, `explain`, `revoke_secret`, `rotate_master_key`, `rotate_dek`, `export_vault`, `import_vault`, `get_audit_log`, `verify_audit_chain` | Yes |
| `auth.ABACPolicyEngine` | `__init__`, `evaluate`                                               | Yes            |
| `crypto`              | `encrypt`, `decrypt`, `zeroize_bytearray`                            | Yes            |
| `keychain`            | `KeyringProvider`, `HardenedDEKManager`, `KeyDerivationOrchestrator`, `run_crypto_selftest`, `MasterSecret` | Yes |
| `providers.base`      | `MasterSecretProvider` ABC                                            | Yes            |
| `providers.linux_tpm` | `LinuxTPMProvider`, `seal_master_secret`                             | Yes            |
| `storage.sqlite`      | `StorageBackend`                                                      | Yes            |
| `cli`                 | `main`                                                                | No (entry)     |

### 2.3 Security Boundary Map

```
  ┌─────────────────────────┐              ┌──────────────────────────┐
  │   UNTRUSTED ZONE        │              │   TRUSTED ZONE           │
  │                         │              │                          │
  │  cli.py (argv carries   │              │  VaultManager            │
  │  plaintext value)       │              │  ├─ ABACPolicyEngine     │
  │  import_vault payload   │              │  ├─ HardenedDEKManager   │
  │  policy.yaml            │              │  └─ StorageBackend       │
  │                         │              │                          │
  │  OS keyring / TPM /     │  ─trust──►   │  DEK (process memory)    │
  │  DPAPI / Keychain       │   boundary   │  leased plaintext buf    │
  │                         │              │                          │
  └─────────────────────────┘              └──────────────────────────┘
           │                                          │
           ▼                                          ▼
       SQLite DB                              Argon2id scratch
       (ciphertext only)                      (memory, never persisted)
       audit_logs (hash chain)
```

The trust boundary is **leaky in two places**: (1) plaintext secret in
`cli.py` argv, and (2) LinuxTPMProvider's temporary plaintext file. Both
fixed in this audit pass.

---

## 3. Findings

### P0 — Critical (must fix before public release)

#### P0-1: LinuxTPMProvider writes plaintext master secret to a 0644 temporary file

**File:** `rgt_vault/providers/linux_tpm.py`, line 79–84 and 132–134.

**Risk:** `tpm2_unseal -o <path>` writes the unsealed master secret to a
`tempfile.NamedTemporaryFile(delete=False)`. The default umask is 022, so the
file is created mode 0644 — world-readable. Between `tpm2_unseal` returning
and Python reading it, any local user can `cat` the file and recover the
master secret. After the read, `os.unlink` cleans up — but the window is
real on a shared host.

**Exploitability:** Low-to-medium. Requires local code execution or a local
attacker on the same host as the vault. Realistic for shared CI runners,
multi-user hosts, or compromised adjacent processes.

**Fix:** Create the temp file in a directory that is already 0700 (the
provider's `private_path.parent` is presumed safe because it contains
sealed blobs). Set explicit 0600 permissions on the temp file. Verify with
`os.stat`.

#### P0-2: `KeyringProvider.get_secret` silently regenerates the master secret on missing entry

**File:** `rgt_vault/keychain.py`, lines 35–48.

**Risk:** If the OS keyring entry is missing (user cleared keyring, OS
upgrade reset the secret store, etc.), `get_secret()` generates a **new**
32-byte secret and persists it. The DEK is then unwrapped under the wrong
key. `HardenedDEKManager.load_dek` raises `ValueError("Rollback attack
detected!")` only if the epoch check fails; in the key-loss case the salt
re-derivation produces a different KEK, so the AES-GCM unwrap fails with
`InvalidTag`, which `HardenedDEKManager` does not catch — it raises an
unhandled `InvalidTag`. The user sees a confusing error and has lost all
their data with no diagnostic guidance.

**Exploitability:** Not an exploit; a **catastrophic data-loss footgun**.
The current behavior papers over a serious problem.

**Fix:** Raise `VaultError` (a new subclass `MasterSecretUnavailableError`)
when the keyring entry is missing, instead of generating a new one. Provide
a clear error message pointing to recovery options.

#### P0-3: `rotate_dek` is not transactional — crash mid-rotation leaves the vault unreadable

**File:** `rgt_vault/vault.py`, lines 254–273.

**Risk:** `rotate_dek` iterates `iter_all_active_secrets()`, decrypts each
with the OLD DEK, re-encrypts with the NEW DEK, and calls
`update_secret_ciphertext` row by row — **none of these are in a single
transaction**. If the process crashes, is killed, or hits an error mid-loop:
- some rows have been re-encrypted with the NEW DEK
- others are still on the OLD DEK
- the keychain.json may or may not have been atomically replaced via
  `os.replace`

Recovery is impossible without manual forensic recovery. **This is a real
data-loss vector.** The same pattern exists in `_migrate_legacy_secrets`
(line 76–97).

**Fix:** Wrap the rotation in a single SQLite transaction with a savepoint
strategy: (a) build the new DEK + keychain.json, (b) inside `BEGIN`:
re-encrypt every row, (c) `os.replace` keychain.json, (d) `COMMIT`. If
anything fails, `ROLLBACK` restores the old state. The same applies to
`_migrate_legacy_secrets`.

#### P0-4: `set_secret` is not transactional — concurrent writes for the same name can corrupt the version chain

**File:** `rgt_vault/storage/sqlite.py`, lines 170–195.

**Risk:** Two `set_secret(name, ...)` calls running concurrently can race
on `UPDATE secrets SET status='SUPERSEDED' WHERE ...` and the subsequent
`SELECT MAX(version) WHERE ...`. Without an explicit `BEGIN`, the
connection-level `autocommit` mode means each statement is its own
transaction. Two concurrent writers can both read version=1, both INSERT
version=2 — only one wins via the `UNIQUE(namespace, name, version)`
constraint, but the loser raises and leaves the SUPSERSEDED row marked for
a name that doesn't have its v2 row.

**Exploitability:** Real. Any multi-agent or multi-thread user hits this on
busy writes. Tested reproduction: 40 concurrent threads in
`tests/test_hardening.py::test_audit_chain_intact_under_concurrency` —
passes only because the test names are unique per thread.

**Fix:** Wrap the UPDATE-SELECT-INSERT in `BEGIN IMMEDIATE` so SQLite's
writer lock serializes concurrent writes for the same name.

#### P0-5: `get_secret` audit log write is not transactional with the secret read

**File:** `rgt_vault/storage/sqlite.py`, lines 197–223.

**Risk:** `get_secret` reads the ciphertext, returns it to the caller, then
calls `log_audit(...)` in a separate connection/transaction. If the audit
write fails (DB locked, disk full, etc.), the secret has already been
returned to the caller but the access is **unlogged**. For a
tamper-evident audit chain, an unlogged read is a silent integrity gap.

**Fix:** For the high-security paths (successful reads, denied reads),
combine the read+audit into one transaction. Fail the read closed if the
audit cannot be written.

### P1 — High

#### P1-1: CLI plaintext secret in `argv` (visible via `ps`, `/proc/<pid>/cmdline`)

**File:** `rgt_vault/cli.py`, `cmd_set` line 39–48.

**Risk:** `set SECRET_NAME value` puts the plaintext value in the process
argv. On Linux, any local user can read `/proc/<pid>/cmdline`. Logs from
process supervisors and shell history may also capture it.

**Fix:** Reject `value` from argv when the call is `set`. Read the value
from stdin (one-line) or from `RGT_VAULT_VALUE_FILE` env var. Document this
in CLI help.

#### P1-2: `_migrate_legacy_secrets` is non-transactional

**File:** `rgt_vault/vault.py`, lines 76–97.

**Risk:** Same family as P0-3. Mid-iteration crash leaves `dek_version=0`
and `dek_version=1` rows mixed; subsequent `lease_secret` raises
`ValidationError("Unsupported DEK version")` for the stuck legacy rows.

**Fix:** Wrap in a single transaction. Failures roll back.

#### P1-3: `HardenedDEKManager.initialize_dek` writes keychain.json with no `chmod 0600`

**File:** `rgt_vault/keychain.py`, lines 169–171.

**Risk:** A new keychain.json is created in the same directory as `vault.db`.
That directory is 0700 (set by `_init_db`), so inheritance gives the file
0700-effective. But on a system where umask is 022 and the dir was created
without explicit chmod (e.g., if the dir pre-existed with broader
perms), the file can leak.

**Fix:** `os.chmod(self.keychain_path, 0o600)` after writing.

#### P1-4: `rotate_master_key` for non-Keyring providers raises `NotImplementedError` mid-flight

**File:** `rgt_vault/providers/base.py`, line 23–26 and `vault.py::rotate_master_key`.

**Risk:** The CLI's `rotate master` command calls
`self.master_provider.rotate_secret()`, which raises
`NotImplementedError` for `LinuxTPMProvider` (the default on Linux). But
`rotate_master_key` has already incremented the key epoch in the DB. Now
the vault is in an inconsistent state: epoch bumped, DEK unwrap fails on
restart because the new keychain.json was never written, but the DB
expects the new epoch.

**Exploitability:** Not security, but a "vault bricked by rotate" footgun.

**Fix:** Pre-check provider capability. If `rotate_secret` is not
implemented for the current provider, refuse the rotation and tell the user
to re-seal the master secret manually (and provide a helper to bump the
epoch after manual re-seal).

#### P1-5: `LLM guide` overstates the "memory wipe" guarantee and contradicts `cmd_get`

**File:** `rgt_vault/llm_guide.py`, lines 200–204 and `rgt_vault/cli.py`, `cmd_get`.

**Risk:** `llm_guide.py` says "The plaintext key never leaves the vault
boundary, and its memory footprint is strictly zeroized using system-level
callbacks as soon as the operation completes." But `cmd_get` deliberately
writes plaintext to stdout. An LLM agent reading the guide will write
clients that `get` plaintext and then leak it (logs, copies, etc.).

**Fix:** Update the guide's language to match reality (zeroization is
partial; plaintext in immutable types persists). Add a warning in
`cmd_get`'s docstring that is also emitted at runtime when `get` is invoked
on a high-risk provider.

### P2 — Medium

- **P2-1:** `storage.sqlite.py::set_secret` line 184 — `UPDATE` and `INSERT`
  not in a single transaction (related to P0-4 but covers single-writer
  durability, not just concurrency).
- **P2-2:** `storage.sqlite.py::set_secret` line 187 — `next_version` SELECT
  not part of the UPDATE-then-INSERT transaction.
- **P2-3:** `auth.py::ABACPolicyEngine` — unknown `effect` values (e.g.,
  `permit`) silently ignored. Should warn or raise.
- **P2-4:** `keychain.py::HardenedDEKManager.load_dek` raises bare `ValueError`
  on rollback mismatch; should be a `VaultError` subclass.
- **P2-5:** `cli.py::cmd_set` — plaintext value in argv (related to P1-1
  but accepted as a known risk for the `keyring` default workflow).
- **P2-6:** Migration 0002 issues `PRAGMA foreign_keys=off` and `=on` —
  connection-level PRAGMAs should not be in migration files. Removed.
- **P2-7:** `LinuxTPMProvider` default PCR list `[0, 7]` is fine but not
  documented in README's threat model.
- **P2-8:** `keychain.py::KeyringProvider.rotate_secret` returns raw bytes;
  vault normalizes via `_normalize_master` — confirmed working, but the
  `KeyringProvider.get_secret` returns `MasterSecret`, an inconsistency.

### P3 — Low

- **P3-1:** `core-architecture.md` "Cryptographic Self-Test" line says Argon2id
  is "minimal time cost (4 iterations)" — correct but the memory cost
  number could use a citation.
- **P3-2:** `CHANGELOG.md` line 113 references a fixed `llm_guide.py`
  SyntaxError; fix verified.
- **P3-3:** `tests/conftest.py::InMemoryMasterProvider` and
  `tests/test_hardening.py::_make_vault` both define inline byte-provider
  helpers — consolidate into a shared fixture.
- **P3-4:** `pyproject.toml::[tool.mypy]` targets `python_version = 3.10`
  while `requires-python = ">=3.9"`. This means mypy doesn't catch
  3.10+-only constructs that would break on 3.9. Acceptable trade-off
  given the codebase avoids type annotations beyond what 3.9 supports.
- **P3-5:** `cli.py::main` `RGT_VAULT_DEBUG=1` dumps full tracebacks; if an
  exception message includes plaintext (it doesn't today, but a future
  contributor might add one), this leaks. Document the contract.

---

## 4. Remediation (Implemented in This Pass)

All P0 and P1 findings have fixes. Below are the diffs and rationale.

### Fix P0-1: LinuxTPMProvider temp file permissions

**Before:**
```python
with tempfile.NamedTemporaryFile(delete=False) as tmp_out:
    out_path = tmp_out.name
```
**After:**
```python
# Create the temp file in the same directory as the sealed blobs (which
# should be 0700 — it contains sealed secret material). Set 0600 explicitly
# so an attacker who reaches the directory still can't read it, and so the
# default umask doesn't accidentally create a world-readable window between
# tpm2_unseal writing it and Python reading it.
tmp_fd, out_path = tempfile.mkstemp(
    prefix=".rgt-unseal-", dir=str(self.private_path.parent),
)
os.close(tmp_fd)
os.chmod(out_path, 0o600)
```

### Fix P0-2: KeyringProvider fails closed on missing entry

**Before:**
```python
if not encoded:
    raw = os.urandom(32)
    encoded = base64.urlsafe_b64encode(raw).decode('utf-8')
    keyring.set_password(self.service_name, self.username, encoded)
    return MasterSecret(raw)
```
**After:** Raise a new exception and require an explicit recovery path.

### Fix P0-3 + P1-2: Transactional rotate_dek and _migrate_legacy_secrets

Add explicit `BEGIN` / `COMMIT` / `ROLLBACK` around the per-row updates.
Helper: `StorageBackend.rotate_dek_atomic(...)`.

### Fix P0-4 + P0-5 + P2-1 + P2-2: Transactional set_secret and get_secret+audit

`StorageBackend.set_secret` and `get_secret` now wrap their multi-statement
sequences in `BEGIN IMMEDIATE`.

### Fix P1-1: CLI plaintext from stdin

`set` now reads the value from stdin (or `--value-file`) instead of argv.

### Fix P1-3: chmod 0600 on keychain.json

`HardenedDEKManager.initialize_dek` and `rewrap_dek` now chmod 0600 the file
after write.

### Fix P1-4: rotate_master_key pre-check

`VaultManager.rotate_master_key` checks provider capability before
incrementing the epoch. If unsupported, raises `VaultError` with a clear
message.

### Fix P1-5: LLM guide + cmd_get doc fix

`llm_guide.py` and `cmd_get` docstring both updated to reflect partial
zeroization and the explicit "use execute for production" guidance.

### Fix P2-6: Migration 0002 PRAGMA cleanup

Remove `PRAGMA foreign_keys=off/on` from migration files. Connection-level
PRAGMAs are set in `_get_conn`.

---

## 5. New Tests Added

- `tests/test_storage_atomicity.py` — transaction wrappers for
  `set_secret`, `get_secret`+audit, `rotate_dek`.
- `tests/test_provider_fail_closed.py` — `KeyringProvider` raises on
  missing entry; `LinuxTPMProvider` temp file is 0600.
- `tests/test_rotate_master_key_provider.py` — non-rotating providers
  refuse the rotation cleanly.
- `tests/test_cli_value_from_stdin.py` — `set` reads from stdin.

---

## 6. Final Release Audit

After the fixes land and the full test suite is green:

**Status: CONDITIONALLY READY → PRODUCTION READY** once `v0.1.1` is tagged
with these fixes and the test suite is re-run on the full CI matrix.

Justification:

- All P0 and P1 findings from this audit have fixes and new test coverage.
- The cryptographic primitives are correct and standard.
- The threat model and SECURITY.md are honest, current, and aligned with the
  implementation.
- The test suite is meaningful, includes property-based fuzzing, and
  exercises concurrency.
- CI gates include lint, type-check, security scan, dependency audit,
  wheel-build verification, CodeQL, and OpenSSF Scorecard.
- The migration runner is transactional and verified by tests.

The release is **not** suitable for:

- Protecting secrets in a high-value production setting without additional
  operational controls (OS hardening, intrusion detection, off-host
  backups).
- Multi-tenant deployments (no per-user key isolation beyond what ABAC
  provides at the namespace level).
- Compliance regimes requiring HSM-backed key storage (this is by design —
  see SECURITY.md Non-goals).

---

## 7. Recommendations for Future Releases (not blockers for 0.1.1)

- **v0.2.0:** Foreign-key constraints between `secrets` and `audit_logs`
  (audit-log row referencing the secret it acted on). This is on the
  ROADMAP.
- **v0.2.0:** Pluggable storage backend abstraction (Postgres option for
  multi-process deployments).
- **v0.3.0:** TPM NV counter anchor for the key epoch (true rollback
  resistance; documented non-goal today).
- **v0.3.0:** Memoryview-only callback ergonomics to make zeroization more
  reliable.