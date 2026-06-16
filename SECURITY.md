# Security Policy

`rgt-vault` is a local, encrypted secrets manager for AI agents. This document
states what it protects, what it explicitly does **not** protect, and how to
report a vulnerability. Please read the guarantees carefully — they are
deliberately conservative.

## Supported versions

`rgt-vault` is pre-1.0 (`0.x`). Only the latest released version receives
security fixes. APIs and on-disk formats may change between `0.x` releases.

## Threat assumptions

The security model assumes:

- The host operating system and the running Python process are **trusted** at
  the moment of use. A compromised OS, root/Administrator attacker, or memory
  scraper running in the same process can read secrets while they are in use.
- The OS-native secret store (Windows DPAPI, macOS Keychain, Linux TPM, or the
  `keyring` Secret Service) correctly protects the **master secret**.
- An attacker may obtain **offline copies** of the SQLite database
  (`vault.db`) and the wrapped-key file (`keychain.json`), e.g. from a backup
  or a stolen disk, but **not** the master secret.

## Security guarantees

Under the assumptions above:

- **Confidentiality at rest.** Secret values are encrypted with AES-256-GCM
  under a per-vault Data Encryption Key (DEK). The DEK is wrapped with a Key
  Encryption Key derived from the master secret via Argon2id + HKDF-SHA512. An
  attacker with `vault.db` + `keychain.json` but without the master secret
  cannot recover plaintext.
- **Integrity / anti-tampering.** Each secret is bound by AES-GCM Associated
  Data (`vault_id:namespace:name`). Editing the database, swapping ciphertexts
  between entries, or moving a `keychain.json` to a different vault causes
  authenticated decryption to fail.
- **Authorization.** A default-deny ABAC engine gates every read/write; an
  explicit `deny` rule always overrides any `allow`.
- **Tamper-evident audit.** Operations are recorded in a SHA-256 hash-chained
  audit log; `verify_audit_chain()` detects insertion, deletion, or edits.
- **Forward protection on master-key rotation.** Rotating the master key
  re-wraps the DEK under a new key and increments the key epoch, invalidating
  the previously wrapped key.

## Non-goals / what is NOT protected

- **Not an HSM.** Keys exist in process memory during use. A live-process
  compromise, debugger, or core dump can expose them.
- **Zeroization is best-effort and partial.** The vault wipes the `bytearray`
  it hands to `lease_secret`/`execute`. If your callback copies the secret into
  an immutable object (`bytes(buf)`, `buf.decode()`, logging it, etc.), that
  copy is **outside** the vault's control and will not be wiped. Python's
  memory model cannot guarantee secrets are unrecoverable.
- **Backup rollback is only partially mitigated.** The key epoch is stored in
  the database. Restoring a *matched* old pair of `vault.db` **and**
  `keychain.json` (the realistic backup-rollback scenario) is **not** detected,
  because their epochs agree. Epoch checking only prevents mixing a current
  database with a stale keychain (or vice versa). For true rollback resistance,
  anchor the epoch in an append-only/monotonic store outside the database.
- **No protection against a malicious operator** who controls the policy file,
  the master secret, or the audit database.
- **Cross-host portability of backups is constrained.** Exports are bound to a
  `vault_id` and DEK; they can only be restored into the same vault (same
  `keychain.json`). Import refuses payloads from a different vault.

## Reporting a vulnerability

Please report security issues **privately**. Do not open a public issue for
undisclosed vulnerabilities.

- **Email:** REDACTED
- Include: affected version/commit, a description, reproduction steps or a
  proof-of-concept, and impact.
- **Response targets:** acknowledgement within 5 business days; a remediation
  plan or assessment within 30 days. Coordinated disclosure is preferred —
  please allow a fix to ship before public discussion.

Thank you for helping keep `rgt-vault` users safe.
