# Threat Model

This document states, in concrete terms, what `rgt-vault` defends against and
what it does not. It complements [SECURITY.md](../SECURITY.md), which holds the
formal guarantees and the disclosure process. When the two disagree, SECURITY.md
governs.

## Assets

1. **Secret plaintext** (API keys, tokens, passwords) — highest value.
2. **Data Encryption Key (DEK)** — decrypts all secrets; in memory only.
3. **Master secret** — root of trust; held by the OS-native store.
4. **Audit log integrity** — evidence of access.

## Trust boundaries

```
                 untrusted                 |            trusted
   ┌───────────────────────────────┐       |   ┌───────────────────────────┐
   │ backups, stolen disk, git repo │       |   │ live process memory        │
   │ vault.db + keychain.json       │  ───► |   │ DEK, leased plaintext      │
   └───────────────────────────────┘       |   └───────────────────────────┘
                                            |   ┌───────────────────────────┐
                                            |   │ OS secret store (master)   │
                                            |   └───────────────────────────┘
```

The line moves the moment an attacker gains code execution in the process or
root on the host — everything to the right then becomes readable.

## Protects against

- **Git leaks / committed databases.** Committing `vault.db` exposes only
  AES-256-GCM ciphertext; without the master secret it is not decryptable.
  `.gitignore` also excludes vault runtime files by default.
- **Stolen backups / lost disks.** Same as above: ciphertext at rest is bound
  to a DEK that is itself wrapped under an Argon2id-stretched master key.
- **Ciphertext tampering / swapping.** AAD (`vault_id:namespace:name`) makes
  edited or swapped ciphertext fail authentication.
- **Prompt injection that tries to exfiltrate a specific secret.** ABAC limits
  which agent/purpose can read which namespace; honeytokens turn probing into a
  loud, logged `HONEYTOKEN_TRIGGERED` event; rate limits cap mass extraction.
- **Rogue or buggy agents.** Default-deny authorization; explicit `deny` wins;
  every access is recorded in a tamper-evident, hash-chained audit log.
- **Accidental disclosure.** Secrets are leased in a buffer the vault wipes;
  the API never returns plaintext to general callers, and the DB stores only
  ciphertext.
- **Wrapped-key / metadata rollback mismatch.** A stale `keychain.json` paired
  with a current DB (or vice versa) fails closed via the key epoch.

## Partially protects against

- **Local malware / compromised user account.** If the attacker can run code as
  the user, they can ask the OS store for the master secret and read secrets in
  use. Honeytokens, rate limits, and the audit log raise the odds of detection
  but do not prevent access.
- **Memory disclosure of *copies*.** The vault wipes its own buffer; plaintext
  the caller copies into `str`/`bytes` is not wiped and may be recoverable from
  a dump until GC.
- **Full-backup rollback.** Restoring a matched old `vault.db` + `keychain.json`
  pair is not detected (the epoch lives in the rolled-back DB).

## Does not protect against

- **Root / Administrator compromise** of the host.
- **Kernel or hypervisor compromise.**
- **Memory scraping by a privileged attacker** (debugger, core dump, ptrace).
- **TPM/DPAPI/Keychain extraction attacks** against the OS store itself.
- **A malicious operator** who controls the policy file, the master secret, or
  the audit database.
- **Side channels** (timing, power, cache) against the underlying primitives.

## Attacker scenarios considered

| Scenario | Outcome |
|---|---|
| Attacker clones the repo with a committed `vault.db` | Sees ciphertext only; cannot decrypt |
| Attacker restores only an old `keychain.json` | Fails closed (epoch mismatch) |
| Attacker restores matched old DB + keychain | **Not detected** (documented gap) |
| Compromised agent reads a honeytoken | Blocked + critical audit event |
| Compromised agent mass-reads secrets | Throttled by rate limiter + logged |
| Attacker edits a ciphertext row | GCM auth fails on read |
| Attacker tampers with an audit row | `verify_audit_chain()` returns False |
| Attacker with root on the host | Game over (out of scope) |
