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
| Attacker brute-forces capability tokens | Per-agent failed-verification cap (100/hr) locks the agent out; `CAPABILITY_DENIED` audit event (RGT-277) |
| Attacker points a provider/client at a cloud-metadata URL | SSRF guard rejects link-local/metadata IPs (169.254.0.0/16, fe80::/10); non-loopback needs explicit opt-in (RGT-109 Python, RGT-197 Go) |
| Attacker with root on the host | Game over (out of scope) |

## Operational cryptographic limits

- **DEK auto-rotation (RGT-219).** The Data Encryption Key rotates
  automatically once it has performed `DEK_MAX_ENCRYPTIONS` (100M) encryptions
  or covered `DEK_MAX_BYTES` (512 GiB), both set far below the AES-256-GCM
  safety bounds in NIST SP 800-38D (2^32 encryptions / 2^39−256 bytes under a
  random-96-bit-nonce key). Counters are durable (persisted in the `metadata`
  table) and survive process restarts. They are tallied on the ongoing write
  path (`set_secret`) only; the one-time legacy-migration bulk rewrite is
  deliberately **not** tallied, because it runs inside its own open SQLite
  transaction and calling back into the counter store from there would
  contend for the write lock. See the comments in `python/vault.py`
  (`_record_dek_usage_and_maybe_rotate`, `rotate_dek`, `_migrate_legacy_secrets`).

- **SSRF guard (RGT-109 / RGT-197).** Outbound HTTP (Ollama provider in
  Python, the Go server/MCP/TUI clients) rejects link-local and
  cloud-metadata addresses unconditionally, and any non-loopback address
  unless remote access is explicitly opted in (`allow_remote` / `allowRemote`).
  The Go guard enforces this at the dialer (`net.Dialer.Control`, post-DNS,
  per-connection) and so also closes the DNS-rebinding window; the Python
  guard is a resolve-then-connect check with a documented residual TOCTOU gap
  accepted for its threat model (a locally-configured host, not per-request
  user URLs).
