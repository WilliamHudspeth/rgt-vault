# ADR-0001: Key Hierarchy & Wrapping Strategy

- Status: proposed
- Date: 2026-06-17
- Deciders: Security Champion
- Consulted: Crypto Maintainer, Core Maintainer
- Informed: All engineers

## Context and Problem Statement

The rgt-vault project must manage multiple keys across multiple scopes:

- A **master key** that protects everything else (KEK).
- **Per-vault data encryption keys** (DEKs) that protect individual vault contents.
- **Per-agent signing keys** for capability tokens.
- **Audit-chain keys** for the append-only hash-chain.

The forces in play:

1. Rotating a single master key without re-encrypting all DEKs is operationally essential (rotation should not require rewriting petabytes of stored data).
2. A compromised vault should not leak other vaults (per-vault key isolation).
3. Lost keys cannot be recovered — the system must be designed so loss is detectable and bounded.
4. Key material must never appear in logs, audit rows, or error messages.

## Considered Options

1. **Single master key encrypts everything directly.**
2. **Enveloped encryption: master KEK wraps per-vault DEKs; DEKs encrypt data.**
3. **HSM-backed root key with derived subkeys** (HSM wraps DEKs, derived from a master seed).

## Decision Outcome

Chosen option: **2 — Enveloped encryption (master KEK + per-vault DEKs).**

Rationale:

- Rotation: rotating the master KEK only re-wraps the (small) DEK set, not the (large) encrypted data.
- Isolation: a per-vault DEK compromise only affects that vault.
- Audit-chain integrity: the audit-chain key is a separate DEK with no wrapping (loss of audit key does not lose the chain — it loses the ability to verify; the chain itself is still inspectable).
- Operational simplicity: no HSM dependency; pure software cryptography via libsodium / PyNaCl.

### Consequences

- Good, because rotation is cheap (re-wrap, not re-encrypt).
- Good, because per-vault isolation limits blast radius.
- Good, because no HSM procurement or key ceremony required for v1.0.0.
- Bad, because the master KEK becomes a single point of compromise — loss of the KEK = loss of all DEKs = loss of all data.
- Bad, because we depend on libsodium's wrapped-key format and must keep it patched.
- Neutral, because we still need a backup/recovery path for the master KEK.

### Confirmation

This decision is correct if:

- The `python3 scripts/program/release_gate.py --milestone v0.3.0` security gate passes (no critical crypto issues).
- A simulated rotation (`tests/test_key_rotation.py`) re-wraps the DEK set in under N seconds.
- The master KEK is never observed outside of an enclave / specific decrypt path (verified by `bandit` and the crypto-review-checklist).

## Pros and Cons of the Options

### Option 1: Single master key, direct encryption

- Good, because simpler key management code.
- Bad, because rotation requires re-encrypting every vault.
- Bad, because one compromise = total loss.

### Option 2: Enveloped encryption (chosen)

See "Decision Outcome."

### Option 3: HSM-backed root key with derived subkeys

- Good, because the root key never leaves hardware.
- Bad, because HSM procurement, key ceremony, and operational cost are out of scope for v1.0.0.
- Bad, because HSM availability becomes a deployment dependency.

## References

- NIST SP 800-57 Part 1 Rev. 5 (Recommendation for Key Management)
- NIST SP 800-38F (Key Wrapping)
- libsodium `crypto_secretbox` / `crypto_box` documentation
- OWASP Cryptographic Storage Cheat Sheet
- ADR-0003 (audit-chain uses an independent key derived via HKDF from the audit DEK)
