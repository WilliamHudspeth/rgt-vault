# Cryptography Review Checklist

Required for any ticket with the `comp:crypto` component label, or any PR that touches `vault/crypto/`, key-derivation code, signature verification code, or the key hierarchy.

This is the highest-risk area in the project. Use this in conjunction with `security-review-checklist.md` and the project ADR for crypto design (`docs/adr/ADR-0001-key-hierarchy.md`).

## Primitives & Design

- [ ] **No custom cryptography** — primitives come from audited libraries only (libsodium / PyNaCl / `cryptography` package). No hand-rolled ciphers, hash constructions, MACs, or KDFs.
- [ ] **Approved primitives only** — the change uses one of:
  - Symmetric: XChaCha20-Poly1305 (preferred), AES-GCM (with 96-bit nonce)
  - Hash: SHA-256 / SHA-512 / BLAKE2b
  - KDF: Argon2id (memory-hard), HKDF (for derivation)
  - Asymmetric: Ed25519 (signing), X25519 (agreement)
  - MAC: HMAC-SHA-256/512, Poly1305
- [ ] **NIST references cited** — every primitive choice links to the relevant NIST SP 800-38D / FIPS 180-4 / FIPS 186-5 section, or to the RFC (e.g. RFC 8439 for ChaCha20-Poly1305).
- [ ] **No deprecated primitives** — no MD5, SHA-1, DES, 3DES, RC4, RSA-PKCS1v1.5, raw RSA, ECDSA with deterministic k, or anything else from OWASP "broken crypto" lists.

## Key Handling

- [ ] **Key separation enforced** — distinct keys for distinct purposes (encryption key ≠ authentication key ≠ audit-chain key). Document the purpose of every key in code.
- [ ] **Key rotation path documented** — the change includes or updates a documented rotation procedure (how is a new key generated, distributed, and the old key retired?).
- [ ] **Key destruction path documented** — SecureBuffer / zeroize-on-drop is in use; the procedure for retiring a key from disk and from memory is documented.
- [ ] **Keys never logged** — no key material, raw derived bytes, or key-encryption-keys appear in any log path, error message, or audit row.
- [ ] **Key material scope is minimal** — a key is accessible only to the function(s) that need it, not held in module-level globals.

## Nonces, IVs, and Counters

- [ ] **Nonce uniqueness verified** — for each (key, nonce) pair the algorithm is invoked with, the construction guarantees uniqueness. Random 192-bit nonces (XChaCha20-Poly1305) are safe; AES-GCM 96-bit nonces must be a counter.
- [ ] **No nonce reuse** — code paths that could cause nonce reuse (e.g. counter wraparound, branch reuse) are impossible by construction or caught by an assertion.
- [ ] **IV generation uses a CSPRNG** — never derived from a timestamp, PID, or other low-entropy source.

## Constant-Time & Side Channels

- [ ] **Constant-time comparisons** — MAC verification, signature verification, key comparison all use `hmac.compare_digest` / `sodium_memcmp` / equivalent. No `==` on byte strings for security checks.
- [ ] **No early-exit on partial match** — verification completes the full check before declaring success or failure.
- [ ] **No secret-dependent branches** — code paths don't branch on key material or decrypted content.

## Testing

- [ ] **Test vectors added** — at least one known-answer test (KAT) from RFC 7748 / RFC 8032 / NIST CAVP / project Wycheproof, proving correctness.
- [ ] **Negative test vectors** — at least one test where verification is *expected to fail* (tampered ciphertext, wrong key, wrong nonce).
- [ ] **Failure mode tested** — what happens when a key is wrong, when a nonce collides (in a test), when the underlying syscall fails? Each path produces a defined error, not a panic or silent corruption.
- [ ] **Fuzz coverage** — at least one fuzz harness in `tests/fuzz/` covering this code path (or a follow-up ticket created if not present).

## Documentation

- [ ] **Threat model cross-link** — if the change touches trust boundaries or attacker capabilities, `docs/threat-model.md` is updated in the same PR.
- [ ] **ADR cross-link** — if a new primitive or construction is introduced, an ADR exists at `docs/adr/ADR-NNNN-*.md` and is referenced from the code.
- [ ] **Audit row format documented** — if the change introduces a new crypto-related audit event, the row format is documented in the audit-log spec.

## Sign-off

- [ ] PR approved by Crypto Maintainer (per `reviewer-matrix.md`)
- [ ] Author is **not** the final reviewer (no self-approval on `comp:crypto`)
- [ ] If any finding is a regression, file a `regression` label and add to next milestone
- [ ] Findings documented in `AUDIT.md` if they affect the public threat model
