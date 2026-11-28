# ADR-0003: Audit Chain Design (Hash-Linked, Append-Only)

- Status: proposed
- Date: 2026-06-17
- Deciders: Security Champion, Audit Maintainer
- Consulted: Storage Maintainer
- Informed: All engineers

## Context and Problem Statement

Every security-relevant action (policy decision, lease grant, lease revoke, secret read, secret write, capability execution) must be recorded for audit. The audit log has stricter requirements than application logging:

1. **Tamper-evidence** — an attacker who gains write access to the audit store must not be able to silently edit or delete rows.
2. **Append-only** — rows are never updated or deleted by application code.
3. **Verifiable** — a third party (auditor, customer) can verify the chain end-to-end.
4. **Queryable** — operations and security teams can still search by date, actor, action.

The forces in play:

- We do not have an external timestamping authority (no TSA, no blockchain). The chain must be self-verifying.
- Storage is SQLite (v0.2.x → v0.5.x); later, Postgres. The design must work on both.
- Retention policies require pruning old rows — but pruning must not break verification.

## Considered Options

1. **Plain append-only table, no chain.** Trust the database integrity.
2. **Hash-linked chain: each row's `entry_hash` is a SHA-256 over the previous row's hash and this row's fields.** Every row knows its predecessor. (As built: `sha256(prev_hash|timestamp|action|secret_name|details|policy_hash)`, `python/storage/sqlite.py`.)
3. **Merkle-tree anchoring** with periodic root publication to an external store.
4. **External WORM storage** (S3 Object Lock, etc.).

## Decision Outcome

Chosen option: **2 — Hash-linked chain, with optional Merkle anchoring in v1.0.0.**

Rationale:

- Tamper-evidence without external dependencies (works offline).
- Trivially verifiable: walk the chain and confirm each `prev_hash` matches the previous row.
- Compatible with SQLite (one extra column) and Postgres (same).
- Optional Merkle root publication (e.g. to a customer's compliance store) can be added later without breaking the chain.

### Implementation status and limits (checked against the code, 2026-11-26)

**Go (primary line): Gap (Go).** `Store.AddAuditEntry` / `VerifyAuditChain` implement the same unkeyed SHA-256 chain, but over an in-memory slice: nothing is persisted, the log is empty after every restart, there is no `agent_id`-style column, and no external anchor. The table below was verified against the end-of-life Python implementation (SQLite) and applies to Go's chain by construction.

The original goal "an attacker with write access to the audit store must not be able to silently edit or delete rows" is only **partly** met:

| Attack on `vault.db` | Detected by `verify_audit_chain()`? |
|---|---|
| Edit a covered field of any row | Yes |
| Insert a row | Yes |
| Delete a row from the head or the middle | Yes |
| Delete the **last N rows** | **No** (the remaining prefix is a valid chain) |
| Delete the whole table | **No** (an empty log verifies as OK) |
| Rebuild a fresh, consistent chain | **No** (the hash is unkeyed SHA-256) |
| Edit `agent_id` (not part of the hash input) | **No** |

"Append-only" holds for the application code paths except `import_vault`, which deletes and replaces the whole `audit_logs` table. Closing the tail and rebuild gaps needs an external anchor of the head hash and/or a keyed (HMAC) chain; both are future work. [SECURITY.md](../../.github/SECURITY.md#audit-chain-limitations) states the same limits for users.

### Consequences

- Good, because verification is a single linear pass — O(n) but trivially parallelizable.
- Neutral, because retention pruning is **not implemented and would break verification today**: `verify_audit_chain` assumes the first retained row was hashed with an empty `prev_hash`, so removing the oldest rows fails verification (confirmed by running the legacy Python code on 2026-11-26). A pruning design needs a checkpoint row first.
- Good, because every row includes its provenance (the hash input includes the previous row's `entry_hash`, so any change to a row breaks every subsequent row).
- Bad, because a single corrupted row invalidates the rest of the chain from that point on — must be detected and isolated.
- Bad, because the canonical-form definition (column order, type coercion, null handling) must be exact; any drift breaks the chain. Test vectors are mandatory.
- Neutral, because Merkle anchoring in v1.0.0 adds an external dependency that doesn't exist in v0.x.

### Confirmation

This decision is correct if:

- Chain verification is exercised by `tests/test_audit_v2_hardening.py` (`test_verify_on_fresh_vault`, `test_verify_detects_tampered_audit_row`, `test_verify_detects_inserted_orphan_row`), `tests/test_hardening.py::test_audit_chain_intact_under_concurrency`, and `tests/test_capability_integration.py::test_audit_chain_verifies_after_capability_and_legacy`. There is no 10k-row synthetic harness.
- A tampering test (modify one row, verify the chain detects it) passes (`test_verify_detects_tampered_audit_row`).
- The chain head is exposed for periodic checkpointing (planned: v0.5.0 observability epic).

## Pros and Cons of the Options

### Option 1: Plain append-only

- Good, because trivial to implement.
- Bad, because tamper-evidence requires trusting the database; an attacker with DB write access can rewrite history.

### Option 2: Hash-linked (chosen)

See "Decision Outcome."

### Option 3: Merkle anchoring

- Good, because an external anchor makes rollback-attack detection cheap.
- Bad, because we don't have an external anchor in v0.x.
- Note: planned as additive on top of option 2 in v1.0.0.

### Option 4: External WORM storage

- Good, because the storage layer enforces immutability.
- Bad, because deployment-coupled to a specific cloud provider.
- Bad, because SQLite-first development doesn't fit.

## References

- NIST SP 800-92 (Guide to Computer Security Log Management)
- RFC 9162 (Certificate Transparency v2 — design inspiration)
- Trillian (Google) — Merkle tree log design
- Audit row schema: `python/storage/migrations/0001_initial.sql`, `0002_namespace.sql` (adds `policy_hash`), `0005_audit_agent_id.sql` (adds `agent_id`)
