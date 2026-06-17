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
2. **Hash-linked chain: each row contains `prev_hash = SHA256(prev_row || prev_hash)`.** Every row knows its predecessor.
3. **Merkle-tree anchoring** with periodic root publication to an external store.
4. **External WORM storage** (S3 Object Lock, etc.).

## Decision Outcome

Chosen option: **2 — Hash-linked chain, with optional Merkle anchoring in v1.0.0.**

Rationale:

- Tamper-evidence without external dependencies (works offline).
- Trivially verifiable: walk the chain and confirm each `prev_hash` matches the previous row.
- Compatible with SQLite (one extra column) and Postgres (same).
- Optional Merkle root publication (e.g. to a customer's compliance store) can be added later without breaking the chain.

### Consequences

- Good, because verification is a single linear pass — O(n) but trivially parallelizable.
- Good, because retention pruning is safe (chain integrity is preserved as long as the head is retained).
- Good, because every row includes its provenance (the hash input is `prev_row_canonical_form || prev_hash`, so any change to a row breaks every subsequent row).
- Bad, because a single corrupted row invalidates the rest of the chain from that point on — must be detected and isolated.
- Bad, because the canonical-form definition (column order, type coercion, null handling) must be exact; any drift breaks the chain. Test vectors are mandatory.
- Neutral, because Merkle anchoring in v1.0.0 adds an external dependency that doesn't exist in v0.x.

### Confirmation

This decision is correct if:

- A `tests/test_audit_chain.py` harness verifies the chain over a 10k-row synthetic log.
- A tampering test (modify one row, verify the chain detects it) passes.
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
- Project wiki: audit row format spec (companion to this ADR)
