# Architecture Decision Records (ADRs)

This directory holds the Architecture Decision Records for the rgt-vault project. Each ADR captures *one* significant design decision, the context that led to it, the options considered, and the consequences of the chosen path.

## Format

Use the [MADR](https://adr.github.io/madr/) template (Markdown Any Decision Records):

```markdown
# ADR-NNNN: <Short title>

- Status: proposed | accepted | deprecated | superseded by ADR-XXXX
- Date: YYYY-MM-DD
- Deciders: <who made the decision>
- Consulted: <who was consulted>
- Informed: <who was notified>

## Context and Problem Statement

<What is the issue? What are the forces at play?>

## Considered Options

1. <Option A>
2. <Option B>
3. <Option C>

## Decision Outcome

Chosen option: "<X>", because <reasoning>.

### Consequences

- Good, because <reason>
- Bad, because <reason>
- Neutral, because <reason>

### Confirmation

<How will we know this decision worked? What metrics or events would prove it right or wrong?>

## Pros and Cons of the Options

### <Option A>

<example good | example bad>

### <Option B>

<example good | example bad>

## References

- <links, prior art, RFCs, NIST publications>
```

## Index

| ADR | Title | Status | Milestone |
|-----|-------|--------|-----------|
| [ADR-0001](ADR-0001-key-hierarchy.md) | Key Hierarchy & Wrapping Strategy | proposed | v0.3.0 |
| [ADR-0002](ADR-0002-abac-over-rbac.md) | ABAC over RBAC for Capability Authorization | proposed | v0.3.0 |
| [ADR-0003](ADR-0003-audit-chain-design.md) | Audit Chain Design (Hash-Linked, Append-Only) | proposed | v0.3.0 |
| [ADR-0004](ADR-0004-agent-capability-model.md) | Agent Capability Model & Discovery | proposed | v0.2.0 |

## When to write an ADR

Write an ADR when a decision:

- Is difficult or expensive to reverse.
- Locks in a security property (crypto choice, key rotation, audit semantics).
- Defines a public API contract.
- Establishes a process that other code will depend on.
- Sets a precedent the team will repeat.

Skip an ADR for:

- A library choice with a trivial replacement cost (just note it in code).
- An internal refactor that doesn't change behavior.
- A bug fix that aligns code with an existing ADR.

## Lifecycle

- **proposed** — drafted, under review.
- **accepted** — accepted by reviewers, in force.
- **deprecated** — no longer the recommended path, but old code may still follow it.
- **superseded by ADR-XXXX** — explicitly replaced by a newer ADR.

Deprecated and superseded ADRs are not deleted — they remain as a record of *why* the path changed.
