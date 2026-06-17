# ADR-0004: Agent Capability Model & Discovery

- Status: proposed
- Date: 2026-06-17
- Deciders: Security Champion, Core Maintainer
- Consulted: API designer, ABAC policy owner
- Informed: All engineers

## Context and Problem Statement

An "agent" in rgt-vault is any caller — human via CLI, internal service, external integration — that wants to perform actions against vault secrets or vault-managed capabilities. We need a unified model for:

1. **Identity** — who/what is making the request.
2. **Authentication** — proof of identity.
3. **Authorization** — decision (via ABAC, per ADR-0002).
4. **Capability discovery** — what actions are *available* to this agent, for UX and least-surprise.
5. **Audit** — every action produces a row (per ADR-0003).

The forces in play:

- Human operators and service agents have very different ergonomic needs (humans want discoverability; services want predictability).
- Capability descriptions should be self-describing so the policy can reason about them.
- The model must work over both the local CLI (`vault execute ...`) and the remote HTTP API (`POST /v1/capabilities/{name}/invoke`).
- Capability tokens should be short-lived and scope-bound.

## Considered Options

1. **Fixed catalog of capabilities, hard-coded** — `read`, `write`, `execute`, `rotate`.
2. **Capability registry with introspection** — capabilities register themselves with metadata (name, inputs, outputs, required scopes); the vault exposes a discovery endpoint.
3. **WASM-style plugin model** — third parties ship capability modules; the vault loads them.

## Decision Outcome

Chosen option: **2 — Capability registry with introspection.**

Rationale:

- Aligns with v0.2.0 epic RGT-60 (Capability Execution Framework).
- Capabilities are first-class objects: name, version, required scopes, input schema, output schema, audit row format.
- Discovery (`GET /v1/capabilities`) powers UX (CLI help text, admin UI), policy authoring (the ABAC policy references capabilities by name + version), and audit (the row carries the capability ID).
- Plugin loading is a future direction (post-v1.0.0) — would extend this design, not replace it.

A capability token is:

- Signed (Ed25519, per ADR-0001 key hierarchy).
- Scope-bound (the token says "may invoke capability X with subject Y in scope Z").
- Short-lived (default 5 minutes; max 1 hour).
- Audience-bound (the token is for vault T, not vault U).

### Consequences

- Good, because policy authors can write ABAC rules against `(agent, capability, version, scope)` tuples — fine-grained.
- Good, because the registry is a single point to add a new capability without code changes to the policy engine.
- Good, because the audit row carries enough context to reconstruct intent post-hoc.
- Bad, because every new capability requires registry registration, policy review, and audit-format documentation — process overhead.
- Bad, because capability versions can fragment (a "read" v1 and v2 both exist; policy has to choose).
- Neutral, because discovery is read-only and does not itself require authorization beyond agent authentication.

### Confirmation

This decision is correct if:

- `GET /v1/capabilities` returns the registered set, and unauthenticated callers see only public metadata.
- A test (`tests/test_capability_registry.py`) demonstrates that an unauthorized capability invocation is denied with audit row.
- The capability model is documented in `docs/api.md` and the ABAC policy simulator (v0.3.0) reasons about capabilities.

## Pros and Cons of the Options

### Option 1: Fixed catalog

- Good, because trivial.
- Bad, because no extensibility; every new action is a code change.

### Option 2: Registry + introspection (chosen)

See "Decision Outcome."

### Option 3: WASM plugin model

- Good, because third-party extensibility.
- Bad, because a WASM runtime is a significant attack surface.
- Bad, because post-v1.0.0; deferred.

## References

- RFC 8693 (OAuth 2.0 Token Exchange — capability tokens resemble scoped access tokens)
- ADR-0001 (signing keys come from the key hierarchy)
- ADR-0002 (ABAC decides whether a capability token is honored)
- ADR-0003 (every capability invocation produces an audit row)
- v0.2.0 epic RGT-60
