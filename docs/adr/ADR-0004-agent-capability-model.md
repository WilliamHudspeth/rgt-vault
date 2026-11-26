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
- The model must work over both the in-process API (`VaultManager.execute_capability`) and the HTTP API (`POST /v1/capabilities/execute`).
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

- Signed. *Intended:* Ed25519 per the ADR-0001 key hierarchy. *As built:* HMAC-SHA256 with a shared key (`HMACTokenVerifier`); `Ed25519TokenVerifier` is a stub that raises `NotImplementedError`.
- Scope-bound (the token says "may invoke capability X with subject Y in scope Z"). As built: agent id, capability, capability version and context bindings.
- Short-lived. *Intended:* default 5 minutes, max 1 hour. *As built:* default 60 seconds from `sign(ttl_seconds=60)`; no maximum is enforced.
- Audience-bound (the token is for vault T, not vault U). **Not implemented**: the payload has no audience claim.

### Consequences

- Good, because policy authors can write ABAC rules against `(agent, capability, version, scope)` tuples — fine-grained.
- Good, because the registry is a single point to add a new capability without code changes to the policy engine.
- Good, because the audit row carries enough context to reconstruct intent post-hoc.
- Bad, because every new capability requires registry registration, policy review, and audit-format documentation — process overhead.
- Bad, because capability versions can fragment (a "read" v1 and v2 both exist; policy has to choose).
- Neutral, because discovery is read-only and does not itself require authorization beyond agent authentication.

### Confirmation

This decision is correct if:

- `GET /v1/capabilities` returns the registered set. As built it **requires a bearer token** (`tests/test_capability_integration.py::test_http_list_capabilities_requires_bearer`); there is no unauthenticated public view. Agents can ask which capabilities they are authorized for with `GET /v1/capabilities/list?agent=...`.
- Denial of an unauthorized or mismatched invocation is covered by `tests/test_capability_integration.py::test_http_execute_capability_denied_on_token_mismatch`, `::test_http_execute_capability_404_on_unknown_capability` and `tests/test_capabilities.py::test_execute_capability_denies_unknown_capability`; the code writes a `CAPABILITY_DENIED` row on the freeze, verifier, lockout, token-mismatch, binding, hook and registry failure paths (a missing token is rejected earlier with a plain validation error). Registry behavior is tested in `tests/test_capabilities.py` (`test_registry_*`); an earlier draft of this ADR named a registry test file that was never written.
- The capability model is documented in [`docs/concepts/capabilities.md`](../concepts/capabilities.md) and the endpoints in [`docs/guides/api.md`](../guides/api.md). The ABAC simulator treats a capability name as the `action` attribute (`GET /v1/capabilities/list`).

### Known gaps on this commit

- **Go (primary line): Gap (Go).** No capability registry, token verifier, `execute` endpoint or discovery endpoint. The Go server's `GET /v1/actions` returns a hard-coded list of four names, and `/use` is a stub. Everything below describes the end-of-life Python code, which is the reference for the port.

- `rgt-vault serve` does not configure a `token_verifier`, so `/v1/capabilities/execute` currently fails closed with a 400 until the server is wired with one (RGT-337).
- The vault holds the HMAC key, so it could mint tokens as well as verify them; there is no key rotation procedure for it.
- Replay: a valid token can be reused until it expires unless a `TwoFactorHook` replay cache is installed.

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
