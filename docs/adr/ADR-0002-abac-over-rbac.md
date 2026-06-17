# ADR-0002: ABAC over RBAC for Capability Authorization

- Status: proposed
- Date: 2026-06-17
- Deciders: Security Champion, Core Maintainer
- Consulted: API designer
- Informed: All engineers

## Context and Problem Statement

The rgt-vault project must authorize every agent action (read secret, write secret, execute capability) against a policy. The two dominant paradigms are:

- **RBAC** (Role-Based Access Control): agents have roles; roles map to permissions.
- **ABAC** (Attribute-Based Access Control): policies are evaluated against attributes of the subject, action, resource, and environment.

The forces in play:

1. Agents are heterogeneous (humans, internal services, external integrations) — their identity is rarely a single role.
2. Capabilities carry rich context (intended target, time-of-day, source network, prior approvals, classification level of the secret).
3. Authorization decisions must be auditable (each decision produces a row).
4. The policy needs to express time-bound grants, environment-conditional grants (e.g. "only if not on a public IP"), and least-privilege scopes.

## Considered Options

1. **RBAC with predefined roles** (admin, operator, auditor, agent).
2. **ABAC with a policy DSL** (subject/action/resource/environment attributes → allow/deny).
3. **Capability-based security** (each agent holds unforgeable tokens; the tokens themselves encode the permission).

## Decision Outcome

Chosen option: **2 — ABAC with a policy DSL.**

Rationale:

- Expresses time-bound and environment-conditional grants natively.
- Compatible with capability tokens (capabilities become one of the subject attributes; ABAC decides whether the capability is honored).
- Audit row is a faithful record of the decision: `(subject_attrs, action, resource, env, decision, policy_id, timestamp)`.
- Deny-overrides-allow is straightforward to express (and is enforced per the security-review-checklist).

Capabilities are the *transport*; ABAC is the *decision*.

### Consequences

- Good, because the policy is auditable and testable as data.
- Good, because adding a new role / attribute does not require code changes.
- Bad, because a policy DSL can grow complex; we will need a policy simulator (`type:design` ticket exists in v0.3.0).
- Bad, because policy writers need to understand the attribute vocabulary; documentation is non-optional.
- Neutral, because RBAC can be expressed in ABAC (subject attribute = "role") — they are not exclusive.

### Confirmation

This decision is correct if:

- A policy simulator exists and is exercised in CI (planned: v0.3.0 epic RGT-61).
- Every policy decision produces an audit row (verified by `tests/test_audit_hooks.py`).
- Deny-overrides-allow is the default and is verified by `tests/test_policy_simulator.py`.

## Pros and Cons of the Options

### Option 1: RBAC

- Good, because simple to reason about for small teams.
- Bad, because "role explosion" — every new context becomes a new role.
- Bad, because environment-conditional grants are awkward.

### Option 2: ABAC (chosen)

See "Decision Outcome."

### Option 3: Pure capability-based

- Good, because tokens are unforgeable and self-contained.
- Bad, because revocation is hard (the token is the permission; expiry is the only revocation lever).
- Bad, because the policy question "may this capability be used *now* against *this* resource" still needs ABAC somewhere.

## References

- NIST SP 800-162 (Guide to ABAC)
- RFC 8693 (OAuth 2.0 Token Exchange — used as inspiration for capability transport)
- OWASP Authorization Cheat Sheet
- ADR-0004 (agent capability model integrates with this policy layer)
