---
name: Feature request
about: Suggest an enhancement
title: "[feat] "
labels: enhancement
---

## Problem / motivation

What are you trying to do that `rgt-vault` makes hard today?

## Proposed solution

What you'd like to see.

## Security constraints

Every feature states what it must **not** allow, not only what it should do.
Write at least one constraint as "As a <role>, I can <do X>. I must not be able
to <do Y>", for example "As an agent, I can use a secret in my own namespace. I
must not be able to use, list or revoke another agent's secrets."

- **Who may use this, and who must be refused?**
- **What secret or sensitive data does it touch**, and who can see it (the
  caller, the log, the audit trail)?
- **Does it cross a trust boundary** (new endpoint, new outbound call, new
  credential, new component)? If yes, say which and note the
  [threat model](../../docs/security/threat-model.md) section it affects.
- **What should be audited**, and what must never be logged?
- **How should it fail** (deny by default, fail closed)?

## Alternatives considered

## Additional context
