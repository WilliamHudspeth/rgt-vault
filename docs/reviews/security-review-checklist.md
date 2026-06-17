# Security Review Checklist

Required for any ticket with `security:*` label OR `comp:crypto`, `comp:auth`, `comp:keyring`, `comp:audit` component label.

## Before Review

- [ ] PR diff understood
- [ ] Threat model reviewed (does this change invalidate any existing assumptions?)
- [ ] Related issues / prior art in the security audit files reviewed

## Code Review

- [ ] **Secrets never logged** — no API keys, tokens, passwords, or secret material in any log path
- [ ] **Authorization reviewed** — ABAC deny rule overrides allow; default-deny; no allow-by-default fallbacks
- [ ] **Crypto reviewed** (where applicable) — constant-time comparisons, IV/nonce uniqueness, key handling, no deprecated primitives
- [ ] **Input validation reviewed** — length limits, type checks, injection vectors (SQL, command, template, path traversal)
- [ ] **Audit logging reviewed** — every policy decision (allow/deny, lease grant/revoke, write attempt) produces an audit row
- [ ] **Failure modes reviewed** — what happens when deps are unavailable? No silent failures. Errors don't leak secrets.

## Operational Review

- [ ] **Rate limits present** — auth attempts, API calls, expensive operations all bounded
- [ ] **Permissions minimal** — least-privilege principle applied to file access, network, process spawning
- [ ] **Dependencies audited** — no new transitive deps without review
- [ ] **Backwards compatibility checked** — old configs/tokens still work; deprecation path documented

## Sign-off

- [ ] Reviewer identity recorded in commit message (`Reviewed-by:`) or PR comment
- [ ] **Author is not the final reviewer** (for comp:crypto, comp:auth, comp:keyring, comp:audit)
- [ ] If any finding is a regression, file a `regression` label and add to next milestone
- [ ] Findings documented in `AUDIT.md` if they affect the public threat model

## After Approval

- [ ] PR merged with required approvals (GitHub branch protection is the source of truth)
- [ ] Ticket moved to `Testing` (or `Done` if test coverage was already verified)
- [ ] If new threat model concerns, update `docs/threat-model.md`
- [ ] If new audit row format, update audit-log documentation

## Threat Model Impact

(Required for any change touching security boundaries.)

- [ ] No trust boundary changed — document why this change does not alter assumptions in `docs/threat-model.md`
- [ ] New trust boundary documented — if a new actor/system crosses an existing boundary, add a Trust Boundary Diagram update + a paragraph in `docs/threat-model.md`
- [ ] New attacker capability documented — if this change grants an actor a new capability (e.g. new code path, new network surface, new file write), add an ATT&CK-style reference to `docs/threat-model.md`
- [ ] Threat model updated — if any of the above three checked "yes" or "documented", the threat model document is updated in the same PR (not a follow-up)