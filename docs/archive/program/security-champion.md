# Security Champion Role

The rgt-vault project has many security-relevant components (crypto, key management, ABAC, audit chains, agent execution). Diffuse security ownership is the failure mode where "everyone is responsible" means "no one is." The Security Champion role concentrates that responsibility on a single named owner.

## Responsibilities

The Security Champion is the named individual who:

- **Approves crypto changes** — final `review:security` sign-off on any `comp:crypto` ticket.
- **Approves auth changes** — final sign-off on any `comp:auth` or `comp:abac` ticket.
- **Approves threat-model changes** — any PR that updates `docs/threat-model.md` requires Security Champion review.
- **Runs release security review** — before any milestone close, the Security Champion runs `python3 scripts/program/release_gate.py --milestone <X>` and verifies the security-specific gates are green.
- **Triages security findings** — owns the `sev:blocker` and `sev:critical` queue. When a new high-severity ticket is filed, the Security Champion is added as a watcher (via Multica assignment).
- **Maintains the threat model** — at least quarterly, the Security Champion reviews `docs/threat-model.md` for accuracy against current code.
- **Coordinates external audits** — point of contact for any third-party security review.

## Label

Tickets requiring Security Champion review carry the `reviewer:security-maintainer` label (per `reviewer-matrix.md`). The Multica label `reviewer:security-champion` is an alias used for high-severity tickets specifically.

## Authority

The Security Champion can:

- Block any PR from merging, regardless of other approvals, by adding the `review:blocked` label.
- Bump a `sev:minor` to `sev:major` (or higher) without consensus if the impact warrants it.
- Grant a one-time waiver for a `sev:critical` finding to ship a release, *in writing*, with an expiration date and a follow-up ticket.

The Security Champion cannot:

- Self-approve `comp:crypto`, `comp:auth`, `comp:keyring`, or `comp:audit` PRs (no-self-approval still applies — they recuse to the next reviewer).
- Permanently waive a `sev:blocker`. That requires an out-of-band decision from the project maintainer.

## Backup

If the Security Champion is unavailable for more than 5 business days, a backup is designated. The backup has the same authority but cannot grant `sev:critical` waivers — those defer until the primary returns.

## When the role rotates

When the Security Champion role changes:

1. Update `docs/program/security-champion.md` with the new name.
2. File a `type:process` ticket referencing this rotation.
3. Multica: transfer all open `reviewer:security-maintainer` assignments to the new champion.
4. Add an ADR (`docs/adr/`) entry if the rotation also changes the security process.
5. Announce on the project's #security channel.

## Why a single person

Two-person security ownership on a project this size creates worse outcomes than one-person ownership with a backup:

- Decisions stall because nobody can break ties.
- Accountability diffuses.
- The role becomes performative rather than substantive.

A single named owner with explicit authority and a named backup is the model that works for projects of this size.
