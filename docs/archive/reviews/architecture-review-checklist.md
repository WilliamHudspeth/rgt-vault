# Architecture Review Checklist

Required for tickets labeled `effort:L`, `effort:XL`, or `type:design`.

## Strategic Fit

- [ ] **Fits roadmap** — the change supports a documented milestone (v0.2 / v0.3 / v0.4 / v0.5 / v1.0)
- [ ] **Aligns with the project's threat model** — see `docs/threat-model.md`
- [ ] **Aligns with the project's architecture** — see `core-architecture.md`
- [ ] **Doesn't conflict with planned work** — check RGT-* in the relevant milestone epic

## Design Quality

- [ ] **No duplicate abstraction** — similar logic doesn't exist elsewhere; if it does, this should reuse
- [ ] **Public API justified** — every public function/class has a clear use case and docstring
- [ ] **Dependency direction correct** — high-level modules don't import from low-level internals
- [ ] **No circular dependencies introduced**
- [ ] **Module boundaries clean** — this change doesn't leak implementation across layers
- [ ] **Single Responsibility Principle** — one logical change, not three changes in a trench coat

## Compatibility

- [ ] **Backward compatibility considered** — old configs/tokens/DBs still work after this change
- [ ] **Deprecation path documented** — if anything is deprecated, when is the cutoff?
- [ ] **Migration path tested** — existing data formats / DBs can migrate without manual intervention
- [ ] **Public API changes** — backward-incompatible changes require a major version bump

## Performance

- [ ] **Performance impact estimated** — no surprise O(n²), no unbounded loops
- [ ] **Memory impact considered** — no unbounded caches / buffers
- [ ] **Concurrency safe** — appropriate locks / atomic operations / immutability
- [ ] **Database indexes** — added for any new query patterns

## Security (in conjunction with Security Review)

- [ ] **Threat model still holds** — or is updated
- [ ] **Trust boundaries unchanged** — or explicitly documented if they changed
- [ ] **No new attack surface** — or if added, threat-modeled

## Observability

- [ ] **Observability requirements considered** — does this change create a new failure mode that needs detection?
- [ ] **Metrics added where operationally useful** — only if a new measurable behavior needs visibility (per `/docs/program/dashboard.py`); not required for purely-internal refactors

## Documentation

- [ ] **ARCHITECTURE.md updated** — if the change affects the architectural diagram
- [ ] **README updated** — if user-facing
- [ ] **CHANGELOG entry** — under `[Unreleased]`
- [ ] **Inline architecture decision record** — if the choice is non-obvious

## Sign-off

- [ ] Reviewer identity recorded
- [ ] Author is **not** the reviewer (separate from code/security review)
- [ ] PR approved by required reviewer(s) (GitHub branch protection is the source of truth)
- [ ] ADR created or updated if architectural decision changed (see `docs/adr/`)
- [ ] Ticket moved to implementation phase