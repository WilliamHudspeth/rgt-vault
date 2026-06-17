# Code Review Checklist

Required for every PR / ticket transition to Code Review state.

## Functional Review

- [ ] **Acceptance criteria satisfied** — every item in the ticket's `Acceptance:` section is met
- [ ] **Tests added or updated** — unit tests for new logic; integration tests for cross-module behavior
- [ ] **Existing tests still pass** — no regressions introduced

## Quality Review

- [ ] **Error handling reviewed** — no bare `except:`, no silent failures, errors carry useful context
- [ ] **Logging reviewed** — no secrets in logs (verify against security checklist), log levels are appropriate
- [ ] **Documentation updated** — inline docstrings on public functions, README if user-facing, CHANGELOG entry added
- [ ] **No dead code** — no commented-out blocks, no unused imports, no unreferenced functions
- [ ] **No new TODOs** — or explicit follow-up tickets created for each one

## Style Review

- [ ] **Formatting passes** — `ruff format` (run via CI)
- [ ] **Linting passes** — `ruff check`
- [ ] **Type hints present** — on public function signatures
- [ ] **Naming clear** — variable/function names describe what they do, not how

## Operational Review

- [ ] **No new top-level imports of deprecated stdlib / third-party modules**
- [ ] **No new global state** — or if added, documented in `ARCHITECTURE.md`
- [ ] **No new files at the repo root** without explicit justification
- [ ] **Migration path documented** — if any DB schema / config format changes

## Sign-off

- [ ] PR approved by required reviewer(s) (per component → reviewer mapping)
- [ ] Review history preserved in GitHub (do not squash-merge; keep approvals visible)
- [ ] Ticket moved to `Security Review` (if applicable) or `Testing`

## When to escalate

Escalate to `Security Review` if the change touches:
- Anything with `security:*` label
- `comp:crypto`, `comp:auth`, `comp:keyring`, `comp:audit` files
- Error handling that might leak data
- Logging paths
- Configuration parsing

Escalate to `Architecture Review` if the change:
- Touches `effort:L`, `effort:XL`, or `type:design` tickets
- Introduces a new public API
- Changes a core data structure
- Adds a new module / subpackage