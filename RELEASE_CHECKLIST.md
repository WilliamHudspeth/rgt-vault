# Release Checklist

Run through this before tagging a public release.

## Repository hygiene

- [ ] No secrets, credentials, API keys, or tokens committed (grep history too)
- [ ] No hardcoded local paths or machine-specific values
- [ ] No debug prints or commented-out dead code
- [ ] No `TODO`/`FIXME` without a tracked issue reference
- [ ] `.gitignore` excludes vault runtime data (`*.db`, `keychain.json`, `*.priv`, `*.pub`)
- [ ] Build/cache artifacts not committed (`*.egg-info/`, `.pytest_cache/`, `__pycache__/`)

## Correctness & tests

- [ ] `pytest -q` green on Linux, macOS, Windows
- [ ] Tested against the minimum pinned `cryptography` (≥ 44.0)
- [ ] Default `VaultManager()` path verified per platform provider
- [ ] CLI commands run (`simulate` at minimum)

## Packaging

- [ ] `python -m build` produces a wheel and sdist
- [ ] `pip install dist/*.whl` into a clean venv works **and** migrations apply
      (i.e. `*.sql` shipped in the wheel)
- [ ] `pip install -e .` works
- [ ] `rgt-vault --help` resolves (console entry point)
- [ ] Version bumped in `pyproject.toml`; `CHANGELOG.md` "Unreleased" promoted to the version

## Documentation

- [ ] README quickstart copy-pastes and runs
- [ ] SECURITY.md guarantees/non-goals match current behavior
- [ ] ARCHITECTURE.md matches the code (primitives, rotation, rollback caveats)
- [ ] `llm_guide.py` claims match the code (no overstated guarantees)
- [ ] LICENSE present and referenced in `pyproject.toml`

## Security sign-off

- [ ] No secrets/credentials committed (scan history too)
- [ ] Tests passing on the full CI matrix
- [ ] Security docs updated (SECURITY.md, docs/threat-model.md)
- [ ] Threat model reviewed; no guarantee overstated
- [ ] Dependencies audited (`pip-audit`); no actionable advisories
- [ ] Migration path tested (fresh install + upgrade from prior schema)
- [ ] Rollback behavior tested (epoch mismatch fails closed)
- [ ] Backup → restore tested (export/import round-trip on same vault)
- [ ] No secret plaintext reachable via logs, exceptions, or audit records
- [ ] Disclosure contact in SECURITY.md is current
- [ ] Quality gates green: `ruff`, `mypy`, `bandit --severity-level medium`, `pytest`
