# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-06-16

### Fixed
- **Default vault path crashed.** Platform providers return raw `bytes` while
  the KDF expected a `MasterSecret`; `VaultManager` now normalizes either form
  (`_normalize_master`). The default `VaultManager()` and the CLI now run.
- **`execute()` leaked a plaintext `str`.** Callbacks now receive the mutable
  `bytearray` the vault zeroizes, instead of an immutable `str` copy that
  lingered in memory. **Breaking:** callback signature is now `(bytearray)`.
- **Wheel installs shipped no migrations.** Added `package-data`/`MANIFEST.in`
  so `*.sql` migration files are included; `pip install .` now works (not only
  editable installs).
- **CLI `simulate` was broken** (missing `action` argument; always printed
  ALLOWED). It now evaluates correctly, prints the reason, and runs without a
  master-secret provider. Added `--action`.
- **Audit hash-chain write race.** Read-previous-hash and insert are now a
  single `BEGIN IMMEDIATE` transaction, serialized by a process lock, so
  concurrent writers cannot fork the chain.
- Replaced deprecated `datetime.utcnow()` with timezone-aware UTC.
- **`llm_guide.py` was a latent `SyntaxError`** — a nested `"""` in an example
  terminated the guide string early. The module now imports.
- **`import_data` raised an unhandled `TypeError`** on non-list collections
  (e.g. `{"secrets": None}`), found by fuzzing; it now raises `ValueError`.

### Added
- `cross-vault import guard`: exports carry their `vault_id`; importing into a
  different vault is refused instead of silently producing undecryptable data.
- `MasterSecretProvider.rotate_secret()` in the base ABC (raises
  `NotImplementedError` for providers without automated rotation).
- Apache-2.0 `LICENSE`, `SECURITY.md` (threat model + disclosure),
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.gitignore`, issue/PR templates.
- `tests/conftest.py` with a keyring-free in-memory provider; new
  `tests/test_hardening.py` covering normalization, zeroization, audit-chain
  concurrency, and the cross-vault import guard.
- **CI/CD & supply chain:** GitHub Actions matrix (Ubuntu/macOS/Windows ×
  Python 3.9/3.11/3.12/3.13) running tests+coverage, ruff, mypy, bandit, a
  wheel build that asserts migrations are packaged, plus CodeQL, OpenSSF
  Scorecard, and Dependabot.
- **Property/fuzz tests** (`tests/test_fuzz.py`, Hypothesis) over `decrypt`,
  DEK unwrap, and `import_vault`.
- **Benchmarks** (`benchmarks/bench.py`) and a Performance table in the README.
- **Formal threat model** (`docs/threat-model.md`) and Mermaid architecture
  diagrams; `ROADMAP.md` and `RELEASE_CHECKLIST.md`.
- Tooling config in `pyproject.toml` (ruff/mypy/bandit/pytest/coverage) and a
  richer `[dev]` extra; project URLs.

### Changed
- Pinned dependencies (`cryptography>=44.0.0`, `keyring>=24`, `PyYAML>=6`);
  added project metadata, classifiers, and a `rgt-vault` console entry point.
- Documentation corrected to match the implementation: AES-256-GCM (not
  AES-128/Fernet), accurate rotation semantics, partial-zeroization and
  partial-rollback caveats, working quickstart and examples.
- Positioned the first release as **`v0.1.0` Security Preview** (not production)
  and removed any maturity overstatement.
- The legacy-migration test is now hermetic (mocks the keyring) so it no longer
  writes to the real OS credential store / requires it in CI.

### Removed
- Dead `refactor.py` (a no-op that leaked a hardcoded local path).
- Committed build/cache artifacts (`agent_vault.egg-info/`, `.pytest_cache/`).
