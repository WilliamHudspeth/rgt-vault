# Contributing to rgt-vault

Thanks for your interest in improving `rgt-vault`. Because this is a security
project, contributions are held to a high bar for correctness and clarity.

## Reporting security vulnerabilities

**Do not open a public issue for a vulnerability.** Follow the private
disclosure process in [SECURITY.md](SECURITY.md).

## Development setup

```bash
git clone <your-fork>
cd rgt-vault
python -m venv .venv && . .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pytest -q
```

The test suite uses an in-memory master-secret provider and temp directories;
it does not require a real TPM/DPAPI/Keychain.

## Pull requests

1. Open an issue first for non-trivial changes so we can agree on the approach.
2. Keep PRs focused; one logical change per PR.
3. **Every change to crypto, authorization, audit, or storage requires tests.**
4. Update docs (`README.md`, `core-architecture.md`, `SECURITY.md`, `llm_guide.py`)
   when behavior changes. Documentation must not overstate guarantees — if a
   protection is partial or best-effort, say so.
5. Add a `CHANGELOG.md` entry under "Unreleased".
6. Ensure `pytest -q` is green and the code byte-compiles.

## Coding guidelines

- Target Python ≥ 3.9.
- Never log, print, or place secret **plaintext** in exceptions, audit records,
  or return values.
- Use `os.urandom` for all salts/nonces/keys; never seed your own RNG.
- Prefer authenticated encryption (AES-GCM) and bind context via AAD.
- Match the style and comment density of the surrounding code.

## Commit messages

Use clear, imperative subject lines (e.g. "Fix audit-chain write race"). Group
related changes; avoid mixing refactors with behavior changes.

## Code of Conduct

By participating you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).
