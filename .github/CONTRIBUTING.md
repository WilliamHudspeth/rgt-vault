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

The Go line (the primary one) builds and tests with:

```bash
cd go && go vet ./... && go test ./...
```

The Python test suite uses an in-memory master-secret provider and temp
directories; it does not require a real TPM/DPAPI/Keychain.

## Pull requests

1. Open an issue first for non-trivial changes so we can agree on the approach.
2. Keep PRs focused; one logical change per PR.
3. **Every change to crypto, authorization, audit, or storage requires tests.**
4. Update docs (`README.md`, [`docs/architecture/overview.md`](../docs/architecture/overview.md),
   [`docs/security/threat-model.md`](../docs/security/threat-model.md), `SECURITY.md`,
   `python/llm_guide.py`) when behavior changes. Documentation must not overstate guarantees — if a
   protection is partial or best-effort, say so.
5. Add a `CHANGELOG.md` entry under "Unreleased".
6. Ensure `pytest -q` is green and the code byte-compiles.
7. Link the issue the PR addresses (a tracker id such as `Closes RGT-123`, or a
   GitHub issue number) in the PR description. This is how a change is traced
   back to a ticket; see the PR template.
8. Tick the **threat-model impact** box in the PR template if the change adds
   or alters a component, a trust boundary, authentication, authorization,
   audit, crypto, storage or outbound network behavior, and update
   [`docs/security/threat-model.md`](../docs/security/threat-model.md) in the
   same PR.

## Security development lifecycle

`rgt-vault` is maintained by one person, so the process below is small and
mostly relies on automated checks. Each stage names the artifact that
implements it. If a stage is only partly enforced, that is stated.

| Stage | What happens | Where it lives |
|---|---|---|
| Requirements | Feature requests state security constraints ("who may do this, who must not be able to") | [Feature request template](ISSUE_TEMPLATE/feature_request.md) |
| Design | Significant decisions are written as ADRs; new components and trust-boundary changes are reviewed against the threat model | [ADRs](../docs/adr/README.md), [threat model](../docs/security/threat-model.md), PR template checkbox |
| Implementation | Secure-coding rules below; lint, type and security linters. **Go is the primary line**; Python is end-of-life and takes no new features | Coding guidelines, `go vet`, `gofmt`; for the legacy Python code `ruff`, `mypy`, `bandit` (`ci.yml`, `review-gate.yml`) |
| Verification | Tests, dependency audits, secret scan, static analysis | Run `cd go && go vet ./... && go test ./...` locally; `govulncheck`, `pip-audit`, `gitleaks` and the Python tests (coverage gate 80%) in CI; CodeQL (weekly schedule) |
| Review | Every change goes through a PR with the security checklist; reviewers can use the [review checklists](../docs/archive/reviews/security-review-checklist.md) | PR template; whether a second reviewer is *required* depends on repository branch-protection settings, which this file cannot assert |
| Release | Tagged releases built by goreleaser, SBOM generated | `release.yml`, `ci.yml` (`sbom`) |
| Maintenance | Dependabot for pip, Go modules and Actions; private vulnerability disclosure | `.github/dependabot.yml`, [SECURITY.md](SECURITY.md) |

Known gaps (tracked as issues, not hidden): CI does **not** run `go vet` or
`go test` on pull requests (`go test ./...` runs only in `release.yml`, on a
tag), so run them locally before opening a PR; the CodeQL and Scorecard
`push`/`pull_request` triggers name `main` while the default branch is
`master`; the threat-model box and the ticket link are conventions checked by a
human, not by CI.

### Secure coding checklist

Short list for authors and reviewers (the PR template repeats it):

1. No secret plaintext in logs, exceptions, audit rows or return values.
2. Authorization decisions go through `VaultManager` / the ABAC engine, not
   ad-hoc checks in a route handler.
3. Validate and bound every external input (length, charset, size); fail
   closed on error.
4. Randomness from `crypto/rand` (Go), `os.urandom` / `secrets` (Python) only; never
   hand-rolled crypto, never a reused nonce.
5. Outbound requests go through the existing URL/dialer guards.
6. New code that crosses a trust boundary updates the threat model and adds a
   test for the denial path, not only the happy path.
7. Documentation must not claim more than the code and tests show.

## Coding guidelines

- Go is the primary line: follow `go/go.mod` (Go 1.25) and keep `go vet ./...`
  clean. The Python line is legacy: it takes bug and security fixes only (≥ 3.9).
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
