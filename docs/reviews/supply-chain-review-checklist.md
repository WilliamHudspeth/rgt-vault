# Supply Chain Review Checklist

Required for any ticket that adds, removes, upgrades, or replaces a third-party dependency (direct or transitive). Also required when adding a new build step, a new CI action, or a new container base image.

A vault project is only as secure as the worst dependency it ships. This checklist is the gate between "I want to add `httpx`" and "the lockfile now contains `httpx`."

## Before adding the dependency

- [ ] **Dependency justified** — explain in the PR description *why* this dependency is needed. "It has a nice API" is not sufficient; "we need HTTP/2 server-push with multiplexing, and the stdlib `http.client` does not support it" is.
- [ ] **Alternative considered** — could the stdlib do it? Could an existing dependency in our tree already do it? If yes, document why we still need the new one.
- [ ] **Maintenance status checked** — the project is actively maintained (commits in the last 12 months, responsive to security advisories).
- [ ] **License reviewed** — license is compatible with rgt-vault's license (Apache-2.0 by default). Copyleft (GPL/AGPL) requires an explicit maintainer sign-off in writing.

## Dependency metadata

- [ ] **Dependency pinned** — the lockfile (e.g. `uv.lock`, `requirements.txt` with hashes) records an exact version and hash. No floating ranges in production lockfiles.
- [ ] **Version chosen is the latest stable** — or if not, document why (e.g. "waiting for upstream fix of CVE-XXXX in next release").
- [ ] **Transitive deps surfaced** — `pip-compile` / `uv lock` is run so the full transitive tree is visible. Anything surprising is called out in the PR description.
- [ ] **No abandoned packages** — packages with no maintenance, or marked archived by their maintainer, require an explicit decision and a follow-up plan.

## Vulnerability scanning

- [ ] **Vulnerability scan clean** — `pip-audit` / `osv-scanner` / `safety` returns zero high/critical findings for the new direct and transitive deps.
- [ ] **SBOM generated** — `cyclonedx-py` or `syft` produces an SBOM that includes the new dep. SBOM is committed to the release artifact.
- [ ] **No known unpatched CVEs** — if a CVE exists but is not yet patched upstream, document the risk and the planned mitigation (vendoring, fork, replacement).

## Trust & provenance

- [ ] **Source verified** — the package is pulled from the official PyPI registry (or another trusted source). `pip install` with `--require-hashes` is configured for CI.
- [ ] **No typosquatting risk** — the package name is unambiguous; there is no plausible-squatted near-miss (e.g. `requesets` vs `requests`).
- [ ] **No bundled malware indicators** — release artifacts checked against malware scanners (e.g. `clamav` on wheel contents).

## Build & CI

- [ ] **CI workflow pinned** — any new GitHub Action is pinned to a SHA, not a tag (per the project's policy in `.github/workflows/review-gate.yml`).
- [ ] **Container base images pinned** — `Dockerfile` uses `image@sha256:...` digests, not floating tags.
- [ ] **Reproducible builds considered** — where possible, builds are reproducible from source (a separate, deeper hardening item — at minimum, the build inputs are recorded in the SBOM).

## Sign-off

- [ ] PR approved by Core Maintainer (per `reviewer-matrix.md`).
- [ ] For cryptographic libraries: also approved by Crypto Maintainer (per the crypto-review-checklist).
- [ ] If the dep is in the hot path (called by every secret read/write), an architecture review (`effort:L` or higher ticket) is filed.
- [ ] Dependency is added to the project's dependency inventory (a CSV or SBOM in `dist/sbom/`) so the next audit finds it.

## Removal

When a dependency is removed:

1. Remove it from `pyproject.toml` / `requirements*.txt`.
2. Re-run `uv lock` / `pip-compile` so transitive deps are pruned.
3. Re-run `pip-audit` to confirm nothing surprising got pulled in.
4. Update the SBOM.
5. Add a CHANGELOG entry under `[Unreleased] → Removed`.

Removal PRs follow the same review path as addition PRs.
