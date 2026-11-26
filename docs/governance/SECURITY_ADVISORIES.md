# Security Advisories

The register of published security advisories for `rgt-vault`, and an honest
description of how advisories and mitigation guidance are (and are not)
handled. It supports objectives 9.2 and 9.3 of [GOVERNANCE.md](GOVERNANCE.md).

- **Verified against:** commit `c3b090b` on `master`, checked 2026-11-26.
- **Authoritative policy:** [`.github/SECURITY.md`](../../.github/SECURITY.md).
  If this file disagrees with it, `SECURITY.md` governs.
- **Earlier draft:** the previous version of this file described a security
  mailing list, a notification email template, advisory statistics, opt-in and
  opt-out notification management, a 30-day embargo and placeholder
  `github.com/yourorg/...` links. None of those exist, and they have been
  removed.

## Register

**No security advisory has been published for `rgt-vault`.**

| Advisory | Date | Affected versions | Fixed in | Severity | Link |
|---|---|---|---|---|---|
| none | n/a | n/a | n/a | n/a | n/a |

Check for newer entries on the repository's GitHub "Security" tab. GitHub
security advisories (and a CVE, if one is requested through GitHub) would be the
authoritative record; this register is only a convenience copy and may lag.

## How vulnerabilities reach the maintainer

- **Private email** to the address in `.github/SECURITY.md`.
- **GitHub private vulnerability reporting**, which is enabled on the
  repository.
- Reporters should not file public issues for undisclosed vulnerabilities.

**Response targets** (from `.github/SECURITY.md` and nothing else):

| Step | Target |
|---|---|
| Acknowledge the report | Within 5 business days |
| Remediation plan or assessment | Within 30 days |
| Disclosure | Coordinated; reporters are asked to allow a fix to ship before public discussion |

There is one maintainer, no on-call rota and no bug-bounty programme, so these
are targets for a single person, not service-level agreements. No time-bound
embargo beyond the 30-day assessment target is promised.

## Supported versions

From `.github/SECURITY.md`: `rgt-vault` is pre-1.0 (`0.x`) and only the latest
released version receives security fixes. The future of the Python line (it is
described as maintenance-mode, with Go as the primary line) is an open
decision tracked in RGT-165.

## What is done today when a fix ships

- The fix lands in the repository with a regression test, as required by
  `.github/CONTRIBUTING.md` for crypto, authorization, audit and storage
  changes.
- `CHANGELOG.md` records it under a `### Security` heading.
- Releases are tagged (`vX.Y.Z`); the Go release workflow creates a **draft**
  GitHub release with checksums and SBOMs that the maintainer then edits and
  publishes.
- Nothing proactively notifies users beyond GitHub's own notifications for
  people watching the repository or the releases. No mailing list, chat channel
  or social-media announcement exists (Gap, RGT-485).

## Mitigation guidance when no patch exists

There is no standing process or history of issuing workarounds ahead of a fix
(Gap, RGT-486). The guidance that exists is static and already public, and
applies to weaknesses the project knows about:

| Known weakness | Guidance | Source |
|---|---|---|
| Daemon has no TLS | Keep the default loopback bind (`--host 127.0.0.1`); if remote access is unavoidable, terminate TLS in a reverse proxy you configure yourself (no example config ships) | `deploy/rgt-vault.service`, `rgt_vault/cli.py` |
| All agents share one bearer token; agent name is self-declared | Run agents as a different OS user from the daemon, give agents only the agent token, and keep the operator token separate and out of agent reach | `deploy/rgt-vault.service`, `deploy/setup-daemon.sh`, RGT-236 |
| Go server is a skeleton (in-memory plaintext, allow-all policy, prints its token, binds all interfaces) | Do not use it with real secrets | `go/README.md`, `go/cmd/server/main.go` |
| Audit chain is unkeyed; root-level replacement undetected | Persist the tail hash to an independent store after each write | `.github/SECURITY.md` "Audit Chain Limitations" |
| Backup rollback with a matched old pair is undetected | Anchor the key epoch in an append-only or monotonic store | `.github/SECURITY.md`, `docs/ROADMAP.md` |
| Zeroization is best effort | Follow the secure-buffer patterns | `docs/guides/secure-buffer-patterns.md` |
| Revoked secrets are kept as ciphertext | Treat revocation as access removal, not erasure; no erase command exists | `rgt_vault/storage/sqlite.py`, `rgt_vault/vault.py` |

## Fields an advisory should carry

This is a checklist for when the first advisory is written, using GitHub's
advisory form. It is not evidence that a process has run.

- Identifier (GHSA, plus a CVE if requested), title, severity (CVSS or a
  plain-language rating) and affected and fixed versions.
- Which line is affected (Python, Go or both) and which component.
- Impact on confidentiality, integrity and availability.
- Workaround or mitigation if no fixed version exists, and how to confirm it.
- Credit to the reporter if they agree.
- Dates: reported, fixed, disclosed.

## Maintenance

Update this file whenever a GitHub advisory is published or the response
targets in `.github/SECURITY.md` change. There is no recurring review.
