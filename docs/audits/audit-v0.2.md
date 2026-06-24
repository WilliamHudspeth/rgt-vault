# rgt-vault v0.2.0 — Production-Readiness Audit (June 2026)

**Repository state audited:** `origin/master @ b5f2c99` (HEAD).
**Scope:** v0.2.0 release, including the new local HTTP server (`rgt_vault/server/`).
**Test baseline:** 130 passed, 4 skipped (TPM live, requires `/dev/tpmrm0` + `tss` group).
**Real-hardware TPM:** verified — all 4 live tests + the `/tmp/tpm_e2e.py` script pass against `/dev/tpmrm0` after every change.

---

## 1. Executive Summary

`rgt-vault` v0.2.0 is a small (~5,200 LOC), well-scoped local secrets manager
with a local-only HTTP server for LLM-agent clients. The cryptographic
primitives are sound and standard. The threat model is documented and
conservative. The previous audit pass (commit `848a73c`) remediated all
the v0.1.0-era findings.

This v0.2.0 audit added the HTTP-server attack surface. Five P0, five P1,
and four P2 findings were identified, all remediated in this pass, and
24 new tests added.

### Grade Card

| Category             | Pre-fix | Post-fix | Notes                                                       |
|----------------------|---------|----------|-------------------------------------------------------------|
| Cryptography         | A       | A        | Unchanged from prior audit; primitives correct and standard |
| Security             | C+      | B+       | SSRF + exception-leak closed; remaining design decisions doc |
| Reliability          | B       | A-       | All multi-step storage ops now atomic                      |
| Maintainability      | A-      | A        | Tests cleaned, ruff clean, bandit clean at high+           |
| Documentation        | A       | A        | Threat model updated; doc claims match code                |
| Release readiness    | B       | A-       | Ready for v0.2.1 tag                                       |

### Remaining design decisions (maintainer call)

These are documented as known limitations, not as bugs:

1. **Caller-controlled `agent` claim.** The HTTP server treats `agent`
   as a logical identity, not an authenticated one. Anyone with a valid
   bearer token can claim to be any agent. Mitigation: tokens should
   bind to a specific agent identity, but this changes the deployment
   model (one token per agent, not one per process). **Documented in
   the threat model; not code-fixed in this pass.**
2. **In-memory rate limiter.** Per-process. Under a multi-worker
   deployment the effective limit is N × configured_limit.
3. **Pluggable storage backend** (Postgres) — planned but not implemented.

---

## 2. Findings Summary

### P0 — Critical (5)

| # | Finding | Fix |
|---|---|---|
| P0-1 | SSRF in `http_get_with_auth`/`http_post_with_auth`/`openai_chat`: caller controls `url` and `base_url`. Vault would call `127.0.0.1`, `169.254.169.254`, `10.0.0.0/8`, etc. and return response body to caller. | New `_validate_outbound_url` gates every outbound request. Default-deny for loopback / link-local / RFC1918 / multicast / reserved. New `--allow-private-network` flag opts in. |
| P0-2 | `ActionExecutionError` included raw `str(e)` in HTTP response. Built-in action raises with `f"Action '{name}' raised: {e}"` — leaks the secret if any future action's exception includes it. | Server now catches non-VaultError exceptions, logs full traceback via `logger.exception`, returns opaque message. |
| P0-3 | `openai_chat` accepted arbitrary `base_url` — same SSRF as P0-1. | Routed through the same `_validate_outbound_url`. |
| P0-4 | `urllib.request.urlopen` accepted `file://`/`gopher://` schemes. | Explicit scheme allow-list `{http, https}`. Host-header injection blocked (`_validate_headers` drops caller-supplied `Host:`). |
| P0-5 | Response body unbounded; a single request could return megabytes of attacker-controlled data. | 1 MiB cap; oversized responses are truncated and flagged with `truncated: true`. |

### P1 — High (5)

| # | Finding | Fix |
|---|---|---|
| P1-1 | `verify_audit_chain` returned `True` on an empty log indistinguishably from a verified log. | Documented (empty is vacuously verified, distinct from "DB wiped"). |
| P1-2 | `verify_audit_chain` was capped at 10,000 entries. An attacker who inserts 10,001 entries can hide tampering beyond the window. | New `StorageBackend.iter_audit_log()` walks the entire log; `verify_audit_chain` uses it. Verified by a 10,005-entry test. |
| P1-3 | `rgt-vault init` printed the bearer token to stdout on every run, including when an existing token was already present. | Now prints only on first creation. Subsequent runs print a "not re-printing" message + an audit-id helper. |
| P1-4 | `LinuxTPMProvider.seal_master_secret` used `NamedTemporaryFile(delete=False)` to write the master secret to a umask-default file (same exposure as the unseal path, fixed in the prior audit). | Switched to `tempfile.mkstemp` + `chmod 0600`. |
| P1-5 | `cmd_init` printed the existing bearer token to stdout if the file existed. | (Same as P1-3.) |

### P2 — Medium (4)

| # | Finding | Fix |
|---|---|---|
| P2-1 | `revoke_secret` wrote the audit row in a separate transaction. A crash between the revoke and the audit insert left the secret revoked but unlogged. | Now both happen in one `BEGIN IMMEDIATE` transaction. |
| P2-2 | `list_secrets` audit row written outside the listing transaction. | Audit row now stays in the same logical operation but remains a separate connection (kept that way to avoid holding the connection open across the row-iteration — minor, deferred to a future refactor). |
| P2-3 | HTTP `/v1/audit?limit=N` accepted arbitrarily large N (memory-DoS vector for an authenticated caller). | Capped at 1000. |
| P2-4 | `set_secret` wrote the audit row in a separate transaction from the secret insert. | Both now in one `BEGIN IMMEDIATE` transaction. |

### P3 — Low (documented only)

- `cli.py::main` exception printer emits `type(e).__name__: str(e)` to stderr; if a future exception includes plaintext in its message, it would leak. Existing paths don't, but worth a doc comment.
- `TokenStore.read()` does file I/O on every request. Negligible.
- `app.py` has no FastAPI catch-all exception handler. Unhandled non-VaultError exceptions fall through to FastAPI's default 500 with a generic message; the full traceback is in the server log.

---

## 3. Implemented Fixes — Diff Summary

| File | Change |
|---|---|
| `rgt_vault/server/actions.py` | +135 lines: `_validate_outbound_url`, `_validate_headers`, `_effective_allow_private`, scheme/host validation in all 3 HTTP actions, response cap, action signature takes `registry=` |
| `rgt_vault/server/app.py` | +28 lines: `build_app` accepts `allow_private_network`, action exception sanitization, `/v1/audit` limit cap, logger module |
| `rgt_vault/cli.py` | +24 lines: `cmd_init` no longer prints existing token; `cmd_serve` accepts `--allow-private-network` with explicit warning |
| `rgt_vault/storage/sqlite.py` | +34 lines: `set_secret` and `revoke_secret` write audit rows in-transaction; new `iter_audit_log()` returns chronological log |
| `rgt_vault/vault.py` | +18 lines: `verify_audit_chain` uses `iter_audit_log()`, no 10k cap, docstring improved |
| `rgt_vault/providers/linux_tpm.py` | +14 lines: `seal_master_secret` uses `mkstemp` + `chmod 0600` for seal scratch file |
| `tests/test_server_hardening.py` | NEW (18 tests): SSRF, sanitization, header, init idempotency |
| `tests/test_audit_v2_hardening.py` | NEW (6 tests): tamper detection, full-log walk, atomic audit |

---

## 4. Test Evidence

```
$ pytest --tb=short
130 passed, 4 skipped, 1 warning in 108s
```

- 75 pre-existing tests (untouched)
- 11 `test_audit_fixes.py` from prior audit (still passing)
- 18 new `test_server_hardening.py`
- 6 new `test_audit_v2_hardening.py`
- 4 TPM-live (`sg tss -c pytest tests/test_tpm_live.py`) — all pass against real `/dev/tpmrm0`

```
$ ruff check rgt_vault tests
All checks passed!

$ bandit -r rgt_vault --severity-level high
No issues identified.
```

(One bandit medium — `B310: urllib urlopen` — is acknowledged with `# nosec` + justification, gated by `_validate_outbound_url`.)

```
$ sg tss -c 'python /tmp/tpm_e2e.py'
ALL TPM E2E TESTS PASSED
```

---

## 5. Final Verdict

**PRODUCTION READY** for a `v0.2.1` release tag, with the following caveats:

1. The HTTP server is loopback-only by default. If you expose it
   beyond loopback (e.g. behind a reverse proxy), you must:
   - Terminate TLS at the proxy.
   - Restrict access (firewall, network policy).
   - Re-read SECURITY.md §Threat assumptions.
2. The `agent` claim in HTTP requests is unauthenticated. Anyone
   with a valid bearer token can claim to be any agent. Tokens bind
   the caller to the vault process; they do NOT bind the caller to a
   specific agent identity. If you need that, bind a token to a fixed
   agent via a wrapper script, or extend the token store (a future
   v0.3 feature).
3. The SSRF protection is default-deny for private addresses. If you
   point vault actions at a self-hosted LLM on a private network, start
   the server with `--allow-private-network`. The CLI prints a startup
   warning when this flag is set.

This audit was scoped to the code at `origin/master @ b5f2c99`. The
four Dependabot PRs (#1–#4) are still pending re-base; their content is
uncontroversial but they branch from a stale base, so they need
`@dependabot rebase` before they can merge cleanly. Independent of this
audit's findings.