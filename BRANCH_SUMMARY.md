# Branch Summary: `audit-hook-layer`

Branch: `audit-hook-layer` (continuing; not a fresh checkout)
Base: `master` at `aee4042` (latest) + 1 ahead (`1ad5b7f` — roadmap docs)
Not merged. Not pushed to `main`/`master`/`production`/`release`.
Per the prompt's CRITICAL GIT RULES: do not merge, do not rebase main,
do not push to main.

## What this branch does

Evolves the vault from a *secret access controller* into a
*capability executor* for AI agents. The secret material no
longer crosses the vault boundary by default; the agent calls a
named capability and the vault performs the action internally,
returning only the action's result.

This branch is the implementation of the spec delivered alongside
the prompt: capability tokens, TokenVerifier hierarchy, capability
registry, hook layer refactor, freeze integration, audit chain
extension, removal of SOAR mode, and the new HTTP surface.

## Files changed

New:
- `rgt_vault/token.py` — v2 capability token format, TokenVerifier
  ABC, `HMACTokenVerifier` (v1), `Ed25519TokenVerifier` (stub).
- `rgt_vault/capabilities.py` — `CapabilityRegistry`,
  `CapabilityContext`, `CapabilitySpec`, built-in capabilities
  (`secrets.echo`, `secrets.use`).
- `tests/test_token.py` — 20 tests.
- `tests/test_capabilities.py` — 31 tests.
- `tests/test_capability_integration.py` — 12 tests.
- `CAPABILITY_SECURITY.md` — architecture document.
- `MIGRATION_GUIDE.md` — v0.2 → v0.3 caller migration.
- `BRANCH_SUMMARY.md` — this file.

Modified:
- `rgt_vault/vault.py` — added `execute_capability` (the new
  primary enforcement point), `_hook_consult_capability` (sibling
  of the legacy `_hook_consult`), `capability_registry` and
  `token_verifier` constructor parameters, `action_registry`
  (owns the built-in actions; `secrets.use` needs it). Legacy
  methods (`set_secret`, `lease_secret`, `execute`, `rotate_*`)
  unchanged in behavior; `set_secret` docstring marked
  deprecated. Removed a duplicate `revoke_secret` definition
  (pre-existing bug — the second one was dead code).
- `rgt_vault/hook.py` — `HookRequest` extended with the new
  capability fields (`capability`, `capability_version`, `payload`,
  `token_metadata`, `is_capability` property). `TwoFactorHook`
  now dispatches v1 vs v2 tokens. `WebhookHook` no longer has a
  `mode` parameter; the `soar` mode is removed. `hook_from_config`
  rejects `mode: "soar"`. Removed a dead `mac` placeholder line
  in the legacy `CapabilityToken.to_compact` (pre-existing
  placeholder that was assigned but never used).
- `rgt_vault/exceptions.py` — added `CapabilityNotFoundError`
  and `CapabilityVersionError`.
- `rgt_vault/server/app.py` — added `POST /v1/capabilities/execute`
  and `GET /v1/capabilities`. New exception types mapped to HTTP
  status codes. `execute_capability` endpoint sanitizes handler
  exceptions the same way `/use` does.
- `CHANGELOG.md` — added the `[Unreleased]` section documenting
  the v0.3 capability work.
- `ROADMAP.md` — moved the "capability model" strategic item from
  the "Under consideration" section into the "Planned" section,
  marked the v0.3 building blocks as done; kept the Go rewrite
  in "Strategic direction" for the future.

## Test status

```
193 passed, 4 skipped in 149.65s
```

130 pre-existing + 63 new tests. No previously passing test was
broken.

Coverage of new code:

| File                       | Stmts | Br | Cover |
| -------------------------- | ----- | -- | ----- |
| rgt_vault/token.py         | 118   | 38 | 88%   |
| rgt_vault/capabilities.py  | 93    | 22 | 87%   |
| rgt_vault/vault.py (new)   | (incl. existing) |   | 90%   |
| rgt_vault/server/app.py    | 127   | 12 | 91%   |

Linter: `ruff check` — all checks pass.

Type checker: `mypy` — 3 errors in pre-existing legacy code
(`hook.py` lines 383, 455, 681); zero errors in the new code.

## Open questions for the operator

1. **HMAC vs Ed25519 in production.** The branch ships with
   `HMACTokenVerifier` and an `Ed25519TokenVerifier` architectural
   stub. The migration guide points operators at the HMAC verifier
   for v1 deployment. The stub is there to keep the call sites
   abstract — switching to Ed25519 should not require changes
   elsewhere. **Action:** review whether to implement Ed25519
   verification as a follow-up branch, or keep the stub.

2. **`secrets.use` bridge capability.** The branch keeps the v0.2
   `ActionRegistry` (`openai_chat`, `http_get_with_auth`,
   `http_post_with_auth`, `echo`) and exposes it to the
   capability path via the `secrets.use` bridge. This is a
   backwards-compatibility measure; the spec marks the v0.2
   `lease_secret` path as legacy but the operator's existing
   action handlers should keep working through v0.3. **Action:**
   decide whether to keep the bridge in v0.4 or split it into
   per-service capabilities (`openai.chat_completion`,
   `http.get_with_auth`, etc.).

3. **Capability token TTL enforcement.** The verifier's
   `is_expired` check is `now > expires_at` (strict greater-than).
   A token with `ttl=1` is valid for 1 second plus whatever
   sub-second remainder there is in the second the sign happened.
   This matches industry convention; flagging because the test
   for "expired token" had to be rewritten to forge a
   definitely-past `exp` to be deterministic. **Action:** none
   required; the convention is correct, but the test rewrite is
   worth knowing about if you read the diff.

4. **Capability rate limit.** The branch reuses the existing
   in-process `RateLimiter` for capability executions. A future
   refactor could split secret-access and capability limits into
   separate buckets, but the threat model is the same (an agent
   hammering the vault should be throttled). **Action:** none
   required; flagged for future consideration.

5. **Hook observability.** The branch's `LogHook` records
   capability requests too. If you're using `LogHook` in
   staging to evaluate a stricter hook, the in-memory
   `consultations` list will now include capability entries.
   The dictionary shape is identical to legacy entries with
   `operation="capability"`. **Action:** check any dashboards
   that aggregate hook consultations; they may need a small
   update to render the new `operation` value.

6. **HTTP exception sanitization for capability handlers.** The
   `/v1/capabilities/execute` endpoint sanitizes handler
   exceptions the same way `/use` does — the response body
   says "see server logs for details". If a handler wants to
   surface a specific error code to the agent, it should
   raise a `VaultError` subclass (mapped via `_STATUS_MAP`)
   rather than a bare `Exception`. **Action:** documented in
   `CAPABILITY_SECURITY.md`; no immediate work.

## How to review

1. Read `CAPABILITY_SECURITY.md` first (architecture entry
   point).
2. Read `MIGRATION_GUIDE.md` to understand the caller impact.
3. Review `rgt_vault/token.py` (small, self-contained) and
   `rgt_vault/capabilities.py` (registry + context).
4. Review `execute_capability` in `rgt_vault/vault.py` (the
   new primary enforcement point). The pre-flight checks
   (freeze → token verify → agent/cap/version match → context
   binding → hook consult → registry → payload validation →
   rate limit → handler) are the security boundary; verify
   that each check fails closed.
5. Review the hook changes in `rgt_vault/hook.py`:
   `HookRequest.is_capability`, the v1/v2 token dispatch in
   `TwoFactorHook.consult`, the removal of `soar` mode in
   `WebhookHook` and `hook_from_config`.
6. Read the tests — they are documentation as much as
   verification. Each test maps to a specific requirement in
   the spec.
7. Spot-check the `secrets.use` bridge — the path that
   preserves v0.2 caller behavior.

## Rollback

The branch does not modify the database schema, the ABAC policy
format, the audit chain format, or any wire format that v0.2
callers depend on. Rollback is `git reset --hard origin/master`
on this branch (the `audit-hook-layer` branch is private to
this work — not pushed to main, not pushed to a release branch).
