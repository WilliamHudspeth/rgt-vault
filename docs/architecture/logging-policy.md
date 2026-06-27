# Logging Policy

Covers ASVS 7.x / WSTG-ERRH / RGT-409 to RGT-432.

## What is logged (RGT-411, RGT-413, RGT-414)

Every `VaultManager` operation appends a row to the hash-chained `audit_logs`
table via `StorageBackend.log_audit()`. The following classes of event are
always recorded:

| Category | Events logged |
|---|---|
| Authentication | `HTTP_API` (token verified), `HTTP_OPERATOR` (operator token) |
| Authorization | `ABAC_DENY`, `ABAC_ALLOW` recorded by `_hook_consult` |
| Secret lifecycle | `SET_SECRET`, `GET_SECRET`, `REVOKE_SECRET`, `LIST_SECRETS` |
| Key management | `ROTATE_DEK`, `ROTATE_MASTER` |
| Audit chain | `VERIFY_CHAIN` |
| Capability execution | `EXECUTE_CAPABILITY`, `CAPABILITY_DENY` |

Each row stores: `action`, `secret_name`, `timestamp` (UTC ISO-8601),
`details`, `agent_id`, `entry_hash`, `prev_hash`, `policy_hash`.

## What is never logged (RGT-409, RGT-410, RGT-413, RGT-428)

- **Plaintext secret values** — secrets are only ever held in `bytearray`
  inside `SecureBuffer`; they are never serialised to strings for logging.
- **Bearer tokens** — only the first 8 characters of the token hash are
  recorded (`token=<8-char-id>`); the full value is never written.
- **Passwords or passphrases** — vault operations do not accept passwords;
  all authentication is token-based.
- **TOTP codes** — the approval broker records the outcome (approved/denied)
  not the code itself.
- **PII** — no user personal data flows through the vault layer. Application
  callers are responsible for not storing PII as secret names or details.

## Log encoding / injection prevention (RGT-415)

`_sanitize_log_field()` in `storage/sqlite.py` encodes `\r`, `\n`, and `\t`
to their escape sequences before any caller-supplied string is written to the
audit table. This prevents CRLF injection attacks in forwarded log streams.

## Log integrity (RGT-416)

The `audit_logs` table is protected by:

1. **Hash chaining** — each row includes `prev_hash` and `entry_hash`
   (SHA-256), forming a tamper-evident chain. `VaultManager.verify_audit_chain()`
   recomputes the chain and fails closed on any mismatch.
2. **Database file permissions** — the vault database should be owned by the
   vault service user with mode `0600`. Operators should verify this with
   `stat ~/.secure-vault/vault.db`.
3. **Constant-time comparison** — `verify_audit_chain` uses `hmac.compare_digest`
   to avoid timing-oracle attacks (RGT-403).

## Error handling (RGT-418, RGT-419, RGT-420, RGT-421)

- All FastAPI exception handlers return a generic JSON body with an opaque
  `incident_id` (12-char hex UUID). Stack traces are never returned to clients.
- A global last-resort `Exception` handler (`_unhandled_exception_handler`)
  catches anything not matched by the type-specific handlers.
- The full exception is written to the server logger (`rgt_vault.server`) at
  `ERROR` level so operators can correlate `incident_id` to a log line.

## Credentials over secure channels (RGT-422)

The server requires TLS in production (`APP_ENV=production`). Bearer tokens in
`Authorization` headers must only be transmitted over HTTPS. The `HSTS` header
(`max-age=63072000`) is set on all responses to enforce this in browsers.

## Remote logging and retention (RGT-429, RGT-430, RGT-431)

For production deployments:

- Forward `rgt_vault.server` logs to a centralized SIEM (e.g. Loki, Elasticsearch)
  via a syslog forwarder or log-shipping agent.
- Configure log rotation with a minimum retention of 90 days; compress older
  segments with gzip.
- Restrict raw log file read access to the security team role; the vault TUI
  and API expose a read-only audit view that does not require OS-level log access.

## Attack indicator monitoring (RGT-432)

The audit chain includes every API request path and status. An operations team
should alert on:

- High rate of `ABAC_DENY` events from a single `agent_id` (credential stuffing)
- Repeated `HTTP_API` failures (rate-limit breaches)
- Consecutive 4xx responses to `/v1/` (active scanning)
- Any `VERIFY_CHAIN` failure (potential log tampering)

## Platform attack surface (RGT-427)

- Run the vault server as a dedicated non-root OS user with no shell.
- Disable unused server modules; the FastAPI app exposes only the documented
  `/v1/` endpoints plus `/healthz`.
- All exceptions produce generic error pages — no framework banners, stack
  traces, or internal paths are sent to clients.
