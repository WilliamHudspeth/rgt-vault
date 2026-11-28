# Logging Policy (Go Line of Record)

Covers OWASP ASVS 4.0 Chapter V7 (Error Handling and Logging), V1.7 (Logging Architecture), and Multica issues `RGT-247`, `RGT-248`, `RGT-409`–`RGT-411`, `RGT-413`–`RGT-416`, `RGT-418`–`RGT-421`, and `RGT-428`–`RGT-432`.

> **Line of record:** Go (`go/`). The Python implementation (`python/`) is end-of-life and frozen. Every event name, field name, file path, and limitation in this document reflects what actually exists in the Go codebase on `master`; unimplemented items and deferred format changes are listed in [Section 8 (Gaps & Planned Designs)](#8-gaps--planned-designs).

---

## 1. Two Logging Planes

`rgt-vault` separates durable security audit records from operational process logs:

1. **Cryptographic Audit Chain (`audit_logs` SQLite table)** — implemented across `go/internal/audit`, `go/internal/store`, `go/internal/vault`, `go/internal/server`, and `go/cmd/rgt-vault`. Records authentication outcomes, scope/ABAC/hook/approval decisions, secret lifecycle, capability execution, token/TOTP administration, rate limiting, honeytoken triggers, rotations, and imports inside `vault.db`.
2. **Operational Structured JSON Logs (`go/internal/logging`)** — built on Go's standard `log/slog` `JSONHandler`. Produces single-line JSON records with UTC timestamps, sensitive-field redaction, and control-character encoding.
   - `go/internal/actions` and `go/internal/hooks` (`LogRedactionHook`) accept `*slog.Logger`.
   - `go/internal/server`, `go/internal/servecmd`, `go/internal/mcp`, and `go/internal/approval.LogNotifier` currently emit plain-text `log.Printf` lines sanitized via `handlers.LogSafe`; wiring them onto `go/internal/logging` (including optional file output through `FileWriter` and SIGHUP-driven reopen) is **not done yet** and is tracked in `RGT-512` / [Section 8.1](#81-current-implementation-gaps-in-go). Until then the Go daemon logs only to stdout/stderr (systemd-journald) and no deployed process writes JSON log files.

---

## 2. Audit Chain Schema and Real Event Names (`RGT-411`, `RGT-413`, `RGT-414`)

### 2.1 `audit_logs` Columns (`go/internal/store/auditlog.go`)

| Column | Type | Hashed in `entry_hash`? | Sanitized / Validated on Write | Notes |
|---|---|---|---|---|
| `id` | `INTEGER PRIMARY KEY` | No | N/A | Monotonic SQLite row ID |
| `timestamp` | `TEXT NOT NULL` | Yes | Generated (`audit.PyISOTime`) | UTC ISO-8601 (`+00:00`, microseconds omitted when zero) |
| `action` | `TEXT NOT NULL` | Yes (sanitized) | `audit.Sanitize` (`\r`, `\n`, `\t`) | Event name from §2.2 |
| `secret_name` | `TEXT` (nullable) | Yes (as stored; `NULL` -> `""`) | `validation.ValidateName` at `vault`/HTTP boundary | Not passed through `audit.Sanitize` in `store` (frozen format) |
| `details` | `TEXT` (nullable) | Yes (sanitized) | `audit.Sanitize` + `AuditPath` percent-encoding | Investigation context |
| `prev_hash` | `TEXT` (nullable) | Indirectly (genesis `""`, then prior `entry_hash`) | Hex string | Stored `prev_hash` column is not re-read by `audit.Verify` |
| `entry_hash` | `TEXT NOT NULL` | Output | Lowercase SHA-256 hex | `sha256(prev\|timestamp\|sanitize(action)\|secret_name\|sanitize(details)\|policy_hash)` |
| `policy_hash` | `TEXT` (nullable) | Yes | Hex string (`sha256(yaml)[:16]`) | Empty string when policy YAML is empty |
| `agent_id` | `TEXT` (nullable) | **No** (frozen format) | Token-derived (`auth.Store`) or `validation.ValidateAgent` | Populated on HTTP/CLI rows; internal `Vault.logAudit` rows record `Agent: <id>` in `details` |

### 2.2 Events Recorded Across Go (`store`, `vault`, `server`, `cmd/rgt-vault`)

| Category | `action` Value | Source | What Is Recorded |
|---|---|---|---|
| HTTP authentication success | `HTTP_API`, `HTTP_OPERATOR` | `go/internal/server/handlers/handlers.go` (`AuditHTTP`) | `token=<id> ip=<peer> <method> <escaped_path>`, `agent_id` |
| HTTP authentication failure | `AUTH_FAILED`, `AUTH_RATE_LIMITED` | `go/internal/server/middleware.go` (`AuthMiddleware`) | `ip=<peer> <method> <escaped_path> reason=<missing\|empty\|expired\|invalid> token=<short_id>` |
| HTTP scope / IDOR denial | `AUTHZ_DENIED` | `go/internal/server/handlers/identity.go` (`AuditDenied`) | `token=<id> ip=<peer> <method> <escaped_path> reason=<missing scope ...\|agent mismatch ...>`, `agent_id` |
| Secret lifecycle | `SET_SECRET`, `GET_SECRET`, `GET_SECRET_FAILED`, `LIST_SECRETS`, `REVOKE_SECRET` | `go/internal/store/secrets.go` | Version, namespace, secret name, or `Secret not found` / `Checksum mismatch` |
| Secret lease & HTTP read | `LEASE_GRANTED`, `LEASE_RETURNED`, `SECRET_READ` | `go/internal/vault/secrets.go`, `handlers/handlers.go` (`LeaseSecret`) | Agent, secret name, namespace, purpose, `token=<id>` |
| ABAC & 2FA flag protection | `POLICY_DENIED`, `REQUIRE_2FA_DOWNGRADE_DENIED`, `REQUIRE_2FA_DOWNGRADED` | `go/internal/vault/secrets.go` | Action, agent, namespace, secret name, policy denial reason |
| Operator approval & 2FA | `APPROVAL_APPROVED`, `APPROVAL_DENIED`, `APPROVAL_BAD_CODE`, `APPROVAL_CODE_REPLAY`, `APPROVAL_AUTO_DENIED`, `APPROVAL_LOCKOUT`, `APPROVAL_THROTTLED`, `APPROVAL_SOD_DENIED`, `APPROVAL_QUEUE_FULL` | `go/internal/vault/secrets.go`, `handlers/approvalflow.go`, `internal/approval/notify.go` | Request ID, operator `token=<id>`, IP, attempt counter (`attempt=k/n`), reason (never the TOTP code) |
| Capability execution | `CAPABILITY_EXECUTED`, `CAPABILITY_DENIED`, `CAPABILITY_FAILED`, `HOOK_CAPABILITY` | `go/internal/vault/capability.go` | Capability name, version, agent, `token_id`, reason (never token or secret) |
| Pre-op hook consultation | `HOOK_READ`, `HOOK_WRITE`, `HOOK_LIST`, `HOOK_REVOKE`, `HOOK_ROTATE`, `HOOK_SIMULATE` | `go/internal/vault/hook.go` | JSON `{"hook_id": "...", "decision": "allow\|deny\|freeze", "reason": "..."}` |
| Rate limit & honeytoken | `RATE_LIMITED`, `HONEYTOKEN_TRIGGERED` | `go/internal/vault/secrets.go`, `gatehelpers.go` | Agent, secret name, critical severity JSON on honeytoken hit |
| Simulation, rotation, import | `SIMULATION_RUN`, `ROTATE`, `IMPORT` | `go/internal/vault/{policy,rotate,export}.go` | Policy simulation parameters, `MASTER_KEY`/`DEK` rotation, `VAULT` import |
| Token & TOTP administration | `TOKEN_MINTED`, `TOKEN_ROTATED`, `TOKEN_REVOKED`, `TOKEN_IMPORTED`, `TOTP_SECRET_REPLACED` | `go/cmd/rgt-vault/{tokenaudit,enroll}.go` | Token record ID, agent, scopes, expiry, old TOTP fingerprint, OS user |

---

## 3. Operational JSON Log Format (`go/internal/logging`, `RGT-247`)

Loggers constructed with `logging.New(...)` or `logging.NewWithCloser(...)` emit one JSON object per line with UTC RFC3339Nano timestamps and stable field constants:

| Key Constant | JSON Key | Description |
|---|---|---|
| `FieldTime` | `time` | UTC timestamp (`2026-11-26T20:04:05.123456Z`) |
| `FieldLevel` | `level` | `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `FieldMessage` | `msg` | Scrubbed, control-character-encoded event summary |
| `FieldComponent` | `component` | Subsystem name (e.g. `server`, `actions`, `mcp`) |
| `FieldEvent` | `event` | Structured event code |
| `FieldAgent` | `agent` | Authenticated agent identifier |
| `FieldNamespace` | `namespace` | Target secret namespace |
| `FieldSecretName` | `secret_name` | Target secret name (never its value) |
| `FieldTokenID` | `token_id` | 8-hex-char SHA-256 prefix or token record ID (`logging.TokenHashID`) |
| `FieldIncidentID` | `incident_id` | 16-hex-char random error correlation ID (`logging.NewIncidentID`) |
| `FieldRequestID` | `request_id` | Per-operation correlation UUID |
| `FieldHTTPMethod` | `http_method` | HTTP verb (`GET`, `POST`, ...) |
| `FieldHTTPPath` | `http_path` | Request path (without query string) |
| `FieldHTTPStatus` | `http_status` | Integer HTTP response status code |
| `FieldDurationMS` | `duration_ms` | Request latency in milliseconds |
| `FieldAction` | `action` | Executed action name |
| `FieldErrorType` | `error_type` | Classified error category |
| `FieldReason` | `reason` | Non-sensitive denial or failure summary |

---

## 4. What Is Never Logged (`RGT-409`, `RGT-410`, `RGT-428`)

The following data classes are excluded from both `audit_logs` and operational logs:

- **Plaintext secret values** — encrypted with AES-256-GCM before `store.SetSecret`; `Vault.Lease` and `Handlers.SetSecret` wipe temporary `[]byte` buffers after use. `logging.Redactor` and `hooks.Redact` scrub `value`, `secret`, `secret_value`, and replace any `[]byte` / `[N]byte` with `<N bytes redacted>`.
- **Master secrets and Data Encryption Keys (DEKs)** — never serialized to strings or audit rows; `master_key`, `master_secret`, `dek`, and `wrapped_dek` attributes are scrubbed to `[REDACTED]`.
- **Bearer, operator, and capability tokens** — `auth.Store` persists only `sha256(token)`; `AUTH_FAILED`, `HTTP_API`, and `servecmd` log only record IDs or 8-hex SHA-256 prefixes (`auth.TokenID` / `auth.PresentedID`); `captoken.TokenID` uses a 16-hex SHA-256 prefix; `Vault` strips `capability_token` from `HookResponse.Extra`. `logging.Redactor` scrubs `Authorization`, `Cookie`, `Bearer ...`, `Basic ...`, JWT/`eyJ...`, `sk-*`, `ghp_*`, and `AKIA*` strings across headers, maps, structs, slices, and error values.
- **TOTP secrets and OTP codes** — `rgt-vault enroll-2fa` suppresses the provisioning URI on non-TTY stdout unless `--show-secret` is passed, and `TOTP_SECRET_REPLACED` logs only `old_secret_fingerprint`. `APPROVAL_BAD_CODE` / `APPROVAL_CODE_REPLAY` never log the submitted code. `logging.Redactor` scrubs `totp*`, `otp*`, `passcode`, 6–8 digit string `code` attributes, and `otpauth://...?secret=...` URIs.
- **PII and request metadata** — `rgt-vault` has no user accounts, e-mail addresses, or payment data. `server.LoggingMiddleware` and `logging.HTTPMiddleware` omit query strings, headers, bodies, and client IPs. `HTTP_API`, `AUTH_FAILED`, and `AUTHZ_DENIED` audit rows record `ip=<ClientIP>` strictly for security investigation (normally `127.0.0.1` under loopback binding). Callers **must not** place regulated personal data into unencrypted identifier or metadata fields (`secret_name`, `namespace`, `agent`, `purpose`, `note`); any regulated data must be stored inside the encrypted secret `value`.

---

## 5. Log Injection Prevention (`RGT-415`)

- **Operational JSON logs (`go/internal/logging.SanitizeText`)**: Encodes `\r` (`\r`), `\n` (`\n`), `\t` (`\t`), ESC/ANSI (`\x1b`), ASCII C0 (`0x00..0x1f`), DEL (`0x7f`), invalid UTF-8 (`\xNN`), Unicode C1 (`U+0080..U+009F`), line/paragraph separators (`U+2028`, `U+2029`), and BiDi marks and overrides (`U+200E`, `U+200F`, `U+202A..U+202E`, `U+2066..U+2069`).
- **HTTP server logs & audit paths (`go/internal/server`)**: `PathMiddleware` rejects paths containing control characters (`< 0x20` or `0x7f`) with `400`; `LoggingMiddleware`, `RecoverMiddleware`, and `handlers.writeError` wrap request-derived strings and error messages in `handlers.LogSafe`; `AuditHTTP`, `AuditAuthFailure`, and `AuditDenied` record `handlers.AuditPath(r)` (`r.URL.EscapedPath()`, percent-encoded) and `safeAgentLabel`.
- **Audit chain (`go/internal/audit.Sanitize` + `go/internal/validation`)**: `audit.Sanitize` encodes `\r`, `\n`, and `\t` in `action` and `details`. Public `Vault` methods validate `name`, `namespace`, `agent`, `note`, and `purpose` via `go/internal/validation`, rejecting control characters before `store` is called. Direct calls to low-level `store.LogAudit` / `Vault.Audit` leave `secret_name` and `agent_id` unescaped in SQLite due to the frozen Python-compatible hash format.

---

## 6. Log Integrity, Access Separation, Rotation, and Retention (`RGT-416`, `RGT-430`, `RGT-431`)

### 6.1 Access Control and Separation of Duties (`RGT-431`)
- **HTTP API (`go/internal/server/authz.go`)**: `GET /v1/audit` and `POST /v1/audit/verify` require `ScopeAudit` (or `ScopeOperator`). Standard `agent` and `agent+lease` tokens receive `403` (`AUTHZ_DENIED`). Conversely, a dedicated `audit`-scoped token (`rgt-vault token mint --agent auditor --scopes audit`) can read and verify the audit chain without any ability to read/write/revoke secrets, approve requests, or rotate keys.
- **OS & systemd (`deploy/rgt-vault-go.service`, `go/internal/store/store.go`)**: `vault.db` (`0600`) and `tokens.json` (`0600`) sit in `0700` directories owned by the dedicated `rgtvault` account (`ProtectSystem=strict`, `ReadWritePaths=/var/lib/rgt-vault`). Journald files (`/var/log/journal`, `root:systemd-journal` `0640`) are written by journald, not by `rgtvault`, and are readable by the `adm` / `systemd-journal` groups; the unit's `ProtectSystem=strict` leaves `/var/log` read-only to the daemon. The optional file-log reference policy (`deploy/logrotate.d/rgt-vault`) is not active on a default install and does **not** make archives tamper-proof against `rgtvault`: its `root:adm` `0440` archives live in a directory the daemon user must be able to write to, so the daemon could still delete them. This document claims the API-layer separation (`ScopeAudit`) only; OS-layer protection of file logs is part of `RGT-512`.

### 6.2 Rotation and Retention (`RGT-430`)
- **`deploy/journald.conf.d/rgt-vault.conf`**: `Storage=persistent`, `Compress=yes`, `Seal=yes`, `MaxFileSec=1day`, `MaxRetentionSec=90day`, `SystemMaxUse=1G`, `SystemKeepFree=2G`. Journals are kept **for up to 90 days, subject to the `SystemMaxUse` / `SystemKeepFree` size caps**, which evict the oldest archived files first under sustained volume. Strict 90-day retention needs a larger partition or off-host shipping (§7).
- **`deploy/logrotate.d/rgt-vault`**: Daily rotation, 90-day retention (`rotate 90`, `maxage 90`), gzip compression (`compress`, `delaycompress`), `copytruncate` (no SIGHUP: the daemon does not reopen log files yet; its only SIGHUP handling is TLS certificate reload, ignored without `--tls-cert`), and a `postrotate` `chown root:adm` + `chmod 0440` on rotated segments. This policy only applies once file logging is wired (`RGT-512`); the shipped unit cannot write `/var/log/rgt-vault` (`ProtectSystem=strict`, `ReadWritePaths=/var/lib/rgt-vault`). `logging.FileWriter` creates files `0600` and, on POSIX, directories `0700` (an existing group/other-accessible directory owned by the process is tightened, sticky/shared directories such as `/tmp` are left alone), opens with `O_NOFOLLOW`, and tightens an existing file to `0600`; Windows has no `O_NOFOLLOW` equivalent here and relies on NTFS ACLs.

### 6.3 Audit Hash-Chain Tamper-Evidence Boundary (`RGT-416`)
`store.VerifyAuditChain` / `audit.Verify` walks `audit_logs` oldest-first using `subtle.ConstantTimeCompare`:
- **Detected:** Accidental corruption, edits to `timestamp`/`action`/`secret_name`/`details`/`policy_hash`, and deletion of any non-tail row.
- **Not detected:** `entry_hash` is unkeyed SHA-256 and excludes `agent_id` and `prev_hash`; any principal with direct write access to `vault.db` can mutate `agent_id`, truncate tail rows, or recompute every `entry_hash` from genesis.

---

## 7. Remote Transmission, Error Handling, and Monitoring Guidance (`RGT-248`, `RGT-418`–`RGT-421`, `RGT-429`, `RGT-432`)

- **Error Handling (`RGT-418`–`RGT-421`)**: `RecoverMiddleware` catches panics globally with a 16-hex `incident_id` and logs `panic_type` + stack server-side only; `handlers.writeError` maps `vault`/`actions`/`capabilities`/`approval` errors via `statusRules` with a 12-hex `incident_id` and suppresses unexpected internal/action/capability error details (`"internal server error"`, `"Action '<name>' failed; see server logs for details."`). Middleware rejections via `WriteJSONError` (`400`/`401`/`403`/`404`/`405`/`413`/`429`, plus `AuthMiddleware` `500` on unreadable token store) return generic JSON without stack traces or file paths, though they do not yet attach `incident_id` (see §8.1).
- **Dedicated Partitions & Remote TLS Shipping (`RGT-248`, `RGT-429`)**: Mount `/var/log/journal` (or `/var/log/rgt-vault`) and `/var/lib/rgt-vault` on separate partitions. Forward logs out-of-process over TLS 1.2+ using `systemd-journal-upload` (HTTPS/mTLS) or `rsyslog` (`ForwardToSyslog=yes` + `omfwd` `StreamDriver="ossl"`).
- **Attack Indicator Queries (`RGT-432`)**:
  - **Audit chain**: Alert immediately on `HONEYTOKEN_TRIGGERED`, `APPROVAL_CODE_REPLAY`, `APPROVAL_LOCKOUT`, `APPROVAL_SOD_DENIED`, `GET_SECRET_FAILED` (`Checksum mismatch`), failed `VerifyAuditChain()`, or spikes in `AUTH_FAILED`, `AUTH_RATE_LIMITED`, `AUTHZ_DENIED`, `POLICY_DENIED`, or `RATE_LIMITED`.
  - **HTTP logs** *(note: `audit_logs` `HTTP_API` rows are written before handlers execute and do not store HTTP status codes; status codes appear in `LoggingMiddleware` / `logging.HTTPMiddleware`)*: Alert on sustained `4xx` scanning bursts (`-> 400|401|403|404|422`) and any `5xx` or `PANIC incident=` entries.

---

## 8. Gaps & Planned Designs

### 8.1 Current Implementation Gaps in Go

| Gap | Affected Issues | Planned Resolution |
|---|---|---|
| `go/internal/server`, `go/internal/servecmd`, `go/internal/mcp`, and `go/internal/approval.LogNotifier` emit plain-text `log.Printf` lines rather than `go/internal/logging` JSON | `RGT-247`, `RGT-432` | Follow-up server/CLI adoption pass rewiring `LoggingMiddleware`, `RecoverMiddleware`, `writeError`, `servecmd`, `mcp`, and `LogNotifier` onto `go/internal/logging` (`HTTPMiddleware`). |
| Middleware-generated HTTP errors (`server.WriteJSONError`, including `AuthMiddleware` `500` `"authentication unavailable"` and `401`/`403`/`429` responses) omit `incident_id`, whereas `handlers.writeError` (12-hex) and `RecoverMiddleware` (16-hex) include it | `RGT-418`, `RGT-419` | **Batch H4** unifies middleware and handler error responses onto a single envelope with a 16-hex `incident_id` on every error. |
| `go/internal/logging` is not used by any production binary; no deployed process writes JSON log files, so `deploy/logrotate.d/rgt-vault` is a reference policy and `SIGHUP` -> `FileWriter.Reopen` is unwired | `RGT-430`, `RGT-431`, `RGT-512` | `RGT-512`: wire the package into `server`/`servecmd`/`mcp`/`approval`/`gateway` with SIGHUP reopen and decide `/var/log/rgt-vault` ownership. |
| No built-in remote SIEM shipper or automated partition check inside the Go binary; active 4xx/5xx alerting requires an external SIEM | `RGT-248`, `RGT-429`, `RGT-432` | Operator deployment controls (`systemd-journal-upload` / `rsyslog` TLS, dedicated filesystems, SIEM alert rules in §7). |

### 8.2 Design Only (`N4` / `RGT-511` / `RGT-416`): Keyed HMAC Audit Chain (Format v2)

Because changing `audit.EntryHash` breaks Python<->Go byte-compatibility (`rgt-plan-go.md` §0.4, `RGT-489`), replacing the unkeyed SHA-256 chain is deferred until after `python/` removal (**Batch GZ**) and explicit maintainer sign-off (tracked in `RGT-511`).

**Proposed v2 Design:**
1. **Domain-Separated Audit MAC Key**: Derive a dedicated 256-bit HMAC key from the master secret (distinct from the DEK, rotated per `key_epoch`, wiped on `Vault.Close()`):
   `K_audit(epoch) = HKDF-SHA256(ikm = master_secret, salt = vault_id, info = "rgt-vault:audit-hmac:v2:" || epoch)`.
2. **Complete Length-Prefixed Input**: Frame **every** column unambiguously (including `id`, `prev_hash`, and `agent_id`, distinguishing SQL `NULL` from `""`):
   `frame = "v2" || u64be(id) || u64be(epoch) || lp(prev_hash) || lp(timestamp) || lp(action) || lp_null(secret_name) || lp_null(details) || lp_null(policy_hash) || lp_null(agent_id)`.
3. **Versioned Tag**: Store `entry_hash = "hmac-sha256-v2:" || hex(HMAC-SHA256(K_audit(epoch), frame))` and verify `r.PrevHash == prev` explicitly on every row.
4. **Truncation & Epoch Anchoring**: Persist an authenticated head MAC (`audit_head_hash`, `audit_row_count`) or external SIEM/TPM NV anchor to detect tail truncation and whole-DB rollback, with an `EPOCH_TRANSITION` row chaining `K_audit(epoch)` to `K_audit(epoch+1)`.
5. **Migration**: Keep `audit.Verify` dual-mode (`v1` legacy chain verified up to a signed `CHAIN_UPGRADE_V2` boundary row; all subsequent rows require valid `hmac-sha256-v2:` tags).
