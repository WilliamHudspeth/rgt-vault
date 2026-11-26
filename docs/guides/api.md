# HTTP API reference

Direction (2026-11-26): the **Go server is the primary API**. The Python server
is end-of-life and is documented [further down](#legacy-python-http-api) only
because it is the reference for behaviour the Go server has not implemented
yet. Anything documented for the Python server and absent from Go is marked
**Gap (Go)**.

The Go routes below were taken from `go/internal/server/router.go` and the
handlers in `go/internal/server/handlers/handlers.go`. Start the server with
`go run ./cmd/server` (listens on `:8080`) or `rgt-vault serve`; the `rgt-vault`
CLI, TUI and MCP bridge are clients of this API.

> **The Go server is an in-memory skeleton.** Secrets are stored in plaintext
> in process memory and are lost on restart; policy is allow-all; the audit log
> is in memory. Do not put real secrets in it. See the
> [threat model](../security/threat-model.md#parity-gaps-gap-go).

## Conventions (Go server)

| Topic | Behavior |
|---|---|
| Base URL | `http://localhost:8080` (binds all interfaces by default, RGT-259) |
| Authentication | `Authorization: Bearer <token>` on every route except `/healthz`, `/crossdomain.xml`, `/clientaccesspolicy.xml` and `OPTIONS`. The bare token without `Bearer ` is also accepted. The token file is `~/.config/rgt-vault/server.token` (override `RGT_VAULT_TOKEN_FILE`) |
| Roles | One token, one role. **Gap (Go)**: no operator/agent scopes |
| Identity | The acting `agent` is a field in the JSON body, not derived from the token. **Gap (Go)**: no per-agent identity |
| Request bodies | JSON. `Content-Type` is **not** enforced; unknown fields are accepted; there is no body size cap. **Gap (Go)**: the Python server enforces content type and typed models |
| CORS | `Access-Control-Allow-Origin` reflects the request `Origin` when `CORS_ALLOWED_ORIGINS` is `*` or lists it; with it unset, any origin is allowed unless `APP_ENV=production`. All `OPTIONS` requests get 204 before auth |
| Response headers | `Content-Security-Policy: default-src 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` |
| Transport | **Plain HTTP.** **Gap (Go)**: no TLS |
| Unknown routes | chi's default plain-text `404` / `405` |

### Error format

```json
{"error": "ValidationError", "detail": "'name' is required"}
```

| Status | `error` | Meaning |
|---|---|---|
| 400 | `ValidationError` | Bad JSON, missing required field, bad `target`, `limit` out of range |
| 401 | `ServerAuthError` | Missing, empty or wrong bearer token |
| 403 | `PolicyDeniedError` | Defined but never returned: there is no policy to deny |
| 404 | `SecretNotFoundError` | Unknown `namespace/name` |
| 500 | `ServerAuthError` / `InternalError` | Token file missing; any other error is returned with its raw message (**no incident id, no sanitizing**) |

## Routes

| Method & path | Auth | Request | Success response |
|---|---|---|---|
| `GET /healthz` | **public** | — | `{"status": "ok", "vault_id", "key_epoch", "version"}` (`version` empty when `APP_ENV=production`). Discloses vault id and epoch to anyone who can reach the port |
| `GET /crossdomain.xml`, `GET /clientaccesspolicy.xml` | **public** | — | Restrictive policy with status 404 and no-cache headers |
| `POST /v1/secrets` | token | `{name, value, namespace="default", agent="cli", purpose=""}`; `name` and `value` required | `{"ok": true, "namespace", "name"}` |
| `GET /v1/secrets` | token | Query `namespace` (default `default`) | `{"namespace", "secrets": [{name, value, namespace, agent, purpose, created_at}]}`. **The list includes each secret's plaintext `value`** (RGT-346; the MCP `lease_secret` tool relies on it today) |
| `GET /v1/secrets/{namespace}/{name}` | token | — | Metadata only: `name, namespace, agent, purpose, created_at` |
| `DELETE /v1/secrets/{namespace}/{name}` | token | — | Removes the secret |
| `POST /v1/secrets/{namespace}/{name}/use` | token | `{action, agent, purpose, params}`; `action` and `agent` required | `{"ok": true, "action", "result": {action, status, secret_leased, secret_len, message}}`. **A stub**: no action runs and nothing is sent anywhere; it only confirms the secret exists and writes a `SECRET_USE` audit row |
| `POST /v1/secrets/{namespace}/{name}/revoke` | token | — | Same as delete in this server |
| `POST /v1/rotate` | token | `{"target": "master" \| "dek"}` | `{"ok": true, "target", "key_epoch"}`. Only increments an epoch counter: there are no keys to rotate |
| `GET /v1/audit` | token | Query `limit` (1–1000, default 50) | `{"entries": [{timestamp, event, principal, detail, hash}]}` for the last `limit` entries |
| `POST /v1/audit/verify` | token | — | `{"ok": bool}`: the in-memory SHA-256 chain recomputes. Does **not** detect tail truncation or a rebuilt chain ([SECURITY.md](../../.github/SECURITY.md#audit-chain-limitations)) |
| `POST /v1/policy/simulate` | token | `{agent, namespace, purpose, action="read"}`; `agent`, `namespace` required | `{"allowed": true, "reason": "simulated - all access granted in stub", …}`. **Gap (Go)**: always allows |
| `GET /v1/actions` | token | — | Static list: `echo`, `http_get_with_auth`, `http_post_with_auth`, `openai_chat`. **Gap (Go)**: names only; none is implemented |

Audit entries are written for set, use, revoke/delete and rotate. Unauthorized
requests are **not** audited (**Gap (Go)**, RGT-233/413).

### Behaviour documented elsewhere that Go does not have (Gap (Go))

These exist in the legacy Python server (see below) and are required for
parity:

- `POST /v1/capabilities/execute`, `GET /v1/capabilities`,
  `GET /v1/capabilities/list` — capability tokens and registry.
- `GET /v1/requests`, `POST /v1/requests/{id}/approve`,
  `POST /v1/requests/{id}/deny` — operator approvals with TOTP.
- `limit` / `offset` pagination and a required `agent` on `GET /v1/secrets`.
- Content-Type, Accept, Host-header, CSRF and URL-normalization middleware.
- Honeytokens, rate limiting, lockout, and ABAC on every route.

### Gateway admin paths (`go/cmd/gateway`, transitional)

| Method & path | Auth | Notes |
|---|---|---|
| `PUT` or `POST /__cutover?go=N` | **none** | Sets the percentage of traffic sent to the Go server (0–100, clamped); 400 on a missing or non-integer `go` |
| `GET /__cutover/stats` | **none** | `{go_percent, python_reqs, go_reqs, go_fails}` |

All other paths are proxied. These admin paths are unauthenticated (RGT-162);
reach them only from a trusted loopback or management network. The gateway goes
away with the Python line.

### Client programs

| Client | Talks to | Notes |
|---|---|---|
| `rgt-vault` CLI (`go/cmd/rgt-vault`) | `/v1/secrets`, `/v1/rotate`, `/v1/audit`, `/v1/audit/verify`, `/v1/policy/simulate`, `/healthz` | One subcommand per route; `--host` and `--token` flags |
| `rgt-vault tui` (`go/internal/tui`) | Same routes | Approval queue needs `/v1/requests*`, which Go does not have (**Gap (Go)**) |
| `rgt-vault mcp` (`go/internal/mcp`) | `/v1/secrets` (list and read) and `/v1/secrets/{ns}/{name}/revoke` | Tools `list_secrets`, `lease_secret` (returns plaintext), `revoke_secret`; see the [MCP guide](mcp.md) |

---

<a id="legacy-python-http-api"></a>

# Legacy Python HTTP API

> **End-of-life.** Documented as the reference for behaviour the Go server still
> lacks. No new features land here; it is removed once Go reaches parity.

Everything below was taken from the route definitions in
`python/server/app.py` (the legacy Python server, started by
`python -m rgt_vault.cli serve`) and compared with the Go routes above. A
route that exists on only one server is marked. The interactive OpenAPI pages `/docs`, `/redoc` and
`/openapi.json` are served by the Python app **only when `APP_ENV` is not
`production`**.

## Conventions

| Topic | Behavior |
|---|---|
| Base URL | `http://127.0.0.1:8765` (Python `serve` default); Go server `:8080` |
| Authentication | `Authorization: Bearer <token>` on every route except those marked *public*. The Python server also accepts the bare token without `Bearer ` (convenient for local clients) |
| Token kinds | **Agent token** (all `/v1/*` routes except approvals) and **operator token** (`/v1/requests*`). If the daemon is started without `--operator-token-file`, the operator routes accept the agent token as well |
| Identity | The acting agent is the `agent` / `agent_id` field of the request, **not** derived from the token on the plain HTTP routes (see threat model, privilege escalation) |
| Request bodies | `Content-Type: application/json` is required for `POST`/`PUT`/`PATCH` bodies on `/v1/*` (else 415) |
| `Accept` | If sent, it must allow `application/json`, `*/*` or `application/*` (else 406) |
| Host header | Python accepts only `localhost`, `127.0.0.1`, `[::1]` (DNS-rebinding guard); other hosts get 400 |
| Path normalization | Paths containing `..`, `\`, `//` or control characters are rejected with 400 |
| CSRF | State-changing requests that carry a valid bearer token skip CSRF. Requests without one must pass the double-submit `csrf_token` cookie / `X-CSRF-Token` header check, else 403 |
| Response headers | `Content-Security-Policy: default-src 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Content-Disposition: attachment` on API responses |
| Transport | **Plain HTTP.** Neither server terminates TLS; bind to loopback or put a TLS-terminating reverse proxy in front |

### Error format

```json
{"error": "PolicyDeniedError", "detail": "…", "incident_id": "3f2a9c0d1b7e"}
```

| Status | Error | Meaning |
|---|---|---|
| 400 | `ValidationError`, `CapabilityVersionError`, other `VaultError`; bad `limit`/`offset`/`target` | Client error |
| 401 | `ServerAuthError` | Missing, empty or wrong bearer token |
| 403 | `PolicyDeniedError`; `PermissionError` (honeytoken, rate limit); CSRF failure | Denied by policy, approval, hook, lockout or freeze |
| 404 | `SecretNotFoundError`, `ActionNotFoundError`, `CapabilityNotFoundError` | Unknown object |
| 406 / 415 | `NotAcceptable` / `UnsupportedMediaType` | Content negotiation |
| 409 | HTTP detail | `/v1/requests*` when no approval broker is active |
| 422 | FastAPI validation body (no `incident_id`) | Request body does not match the model |
| 500 | `ActionExecutionError`, `InternalServerError` | Handler fault; detail is generic, the traceback is in the server log |

Errors raised as `VaultError` subclasses and unhandled exceptions use the
shape above. Errors raised directly by a route as `HTTPException` (bad
`limit`, `offset` or `target`, malformed action params, no approval broker,
bad TOTP code on approve) use FastAPI's default `{"detail": "…"}` without
`error` or `incident_id`, and the middleware errors (406, 415, CSRF 403) use
`{"error", "detail"}` without `incident_id`. The Go server uses
`{"error","detail"}` for its own errors.

## Routes

### Health and housekeeping

| Method & path | Auth | Servers | Notes |
|---|---|---|---|
| `GET /healthz` | **public** | Py, Go | Python returns `status`, `vault_id`, `key_epoch` and the registered action names; Go returns `status`, `vault_id`, `key_epoch`, `version` (empty in production). Both disclose the vault id and key epoch to any caller that can reach the port |
| `GET /crossdomain.xml`, `GET /clientaccesspolicy.xml` | **public** | Py, Go | Return a restrictive policy with status 404 and no-cache headers |
| `GET /docs`, `/redoc`, `/openapi.json` | public | Py (non-production only) | Swagger UI / ReDoc with SRI-pinned CDN assets |

### Secrets

| Method & path | Auth | Servers | Request | Success response |
|---|---|---|---|---|
| `POST /v1/secrets` | agent | Py, Go | JSON `{name, value, namespace="default", agent="cli", purpose="", note="", require_2fa=false}` (Python); Go: `{name, value, namespace, agent, purpose}` | `{"ok": true, "namespace", "name"}` |
| `GET /v1/secrets` | agent | Py, Go | Query `namespace`, `agent` (both required in Python), `purpose`, `limit` (1–1000, default 100), `offset` (≥ 0) | Python: `{"namespace", "secrets": [{secret_id, name, latest_version, created_at, updated_at, status, note, require_2fa}]}` (no values). **Go: the list includes each secret's `value`** |
| `GET /v1/secrets/{namespace}/{name}` | agent | **Go only** | — | Metadata without the value |
| `DELETE /v1/secrets/{namespace}/{name}` | agent | **Go only** | — | Removes the secret |
| `POST /v1/secrets/{namespace}/{name}/use` | agent | Py, Go | JSON `{action, agent, purpose="", params={}}`. `action` must be a registered action; `params` keys must be in that action's `params_schema` | `{"ok": true, "action", "result"}`. The secret is leased, passed to the action and wiped; it is **not** returned. Go: stub result only |
| `POST /v1/secrets/{namespace}/{name}/revoke` | agent | Py, Go | Python: query `agent` (default `system`) | `{"ok": true, "namespace", "name"}` |

Python `use` passes through the full chain: hook, rate limit, honeytoken
check, ABAC, approval gate (with TOTP for `require_2fa` secrets). Denials
return 403; a timeout or denied approval returns 403.

### Capabilities (Python only)

| Method & path | Auth | Request | Success response |
|---|---|---|---|
| `POST /v1/capabilities/execute` | agent | JSON `{capability, agent_id, capability_token, payload={}, capability_version=1}` | `{"ok": true, "capability", "result"}` |
| `GET /v1/capabilities` | agent | — | `{"capabilities": [{name, description, supported_versions, params_schema}]}` |
| `GET /v1/capabilities/list` | agent | Query `agent` (required), `namespace="*"`, `purpose="*"` | `{"agent", "capabilities": […]}` filtered by the ABAC decision for that agent |

`capability_token` is a v2 HMAC token (`HMACTokenVerifier.sign`). Failure
modes: 400 (no verifier configured, malformed body, unsupported version), 403
(bad signature, expired, agent/capability/version mismatch, binding violation,
hook denial, frozen vault, lockout after 100 failed verifications per hour),
404 (unknown capability), 500 (handler fault, sanitized). **`python -m rgt_vault.cli serve`
does not configure a verifier on this commit, so the endpoint answers 400 until
the app is built with one** (`build_app` callers can pass a `VaultManager` that
has `token_verifier=` set).

### Operator approvals (Python only)

| Method & path | Auth | Request | Success response |
|---|---|---|---|
| `GET /v1/requests` | operator | — | `{"requests": [{request_id, agent, namespace, secret_name, purpose, action, require_2fa, created_at}]}` (never a secret value). 409 if no broker |
| `POST /v1/requests/{request_id}/approve` | operator | `{totp_code?: string, operator="operator"}` | `{"ok": true, "request_id", "decision": "approved"}`; 400 on a bad or missing TOTP code or unknown id |
| `POST /v1/requests/{request_id}/deny` | operator | `{reason="denied by operator", operator="operator"}` | `{"ok": true, "request_id", "decision": "denied"}` |

### Administration

| Method & path | Auth | Servers | Request | Success response |
|---|---|---|---|---|
| `POST /v1/rotate` | agent token (no operator scope on this commit) | Py, Go | `{"target": "master" \| "dek"}` | `{"ok": true, "target", "key_epoch"}`; 400 for any other target |
| `GET /v1/audit` | agent | Py, Go | Query `limit` (1–1000, default 50) | `{"entries": […]}`; Python returns newest first |
| `POST /v1/audit/verify` | agent | Py, Go | — | `{"ok": bool}`. `true` means the chain is internally consistent; it does **not** detect tail truncation or a rebuilt chain ([SECURITY.md](../../.github/SECURITY.md#audit-chain-limitations)) |
| `POST /v1/policy/simulate` | agent | Py, Go | `{agent, namespace, purpose="", action="read"}` | `{"allowed", "reason", "matched_rule"}`. **Go always answers `allowed: true`** (stub). Python also writes a `SIMULATION_RUN` audit row |
| `GET /v1/actions` | agent | **Go only** | — | Static list of the four built-in action names |

Every authenticated Python request writes an `HTTP_API` (or `HTTP_OPERATOR`)
audit row with the token id, client IP, method and path. The row is written
before the handler runs, so it does not record the response status. A request
that fails authentication is not written to the audit log on this commit.

### Built-in actions

Used with `/use`. Parameters not listed in an action's `params_schema` are
rejected (400).

| Action | Params | What it does |
|---|---|---|
| `echo` | `message` | Diagnostic; confirms a lease worked and never returns the secret |
| `http_get_with_auth` | `url`, `headers` | GET with the secret as a Bearer token |
| `http_post_with_auth` | `url`, `body`, `headers` | POST with the secret as a Bearer token |
| `openai_chat` | `model`, `messages`, `base_url`, `max_tokens`, `temperature` | POST to an OpenAI-compatible `/v1/chat/completions` endpoint |

Outbound URLs must be `http`/`https` and are refused if they resolve to a
loopback, link-local, private, reserved, multicast or unspecified address
unless the server was started with `--allow-private-network`.

---

# Legacy Python library API

> **End-of-life.** The Python library is legacy and will be removed.

`VaultManager` accepts any `MasterSecretProvider`. If none is given, a platform-appropriate one is selected:

| Platform | Provider | Backing store |
|---|---|---|
| Windows | `WindowsDPAPIProvider` | DPAPI-sealed blob (`VAULT_DPAPI_BLOB`) |
| macOS | `MacOSKeychainProvider` | Keychain item |
| Linux | `LinuxTPMProvider` | TPM-sealed blob (`tpm2-tools`) |
| any | `KeyringProvider` | `keyring` Secret Service (dev default) |

Platform providers require you to **seal** the master secret first (see each provider's `seal_master_secret` helper). For a zero-setup start, pass `KeyringProvider()` explicitly.

```python
# Fast rotation: re-wraps the DEK under a new master key. Does NOT re-encrypt
# secrets. Use on suspected master-secret/OS compromise.
vault.rotate_master_key()

# Slow rotation: generates a new DEK and re-encrypts every secret. Use on
# suspected DEK/memory compromise. Recommended periodically.
vault.rotate_dek()
```

`KeyringProvider` supports automated rotation. DPAPI/TPM providers require re-sealing the master secret out-of-band.

```python
blob = vault.export_vault()          # base64 JSON; secret values stay encrypted
# ... store `blob` somewhere durable ...

# Restore MUST target the same vault: same vault_id and the original
# keychain.json (DEK). Importing into a different vault is refused.
vault.import_vault(blob)
```

Back up `vault.db` **and** `keychain.json` together. The master secret lives in the OS store and is backed up separately according to your OS's mechanism.
