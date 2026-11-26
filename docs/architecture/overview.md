# Architecture Overview

RGT Vault separates the **capability execution model** from the underlying **secure secret storage**.

> **Direction (2026-11-26).** The Go line (`go/`) is the only maintained
> target. The Python line (`python/`) is end-of-life: no new features, removed
> once Go reaches parity. This page describes both: Go as the product, Python as
> the legacy reference for behaviour Go has not built yet. Items missing from Go
> are marked **Gap (Go)**. Much of the design below (capability execution,
> storage, key hierarchy) is what the Go line is *meant* to provide; today the
> Go server is an in-memory skeleton.

This layered approach ensures that agents only receive the capabilities they are authorized to use, while the highly sensitive secret material is protected by a robust cryptographic key hierarchy.

*   **[Execution Flow](execution-flow.md):** How the Vault intercepts requests, verifies tokens, and executes capabilities.
*   **[Cryptography](crypto.md):** How the Vault secures data at rest using AES-GCM, Argon2id, and OS-native keychain APIs.
*   **[Threat model](../security/threat-model.md):** Assets, trust boundaries, the data-flow diagram, and what is not defended.
*   **[Trust boundary](../concepts/trust-boundary.md):** Same-user (soft) versus separate-account (hard) deployment.
*   **[ADRs](../adr/README.md):** Why ABAC, why a hash-chained audit log, why a capability model, how keys are layered.
*   **[API reference](../guides/api.md):** Every HTTP route, with its authentication and failure modes.

Everything below was checked against the code on the commit that introduced
this page. Where an implementation is a stub or an earlier document
over-claimed, it says so.

## Components and what each one is for

This is the component inventory for RGT-229 / RGT-255: each component, the
business or security function it provides, and where it lives.

### Go line (primary)

| Component | Path | Business function | Security function / status |
|---|---|---|---|
| Server | `go/cmd/server`, `go/internal/server` (chi router, middleware, handlers) | REST API for secrets, rotate, audit, policy simulation, action listing | Bearer auth, CORS, security headers. **Gap (Go)**: store is an in-memory plaintext map, policy is allow-all, no TLS, no per-agent identity |
| Auth | `go/internal/auth` | File-backed bearer token, token id for logs | Constant-time compare; token is stored and printed in plaintext by `cmd/server`, never expires |
| Crypto / KDF | `go/internal/crypto`, `go/internal/kdf` | AES-256-GCM (12-byte random nonce, AAD) and Argon2id/HKDF helpers | Sound and tested, wire-compatible with the Python format, but **not imported by any non-test Go code** (**Gap (Go)**: unused) |
| CLI | `go/cmd/rgt-vault` | One subcommand per API route, plus `serve`, `init`, `status`, `mcp`, `tui` | Holds the bearer token |
| TUI | `go/internal/tui` | Operator console (secrets, audit, rotate) | **Gap (Go)**: no approval queue because the server has no `/v1/requests*` |
| MCP bridge | `go/internal/mcp` | stdio JSON-RPC server exposing `list_secrets`, `lease_secret`, `revoke_secret` | `netguard` dialer; `lease_secret` returns plaintext to the client |
| `netguard` | `go/internal/netguard` | Outbound dialer guard | Blocks link-local always, non-loopback unless opted in |
| Gateway | `go/cmd/gateway`, `go/internal/gateway` | Percentage-based cutover proxy between the Python and Go servers (transitional) | Go failures fall back to Python. Admin paths unauthenticated |

### Legacy Python line (reference until removed)

| Component | Path | Business function | Security function |
|---|---|---|---|
| `VaultManager` | `python/vault.py` | Set/lease/revoke/rotate secrets; execute capabilities; export/import | **The single enforcement point**: hook → rate limit → honeytoken → ABAC → approval gate → decrypt → audit, in that order (`lease_secret`) |
| ABAC engine | `python/auth.py` | Loads a YAML policy | Default-deny; explicit `deny` beats any `allow` |
| Crypto | `python/crypto.py`, `python/keychain.py` | AES-256-GCM encrypt/decrypt; DEK wrapping | 96-bit random nonces, AAD `vault_id:namespace:name`, Argon2id + HKDF-SHA512 for the key-encryption key |
| Storage | `python/storage/sqlite.py` | Secrets, versions, honeytokens, audit rows (one SQLite file) | Hash-chained audit rows written in the same transaction as the change |
| Providers | `python/providers/*` | Fetch the master secret (DPAPI, macOS Keychain, Linux TPM tools, Secret Service) | Keep the root of trust out of the repo and the DB. **Gap (Go)** |
| Capability tokens | `python/token.py`, `python/capabilities.py` | Action-scoped HMAC tokens (v2) and a capability registry | Binds agent, capability, version, context and expiry. **Gap (Go)**; **Ed25519 is a stub in both lines** (`Ed25519TokenVerifier` raises `NotImplementedError`) |
| Hooks and approval | `python/hook.py`, `python/approval.py`, `python/totp.py` | Webhook / SOAR gate, human approval with TOTP | Fail-closed. **Gap (Go)** |
| HTTP server | `python/server/app.py`, `auth.py`, `actions.py` | The `/v1/*` API, built-in outbound actions | Bearer auth, security headers, CSRF, content-type enforcement, SSRF guard. **Gap (Go)** for everything beyond headers and bearer auth |
| CLI / TUI | `python/cli.py`, `python/tui.py` | Operator workflows | Holds the operator token |
| Shadow writer | `python/shadow.py` | Dual-write migration mirror to the Go server | Python stays authoritative; failures audited, never raised |
| MCP server | `python/server/mcp_server.py` | FastMCP experiment | Fails closed; not a supported path |
| Input validation | `python/input_validation.py` | Name / namespace / agent allow-lists | Applied in `VaultManager`. **Gap (Go)**: handlers only check for empty fields |
| `internal/llm` | `internal/llm/` | Developer tooling: LLM router, kanban loop | Outside the vault trust boundary |

### Where security controls live (and where they are duplicated)

RGT-230 asks for centralized, reusable controls. The honest picture:

| Control | One home? | Go | Legacy Python |
|---|---|---|---|
| Authorization (ABAC) | Should be | **Gap (Go)**: none | Yes: `VaultManager` calls `auth.evaluate`; handlers make no decisions |
| Encryption / key handling | Yes in both libraries | Library exists in `internal/crypto`, unused | `crypto.py` + `keychain.py` only |
| Audit chain | Yes | `Store.AddAuditEntry` (in memory) | `storage.log_audit` / `_append_audit_in_tx` |
| Input validation | No | Per-handler empty checks | `VaultManager._validate_string_param` plus pydantic models |
| Outbound network guard | **No** | `netguard` (dialer) | `actions._validate_outbound_url`; none on `WebhookHook` / `ShadowWriter` |
| Caller authentication | **No** | One shared bearer token, self-asserted `agent` | Same on the plain HTTP path; signed capability token is the stronger path but `serve` does not wire a verifier |

## Business logic

RGT-254: the rules the system implements, in one place. The behaviour below is
what the legacy Python code does today; the **Go** note on each item says
whether the Go server does it.

1. **Store.** Validate names, encrypt with the DEK under AAD, mark the previous
   version `SUPERSEDED`, insert the new version, write the audit row, all in one
   transaction. A new version does not inherit the previous `require_2fa` flag.
   *Go:* **Gap (Go)** — overwrites a map entry in plaintext; only audit is
   written (separately).
2. **Use a secret.** `POST /v1/secrets/{ns}/{name}/use`: hook, rate limit
   (default 100/hour/agent), honeytoken check, ABAC, approval gate, decrypt into
   a mutable buffer, run the named action, zeroize, audit. The value is not
   returned. *Go:* **Gap (Go)** — stub that checks existence and audits.
3. **Execute a capability.** `POST /v1/capabilities/execute`: freeze check, HMAC
   token verification, agent/capability/version match, context-binding check,
   hook, handler lookup, params validation, rate limit, handler; every outcome
   audited. *Go:* **Gap (Go)** — no capabilities.
4. **Approve.** With `--require-approval`, a gated request waits (timeout fails
   closed) until an operator approves or denies; `require_2fa` secrets need a
   replay-guarded TOTP code. *Go:* **Gap (Go)**.
5. **Rotate.** Master rotation re-wraps the DEK and bumps the epoch; DEK
   rotation re-encrypts every secret and also happens automatically after 100M
   encryptions or 512 GiB. *Go:* **Gap (Go)** — `rotate` only increments a
   counter.
6. **Honeytokens.** Reading a registered decoy raises a critical
   `HONEYTOKEN_TRIGGERED` row and denies the call. *Go:* **Gap (Go)**.
7. **Backup.** Export is base64 JSON with ciphertext; import replaces secrets,
   audit rows and honeytokens wholesale, refuses another `vault_id`, and has no
   integrity tag beyond that id (RGT-377). *Go:* **Gap (Go)**.
8. **Audit.** Each row's hash covers the previous hash and the row's fields;
   `verify` recomputes the chain. Tamper-evident for edits and head/middle
   deletes, not for tail truncation or a rebuilt chain. *Go:* in-memory only.

## Remote services the system talks to

| Service | Direction | Authenticated by | Control |
|---|---|---|---|
| Backend for MCP bridge / Go CLI / TUI | client → Go server | Bearer token | Plain HTTP; `netguard` dialer |
| LLM/HTTP APIs named by legacy `openai_chat`, `http_*_with_auth` | vault → internet | The leased secret as Bearer | Outbound URL guard, default TLS verification. **Gap (Go)**: stub |
| Webhook / SOAR hook (legacy) | vault → operator URL | Optional bearer token | Any failure denies; 5 s timeout. **Gap (Go)** |
| Go shadow server (legacy migration) | Python → Go | Bearer token | Failure audited, never raised |
| OS secret store / TPM tools (legacy) | vault → local OS | OS identity | Local only. **Gap (Go)** |

## Data flow

The diagram and the trust-boundary table are in the
[threat model](../security/threat-model.md#data-flow-diagram); they are kept
there so the diagram and the threat analysis do not drift apart.
