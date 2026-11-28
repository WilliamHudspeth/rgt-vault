# Go vs Python parity table (master `5a049d2`, 2026-11-27)

Appendix to [ASSESSMENT.md](ASSESSMENT.md).

**How to read the status column**

- **works**: I ran it on the Go binary and it did what it says (see [run-log.md](run-log.md)).
- **works (tests)**: not run by hand; covered by Go tests that pass (`go test -race ./...`).
- **partial**: present, with a gap that a user or a demo will hit.
- **missing**: not in Go.
- **dropped**: deliberately not ported; the reason is given.

Python sources: `python/cli.py`, `python/server/app.py`, `python/server/actions.py`,
`python/capabilities.py`, `python/hook.py`, `python/tui.py`, `python/server/mcp_server.py`, `examples/`.
The RGT-522 to RGT-541 keys are the issues filed by this assessment (ASSESSMENT.md section 11).

## 1. CLI subcommands

| Feature | Python | Go | Status | Issue |
|---|---|---|---|---|
| `init` | writes the bearer token file only | creates vault, token store and operator token; idempotent | works (Go does more). Fails on Linux without a Secret Service | RGT-522 |
| `serve` | `--host --port --policy --provider --require-approval --totp-secret-file --approval-timeout --operator-token-file --allow-private-network` | same, plus TLS, mTLS, per-agent token store, `--harness-key-file`, `--require-approval-for` | works | |
| `set` | in-process, `--agent --purpose` | over HTTP; value from stdin or `--value-file` | partial: no `--require-2fa` / `--note` flag (the API has both) | RGT-525 |
| `get` | in-process, prints plaintext, `--purpose` required | over HTTP needs a token with `agent,lease`; or `--offline` | works, but the documented quickstart `get` fails (operator token has no `lease` scope) and prints only `HTTP 403` | RGT-524, RGT-526 |
| `list` | yes | yes | works | |
| `revoke` | yes | yes | works | |
| `simulate` | offline, `--policy` file | asks the running server; `--agent X` needs operator scope | works (no offline form) | |
| `fingerprint` | yes | yes | works. RGT-502 says it always fails: no longer true | RGT-502 (close) |
| `rotate` | master or DEK | `--target master\|dek`, operator scope | works. Shared keyring entry: rotating one vault's master breaks every other vault of the same OS user | RGT-535 |
| `verify-audit` | yes | online and `--offline`; exit 2 and the first bad row id on tamper | works | |
| `audit` | "tail the audit log" | prints one line of raw JSON | partial: no table, no filter | RGT-527 |
| `status` | vault id, epoch, counts, chain | `status` (server up?) and `status --offline` (the Python output) | works | |
| `enroll-2fa` | yes | yes, audited `--force` | works. Its "start the daemon with" hint names a flag that now errors | RGT-524 |
| `tui` | Textual "Approval Center" | Bubble Tea dashboard | partial, see section 5 | RGT-528 |
| `export` / `import` | library only | CLI, Python-compatible v1 format | works. Import also succeeded while a server had the DB open (not investigated further) | RGT-377 (D7) |
| `migrate check` | n/a | yes | works | |
| `provider seal tpm\|dpapi\|macos` | library only | CLI | works (tests) for DPAPI on the Windows VM (RGT-501); TPM and macOS never run on real hardware | RGT-507, RGT-541 |
| `token mint\|list\|revoke\|rotate\|import` | n/a (one shared token) | yes | works; revoke takes effect on the running server | |
| `crypto-audit` | n/a | yes | works | |
| `mcp` | separate fastmcp module | subcommand | works, see section 6 | RGT-536 |
| `version` | n/a | only `--version`; prints `dev (commit none, built unknown)` from a plain `go build`; `/healthz` and MCP say `0.3.0` (hard-coded) | partial | RGT-531 |
| run an action (`use`) | n/a (examples call the library) | **no subcommand**: curl only | missing | RGT-525 |
| approve / deny / list requests | TUI only | TUI or curl; **no subcommand** | missing | RGT-525 |
| mint a capability token | library (`TokenVerifier.sign`) | **no command**; a harness must sign by hand | missing | RGT-519 |
| add a honeytoken | library (`storage.add_honeytoken`) | `store.AddHoneytoken` exists, nothing calls it | missing | RGT-538 |

## 2. HTTP API

| Route | Python | Go | Status |
|---|---|---|---|
| `GET /healthz` | yes | yes; returns vault id, key epoch, action names and `version: 0.3.0` without auth | works (RGT-531) |
| `POST /v1/secrets` | yes | yes (`require_2fa`, `note`) | works |
| `GET /v1/secrets` | names only | names only; `?name=` returns 400 "the name= filter was removed" | works. RGT-504 is done in code |
| `GET /v1/secrets/{ns}/{name}` | n/a | fingerprint | works |
| `POST /v1/secrets/{ns}/{name}/use` | yes | yes | works |
| `POST /v1/secrets/{ns}/{name}/lease` | n/a | returns plaintext to a token with `agent`+`lease` | works; by design, but it is the one path where a secret leaves the vault |
| `POST /v1/secrets/{ns}/{name}/revoke` | yes | yes | works |
| `POST /v1/rotate` | yes | yes, operator scope | works |
| `GET /v1/audit`, `POST /v1/audit/verify` | yes | yes, audit scope | works |
| `POST /v1/policy/simulate` | yes | yes | works |
| `GET /v1/requests`, approve, deny | yes | yes, operator scope, attempt cap, replay guard | works |
| `POST /v1/capabilities/execute` | fails closed (no verifier wired) | works with `--harness-key-file` | works; error mapping is rough (RGT-537) |
| `GET /v1/capabilities`, `/v1/capabilities/list` | yes | yes; `/list` returned `[]` for an agent that can execute `secrets.echo` | partial (RGT-537) |
| `GET /v1/actions` | n/a | yes | works |
| `/docs`, `/redoc`, CSRF cookie | yes | no | dropped (no browser surface; documented) |

## 3. What an agent can actually do with a secret

| Capability | Python | Go | Status | Issue |
|---|---|---|---|---|
| `http_get_with_auth` (secret as `Authorization: Bearer`) | yes | yes | works | |
| `http_post_with_auth` | yes | yes | works | |
| `openai_chat` | yes | yes | works (tests); not run against a real endpoint | |
| `echo` | yes | yes | works | |
| Restrict *where* the secret may be sent | no | `actions.Config.HostAllowlist` exists, `serve` never sets it: an agent allowed to use a secret can send it to any https host | **missing (security)** | RGT-523 |
| Other auth schemes (`token ...`, `x-api-key`, Basic, query param) | no | no: callers cannot set `Authorization`, and the scheme is always Bearer | missing in both | RGT-539 |
| Arbitrary in-process callback (`vault.execute(callback=...)`) | library API | no public Go API (`internal/` packages) | dropped (the Go line is a daemon, not a library) | |
| Env injection into a subprocess, git credential helper, ssh-agent | no | no | missing in both; the most asked-for "useful" actions for coding agents | RGT-539 |
| `secrets.echo`, `secrets.use` capabilities | yes | yes | works; a policy denial inside `secrets.use` comes back as HTTP 500 | RGT-537 |
| Named domain capabilities (`github.read_repo` in the README) | no (README fiction) | no | missing in both; README must stop showing it | RGT-530 |

## 4. Security features

| Feature | Python | Go | Status | Issue |
|---|---|---|---|---|
| AES-256-GCM, Argon2id + HKDF, keychain.json, SQLite schema | yes | byte-compatible | works (tests + compat suite) | |
| Hash-chained audit, tamper detection | yes | yes | works (tampered row 61 found) | |
| ABAC policy (deny wins, default deny, fnmatch) | yes | yes | works | |
| Policy `ttl` (lease lifetime) | used by the 2FA hook's v1 tokens | parsed, then unused by the vault and server | **partial: the documented "TTL-based leases" do nothing in Go** | RGT-540 |
| Per-agent identity and scopes | no (shared token, self-asserted agent) | yes | works (Go only) | |
| Approval broker, fail-closed timeout | yes | yes | works | |
| TOTP second factor, replay guard, attempt cap | yes | yes, state persisted across restarts | works | RGT-510 |
| Capability tokens v2 (HMAC), single use | yes | yes | works | |
| Capability tokens v3 (Ed25519) | stub | package only, not wired into `serve` | missing (wiring) | RGT-519 |
| Honey capabilities | no | yes (5 defaults + policy list) | works (Go only) | RGT-520 |
| Honeytokens (decoy secrets) | library only | store only | missing (no way to create one) | RGT-538 |
| Hooks: log, webhook, 2FA hook, freeze file, SIGUSR1/2 kill switch | library only | package only; `serve` always uses the Off hook | missing (wiring) in both; docs describe a "freeze" state | RGT-540 |
| Security event webhook | no | yes (`RGT_VAULT_SECURITY_WEBHOOK_URL`) | works (tests) | RGT-509 |
| SSRF guard for actions | partial | dial-time guard, https only, no redirects | works (loopback, metadata and http:// refused) | |
| Rate limiter, auth-failure limiter | yes | yes | works (tests) | |
| TLS, mTLS, cert reload | no | yes | works (tests) | |
| Structured logging with redaction | hooks | `internal/logging` exists; only error handling and the gateway import it; the server logs with the standard logger | missing (wiring) | RGT-512 |
| Legacy Fernet rows (`dek_version=0`) | migrates | refuses with instructions | dropped (decision D3) | |
| `AgentVaultClient`, `bypass_verification`, `email_verification`, shadow dual-write | yes | no | dropped (backdoors / dead code) | RGT-135 |

## 5. TUI

| Feature | Python (Textual) | Go (Bubble Tea) | Status | Issue |
|---|---|---|---|---|
| Pending requests, approve / deny | yes | yes | works | |
| TOTP prompt | yes | yes, typed one key at a time | partial: a pasted code is silently ignored | RGT-528 |
| Store a secret (title, value, note) | yes | no (read-only dashboard) | missing | RGT-528 |
| Secret list, fingerprints, 2FA and note columns, search, tree | no | yes | works | |
| Live audit stream | no | yes | works | |
| Rotate master with confirmation | no | yes | works (not pressed `y`) | |
| "Panic lock" (`P`) | no | clears the local list and quits; the server keeps serving | **misleading label** | RGT-528 |

## 6. MCP

| Feature | Python (fastmcp, in-process) | Go (stdio, over HTTP) | Status | Issue |
|---|---|---|---|---|
| Execute | `vault_execute` | `execute_secret` (action on a secret), `execute_capability` (needs a capability token) | works with a scripted client | |
| List | `vault_list_capabilities` | `list_secrets`, `list_capabilities` | works | |
| Plaintext | no | `lease_secret` (needs `lease` scope; refused for a plain agent token) | works | |
| Revoke | no | `revoke_secret` | works (policy-gated) | |
| Policy summary resource | `vault://policy` | `vault://policy` returns `{"default_ttl":300,"rules":null}` | partial (empty) | RGT-536 |
| Error detail to the agent | n/a | every denial is `backend error: 403 Forbidden`; the reason goes to stderr only | partial | RGT-536 |
| Tested with a real MCP client (Claude Code/Desktop) | no | not by me; SDK e2e tests pass | unverified | RGT-536 |

## 7. Providers and platforms

| Platform | Provider | Go status | Evidence |
|---|---|---|---|
| Linux desktop | Secret Service keyring | works in CI (`gnome-keyring` on a private bus) | review-gate `compat` job |
| Linux headless / server / systemd | none usable out of the box: no Secret Service; TPM needs `tpm2-tools` and a one-time seal, never run on real hardware | **blocked** | section A0 of the run log; `deploy/rgt-vault-go.service` comment "NOT verified on real TPM hardware" |
| Windows desktop | Credential Manager keyring | works | my VM run, RGT-501 |
| Windows non-interactive (SSH, service) | keyring fails with error 1312; DPAPI is the answer | DPAPI works (tests on the VM); no service install guide | RGT-501, my VM run |
| macOS | Keychain keyring / `security` | unverified: live tests hang on hosted runners, job dropped | RGT-507 |

## 8. Examples and docs

| Item | Python | Go | Status | Issue |
|---|---|---|---|---|
| "See it in 30 seconds" demos (`examples/*.py`) | 4 scripted scenarios, outbound call stubbed | none | missing | RGT-529 |
| README quick start | `pip install rgt-vault` (not on PyPI), `rgt-vault policy create`, `rgt-vault mcp start` (neither exists) | n/a | wrong for both lines | RGT-530 |
| Go quickstart (`go/README.md`, `docs/getting-started/installation.md`) | n/a | fails at `set` without `--as-operator`; `get` fails | broken as written | RGT-524 |
