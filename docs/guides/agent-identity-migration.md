# Agent identity: migrating to per-agent tokens (Go line, batch H1)

**This is a breaking change** to the HTTP API and the CLI of the Go line.

## What changed

Before H1, the Go server (like Python) had **one shared bearer token** (`server.token`) for every
client. The ABAC subject was whatever `agent` the request body or query named, so any client
holding the token could act as any agent. A second shared file (`operator.token`) guarded only the
approval endpoints.

From H1, `rgt-vault serve` authenticates against a **per-agent token store**:

- `~/.config/rgt-vault/tokens.json` (flag `--token-store`, env `RGT_VAULT_TOKEN_STORE`), mode 0600.
  It maps `sha256(token)` to `{id, agent_id, scopes, created_at, expires_at}`. It holds **hashes
  only**: a token's plaintext is shown once, when it is minted, and can't be recovered.
- **The token decides the agent.** The server derives the ABAC subject from the token. A request
  that names a different agent (`agent` / `agent_id` / `operator` in the body, `?agent=` in the query)
  gets **403** and an `AUTHZ_DENIED` audit row. The field may be left out, or may repeat the
  token's own agent.
- **Scopes** decide which routes a token reaches:

  | Scope      | Routes                                                                                   |
  |------------|------------------------------------------------------------------------------------------|
  | `agent`    | secrets set / list / use / revoke / fingerprint, `/v1/policy/simulate`, `/v1/capabilities*`, `/v1/actions`, all as the token's own agent and under ABAC |
  | `lease`    | together with `agent`: `POST /v1/secrets/{ns}/{name}/lease`, the only route that returns a plaintext value |
  | `audit`    | `GET /v1/audit`, `POST /v1/audit/verify`                                                 |
  | `operator` | `/v1/requests*` (approve / deny), `POST /v1/rotate`, and everything `audit` reaches. It may also simulate or list capabilities for another agent |

  There is no policy-changing HTTP endpoint. The policy is a file that `serve` reads at startup.
- Missing, unknown, revoked and expired tokens all get the same generic **401**. Each failure writes
  an `AUTH_FAILED` audit row: client IP, route, reason, and at most a short token id (the store
  record id, or an 8-hex sha256 prefix). The row never contains the token. More than 10 failures from
  one address in one minute get **429**, plus one `AUTH_RATE_LIMITED` row per window. A valid token
  from that address keeps working.
- **`GET /v1/secrets?name=` (the plaintext route from decision D5) is removed** (RGT-504). It now
  returns 400. Read a value with `POST /v1/secrets/{namespace}/{name}/lease` (optional body
  `{"purpose": "..."}`), which needs the `lease` scope, or with `rgt-vault get --offline` on the
  vault files.
- **The fingerprint route** `GET /v1/secrets/{namespace}/{name}` now checks ABAC `read` for the token's agent.
  A secret the agent may not see, a secret that does not exist, a revoked one and a missing `?version=` all get the
  same 404 (`SecretNotFoundError`), so the route reveals nothing about another agent's secrets or versions. Each
  denial writes an `AUTHZ_DENIED` row.
- `POST .../use`, `/v1/policy/simulate` and `/v1/capabilities/execute` no longer require
  `agent` / `agent_id`: the token supplies it.

## Migrating

1. **Create the store and an operator token** (idempotent):

   ```bash
   rgt-vault init
   ```

   This mints an operator token for agent `operator` with scopes `agent,audit,operator`. It has no
   `lease` scope: the operator reads plaintext with `rgt-vault get --offline`. Its plaintext goes to
   `~/.config/rgt-vault/operator.token` (0600), which the TUI and the operator commands read.
   - An existing `operator.token` from a pre-H1 `init` that is not in the store yet is **imported
     with the `operator` scope only**: exactly its old privilege, the approval endpoints. Its holder
     keeps working for approvals but gains nothing.
   - If that file is readable by other users (Unix group or other bits), the token may be exposed,
     so `init` refuses to import it. Run `init --force` to mint a new one (recommended), or
     `--force-import` to import it anyway with a warning.
   - `init --force` mints a new operator token and revokes the replaced one.
   - `init` no longer creates `server.token`.

2. **Mint one token per agent**, with the fewest scopes it needs:

   ```bash
   rgt-vault token mint --agent research_agent --out ~/.config/rgt-vault/research.token
   rgt-vault token mint --agent deploy_bot --scope agent,lease --expires 720h --out deploy.token
   rgt-vault token mint --agent auditor --scope audit --expires 24h
   ```

   Without `--out` the token is printed once. With `--out` it goes to a new 0600 file and is not
   printed.

3. **Give each client its own token, explicitly**: `--token`, `RGT_VAULT_TOKEN`, or
   `RGT_VAULT_TOKEN_FILE=path`. The CLI never silently picks the operator token for an agent:
   - **`rgt-vault mcp`** uses only these explicit sources. Without one it refuses to start, and it
     refuses `--as-operator`. An agent harness with a missing or mistyped token variable therefore
     fails instead of running as the operator.
   - **Agent commands** (`set`, `get`, `list`, `revoke`, `simulate`, `fingerprint`) use the explicit
     sources, then the legacy `~/.config/rgt-vault/server.token`. They fall back to
     `~/.config/rgt-vault/operator.token` only with `--as-operator`, which the human operator passes
     on purpose. Without a token they fail before sending anything.
   - **Operator commands** (`tui`, `audit`, `verify-audit`, `rotate`) fall back to `operator.token`,
     then `server.token`.
   - MCP no longer sends the `mcp-client` label, and the TUI no longer sends `operator` / `tui`. Set
     `--agent` / `RGT_VAULT_MCP_AGENT` only for a legacy server.

4. **Fix the ABAC policy subjects.** Rules now match the agent in the token. A client that used to
   claim `"agent": "x"` must be minted as agent `x`, or the policy must name its new agent id.

5. **Remove the legacy token files** once every client has moved: `server.token`, and the old
   operator file if `init` did not import it. A shared token that only one agent used can be kept
   as that agent's token:

   ```bash
   rgt-vault token import --file ~/.config/rgt-vault/server.token --agent ci_runner --scope agent
   ```

   Only do this when exactly one client holds the file: everyone who holds it becomes `ci_runner`.

6. **Restart `serve`** without `--token-file` / `--operator-token-file`. Those flags now need
   `--legacy-shared-token`, and `serve` refuses to start without it. `serve` also refuses to start
   when the store has no tokens.

Day-to-day token management works against a running server. The server re-reads the store at the
next request, so you don't need to restart it:

```bash
rgt-vault token list                 # id, agent, scopes, created, expiry; never hashes or tokens
rgt-vault token rotate tok_1a2b...   # new token, same agent and scopes; the old one stops working
rgt-vault token revoke tok_1a2b...
```

## Legacy mode (temporary)

`rgt-vault serve --legacy-shared-token [--token-file F] [--operator-token-file F]` keeps the
pre-H1 identity model: one shared token, the self-asserted `agent` field, and the operator file for
`/v1/requests*` only. It logs a deprecation warning at startup. `rgt-vault init
--legacy-shared-token` creates the old token files.

**Legacy mode enforces no scopes.** Any holder of the shared token can act as any agent it names.
To limit the damage, legacy mode by default **refuses** (403, audited) the routes that were the
worst pre-H1 exposure:

- the plaintext lease route;
- `/v1/rotate`;
- `/v1/audit` and `/v1/audit/verify`.

Use `rgt-vault get --offline` and `verify-audit --offline` on the vault host instead. If you need the
full pre-H1 behaviour for a while, add `--legacy-allow-privileged-routes`. It logs a second warning:
every token holder can then read every secret, rotate keys and read the audit log.

Also in legacy mode:

- The plaintext route is `POST .../lease`, not `GET ?name=`.
- The fingerprint route keeps Python's ungated behaviour.
- MCP and TUI clients must set `--agent` (or `SetAgent`) if the server needs one: `use`,
  `simulate` and `capabilities/execute` still require the field in legacy mode.

Legacy mode will be removed in a later release. Don't use it for more than one agent: every holder
of the token can act as every agent.

## Not covered (open items)

- Tokens are static bearer credentials with an optional expiry. They are not short-lived session
  tokens, and there is no periodic re-authentication (ASVS 3.3.2 / 3.5.2; see
  `docs/security/asvs/V4.md`).
- There is no `token` HTTP API. Tokens are managed only with the CLI, on the host that owns the
  store file.
- Transport is still plain HTTP on loopback (TLS is batch H6).
- **Windows:** the `0600` / `0700` modes are not owner-only ACLs on Windows, and the code does not
  set ACLs. `tokens.json` (hashes only), `operator.token` and `--out` files rely on the ACL of the
  user profile directory they sit in. Keep them under your profile (the default
  `%USERPROFILE%\.config\rgt-vault`), not in a shared directory (RGT-501).
