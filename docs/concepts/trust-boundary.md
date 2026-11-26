# Trust Boundary

> **Direction (2026-11-26).** Go (`go/`) is the only maintained line; the Python
> daemon is end-of-life and is described here as the legacy reference for the
> guarantees the Go line must reach (**Gap (Go)** marks what Go lacks today).
> The deployment advice (soft vs hard posture) applies to either line.

RGT Vault's value depends entirely on **where the boundary actually is**.
This page is deliberately blunt about what the project does and does not
protect against, because an over-stated security claim is worse than an
honest one.

## The claim, stated honestly

> **The agent never receives raw secrets through approved interfaces.**

An agent requests a *capability* (e.g. `openai.chat_completion`). The vault
evaluates policy, optionally asks a human to approve, leases the secret into
a server-side buffer, runs the action, and returns only the result. Through
the API, the secret value never reaches the caller.

That claim is true **by construction** for the legacy Python daemon's `/use` and
`/v1/capabilities/execute` endpoints, regardless of deployment: the response
contains the action result, never the secret. It is **not** true for every
surface in this repository, and the Go line (the target) does not meet it yet:

| Surface | Does the caller receive plaintext? |
|---|---|
| Go server `GET /v1/secrets` | **Yes** (**Gap (Go)**): each listed secret includes its `value`; the server is an in-memory plaintext store, not a protected one |
| Go MCP bridge `lease_secret` tool | **Yes**: it returns the secret value to the MCP client, i.e. to the agent ([MCP guide](../guides/mcp.md)) |
| Go server `POST /v1/secrets/{ns}/{name}/use` | No, but it is a stub: no action runs |
| Go CLI `get` | Yes, by design (a human at a terminal) |
| Legacy Python `/use` and `/v1/capabilities/execute` | No |
| Legacy Python CLI `get` and in-process `lease_secret` | Yes, by design |

Until the Go server has real capability execution (**Gap (Go)**), the claim
cannot be made for the Go line.

## What "the agent can never see it" actually requires

If the vault database, the master key (OS keyring), and the agent all run as
**the same OS user on the same machine**, then a *fully malicious* agent with
shell access can bypass the API entirely — read `vault.db`, pull the master
key from the keyring, or scrape process memory. In that setup the API
boundary is real against a *well-behaved or prompt-injected* agent, but it is
**not** a wall against arbitrary local code execution.

So there are two honest postures:

| Posture | Protects against | Does **not** stop |
|---|---|---|
| **Soft** (same host, same user) | prompt injection; an agent that respects the API; casual secret exfiltration into the model's context | a malicious agent with shell reading the DB / keyring directly |
| **Hard** (separate service account or container/VM) | all of the above **plus** direct access to secret material | physical host compromise, kernel compromise, root |

## Earning the stronger claim

Run the vault as its own locked-down account. Then you can honestly say:

> **The agent cannot directly access secret material.**

The repo ships the pieces to do this on Linux for the **legacy Python daemon**
(**Gap (Go)**: no systemd unit for the Go server yet, planned in RGT-232/263):

- `deploy/rgt-vault.service` — a hardened systemd unit that runs the daemon
  as a dedicated `rgtvault` user with `ProtectSystem=strict`,
  `NoNewPrivileges`, a private `/tmp`, and a single writable state dir.
- `deploy/setup-daemon.sh` — creates the `rgtvault` account, locks the state
  dir to `0700`, installs the app, and mints **two** tokens.

The agent's user account has no read access to `/var/lib/rgt-vault`. It holds
only the **agent token** and talks to `http://127.0.0.1:8765`. The **operator
token** (a separate credential) is the only thing that can approve or deny a
request, so an agent cannot self-approve even if it obtains the agent token.

Two limits of this split are worth knowing:

- The separation exists only when the legacy daemon is started with
  `--operator-token-file` (the shipped `deploy/rgt-vault.service` does this). Without it
  the approve/deny endpoints accept the agent token and the CLI warns.
  **Gap (Go)**: the Go server has one token and no approval routes.
- The agent token is **shared by every agent**, and `/use` trusts the `agent`
  name in the request body, so two agents using the same daemon can impersonate
  each other for ABAC purposes. Run one daemon (or one token scope) per trust
  level until per-agent identity lands (RGT-236 and related).

```
  ┌────────────┐   loopback HTTP + agent token   ┌──────────────────────┐
  │  LLM agent │ ───────────────────────────────▶│  rgt-vault daemon     │
  │ (user: ai) │   list titles / request use     │  (user: rgtvault)     │
  └────────────┘                                  │  vault.db, master key │
        ▲                                         │  0700, unreadable to  │
        │ result only, never the secret           │  the 'ai' user        │
        └─────────────────────────────────────────└──────────────────────┘
                                                              ▲
                            operator token + TOTP             │ approve / deny
                          ┌──────────────────────────────────┘
                          │  human at the TUI (their own account)
                          └──────────────────────────────────
```

On **Windows / macOS**, the equivalent is to run the daemon under a separate
local user account (or a container/VM) whose home and vault directory the
agent's account cannot read. The token split and the loopback API are the
same; only the OS mechanism for the separate account differs.

## What the TOTP second factor actually buys

Be precise about this rather than security-theatrical. Once you have a
separate operator account, a separate operator token, and the approval
console, the TOTP prompt on an approval defends against exactly one thing:

> **a stolen or misused operator token.**

If the operator token leaks (copied from the workstation, left in a shell
history, exfiltrated by something running as the human's user), 2FA means
the holder still cannot approve a release of a 2FA-flagged secret without
also having the live authenticator code.

What it does **not** add: if the operator's workstation is fully trusted and
uncompromised, the token already lives there and the TOTP is closer to demo
value than security value. That is a fine reason to keep it — it makes the
human-in-the-loop step legible in a demo — but the honest framing is "second
factor against a stolen operator token," not "makes approval unbreakable."
2FA is therefore opt-in per secret (`require_2fa`), so you can reserve the
friction for the credentials that actually warrant it.

## Other trust boundaries in the repository

The same-user/separate-account analysis above applies to whichever daemon you
run. The other components cross boundaries too; the full data-flow diagram and the
per-boundary authentication table are in the
[threat model](../security/threat-model.md#data-flow-diagram).

- **Go server and cutover gateway.** Neither enforces the vault guarantees yet.
  The Go server keeps secrets in plaintext memory and the gateway's `/__cutover`
  admin paths are unauthenticated; do not put real secrets behind them.
- **MCP.** An MCP client is an agent. See the table above for what each MCP
  path returns.
- **Outbound calls.** When an action uses a leased secret it sends it to a
  third party by design. The destination checks are described in the threat
  model; the trust placed in the destination is yours.

## What is explicitly out of scope

RGT Vault does **not** defend against full host compromise, a kernel-level
attacker, or physical access. For master-key protection against disk theft,
seal the key in a TPM (Linux), the Secure Enclave / Keychain (macOS), or
DPAPI (Windows) — see [crypto](../architecture/crypto.md). Hardware sealing
raises the bar on the *key at rest*; it does not change the agent-boundary
analysis above.

## See also

- [Security Model](security-model.md) — the zero-trust-for-agents premise.
- [Capabilities](capabilities.md) — what an agent requests instead of a secret.
