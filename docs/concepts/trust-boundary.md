# Trust Boundary

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

That claim is true **by construction**, regardless of deployment.

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

The repo ships the pieces to do this on Linux:

- `deploy/rgt-vault.service` — a hardened systemd unit that runs the daemon
  as a dedicated `rgtvault` user with `ProtectSystem=strict`,
  `NoNewPrivileges`, a private `/tmp`, and a single writable state dir.
- `deploy/setup-daemon.sh` — creates the `rgtvault` account, locks the state
  dir to `0700`, installs the app, and mints **two** tokens.

The agent's user account has no read access to `/var/lib/rgt-vault`. It holds
only the **agent token** and talks to `http://127.0.0.1:8765`. The **operator
token** (a separate credential) is the only thing that can approve or deny a
request, so an agent cannot self-approve even if it obtains the agent token.

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
