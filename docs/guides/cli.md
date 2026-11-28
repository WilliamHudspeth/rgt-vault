# CLI Guide

`rgt-vault` is one binary with two kinds of subcommand:

- **Client commands** talk to a running `rgt-vault serve` over HTTP (`--host`, default
  `http://127.0.0.1:8765`): `set`, `get`, `list`, `revoke`, `simulate`, `fingerprint`, `rotate`,
  `audit`, `verify-audit`, `status`, plus `mcp` and `tui`. The bearer token comes from `--token`,
  `$RGT_VAULT_TOKEN` or `$RGT_VAULT_TOKEN_FILE`. There are only two file fallbacks:
  - `tui`, `audit`, `verify-audit` and `rotate` fall back to `~/.config/rgt-vault/operator.token`.
  - The agent commands fall back to it only with `--as-operator`.
  - `mcp` never uses a file fallback.
  - All but `mcp` finally try the legacy `~/.config/rgt-vault/server.token`.
- **Token commands** manage the per-agent token store: `token mint|list|revoke|rotate|import`.

**Identity (breaking change, batch H1):** every token belongs to one agent and carries scopes
(`agent`, `lease`, `audit`, `operator`); the server takes the ABAC subject from the token and
refuses a request that names another agent. See [agent-identity-migration.md](agent-identity-migration.md).
- **Vault commands** open the vault files themselves and need no server: `serve`, `init`,
  `enroll-2fa`, `export`, `import`, `migrate check`, `provider seal`, and the offline forms of
  `get`, `verify-audit` and `status`.

The vault is selected by three global flags (or environment variables), placed before or after
the subcommand: `--db` / `RGT_VAULT_DB` (default `~/.secure-vault/vault.db`; `keychain.json` lives next
to it), `--policy` / `RGT_VAULT_POLICY` (ABAC YAML; **without one every request is denied**) and
`--provider` / `RGT_VAULT_PROVIDER` (`keyring`, the default, or `platform`: DPAPI on Windows, the
Keychain on macOS, the TPM on Linux).

Exit codes: `0` ok, `1` error, `2` the audit chain does not verify.

## Set up

```bash
# Creates the vault (vault.db + keychain.json, master secret in the OS keyring), the per-agent
# token store (~/.config/rgt-vault/tokens.json, hashes only) and an operator token whose
# plaintext goes to ~/.config/rgt-vault/operator.token (0600). Safe to repeat.
rgt-vault init

# One token per agent, least privilege (shown once, or written 0600 with --out):
rgt-vault token mint --agent research_agent --out research.token            # scope agent
rgt-vault token mint --agent deploy_bot --scope agent,lease --expires 720h  # may read plaintext

# A minimal development policy (see policies.md for real ones):
cat > policy.yaml <<'YAML'
rules:
  - effect: allow
    agent: "*"
    namespace: "*"
    purpose: "*"
    action: "*"
YAML

rgt-vault serve --policy policy.yaml     # 127.0.0.1:8765, data persists across restarts
```

`init` never prints a token and never resets an existing vault. It mints the operator token with
the scopes `agent,audit,operator` (no `lease`: read plaintext with `get --offline`). An existing
operator token file that is not in the store yet is imported with the `operator` scope only. A file
that other users can read is refused unless you pass `--force-import`. `--force` mints a new operator token and revokes the
old one (never touching the vault); `--tokens-only` skips the vault; `--operator-agent` names the
operator token's agent (default `operator`); `--harness-key-file PATH` also creates the HMAC key for
v2 capability tokens. `--legacy-shared-token` creates the pre-H1 shared `--token-file` and operator
file instead. A token file below 32 random bytes, or an obviously degenerate one, is refused.

## `token`

```text
rgt-vault token mint   --agent NAME [--scope agent[,lease,audit,operator]] [--expires 24h] [--out FILE]
rgt-vault token list   [--json]        # id, agent, scopes, created, expiry; never hashes or tokens
rgt-vault token revoke ID
rgt-vault token rotate ID [--expires D] [--out FILE]   # same agent and scopes; the old token dies
rgt-vault token import --file FILE --agent NAME [--scope ...] [--expires D]   # migrate a token file
```

All take `--store` (env `RGT_VAULT_TOKEN_STORE`, default `~/.config/rgt-vault/tokens.json`).
Writes are atomic (temp + rename, 0600) under a lock file, and a running server sees them at its
next request.

## `serve`

```text
rgt-vault serve [--db PATH] [--policy FILE] [--provider keyring|platform]
                [--host 127.0.0.1] [--port 8765]
                [--tls-cert FILE --tls-key FILE [--tls-client-ca FILE [--tls-client-auth require|verify-if-given]]]
                [--allow-insecure-non-loopback]
                [--token-store PATH | --legacy-shared-token [--token-file PATH] [--operator-token-file PATH]]
                [--require-approval [--totp-secret-file PATH] [--approval-timeout 120s]]
                [--harness-key-file PATH] [--allow-private-network]
```

- Loopback plain HTTP is the default. A non-loopback `--host` is refused unless the daemon serves
  TLS (`--tls-cert`/`--tls-key`: TLS 1.2+, AEAD suites, certificate hot-reload on SIGHUP, optional
  mTLS with `--tls-client-ca`) or you pass `--allow-insecure-non-loopback` (plain HTTP, logged and
  audited; the old `--allow-non-loopback` is a deprecated alias). Clients use `https://` with
  `--cacert`. See [TLS and transport security](tls.md).
- Authentication is the per-agent token store (`--token-store`). `serve` refuses an empty or
  corrupt store.
- `--legacy-shared-token` (deprecated, logs a warning) restores the single shared `--token-file`
  with a self-asserted agent and no scope enforcement. `--operator-token-file` then separates the
  approve/deny token. The lease route, `/v1/rotate` and the audit log are refused in that mode
  unless you add `--legacy-allow-privileged-routes`.
- `--require-approval` holds every unseal until a token with the `operator` scope approves it
  (`--totp-secret-file` adds a TOTP code for `require_2fa` secrets; create one with
  `enroll-2fa`). An agent cannot approve its own request unless its token carries `operator`.
  In legacy mode it **requires** `--operator-token-file`. `--approval-timeout` is at most 24h.
- `--harness-key-file` wires the HMAC verifier for `/v1/capabilities/execute`; without it that
  endpoint fails closed.
- Also read from the environment: `RGT_VAULT_HOST`, `RGT_VAULT_PORT`, `RGT_VAULT_TOKEN_STORE`,
  (legacy only) `RGT_VAULT_TOKEN_FILE` and `RGT_VAULT_OPERATOR_TOKEN_FILE`, `RGT_VAULT_TOTP_SECRET_FILE`, `RGT_VAULT_HARNESS_KEY_FILE`,
  `CORS_ALLOWED_ORIGINS`, `RGT_VAULT_MAX_BODY_BYTES`.
- `rgt-vault-server` is a deprecated alias of this command.

## Secrets (against a server)

```bash
# The plaintext is read from stdin (or --value-file PATH); it is never an argv positional,
# because argv is visible to other local users.
echo "sk-..." | rgt-vault set OPENAI_API_KEY --namespace openai --purpose setup   # as the token's agent
rgt-vault list --namespace openai          # names and timestamps, never values
rgt-vault get OPENAI_API_KEY --namespace openai
rgt-vault fingerprint OPENAI_API_KEY --namespace openai
rgt-vault revoke OPENAI_API_KEY --namespace openai
rgt-vault rotate --target dek              # or master
rgt-vault simulate --namespace openai --purpose inference --action read   # --agent X needs operator
rgt-vault audit --limit 20
rgt-vault verify-audit                     # OK, or TAMPERED and exit 2
```

`get` over HTTP asks the server to lease the secret as the token's agent
(`POST /v1/secrets/{ns}/{name}/lease`); the token needs the `agent` and `lease` scopes. The
offline form opens the vault locally, operator-only, with the same policy and the same audit
rows, and needs no server:

```bash
rgt-vault --db ~/.secure-vault/vault.db --policy policy.yaml \
    get OPENAI_API_KEY --namespace openai --purpose inference --offline
```

## Offline commands

```bash
rgt-vault verify-audit --offline --db ~/.secure-vault/vault.db   # read-only; no server, no master secret
rgt-vault status --offline --db ~/.secure-vault/vault.db         # vault id, epoch, secrets per namespace, chain
rgt-vault status                                                 # without --offline: is the server up?
```

An explicit `--db` implies `--offline` for `get`, `verify-audit` and `status`.

## Backup and restore

```bash
rgt-vault export --out backup.b64          # ciphertext + audit log + honeytokens, 0600
rgt-vault import --in backup.b64 --yes     # REPLACES the vault's contents; same vault_id only
```

The format is Python's export v1: either line can import the other's export. Secrets are bound to
the vault id and key, so an export restores only into the same vault.

## Two-factor approval

```bash
rgt-vault enroll-2fa --out ~/.config/rgt-vault/totp.secret --account alice
rgt-vault serve --policy policy.yaml --require-approval \
    --totp-secret-file ~/.config/rgt-vault/totp.secret     # approve with an operator-scoped token
```

The secret file is created 0600 and never overwritten without `--force`; a forced replacement is
written to the audit log first (`TOTP_SECRET_REPLACED`). The provisioning URI and secret are shown
once, on the terminal; when stdout is redirected they are not printed unless you pass
`--show-secret`, so they do not end up in logs.

## Coming from the Python line

```bash
rgt-vault migrate check --db ~/.secure-vault/vault.db
```

Opens the database read-only and reports the vault id, key epoch, schema migrations, `keychain.json`,
the secrets' `dek_version` and the audit chain. A vault with `dek_version=0` (legacy Fernet) rows is
refused: open it once with the last Python release, which upgrades them, then check again. The files
are shared as they are; nothing is exported or converted.

## Master-secret providers for `--provider platform`

```bash
rgt-vault provider seal tpm   --generate --out-dir /var/lib/rgt-vault/sealed        # Linux, needs tpm2-tools
rgt-vault provider seal dpapi --generate --out C:\ProgramData\vault\sealed.bin      # Windows
rgt-vault provider seal macos --generate                                            # macOS Keychain
```

Choose one secret source: `--generate` (a new vault), `--master-file` (move an existing vault's
secret) or `--from-keyring` (re-home the keyring secret). The secret is never printed, and an
existing sealed blob is not replaced without `--force`/`--update`. At run time the platform
provider reads `VAULT_DPAPI_BLOB`, `VAULT_KEYCHAIN_SERVICE` / `VAULT_KEYCHAIN_ACCOUNT` and
`VAULT_TPM_PRIV` / `VAULT_TPM_PUB`, as in Python. TPM sealing and DPAPI need the real hardware or OS
and are not exercised by the automated tests.

## Providers

`--provider` / `RGT_VAULT_PROVIDER` chooses where the vault's master key lives: `keyring` (the default),
`file` or `platform`. On a headless server, a container or any host without a desktop keyring, use `file`:

```bash
rgt-vault init --provider file                     # key at ~/.config/rgt-vault/keys/<vault-id>.key (0600)
rgt-vault serve --provider file --policy policy.yaml
rgt-vault --provider file --master-key-file /srv/keys/master.key init   # or RGT_VAULT_MASTER_KEY_FILE
```

Under systemd the `file` provider reads `$CREDENTIALS_DIRECTORY/rgt-vault-master`
(`LoadCredentialEncrypted=`), so the key can be sealed at rest with `systemd-creds` (TPM2 or host key).
To move an existing keyring vault to a key file, or to provision a key before `init`:

```bash
rgt-vault provider seal file --from-keyring --out ~/keys/master.key   # or --generate / --master-file F
rgt-vault provider seal file --generate --out - | systemd-creds encrypt --name=rgt-vault-master - OUT
```

The key file is refused when other users could read or replace it (mode, owner, hard links, a writable
directory on its path; on Windows any ACE beyond you, SYSTEM and Administrators). When the keyring is
unreachable, `init` stops before creating anything and lists these options. A plain key file is weaker than
the TPM or DPAPI at rest. Read [providers.md](providers.md) for the checks, the systemd recipe and the threat
model.
