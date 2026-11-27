# CLI Guide

`rgt-vault` is one binary with two kinds of subcommand:

- **Client commands** talk to a running `rgt-vault serve` over HTTP (`--host`, default
  `http://127.0.0.1:8765`, and a bearer token from `--token`, `$RGT_VAULT_TOKEN` or
  `~/.config/rgt-vault/server.token`): `set`, `get`, `list`, `revoke`, `simulate`,
  `fingerprint`, `rotate`, `audit`, `verify-audit`, `status`, plus `mcp` and `tui`.
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
# Creates the vault (vault.db + keychain.json, master secret in the OS keyring) and the agent and
# operator token files (0600, 32 random bytes each). Safe to repeat: existing files are kept.
rgt-vault init

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

`init` never prints a token and never resets an existing vault. `--force` replaces the token
files (never the vault); `--tokens-only` skips the vault; `--harness-key-file PATH` also creates
the HMAC key for v2 capability tokens. A token below 32 random bytes, or an obviously degenerate
one, is refused at `init` and at `serve`.

## `serve`

```text
rgt-vault serve [--db PATH] [--policy FILE] [--provider keyring|platform]
                [--host 127.0.0.1] [--port 8765] [--allow-non-loopback]
                [--token-file PATH] [--operator-token-file PATH]
                [--require-approval [--totp-secret-file PATH] [--approval-timeout 120s]]
                [--harness-key-file PATH] [--allow-private-network]
```

- Loopback only: a non-loopback `--host` is refused without `--allow-non-loopback`, and then it
  is plain HTTP, so put a TLS reverse proxy in front.
- `--operator-token-file` separates the approve/deny scope from the agent token. Without it an
  agent could approve its own request, and the server warns.
- `--require-approval` holds every unseal until an operator approves it (`--totp-secret-file`
  adds a TOTP code for `require_2fa` secrets; create one with `enroll-2fa`).
- `--harness-key-file` wires the HMAC verifier for `/v1/capabilities/execute`; without it that
  endpoint fails closed.
- Also read from the environment: `RGT_VAULT_HOST`, `RGT_VAULT_PORT`, `RGT_VAULT_TOKEN_FILE`,
  `RGT_VAULT_OPERATOR_TOKEN_FILE`, `RGT_VAULT_TOTP_SECRET_FILE`, `RGT_VAULT_HARNESS_KEY_FILE`,
  `CORS_ALLOWED_ORIGINS`, `RGT_VAULT_MAX_BODY_BYTES`.
- `rgt-vault-server` is a deprecated alias of this command.

## Secrets (against a server)

```bash
# The plaintext is read from stdin (or --value-file PATH); it is never an argv positional,
# because argv is visible to other local users.
echo "sk-..." | rgt-vault set OPENAI_API_KEY --namespace openai --agent admin --purpose setup
rgt-vault list --namespace openai          # names and timestamps, never values
rgt-vault get OPENAI_API_KEY --namespace openai
rgt-vault fingerprint OPENAI_API_KEY --namespace openai
rgt-vault revoke OPENAI_API_KEY --namespace openai
rgt-vault rotate --target dek              # or master
rgt-vault simulate --agent research_agent --namespace openai --purpose inference --action read
rgt-vault audit --limit 20
rgt-vault verify-audit                     # OK, or TAMPERED and exit 2
```

`get` over HTTP asks the server to lease the secret (a transitional route, decision D5). The
preferred form opens the vault locally, operator-only, with the same policy and the same audit
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
    --operator-token-file ~/.config/rgt-vault/operator.token \
    --totp-secret-file ~/.config/rgt-vault/totp.secret
```

The secret file is created 0600 and never overwritten without `--force`; a forced replacement is
written to the audit log first (`TOTP_SECRET_REPLACED`).

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
