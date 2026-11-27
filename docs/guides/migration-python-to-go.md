# Migrating a vault from the Python line to the Go line

Status: the Python line (`rgt_vault`) is **end-of-life**: no new features, CI/security fixes only, removal tracked in
RGT-165. Go (`go/`) is the only supported implementation.

**The migration is in place.** The Go build opens the *same* files the Python line wrote: no export, no re-encryption,
no new keys.

| What | Where | Changes? |
|---|---|---|
| Vault database | `~/.secure-vault/vault.db` (SQLite, WAL) | no: same schema (the five migrations), same rows |
| Wrapped data key | `keychain.json` next to `vault.db` | no: same format (Argon2id parameters are read from the file) |
| Master secret | OS keyring entry `rgt_vault` / `master_key`, or the platform provider (DPAPI, macOS Keychain, TPM) | no: same entry, same encoding |
| Agent token | `~/.config/rgt-vault/server.token` (one shared token) | **yes**: Go uses a per-agent token store (`~/.config/rgt-vault/tokens.json`, hashes only); mint one token per agent. Same default port 8765. The old file works only through the temporary `serve --legacy-shared-token` bridge |
| Policy | your `--policy` YAML | no: same ABAC semantics (`fnmatch`, deny precedence, `*` crosses `/`) |

What is *proved* about this, and where, is listed in [What is verified](#what-is-verified) and the
[appendix](#appendix-parity-checklist-for-removing-python).

> **Before you start**
>
> * The Go release (RGT-163) has not been cut yet. Until it is, build the binary yourself:
>   `cd go && CGO_ENABLED=0 go build -o rgt-vault ./cmd/rgt-vault` (Go version from `go/go.mod`).
> * **Do not run Python and Go on the same vault at the same time.** Stop the Python server first.
> * **Identity changes on the Go line (batch H1).** Python has one shared bearer token and a self-asserted agent name;
>   Go gives every agent its own token and takes the agent from it. Mint tokens before you start the Go server
>   (step 3, and [agent-identity-migration.md](agent-identity-migration.md)). `serve --legacy-shared-token` keeps the
>   Python model only as a temporary bridge, and even then refuses the lease route, rotation and the audit log unless
>   `--legacy-allow-privileged-routes` is also given.

## 1. Back up (2 minutes, do not skip)

Stop anything that has the vault open (`rgt-vault serve`, the MCP server, the TUI), then:

```bash
cp -a ~/.secure-vault ~/.secure-vault.pre-go-$(date +%Y%m%d)      # vault.db, keychain.json (and any -wal/-shm)
cp -a ~/.config/rgt-vault ~/.config/rgt-vault.pre-go-$(date +%Y%m%d)   # token(s)
```

The master secret is not in those directories. With the default `keyring` provider it lives in the OS keyring, which
a file copy does not capture. A vault is only recoverable from a backup if the master secret that goes with that
`keychain.json` is recoverable too, so decide now how you would restore it (your keyring's own backup, or, if you accept
the risk, a copy of the entry in a password manager). The platform providers keep their sealed blobs outside the vault
directory too (`VAULT_DPAPI_BLOB`, `VAULT_TPM_PRIV` / `VAULT_TPM_PUB`): back those files up as well.

## 2. Check the vault (read-only)

```bash
rgt-vault migrate check --db ~/.secure-vault/vault.db
```

It opens `vault.db` read-only (nothing is written, **no master secret is needed**) and prints the vault id, key epoch,
applied migrations, the keychain, the DEK versions of the secrets and the audit-chain verdict:

```
database:     /home/you/.secure-vault/vault.db
vault_id:     5a11c0de-0000-4000-8000-000000000001
key_epoch:    3
migrations:   1,2,3,4,5
secrets:      16 rows (dek_version 1: 16)
keychain:     keychain.json version 1, kdf argon2id, key_epoch 3
audit rows:   52
audit chain:  OK
verdict:      READY (the master secret was not checked: it is only needed to open the vault)
```

| Exit status | Meaning | What to do |
|---|---|---|
| 0 | READY | continue |
| 1 | NOT READY | read the reasons it prints; the common ones are below |
| 2 | the audit chain does not verify | do **not** migrate yet: the vault was modified outside the vault code, or damaged. `rgt-vault verify-audit --db ... ` names the first bad row. Investigate with the Python line first |

Reasons for exit 1:

* **Legacy `dek_version=0` rows** (secrets still encrypted with the pre-AES-GCM Fernet scheme). Go refuses these
  (decision D3). Open the vault **once with the last Python release**; it upgrades them to AES-256-GCM automatically
  on open. Then run `migrate check` again.
* `keychain.json` missing while the vault holds secrets: restore it from your backup. Never let a new key be generated;
  the existing secrets would become unreadable.
* `keychain.json` epoch different from the database epoch (a rolled-back keychain, or a backup mix-up). Restore
  `vault.db`, `keychain.json` **and** the master secret from the same point in time.
* A schema newer than this build knows.

## 3. Point Go at the same files

The Go CLI uses Python's flags and the same defaults:

```bash
export RGT_VAULT_DB=~/.secure-vault/vault.db        # same default as Python's --db
export RGT_VAULT_POLICY=~/.config/rgt-vault/policy.yaml   # your existing policy; unset = deny everything
export RGT_VAULT_PROVIDER=keyring                   # or: platform
```

**Master-secret provider.** Keep the one you already use; Go reads the same store:

| `--provider` | Backing store | Environment (same names as Python) |
|---|---|---|
| `keyring` (default) | OS keyring, service `rgt_vault`, user `master_key` (Linux Secret Service, macOS Keychain, Windows Credential Manager) | none |
| `platform` on Windows | DPAPI blob file | `VAULT_DPAPI_BLOB` |
| `platform` on macOS | Keychain item | `VAULT_KEYCHAIN_SERVICE`, `VAULT_KEYCHAIN_ACCOUNT` |
| `platform` on Linux | TPM 2.0 sealed blobs (plus the `<priv>.pcrs` file) | `VAULT_TPM_PRIV`, `VAULT_TPM_PUB` |

Do **not** re-run provisioning for an existing vault: a fresh master secret cannot unwrap the existing data key.
(`rgt-vault provider seal ...` exists for *new* vaults, and for moving an existing secret with `--master-file` or
`--from-keyring`.)

Try the vault offline first (no server involved; same policy, same audit rows as the server):

```bash
rgt-vault get DB_PASSWORD --namespace prod --agent ci-bot --purpose "migration check" --offline
```

then create the token store and one token per agent, and start the server on the same port as before:

```bash
rgt-vault init --tokens-only        # token store + an operator token in ~/.config/rgt-vault/operator.token
rgt-vault token mint --agent ci-bot --scope agent,lease --out ~/.config/rgt-vault/ci-bot.token
rgt-vault serve                     # 127.0.0.1:8765, per-agent tokens from ~/.config/rgt-vault/tokens.json
```

Point each client at its own token (`RGT_VAULT_TOKEN_FILE=~/.config/rgt-vault/ci-bot.token`, or `--token`). The TUI
and the operator commands (`audit`, `verify-audit`, `rotate`) use `operator.token` on their own. `mcp` and the agent
commands need an explicit token. The port and routes are the same as Python's, except that the plaintext route is now
`POST .../lease`. If a client cannot be changed yet, the temporary bridge is
`rgt-vault serve --legacy-shared-token` (see [agent-identity-migration.md](agent-identity-migration.md)).

## 4. Verify

```bash
rgt-vault migrate check --db ~/.secure-vault/vault.db        # still READY, now with the Go-written audit rows
rgt-vault verify-audit --db ~/.secure-vault/vault.db         # OK  (offline; exit 2 = TAMPERED)
rgt-vault status --db ~/.secure-vault/vault.db               # vault id, epoch, active secrets per namespace
rgt-vault export --out /safe/place/vault-export.b64          # ciphertext-only dump, Python's export format
```

and, if you keep Python installed for the transition, the other side agrees:

```bash
rgt-vault verify-audit          # Python CLI against the same vault: OK
```

## What changes

| | Python line | Go line |
|---|---|---|
| Agent identity | one shared bearer token; the `agent` field is self-asserted | **per-agent tokens** (H1, breaking): `tokens.json` store, the agent comes from the token, scopes `agent`/`lease`/`audit`/`operator`. The Python model is only `serve --legacy-shared-token`, which also refuses lease/rotate/audit unless `--legacy-allow-privileged-routes`. See [agent-identity-migration.md](agent-identity-migration.md) |
| Port, token file, routes | 8765, `~/.config/rgt-vault/server.token` | 8765, `~/.config/rgt-vault/tokens.json` + per-agent tokens. Go-only routes: `GET /v1/secrets/{namespace}/{name}` fingerprint (ABAC-gated), `GET /v1/actions`, `POST /v1/secrets/{namespace}/{name}/lease` (plaintext, `lease` scope; replaces `GET /v1/secrets?name=`, which answers 400) |
| `/docs`, `/redoc`, `/openapi.json`, CSRF cookie | served (docs outside production) | not served; auth is the bearer header only |
| `get` | leases in-process and prints the value | asks the server by default (`POST .../lease`, token needs `agent`+`lease`); `get --offline` (or an explicit `--db`) opens the files like Python did. `--purpose` is required offline |
| Default `--agent` | `cli` | none: the token's agent. `--agent` is only for legacy servers (a different agent is refused) |
| `init` | writes the token file | also opens (never resets) the vault, creates the token store and an operator token (`operator.token`); `--legacy-shared-token` for the old token files |
| Seal helpers, export/import | library functions only | CLI: `provider seal dpapi|macos|tpm`, `export`, `import --yes` |
| MCP | in-process FastMCP | `rgt-vault mcp`, a stdio bridge to a running server |
| Legacy Fernet rows | migrated on open | refused: open once with the last Python release |
| Not ported (never wired into the Python CLI, or dead) | shadow dual-write, e-mail verification, `bypass_verification`, `AgentVaultClient` | none of these exist in Go |

Wire and file formats are byte-compatible by construction and by test: AES-256-GCM secret layout and AAD, the keychain
KDF chain and its un-prepended nonce, the audit hash input (including Python's `None` rendering of NULL columns and
`isoformat()` without microseconds), v1/v2 capability tokens, export envelope v1.

## Rollback

* **Go only read** (`migrate check`, `verify-audit`, `get --offline`, serving reads): the files only gained audit
  rows, and Python opens the vault as it is. Stop Go, start Python.
* **Go wrote or rotated** (`set`, `rotate --target dek|master`, `import`): Python still opens the vault, reads every
  version, verifies the chain and keeps writing. This is tested in both directions
  (`go/internal/compat`, TestPythonOpensGoModifiedVault and TestKeyringInPlaceMigration). The only rule: `vault.db`,
  `keychain.json` and the master secret must stay a matching set.
* **Restoring a backup**: restore all three from the same moment, or none. A `keychain.json` whose epoch differs
  from the database is refused as a rollback attack (*Rollback attack detected*); that refusal is protecting you.
  A rotation interrupted by a crash leaves `keychain.json.new`; `migrate check` reports it and the next Go open completes the rotation.
* **Undo the Go release itself**: the Go binary changes no files other than the three above and the token files;
  delete the binary and use Python as before.

## Known limits

* Legacy `dek_version=0` vaults must pass through the last Python release once (above).
* The Go HTTP server returns plaintext only on `POST /v1/secrets/{namespace}/{name}/lease`, which needs a token with
  the `agent` and `lease` scopes (RGT-504); the transitional `GET /v1/secrets?name=` is gone.
* Windows: the Go `0600` token-file mode is not enforced as an owner-only ACL; the file inherits the profile's ACL
  (RGT-501). Defender may flag cross-compiled test binaries (RGT-503); build with the native toolchain.
* A DPAPI blob sealed with `CRYPTPROTECT_LOCAL_MACHINE` (Python's format) can be unsealed by any local user who can
  read the file: restrict its ACL.
* macOS Keychain: Python/Go interoperability is **not verified** (the live tests hang on hosted CI runners, RGT-507).
  If you use `--provider keyring` or `platform` on macOS, run `migrate check`, then `get --offline` on a *copy* of the
  vault first. The TPM provider is verified against a software TPM in CI, not on real hardware.
* The audit chain does not cover `agent_id` (same as Python), and rows imported from other tools that stored NULL
  `details` verify only the way Python verifies them.
* Python features that were library-only (hooks configuration, webhook/2FA hooks, the freeze watcher) are not wired
  into the Go CLI by this migration.

## What is verified

Everything below runs in `go test ./internal/compat` (plus the CI job `compat (python<->go)`), against vaults that
the **real Python implementation** produced (`go/testdata/pyvault`, regenerate with
`tests/compat/gen_go_fixtures.py`):

* Go opens `small` (rotated twice, 1 MiB secret), `default` (production Argon2 cost) and `epoch1` through the whole
  stack, decrypts every secret version exactly as Python's manifest says (including the versions Python itself could no
  longer decrypt), reproduces Python's chain verdict, first/last hash and export bytes.
* Go writes, revokes, rotates the DEK and the master key (through the HTTP API) and re-verifies, in the same process and after
  re-opening the files.
* The 10 edge databases: Go's verdict and first bad row equal Python's, the legacy Fernet vault is refused without writing.
* **Python opens what Go modified**: reads every version Go reads, verifies the chain, serves it through its FastAPI
  app, imports Go's export, writes; Go reads Python's write and imports Python's export.
* A real keyring: Python creates a vault with its master secret in the Secret Service, the Go binary migrates it in
  place (`migrate check`, `get --offline`, `serve`, `set`, `rotate dek|master`, `export`), Python opens it again with the key
  Go wrote to the keyring.
* Every HTTP route and CLI subcommand of Python has a Go counterpart or a documented omission (table tests).

## Appendix: parity checklist for removing Python

Removing `python/` (batch GZ) may not be scheduled until **every box is ticked by a human** and links its evidence.
Boxes below are ticked only where this repository's CI or tests prove them; the rest say what is missing.
The same list is posted on RGT-165.

Evidence below is CI run [45934553386](https://github.com/WilliamHudspeth/rgt-vault/actions/runs/45934553386) on commit `84f9af2` of PR [#52](https://github.com/WilliamHudspeth/rgt-vault/pull/52) (jobs `compat (python<->go)`, `tpm (swtpm)`, `providers (windows-latest)`, `go (ubuntu/macos/windows)`), or a test name in `go/internal/compat`. Unticked boxes say what is missing.

1. [ ] G1–G12 merged; `go test -race ./...` green on linux/macos/windows; coverage of new packages ≥85%.
   * Done: G0–G11 are merged (G0 #34, G1 #24, G2 #26, G3 #33, G4 #35, G5 #27, G6 #36, G7 #40, G8a #45, G8b #44, G9 #48, G10 #50, G11 #49); the `go (ubuntu-24.04 / macos-latest / windows-latest)` jobs run `go vet` and `go test -race` and were green on `84f9af2`.
   * Missing: G12 itself (this PR) is not merged; the ≥85% gate is not met package-wide today (measured with `go test -cover ./...`: `internal/crypto` 83.9%, `internal/kdf` 82.5%, `internal/server/handlers` 21.5% in its own package (exercised from `internal/server`), `internal/auth` and `cmd/gateway` 0% in their own packages), and no CI job enforces it.
2. [x] G12 round trip green: the Python-created `small` and `default` fixtures are fully readable by Go; a Go-modified vault is readable by Python and `verify_audit_chain()` is True; Python's export imports into Go.
   * Evidence: `go/internal/compat` `TestFixturesFullStackRead`, `TestFixturesWriteRotateReverify`, `TestFixturesExportImport`, `TestEdgeChainVerdicts`, `TestPythonOpensGoModifiedVault` (also `epoch1` and a Go-created vault), in the `compat (python<->go)` job (required check).
3. [ ] Provider matrix green in CI (Linux keyring, macOS keychain, Windows keyring and DPAPI; TPM swtpm-green or human-verified; record which).
   * [x] Linux keyring (Secret Service / gnome-keyring): `TestKeyringInPlaceMigration` in the `compat` job: Python creates a vault with its master secret in the real keyring, the Go binary migrates it in place (`migrate check`, `get --offline`, `serve`, `set`, `rotate dek|master`, `export`), Python re-opens it with the key Go wrote; plus `TestLiveKeyring`.
   * [x] Windows keyring (Credential Manager): the same test with the real Python `keyring` WinVault backend, `providers (windows-latest)`; manual confirmation in RGT-501.
   * [x] Windows DPAPI: `TestPythonDPAPIInterop`, Python (pywin32) seals / Go unseals and the reverse, with and without entropy, `providers (windows-latest)`; manual confirmation in RGT-501.
   * [x] TPM: **swtpm-green** (`tpm (swtpm)`: `TestLiveTPMSealUnseal`, `TestPythonTPMInterop`, Python seals / Go unseals and the reverse, through tpm2-abrmd). Not verified on real hardware (RGT-16 owner).
   * [ ] macOS Keychain: **not green**. The live provider tests hang on hosted macOS runners (`security add-generic-password` times out, also with an unlocked temporary keychain), so no macOS job is in CI. A human must run `RGT_TEST_REAL_KEYRING=1 RGT_TEST_MACOS_KEYCHAIN=1 go test ./internal/providers` and `go test ./internal/compat -run TestPythonMacOSKeychainInterop` (with `RGT_VAULT_PYTHON`) on a real Mac. Tracked in RGT-507.
4. [x] Every route in `python/server/app.py` has a Go counterpart, or a documented deliberate omission (`/docs`, `/redoc`, `/openapi.json`; the CSRF cookie is a middleware, not a route). Evidence: `TestRouteParity` (parses both and fails on any undocumented difference).
5. [x] Every `python/cli.py` subcommand has a Go counterpart, including `enroll-2fa`, and `export` / `import` / `provider seal` exist (D4). Evidence: `TestCLICommandParity`.
6. [x] Legacy handling per D3 is implemented and documented: Go refuses a vault with `dek_version=0` rows, names the last-Python-release step, and writes nothing. Evidence: `TestLegacyFernetVaultRefused`, `TestCLIMigrateCheckRefusals`, this guide.
7. [ ] H1 merged (PR #53: per-agent tokens, scopes, token-derived ABAC subject; this guide already describes it). Tick when it is merged.
8. [ ] A Go release cut from parity master (RGT-163 plumbing), with release notes linking this guide. Not done.
9. [ ] The maintainer migrates their own vault(s) with this guide and confirms. Not done (needs a human).
10. [ ] The EOL announcement has been public for at least the notice period (D2) before GZ merges. Not done.
