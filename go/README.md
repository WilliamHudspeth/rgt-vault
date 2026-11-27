# rgt-vault-server (Go)

> ## ✅ PRIMARY — This is the v0.3.0+ supported release.
>
> The Go implementation is the **active development line** for rgt-vault.
> All new feature work (capability-based execution, Ed25519 tokens, v2 audit
> chain) lands here. The Python implementation
> ([`../README.md`](../README.md)) is in **maintenance mode** and will be
> archived 6 months after v0.3.0 ships.
>
> **If you're new to rgt-vault, start here.**

A Go rewrite of the rgt-vault local-first secrets manager, with a
capability-based execution layer on top of the v0.2.0 cryptographic core.

## Status

The CLI and server run on the **real vault**: encrypted SQLite storage (`vault.db` + `keychain.json`,
the same files and formats as the Python line), the hash-chained audit log, ABAC policy, hooks,
approval with TOTP, capability tokens and the built-in actions. Data persists across restarts.

> **v0.3.0 was different.** The v0.3.0 release served an in-memory stub store: secrets written to it
> were lost when the process exited. If you stored anything with that release, it is gone. Use a build
> from this line and `rgt-vault serve` (below) instead.

## Quick start

```bash
cd go/
go build -o rgt-vault ./cmd/rgt-vault

./rgt-vault init                          # vault (+ master secret in the OS keyring), agent + operator tokens (0600)
cat > policy.yaml <<'YAML'
rules:
  - effect: allow
    agent: "*"
    namespace: "*"
    purpose: "*"
    action: "*"
YAML
./rgt-vault serve --policy policy.yaml &   # 127.0.0.1:8765; no --policy = every request denied

echo "my-secret" | ./rgt-vault set api-key --namespace prod
./rgt-vault get api-key --namespace prod
./rgt-vault verify-audit
```

`init` is idempotent and never overwrites an existing vault or token (see [`docs/guides/cli.md`](../docs/guides/cli.md)
for every subcommand and flag: `serve`, `init`, `status`, `enroll-2fa`, `export`/`import`,
`migrate check`, `provider seal`, offline `get`/`verify-audit`).

Requires Go 1.26+ (see `go.mod`). The default port is **8765**, like the Python line.
`rgt-vault-server` (`./cmd/server`) is a deprecated alias of `rgt-vault serve`.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET  | `/healthz` | none | liveness check |
| POST | `/v1/secrets` | bearer | set a secret |
| GET  | `/v1/secrets` | bearer | list secrets by namespace (never values) |
| GET  | `/v1/secrets/{namespace}/{name}` | bearer | ciphertext fingerprint |
| POST | `/v1/secrets/{namespace}/{name}/use` | bearer | lease a secret and run an action |
| POST | `/v1/secrets/{namespace}/{name}/revoke` | bearer | revoke a secret |
| POST | `/v1/rotate` | bearer | rotate master/DEK |
| GET  | `/v1/audit` | bearer | read audit log |
| POST | `/v1/audit/verify` | bearer | verify audit chain |
| POST | `/v1/policy/simulate` | bearer | simulate a policy decision |
| GET  | `/v1/actions` | bearer | list registered actions |
| GET/POST | `/v1/capabilities*` | bearer | list / execute capabilities (needs `--harness-key-file`) |
| GET/POST | `/v1/requests*` | operator | list / approve / deny pending approvals |

## TUI Dashboard (rgt-vault-tui)

The Go implementation includes a full-featured terminal UI built with Charmbracelet `bubbletea` (`internal/tui/`).
- **Dashboard Mode**: Browse secrets, view namespaces via a tree-view (`t`), filter via fuzzy search (`/`), and copy fingerprints to the clipboard (`c`).
- **Live Audit Log Stream**: Press `a` from the dashboard to open a real-time view of vault activity streaming directly from the server.
- **Master Key Rotation**: Safely trigger a master key rotation (`r`) with confirmation.

## Run the tests

```bash
cd go/
go test ./...
```

The CLI tests run against a real `server.New` stack on a throwaway vault and against the
Python-generated fixtures in `testdata/pyvault`. Set `RGT_VAULT_PYTHON=/path/to/.venv/bin/python`
(a Python with `rgt_vault` installed) to also run the real-Python export/import round trip.

## Differences from the Python line

- **No plaintext in process:** the Go server is designed from day one around
  the capability model (RGT-128, RGT-166). Secrets are *consumed* by named
  server-side actions; the LLM agent never receives the secret bytes.
- **Static binary:** no Python runtime, no `cryptography` wheel pain on
  cross-platform install. Single-file deploy.
- **Same files, no conversion:** a Python vault opens as it is (`rgt-vault migrate check` tells you
  first; legacy `dek_version=0` rows must be upgraded once with the last Python release).

## Cutover plan (RGT-161 → RGT-165)

1. **RGT-161** — Dual-write mode: Python `VaultManager` forwards writes to
   the Go server as a shadow write; 24h divergence check.
2. **RGT-162** — Cutover gateway: tiny reverse proxy routes traffic from
   100 % Python → 50/50 → 100 % Go over 2 weeks.
3. **RGT-163** — Public release v0.3.0: signed GitHub release + Homebrew
   tap + apt repo + winget manifest.
4. **RGT-164** — Python maintenance-mode banner. (DONE — see
   [`../README.md`](../README.md).)
5. **RGT-165** — Python EOL archive: mark Python repo `archived` on GitHub;
   bump Go to v1.0.0. (After 6-month soak post v0.3.0.)

See [`../docs/architecture/agentic-patterns-and-go-migration.md`](../docs/architecture/agentic-patterns-and-go-migration.md)
for the full design rationale.

## Reference

- Python v0.2.0 (maintenance): [`../README.md`](../README.md)
- Architecture: [`../ARCHITECTURE.md`](../ARCHITECTURE.md)
- Threat model: [`../docs/threat-model.md`](../docs/threat-model.md)
- ROADMAP: [`../ROADMAP.md`](../ROADMAP.md)
- Kanban: https://10.10.88.88:3050/rgt-vault
