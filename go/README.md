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

- **Milestone:** v0.3.0 — Enterprise Security (in progress)
- **Coverage of v0.2.0 API surface:** server skeleton (auth, middleware, secret
  CRUD, audit endpoint) — `handlers/handlers.go`
- **Not yet implemented:** SQLite-backed storage, AES-256-GCM crypto
  primitives, Argon2id keychain manager, hash-chained audit log, capability
  executor, action registry, Ed25519 token v2

See the milestone tickets in [Multica rgt-vault](https://10.10.88.88:3050/rgt-vault)
(`RGT-144` … `RGT-166`) for the per-component migration plan.

## Quick start

```bash
cd go/
go build -o rgt-vault-server ./cmd/server
./rgt-vault-server
# -> starts on :8080, mints a bearer token at
#    ~/.config/rgt-vault/server.token (printed once on first run)
```

Requires Go 1.23.4+.

## Endpoints (current Go skeleton)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET  | `/healthz` | none | liveness check |
| POST | `/v1/secrets` | bearer | set a secret |
| GET  | `/v1/secrets` | bearer | list secrets by namespace |
| GET  | `/v1/secrets/{namespace}/{name}` | bearer | get a single secret |
| POST | `/v1/secrets/{namespace}/{name}/use` | bearer | lease/use a secret |
| POST | `/v1/secrets/{namespace}/{name}/revoke` | bearer | revoke a secret |
| DELETE | `/v1/secrets/{namespace}/{name}` | bearer | delete a secret |
| POST | `/v1/rotate` | bearer | rotate master/DEK |
| GET  | `/v1/audit` | bearer | read audit log |
| POST | `/v1/audit/verify` | bearer | verify audit chain |
| POST | `/v1/policy/simulate` | bearer | simulate a policy decision |
| GET  | `/v1/actions` | bearer | list registered actions |

The Go server is currently an **in-memory** store. The next milestone replaces
this with the SQLite-backed `VaultManager` ported from Python
(`rgt_vault/storage/sqlite.py`).

## Run the tests

```bash
cd go/
go test ./...
```

Current coverage: server + middleware + auth integration tests
(`internal/server/server_test.go`, 564 LOC).

## Differences from the Python line

- **No plaintext in process:** the Go server is designed from day one around
  the capability model (RGT-128, RGT-166). Secrets are *consumed* by named
  server-side actions; the LLM agent never receives the secret bytes.
- **Static binary:** no Python runtime, no `cryptography` wheel pain on
  cross-platform install. Single-file deploy.
- **Better concurrency:** the Go `Store` (`handlers/handlers.go`) uses
  `sync.RWMutex` and is safe for parallel use out of the box.

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
