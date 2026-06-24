# rgt-vault v0.2.x — End of Life Notice

**Status:** Python line (`rgt-vault v0.2.x`) is in **maintenance mode** and is
approaching **end of life**. The supported release is now the Go line
(`rgt-vault-server v0.3.x+`).

**Effective date:** 2026-06-22
**Python line EOL date:** 2026-12-22 (6-month soak from effective date)
**Migration target:** [go/README.md](go/README.md) (the new server)

## Why

The Python line served us well through `v0.1.x → v0.2.x`, but as the project
grew we hit a wall that no amount of Python work could remove: the
capability-based execution layer and the v2-token system (delivered on the
`audit-hook-layer` branch) need single-binary deployment, a Go-style `cgo`-free
build chain, and a memory profile that fits on a $5 VPS. The Go rewrite
[landed as the `go/` subdirectory](go/README.md) and is now the supported
release.

## What this means for users

| | Python line (`v0.2.x`) | Go line (`v0.3.x+`) |
|---|---|---|
| Status | Maintenance mode → EOL 2026-12-22 | Supported |
| New features | None | Yes |
| Bug fixes | Security only, best-effort | Yes |
| Capability security model | WIP on `audit-hook-layer` branch | Landed |
| v2 tokens | WIP | Landed |
| AES-256-GCM at rest | Yes (in `rgt_vault/crypto.py`) | Primitives landed (RGT-198); Store integration pending |
| Argon2id DEK derivation | Yes | Not yet — see [§ Crypto parity gaps](#crypto-parity-gaps) |
| HKDF key separation | Yes | Not yet — see [§ Crypto parity gaps](#crypto-parity-gaps) |
| Persistence | SQLite (`v.db`) | In-memory only (Store is `map`-backed) |
| Process model | Python 3.10+ interpreter | Single static binary |

**TL;DR for existing users:** stay on `v0.2.x` for now. The Python line is
frozen except for security backports. Plan to migrate to the Go line once the
[crypto parity gaps](#crypto-parity-gaps) close and a tagged `v0.3.0` release
lands.

## Migration path

1. **Today:** pin to `rgt-vault v0.2.x`. It is still maintained for security
   fixes. The maintenance-mode banner in the [top-level README](README.md)
   makes this explicit.
2. **2026-09 (target):** `rgt-vault-server v0.3.0` tags. The Go line gets:
   - Store integration of `internal/crypto` (encrypt-at-rest)
   - Argon2id + HKDF parity with Python
   - Real persistence (likely BoltDB or SQLite via `modernc.org/sqlite`)
   - A `Makefile` for build/test/release
3. **2026-12-22:** Python line reaches EOL. Repo will be marked archived on
   GitHub. The `rgt-vault-server` Go repo (or subdirectory) becomes the only
   supported release.

## Crypto parity gaps

The Go line currently ships AES-256-GCM primitives
([`go/internal/crypto/`](go/internal/crypto/), committed in
`2e189b9`) that are byte-for-byte compatible with
[`rgt_vault/crypto.py`](rgt_vault/crypto.py). The Store, however, does **not**
yet call `Encrypt`/`Decrypt` — secrets are still stored plaintext in memory.
Closing this gap is the next big lever; tracked under RGT-145 / RGT-146.

Argon2id (DEK derivation) and HKDF (key separation) are also not yet
implemented in Go. They are listed in RGT-145 with `done` status in the kanban
but the on-disk state does not match the acceptance criteria — this is being
addressed in follow-up tickets.

## How to migrate a deployment

1. **Inventory your secrets.** `rgt-vault list` (Python) gives you everything
   in the active namespace.
2. **Stand up a `rgt-vault-server` instance** following
   [go/README.md](go/README.md). Auth is via the same 32-byte bearer-token
   pattern; the token file is at `~/.config/rgt-vault/server.token` on both
   lines.
3. **Replay your secrets** via `POST /v1/secrets`. (A bulk-import endpoint is
   on the roadmap.)
4. **Cut your clients over.** The wire protocol is the same
   (`/v1/secrets`, `/v1/secrets/{ns}/{name}/use`, `/v1/audit`,
   `/v1/audit/verify`, `/v1/rotate`).
5. **Decommission the Python line** on or after 2026-12-22.

## Reporting issues

- **Python line bugs (security only):** open an issue on
  `WilliamHudspeth/rgt-vault` with the `security` label. We will backport
  fixes through 2026-12-22.
- **Go line bugs / feature requests:** same repo, no special label.

## License

The Python line and the Go line are released under the same license
([LICENSE](LICENSE) in this repo). The EOL transition does not change the
license of either codebase.

---

*This notice is a work in progress. It will be updated as the
crypto-parity gaps close and `v0.3.0` tags. Last edited 2026-06-22.*
