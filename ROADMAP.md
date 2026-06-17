# Roadmap

Status of known gaps and planned work. Items reference findings from the
production-readiness audit.

## Known limitations (documented, not yet fixed)

- **Full-backup rollback (SECURITY non-goal).** The key epoch lives in the
  rollback-able database, so restoring a matched old `vault.db` + `keychain.json`
  pair is not detected. *Plan:* anchor the epoch in an append-only or
  hardware-monotonic store (e.g. TPM NV counter) outside the DB.
- **Partial zeroization.** Python cannot guarantee plaintext copies (`str`,
  `bytes`) are unrecoverable. *Plan:* document patterns; investigate
  `memoryview`-only callback ergonomics.
- **Master secret in memory.** `MasterSecret` wraps immutable `bytes` and cannot
  be wiped. *Plan:* evaluate a mutable-buffer master representation.

## Planned

- **Local HTTP server for LLM/agent clients.** ~~A loopback FastAPI surface with
  bearer-token auth and server-side actions so non-Python clients can use the
  vault without plaintext crossing the wire.~~ **DONE** in `rgt_vault/server/`
  (`rgt-vault serve`); covered by `tests/test_server.py` and
  `tests/test_actions.py`.
- **Migration atomicity.** ~~Wrap each migration file + its bookkeeping row in a
  single transaction; verify with `PRAGMA integrity_check`.~~ **DONE** in
  `rgt_vault/storage/sqlite.py::_apply_migrations`; covered by
  `tests/test_migration_atomicity.py`.
- **Automated rotation for platform providers.** DPAPI/TPM re-seal helpers
  invoked through `rotate_secret()`. (The Linux TPM provider now uses an
  explicit `tpm2_createprimary` flow that *can* be re-sealed by re-running
  `seal_master_secret` with a new secret and swapping the .priv/.pub
  files; this is the building block but the high-level API is still TODO.)
- **CLI parity.** ~~`get`/`lease`/`list`/`rotate`/`audit verify` subcommands with a
  selectable provider (`--provider keyring|dpapi|tpm`).~~ **DONE** in
  `rgt_vault/cli.py`; covered by `tests/test_cli.py`.
- **Linux TPM live integration tests** (previously only mocked). **DONE**
  in `tests/test_tpm_live.py`; auto-skipped when `/dev/tpmrm0` is
  unreadable.
- **Audit log noise reduction.** Separate storage-layer and policy-layer events;
  avoid logging debug reads (e.g. `get_fingerprint`).
- **CI.** GitHub Actions matrix (Linux/macOS/Windows × Python 3.9–3.12) running
  `pytest`, `ruff`, and a wheel-build smoke test.
- **Foreign keys / referential integrity** across `secrets`/`audit_logs`.

## Done in v0.3 (capability security refactor on `audit-hook-layer`)

The "Under consideration" items below this section are now
implemented on the `audit-hook-layer` branch and land in v0.3.
Not merged yet — see `BRANCH_SUMMARY.md` for the review.

- **Per-agent tokens.** Replaced the v0.2 namespace-scoped
  capability tokens with action-scoped v2 tokens (one token
  = one capability + context bindings). `TokenVerifier` ABC
  with `HMACTokenVerifier` v1 implementation; `Ed25519TokenVerifier`
  is a stub for future deployment.
- **Egress-proxy model.** `VaultManager.execute_capability` is
  the new primary enforcement point. The vault leases the
  secret, runs the action handler inside the vault, and
  returns only the result. Plaintext never crosses the
  boundary. The `secrets.use` bridge capability wires the v0.2
  `ActionRegistry` into the new path for backwards
  compatibility.
- **Capability registry.** `CapabilityRegistry` is the single
  point of dispatch; capability names are first-class
  entities. New code registers a capability and calls
  `execute_capability`; no more giant if/elif blocks.
- **Hook layer refactor.** `HookRequest` carries the new
  capability fields; hooks branch on `req.is_capability`.
  `TwoFactorHook` dispatches v1 vs v2 tokens. `WebhookHook`
  no longer has a `soar` mode — SOAR products integrate
  through `webhook` mode.
- **HTTP surface.** `POST /v1/capabilities/execute` and
  `GET /v1/capabilities`. Bearer-token gated, the same
  exception-to-HTTP-status mapping, the same exception
  sanitization as the v0.2 `/use` endpoint.

## Under consideration

- Pluggable storage backends (Postgres) for multi-process deployments.
- Optional envelope re-encryption to enable cross-vault backup restore.
- **MCP server** so MCP-compatible agent frameworks (Claude Desktop,
  Cursor, VS Code, Continue, Roo, Cline) can consume the vault
  without a custom integration. The capability surface is the
  natural API boundary for MCP tools.
- **Redaction middleware** so agent frameworks that log tool I/O
  don't leak secrets into their own logs.

## Strategic direction — Go rewrite + capability model

**Status:** design discussion only. Not scheduled. Will not happen without a
maintainer decision and a migration plan that preserves the v0.2.x Python
package as the supported release until the Go rewrite is feature-complete
and parity-tested. Anything in this section is a *direction*, not a
commitment.

### Why Go is on the table

The current Python implementation scores well on correctness and
auditability but poorly on three operator-facing axes:

| Axis | Python (current) | Go (proposed) |
|---|---|---|
| `git clone && ./run` | requires Python 3.9+, a venv, `pip install` | single static binary |
| Startup time | ~400 ms cold (Argon2id 256 MB + import path) | <100 ms |
| Cross-platform release artifact | sdist + wheel per Python minor | one binary per OS/arch |
| Terminal-native TUI | third-party (Textual / urwid / prompt_toolkit) | Bubble Tea (charmbracelet) |
| Dependency footprint | cryptography, keyring, fastapi, uvicorn, pyyaml | stdlib + `golang.org/x/crypto` |

For a project whose target users are homelab operators, security
engineers, and AI-agent framework integrators, "single static binary
that opens to a TUI" is materially easier to adopt than
"pip install into a virtualenv."

### What the rewrite would actually change

The Go rewrite is **not** a "port the same code" exercise. The
suggested shape:

```
rgt-vault (Go)
├── core/             # AES-256-GCM, Argon2id, HKDF (unchanged primitives)
├── providers/        # OS Keychain, TPM, DPAPI — Go equivalents of the
│                     #   current Python providers; ABI surface kept
│                     #   narrow so cross-language interop stays sane
├── capabilities/     # NEW: agent identity + leased capabilities (the
│                     #   architectural moat; replaces ABAC with a
│                     #   capability gate)
├── proxy/            # NEW: vault executes outbound calls on the
│                     #   caller's behalf; plaintext never crosses the
│                     #   trust boundary
├── mcp/              # NEW: MCP server so any MCP-compatible agent
│                     #   framework (Claude Desktop, Cursor, OpenAI
│                     #   Agents, VS Code, Continue, Roo, Cline) can
│                     #   consume the vault without a custom integration
├── tui/              # Bubble Tea TUI: dashboard, search, tree view,
│                     #   live TOTP countdown, panic key, auto-lock,
│                     #   clipboard auto-clear
└── redactor/         # NEW: redaction middleware so agent frameworks
                       #   that log tool I/O don't leak secrets
```

The crypto primitives would be the **same** — AES-256-GCM, Argon2id,
HKDF-SHA512 — so the on-disk format can stay compatible. `vault.db`
written by the Python v0.2.x line should be readable by the Go line,
and vice versa.

### What survives the rewrite

- The cryptographic envelope (AES-256-GCM wrapping DEK, Argon2id
  master derivation, HKDF binding context) — already primitive-correct.
- The audit log hash chain format.
- The ABAC policy YAML schema (compatible parser).
- The provider abstractions (Keyring, TPM, DPAPI, macOS Keychain).
- The HTTP API contract — Go server is a drop-in replacement for
  `rgt-vault serve`.
- The threat model and SECURITY.md guarantees.

### What is at risk

The Go rewrite **destroys** the existing install base unless we ship
the Python line in parallel for at least one release cycle. That
means two implementations of the same crypto to maintain, two
test suites, and two CI matrices. It is non-trivial work even
though the primitive code is small.

Specifically at risk during the rewrite:

- **Audit-chain test vectors** must be regenerated for the new
  crypto library. SHA-256 is SHA-256, but the JSON serialization
  for `entry_hash` is byte-for-byte sensitive — Go's `encoding/json`
  field ordering differs from Python's `json.dumps`.
- **Argon2id parameter compatibility** must be re-verified end-to-end.
  `golang.org/x/crypto/argon2` is correct but the parameter encoding
  in `keychain.json` is a JSON blob, so both implementations need to
  read/write identical shapes.
- **The HTTP server** is currently 222 lines of FastAPI glue. A Go
  rewrite (using chi or stdlib `net/http`) is straightforward but
  re-tested.

### Capability model — separate from the language question

The capability / lease / proxy ideas are **independent** of the Go
rewrite. They can be implemented in the existing Python codebase
first, behind a feature flag, with the Python TUI (e.g. Textual)
serving as the prototype. Doing it in Python first lets us validate
the threat model before committing to a cross-language migration.

A reasonable staged path:

1. **Now (Python):** Keep iterating on the audit-remediated
   v0.2.x line. Add a `Capability` dataclass + a `request_lease()`
   method that returns a short-lived capability token. Keep it
   additive, no breaking changes.
2. **Next (Python):** Add the egress-proxy `/use` mode — vault
   executes the outbound call, returns only the response body.
3. **Same release:** Add `redact()` middleware; ship `rgt-vault
   mcp` exposing the lease + proxy API.
4. **Then, IF the maintainer decides:** Begin the Go rewrite in a
   separate repo (`rgt-vault-go`), importing the same `.vault.db`
   format and HTTP contract. Mark the Python package as
   `maintenance-mode` only after the Go build has full feature
   parity AND a 6-month soak with no critical CVEs.

### Things to decide before any rewrite

The maintainer should explicitly answer these before starting the
Go work:

1. **Repo strategy.** Single repo with two `Makefile` targets
   (`make python`, `make go`)? Or a separate `rgt-vault-go` repo?
   The former is easier for users; the latter is cleaner for
   contributors.
2. **Backwards-compat window.** How long does the Python line stay
   supported after the Go line reaches feature parity? Six months
   is the minimum for any production user to migrate.
3. **Distribution.** Homebrew + `apt` + `winget` + signed GitHub
   release artifacts. Signing keys, reproducibility, SBOM.
4. **TUI scope.** Full Bubble Tea TUI in v1.0, or a minimal
   `rgt-vault prompt` first?
5. **MCP scope.** Local stdio MCP server in v1.0, or HTTP+SSE first?
6. **Redaction library.** Roll our own, or depend on a
   third-party (`scrubadub`, etc.)? Security tooling should not
   depend on regex-only libraries for secret detection.

### What the Go rewrite is NOT

- It is not a v2 with a "Go is faster, everything else stays"
  attitude. Speed without the capability model is just a faster
  secret manager; the market does not need another one.
- It is not a rewrite of the crypto layer. The crypto is the
  easiest part. The capability gate is the hard part.
- It is not a rewrite that drops the Python package on day one.
  The Python package is the supported release until parity is
  proven.

### Recommendation

Build the **capability + proxy + MCP** features on top of the
**current Python implementation** first. Validate the threat
model with real users. Then, *only if* those features succeed in
adoption, begin the Go rewrite as a separate artifact that consumes
the same on-disk format and HTTP contract.

Doing it in that order means a failed Go rewrite still leaves a
working, audited, security-reviewed Python package behind. Doing
the Go rewrite first means a half-finished migration strands every
existing user.
