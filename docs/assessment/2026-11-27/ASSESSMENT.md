# rgt-vault: whole-repo assessment and demo-readiness plan

Date: 2026-11-27. Assessed commit: master `5a049d2` (PR #62 merged). Assessor: Claude (research sub-agent).

Appendices: [run-log.md](run-log.md) (raw evidence), [parity-table.md](parity-table.md),
[demo-scripts.md](demo-scripts.md), [backlog-triage.md](backlog-triage.md).

**Question asked:** where is the app now, against where it must be for Will to give a demo of it working
in Go that is actually useful, and to have it properly set up?

## 1. Executive summary

The Go engine is real and it works. I built master, ran the full agent flow by hand on Linux and on the
Windows VM, and the central promise holds: an agent with its own token asked the vault to call an API,
a human approved it (with a TOTP code for a sensitive secret), the upstream received the credential, and
the agent got only the response. Policy denials, identity checks, the honey trap, token revocation,
key rotation, export and import, and tamper detection all behaved correctly. All 34 Go test packages pass
under the race detector in 88 seconds.

What is not ready is everything around the engine. **On Will's own Linux machine `rgt-vault init` fails**,
because the default provider needs a desktop keyring that is not installed and the only alternative is an
unprovisioned TPM. The documented quickstart fails at its fifth step. The top-level README describes
commands that exist in neither line. The core action ("use this secret to call that API") has no CLI
command, so a demo needs `curl`. There is no installable Go release. And one gap is a matter of substance
rather than polish: **nothing limits where a credential may be sent**, so an agent allowed to use the
GitHub token can have the vault send it to any https host.

A demo is possible **today** with the scripts in the appendix, on the Windows VM or on Linux after
installing a keyring daemon. A demo Will can give without caveats needs the nine P0 items below, which
is about 11 worker-sessions and one decision from Will.

| Area | Status | One-line reason |
|---|---|---|
| Core vault: crypto, storage, audit chain, rotation, backup | **Green** | byte-compatible with Python, tests pass, verified by hand |
| Agent identity and ABAC policy | **Green** | per-agent tokens, scopes, spoofing refused, default deny |
| Approval and TOTP | **Green** | bad code, replay, deny and timeout all correct |
| Honey capabilities | **Green** | trap fires, response is indistinguishable, audit row and alert written |
| Useful agent actions | **Amber** | four actions (HTTP GET/POST with bearer, OpenAI chat, echo); no destination control; bearer only |
| MCP server | **Amber** | works from a scripted client; denials opaque to the model; not rehearsed with a real client |
| TUI | **Amber** | works; pasted TOTP codes ignored; "panic lock" does not lock anything |
| CLI experience | **Red** | quickstart fails as written; no `use`, `approve`; errors say only "HTTP 403"; `audit` is raw JSON |
| First run and providers | **Red** on Linux servers, **Green** on Windows desktop, unverified on macOS | no usable provider on a headless Linux host |
| Packaging and release | **Red** | only Go release is a draft of the old in-memory stub; `releases/latest` is 404; `go install` impossible; version prints `dev` |
| Documentation | **Red** at the top (README), **Amber** below | README is Python-era; Go guides mostly right; ASVS documents are thorough |
| CI and repository hygiene | **Amber** | checks are sound; master is unprotected; a Python timing flake turned master red tonight |
| Security posture | **Amber** | much hardening landed; destination gap, logging not wired, risk acknowledgements pending |
| Backlog | **Amber** | 248 issues "in review", most of them bulk-closable; several epics and "done" items are wrong |

## 2. What works (I ran it)

All evidence is in [run-log.md](run-log.md); section letters refer to it.

- **Build and tests.** `go build` takes 1.7 s here (26 s on the Windows VM). `go test -race ./...`: 34
  packages ok, 88 s. `go vet` clean. Cross-builds for Windows, macOS arm64 and Linux arm64 succeed.
  The systemd unit lints pass.
- **The agent flow (C, C3).** Agent `coder` (scope `agent`) called `http_get_with_auth` on `GITHUB_TOKEN`.
  The mock upstream logged `auth valid`; the agent received the JSON body and never the token. The same
  call with purpose `billing` was denied by policy, by agent `rogue` was denied by an explicit deny rule,
  and with a forged `agent` field was refused ("agent does not match the authenticated token"). Reading
  plaintext needs the separate `lease` scope and was refused without it.
- **Approval and TOTP (D1'' to D3').** Requests block until an operator-scoped token approves. An agent
  cannot approve. A 2FA-marked secret needs a code: missing and wrong codes are counted and raise security
  events, a reused code is rejected as a replay, a denial reaches the agent with the reason, and no answer
  means "approval timed out", denied.
- **Honey trap (C6, C7).** Probing `aws.admin.full`, or a name listed in the policy file, wrote a
  critical audit row and a log alert, and returned exactly what any unknown capability returns.
- **Audit (C8, C9).** Every step is recorded. After I edited one row in SQLite, `verify-audit` printed
  `TAMPERED` with the row id and exited 2.
- **Operations (E).** DEK and master rotation, export, revoke, import and token revocation on a running
  server all worked. The SSRF guard refused loopback, the cloud metadata address and plain http.
- **MCP (F).** A scripted JSON-RPC client listed six tools and ran `execute_secret` successfully as the
  agent; denials came back as errors.
- **TUI (G).** Dashboard, help, live audit stream, pending requests and approval with a typed TOTP code
  all worked in a real terminal.
- **Windows.** On the lab VM, master built natively and the flow (init with Credential Manager, tokens,
  serve, set, use, denials, honey trap, rotation, verify, export) worked in the desktop session.
- **Removed already.** The plaintext route `GET /v1/secrets?name=` answers 400: RGT-504 is done in code.
  `fingerprint` works: RGT-502 is obsolete.

## 3. What does not work, in the order a demo hits it

1. **`init` fails on nitoryu (A0).** `read OS keyring entry …: The name org.freedesktop.secrets was not
   provided by any .service files`. `--provider platform` then asks for a TPM blob under `/etc/vault`.
   The failed `init` leaves a `vault.db` behind. The systemd unit itself says the keyring cannot work
   under systemd and that the TPM path was never run on real hardware. I had to write a fake Secret
   Service to continue. → RGT-522
2. **The documented quickstart fails (A).** `go/README.md` and `docs/getting-started/installation.md`
   say the operator token is read automatically. `set`, `list` and `get` answer "no bearer token" until
   you add `--as-operator`, and `get` then fails with `HTTP 403` because the operator token has no `lease`
   scope (`init --help` says it has). → RGT-524
3. **No command for the main action.** Running an action on a secret, approving a request and storing a
   2FA-required secret are API-only. The Go docs never show the `/use` request body; I read
   `handlers.go` to find it. → RGT-525
4. **Errors hide the reason.** The server answers `{"error":"PolicyDeniedError","detail":"Agent 'rogue'
   denied …","incident_id":…}`; the CLI prints `Error: list failed: HTTP 403`. → RGT-526
5. **`audit` prints one line of raw JSON**, a third of it `HTTP_API` and `HOOK_*` noise, with no filter.
   The rows written for a `use` do not say which action ran or which host received the credential, and
   their `agent_id` column is empty (the agent is only in the detail text). → RGT-527
6. **TUI.** A pasted TOTP code is silently dropped (only single key presses are accepted). `P` "panic
   lock" clears the screen and exits; the server keeps serving. → RGT-528
7. **Capabilities.** `/v1/capabilities/execute` needs a signed capability token and nothing in the
   product can sign one; I wrote 12 lines of Python from the wire format. A policy denial inside
   `secrets.use` comes back as HTTP 500, as do SSRF refusals. `/v1/capabilities/list` returned `[]`.
   → RGT-519, RGT-537
8. **MCP.** The model sees only "backend error: 403 Forbidden". The `vault://policy` resource returns
   `rules: null`. `docs/guides/mcp.md` lists three of the six tools. → RGT-536
9. **Version.** `rgt-vault version` is an unknown command; `--version` prints `dev (commit none, built
   unknown)`; `/healthz` and MCP say `0.3.0`, hard-coded. → RGT-531
10. **Two vaults, one keyring entry (I).** The keyring provider always uses `rgt_vault/master_key`. I
    created a second vault for the same user, rotated the master on the first, and the second became
    unreadable (`unable to unwrap DEK`). Inherited from Python, but it is silent data loss. → RGT-535

## 4. Where the documents say more than the code does

| Claim | Where | Reality |
|---|---|---|
| `pip install rgt-vault`, `rgt-vault policy create`, `rgt-vault mcp start`, `vault.execute_capability("github.read_repo")` | `README.md` | not on PyPI; neither command exists in Python or Go; no such capability |
| "Secret never leaves the vault" | `README.md` | true for `use`; a token with the `lease` scope gets plaintext; and the vault will send the credential to any https host the agent names |
| Python "maintenance mode (EOL: 2026-12-22)", "supported for 6 months" | `README.md`, `go/README.md`, goreleaser footer | end-of-life since 2026-11-26 |
| "v0.3.0+ supported release", Homebrew, tarball install | `go/README.md`, `installation.md` | no published Go release; the download URL is 404 |
| A "freeze" state, hooks | `docs/concepts/security-model.md` | hook code exists; `serve` cannot enable any hook (true of Python too) |
| TTL-based leases | RGT-29 (done), policy `ttl` | parsed, never applied in Go |
| Log Redaction Middleware | RGT-28 (done) | the Go package exists; the server does not use it. `docs/security/asvs/V7.md` and `logging-policy.md` say so plainly (RGT-512) |
| Ed25519 capability tokens | CHANGELOG | package only (RGT-519) |
| Token files are 0600 | CLI output on Windows | inherited profile ACL only |
| Navigation index | `docs/README.md` | links to files that do not exist; marks existing pages "coming soon" |

## 5. Setup and packaging

- **Install.** Building from source is the only way. `go install` cannot work because the module is named
  `rgt-vault-server`, not its repository path. The release workflow and goreleaser config exist and
  produce archives, checksums and SBOMs for six targets, but the one Go release (v0.3.0) is an unpublished
  draft built from the in-memory stub. Signing, Homebrew, winget and deb are commented out or absent.
- **Config.** Vault in `~/.secure-vault/`, tokens and TOTP secret in `~/.config/rgt-vault/`; environment
  variables are documented in `docs/guides/cli.md`, which is the most accurate document in the tree.
- **Service.** Linux: a hardened systemd unit exists (exposure score 1.3) but depends on the unverified TPM
  path. Windows: no service guide, and the keyring fails in non-interactive sessions, so a service needs
  DPAPI. macOS: nothing verified.
- **CI.** Go jobs (test on three operating systems, compat with real Python, swtpm, Windows providers),
  CodeQL, Scorecard and gitleaks are in place and green. **master has no branch protection and no
  required checks.** Tonight's red run on master is a timing flake in a Python example test.
- **Time to first success.** With the appendix scripts: 2 seconds. Following the documents: blocked on
  this host; with a desktop keyring, about a minute to a stored secret and, by my estimate, 20 to 30
  minutes to a first agent action, because that step is undocumented.

## 6. Security posture before a public demo

The hardening batches are substantial: per-agent identity, TLS, approval hardening, error handling,
honey capabilities, ASVS documents for V4 to V7. What remains:

- **Destination control (new, P0).** `actions.Config.HostAllowlist` exists and `serve` never sets it.
  I confirmed that an agent permitted to use the GitHub token could have it sent to a second host of its
  choosing (run log C4). For a product whose pitch is limiting what a compromised agent can do, this is
  the first question a security audience asks.
- **Known and filed:** logging not wired (RGT-512), Ed25519 not wired (RGT-519), memory hygiene
  (RGT-514 to 518), rotation fault injection (RGT-508), approval round two (RGT-510).
- **Needs Will's acknowledgement before a public release, not before a demo:** RGT-222, 280, 285, 315,
  408; and the held format decisions RGT-377 (D7), RGT-399 (D8), RGT-217, RGT-218.
- **Would embarrass a live demo:** see "What not to say or show" in [demo-scripts.md](demo-scripts.md).

## 7. The demo

[demo-scripts.md](demo-scripts.md) has a 5-minute and a 15-minute script with staging script, helpers,
expected output from my run, fallbacks and a list of what not to claim. The story: a coding agent gets
the result of a GitHub call after a human approves in the TUI; it cannot read the token; an admin token
needs a TOTP code; a second agent trips a honey capability and is revoked; the audit chain shows it all
and detects tampering.

- **Works today:** every step, through shell helpers, on the Windows VM or a Linux desktop with a keyring.
- **Missing for a clean run:** RGT-522 (so it runs on nitoryu), RGT-523 (so the destination claim is true),
  RGT-525 to RGT-528 (so no helper is needed), RGT-529 (the scripts in the repository, run by CI).
- **Not verified:** MCP from a real Claude client; the real GitHub endpoint; a real Linux keyring.

## 8. The plan

Sizes: S is up to half a worker-session, M is one to two, L is three or more. A worker-session is one
agent producing one reviewed PR. Owners follow the lab rule that Gemini output is double-checked by Claude.

### P0: blockers for a demo without caveats

| # | Item | Size | Owner | Depends on | Wave |
|---|---|---|---|---|---|
| RGT-522 | Linux first run without a desktop keyring: a provider that works on a server, plus an error that says what to do | M | Opus, after decision 1 | decision 1 | 1 |
| RGT-523 | Destination allow-list for HTTP actions, per secret or per policy rule; default closed for new vaults | M | Opus, security review | none | 1 |
| RGT-524 | Make the quickstart, help texts and Go guides true; CI job that runs the quickstart literally | S | Sonnet | none | 1 |
| RGT-525 | CLI: `use`, `requests list\|approve\|deny`, `set --require-2fa --note` | M | Sonnet | none | 1 |
| RGT-526 | CLI prints the server's reason and incident id | S | Sonnet (same PR as RGT-525) | none | 1 |
| RGT-528 | TUI: accept pasted codes, rename or implement panic lock, pending badge | S | Sonnet or Gemini + Claude review | none | 1 |
| RGT-527 | Readable `audit` with filters; an audit row naming the action and destination host | M | Sonnet, Opus review (audit rows) | RGT-523 | 2 |
| RGT-529 | Demo kit in the repository (`examples/demo/`), run in CI on Linux and Windows | M | Sonnet | RGT-522, 2, 4, 6 | 2 |
| RGT-530 | README rewritten Go-first, end-of-life notice, docs index | S | Sonnet, Will approves wording | RGT-529 | 2 |

Wave 1 is five parallel workers on disjoint directories (`internal/providers`, `internal/actions` +
`internal/server/stack.go`, `cmd/rgt-vault`, `internal/tui`, docs). RGT-522 and RGT-523 both touch
`internal/servecmd/servecmd.go`: merge RGT-522 first. Wave 3 is a rehearsal on nitoryu and the Windows VM.

**Critical path:** decision 1 → RGT-522 → RGT-523 → RGT-529 → rehearsal. RGT-525, 5, 6 and 7 shorten the script
but do not block it. **P0 total: about 11 worker-sessions plus reviews; two waves.**

**If the demo must happen before any of this lands:** use the Windows VM (or install `gnome-keyring` on
nitoryu), the appendix scripts, and do not make the destination claim.

### P1: a credible v0.x release

| # | Item | Size | Owner | Depends on |
|---|---|---|---|---|
| RGT-531 | Version reporting: `version` command, build info fallback, `/healthz` and MCP use it | S | Sonnet | none |
| RGT-532 | Install path: module path for `go install`, publish a release, fix the 404 link and the footer, retire the stub draft | M | Sonnet, after decisions 2 and 3 | RGT-531; with RGT-163 |
| RGT-533 | Protect master; required checks are the Go jobs | S | **Will** (admin) | none |
| RGT-534 | Stop the Python example timing flake from turning master red | S | Sonnet | none |
| RGT-535 | One keyring entry per vault, or refuse a master rotation that would orphan another vault | M | Opus | RGT-522 |
| RGT-536 | MCP: reason in errors, real policy summary, version, verified Claude Code and Desktop setup | M | Sonnet | RGT-526 |
| RGT-537 | Error mapping: policy denial and SSRF refusal are not 500; no internal names in messages | S | Sonnet | none |
| RGT-538 | Honeytokens: a way to add and list decoy secrets | S | Sonnet | none |
| RGT-540 | Wire the kill switch and hooks into `serve`, and apply or remove the policy `ttl`; fix the documents | M | Opus, after decision 7 | none |
| RGT-541 | Service deployment verified end to end: Linux systemd on a real machine, Windows service with DPAPI and file ACLs | M | Claude with the VM; **Will** for hardware | RGT-522 |
| RGT-512 | Wire `internal/logging` | M | Sonnet | none |
| RGT-519 | Wire Ed25519 verifier and a mint command (extend it to mint v2 tokens too) | M | Opus | none |
| RGT-163 | Signed release, SBOM, Homebrew, winget | M | Sonnet, **Will** for signing keys | RGT-532 |
| RGT-377 | Export v2 with HMAC (decision 5) | M | Opus | decision 5 |

P1 total: about 16 to 20 worker-sessions.

### P2: Python removal and the long term

| Item | Size | Note |
|---|---|---|
| GZ: delete `python/`, Python CI, `go/cmd/gateway`; close RGT-135, RGT-165 | M | after the checklist in the Go plan, section 4, and Will's approval; at least 30 days after the first Go release |
| RGT-539: more useful actions (other auth schemes, env injection into a subprocess, git credential helper) | L | needs a design; this is what makes the product useful beyond HTTP APIs |
| RGT-514 to 518 memory hygiene | M each | |
| RGT-508, 510, 513, 520, 509 follow-ups | S to M each | |
| RGT-506, 507, 503 platform CI issues | S each | 503 needs the code-signing decision |
| Backlog clean-up ([backlog-triage.md](backlog-triage.md) section 7) | S | mostly Will: merge PRs #19, #22, #23, then bulk-close |
| RGT-31 risk scoring, RGT-16 TPM epoch anchor, RGT-217, RGT-218 | L | held |

P2 total: about 15 worker-sessions. **Whole plan: roughly 45 to 50 worker-sessions.** At the pace of the
last day (about 25 PRs with four to six parallel workers) the limit is review and decisions, not coding:
P0 in one to two days, P1 in two to three more.

### Release and versioning recommendation

Cut **v0.4.0** as the first real Go release, as a pre-release labelled "security preview", once P0 and
RGT-531 and RGT-532 are in. Do not reuse v0.3.0: the tag points at the stub. Delete the v0.3.0 draft
release; keep the tag as history. Tag `v0.4.0-rc1` first to exercise the release workflow.

### Repository hygiene

- README: Go-first, built from the demo kit, no Python commands. EOL wording per decision D2: "The Python
  implementation is end-of-life as of 2026-11-26. It receives CI and security fixes only and will be
  removed no earlier than 30 days after the first Go release. Existing vaults open unchanged with the Go
  binary (docs/guides/migration-python-to-go.md)."
- Move `docs/getting-started/quickstart.md` and `docs/guides/api.md`, `migration.md` (Python) to
  `docs/archive/` at GZ; fix `docs/README.md` now.
- Close draft PR #15 when RGT-532 starts.

## 9. Decisions only Will can make

1. **Which provider for Linux servers?** Recommended: add an explicit `file` provider (a 0600 key file,
   or systemd's credentials directory), documented as weaker than TPM, so `init` works everywhere; keep
   TPM as the hardened option. The alternative is to require a keyring daemon and say so.
2. **Release version.** Recommended: v0.4.0 pre-release after P0; delete the v0.3.0 draft.
3. **Rename the Go module** to its repository path so `go install` works. Recommended: yes, in one
   mechanical PR in a quiet window before v0.4.0.
4. **Protect master** with required Go checks. Recommended: yes, now.
5. **D7, export v2 with HMAC (RGT-377).** Recommended: yes, with a v1 read path, in P1.
6. **D8, ciphertext header (RGT-399), and RGT-217, RGT-218.** Recommended: no for now; revisit after GZ.
7. **Kill switch and lease TTL.** Recommended: wire the freeze file and signal (small, and a strong demo
   moment); remove the `ttl` claim unless a use for it is designed.
8. **Risk acknowledgements RGT-222, 280, 285, 315, 408.** Recommended: acknowledge as not applicable or
   residual, before the public release.
9. **Honey names.** The five defaults are in public source. Recommended: keep them, never list honey
   names through any API, and tell operators to add their own in the policy file.
10. **End-of-life wording and date (D2).** Recommended text is in section 8.
11. **Windows code signing (RGT-503).** Recommended: defer; build natively for the demo.
12. **RGT-31 thresholds.** Recommended: hold; it is design only.

## 10. What I could not verify

- A real Secret Service on Linux (none installed here; CI covers it), the TPM path, and macOS.
- MCP with Claude Code or Claude Desktop; I used a scripted client.
- The real GitHub API and `openai_chat` against a real endpoint (no real secrets, no external calls).
- `govulncheck` locally (CI's security job is green).
- Branch protection details: the API refused the protection endpoint; the branch object reports
  `protected: false` and there are no rulesets.
- The Python-to-Go interop on Windows was not repeated (RGT-501 did it on an older commit).
- Each acceptance line of the 248 in-review issues; I sampled.
- The Windows VM was already running when I started; I left it running and removed everything I created.

## 11. New issues

Filed in the Multica workspace rgt-vault on 2026-11-27, unassigned, under the tracking issue **RGT-521**
"Demo-ready Go release: assessment 2026-11-27". I searched before filing; none duplicates an existing issue.

| Key | Phase | Item |
|---|---|---|
| RGT-522 | P0 | Linux first run without a desktop keyring (provider + error) |
| RGT-523 | P0 | Destination allow-list for HTTP actions |
| RGT-524 | P0 | Quickstart, help texts and guides made true; CI runs the quickstart |
| RGT-525 | P0 | CLI `use`, `requests`, `set --require-2fa` |
| RGT-526 | P0 | CLI prints the server's reason |
| RGT-527 | P0 | Readable `audit`; audit row for action and destination |
| RGT-528 | P0 | TUI paste, panic-lock label, pending badge |
| RGT-529 | P0 | Demo kit in the repository |
| RGT-530 | P0 | README rewrite, Go-first, EOL notice |
| RGT-531 | P1 | Version reporting |
| RGT-532 | P1 | Install path, module path, first real release |
| RGT-533 | P1 | Protect master |
| RGT-534 | P1 | Python example timing flake |
| RGT-535 | P1 | Shared keyring master entry |
| RGT-536 | P1 | MCP errors, policy resource, real-client setup |
| RGT-537 | P1 | API error mapping |
| RGT-538 | P1 | Honeytoken add/list |
| RGT-539 | P1 | Design: more useful actions |
| RGT-540 | P1 | Kill switch, hooks and policy `ttl` |
| RGT-541 | P1 | Service deployment verified (Linux, Windows) |
