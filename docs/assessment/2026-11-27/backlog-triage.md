# Multica backlog triage (workspace rgt-vault, 2026-11-27)

Appendix to [ASSESSMENT.md](ASSESSMENT.md). Source: all 520 issues (RGT-1 to RGT-520), paged with
`multica issue list --limit 100 --offset N --output json`. I read titles, status, priority and parent for
every issue, and the description or comments only for the ones named below. I changed no status and no
assignee.

## 1. The numbers

| Status | Count |
|---|---|
| in_review | 248 |
| done | 175 |
| todo | 36 |
| backlog | 31 |
| cancelled | 20 |
| in_progress | 10 |

| Theme | Total | Open (not done/cancelled) | Note |
|---|---|---|---|
| ASVS / WSTG verification (children of RGT-492 and loose ASVS items) | 203 | 192 (185 in review) | V1: 40, V2: 56, V3: 20, V4: 9, V5: 30, V6: 15, V7: 12 |
| Python-era features, audits, misc (RGT-1 to 71, 112 to 142, 197 to 224) | 107 | 16 | mostly closed in June against Python |
| `internal/llm` and kanban tooling (RGT-72 to 111) | 40 | 3 | not the vault product |
| Go migration and Go line (RGT-143 to 166, 497 to 505) | 34 | 21 in review | the G and H batches |
| ASVS epics RGT-490 / RGT-491 children | 32 | 0 | closed in June |
| `OPT-*` lab model experiments (RGT-167 to 196) | 30 | 30 backlog | **not rgt-vault work at all** |
| Governance (children of RGT-488) | 28 | 28 in review | PR #19 |
| Epics | 23 | 16 todo | see section 2 |
| Follow-ups filed 2026-11-27 (RGT-508 to 520) | 13 | 13 | real, current work |
| CI and release | 10 | 6 | |

**What this means.** The board says 248 items are "in review", which reads like 248 things waiting on Will.
In practice about 213 of them are ASVS or governance verification rows whose evidence is a chapter document
(`docs/security/asvs/V4.md` to `V7.md`, `V9-TLS.md`, and PRs #19, #22, #23 for V1 to V3 and governance).
Nobody can review 213 issues one by one. They should be closed per chapter, in bulk, once the chapter
document is merged and Will has skimmed it. That is six or seven decisions, not 213.

## 2. Epics whose status does not match their children

| Epic | Epic status | Children | Problem |
|---|---|---|---|
| RGT-492 OWASP ASVS & WSTG Compliance | **done** | 170 in review, 6 in progress, 1 todo, 8 done | marked done with 177 open children |
| RGT-40 Agent Identity & Session Management | **done** | RGT-46 in progress | Ed25519 verifier is not wired (RGT-519) |
| RGT-488 Software Security Governance | todo | 28 in review | waits on PR #19 |
| RGT-489 Cryptography, TLS & Transport Security | todo | 6 in review | the work landed in PRs #46, #55 |
| RGT-61 Agent Authentication | todo | 5 done, 1 in review | closable after RGT-35 review |
| RGT-60 Capability Execution Framework | todo | 6 done, 1 todo (RGT-39) | |
| RGT-65, RGT-64, RGT-68, RGT-71 | todo | all children done | **close the epics** |
| RGT-39 Advanced Hook & Monitoring Ecosystem | todo | 3 done | hooks are not wired into `serve` in either line (RGT-540) |
| RGT-62, RGT-63, RGT-66 | todo | children done or cancelled | close, or restate what is left |
| RGT-67 Observability, RGT-69 Memory Hygiene, RGT-70 Detection Traps | todo | few or no children | RGT-512, RGT-514 to 518, RGT-520 belong under these |
| RGT-216 gRPC/UDS hybrid, Go edge in front of the Python core | todo | none | **obsolete**: Python is end-of-life |

## 3. Marked done (or in review) but not true in Go

These were closed against the Python line, or describe a capability that exists as a Go package without
being reachable from the product.

| Issue | Claim | What I found in Go |
|---|---|---|
| RGT-29 TTL-based Capability Leases (done) | leases expire | the policy `ttl` is parsed and then used by nothing in `internal/vault` or `internal/server`. A lease lasts as long as the server-side callback. Only capability tokens carry an expiry, and nothing in the product mints them. |
| RGT-34, RGT-45 Local Freeze Signal / Kill Switch (done) | operator can freeze the vault | `internal/hooks` has the freeze file, the watcher and SIGUSR1/2; `serve` always runs the Off hook and has no flag for any of it. Same in Python (library only). The TUI's `P` "panic lock" only quits the TUI. |
| RGT-33, RGT-44 AuditHook interface (done) | pluggable hooks | package exists; not configurable from `serve`. |
| RGT-28 Log Redaction Middleware (done) | logs are redacted | `internal/logging` exists and is tested, but the server, MCP, approval and hooks still log with the standard logger (RGT-512). |
| RGT-26, RGT-37, RGT-114 Capability-based access control (done) | "agent requests github.read_repo" | the registry has two built-ins, `secrets.echo` and `secrets.use`. Executing one needs a capability token that no shipped tool can mint (RGT-519). |
| RGT-56 `/v1/capabilities/list` (done) | lists what the agent may execute | returned `[]` for an agent that had just executed `secrets.echo`. |
| RGT-150 TPM provider (done) | TPM sealing | code and swtpm CI job exist; never run on a real TPM. |
| RGT-163 Public release v0.3.0 (in review) | signed release, Homebrew, apt, winget | the only Go release is a **draft** built from the in-memory stub; `releases/latest` is 404; no signing, tap, apt or winget. |
| RGT-164 Python maintenance-mode notice (done) | README banner | superseded by the end-of-life decision of 2026-11-26; the README still says "maintenance mode (EOL: 2026-12-22)". |
| RGT-161 dual-write (done), RGT-162 cutover gateway (in review) | Python to Go traffic split | moot with in-place migration; `go/cmd/gateway` still ships (decision D10: delete in GZ). |
| RGT-490, RGT-491 and their 32 children (done in June) | input validation and HTTP hardening verified | verified against Python. The Go evidence is `docs/security/asvs/V5.md` and the hardening tests; I did not re-check each of the 32. |

The eight phantom Go-migration issues the plan flagged on 2026-11-26 (RGT-147, 148, 149, 151, 152, 154,
156, 166) are **no longer phantom**: the code landed in the G-batch PRs (#35 to #52) and they sit in review. They can be
closed.

## 4. Done in the code, still open on the board

| Issue | Status | Evidence |
|---|---|---|
| RGT-504 remove the D5 plaintext route | in review | `GET /v1/secrets?name=` answers 400 "the name= filter was removed" (run log C3) |
| RGT-502 `fingerprint` always fails | in review | `rgt-vault fingerprint api-key` prints `063fd620` (run log A2) |
| RGT-505 systemd unit flags | in review | `deploy/rgt-vault-go.service` passes `--db --policy --provider --token-store` |
| RGT-500 bump Actions to Node 24 | todo | commits `b74e668`, `62a98bd` are on master |
| RGT-496 run Go tests on PRs | in review | review-gate `go` job |
| RGT-497, RGT-498, RGT-499 | in review | approval gate, token strength check and rotation of all versions landed in the G and H batches; approval and rotation worked in my run, I did not check each acceptance line |
| RGT-494 CI red on master | in progress | CI was green on `510c37a`; the red run on `5a049d2` is a Python timing flake (RGT-534), not the listed causes |
| RGT-30, RGT-35, RGT-46 | in review / in progress | PR #62 merged; RGT-46's remaining part is RGT-519 |
| RGT-32 memory hygiene research | in review | PR #61 merged; follow-ups are RGT-514 to 518 |

## 5. Stale, duplicate or out of scope

- **RGT-167 to RGT-196 (30 `OPT-*` issues).** Model-routing experiments for other lab agents (Tim, Sue,
  Cine, Smalls). They have nothing to do with rgt-vault. Move them to the right workspace or cancel them.
- **RGT-72 to RGT-111, RGT-86, RGT-90, RGT-91.** `internal/llm` and kanban tooling, decision D9. Three are
  still in review. Long term these and the `internal/` directory belong in the tooling repository.
- **RGT-165** "Python EOL archive after 6-month soak": the title contradicts the decision (no archive, no
  six-month soak). Reword it as the plan proposes and use it as the GZ gate.
- **RGT-135** delete `AgentVaultClient`: closes with GZ.
- **RGT-216**: obsolete (see section 2).
- **RGT-133** README over-claims about `verify_audit_chain`: fold into the README rewrite (RGT-530).
- **RGT-222** password storage and forgot-password flow: not applicable (no passwords); needs Will's ack.
- **RGT-16** TPM epoch anchor (in progress, draft PR #16 untouched since July): design only; park it.
- **Draft PR #15** (RGT-163, v0.3.0 release plumbing, untouched since July, 13 failing checks): superseded.
  Its three files have all changed on master since. Close it when the v0.4.0 release work starts.
- Duplicates already cancelled correctly: RGT-495 (of 494), RGT-5/20, RGT-7/22/53, RGT-10 (of 16), RGT-11/17,
  RGT-12/18.

## 6. Blocked on Will

| Item | What is needed |
|---|---|
| PRs #19, #22, #23 | docs, mergeable, waiting since 2026-11-26. They unblock about 100 of the in-review ASVS and governance rows. |
| RGT-377 (D7) export v2 with HMAC | format change sign-off |
| RGT-399 (D8) ciphertext header | format change sign-off (plan default: no) |
| RGT-217, RGT-218 | format changes; plan default: after GZ |
| RGT-222, RGT-280, RGT-285, RGT-315, RGT-408 | accepted-risk / not-applicable acknowledgement |
| RGT-31 | thresholds for risk scoring (design only so far) |
| RGT-503 | Windows Defender flags the cross-built test binary: decide on code signing |
| RGT-501 | Windows VM validation was done on `f8ace41` / `57eeae9`, before the server and CLI ran on the real vault. I re-ran the CLI flow on `5a049d2` (run log). The Python interop part was not repeated. |
| Branch protection on master | only a repository admin can set it (RGT-533) |

## 7. Recommended clean-up, in order

1. Merge or reject PRs #19, #22, #23. Then close the ASVS and governance rows chapter by chapter with one
   comment each that links the chapter document (7 bulk actions).
2. Close what section 4 lists, and the eight former phantom issues.
3. Fix the epic statuses in section 2; reopen RGT-492 or close its children.
4. Move or cancel RGT-167 to 196.
5. Add a comment on each issue in section 3 that says what is true in Go, and link the new issue that
   covers the gap. Do not reopen them: the new issues carry the work.
