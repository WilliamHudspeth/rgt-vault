# Design: Intent Verification & Risk Scoring Engine (RGT-31)

Status: **design only, Go line (`go/`)**. Nothing here is implemented. The
Python line is end-of-life and is not extended. Line numbers cite master at
`3e269d3`; re-check them before implementing.

Acceptance criteria of RGT-31 this design must satisfy: a 0-100 risk score per
action; configurable thresholds that block; high-risk actions (for example a
`delete_repo`-style action) need explicit human approval or are blocked for
non-admin agents.

## 1. What the code does today (the seams)

| Seam | Where | What it can and cannot do |
|---|---|---|
| `vault.Hook` | `go/internal/vault/hook.go:99-103` (`ID`, `Frozen`, `Consult`) | Returns `allow`, `deny` or `freeze` only (`hook.go:15-20`). An error or panic is a deny (`hook.go:132-151`). Runs **first** on every op, before the rate limiter and ABAC (`hook.go:90-93`), and its decision plus `HookResponse.Extra` is written to the audit chain as `HOOK_<OP>` (`hook.go:157-189`, `Extra` at `hook.go:68-72`). It sees `HookRequest` (`hook.go:40-54`): agent, namespace, purpose, secret name, capability, payload, request id. It does **not** see the token id or scopes. Covers reads, writes, rotate, revoke, list, simulate and the capability path (`capability.go:261`, `337-380`). |
| `approval.Gate` | `go/internal/approval/approval.go:95-98`; `Request` at `:45-58` | Blocks until an operator approves (TOTP when `Require2FA`, separation of duties at `approval.go:552`). Called in `unseal` **after** the ABAC check and before ciphertext is read (`secrets.go:228-262`). Only the read path uses it through the vault. Set/rotate/revoke are gated one layer up in the HTTP handlers (`server/handlers/approvalflow.go:150-176`, refusing with 409 when no broker, `:154`). The **capability path has no approval gate** (`capability.go:125-330`). |
| ABAC | `go/internal/policy/policy.go:197-216` (`Evaluate`, explicit deny wins, default deny); effects are only `allow`/`deny` (`policy.go:237-251`) | Static, stateless, Python-compatible. Its text hash is stored in every audit row (`vault.go:485-492`). Do **not** extend it for risk (byte-compat traps, `policy.go` header). |
| Rate limiter | `go/internal/vault/ratelimit.go:58-92` (`Allow`, `Count`, `Record`, `Reserve`); default 100 per hour per agent (`vault.go:37-38`); shared by leases, gated ops and capabilities (`secrets.go:233`, `gatehelpers.go:53`, `capability.go:302`) | Per-agent sliding window in memory. `Count` reads without recording (`ratelimit.go:78`), which is the right primitive for a rate signal. |
| Agent identity | `go/internal/auth/store.go:94-107` (`Principal{TokenID, Agent, Scopes, Legacy}`), `Authenticate` at `:359`; scopes `agent`, `operator`, `audit`, `lease` (`:25-45`) | The ABAC subject is the token's `agent_id`; a request naming another agent is refused (`server/handlers/identity.go:12-19`). A `Legacy` principal has a self-asserted agent. There is **no agent tier or trust level** in the token record (`store.go:134-141`). |
| Audit log | `go/internal/store/auditlog.go:67-162`; hash input in `go/internal/audit/audit.go:7-14,40-61` | Append-only chain. `agent_id` is **not** part of the hash (`audit.go:7-14`). Rows written by the vault itself (`logAudit`, `vault.go:485-492`) leave `agent_id` NULL; the agent is only inside the `details` text (for example `"Agent: x"`, `secrets.go:266`). Only HTTP-layer rows set it (`handlers.go:148`, `Vault.Audit` at `vault.go:495-507`). |
| Honeytokens | `secrets.go:338-352` | A decoy hit already writes `HONEYTOKEN_TRIGGERED` (critical) and refuses. This is a ready-made high-confidence signal. |
| Capability tokens | `captoken`, binding check at `capability.go:240` | The only place where intent is **cryptographically bound** (agent, capability, version, context bindings pinned by the harness). |

Consequences for the design:

1. A risk decision that needs a human cannot be a `Hook` result today (no
   "require approval" value in `HookDecision`, `hook.go:15-20`). It has to go
   through `approval.Gate` or the handler gate.
2. History cannot be queried from `audit_logs.agent_id` for vault-written
   events. A first version must keep its own in-memory counters (like the
   rate limiter) rather than parse `details` strings.
3. ABAC already decides *who may do what*. Risk scoring must only ever add
   friction on top of an ABAC allow. It must never turn a deny into an allow.

## 2. Threat model (what scoring is for)

In scope (actor holds a **valid** agent token and passes ABAC):

- T1 Prompt-injected or compromised agent that enumerates secrets, or reads many
  in a burst (mass extraction below the hard rate cap).
- T2 Agent suddenly touching namespaces or secrets it has never used, or doing
  so at unusual times.
- T3 Agent attempting a destructive or irreversible action (revoke, rotate,
  a destructive capability) it normally never performs.
- T4 Stolen agent token replayed from another context: new source IP, odd
  hours, new access pattern.
- T5 Probing: a run of denials (`POLICY_DENIED`, `APPROVAL_DENIED`,
  `AUTHZ_DENIED`, failed credentials) followed by a success.

Out of scope or only partly covered (state honestly):

- Root or code execution on the host (everything in memory is readable; see
  `docs/security/threat-model.md`).
- Slow-and-low extraction that stays under every threshold. A rule engine is
  evadable by someone who knows the rules. It raises cost; it is not a
  boundary.
- **True intent verification.** `purpose` is a free-text string the agent
  asserts (`HookRequest.Purpose`, `hook.go:44`). The engine can only check
  *consistency* (is this purpose one this agent declared for this
  namespace?), not truth. Cryptographic intent exists only on the capability
  path (token bindings). The doc therefore calls the feature "intent
  consistency checking", and the open questions ask whether to mandate
  capability tokens for the highest-risk actions.
- A malicious operator, or a compromised approver token (separation of duties
  is the existing control, `approval.go:552`).

## 3. Inputs (signals)

All signals are computed once per request into an immutable `Signals` struct, so
the score is a pure function of `(Signals, Config)`.

Static (from the request and a new risk config):

| Signal | Source | Notes |
|---|---|---|
| operation / action class | `HookRequest.Operation`, `approval.Request.Action`, capability name | Base impact points per class: read < list < write < rotate < revoke < `destructive` (config-defined list, for example `delete_repo`). |
| agent tier | glob on agent id in the risk config (`agent: "ci-*"` → tier `standard`) | The token store has no tier today (see open question Q3). |
| namespace sensitivity | glob → points in config | `prod/*` scores higher than `dev/*`. |
| secret flags | `Requires2FA` (`secrets.go:208-224`), honeytoken | Honeytoken hit = hard `deny` (already refused today). |
| principal quality | `Principal.Legacy`, scope set | Legacy self-asserted agent adds points; a `lease`-scoped token reading plaintext adds points. Needs the principal passed in (see §5). |
| declared intent | config: per-agent list of expected `(namespace glob, purpose glob)` | Mismatch adds points. This restates ABAC loosely on purpose, so it only matters when ABAC is broad (for example `purpose: "*"`). |

Dynamic (in-memory sliding windows keyed by agent, injected clock):

| Signal | Computation |
|---|---|
| request rate | `RateLimiter.Count(agent)` (`ratelimit.go:78`) over the window, as a fraction of the cap |
| burst | events in the last 60 s |
| breadth | distinct `(namespace, name)` touched in the window (enumeration) |
| novelty | `(agent, namespace, name)` not in a bounded seen-set (LRU, e.g. 10 000 per agent) |
| denial run | count of ABAC / approval / authz denials for the agent in the window (fed by the engine's own observation of decisions, not by parsing the log) |
| time of day | UTC hour against configured working hours per tier; off-hours adds points |

Not used: free-text analysis of `purpose` by a model, any network lookup,
anything that sends request data off the host.

## 4. Scoring model

Options:

| | Rule-based weighted sum | Anomaly baseline (per-agent EWMA / z-score) |
|---|---|---|
| Explainable | Yes: score = sum of named rules | Weak: "3.2 sigma" is not an operator's reason |
| Deterministic | Yes: pure function, golden-testable | Only with persisted state and fixed seeds |
| Cold start | None: static rules work on day 1 | Needs a learning period; new agents look anomalous or are waved through |
| Poisoning | An agent cannot raise its own limits | An agent can pad with benign calls to widen its baseline |
| State | Counters in memory | Persisted per-agent statistics, migration, retention |
| Effort | M | L |

**Recommendation: rule-based weighted sum, with one baseline-flavoured rule
(novelty via a bounded seen-set).** It is the simplest option that is
explainable and deterministic, and the acceptance criteria (0-100 per action,
configurable thresholds) do not need more. An anomaly model stays a later,
opt-in addition that may only *add* points, never lower them.

```
score = clamp(0, 100, sum(points of every rule that fires))
```

Every fired rule is recorded as `{id, points}`. Rules are listed in the config
and evaluated in a fixed order. Example default weights (to be tuned, not
measured):

| Rule id | Fires when | Points |
|---|---|---|
| `op.read` / `op.write` / `op.rotate` / `op.revoke` / `op.destructive` | base by action class | 5 / 20 / 40 / 50 / 70 |
| `ns.sensitive` | namespace matches a sensitive glob | +15 |
| `agent.legacy_principal` | `Principal.Legacy` | +10 |
| `agent.lease_scope` | plaintext lease over HTTP | +5 |
| `hist.novel_secret` | first access to this secret by this agent | +10 |
| `hist.breadth` | more than N distinct secrets in the window | +20 |
| `hist.rate_high` | count over 70 % of the cap | +15 |
| `hist.denial_run` | at least 3 denials in the window | +25 |
| `time.off_hours` | outside the tier's hours | +10 |
| `intent.mismatch` | declared intent list exists and nothing matches | +15 |
| `hist.unavailable` | the engine lost its window state (restart is fine, an internal error is not) | +30 |

Hard overrides (not scored, evaluated after the sum, only escalate):

- `floor: {match: capability or action class, min: require_approval}`.
- `deny_unless_tier: {match: destructive, tiers: [admin]}`.

## 5. Decision outputs and where it plugs in

Bands, configurable: `score < approve_at` → **allow**; `approve_at <= score <
deny_at` → **require_approval**; `score >= deny_at` → **deny**. Starting
defaults: 40 and 80. `Assessment` carries `{Score, Decision, Reasons[],
ConfigHash, Mode}`.

Rules of composition:

- ABAC deny, hook deny, rate limit, honeytoken and every existing refusal stay
  as they are and come first. Risk is evaluated **after the ABAC allow** and
  can only keep the result or make it stricter.
- `require_approval` with no broker configured is a **deny** (same fail-closed
  rule as `approvalflow.go:154`).
- The approver must still be a different token (`approval.go:552`) and, when
  the secret needs it, a TOTP code. Risk adds no new way to approve.
- Never approve by score: a high score cannot be lowered by the requester.

Integration plan (smallest change that works):

1. **New package `go/internal/risk`**: pure engine (`Config`, `Signals`,
   `Assess(Signals) Assessment`), YAML config in a **separate file** with its
   own hash, plus the in-memory window state. It imports no vault, store or
   approval package, in the style of `internal/policy` and `internal/approval`.
2. **Shadow mode via the existing hook seam, no vault change.** A
   `hooks.RiskHook` (new file beside `go/internal/hooks/basic.go:11-77`)
   computes the assessment in `Consult`, always returns `allow`, and puts
   `{"risk_score","risk_decision","risk_rules"}` in `HookResponse.Extra`
   (`hook.go:68-88`), so it lands in the existing `HOOK_<OP>` row with no new
   event. Because `Hook` is already wired for all ops and the capability
   path, shadow mode covers everything on day one.
3. **Enforcement via an `approval.Gate` wrapper** (`approval.go:95-98`):
   `risk.Gate{Inner approval.Gate, Engine}` returns `Allowed:false` for deny,
   delegates to the broker for require_approval, and passes through for allow.
   This needs only `vault.Config.Approval` (`vault.go:73-74`). Today the vault
   installs the broker only with `--require-approval` (`server/stack.go:253-255`),
   so the wiring must also install the wrapper when risk enforcement is on.
4. **Two small vault/handler additions** (separate issues): call the
   same `Assess` in the HTTP handler gate for set/rotate/revoke
   (`approvalflow.go:150`) and add an approval step on the capability path
   (between `capability.go:261` and `:269`), which has none today.
5. **Principal propagation.** `HookRequest` has no token id or scopes
   (`hook.go:40-54`), so `agent.legacy_principal` and `agent.lease_scope` need
   the principal in the context. `approval.RequesterFrom(ctx)` already
   carries an identity for the broker (`approvalflow.go:175`); the same
   context value can be read by the engine. Phase 2 can ship without those two
   rules if this is delayed.

Why not extend ABAC with a `require_approval` effect or a `risk:` key: the
policy parser is byte-compatible with Python and its hash is part of every audit
row (`policy.go` header, `vault.go:490`). A separate risk file leaves both
untouched.

## 6. Failure modes (fail closed)

| Failure | Behaviour |
|---|---|
| Risk config missing or invalid at start with enforcement on | Refuse to start (like a bad policy). |
| `Assess` returns an error or panics (enforce mode) | `deny`, reason `risk engine error`, matching `hook.go:132-151`. |
| Same, in shadow mode | Record `risk_error` in the audit row and **allow**: shadow never enforces. This is the only intentional fail-open and is labelled by `Mode`. |
| `require_approval` but no broker | `deny` (`approvalflow.go:154` precedent). |
| Window state lost (restart) | Counters start empty, so history rules under-fire after a restart. Mitigate with `hist.unavailable` only on internal errors, and with a warm start from the audit log in phase 5. State this limitation in the operator docs. |
| Clock jumps | Use the injected clock plus monotonic comparisons; a backwards jump must not shrink a window below its events (reuse the `RateLimiter` pattern, `ratelimit.go:40-54`). |
| Engine lock contention | `Assess` must stay O(rules) with one short mutex; budget 1 ms. The hook is called unlocked (`hook.go:155`), so a slow engine cannot stall the vault lock, only that request. |
| Unknown decision value | `deny` (as `hook.go:145-150`). |

## 7. Privacy

- The score profiles an agent's behaviour. It is kept in memory plus the audit
  log (already per-agent). No new store, no export, no third party.
- Reasons are rule ids and point values, never raw purposes, payloads or
  secret names beyond what the existing rows already hold. `HookRequest.Payload` and the capability token are passed to hooks
  (`capability.go:356-358`), so the engine must never log or store them; it
  reads only the capability name and version.
- Webhook/notifier text for an approval must reuse the existing redaction
  (`go/internal/hooks/redaction.go`) and show score plus rule ids only.
- If any later phase persists history, it needs a retention limit (default 30
  days) and an operator command to purge it.

## 8. Audit event shape (additive only)

Do not touch the hash input, existing event names or existing `details`
strings (`audit.go:7-14`). Add:

- Shadow phase: `extra` keys in the existing `HOOK_*` rows (see §5.2).
- Enforcement phase: one new event `RISK_ASSESSED`, written only when the
  decision is not `allow` or the score is at least `log_at` (default 20), to
  avoid flooding. `secret_name` as for the operation; `agent_id` set on this
  row (not hashed, so it adds no format change). Details is the same
  sorted-key JSON the hooks use (`hook.go:171`, `pyDumps`):

```json
{"agent":"ci-1","config_hash":"…","decision":"require_approval","mode":"enforce",
 "op":"read","rules":[{"id":"hist.novel_secret","pts":10},{"id":"ns.sensitive","pts":15}],
 "score":40}
```

- An approval row stays `APPROVAL_DENIED` (`secrets.go:262-271`); the risk
  reason is appended to its existing `Reason:` text only.

Not verified: whether any external consumer of the audit log (dashboards,
Python tooling) filters on a fixed list of action names. A grep for `HONEYTOKEN_TRIGGERED`/`LEASE_GRANTED` in
`*.go`, `*.py`, `*.sh` and workflow YAML found only the writer in
`go/internal/vault/secrets.go`, `python/vault.py` and a mention in
`python/llm_guide.py`, so no reader that filters by name was found in the
repo, but an operator's own tooling is unknown.

## 9. Testing strategy

- Pure unit tests with an injected clock: one table row per rule, boundary
  values at each threshold, clamp at 0 and 100, rule order independence of the
  total.
- Golden vectors in `go/internal/risk/testdata/` for config → signals →
  assessment (including the reasons list), so a weight change is visible in the
  diff.
- Property tests: adding a firing rule never lowers the score; a result never
  becomes more permissive than the ABAC decision; identical inputs give an
  identical assessment (determinism).
- Fail-closed tests in the style of the existing hook tests
  (`hooks_test.go`): error, panic, unknown decision, no broker.
- Integration test through `vault.Open` with a stub broker: ABAC-allowed read
  with score ≥ approve_at parks a request; ABAC deny never reaches the engine;
  shadow mode never changes a result; `-race` with concurrent agents.
- Fuzz the config parser. New package needs ≥ 85 % coverage (repo rule).
- A tuning harness (non-CI): replay an exported audit log through the engine
  to count how many past requests would have been escalated, before enforcement
  is turned on.

## 10. Rollout

| Phase | Deliverable | Risk |
|---|---|---|
| 0 | This design reviewed; answers to the open questions | none |
| 1 | `internal/risk` engine, config, tests; no wiring | low |
| 2 | `hooks.RiskHook` shadow mode, `extra` in `HOOK_*` rows, `rgt-vault risk explain` and a `risk` field in `simulate` output | low (never enforces) |
| 3 | Tuning period: operator reviews shadow scores for at least a week against real traffic; adjust weights | none |
| 4 | Enforcement for the read path through `risk.Gate` (approval for mid, deny for high), `RISK_ASSESSED` rows, per-agent override | medium: can block legitimate agents; keep a config switch back to shadow |
| 5 | Handler gate for set/rotate/revoke and an approval step on the capability path; destructive-action floors | medium |
| 6 | Optional: agent tier in the token store, persisted history warm start, `agent_id` on vault-written rows | needs format decisions |

## 11. Open questions for Will

1. **Approval scope.** Is `require_approval` allowed to park every agent call
   above the threshold, or only for the explicitly configured destructive
   classes? (Operator fatigue vs coverage.)
2. **Defaults.** Are 40 / 80 (approve / deny) and the weights in §4 acceptable
   starting points, or do you want shadow data first before any default
   enforcement?
3. **Agent tier.** The token store has no tier. Add an optional `tier` field to
   the token record (additive JSON, `auth/store.go:134-141`), or keep tiers in the
   risk config by agent-id glob? "Blocked for non-admin agents" in the issue
   needs one of them.
4. **What is `delete_repo`?** No such action or capability exists in Go yet
   (built-in actions are `openai_chat`, `http_get_with_auth`,
   `http_post_with_auth`, `echo`, `actions/builtin.go:151-171`). Is the risk
   class list meant for future capabilities, or is there a concrete one to
   target?
5. **Capability tokens as the real intent check.** Should the highest-risk
   actions require a v2 capability token (harness-bound intent) rather than a
   score alone?
6. **History source.** In-memory windows only (simple, reset on restart), or
   also set `agent_id` on vault-written audit rows and warm start from the log?
   The second is an additive change but touches every `logAudit` call site.
7. **Legacy shared token.** Should `--legacy-shared-token` requests be capped
   at `require_approval` regardless of score?
8. **Notifications.** Should a `deny` by risk go to the operator webhook
   (`hooks/eventwebhook.go`) like a honeytoken hit, or only to the audit log?
9. **Python.** Confirm the feature is Go-only and that `python/` readers
   ignoring `RISK_ASSESSED` rows is acceptable (python/ is end-of-life).

RGT-31 stays open for the implementation work; this document is the design
deliverable only.
