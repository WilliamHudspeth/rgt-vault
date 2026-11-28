# Honey capabilities (RGT-30)

Status: implemented in Go (`go/internal/honeycap`, which hooks into
`vault.ExecuteCapability`).

A honey capability is a decoy capability name that looks valuable, such as
`aws.admin.full`. It is never registered and never granted, so no legitimate
caller ever uses one. Any call that names one is a detection signal for an
agent exploring what it can do, or for a stolen token being tried out.

## Behaviour

When `POST /v1/capabilities/execute` (`vault.ExecuteCapability`) names a honey
capability, the vault does three things. They run before any token check, so
the trap fires whatever token is sent: garbage, forged, stolen for another
capability, or genuine.

1. **Audit row.** It writes a `HONEY_CAPABILITY_TRIGGERED` row with
   `severity: critical`. The row holds the agent, the requested name and
   version, the entry point, whether a token was presented, and the number of
   payload keys. It never holds the token or any payload values. This is a
   new, additive action name. The audit hash input and the existing rows are
   unchanged.
2. **Alert.** It raises an `approval.EventHoneyCapability` security event
   through the server's notifier. That notifier always writes a log line, and
   also posts to `--security-webhook` when one is set. The event kind is
   Critical, so it uses the webhook's reserved capacity during an event flood.
3. **Ordinary answer.** It then continues down the normal path. The caller
   gets exactly the status and body that any other unregistered capability
   name gets for the same token: 403 for a bad token or a token for another
   capability, and 404 "unknown capability" for a valid token. Nothing tells
   the caller it hit a trap.

`TestHTTPIndistinguishable` and `TestVaultIndistinguishable` pin this: the
status, the body and the error class match those of an ordinary
unregistered name, and the audit trail is the ordinary one plus the honey
row.

## Flood limits

An attacker can send probes at will, so every output of the trap is bounded.

- **Audit rows.** Per agent, per minute (`vault.HoneyAuditPerAgent` = 32,
  `vault.HoneyAuditWindow`):
  - each of the agent's first 32 probes gets a row;
  - after that, only probes whose running count is a power of two get one
    (64, 128, 256, ...);
  - every row carries `probes_in_window`, so 1,000,000 probes produce about
    46 rows and the log still shows how many there were.

  The limiter tracks at most 4096 agents; beyond that, new agents share one
  bucket (`TestHoneyAuditFloodCapped`).
- **Alerts.** Per (agent, honey name), per minute (`honeycap.AlertWindow`):
  - the first probe alerts at once;
  - later probes in the window are only counted;
  - the next alert after the window says how many were suppressed.

  Spelling variants share one window (`TestAlertDedup`). If probing stops
  inside a window, its suppressed count is never alerted, but it is in the
  audit rows.
- **Webhook.** Honey events have their own delivery budget of 2 in flight on
  `--security-webhook`. They therefore cannot use up the reserved slots of
  lockout, auto-deny or separation-of-duties alerts
  (`TestEventWebhookHoneyFloodCannotStarveCritical`).
- **Size.** In the honey row and in the alert, the name and the agent are
  clipped to 128 bytes, with a `(+N bytes)` marker. A name padded with
  200,000 spaces still trips the trap but writes a row under 1 KiB
  (`TestHoneyOversizeNameClipped`).

  The ordinary `CAPABILITY_DENIED` row written afterwards still echoes the
  requested name in full. That is existing behaviour for every name,
  bounded only by the request body limit.

## Never grantable

- `vault.Open` refuses a registry with a registered capability that matches
  a honey name under the trap's own matching (case and whitespace
  ignored). Without this, `honey_capabilities: [Secrets.Echo]` would
  silently disable the built-in `secrets.echo` and turn every legitimate
  call into a false critical alert. After `Open`, the registry refuses such
  names in `Register` (`TestOpenRefusesNormalizedCollision`,
  `TestRegisterRefusesHoneyAfterOpen`).
- A honey name registered at runtime after `Open` is still never executed,
  even with a genuine token (`TestHoneyNeverRuns`).
- Names match case-insensitively after trimming whitespace. `AWS.Admin.FULL`
  trips the same trap.

## Configuration

Five names are always active: `aws.admin.full`, `iam.root.assume`,
`secrets.export_all`, `vault.master_key.read` and `db.prod.superuser`. They
are public because they are in the source, so add your own names under a
top-level `honey_capabilities` key in the policy file:

```yaml
honey_capabilities:
  - payments.wire.unrestricted
rules:
  - {effect: allow, agent: "ci-*", namespace: ci, purpose: "*", action: "*"}
```

The ABAC engine, in both Go and Python, ignores this key. If the value is not
a list of names matching `[A-Za-z0-9._:/-]{1,128}`, startup fails, because a
typo must not silently disable a trap. Do not write ABAC rules that mention
honey names. They are never executed anyway.

## Limits

- Honey capabilities are not listed by `GET /v1/capabilities`. Listing them
  would change the Python-compatible listing, and would invite legitimate
  agents to try them. Agents find them by guessing names, or by reading
  configuration or documentation the operator plants on purpose.
- A probe costs one extra audit insert, while it is under the row cap. An
  independent review measured about 45-50 µs, roughly 30% slower, on ext4
  with SQLite WAL. A determined local attacker who times many requests can
  therefore tell a honey name from an ordinary one. They can do that only
  after probing it, by which point the alert has fired. There is no timing
  test: a check loose enough to be stable in CI would guard nothing.
