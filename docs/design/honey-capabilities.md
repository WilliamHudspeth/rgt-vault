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

These tests pin the behaviour:

- `TestHTTPIndistinguishable` and `TestVaultIndistinguishable` check that
  status, body and error class match.
- The audit trail is the ordinary one plus the honey row.
- `TestHTTPTimingClass` is a coarse check that the extra cost is one audit
  insert.

## Never grantable

- `vault.Open` refuses a capability registry that registers a honey name.
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
- A probe costs one extra audit insert, which is well under a millisecond on
  local SQLite. An attacker with very precise timing over many requests could
  in principle notice this. Only the configured names are affected.
