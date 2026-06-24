# Capability Security Architecture (v0.3)

Status: design proposal on the `audit-hook-layer` branch. Not merged.
This document is the entry point for understanding how the vault
evolves from a *secret access controller* into a *capability
executor* for AI agents.

## Why

The v0.2 vault controls *who can read a secret*. An agent that holds
the secret can do anything with it — call any API, write any file,
exfiltrate the value. The v0.3 model controls *what actions the
agent can perform* by moving the action inside the vault. The
secret stays inside the vault; the vault returns the action's
result. The agent never sees the secret.

```
                v0.2                              v0.3
              ──────                            ──────
   Agent                                  Agent
     │                                      │
     │ lease_secret("github_api_key")        │ execute_capability(
     ▼                                      │   "github.read_repo",
   Vault ──── returns plaintext ──────►     │   {"repo": "org/x"})
   Agent makes API call with secret        │   )
   Returns the API response                 ▼
                                          Vault ──► makes API call with
                                                   stored secret internally
                                          Agent  ◄── returns the API response
```

Concretely: the secret never crosses the vault boundary. The blast
radius of a compromised agent is "any action the vault will execute
for the capabilities the harness has authorized" instead of "any
API the agent can call with the secret."

## Components

### 1. Capability tokens (v2 wire format)

`rgt_vault/token.py`. JSON payload, HMAC-SHA256 signed, base64url
envelope. The verifier hierarchy is open: `HMACTokenVerifier` is the
v1 implementation, `Ed25519TokenVerifier` is an architectural stub
for future deployment.

```json
{
  "v": 2,
  "agent_id": "research-agent",
  "capability": "github.read_repo",
  "capability_version": 1,
  "context_bindings": {"repo": "org/research"},
  "exp": 1735689600
}
```

Wire envelope: `base64url(payload_json) + "." + base64url(hmac)`.

**Context bindings** are equality constraints: every pinned
key/value must appear in the request payload with the same value.
Extra keys in the payload are allowed. A token with no bindings
is a free pass on context.

### 2. TokenVerifier

`rgt_vault/token.py`. ABC with `sign` and `verify`. Callers
(`VaultManager.execute_capability`, `TwoFactorHook`) only see the
abstract interface; the trust anchor (shared secret, public key) is
encapsulated inside the concrete verifier.

```python
class TokenVerifier(ABC):
    def sign(self, agent_id, capability, capability_version,
             context_bindings, ttl_seconds) -> str: ...
    def verify(self, token) -> CapabilityV2Token: ...
```

### 3. CapabilityRegistry

`rgt_vault/capabilities.py`. A small `name -> CapabilitySpec` map.
Capabilities declare:

- A **handler** (the callable the vault invokes).
- A set of **supported versions** (refused by `execute_capability`
  if the token's `capability_version` is not in the set).
- A **params_schema** (light key check; deeper validation lives in
  the handler).

Built-in capabilities: `secrets.echo` (diagnostic) and `secrets.use`
(bridge that leases a stored secret and runs a v0.2 action against
it — preserves backwards compatibility for callers that need the
old `lease + callback` shape).

### 4. VaultManager.execute_capability

`rgt_vault/vault.py`. The new primary enforcement point. Order of
checks, all fail-closed:

1. **Freeze** — `self.hook.frozen` → deny + audit
2. **Token verify** — `self.token_verifier.verify(token)` → check
   signature, expiration
3. **Agent / capability / version match** between token and request
4. **Context binding** — `tok.check_context(payload)` → every
   pinned key/value must match
5. **Hook consult** on the capability path (new request shape:
   `operation="capability"`, fields for `capability`,
   `capability_version`, `payload`, `token_metadata`)
6. **Registry lookup + version check** — handler must accept the
   version
7. **Payload validation** against `params_schema`
8. **Rate limit** (reused in-process limiter)
9. **Handler invocation** — handler receives a
   `CapabilityContext(vault, agent_id, token_id, capability,
   capability_version, token_metadata)`. **Secret material is
   never put on the context.**

Audit chain: every execution writes a `CAPABILITY_EXECUTED` row
(or `CAPABILITY_DENIED` for any failure path, `CAPABILITY_FAILED`
for handler exceptions) with `agent`, `capability`,
`capability_version`, `hook`, `context_hash` (sha256 of the canonical
payload, so an operator can correlate the row with a specific
request without recording the payload contents). Audit rows
participate in the same hash chain as legacy rows.

### 5. Hook layer refactor

`rgt_vault/hook.py`. `HookRequest` now carries the new capability
fields in addition to the legacy `secret_name`/`namespace` fields.
A request is a capability request iff `operation == "capability"`
and `capability` is set. Legacy calls still produce the old request
shape; capability calls produce the new one. Hooks can branch on
`req.is_capability`.

`TwoFactorHook` now dispatches on the v1 vs v2 token format
(inspect the payload's `v` key). v1 tokens are accepted on the
legacy secret-access path; v2 tokens are accepted on the
capability path. The shared secret and the replay-protection cache
are shared between the two paths.

`WebhookHook` no longer has a `mode` parameter (the `soar` mode
is removed). The wire envelope is uniform across both paths:
capability requests add `capability`, `capability_version`,
`payload`, and `token_metadata` fields; the harness can branch on
`operation` to render the appropriate view. SOAR products
integrate through this same mode.

`OffHook` and `LogHook` are unchanged. `LogHook.consultations` now
records capability requests too — useful for staging a stricter
hook.

### 6. Freeze / panic stop

The hook's existing freeze architecture is reused. When
`self.hook.frozen` is true:

- `execute_capability` denies immediately, before any token
  verification.
- `lease_secret` (legacy) denies immediately, before any
  cryptographic operation.

Freeze can be triggered via:

- `hook.freeze()` from any caller
- A file at `hook.freeze_file` (the operator's "kill switch")
- `kill -USR1 <pid>` (POSIX signal handler installed by
  `install_freeze_signal_handler`)
- An admin HTTP endpoint when `rgt-vault serve` is started with
  `--admin-token` (operator-side; not in this branch)

Every freeze/unfreeze is recorded in the audit chain.

### 7. HTTP surface

`rgt_vault/server/app.py`. Two new endpoints:

- `GET /v1/capabilities` — read-only listing of the registered
  capabilities, descriptions, and supported versions. Bearer-token
  gated like every other endpoint.
- `POST /v1/capabilities/execute` — the v0.3 primary surface.
  Body: `{capability, agent_id, capability_token, payload,
  capability_version}`. Failure modes mapped to HTTP status:

  | Failure                                   | Status |
  | ----------------------------------------- | ------ |
  | Bearer token missing/invalid              | 401    |
  | Body malformed, no verifier, bad version  | 400    |
  | Token signature/exp/binding, hook deny, freeze | 403 |
  | Capability name not registered            | 404    |
  | Handler raised unhandled exception        | 500    |

  Handler exceptions are sanitized: the response body says
  "capability X failed; see server logs for details"; the full
  traceback is in the server log.

The legacy `POST /v1/secrets/{ns}/{name}/use` endpoint remains
available for backwards compatibility. New integrations should
register a capability and call `/v1/capabilities/execute`.

### 8. Legacy APIs

`lease_secret`, `set_secret`, `rotate_secret`, and
`revoke_secret` are still functional. Their docstrings carry a
`.. deprecated::` directive (visible in Sphinx-generated docs;
not enforced at runtime in the v0.3 cycle). They are removed in
v0.4.

## Security model

**Never trust** (all checked at the vault boundary):

- `agent_id` (the caller's claim is compared to the token's
  `agent_id`)
- `payload` contents (validated against the handler's
  `params_schema`; deeper validation is the handler's job)
- `capability` name (must match the token's `capability`)
- `capability_version` (must match the token's
  `capability_version`; the registry's
  `supported_versions` set is a second gate)
- `token_metadata` (token metadata comes from the verified token,
  not from the request body)

**Fail closed** (default deny at every check):

- No token verifier configured → `execute_capability` raises
  `ValidationError("execute_capability requires a configured
  token_verifier; ...")`.
- Token expired → deny + `CAPABILITY_DENIED` audit row.
- Signature invalid → deny + `CAPABILITY_DENIED` audit row.
- Hook frozen → deny + `CAPABILITY_DENIED` audit row.
- Capability version not in `supported_versions` → deny +
  `CAPABILITY_DENIED` audit row.

**Capability execution is preferred over secret retrieval.** New
code should register a capability and call `execute_capability`.
The legacy `lease_secret` path remains for backwards compatibility
and will be removed in v0.4.

## Threat model

The vault's job is to limit what a compromised agent can do with
a secret. v0.2 made that limit coarse ("the agent can read the
secret and do anything"). v0.3 makes it fine-grained ("the agent
can perform exactly the capabilities the harness has authorized,
with the arguments the token's bindings permit").

Replay usefulness is reduced: a stolen token authorizes one
capability for one window of time, with arguments pinned by the
context bindings. A captured token for `github.read_repo` cannot
be replayed against `github.write_issue`.

Blast radius is reduced: a stolen secret leaves the vault only
through the capability surface. An attacker with code execution
on the agent cannot exfiltrate the secret material even if they
succeed in triggering every capability the agent has — the
secret never crosses the vault boundary.

Out of scope: a fully compromised vault process. The token
verifier's trust anchor (shared secret) is the boundary; the
harness holds it, the vault verifies against it. A process that
can read the vault's memory can also read the shared secret if
the verifier keeps it in memory — we do, by design (the harness
needs to be able to mint tokens without a network round trip).
Mitigations (TPM-sealed verifier keys, attested enclaves) are
future work.

## Testing

`tests/test_token.py` — verifier unit tests (20 tests).
`tests/test_capabilities.py` — registry + `execute_capability` unit
tests (31 tests).
`tests/test_capability_integration.py` — end-to-end through the HTTP
surface + webhook + freeze + audit chain (12 tests).

Coverage of new code: `token.py` 88%, `capabilities.py` 87%,
`vault.py` 90%, `server/app.py` 91%. All 193 tests pass
(130 legacy + 63 new).
