# Migration Guide: v0.2 → v0.3

Status: in-progress on the `audit-hook-layer` branch. Not merged.
This guide covers what changes for callers of the v0.2 vault and
how to move to the v0.3 capability model incrementally.

## TL;DR

- The v0.2 API still works. `lease_secret`, `set_secret`,
  `rotate_secret`, `revoke_secret`, and `execute` are
  unchanged in behavior. The `set_secret` docstring now carries
  a `.. deprecated::` directive.
- The new primary surface is `execute_capability`. New code
  should register a capability and call it. v0.2 callers can
  migrate one capability at a time.
- Hooks consulted on the v0.2 path still work; they see a
  `HookRequest` with `operation in {"read", "write", "rotate",
  "revoke", "list", "simulate"}`. Capability calls produce a
  different `operation="capability"` with additional fields.
  Hooks that only know about the v0.2 shape can either deny
  the new path (default) or be updated to branch on
  `req.is_capability`.
- The `soar` hook mode is **removed**. SOAR products integrate
  through `webhook` mode.
- A new `rgt_vault.token.HMACTokenVerifier` is the trust anchor
  for v2 capability tokens. Wire it into `VaultManager` and
  start minting tokens.

## Compatibility matrix

| v0.2 surface                           | v0.3 status                | Migration path |
| -------------------------------------- | -------------------------- | -------------- |
| `lease_secret(name, agent, ns, ...)`   | Deprecated, still works    | Move to `execute_capability("secrets.use", ...)` |
| `set_secret(name, value, ns, agent)`   | Deprecated, still works    | Operator-side config; not agent-facing |
| `rotate_secret()`                      | Unchanged                  | n/a |
| `execute(agent, ns, purpose, name, cb)`| Deprecated, still works    | Register a capability and call `execute_capability` |
| HTTP `POST /v1/secrets/{ns}/{name}/use`| Deprecated, still works    | HTTP `POST /v1/capabilities/execute` |
| HTTP `POST /v1/secrets` (set)          | Unchanged                  | Operator-side config; not agent-facing |
| `TwoFactorHook(mode="soar")`           | **Removed**                | Use `TwoFactorHook` (default) or `WebhookHook` |
| `hook_from_config({"mode": "soar"})`   | **Raises `ValidationError`** | Use `mode: "webhook"` and translate in the harness |
| `HookRequest(operation, agent, ns, purpose, secret_name, capability_token)` | Unchanged | New fields added; check `req.is_capability` |
| `CapabilityToken` (v1)                 | Unchanged (still issued by `TwoFactorHook.issue`) | Use `HMACTokenVerifier` for v2 |
| `TokenStore`, `load_or_create_token`   | Unchanged                  | n/a |

## Step-by-step: move one capability

The v0.3 model is opt-in. The v0.2 vault continues to serve
legacy callers while you migrate. The steps below are the
smallest possible change for one capability.

### 1. Add a capability handler

```python
# my_capabilities.py
from rgt_vault.capabilities import CapabilityRegistry

def _github_read_repo(payload, ctx):
    # ``ctx.vault`` is the VaultManager; ``ctx.agent_id`` is the
    # verified agent; ``ctx.token_id`` is the deterministic
    # token id (safe to log).
    repo = payload["repo"]
    # ... fetch repo contents, return the result ...
    return {"repo": repo, "ok": True}

registry = CapabilityRegistry()
registry.register(
    name="github.read_repo",
    handler=_github_read_repo,
    description="Read a repository's contents via the GitHub API.",
    supported_versions={1},
    params_schema=["repo"],
)
```

### 2. Wire the verifier and the registry

```python
import os
from rgt_vault.vault import VaultManager
from rgt_vault.token import HMACTokenVerifier
from rgt_vault.hook import OffHook  # or TwoFactorHook, WebhookHook
from my_capabilities import registry

vault = VaultManager(
    db_path="...",
    policy_yaml="...",
    master_provider=...,
    hook=OffHook(),
    token_verifier=HMACTokenVerifier(os.environ["RGT_VAULT_HARNESS_KEY"].encode()),
    capability_registry=registry,
)
```

### 3. Mint a v2 token from the harness

```python
from rgt_vault.token import HMACTokenVerifier

verifier = HMACTokenVerifier(shared_secret)
token = verifier.sign(
    agent_id="research-agent",
    capability="github.read_repo",
    capability_version=1,
    context_bindings={"repo": "org/research"},  # pin which repo
    ttl_seconds=300,
)
# Hand ``token`` to the agent.
```

### 4. The agent calls execute_capability

```python
result = vault.execute_capability(
    capability_name="github.read_repo",
    payload={"repo": "org/research"},
    agent_id="research-agent",
    capability_token=token,
    capability_version=1,
)
```

The vault verifies the token, checks the bindings, consults the
hook (if configured), looks up the handler, validates the payload
against the handler's `params_schema`, applies the rate limit, and
invokes `_github_read_repo(payload, ctx)`. The secret material
never crosses the vault boundary.

### 5. (Optional) Wire the hook for additional gating

```python
from rgt_vault.hook import TwoFactorHook

vault.hook = TwoFactorHook(shared_secret=shared_secret)
```

Now the hook gets consulted on every capability execution. The
hook sees `HookRequest(operation="capability", ...)` and can
branch on `req.is_capability` to apply per-capability policy.

## Step-by-step: migrate an existing v0.2 caller

A v0.2 caller that does:

```python
with vault.lease_secret("github_token", "agent-1", "default", "use it") as buf:
    requests.get("https://api.github.com/repos/org/research",
                 headers={"Authorization": f"Bearer {bytes(buf).decode()}"})
```

becomes:

```python
# On the harness:
token = verifier.sign(
    agent_id="agent-1",
    capability="github.read_repo",
    capability_version=1,
    ttl_seconds=300,
)

# On the agent:
result = vault.execute_capability(
    capability_name="github.read_repo",
    payload={"repo": "org/research", "headers": {}},
    agent_id="agent-1",
    capability_token=token,
    capability_version=1,
)
```

The capability handler holds the secret material:

```python
def _github_read_repo(payload, ctx):
    repo = payload["repo"]
    extra_headers = payload.get("headers", {})
    # ctx.vault.lease_secret still works -- the secret leaves the
    # vault only to the handler, never to the agent.
    with ctx.vault.lease_secret("github_token", ctx.agent_id, "default", "github.read_repo") as buf:
        token_str = bytes(buf).decode()
        r = requests.get(
            f"https://api.github.com/repos/{repo}",
            headers={**extra_headers, "Authorization": f"Bearer {token_str}"},
        )
        return {"status": r.status_code, "body": r.text}
```

The agent never sees `buf`. The handler does, and the
zeroization guarantee on `lease_secret` still applies.

## Step-by-step: update a custom hook

A custom hook in v0.2 looked like:

```python
class MyHook(AuditHook):
    def consult(self, req: HookRequest) -> HookResponse:
        if req.operation == "read":
            return self._check_read(req)
        return HookResponse(decision=HookDecision.ALLOW)
```

In v0.3, the hook also sees capability requests. To opt in to
the new shape:

```python
class MyHook(AuditHook):
    def consult(self, req: HookRequest) -> HookResponse:
        if req.is_capability:
            return self._check_capability(req)
        if req.operation == "read":
            return self._check_read(req)
        return HookResponse(decision=HookDecision.ALLOW)

    def _check_capability(self, req):
        # req.capability, req.capability_version, req.payload,
        # req.token_metadata are all populated.
        ...
```

A v0.2 hook that ignores the new fields will continue to work
for legacy secret-access calls. On the capability path it will
see `operation="capability"` and may return ALLOW (default
behavior) or DENY (if the hook has policy that requires
recognition).

## Step-by-step: SOAR migration

If you previously ran `rgt-vault serve` with `--hook-mode soar`:

```
# v0.2 (no longer works):
$ rgt-vault serve --hook-mode soar --webhook-url https://shuffle.example.com/...

# v0.3 (works):
$ rgt-vault serve --hook-mode webhook --webhook-url https://my-front.example.com/...
```

The fronting service translates the SOAR's response shape to
the vault's expected JSON:

```json
{"decision": "allow"}     // or "deny" / "freeze"
```

If your SOAR (Shuffle, Tines, etc.) can be configured to
return this shape directly, you don't even need a fronting
service — just point the vault's webhook URL at the SOAR's
HTTP listener.

## Step-by-step: HTTP API migration

A v0.2 HTTP caller:

```
POST /v1/secrets/default/github_token/use
{
  "action": "http_get_with_auth",
  "agent": "agent-1",
  "purpose": "fetch repo",
  "params": {"url": "https://api.github.com/repos/org/research"}
}
```

becomes (v0.3):

```
POST /v1/capabilities/execute
{
  "capability": "github.read_repo",
  "agent_id": "agent-1",
  "capability_token": "<v2 token from the harness>",
  "payload": {"repo": "org/research"},
  "capability_version": 1
}
```

The HTTP status codes change shape; the new endpoint maps:

| Outcome                | v0.2  | v0.3  |
| ---------------------- | ----- | ----- |
| Bearer token invalid   | 401   | 401   |
| Capability name unknown| n/a   | 404   |
| Token signature fails  | 403   | 403   |
| Capability denied      | 403   | 403   |
| Handler raised         | 500   | 500 (sanitized) |
| Capability not found in registry | n/a | 404 |
| Capability version not supported | n/a | 400 |

## What to do if you can't migrate right now

Don't. The v0.2 API is fully supported in v0.3. Set the
`--hook-mode` to one of the four valid options (`off`, `log`,
`webhook`, `two_factor`) and continue using `lease_secret` /
`execute` exactly as before. The audit chain still verifies;
legacy secret-access audit rows and new capability audit rows
participate in the same hash chain.

When you're ready to migrate, start with one capability
(see "Step-by-step: move one capability" above), and expand
incrementally. The vault will be in a mixed state during
migration — some callers on the v0.2 path, some on v0.3 — and
that's fine; the v0.3 model is designed for that.
