# Capabilities

RGT Vault replaces the traditional "secret leasing" model with **Capabilities**.

## The Core Concept

Instead of giving an agent a secret (e.g., a GitHub API key) and trusting the agent not to leak or abuse it, RGT Vault executes the authorized action *inside* the vault boundary.

**Traditional Model:**
1. Agent requests secret.
2. Agent calls API with secret.

**Capability Model:**
1. Agent requests `github.read_repo` capability.
2. Vault reads the secret internally, makes the API call, and returns the data.

## Capability Tokens

Capabilities are authorized via signed JSON tokens (HMAC-SHA256 or Ed25519).

```json
{
  "v": 2,
  "agent_id": "research-agent",
  "capability": "github.read_repo",
  "context_bindings": {"repo": "org/research"},
  "exp": 1735689600
}
```

The `context_bindings` field restricts exactly what the agent is allowed to do. If the agent attempts to read a different repo, the Vault denies the request.
