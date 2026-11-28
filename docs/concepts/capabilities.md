# Capabilities

> **Gap (Go):** capabilities and capability tokens exist only in the
> end-of-life Python code (`python/capabilities.py`, `python/token.py`). The Go
> server has no capability registry or token verifier; its `/v1/actions` route
> returns a static list of names. This page is the design target for the Go line.

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

Capabilities are authorized via signed JSON tokens. Only **HMAC-SHA256** is implemented (`HMACTokenVerifier`); `Ed25519TokenVerifier` is a placeholder that raises `NotImplementedError`. With HMAC the harness and the vault share one key, so whoever can verify tokens can also mint them. The default lifetime is 60 seconds.

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
