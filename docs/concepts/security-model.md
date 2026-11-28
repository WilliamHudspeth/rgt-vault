# Security Model

> The model below is the design target for the Go line (the only maintained
> line). Capability tokens, a verifier, ABAC, the freeze switch and webhooks are
> implemented today only in the end-of-life Python code; the Go server does not
> have them yet (**Gap (Go)**). See the [threat model](../security/threat-model.md#parity-gaps-gap-go).

The fundamental premise of the RGT Vault security model is **Zero Trust for Agents**.

## Never Trust the Agent
All authorization checks occur at the vault boundary. The vault does not trust:
* The agent's identity claim (on the capability path this is verified via a signed token; on the plain `/use` path the `agent` field is still self-asserted and the bearer token is shared — see the [threat model](../security/threat-model.md#privilege-escalation)).
* The requested capability (must match the token).
* The payload parameters (validated against token bindings).

## Default Deny (Fail Closed)
The system fails closed under all error conditions:
* If no token verifier is configured.
* If a token is expired or invalid.
* If a webhook times out or denies the request.
* If the system is placed into a "freeze" state by an operator.

## Blast Radius Reduction
A stolen capability token only authorizes one specific action, bound to specific parameters, for a limited time (default 60 seconds). A stolen token cannot be used to extract the underlying secret through the Python capability endpoints, because the secret never crosses the vault boundary there. This does not hold if the agent also has shell access as the vault's OS user, or for the Go MCP `lease_secret` tool, which returns plaintext (see [Trust boundary](trust-boundary.md)).
