# Security Model

The fundamental premise of the RGT Vault security model is **Zero Trust for Agents**.

## Never Trust the Agent
All authorization checks occur at the vault boundary. The vault does not trust:
* The agent's identity claim (verified via cryptographic token).
* The requested capability (must match the token).
* The payload parameters (validated against token bindings).

## Default Deny (Fail Closed)
The system fails closed under all error conditions:
* If no token verifier is configured.
* If a token is expired or invalid.
* If a webhook times out or denies the request.
* If the system is placed into a "freeze" state by an operator.

## Blast Radius Reduction
A stolen capability token only authorizes one specific action, bound to specific parameters, for a limited time. A stolen token cannot be used to extract the underlying secret, and an agent with arbitrary code execution cannot dump the secret because it never crosses the vault boundary.
