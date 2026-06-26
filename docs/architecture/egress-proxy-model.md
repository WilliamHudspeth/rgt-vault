# Architectural Design: Egress-Proxy /use Model (RGT-24)

## Overview
This document outlines a future architecture for `rgt-vault` where the vault operates as an active outbound HTTP proxy (the "egress proxy") for registered upstream services. Instead of releasing secret bytes to the local process or executing hardcoded actions, the vault natively handles the outbound HTTP call, injecting the secret dynamically and returning only the upstream response to the caller. This ensures that plaintext secrets never touch the agent's memory or the localhost network boundary.

## 1. Per-Agent Tokens Design
To securely authenticate calls to the egress proxy, `rgt-vault` will utilize **Per-Agent Capability Tokens**.
* **Token Structure:** Extensions of the v2 capability tokens containing specific agent identities and context bindings.
* **Issuance:** Tokens are issued with a short Time-To-Live (TTL) exclusively for the duration of the authorized agent action.
* **Validation:** The Vault intercepts the proxy request, extracts the Bearer token, and verifies the agent's identity against the capability registry before processing the outbound request.

## 2. Request Templating
The core mechanism for injecting secrets safely is **Request Templating**.
* **Upstream Registration:** Administrators define allowed upstreams and the corresponding HTTP request templates in the Vault configuration (e.g., `github_api_template`).
* **Injection at Edge:** When an agent calls the proxy, they provide a template ID and the dynamic (non-secret) parameters. The Vault fetches the corresponding secret, securely interpolates it into the template (e.g., placing it in the `Authorization` header), and dispatches the request.
* **Safety:** The templating engine prevents secret leakage by ensuring the secret is strictly bound to specific header fields or JSON values, never to URL parameters where they could be logged by upstream load balancers.

## 3. Audit Story
Every outbound call routed through the egress proxy is logged immutably into the hash-chained audit log.
* **Audit Row Format:** The audit log will record a new event type: `EGRESS_PROXY_CALL`.
* **Captured Data:** The log records the `agent_id`, the `template_id`, the target domain, the timestamp, and the `context_hash` (the SHA-256 hash of the non-secret payload).
* **Redaction:** The plaintext secret, the upstream response body, and the raw agent token are strictly excluded from the audit log to prevent lateral data leakage.

## 4. Backward Compatibility Plan
To ensure a smooth transition from the current `execute_capability` and `/use` action models to the egress proxy model:
* **Side-by-side Support:** The egress proxy will be exposed on a distinct HTTP port or a new API prefix (e.g., `/v2/proxy`), allowing the legacy `/v1/secrets/.../use` endpoint to function concurrently without interruption.
* **Action Registry Bridge:** Existing built-in actions (like `http_post_with_auth`) can internally be rewritten to wrap the new egress proxy pipeline, meaning agents using the v1 API will benefit from the architectural improvements without requiring client-side updates.
* **Gradual Deprecation:** Once the egress proxy reaches feature parity with all built-in actions, the `/v1/secrets/.../use` endpoint will emit a deprecation header and eventually be sunset in a subsequent major release.
