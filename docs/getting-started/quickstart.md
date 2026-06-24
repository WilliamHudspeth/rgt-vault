# Quick Start

This guide covers the fastest way to get started with RGT Vault.

## Quick Start (Python)

For local development the simplest master-secret source is the cross-platform OS keyring. For production, use a sealed platform provider (DPAPI/TPM).

```python
from rgt_vault.vault import VaultManager
from rgt_vault.keychain import KeyringProvider

policy = """
rules:
  - effect: allow
    agent: research_agent
    namespace: openai
    action: read
  - effect: allow
    agent: admin
    namespace: "*"
    action: write
"""

vault = VaultManager(
    db_path="./.secure-vault/vault.db",
    policy_yaml=policy,
    master_provider=KeyringProvider(),   # dev convenience
)

# Store a secret (admin is allowed to write any namespace)
vault.set_secret("OPENAI_API_KEY", "sk-...", namespace="openai", agent="admin")

# Use it without the plaintext leaking to the caller.
# The callback receives a *bytearray* that is wiped when it returns.
def call_api(key_buf: bytearray):
    api_key = key_buf.decode("utf-8")   # your copy — your responsibility
    ...                                 # use api_key
    return "done"

result = vault.execute(
    agent="research_agent",
    namespace="openai",
    purpose="inference",
    secret_name="OPENAI_API_KEY",
    callback=call_api,
)
```

## HTTP Server

For clients that can't call Python directly (an LLM agent in Ollama/llama.cpp/ vLLM, a shell script, another language), run the optional local HTTP server.

```bash
pip install -e ".[server]"
rgt-vault init                 # mints a bearer token (prints the value once)
rgt-vault serve                # binds 127.0.0.1:8765 (loopback only)
```

The server is a thin layer over the same `VaultManager`: every request is gated by the ABAC policy, rate limiter, honeytokens, and hash-chained audit log. **Plaintext never crosses the HTTP boundary** — instead of returning a secret, you ask the vault to run a named *server-side action* that consumes the secret in-process and returns only the result.

```bash
TOKEN="...the token from rgt-vault init..."

# Store a secret
curl -s localhost:8765/v1/secrets -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"OPENAI_API_KEY","value":"sk-...","agent":"admin"}'

# Use it: the vault injects the key as a Bearer token on an outbound call and
# returns only the upstream response — the LLM never sees the secret.
curl -s localhost:8765/v1/secrets/default/OPENAI_API_KEY/use \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"action":"openai_chat","agent":"research_agent","purpose":"inference",
       "params":{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}}'
```

