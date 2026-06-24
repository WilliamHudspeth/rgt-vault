# Usage Guide

This guide covers the detailed usage of `rgt-vault`, including Python APIs, CLI usage, master-secret providers, ABAC policies, and operational tasks.

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

## CLI Usage

```bash
rgt-vault simulate --policy policy.yaml --agent research_agent \
    --namespace openai --purpose inference --action read
# -> ALLOWED / DENIED + reason

# Store a secret. The plaintext value is read from stdin (or use
# --value-file PATH); it is never accepted as an argv positional because
# argv is visible to other local users via /proc/<pid>/cmdline.
echo "sk-..." | rgt-vault --db ~/.secure-vault/vault.db --policy policy.yaml \
    set OPENAI_API_KEY - --namespace openai --agent admin
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

## Master-secret providers

`VaultManager` accepts any `MasterSecretProvider`. If none is given, a platform-appropriate one is selected:

| Platform | Provider | Backing store |
|---|---|---|
| Windows | `WindowsDPAPIProvider` | DPAPI-sealed blob (`VAULT_DPAPI_BLOB`) |
| macOS | `MacOSKeychainProvider` | Keychain item |
| Linux | `LinuxTPMProvider` | TPM-sealed blob (`tpm2-tools`) |
| any | `KeyringProvider` | `keyring` Secret Service (dev default) |

Platform providers require you to **seal** the master secret first (see each provider's `seal_master_secret` helper). For a zero-setup start, pass `KeyringProvider()` explicitly.

## Policy examples

Policies are YAML. Attributes default to `*` (match all). Matching is glob-style (`fnmatch`). **`deny` always wins over `allow`; with no matching `allow`, access is denied.**

```yaml
rules:
  # Block an entire namespace outright.
  - effect: deny
    namespace: production

  # An agent may read its own namespace...
  - effect: allow
    agent: research_agent
    namespace: openai
    action: read

  # ...but never for billing purposes.
  - effect: deny
    agent: research_agent
    purpose: billing

  # Admins can do anything.
  - effect: allow
    agent: admin
    namespace: "*"
    action: "*"
```

## Rotation

```python
# Fast rotation: re-wraps the DEK under a new master key. Does NOT re-encrypt
# secrets. Use on suspected master-secret/OS compromise.
vault.rotate_master_key()

# Slow rotation: generates a new DEK and re-encrypts every secret. Use on
# suspected DEK/memory compromise. Recommended periodically.
vault.rotate_dek()
```

`KeyringProvider` supports automated rotation. DPAPI/TPM providers require re-sealing the master secret out-of-band.

## Backup and recovery

```python
blob = vault.export_vault()          # base64 JSON; secret values stay encrypted
# ... store `blob` somewhere durable ...

# Restore MUST target the same vault: same vault_id and the original
# keychain.json (DEK). Importing into a different vault is refused.
vault.import_vault(blob)
```

Back up `vault.db` **and** `keychain.json` together. The master secret lives in the OS store and is backed up separately according to your OS's mechanism.

## Performance

Sample numbers (Windows 11, single run — **machine-dependent, not a guarantee**):

| Operation | Time |
|---|---|
| Unlock vault (Argon2id 256 MB + DEK unwrap) | ~360 ms |
| Set secret (encrypt + insert + audit) | ~12 ms |
| Lease + decrypt secret | ~19 ms |
| Rotate master key (re-wrap KEK) | ~480 ms |
| Rotate DEK (re-encrypt 1000 secrets) | ~6.9 s |

Unlock and master-key rotation are dominated by Argon2id. Per-secret set/lease latency is dominated by the SQLite audit-log write, not the cryptography.
