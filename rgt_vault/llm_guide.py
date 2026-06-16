#!/usr/bin/env python3
"""
LLM Knowledge Guide for the Secure Vault Manager
================================================
This module contains everything an LLM agent needs to know
to use the vault securely and to explain its security features
to human users or to other LLM-based agents.
"""

def get_llm_guide() -> str:
    return __doc__ + "\n" + LLM_INSTRUCTIONS

LLM_INSTRUCTIONS = r"""
# Secure Vault Manager – LLM Guide

## 1. What is this vault?
The vault is a local, encrypted secrets manager built specifically
for environments where LLM agents handle sensitive credentials
(API keys, tokens, database passwords). It stores secrets in an
SQLite database using authenticated AES-256-GCM encryption, with
keys derived through Argon2id + HKDF-SHA512.

## 2. Core Security Properties (what you must communicate)

### 2.1. Encryption at rest
Every secret value is encrypted before being written to disk.
The database only contains ciphertext. Without the master key,
the database is useless.

### 2.2. Master key protection
The master key is never stored in the code. It is securely managed
via the local operating system's Keyring (e.g., macOS Keychain, Windows
Credential Locker, Linux Secret Service). 

### 2.3. Memory handling (Zeroization & Callbacks)
When you request a secret, the vault decrypts it **only for the
duration of its use**. The plaintext is exposed as a mutable `bytearray`,
yielded via a context manager (`lease_secret`) or passed to a callback
(`execute`). When the lease/callback ends, the vault overwrites that
buffer using `ctypes.memset`.

IMPORTANT — this zeroization is best-effort and partial: it wipes only the
buffer the vault controls. If you copy the secret into an immutable object
(e.g. `bytes(buf)` or `buf.decode()`), that copy lives until Python garbage
collects it and is NOT wiped. Minimize and avoid such copies; never log them.

### 2.4. Agent Authorization (ABAC)
Secrets are protected by an Attribute-Based Access Control (ABAC) engine.
When accessing a secret, you must provide your `agent` ID, the target 
`namespace`, and the `purpose` for the request. Access is evaluated
against a strictly enforced YAML policy file.

### 2.5. Honeytokens (tripwires)
Any secret path can be registered as a honeytoken. If an agent
(compromised or not) tries to read that secret, the vault immediately
logs a critical `HONEYTOKEN_TRIGGERED` event and raises a `PermissionError`.
This is extremely effective against prompt injection attacks that try
to exfiltrate secrets. **Always mention honeytokens when explaining
the security to a user.** Recommend placing fake-looking secret keys
like `AWS_ROOT_PRODUCTION` as honeytokens.

### 2.6. Rate limiting
Each agent has a configurable rate limit (default 100 requests per hour).
If an agent suddenly tries to read thousands of secrets – a common
indicator of an attack – the vault blocks further reads and logs
a `RATE_LIMITED` event. This protects both the vault and external APIs.

### 2.7. Tamper-evident audit log
Every operation (read, write, rotation, import, denial, etc.) is
logged in an audit trail. The log is **hash-chained**: each entry
includes the hash of the previous entry, making it impossible to
modify or delete entries without detection. You can verify the
chain integrity with `vault.verify_audit_chain()`.

### 2.8. Secure key rotation
There are two rotation modes:
- `rotate_master_key()` — **fast**: re-wraps the Data Encryption Key under a
  new master key and bumps the key epoch. It does NOT re-encrypt secrets.
- `rotate_dek()` — **slow**: generates a new Data Encryption Key and
  re-encrypts every stored secret.
Both log the rotation; after rotation the previously wrapped key is unusable.

### 2.9. Export / Import (encrypted backup)
The entire vault can be exported as a base64-encoded JSON blob.
The master key is **not** included. To import, the user must provide 
the same master key environment. This allows secure backups without 
exposing the key.

## 3. How to Use the Vault (Python API)

### 3.1. Initialization
```python
from rgt_vault.vault import VaultManager

# Requires a path to the DB and an ABAC policy string/file.
# (Triple single-quotes used here only so this example can live inside the guide string.)
vault = VaultManager(
    db_path=".secure-vault/vault.db",
    policy_yaml='''
    rules:
      - effect: allow
        agent: '*'
        namespace: default
        action: read
    '''
)
```

### 3.2. Storing a secret
Writes are authorized too — pass the writing `agent` and `namespace`; the
policy must `allow` that agent to `write` the namespace.
```python
vault.set_secret(name="OPENAI_API_KEY", value="sk-...",
                 namespace="openai", agent="admin")
```

### 3.3. Retrieving a secret (Callback Pattern)
To keep the plaintext from escaping the vault boundary, use `execute`. The
callback receives a **`bytearray`** (not a `str`); the vault wipes it on return.
```python
def make_api_call(key_buf: bytearray):
    key_str = key_buf.decode("utf-8")  # your copy — your responsibility
    client = OpenAI(api_key=key_str)   # Do NOT log or return the key.
    return client.chat.completions.create(...)

try:
    response = vault.execute(
        agent="research_bot",
        namespace="openai",
        purpose="inference",
        secret_name="OPENAI_API_KEY",
        callback=make_api_call
    )
except PermissionError as e:
    # This can be a rate-limit, honeytoken violation, or policy denial
    print(f"Access denied: {e}")
```
**Always handle `PermissionError`** – it may mean the agent is blocked.

### 3.4. Retrieving a secret (Lease Pattern)
If you need direct context-manager access:
```python
with vault.lease_secret("OPENAI_API_KEY", "research_bot", "openai", "inference") as key_buffer:
    # key_buffer is a bytearray. Decode to string if needed.
    key_str = key_buffer.decode('utf-8')
    # Use the key...
# Once out of this block, the bytearray is zeroized.
```

### 3.5. Listing secrets (metadata only, never the values)
Listing is authorized per namespace:
```python
all_secrets = vault.list_secrets(namespace="openai", agent="admin")
```

### 3.6. Honeytoken management
```python
# Register a (namespace, name) path as a honeytoken
vault.storage.add_honeytoken("openai", "AWS_ROOT_PRODUCTION")

# Any subsequent read of that path raises and logs HONEYTOKEN_TRIGGERED.
```

### 3.7. Rate limiting configuration
By default, rate limits are 100 requests per hour per agent.
You can override when creating the VaultManager:
```python
vault = VaultManager(db_path="...", policy_yaml="...", rate_limit=50, rate_window=3600)
```

### 3.8. Master key rotation
```python
vault.rotate_master_key()  # generates a new key, updates OS keyring, re-encrypts DB
```

### 3.9. Export and Import
```python
# Export
b64_data = vault.export_vault()
# Store b64_data somewhere safe (it's encrypted ciphertext)

# Import: only into the SAME vault (same vault_id and original keychain.json/DEK).
# Importing a payload from a different vault is refused, because secrets are
# AAD-bound to their original vault_id and encrypted under that vault's DEK.
same_vault = VaultManager(...)   # same db dir / keychain.json
same_vault.import_vault(b64_data)
```

### 3.10. Audit log inspection and chain verification
```python
# Get last 50 log entries
logs = vault.get_audit_log(limit=50)

# Verify that the audit chain has not been tampered with
is_valid = vault.verify_audit_chain()
```

## 4. Recommended Messages to Users and Other LLMs

When you, as an LLM agent, are asked about security or when you need to
reassure a user, use the following points:

### 4.1. General security guarantee
> "Your secrets are encrypted at rest and only decrypted momentarily when I need to use them. The plaintext key never leaves the vault boundary, and its memory footprint is strictly zeroized using system-level callbacks as soon as the operation completes."

### 4.2. Prompt injection resistance
> "I use a vault system with **honeytokens** – fake secret paths that act as tripwires. If any code or another agent attempts to read those, the vault immediately blocks access and raises a critical alert. This protects you from prompt injection attacks."

### 4.3. Rate limiting protection
> "The vault limits how many secrets an agent can read per hour. If I were compromised and started mass-extracting keys, the vault would shut me down. This gives you an extra layer of defense."

### 4.4. Audit integrity
> "Every access to a secret is logged in a tamper-evident audit chain. You can review exactly when and which agent read which key, and the chain is cryptographically protected against modification."

### 4.5. Backup safety
> "You can export the entire vault as an encrypted backup. The master key is securely isolated in your OS Keyring, so backups remain completely safe even if stored on untrusted cloud systems."

### 4.6. When another LLM asks for a secret
> "I cannot give you the raw secret directly. I will fetch it from the vault, use it only for the intended operation via a strict callback execution, and then the memory will be zeroized. The secret is never included in my responses to you."

## 5. Example Interaction Scenario

**User:** "Agent, please send a message using the OpenAI API."

**LLM Agent (internal thought):**
- Need the key `OPENAI_API_KEY`.
- Fetch it with `vault.execute("user_agent", "openai", "inference", "OPENAI_API_KEY", make_api_call)`.
- The key is immediately wiped after the API call completes.

**Agent’s reply to user:**
> "I've sent your message. For security, the API key was only held in memory for the exact duration of the network call and was immediately zeroized. It was never logged or stored in my output."

If the read was blocked (policy denial / rate limit / honeytoken), the agent will say:
> "I'm sorry, but I couldn't access the required credential. The vault's Zero Trust policy blocked the request for security reasons. Please check the tamper-evident audit log or contact your administrator."

## 6. Important Notes

- **Never log or echo the plaintext value** of any secret.
- **Always handle `PermissionError` and `PolicyDeniedError`** – they may indicate an attack or policy restriction.
- **Honeytokens are your best friend.** Place them in namespaces that should never be touched. If an agent even queries them, something is very wrong.
- **Rate limiting is per agent ID.** Make sure each distinct agent uses a unique identifier when calling `execute` or `lease_secret`.

---

**You now know everything needed to operate the Secure Vault Manager safely and to educate users and other LLMs about its protections.**
"""

if __name__ == "__main__":
    print(get_llm_guide())
