# rgt-vault

> ## ⚠️ MAINTENANCE MODE — This is the Python (v0.2.x) line.
>
> The Python implementation is in **maintenance mode** as of 2026-06-22.
> It receives **bugfixes and security patches only**; **all new feature work
> lands in the [Go rewrite](go/)** (`rgt-vault-server`, v0.3.0).
>
> - **New users:** install the Go binary — see [`go/cmd/server/`](go/cmd/server/)
>   and `go/README.md`. The Go line is the primary, supported release.
> - **Existing Python users:** stay on the latest `v0.2.x` tag for security
>   fixes. The Python line will be **archived 6 months after v0.3.0 ships**.
> - **Why:** the [v0.3 capability-based execution layer](go/) (RGT-128,
>   RGT-166) is fundamentally a Go architecture; reimplementing it in Python
>   would lock in tech debt. See [`eol.md`](docs/program/eol.md) for the full migration
>   plan and the 2026-12-22 EOL date.
>
> Tracked by RGT-164 (maintenance mode notice) → RGT-165 (EOL archive notice; see [`eol.md`](docs/program/eol.md) for the full migration plan and 2026-12-22 EOL date).

A local-first secrets manager designed for autonomous AI systems. It combines
AES-256-GCM encryption, Argon2id key derivation, ABAC authorization, secret
leasing, audit logging, and agent-aware access controls to reduce secret
exposure in LLM-powered applications.

> **Status: `v0.2.0` — Security Preview.** Suitable for evaluation and
> feedback, not yet for protecting production secrets. APIs and on-disk formats
> may change before `v1.0.0`. Read the [threat model](docs/security/threat-model.md) and
> [SECURITY.md](SECURITY.md) before relying on it.

## Features

- **AES-256-GCM at rest** with a Master Secret → KEK → DEK key hierarchy
  (Argon2id + HKDF-SHA512).
- **OS-native master-secret storage** — Windows DPAPI, macOS Keychain, Linux
  TPM, or the cross-platform `keyring` Secret Service.
- **ABAC authorization** — default-deny, with explicit `deny` overriding
  `allow`, gating every read and write by `agent` / `namespace` / `purpose` /
  `action`.
- **Leased secrets** — plaintext is handed to your code in a mutable buffer and
  wiped when you're done (see [zeroization caveats](SECURITY.md#non-goals--what-is-not-protected)).
- **Honeytokens** — decoy secret paths that raise and log a critical event on
  any access.
- **Per-agent rate limiting**.
- **Tamper-evident, hash-chained audit log**.
- **Master-key and DEK rotation**.

## Threat model (short version)

`rgt-vault` protects secret **confidentiality and integrity at rest** against an
attacker who steals `vault.db` / `keychain.json` but not the master secret. It
is **not** an HSM and does not defend against a compromised host or live
process. The full [threat model](docs/security/threat-model.md) (protects / partially
protects / does not protect) and the formal guarantees in
[SECURITY.md](SECURITY.md) are the authoritative references — read them before
relying on it.

## Installation

```bash
pip install -e .            # editable / development install
# or, once published:
# pip install rgt-vault
```

Requires Python ≥ 3.9 and `cryptography >= 44` (for Argon2id). On Windows, the
DPAPI provider additionally needs `pywin32` (`pip install -e ".[windows]"`).

## Quick start

For local development the simplest master-secret source is the cross-platform
OS keyring. For production, use a sealed platform provider (DPAPI/TPM) — see
[Master-secret providers](#master-secret-providers).

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

### CLI

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

## Calling the vault from a local LLM / agent

For clients that can't call Python directly (an LLM agent in Ollama/llama.cpp/
vLLM, a shell script, another language), run the optional local HTTP server.

```bash
pip install -e ".[server]"
rgt-vault init                 # mints a bearer token (prints the value once)
rgt-vault serve                # binds 127.0.0.1:8765 (loopback only)
```

The server is a thin layer over the same `VaultManager`: every request is
gated by the ABAC policy, rate limiter, honeytokens, and hash-chained audit
log. **Plaintext never crosses the HTTP boundary** — instead of returning a
secret, you ask the vault to run a named *server-side action* that consumes
the secret in-process and returns only the result:

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

Built-in actions: `openai_chat`, `http_get_with_auth`, `http_post_with_auth`,
and `echo` (a no-secret diagnostic). The server binds to loopback with no TLS;
exposing it beyond `127.0.0.1` requires a reverse proxy you place in front, and
widens the surface the [threat model](docs/security/threat-model.md) discusses. See
`GET /openapi.json` for the full schema.

## Architecture

See [core-architecture.md](docs/architecture/core-architecture.md) for the full cryptographic design. In
brief:

```
master secret (OS-protected)
      │  Argon2id (per-vault salt)
      ▼
  intermediate ── HKDF-SHA512 ──► KEK (32B) + wrap-nonce (12B)
                                     │  AES-256-GCM, AAD = vault_id:epoch
                                     ▼
                            wrapped DEK  (keychain.json)
                                     │  unwrap
                                     ▼
                          DEK (32B, in memory only)
                                     │  AES-256-GCM, AAD = vault_id:namespace:name
                                     ▼
                          secret ciphertext  (vault.db)
```

## Master-secret providers

`VaultManager` accepts any `MasterSecretProvider`. If none is given, a
platform-appropriate one is selected:

| Platform | Provider | Backing store |
|---|---|---|
| Windows | `WindowsDPAPIProvider` | DPAPI-sealed blob (`VAULT_DPAPI_BLOB`) |
| macOS | `MacOSKeychainProvider` | Keychain item |
| Linux | `LinuxTPMProvider` | TPM-sealed blob (`tpm2-tools`) |
| any | `KeyringProvider` | `keyring` Secret Service (dev default) |

Platform providers require you to **seal** the master secret first (see each
provider's `seal_master_secret` helper). For a zero-setup start, pass
`KeyringProvider()` explicitly.

## Policy examples

Policies are YAML. Attributes default to `*` (match all). Matching is glob-style
(`fnmatch`). **`deny` always wins over `allow`; with no matching `allow`, access
is denied.**

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

Test a policy without touching secrets:

```python
print(vault.explain("research_agent", "openai", "inference", action="read"))
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

`KeyringProvider` supports automated rotation. DPAPI/TPM providers require
re-sealing the master secret out-of-band.

## Backup and recovery

```python
blob = vault.export_vault()          # base64 JSON; secret values stay encrypted
# ... store `blob` somewhere durable ...

# Restore MUST target the same vault: same vault_id and the original
# keychain.json (DEK). Importing into a different vault is refused.
vault.import_vault(blob)
```

Back up `vault.db` **and** `keychain.json` together. The master secret lives in
the OS store and is backed up separately according to your OS's mechanism. See
[SECURITY.md](SECURITY.md) for rollback and cross-vault constraints.

## Performance

Run `python benchmarks/bench.py` to measure on your hardware. Sample numbers
(Windows 11, single run — **machine-dependent, not a guarantee**):

| Operation | Time |
|---|---|
| Unlock vault (Argon2id 256 MB + DEK unwrap) | ~360 ms |
| Set secret (encrypt + insert + audit) | ~12 ms |
| Lease + decrypt secret | ~19 ms |
| Rotate master key (re-wrap KEK) | ~480 ms |
| Rotate DEK (re-encrypt 1000 secrets) | ~6.9 s |

Unlock and master-key rotation are dominated by Argon2id (intentionally
expensive — tune `memory_cost`/`time_cost` in `keychain.py` for your threat
model). Per-secret set/lease latency is dominated by the SQLite audit-log
write, not the cryptography.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

The test suite uses an in-memory master-secret provider and temporary
directories; it does not require a real TPM/DPAPI/Keychain. (One legacy-migration
test exercises the `keyring` backend.)

## License

[Apache-2.0](LICENSE).
