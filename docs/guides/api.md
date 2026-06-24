# Python API Guide

`VaultManager` accepts any `MasterSecretProvider`. If none is given, a platform-appropriate one is selected:

| Platform | Provider | Backing store |
|---|---|---|
| Windows | `WindowsDPAPIProvider` | DPAPI-sealed blob (`VAULT_DPAPI_BLOB`) |
| macOS | `MacOSKeychainProvider` | Keychain item |
| Linux | `LinuxTPMProvider` | TPM-sealed blob (`tpm2-tools`) |
| any | `KeyringProvider` | `keyring` Secret Service (dev default) |

Platform providers require you to **seal** the master secret first (see each provider's `seal_master_secret` helper). For a zero-setup start, pass `KeyringProvider()` explicitly.

```python
# Fast rotation: re-wraps the DEK under a new master key. Does NOT re-encrypt
# secrets. Use on suspected master-secret/OS compromise.
vault.rotate_master_key()

# Slow rotation: generates a new DEK and re-encrypts every secret. Use on
# suspected DEK/memory compromise. Recommended periodically.
vault.rotate_dek()
```

`KeyringProvider` supports automated rotation. DPAPI/TPM providers require re-sealing the master secret out-of-band.

```python
blob = vault.export_vault()          # base64 JSON; secret values stay encrypted
# ... store `blob` somewhere durable ...

# Restore MUST target the same vault: same vault_id and the original
# keychain.json (DEK). Importing into a different vault is refused.
vault.import_vault(blob)
```

Back up `vault.db` **and** `keychain.json` together. The master secret lives in the OS store and is backed up separately according to your OS's mechanism.

