# internal/providers

Master-secret providers (Go port of `python/keychain.py` KeyringProvider and `python/providers/*`).
The vault consumes them structurally (`MasterProvider`, optional `Rotator` / `Bootstrapper`); this
package does not import the vault package.

| Provider | Backend | Stored form | Python-compatible |
|---|---|---|---|
| `KeyringProvider` | OS keyring, service `rgt_vault`, user `master_key` | urlsafe-base64 of 32 bytes (padded; unpadded and std-alphabet accepted on read) | Linux: same Secret Service attributes/label as Python keyring (UNVERIFIED live). macOS: written raw via `security`. Windows: WinVault layout (target = service, UTF-16LE blob; `user@service` on collision) via wincred — UNVERIFIED on a real host |
| `MacOSKeychainProvider` | `/usr/bin/security find-generic-password -w` | printable ASCII text; its bytes are the secret | yes |
| `DPAPIProvider` | `CryptUnprotectData(flags=4)`, optional entropy | base64 text file (`VAULT_DPAPI_BLOB`) | yes |
| `TPMProvider` | tpm2-tools (createprimary, load, startauthsession, policypcr, unseal), `<priv>.pcrs` | `.priv`/`.pub` blobs | yes (UNVERIFIED on hardware) |

Env vars (same as Python): `VAULT_DPAPI_BLOB`, `VAULT_KEYCHAIN_SERVICE`, `VAULT_KEYCHAIN_ACCOUNT`,
`VAULT_TPM_PRIV`, `VAULT_TPM_PUB`.

Rules: external tools run with an argv (never a shell); errors carry the tool name and exit status only (RGT-371);
`unsafe` appears only in `dpapi_windows.go`. Tests use the `Runner` / keyring / DPAPI seams, so they run on any OS.
Opt-in live tests: `RGT_TEST_REAL_KEYRING=1`, `RGT_TEST_MACOS_KEYCHAIN=1`, TPM test (needs tpm2-tools + tss group), Windows DPAPI/WinVault tests (run on Windows).

Known limits: a DPAPI blob sealed with `CRYPTPROTECT_LOCAL_MACHINE` (Python's format) can be unsealed by any local user who can read the
file, so restrict the blob's ACL (and use entropy where possible). The macOS keychain secret cannot be hidden from `security`'s own stdin pipeline of the sealing process.
