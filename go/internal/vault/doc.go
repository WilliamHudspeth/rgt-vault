// Package vault is the Go port of python/vault.py VaultManager: the
// orchestration layer that ties the master-secret provider, the keychain
// (DEK), the encrypted SQLite store, the ABAC policy engine, the audit hook
// and the approval gate together.
//
// It opens and writes the SAME files as the Python line (vault.db and
// keychain.json side by side) and reproduces Python's behaviour byte for
// byte where it reaches disk:
//
//   - secret AAD is "{vault_id}:{namespace}:{name}" and only dek_version 1
//     (AES-256-GCM, internal/crypto) is supported;
//   - audit event names and detail strings are Python's, so a chain written by
//     Go verifies in Python and vice versa;
//   - Export produces base64(json.dumps(data, indent=2)) with Python's
//     ensure_ascii escaping, so Python's import_vault reads it, and Import
//     reads Python's export_vault output;
//   - Argon2 parameters for new keychains and rotations default to
//     kdf.DefaultParams() (Python always writes the defaults).
//
// # Deliberate differences from Python
//
//   - Legacy Fernet vaults (ACTIVE rows with dek_version 0) are refused with
//     ErrLegacyVault instead of being migrated (decision D3): open the vault
//     once with the last Python release first.
//   - RotateDEK re-encrypts EVERY secret version (ACTIVE, SUPERSEDED and
//     REVOKED) in one transaction. Python's rotate_dek rewrites only ACTIVE
//     rows, so older versions stop decrypting (RGT-499). Rows that no longer
//     decrypt under the current DEK (for example versions a Python
//     rotate_dek already orphaned) are left unchanged; an ACTIVE row that does
//     not decrypt aborts the rotation, as in Python.
//   - RotateDEK bumps the key epoch and resets the usage counters inside
//     the same transaction as the rewrite (synchronous=FULL), so an
//     interrupted rotation leaves the old keychain and the old database
//     state in effect. RotateMaster stages its re-wrap in keychain.json.new
//     too. If the process dies after the commit but before keychain.json.new
//     is renamed into place (or, for RotateMaster, after the provider
//     switched masters but before the commit), Open completes the rotation;
//     the .new file is trusted only if it unwraps under the provider's
//     current master and its epoch proves which state is current.
//   - Hooks and the approval gate are consulted without holding the vault
//     lock, and a version-specific lease also honours that version's own
//     require_2fa flag (Python checks only the ACTIVE row).
//   - Open refuses to create a new DEK when keychain.json is missing but the
//     database already holds secret versions (they would become unreadable).
//   - Name, namespace, agent and purpose are validated with
//     internal/validation (stricter: a trailing newline is rejected), and the
//     purpose of SetSecret is validated too.
//   - Struct requests have no implicit defaults for agent or namespace: an
//     empty agent is a validation error, never "system".
//
// Not ported on purpose: AgentVaultClient, the shadow dual-write,
// bypass_verification and email verification. Capability execution
// (execute_capability) is added by batch G8a in capability.go; the Hook and
// approval.Gate seams here are what it plugs into.
package vault
