# Design: the `file` master-key provider (RGT-522)

This is the ADR the RGT-522 dispatch planner accepted on 2026-11-28, copied verbatim (sections 5.1 to 5.8),
followed by the deviations of the implementation. User guide: [docs/guides/providers.md](../guides/providers.md).


**Status:** accepted for RGT-522 by the dispatch planner, 2026-11-28, based on Will's decision 1. The 522
worker copies this section into `docs/design/file-provider.md` and records any deviation.

### 5.1 Context

`init` fails on a Linux host without a Secret Service (for example `org.freedesktop.secrets was not provided`) and
the only alternative is an unprovisioned TPM. The master secret is fed through Argon2id → HKDF to wrap the DEK
(`go/internal/kdf/kdf.go:93-105`, `go/internal/keychain/keychain.go:21-45`), so a provider only has to deliver
32 bytes. Providers are structural (`go/internal/providers/provider.go:53-68`: `MasterProvider`, optional
`Rotator`, `Bootstrapper`) and are chosen by name in `go/internal/server/stack.go:131-137`. The accepted names
are hard-coded in `go/internal/servecmd/servecmd.go:183,199-202`. The keyring stores urlsafe-base64 of 32 bytes
(`go/internal/providers/keyring.go:112`, `decodeKeyringSecret`). Existing secret-file checks are spread over
three places: `captoken.readKeyFile` (`go/internal/captoken/ed25519_keys.go:112`, checks the opened file),
`transport.checkKeyInfo` (`go/internal/transport/keyfile.go:66`, mode and owner, Windows not checked, see
`KeyACLNotice` at :82), and `providers.writeFileAtomic` (`go/internal/providers/dpapi.go:94`).

### 5.2 Decision

Add a provider named **`file`** (`--provider file`, `RGT_VAULT_PROVIDER=file`). It delivers the master secret
from exactly one source, chosen in this order:

1. **Explicit path:** `--master-key-file PATH` or `RGT_VAULT_MASTER_KEY_FILE`.
2. **systemd credential:** if `$CREDENTIALS_DIRECTORY` is set and contains `rgt-vault-master` (name overridable
   with `RGT_VAULT_MASTER_CREDENTIAL`), read it. This covers `LoadCredential=` and **`LoadCredentialEncrypted=`**
   (systemd-creds, sealed with the TPM2 and/or the host key). systemd decrypts the credential into a non-swappable
   ramfs that only the service user can read. No crypto in our code.
3. **Default path:** `~/.config/rgt-vault/keys/<vault-id>.key` (the same base dir as the token files,
   `servecmd.configPath`). The path is **per vault**: the vault id comes from vault.db (`store.VaultID`, read in
   `vault.go:228`) through a new optional interface:

   ```go
   // VaultBinder is implemented by providers whose storage location depends on the vault (RGT-522, RGT-535).
   // Open calls it once, after reading the vault id and before Bootstrap/GetMasterSecret.
   type VaultBinder interface { BindVault(vaultID string) error }
   ```

   This is about 15 lines in `go/internal/vault/provider.go` and `vault.go` (just before :268). RGT-535 reuses it
   for the keyring.

**On-disk form:** the same text as the keyring entry, urlsafe-base64 of 32 random bytes plus `\n` (44+1 bytes).
On read, accept that form (padded or not, either alphabet, through `decodeKeyringSecret`) **or exactly 32 raw
bytes** (so `systemd-creds encrypt` of a raw file works). Refuse anything else, and anything over 128 bytes. No new
format, no new primitive, and the vault's keychain.json/KDF/wrap are untouched.

**Creation (Bootstrap, fresh vault only):** for sources 1 and 3, if the file is missing, create the parent
directory 0700 (`MkdirAll`, then check it with the rules below) and the file with `O_CREATE|O_EXCL|O_NOFOLLOW`,
mode 0600 (Windows: explicit protected DACL, see 5.3), write, fsync, fsync the directory. **Never overwrite.**
If the file exists, use it (pre-provisioned). Source 2 is read-only: a missing credential is an error that
names the unit setting.

**Rotation (`rotate --target master`):** sources 1 and 3 implement `Rotator`. They write the new key to a temp
file in the same directory with the same checks, then rename it over the old one, the same pattern as DPAPI
(`dpapi.go:62-90`). Crash recovery is already handled by `vault/rotate.go` (keychain.json.new). Source 2 returns
`ErrRotateNotSupported` with the re-seal recipe (`systemd-creds encrypt …`, restart).

**Provisioning:** `rgt-vault provider seal file (--generate | --from-keyring | --master-file F) --out PATH [--force]`
joins the existing `seal` family (`go/cmd/rgt-vault/provider.go:29-41`). It is the migration path from keyring
to file. To feed systemd it can write to stdout (`--out -`) only when stdout is not a terminal.

### 5.3 Checks on every read (fail closed). All checks are on the opened handle, never stat-then-open

Put this in a new package **`go/internal/secfile`** (`OpenSecret(path, opts) ([]byte, error)`,
`CreateSecret(path, data)`, `CheckDir(dir)`), so 541 and later work reuse one implementation instead of four.

Unix (Linux, macOS):
- Resolve the path once (`filepath.EvalSymlinks`), so the symlink chains of Kubernetes/Docker secret mounts work.
  Then apply **OpenSSH StrictModes-style** checks to **every directory of the resolved path** up to `/`: owned
  by the euid or root, and not group/world-writable. One exception: a **root-owned sticky** directory (such as
  `/tmp`) is acceptable as an *ancestor*, because others cannot rename or replace entries they do not own. It is
  never acceptable as the key's *own* directory, which must be owned by the euid or root and must not be
  group/world-writable. Then `open(resolved, O_RDONLY|O_NOFOLLOW|O_CLOEXEC)` and `fstat`:
  `S_ISREG`, `nlink == 1` (hard links refused), no setuid/setgid, owner == euid or root, `mode & 0o077 == 0`,
  size ≤ 128. The explicit/default sources apply this. For `$CREDENTIALS_DIRECTORY`, systemd's ramfs (0400, owner
  = service user, dir 0500) passes the same checks.
- The error names the exact fix (`chmod 600 …`, `chown …`, "directory … is group-writable").

Windows:
- Open with `FILE_FLAG_OPEN_REPARSE_POINT`; refuse reparse points (symlinks, junctions).
- `GetSecurityInfo` on the **handle** (golang.org/x/sys/windows, already a direct dependency): the owner must be
  the current user's SID, SYSTEM or BUILTIN\Administrators; the DACL must be non-null; allow-ACEs may name only
  the owner, SYSTEM and Administrators; refuse Everyone, Authenticated Users, BUILTIN\Users and any other SID.
- **If the DACL cannot be read or parsed: refuse** (no warn-and-continue). Unlike `transport.KeyACLNotice`, this
  file *is* the vault's root key. An escape hatch `RGT_VAULT_INSECURE_KEY_ACL=1` exists for diagnosis only and
  prints a warning on every start. (Second opinions split warn vs refuse; ERNIE, DeepSeek and Nemotron said fail
  closed. I agree because the alternative silently accepts a world-readable root key.)
- Creation sets a protected DACL (owner + SYSTEM, no inheritance) at `CreateFile` time, not afterwards.

### 5.4 How `init` chooses, and the error text

The default provider stays **`keyring`**, so existing users and Python-compatible vaults are unaffected. `init`
first probes the chosen provider (keyring reachable? file directory creatable?) **before creating vault.db**. If
vault.db was created in this run and opening fails, it removes vault.db, -wal and -shm (only files it created).
When the keyring is unreachable (D-Bus "not provided by any .service files", no session bus, Windows error 1312
"logon session does not exist", macOS "user interaction is not allowed"), `init` exits 1 with:

```
Error: no OS keyring is available here (no Secret Service on the session D-Bus).
rgt-vault keeps the vault's master key in a provider. Choose one:

  1. Key file (works on any machine; recommended for servers and headless hosts):
       rgt-vault init --provider file
     The key goes to ~/.config/rgt-vault/keys/<vault-id>.key (mode 0600). Anyone who can read that file
     and the vault can open the vault: keep it out of backups of ~/.secure-vault. Under systemd, encrypt it
     at rest with systemd-creds (TPM2 or host key): docs/guides/providers.md#systemd

  2. A desktop keyring: start and unlock a Secret Service (GNOME Keyring, KWallet, KeePassXC), then re-run init.

  3. TPM 2.0 (Linux, hardened): rgt-vault provider seal tpm --generate --out-dir DIR, then
       VAULT_TPM_PRIV=DIR/master_secret.priv VAULT_TPM_PUB=DIR/master_secret.pub rgt-vault init --provider platform

No files were created.
```

(Windows and macOS variants name the Credential Manager / Keychain instead of the Secret Service.) Every
command that opens a vault (serve, set, offline commands) prints the same remedy when the keyring is unreachable.

### 5.5 Threat model (put this in docs/guides/providers.md and docs/security/threat-model.md)

| Provider | Protects against | Does not protect against |
|---|---|---|
| `file`, plain | other local non-root users; agents running as other users (the product's trust boundary); misconfigured permissions (refused) | root/Administrator; any process running as the vault's user; disk theft, backups and VM images that contain the key file; a vault directory and key directory backed up together |
| `file` via `LoadCredentialEncrypted=` (TPM2) | the above, **plus** disk/VM-image theft and backup leakage (the key is sealed to the machine's TPM, and to PCRs if configured); the plaintext exists only in an unswappable ramfs for the service user | root on the running host; a compromised service user; PCR changes after firmware updates (if PCRs are bound, re-seal) |
| `file` via `LoadCredentialEncrypted=` (host key only) | casual copying of the credential file | anyone who also copies `/var/lib/systemd/credential.secret` (same disk) |
| `keyring` | other users; encrypted at rest under the login password; locked while logged out | any process in the user's unlocked session; does not work headless or under systemd |
| `platform` TPM | disk theft; the key never exists in a file | root on the running host; PCR changes |
| `platform` DPAPI (machine scope) | disk theft (bound to the machine) | any local user who can read the blob (restrict its ACL, use entropy) |

The docs must say plainly that **`file` is weaker than TPM or DPAPI at rest** unless it is delivered as an
encrypted systemd credential.

### 5.6 Interaction with RGT-535 (one entry per vault)

- `file` is per-vault from day one (default path `<vault-id>.key`). Two vaults never share a key file unless
  the operator points both at the same `--master-key-file`. Then the 535 guard applies.
- 535 implements `VaultBinder` on `KeyringProvider`: new vaults use account `master_key:<vault-id>`. On read,
  try the per-vault account first, then fall back to the legacy `master_key` (Python-created vaults open
  unchanged). A master rotation on a vault still using the legacy entry **migrates it to its per-vault account
  instead of overwriting the shared entry**: write the new secret under `master_key:<vault-id>` and leave
  `master_key` untouched for the other vaults. `rotate --target master` on a shared explicit key file refuses
  without `--yes` when a sibling marker exists. This is option (b) plus a guard. The legacy entry is never
  deleted automatically.

### 5.7 Rejected or deferred options

- **Passphrase mode** (TTY/fd/env-file, Argon2id). The KDF already stretches whatever the provider returns, so it
  would add no new crypto. Deferred anyway: every offline command opens the vault and would prompt; unattended
  restarts need the passphrase stored somewhere, which is a key file again; env-files leak through
  `/proc/<pid>/environ` and `systemctl show`. All 10 api models that answered agreed it should not be the
  headless default. File a follow-up ("file provider: interactive passphrase source for laptops without a
  keyring") only if Will wants it.
- **age envelope.** It needs a new dependency, and its identity file just moves the problem. Rejected.
- **Auto-selecting `file` when the keyring is missing.** Rejected: the operator must make a security choice
  knowingly. It is the first suggestion in the error instead.

### 5.8 Acceptance (adds to the RGT-522 issue's list)

`DBUS_SESSION_BUS_ADDRESS` unset in a Go integration test (`t.Setenv`), so no workflow change is needed. There
are table tests for every refusal (each must fail if its check is removed), a `$CREDENTIALS_DIRECTORY` test with
a fake dir, a Windows DACL test (CI windows-latest: a file with an Everyone ACE is refused), and a test that a
failed `init` leaves no vault.db. Coverage of `internal/secfile` is at least 85%. `go vet` passes under GOOS=windows
and darwin. `deploy/rgt-vault-go.service` gains a `file` variant using `LoadCredentialEncrypted=rgt-vault-master:/etc/credstore.encrypted/rgt-vault-master`.



## Implementation notes and deviations (RGT-522 PR)

1. **Credential source and rotation.** The ADR says source 2 "returns `ErrRotateNotSupported` with the re-seal
   recipe". The credential source is a separate type, `providers.CredentialProvider`, that does **not**
   implement `Rotator`. `vault.RotateMaster` therefore refuses with `vault.ErrRotateNotSupported` (HTTP 400
   `RotateNotSupportedError`) before anything changes. Returning `providers.ErrRotateNotSupported` from a
   `RotateMasterSecret` method would surface as an unclassified HTTP 500, and the vault's refusal message is
   vault-side text this task does not own, so it names the type and says "re-seal out-of-band" rather than
   the exact `systemd-creds` recipe. The recipe is in `providers.CredentialRecipe`, the unit file and
   [providers.md](../guides/providers.md#systemd).
2. **Which `$CREDENTIALS_DIRECTORY` case is an error.** If `$CREDENTIALS_DIRECTORY` is set but holds no
   `rgt-vault-master`, the provider falls through to the default path (a unit may load other credentials).
   It is an error only when `RGT_VAULT_MASTER_CREDENTIAL` names a credential explicitly and it is missing,
   or when that variable is set outside a unit (no `$CREDENTIALS_DIRECTORY`). The error names
   `LoadCredentialEncrypted=`.
3. **Probe.** `init` probes through an optional `Probe() error` method (keyring: one read, where "not found"
   is fine; file: an existing key file must pass every check, otherwise its directory is created 0700 and
   checked; credential: one read). Only the key directory may be created by a probe.
4. **Unreachable-keyring detection** (`providers.IsKeyringUnavailable`) matches backend error text. The Linux
   cases are verified (go-keyring with no Secret Service, and with no bus socket). The Windows (error 1312)
   and macOS ("user interaction is not allowed") cases are UNVERIFIED on real hosts; the macOS backend
   reports only the exit status of `security` (RGT-371), so a locked Keychain may show the generic error.
   `serve` and every command that opens a vault through `openStackAt` print the "existing vault" variant of
   the remedy.
5. **Windows ACL inspection without `unsafe`.** `internal/secfile` reads the DACL through its SDDL text
   (`SECURITY_DESCRIPTOR.String()`), because `go/internal/providers/dpapi_windows.go` is the only file allowed
   to import `unsafe` (RGT-374) and `reflect` is allowlisted too (RGT-379). Deny ACEs and inherit-only ACEs are
   accepted; any allow ACE type other than `A` (object, callback ACEs) is refused. The Windows checks apply
   to the file itself; directories are only checked for being real directories (not reparse points). The
   `RGT_VAULT_INSECURE_KEY_ACL=1` escape hatch turns ACL refusals into a warning on every read and prints a
   warning when the provider is built. It never relaxes the reparse-point, link-count or directory checks.
6. **Group-writable directories are refused even with user-private groups.** On a host with `umask 002`,
   `~/...` directories created by other tools may be 0775; the error names `chmod go-w DIR`. This matches
   OpenSSH StrictModes upstream.
7. **Unix opens use `O_NONBLOCK`** in addition to `O_RDONLY|O_NOFOLLOW|O_CLOEXEC`, so a FIFO at the key path
   is refused instead of blocking.
8. **`provider seal file --master-file`** must hold exactly 32 raw bytes (the file provider stores exactly 32
   bytes); other `seal` targets keep sealing the exact bytes.
9. **`docs/security/threat-model.md`** is not edited by this PR (not in the task's file list); the 5.5 table
   is in [providers.md](../guides/providers.md#threat-model).
