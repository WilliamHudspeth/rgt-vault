# Master-key providers

rgt-vault encrypts every secret with a data key (DEK). The DEK is wrapped under a key derived (Argon2id, then
HKDF) from a 32-byte **master secret**, and a **provider** holds that master secret. Choose it with
`--provider` / `RGT_VAULT_PROVIDER`:

| Provider | Where the master secret is | Use it for |
|---|---|---|
| `keyring` (default) | the OS keyring: Secret Service (Linux), login Keychain (macOS), Credential Manager (Windows) | a desktop session; Python-compatible |
| `file` | a 32-byte key file, or a systemd credential | servers, containers, headless hosts, systemd units |
| `platform` | Windows DPAPI, the macOS Keychain or the Linux TPM 2.0 | hardened installs with that hardware |

The provider only delivers 32 bytes. Changing provider does not change `keychain.json`, the KDF or the wrap.

## The `file` provider

```bash
rgt-vault init --provider file
rgt-vault serve --provider file --policy policy.yaml
```

The key comes from exactly one source, chosen in this order:

1. **An explicit path:** `--master-key-file PATH` or `RGT_VAULT_MASTER_KEY_FILE`.
2. **A systemd credential:** `$CREDENTIALS_DIRECTORY/rgt-vault-master` (rename it with
   `RGT_VAULT_MASTER_CREDENTIAL`), delivered by `LoadCredential=` or `LoadCredentialEncrypted=`. This source is
   read-only.
3. **The per-vault default:** `~/.config/rgt-vault/keys/<vault-id>.key`. The vault id comes from vault.db,
   so two vaults never share a key file.

On disk the key is one line: urlsafe-base64 of 32 random bytes and a newline, the same text the keyring
entry holds. On read, rgt-vault also accepts the unpadded or standard-alphabet form, or exactly 32 raw bytes.
It refuses anything else and anything over 128 bytes.

**Creation.** `init` on a new vault creates the key file only if it is missing. It creates the directory
0700, then the file 0600 with `O_CREAT|O_EXCL|O_NOFOLLOW`, and fsyncs the file and the directory. On Windows
the file gets a protected owner + SYSTEM DACL at creation. An existing key file is never overwritten. If one
is already there, `init` uses it (a pre-provisioned key). If the key file of an existing vault is missing,
opening fails: rgt-vault never makes a new key for a vault that already has secrets.

**One key, one vault.** Once a key has opened a vault, rgt-vault records that vault's id in
`<key>.vault-id` (0600). A key file that belongs to another vault is refused (by `init`, by every open and by
rotation): two vaults sharing a key would mean that rotating one locks the other out. Give every vault its
own key file. The refusal names the vault the key belongs to. Only if that vault is really gone (its data
cannot be opened without this key) remove `<key>.vault-id` to release the key.

**Copies and backups share the key.** A copied vault directory or a restored backup keeps its vault id, so
it opens with the same key file. After a master rotation the old key is gone (`.prev` is removed once the new
key works). A backup taken before the rotation needs the OLD key: save a copy of the key file with every vault
backup (and keep the two apart, see the threat model).

**Rotation.** `rgt-vault rotate --target master` first keeps the current key as `<key>.prev` (0600, never
over an existing `.prev`), then writes the new key to a temp file in the same directory (same checks) and
renames it over the old one. The rotating process holds `<key>.lock` (an `flock`; `LockFileEx` on Windows;
the file stays) from that point until the re-wrapped keychain is installed. `<key>.prev` is removed only
under that lock, only by the vault the key is bound to, and only when the key file still holds the key that
has just opened the vault. Another process that opened the vault with the old key, an offline `export` for
example, therefore never removes a running rotation's `.prev`. While another process holds the lock, opening
simply leaves `.prev` alone; it does not wait. If the rotating process dies before the re-wrap is on disk (it
takes seconds of Argon2id), the next open says that the new key does not open the vault but `<key>.prev`
does, and how to restore it (`mv <key>.prev <key>`). rgt-vault never switches keys on its own. A rotation is
refused while an unconfirmed `.prev` exists. With a systemd credential, rotation is refused before anything
changes: re-seal a new key (below) and restart.

`provider seal file --force` over an existing key keeps the replaced key as
`<key>.replaced-<UTC timestamp>`, a name that rgt-vault never removes. It may be the only key of the vault
that used it: delete it yourself once that vault is gone or re-keyed. `--force` also removes `<key>.vault-id`,
so the new key can serve a new vault.

### Checks on every read

rgt-vault refuses a key file that other users could read or replace. It makes every check on the opened
handle, never with a separate stat before the open. Each refusal names the fix (`chmod 600 …`, `chown …`,
`chmod go-w DIR`).

Linux and macOS (in the style of OpenSSH StrictModes):

- The path is resolved once, so the symlink chains of Kubernetes/Docker secret mounts work.
- The key's own directory must be owned by you or root and must not be group- or world-writable.
- Every ancestor directory up to `/` follows the same rule. A root-owned sticky directory such as `/tmp` is
  accepted as an ancestor, never as the key's own directory.
- The file is opened `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`. It must be a regular file with exactly one
  link and no setuid/setgid bit, owned by you or root, with no group or other permission bits, and at most
  128 bytes.

Windows:

- The file is opened with `FILE_FLAG_OPEN_REPARSE_POINT`. Symlinks, junctions, directories and files with
  more than one hard link are refused.
- The owner must be you, SYSTEM or BUILTIN\Administrators. The DACL must exist and must not be NULL. Allow
  ACEs may name only those three. Everyone, Authenticated Users, BUILTIN\Users and any other SID are refused.
  To fix a file: `icacls FILE /inheritance:r /grant:r "%USERNAME%:F" /grant:r SYSTEM:F`.
- A DACL that cannot be read or parsed is refused. For diagnosis only, `RGT_VAULT_INSECURE_KEY_ACL=1` turns
  ACL refusals into a warning, printed on every start. Do not leave it set.
- **The directory checks on Windows are weaker than on Unix:** only the key's own directory is checked, and
  only for being a real directory (not a reparse point). The DACLs of directories are not checked; the
  protection of a key under your profile is the profile directory's ACL. Keep key files under your profile
  (the default) or in a directory whose ACL you control.

systemd credentials (Linux): systemd 255 delivers `$CREDENTIALS_DIRECTORY/<name>` as `root:root 0440` with a
POSIX ACL granting the service user read, in a `root:root 0550` directory on a read-only tmpfs. The mode
check above would refuse it (group bits show the ACL mask), so **for the credential source only** rgt-vault
accepts a file that is owned by root, has mode at most 0440, sits in a root-owned directory (and passes the
directory chain checks) on a read-only tmpfs or ramfs (checked with `fstatfs`), and passes every other file
check. Verified with systemd 255 (`systemd-run -p User=… -p LoadCredential=rgt-vault-master:…`).

### Provisioning and migration

`rgt-vault provider seal file` writes a key file (0600, never over an existing file without `--force`):

```bash
rgt-vault provider seal file --generate     --out ~/keys/master.key   # a key for a NEW vault
rgt-vault provider seal file --from-keyring --out ~/keys/master.key   # move a keyring vault to a file
rgt-vault provider seal file --master-file raw32.bin --out ~/keys/master.key   # exactly 32 raw bytes
```

After `--from-keyring`, open the vault with `--provider file --master-key-file ~/keys/master.key`. The keyring
entry is left as it is: delete it yourself once the file works. `--out -` writes the key to standard
output, but only when that is not a terminal, for example to pipe it into `systemd-creds encrypt`.

## systemd

Under systemd there is no session D-Bus, so `keyring` cannot work. Use `platform` (the TPM, see
`deploy/rgt-vault-go.service`) or `file` with an **encrypted credential**:

```bash
sudo -u rgtvault rgt-vault provider seal file --generate --out /var/lib/rgt-vault/key.txt
sudo -u rgtvault rgt-vault --provider file --master-key-file /var/lib/rgt-vault/key.txt init \
     --db /var/lib/rgt-vault/vault.db --token-store /var/lib/rgt-vault/tokens.json \
     --operator-token-file /var/lib/rgt-vault/operator.token
sudo mkdir -p /etc/credstore.encrypted
sudo systemd-creds encrypt --with-key=tpm2 --name=rgt-vault-master \
     /var/lib/rgt-vault/key.txt /etc/credstore.encrypted/rgt-vault-master
# keep an offline backup of key.txt, then:
sudo shred -u /var/lib/rgt-vault/key.txt; sudo rm -f /var/lib/rgt-vault/key.txt.vault-id
```

In the unit:

```ini
LoadCredentialEncrypted=rgt-vault-master:/etc/credstore.encrypted/rgt-vault-master
ExecStart=/opt/rgt-vault/bin/rgt-vault serve --provider file --db /var/lib/rgt-vault/vault.db ...
```

At start, systemd decrypts the credential into a non-swappable ramfs that only the service user can read.
rgt-vault reads `$CREDENTIALS_DIRECTORY/rgt-vault-master` there, with the checks above, and has no crypto of
its own for this. `--with-key=tpm2` seals the key to this machine's TPM. Add `--tpm2-pcrs=` to bind it to the
boot state too; re-seal after firmware updates. `--with-key=host` uses `/var/lib/systemd/credential.secret`
instead, which protects only against copying the credential file alone. To **rotate**, generate a new key,
re-run `systemd-creds encrypt` and restart: `rotate --target master` is refused for a credential.

If `$CREDENTIALS_DIRECTORY` is set (rgt-vault runs inside a unit with credentials) but holds no
`rgt-vault-master`, the provider refuses instead of falling back to a plaintext default key file. Pass
`--master-key-file` to use a key file explicitly. The credential's ownership and mode under systemd 255 are
described under the checks above.

## When the keyring is unreachable

`rgt-vault init` checks the provider, without creating anything, before it creates vault.db. Concurrent
`init`s of the same vault are serialised with a lock file (`vault.db.init.lock`, which stays). With no Secret Service on the session D-Bus
(Linux), no logon session (Windows, error 1312) or a locked Keychain (macOS), it exits 1. It lists the
options above, `--provider file` first, and creates no files. If vault.db was created in that run and opening
then fails, `init` removes vault.db, -wal, -shm, keychain.json and a key file bootstrapped in that run (only
files it created, and never those of a vault that already existed).
`serve` and the offline commands print how to reach the keyring or move the key to a file.

## Threat model

| Provider | Protects against | Does not protect against |
|---|---|---|
| `file`, plain | other local non-root users; agents running as other users (the product's trust boundary); misconfigured permissions (refused) | root/Administrator; any process running as the vault's user; disk theft, backups and VM images that contain the key file; a vault directory and key directory backed up together |
| `file` via `LoadCredentialEncrypted=` (TPM2) | the above, **plus** disk/VM-image theft and backup leakage (the key is sealed to the machine's TPM, and to PCRs if configured); the plaintext exists only in an unswappable ramfs for the service user | root on the running host; a compromised service user; PCR changes after firmware updates (if PCRs are bound, re-seal) |
| `file` via `LoadCredentialEncrypted=` (host key only) | casual copying of the credential file | anyone who also copies `/var/lib/systemd/credential.secret` (same disk) |
| `keyring` | other users; encrypted at rest under the login password; locked while logged out | any process in the user's unlocked session; does not work headless or under systemd |
| `platform` TPM | disk theft; the key never exists in a file | root on the running host; PCR changes |
| `platform` DPAPI (machine scope) | disk theft (bound to the machine) | any local user who can read the blob (restrict its ACL, use entropy) |

**The `file` provider is weaker than TPM or DPAPI at rest** unless it is delivered as an encrypted systemd
credential. A plain key file is only as safe as the disk, the backups and the account that hold it: anyone
who has the key file and the vault can open the vault. Keep `~/.config/rgt-vault/keys` out of the backups of
`~/.secure-vault`, or back them up to different places.

Design and decisions: [docs/design/file-provider.md](../design/file-provider.md).
