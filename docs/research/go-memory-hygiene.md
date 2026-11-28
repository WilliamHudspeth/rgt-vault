# Research: memory hygiene for the Go implementation (RGT-32)

Status: **research and recommendation, Go line (`go/`) only.** No code in `go/`
was changed. Line numbers cite master at `3e269d3`. RGT-32 merges RGT-17
(memoryview-only callbacks) and RGT-18 (wipeable master secret), which were
written for Python (`bytearray`, `memoryview`, `ctypes`); the Python line is
end-of-life, so this document answers the same questions for Go.

Every claim is labelled **[verified]** (read in code, or measured by an
experiment described in section 5), **[reasoned]** (follows from documented
behaviour, not tested here) or **[unverified]**.

## 1. Summary

- The two RGT-17/18 ideas already exist in Go in a simpler form: `Vault.Lease`
  hands the caller a `[]byte` and wipes it when the callback returns
  (`vault/secrets.go:171-200`), and the master secret and DEK are plain
  `[]byte` that are wiped (`keychain/keychain.go:288-296`). No `SecureBuffer`
  type is needed. **[verified]**
- Wiping works where the code keeps to the pattern: a leased plaintext that is
  never converted leaves **0** copies after the wipe, and the DEK is gone after
  `Close`. **[verified, section 5]**
- Copies escape in a few specific places: `string(secret)` conversions (HTTP
  lease handler, bearer header), JSON encoding of the response, the HTTP body of
  `SetSecret`, the TOTP and harness key, the Argon2/HKDF intermediates, the
  expanded AES key schedule from `aes.NewCipher`, and stack growth. After a
  `Close` the KEK was still found 3-4 times and the Argon2 output 1-5 times in
  process memory. **[verified]**
- The strongest low-cost fix for what `Wipe` cannot reach is Go's
  `runtime/secret` (`secret.Do`). It is experimental, needs
  `GOEXPERIMENT=runtimesecret`, and is only active on linux/amd64 and
  linux/arm64. In the experiment it removed every residual copy that the
  standard build left. **[verified on go1.27.4; not on the repo's 1.26.11]**
- A cheap, high-value OS control was missing and has a trap: with a piped
  `core_pattern` (Ubuntu's apport) `RLIMIT_CORE=0` did **not** stop a core dump,
  while `RLIMIT_CORE=1` and `prctl(PR_SET_DUMPABLE, 0)` did. **[verified on this
  host]**
- Hardware isolation (RGT-408's literal wording) is out of reach for AES-GCM in
  process; the residual risk stays "DEK is in RAM while the vault is open".
  This research shrinks the *number and lifetime* of copies, it does not remove
  the DEK from memory.

Prioritized recommendations are in section 7; the filed follow-ups are
RGT-514 to RGT-518.

## 2. RGT-17 and RGT-18 in Go terms

| Python idea | Go equivalent today | Gap |
|---|---|---|
| RGT-17: callback gets a `memoryview`, never a `bytes`/`str` | `Lease(ctx, req, fn func(secret []byte) error)` passes the single buffer and wipes it in a `defer` (`secrets.go:171-200`; wipe at `:192`) | The buffer is safe, but `fn` is free to make `string(secret)`; two real callers do (section 4) |
| RGT-18: master secret in a mutable, wipeable buffer | `MasterProvider.GetMasterSecret() ([]byte, error)`; callers `defer keychain.Wipe(master)` (`vault.go:263-267`, `rotate.go:122,146,264`) | The providers read it through immutable strings first (keyring, macOS `security -w`, section 4) |
| Interaction: wipeable store plus restricted access API | The two are one design in Go: `[]byte` plus a callback API | Nothing new to build; the work is closing the escape sites |
| Optional `SecureBuffer` (mmap/ctypes, mlock) | Not present; `docs/guides/secure-buffer-patterns.md` describes the Python class | Evaluated in section 6 (off-heap region), not recommended as a type |

Acceptance of RGT-32 (design doc covering both approaches and their
interaction; threat-model cost and benefit; `SecureBuffer` optional) is met by
sections 2, 3 and 7. The optional utility is deliberately not proposed (section
6.4).

## 3. What memory hygiene does and does not buy

Worth doing against:

- **Core dumps and crash reports** of the server (apport, systemd-coredump)
  that end up in `/var/crash` or a ticket. The process holds the DEK and, for
  the lifetime of a lease, plaintext.
- **Swap and hibernation images**: this dev host has a 4 GiB swap file
  active (`swapon --show`). **[verified]**
- **Same-uid or low-privilege memory reads** (`/proc/<pid>/mem`, gdb) on hosts
  where Yama `ptrace_scope` allows it (here it is 1: a parent can read its
  child). **[verified]**
- **Forward secrecy of a compromise window**: an attacker who only gets a
  memory snapshot *after* a secret was leased should not find it.

Does **not** help against: an attacker who can run code in the process or read
its memory *while* a secret or the DEK is live (the DEK is always live while
the vault is open); a malicious operator; a debugger attached by root. For
those the controls are the ones in `docs/security/threat-model.md` (no root on
the host, ABAC, approval, hardened unit). Hygiene reduces the window and the
number of copies, so it is a defence-in-depth measure with modest cost, not a
boundary.

## 4. Where secrets live and where copies escape

All entries **[verified by reading]** unless marked.

### Master secret

| Where | What happens |
|---|---|
| Providers return `[]byte` (`providers/provider.go:52-54`) | Callers wipe it (`vault.go:267`; `rotate.go:122,146,264`). |
| Keyring: `keyringGet` returns a **string**, then `decodeKeyringSecret` (`providers/keyring.go:50-62,109-120`) | The string copy is immutable and cannot be wiped. |
| macOS: `strings.TrimSpace(string(out))` then `[]byte(secret)` (`providers/macos.go:46-76`) | The command output is wiped (`:72-76`); the intermediate string is not. |
| Windows Credential Manager (`providers/winvault.go:70,129-133`) | Returns strings. |
| DPAPI (`providers/dpapi_windows.go:30-43`) | Good: the OS buffer is cleared and `LocalFree`d. |
| TPM (`providers/tpm.go:146-214`) | `tpm2_unseal -o <file>` writes the **plaintext to a file** in a `MkdirTemp` next to the blobs (`:155`), read with `os.ReadFile`, then `zeroAndRemove` (`:218-227`). Overwrite-then-unlink is not a guarantee on journaling/COW filesystems or SSDs **[reasoned]**. Follow-up RGT-518. |
| `providers.Wipe` uses `clear` (`provider.go:96-99`); `keychain.Wipe` uses a loop plus `runtime.KeepAlive` (`keychain.go:288-296`) | Two helpers for one job; follow-up RGT-515. |

### Argon2id / HKDF intermediates

`kdf.Derive` (`kdf/kdf.go:93-132`) creates the 32-byte Argon2id output
(`:105`), a 64-byte HKDF binding (`:108`), the `kek` array (`:118-119`),
`nonceRaw` (`:120`) and the nonce slice. None is wiped; the caller wipes only
the returned `DerivedKeyMaterial.Key` (`keychain.go:332`). The Argon2 working
memory (256 MiB with default parameters, `kdf.go:43-45`) is allocated inside
`golang.org/x/crypto/argon2` and is garbage after the call. **[unverified]**
whether it zeroes that memory; the experiment only measured the 32-byte output.
Then `aes.NewCipher(km.Key[:])` (`keychain.go:333`) and `aead.Open` (`:357`)
leave a key schedule on the heap.

### DEK

| Where | What happens |
|---|---|
| `keychain.Manager.dek` (`keychain.go:156`) | Wiped by `Close` (`:272-279`, `:283-286`). |
| `Vault.dek` (`vault.go:119`, set `:283`) | A **second** copy: it is the clone that `Initialize`/`Load` return (`keychain.go:174-199,204-253`). Wiped by `Close` (`vault.go:407`), by `failAfterCommit` (`rotate.go:76-77`) and on `RotateDEK` (`rotate.go:310`); `RotateMaster` wipes its own reloaded clone (`rotate.go:191`). |
| `crypto.Encrypt` / `Decrypt` call `aes.NewCipher(dek)` and `cipher.NewGCM` on **every call** (`crypto/crypto.go:67,74,109,114`) | The expanded key schedule is a heap object that is never wiped. After one decrypt and `Close`, the experiment found 1-2 copies of the DEK (2 with default Argon2 parameters, 1 in a quick run with small parameters). Follow-up RGT-517. |

### Plaintext secrets

| Where | What happens |
|---|---|
| `Vault.Lease` buffer (`secrets.go:171-200`, decrypt at `:305`) | Wiped in `defer`; also wiped if the audit write fails (`:309`). |
| HTTP lease handler: `value = string(secret)` (`handlers.go:566`), then `writeJSON` encodes it (`:163-169`, `:586`) | Immutable string plus the encoder and `ResponseWriter` buffers (and TLS records). Opt-in only: needs the `lease` scope (`auth/store.go:38-42`). Inherent to returning JSON; not fixable by wiping. |
| `SetSecret` handler: `Value *string` in the decoded struct (`handlers.go:401-409`), then `[]byte(*req.Value)` wiped (`:445,460`) | The decoded string and the `json.Decoder`/`net/http` buffers remain (the experiment found 1-2 copies even when the test wiped its own body buffer). |
| `secrets.use` actions: `"Bearer " + string(secret)` (`actions/http.go:50`) | A header string; `net/http` and TLS keep further copies. |
| MCP `lease_secret` (`mcp/mcp.go:484-518`) | Returns the plaintext string to the client by design. |
| `crypto.Decrypt` output (`crypto.go:122`) | A fresh slice, handed to `Lease`; fine. |

### Other secrets

| Secret | Where |
|---|---|
| TOTP secret | File bytes `readTOTPSecret` (`server/stack.go:274-305`) → `string(secret)` (`:203`) → `DecodeSecret` → `ReplayGuardedVerifier.key []byte` kept for the process lifetime (`totp/totp.go:289-309`). The file bytes and the string are never wiped. |
| Harness (capability HMAC) key | `readTrimmed` → `os.ReadFile` (`stack.go:141-153,224`), copied into `HMACTokenVerifier.secret` (`captoken/verifier.go:32,44`). The two-factor hook makes **another** copy (`hooks/twofactor.go:66`). Originals never wiped. |
| Bearer tokens | Stored only as SHA-256 (`auth/store.go:203`); the presented token is a request-header string. Low value. |
| Logs | Actions log only action, host and status (`actions/builtin.go:58`); a panic message never includes the value (`vault/capability.go:391-394`); `mcp` redacts known tokens in error bodies (`mcp/capability.go:108-110`). Nothing found that logs a secret via `slog`/`fmt`. **[verified by grep of `%v`/`%+v` on request types, not exhaustive]** |

### Runtime effects (reasoned, partly measured)

- Go's heap GC is non-moving, so a wiped slice is not left behind by *moving*;
  the real leaks are copies (strings, `append` growth, `Decoder` buffers) and
  freed-but-unzeroed memory. **[reasoned]**
- Goroutine stacks are copied when they grow and the old stack is freed without
  clearing. A 32-byte array wiped after a deep call left 1-2 copies when the
  stack grew and 0 when it did not (section 5). **[verified]**
- `append` growth leaves the old backing arrays; `Wipe` clears only the final
  one. **[reasoned]** (the measured accumulate-and-wipe case found 0 residuals,
  so the effect did not show up; do not assume it never happens).
- Freed memory is not zeroed by the allocator, so wiped-then-freed is fine, but
  unwiped-then-freed stays readable until reused. **[verified]**

## 5. Experiments

Throwaway program (not committed; the scratch directory was deleted). Method:
a parent process builds a real `keychain.json` and a ciphertext with the repo's
own `keychain` and `crypto` packages, starts a child that performs the scenario
with the same calls as the vault (`km.Load`, `crypto.Decrypt`, `keychain.Wipe`,
`km.Close`), runs `runtime.GC()` twice, and then the **parent** reads the
child's `/proc/<pid>/mem` and counts occurrences of each known byte pattern
(plaintext, DEK, DEK in word-swapped form, master, Argon2 output, KEK). A
control child that creates no secret reported 0 for every pattern. Each
scenario was run in a fresh process. Default Argon2 parameters (256 MiB, t=4,
p=4), go1.27.4, linux/amd64, two full runs. Counts vary by a few between
runs (GC timing), so only the pattern across rows is meaningful.

Scenario results, standard build, counts found after GC (range over two runs):

| Scenario | plaintext | DEK | Argon2 out | KEK |
|---|---|---|---|---|
| Vault open after `Load` | 0 | 3-4 (2 live) | 2-5 | 4 |
| After `Wipe` + `Close` | 0 | **0** | 5 | 4 |
| Lease, callback only reads, then wipe | **0** | 5-6 | 2-5 | 4 |
| Lease, then `Close` | 0 | **2** | 2 | 4 |
| Lease, callback does `string(secret)` | **2** | 5 | 2 | 4 |
| Lease, callback does `json.Marshal` of the string | **3-4** | 4-5 | 1-2 | 3-4 |
| Lease, callback appends into a growing slice, wipes the final | 0 | 3-4 | 1 | 1-3 |
| `SetSecret` shape: body → `*string` → `[]byte` → wiped | **1-2** | 4-5 | 1-2 | 1-3 |
| `[32]byte` wiped after deep recursion (stack grows) | **1-2** | 4-5 | 1-2 | 3-4 |
| Same, no recursion | **0** | 2-3 | 1-2 | 3-4 |

With the experiment (`GOEXPERIMENT=runtimesecret`, `secret.Do` around `Load` and
around the decrypt-plus-callback): plaintext **0** in every lease variant
(including `string` and `json.Marshal`), DEK exactly 2 while open (the two live
copies), **0** after `Close` even after a lease, Argon2 output and KEK **0** in
all rows. Scenarios not wrapped in `Do` (`SetSecret` shape, stack array)
behaved like the standard build. `Load` took 0.42-0.44 s with and without the
experiment (sampled in 3 runs; sys memory 264-268 MiB).

Other findings:

- The master secret was found in 2 of about 40 standard-build trials (1 copy)
  even though the experiment wiped its buffer: an intermittent copy somewhere
  in the Argon2/blake2b path or on a stack. Not diagnosed. **[unverified cause]**
- The AES key schedule on amd64 holds the key in raw byte order (word-swapped
  pattern count was 0). **[verified]**
- `debug.WriteHeapDump` lists only **live** objects: the leased plaintext never
  appeared after a callback-only lease, the DEK appeared 2 times (the live
  copies) and not after `Close`. A core dump or swap image would also contain
  freed-but-unzeroed memory, so the `/proc/mem` scan is the relevant measure,
  not the heap dump. **[verified]**
- `runtime/secret` source (`GOROOT/src/runtime/secret/`): erases registers and
  stack on return, zeroes heap objects allocated inside `Do` when they are
  freed, supports linux/amd64 and arm64 only (elsewhere `Do` calls `f`), and
  requires results to be copied into caller-allocated memory. **[verified,
  read]** The package is empty without the experiment flag. The repo pins
  `go 1.26.11` (`go/go.mod`); only 1.27.4 is installed, so behaviour on 1.26.11
  is **[unverified]**.

OS-level experiments (Linux, same host):

| Experiment | Result |
|---|---|
| `prctl(PR_SET_DUMPABLE, 0)` in a child, parent (same uid, `ptrace_scope=1`) opens `/proc/<pid>/mem`, `maps`, `environ` | Allowed when dumpable=1; **permission denied** for all three when dumpable=0 **[verified]** |
| Crash a Go program (`GOTRACEBACK=crash`) with `ulimit -c unlimited` under apport (`core_pattern` starts with `|`) | Shell reported "core dumped" with `RLIMIT_CORE` set to 0 **and** unmodified; **not** reported with `RLIMIT_CORE=1` or `PR_SET_DUMPABLE=0` **[verified status only; whether apport wrote a file was not checked]** |
| `mmap` + `mlock` + `madvise(MADV_DONTDUMP)` through std `syscall` | `VmLck` grew by 4 kB, smaps shows `Locked: 4 kB`, `VmFlags: … lo … dd` **[verified]**. `mlock` of a Go heap slice also works (locks its page) **[verified]**. `syscall.Mmap` and `RLIMIT_MEMLOCK` do not exist in std `syscall` on Windows, and the `RLIMIT_MEMLOCK` constant is missing from std on Linux, so portable code needs `golang.org/x/sys` (already a direct dependency, used by `auth/lock_windows.go` and `providers/dpapi_windows.go`) **[verified by `go vet`]** |
| `RLIMIT_MEMLOCK` on this host | 1.9 GiB; the value for a systemd service is **[unverified]** |

`deploy/rgt-vault-go.service` already sets `MemoryDenyWriteExecute`,
`ProtectProc=invisible`, `PrivateTmp`, `NoNewPrivileges` and a syscall filter,
but no `LimitCORE` and no swap limit (grep, no match). No code in `go/` calls
`prctl`, `mlock`, `Setrlimit` or `SetGCPercent` (grep). **[verified]**

## 6. Options

### 6.1 Discipline only (explicit `[]byte` plus `Wipe`)

What exists. Works for the lease callback and the DEK on `Close` (table above).
Cannot reach strings, library buffers or key schedules. Effort: none.

### 6.2 Close the specific copy sites

Wipe the KDF intermediates, the TOTP and harness key bytes, drop the duplicate
`Wipe`, one DEK copy, a single cached AEAD per DEK. All stay inside the
existing formats (RGT-489). Medium value, low risk, small effort each. Cannot
remove strings that `net/http` needs. Follow-ups RGT-515, RGT-517.

### 6.3 `runtime/secret.Do`

Covers exactly what 6.2 cannot (library-internal key schedule, Argon2 and HKDF
intermediates, string copies made inside the callback, stack). Measured to
remove all residuals. Costs: experimental and outside the Go 1 compatibility
promise; the build needs the experiment flag (so CI and release builds change);
only linux/amd64 and arm64 are protected, other platforms silently get no
protection; results must be copied out of `Do`; erased memory is only zeroed at
GC time. Mitigation: a tiny build-tagged wrapper with a plain-call fallback so
the default build never depends on the flag. Follow-up RGT-516 (needs your
decision).

### 6.4 `mlock` / `VirtualLock`, off-heap region

Verified feasible on Linux with std `syscall`, and `x/sys` for the portable
version. But the DEK is copied into a heap-allocated key schedule on every
`aes.NewCipher`, which no lock covers, so the benefit is partial for the cost
of build-tagged code on three OSes, a `RLIMIT_MEMLOCK` failure mode and a new
secret container type. `mlockall` would pin the 256 MiB Argon2 working set and
can fail on a low limit. **Not recommended now.** If swap is the concern, a
deployment control is simpler: `MemorySwapMax=0` in the unit, or encrypted or
no swap (the directive is standard systemd; **[unverified]** on the deployment
systemd version).

### 6.5 memguard-style libraries

Not recommended. They add a third-party package inside the trust boundary
(the repo gates `go.mod` changes and treats supply chain as a risk), and the
features that matter (`mlock`, guard pages, `MADV_DONTDUMP`, wiping) are
available from std and `x/sys`, which is already a direct dependency. They
cannot fix the stdlib key-schedule copy either. Their in-RAM encryption of the
secret is, against a same-process or root attacker, obfuscation because the
decryption key lives in the same process **[reasoned]**. The code of such a
library was not reviewed here.

### 6.6 Core dumps, ptrace and swap

Section 5: set `PR_SET_DUMPABLE=0` at startup; do not rely on `RLIMIT_CORE=0`
when `core_pattern` is a pipe; `LimitCORE=0` in the unit is still worth adding
for file-based patterns **[reasoned]**. Trade-off: debuggers by the same uid can
no longer attach (provide an opt-out flag). Windows (WER) and macOS
(`PT_DENY_ATTACH`) equivalents are **[unverified]** and not proposed. Follow-up
RGT-514.

### 6.7 Shorter DEK lifetime (idle lock)

Wipe the DEK after N idle minutes and re-derive on demand (Argon2 0.43 s plus
the provider). Shrinks the exposure window of an idle server at the cost of a
latency spike and one more state to test. Not filed: see question Q2.

### 6.8 Hardware isolation

Doing AES-GCM per secret inside a TPM or HSM (PKCS#11) removes the DEK from
RAM and is what RGT-408 literally asks for. It is a large design change
(throughput, portability, new dependency) and out of scope here.

## 7. Prioritized recommendations

| # | Change | Effort | Risk | Issue |
|---|---|---|---|---|
| 1 | `PR_SET_DUMPABLE=0` (+ `RLIMIT_CORE=1`) at serve start on Linux, `LimitCORE=0`, `MemorySwapMax=0` in the unit | S | low (breaks same-uid debugger attach; opt-out flag) | RGT-514 |
| 2 | Wipe KDF intermediates, one `Wipe` helper, wipe TOTP and harness key bytes, `[]byte` TOTP API | S | low (outputs unchanged; vectors pin it) | RGT-515 |
| 3 | `runtime/secret` wrapper, CI leg with the experiment, `/proc/self/mem` regression test | M | medium (experimental; linux only) | RGT-516 |
| 4 | One DEK copy and one cached AEAD per DEK | M | low-medium (rotation code, concurrency) | RGT-517 |
| 5 | TPM unseal scratch dir on tmpfs | S | low | RGT-518 |
| – | Document accepted copies: HTTP lease/`SetSecret` strings, bearer header, MCP lease | S | none | (this document) |
| – | `mlock`/off-heap container, memguard-style library, idle lock, HSM | – | – | not filed |

Order: 1, 2 and 5 are independent and cheap; 3 is the decision item for you; 4
pairs with 3 (create the AEAD inside `secret.Do`).

## 8. What remains after all of this

The DEK is in process RAM while the vault is open. HTTP lease and `SetSecret`
still copy plaintext into library buffers outside our control. Core dumps and
same-uid reads are blocked, swap is limited, and copies the standard build
leaves behind are erased on Linux builds with the experiment. RGT-408's
residual-risk statement stays accurate but narrower; it still needs your
explicit acceptance.

## 9. Open questions for Will

- **Q1.** Accept an experimental Go feature (`GOEXPERIMENT=runtimesecret`) in
  release builds on Linux (RGT-516), or keep hygiene to plain-Go fixes only?
- **Q2.** Is an idle-lock (wipe the DEK after N idle minutes, re-derive on the
  next request) acceptable for the server, given a 0.4 s re-derivation and
  provider access?
- **Q3.** Is it acceptable that `serve` is no longer attachable by a same-uid
  debugger by default (RGT-514), with an opt-out flag?
- **Q4.** RGT-69 ("Memory Hygiene & SecureBuffers" epic) is Python-shaped
  (SecureBuffer, `MasterSecret`). Retitle it to the Go work, or leave it and
  track RGT-514 to RGT-518 only under RGT-32?
