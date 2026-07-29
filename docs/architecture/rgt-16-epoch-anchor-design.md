# RGT-16 — Anchoring the key epoch in a hardware-monotonic store

Status: **design / proposed** (no implementation yet)
Ticket: RGT-16 — `pri:critical`, `security:crypto`, `security:audit`, `review:security`, `review:architecture`, `type:design`
Branch: `feat/rgt-16-tpm-epoch-anchor`

---

## 0. The vulnerability being fixed

`key_epoch` today lives in exactly two places, both of which are inside the backup set:

| Location | Code | Rollback-able? |
|---|---|---|
| `metadata` table in `vault.db` | `python/storage/sqlite.py:121` `get_key_epoch()` / `:132` `increment_key_epoch()` | yes |
| `key_epoch` field in `keychain.json` (plaintext) **and** in the DEK-wrap AAD `f"{vault_id}:{epoch}"` | `python/keychain.py:209`, `:221`, `:262` | yes |

`HardenedDEKManager.load_dek` (`python/keychain.py:248`) compares the keychain epoch against
`expected_epoch`, which `VaultManager.__init__` (`python/vault.py:177`, `:203`) reads straight out of
`vault.db`. So the check is **DB-vs-keychain consistency only**. The existing test
`tests/test_vault_v2.py::test_rollback_protection` proves only that: it downgrades the DB epoch and
leaves the keychain at the new epoch, producing a *mismatched* pair.

The actual attack is a **mutually consistent pair**: restore `vault.db` *and* `keychain.json` both
from a snapshot taken at epoch N, discarding a later legitimate rotation to N+1. Both files agree,
`load_dek` passes, the AAD matches, and the vault happily comes up on the retired epoch-N DEK — which
is exactly the key material the rotation was meant to retire (e.g. after a suspected DEK compromise).
There is currently **no external source of truth** to compare against.

Fix: bind the epoch to a store the attacker cannot roll back with a filesystem restore — a TPM 2.0
NV **counter** index.

> Note for implementers: the existing `LinuxTPMProvider` (`python/providers/linux_tpm.py`) uses
> PCR-policy *sealing* (`tpm2_createprimary` / `tpm2_create` / `tpm2_load` / `tpm2_unseal`). That is a
> **different TPM mechanism** and is untouched by this work. What follows uses NV counter indices
> (`tpm2_nvdefine -a nt=1` / `tpm2_nvincrement` / `tpm2_nvread`). Only the subprocess-wrapping and
> error-handling *style* of `_run_tpm_cmd` is reused.

---

## 1. NV index allocation strategy

### 1.1 Which range

TPM 2.0 NV index space is partitioned by handle range. The relevant facts:

- `0x01000000`–`0x01BFFFFF` — owner-hierarchy NV, allocatable by anyone with owner auth.
- `0x01C00000`–`0x01C0FFFF` — **TCG-reserved** (EK certificates, EK templates, platform provisioning).
  Never touch.
- `0x01800000`–`0x018FFFFF` — in practice the least-populated slice of the owner range on Linux
  hosts; `clevis`, `systemd-cryptenroll`, and `tpm2-totp` all cluster elsewhere
  (`0x01000000`–`0x0100FFFF` and `0x0150xxxx`).

**Default index: `0x01800016`** (the `16` is a mnemonic for RGT-16, nothing more). Reserved band for
this project: **`0x01800010`–`0x0180001F`**, so a host running multiple independent vaults can hand
each one its own index without a new allocation discussion.

### 1.2 Deterministic derivation vs. configuration — configuration wins

A tempting design is to derive the index from `vault_id` (`SHA256("rgt-vault:epoch" || vault_id)`
folded into the band). **Reject it.** `vault_id` lives in the same rollback-able `metadata` table as
the epoch (`python/storage/sqlite.py:110`). An attacker restoring a crafted `vault.db` with a
different `vault_id` would redirect us at an *undefined* index, which our first-run logic would then
happily claim — turning the anchor into a no-op. Deriving the trust anchor's address from
attacker-controlled data is circular.

Therefore the index is **host configuration, not vault content**:

```
RGT_VAULT_NV_INDEX   default 0x01800016   (hex string, parsed strictly)
RGT_VAULT_EPOCH_ANCHOR   tpm | file | none    default: tpm on Linux (see §4)
```

Matching the existing `VAULT_TPM_PRIV` / `VAULT_TPM_PUB` convention in
`python/providers/__init__.py:23`, resolved in `create_platform_anchor()`.

**Deployment requirement (must be documented in the runbook):** the anchor configuration is part of
the TCB and **must live outside the vault backup set** — the systemd unit's `Environment=`, or
`/etc/rgt-vault/anchor.conf`. If an operator puts it in the same directory as `vault.db` and restores
the whole directory, the attacker gets to choose the index and the control is void.

### 1.3 Claiming the index (first run) and collision behaviour

```
read  = tpm2_nvreadpublic <idx>
 ├─ index undefined ──► if the vault is fresh (no keychain.json): CLAIM (below)
 │                      else: CRITICAL — anchor missing for an existing vault (§3, case E)
 └─ index defined ────► validate shape:
         nt == counter(1), dataSize == 8, attributes match our template,
         and the recorded `nv_name` in keychain.json (if present) matches
         the name reported by nvreadpublic
      ├─ matches  ──► use it
      └─ differs  ──► FAIL CLOSED: AnchorClaimConflictError
                      "NV index 0x01800016 is already defined by another
                       application (nt=ordinary, size=64). Refusing to
                       overwrite. Pick a free index from 0x01800010-0x0180001F
                       via RGT_VAULT_NV_INDEX, or free this one deliberately."
```

Never `tpm2_nvundefine` an index we did not create. Never `nvdefine` over an existing one. This is
the direct answer to the ticket's warning about shared hardware.

CLAIM:

```sh
tpm2_nvdefine 0x01800016 -C o -s 8 \
  -a "nt=1|ownerread|ownerwrite|authread|authwrite|no_da"
tpm2_nvincrement 0x01800016 -C o     # a fresh counter must be written once before it reads
tpm2_nvread      0x01800016 -C o -s 8   # -> 8-byte big-endian initial value C0
```

**Auth model.** `-C o` (owner hierarchy) with whatever owner auth the platform has — empty on a
default Linux install, which is the realistic dev/CI case. We deliberately do **not** invent a
PCR-bound write policy for the counter:

- A PCR policy on `nvincrement` would break legitimate rotation after any firmware/kernel update
  (the same brittleness the sealing provider already suffers), and rotation is exactly the operation
  we cannot afford to have fail.
- The security property we need is *monotonicity*, which the TPM enforces structurally regardless of
  who holds write auth. An attacker with owner auth can move the counter **forward** (a DoS — see
  §7) but can never move it **backward**, which is the whole point.

Production hardening guidance (runbook, not code): set a non-empty owner hierarchy auth and store it
with the vault's other platform credentials. Recorded as an open question in §7.

### 1.4 Why undefine/redefine does not rescue the attacker

TPM 2.0 (Part 2, NV counter semantics) requires that a newly-defined counter index be initialised to
a value **greater than the largest value any NV counter on that TPM has ever held**. So an attacker
who does `nvundefine` + `nvdefine` gets a *higher* number, not a lower one — which our verify path
reads as "counter > db epoch" → CRITICAL, i.e. it fails closed rather than opening. This is a
load-bearing assumption and **must be empirically verified on target hardware before implementation
is accepted** (§7, risk R2).

---

## 2. The anchoring protocol — chosen: **(a) lockstep, counter value IS the epoch**

### 2.1 Invariant

```
tpm_counter == db_key_epoch == keychain_key_epoch
```

checked on every vault open. One number, one invariant, no derived offsets and no second constant
that itself needs protecting.

### 2.2 Rotation sequence (commit point is the TPM)

Both `rotate_master_key` (`python/vault.py:1072`) and `rotate_dek` (`python/vault.py:1091`) currently
begin with `self.storage.increment_key_epoch()`. That call is replaced by a vault-level helper:

```
_advance_epoch():
  1. record non-authoritative intent marker: metadata['epoch_rotation_pending'] = '1'
  2. anchor.increment()          # tpm2_nvincrement  -- THE COMMIT POINT
  3. new_epoch = anchor.read()   # authoritative value, 8-byte BE
  4. storage.set_key_epoch(new_epoch)   # replaces increment_key_epoch(); absolute, not +1
  5. (caller) rewrap/reinitialise the DEK at new_epoch, as today
  6. clear metadata['epoch_rotation_pending']
```

If step 2 fails, nothing else has happened and the vault stays on the old epoch. The TPM advancing
before the DB means the failure mode of a crash is "counter ahead of DB", never "DB ahead of counter"
— i.e. a crash degrades to *fail-closed*, never to *silently reusing a retired key*.

`storage.increment_key_epoch()` is retired in favour of `set_key_epoch(n: int)`, because the epoch is
no longer the DB's to compute. `get_key_epoch()` stays but is demoted to "the DB's *claim* about the
epoch", to be verified, never trusted.

### 2.3 First-run and migration

- **Fresh vault** (no `keychain.json`): claim the index, read `C0`, and initialise the DB epoch to
  `C0` — **not** to `1`. The counter's start value is TPM-lifetime dependent and may be large; the
  epoch is only an opaque integer in the AAD, so any starting value is fine.
- **Existing vault** (`keychain.json` present, DB epoch e.g. `3`, index unclaimed): a one-shot
  `rgt-vault epoch anchor --init` ceremony. It claims the index, reads `C0`, and performs a *forced
  epoch jump* — load the DEK at the old epoch, rewrap it at `C0`, write `C0` to the DB. Mechanically
  this is `rotate_master_key`'s rewrap path with an externally supplied epoch. It is an explicit
  operator action with its own `EPOCH_ANCHOR_INITIALIZED` audit event; it never happens implicitly on
  a normal open, because "the anchor is missing, let me create one" is precisely what an attacker
  wants us to do.

### 2.4 Why (a) and not (b) "separate witness compared at load"

Option (b) — a counter that merely accompanies the epoch — needs a stored mapping between witness
value and epoch value, and that mapping has to live somewhere. Every candidate location is inside the
backup set, so (b) reduces to protecting a second rollback-able datum with the first: strictly more
state, strictly more code, and one more place to get the comparison subtly wrong.

Against the acceptance criterion — *"Roll-back of vault.db + keychain.json pair detected (epoch
mismatch logged as CRITICAL)"* — (a) satisfies it directly and unconditionally: a consistent
epoch-N pair restored while the TPM sits at N+1 yields `counter != db_epoch` on the very first
comparison at open time, with no dependence on any restored file. (a) also makes the AAD
`f"{vault_id}:{epoch}"` transitively hardware-bound at no extra cost, since the epoch in the AAD is
now a TPM-issued value.

The cost of (a) is the forced epoch jump at migration (§2.3) and the loss of "epoch counts rotations
from 1" as a human-readable property. Both are acceptable; the epoch is an internal AAD component,
not a user-facing version number.

---

## 3. Read / verify path at vault load

Inserted in `VaultManager.__init__` between `self.key_epoch = self.storage.get_key_epoch()`
(`python/vault.py:177`) and the `load_dek` call (`python/vault.py:203`).

```
db_epoch       = storage.get_key_epoch()          # a claim, not a truth
kc_epoch       = keychain.json['key_epoch']       # a claim, not a truth
counter        = anchor.read()                    # the truth
```

| # | Condition | Action |
|---|---|---|
| A | `counter == db_epoch == kc_epoch` | proceed; `load_dek` as today |
| B | `counter > db_epoch` | **CRITICAL** `EPOCH_ROLLBACK_DETECTED`, raise `EpochRollbackError`, refuse to open |
| C | `counter < db_epoch` | **CRITICAL** `EPOCH_ANCHOR_DESYNC`, raise `EpochRollbackError`, refuse to open |
| D | `counter == db_epoch` but `kc_epoch != db_epoch` | **CRITICAL** `EPOCH_KEYCHAIN_MISMATCH`, refuse (this is today's check, now audited at CRITICAL) |
| E | index undefined, `keychain.json` exists | **CRITICAL** `EPOCH_ANCHOR_MISSING`, refuse |
| F | index undefined, no `keychain.json` | first-run claim (§2.3), audit `EPOCH_ANCHOR_INITIALIZED` |
| G | TPM unavailable / `TPMError` / permission denied | **CRITICAL** `EPOCH_ANCHOR_UNAVAILABLE`, refuse (see below) |

**Case B** is the attack in the ticket. It is *also* the shape of a crash between §2.2 step 2 and
step 4 (a torn rotation), where `counter == db_epoch + 1`. **We do not auto-heal, and we do not
downgrade the severity for the `+1` case**, because an attacker rolling back exactly one epoch
produces an identical observation. What the `+1` case gets is a *better error message* — mentioning
`epoch_rotation_pending` if set, and pointing at `rgt-vault epoch reconcile`, an explicit operator
command that reloads the DEK at `db_epoch`, rewraps at `counter`, and emits its own CRITICAL
`EPOCH_RECONCILE` event. The `epoch_rotation_pending` marker lives in the DB and is therefore
forgeable; it is an operator hint only and must never gate the decision.

**Case C** should be unreachable if the protocol holds (the DB can only be set to a value the TPM
just issued). Reaching it means one of: the DB was advanced without the TPM (forged/edited
`vault.db`), the config points at a different index, or the vault has been moved to different
hardware. All three are security-relevant. Refuse; do not "catch up" the counter, because
incrementing to match an attacker-chosen DB value would let a forged DB drive the anchor.

**Case G — fail closed, not degrade.** A vault that opens when its rollback control is unavailable
gives an attacker a trivial bypass: make the TPM unreachable (drop the `tss` group membership, unbind
the device, run in a container without `/dev/tpmrm0`) and the control evaporates. That is precisely
the "no silent fallbacks" failure mode called out in the org conventions and in HUD-485. An operator
who genuinely needs to run without a TPM must say so explicitly and durably (§4), not get it by
accident from a permissions error.

All CRITICAL events use the established pattern in `python/vault.py` — `self._log_audit(<ACTION>,
None, json.dumps({"severity": "critical", ...}))`, matching `HONEYTOKEN_TRIGGERED`
(`python/vault.py:880`, `:913`), so the events land in the hash-chained `audit_logs` table via
`storage.log_audit`. Caveat: the audit chain lives in the same rolled-back `vault.db`, so the alert
must **also** be surfaced out-of-band — logger at `CRITICAL` and a non-zero exit — or the attacker
restores the very log that records the detection. Worth an explicit line in the implementation PR.

New exceptions in `python/exceptions.py`, subclassing `VaultError` alongside
`MasterSecretUnavailableError`: `EpochRollbackError`, `AnchorUnavailableError`,
`AnchorClaimConflictError`.

---

## 4. Fallback monotonic store — allowed, never silent, never a silent *downgrade*

Three modes, selected by `RGT_VAULT_EPOCH_ANCHOR`:

| Mode | Store | Behaviour |
|---|---|---|
| `tpm` | TPM 2.0 NV counter | default on Linux with a usable `/dev/tpmrm0` |
| `file` | `FileMonotonicAnchor` | HMAC-protected counter file **outside the vault directory** — default `/var/lib/rgt-vault/epoch.anchor`, mode `0600`. Value is `u64 BE || HMAC-SHA256(master_secret, "rgt-vault:anchor:v1" \|\| index_tag \|\| value)`, so a backup of `vault.db` + `keychain.json` alone cannot forge it. Emits `EPOCH_ANCHOR_DEGRADED` (severity `warning`) on **every** open. |
| `none` | — | emits `EPOCH_ANCHOR_DISABLED` at severity `critical` on every open. Test/dev only. |

`file` is genuinely weaker: an attacker who captures a whole-host image gets the anchor file too, and
it is only as monotonic as the filesystem. It buys protection against the realistic
*vault-directory-restore* attack and nothing more. That limitation must be stated in the error/warning
text, not just in docs.

**The downgrade trap.** Selecting the mode by environment variable means an attacker who can set the
environment can pick `none`. Mitigation: record the anchor mode and `anchor_id` in `keychain.json`
at initialisation, and at load time refuse to open if the configured mode is *weaker* than the
recorded one (`tpm` > `file` > `none`) — a distinct CRITICAL `EPOCH_ANCHOR_DOWNGRADE`. Downgrading
requires the same explicit `rgt-vault epoch anchor --init` ceremony as an upgrade. This is not
airtight (an attacker who controls the process could rewrite `keychain.json` too), but it converts
the cheapest bypass from "set one env var" into "tamper with the keychain", which then trips case D.

**Platform story** (`create_platform_anchor()`, mirroring `create_platform_provider()`):

- **Linux** — `TPMNVCounterAnchor` when `/dev/tpmrm0` is accessible and `tpm2-tools` is on PATH;
  otherwise hard-fail with instructions to install `tpm2-tools`, join the `tss` group, or explicitly
  opt into `file`.
- **Windows** — TPM 2.0 is present on essentially all Windows 11 hardware, but `tpm2-tools` is not,
  and the TBS layer restricts direct NV access to elevated callers. Reaching it means the TBS API via
  `ctypes` or the TSS.MSR managed stack — a materially larger piece of work than this ticket. v1
  ships `file` on Windows (`%PROGRAMDATA%\rgt-vault\epoch.anchor`, ACL'd to SYSTEM+Administrators),
  with a follow-up ticket for a real TBS-backed anchor. Consistent with the existing DPAPI-based
  master provider being the Windows path.
- **macOS** — the Secure Enclave exposes no general-purpose monotonic counter to userspace. v1 ships
  `file`, sited outside the Time Machine backup set and marked `NSURLIsExcludedFromBackupKey`-
  equivalent. Flagged in §7.

Adopting fail-closed-by-default will break existing installs and most of the current test suite,
which construct `VaultManager` on machines with no TPM. Mitigation: `conftest.py` supplies an
in-memory anchor for tests (§6), and the release notes carry a loud upgrade note. This is a
deliberate, one-time break; softening it into a silent auto-fallback would reintroduce the exact
class of bug the ticket exists to close.

---

## 5. Proposed provider interface

New file `python/providers/monotonic_anchor.py` (ABC + fallback) and
`python/providers/tpm_nv_counter.py` (Linux TPM implementation), exported through
`python/providers/__init__.py`. Signatures and contracts only — no bodies.

```python
class AnchorStrength(IntEnum):
    """Ordered so a numeric comparison detects a downgrade (§4)."""
    NONE = 0
    SOFTWARE = 1   # file-backed
    HARDWARE = 2   # TPM NV counter


class MonotonicAnchorProvider(ABC):
    """A store whose value can only ever increase, and which survives a
    restore of the vault's on-disk files.

    Contract for every implementation:
      * ``read`` never returns a value lower than one it previously returned
        for the same anchor, across process restarts and OS reinstalls.
      * ``increment`` is atomic: it either advances by exactly one and
        returns the new value, or raises and leaves the anchor untouched.
      * No method ever creates, resets, or destroys an anchor implicitly.
        Creation happens only via ``claim``, which the caller invokes from an
        explicit initialisation path.
    """

    strength: AnchorStrength

    @abstractmethod
    def anchor_id(self) -> str:
        """Stable identifier for this specific anchor instance.

        For TPM: ``"tpm-nv:0x01800016:<hex of the TPM2B_NAME from
        nvreadpublic>"`` -- the name covers the index, attributes and auth
        policy, so it changes if the index is undefined and redefined.
        Persisted in keychain.json at init and compared at every load.
        """

    @abstractmethod
    def is_available(self) -> bool:
        """True iff the backing store can be reached right now.

        Must NOT distinguish 'unavailable' from 'unclaimed' -- an
        unreachable TPM returns False here, an accessible TPM with no
        index defined returns True and ``read`` returns None.
        """

    @abstractmethod
    def read(self) -> Optional[int]:
        """Current counter value, or None if the anchor is not yet claimed.

        Raises AnchorUnavailableError if the store is unreachable. Callers
        MUST NOT treat that exception as 'no anchor' (see §3 case G).
        """

    @abstractmethod
    def claim(self) -> int:
        """Create the anchor and return its initial value.

        Fails closed with AnchorClaimConflictError if the underlying slot
        already exists and does not match this provider's expected shape.
        Never overwrites, never undefines. Idempotent only in the sense
        that claiming an already-correctly-shaped anchor returns its
        current value rather than resetting it.
        """

    @abstractmethod
    def increment(self) -> int:
        """Advance by exactly one and return the new value.

        This is the commit point of an epoch rotation. Must be durable
        before returning.
        """


class TPMNVCounterAnchor(MonotonicAnchorProvider):
    strength = AnchorStrength.HARDWARE

    def __init__(
        self,
        nv_index: int = 0x01800016,
        hierarchy: str = "o",
        tpm_device: str = "/dev/tpmrm0",
    ) -> None: ...
    # internal: _nvreadpublic() -> Optional[dict]   (parsed tpm2_nvreadpublic YAML)
    # internal: _assert_shape(pub: dict) -> None    (nt==counter, size==8, attrs match)


class FileMonotonicAnchor(MonotonicAnchorProvider):
    strength = AnchorStrength.SOFTWARE

    def __init__(
        self,
        path: str,
        hmac_key_provider: Callable[[], bytes],   # returns the master secret
        index_tag: str = "default",
    ) -> None: ...


class NullAnchor(MonotonicAnchorProvider):
    """Explicit opt-out. Every method logs at CRITICAL. Tests and dev only."""
    strength = AnchorStrength.NONE


def create_platform_anchor() -> MonotonicAnchorProvider:
    """Per-OS dispatch mirroring ``create_platform_provider``. Honours
    RGT_VAULT_EPOCH_ANCHOR and RGT_VAULT_NV_INDEX. Raises rather than
    silently degrading when the requested mode is unavailable (§4)."""
```

`VaultManager.__init__` gains `anchor: Optional[MonotonicAnchorProvider] = None`, defaulting to
`create_platform_anchor()`, exactly parallel to the existing `master_provider` parameter.

---

## 6. Test plan

No RGT-16 references or epoch-rollback expectations exist in `tests/test_asvs_crypto.py` (its only
epoch touch is `mgr.initialize_dek(..., epoch=1, ...)` at line 337, which is unaffected). The only
constraining test is `tests/test_vault_v2.py::test_rollback_protection` (line ~191), which must be
kept passing — it exercises the *mismatched-pair* case (§3 case D) and stays valid.

Three layers:

**(1) `tests/test_epoch_anchor.py` — TPM command construction, `subprocess.run` mocked.**
Follows the convention in `tests/test_providers.py::TestLinuxTPMProvider` exactly: a `fake_run(args,
**kwargs)` closure dispatching on `str(args)`, installed with `mock.patch("subprocess.run",
side_effect=fake_run)`. Add a small `FakeTPM` holding `{index: {"nt": "counter", "size": 8,
"value": int, "name": "..."}}` that renders `tpm2_nvreadpublic` YAML on stdout and 8-byte big-endian
data for `tpm2_nvread`. Cases:

- claim on an empty TPM → `tpm2_nvdefine` issued with `nt=1` and `-s 8`; returns `C0`
- `increment` → value advances by exactly 1; `read` reflects it
- index already defined **with our shape** → `claim` returns the existing value, no `nvdefine`
- index already defined **with a foreign shape** (`nt=ordinary`, `size=64`) → `AnchorClaimConflictError`,
  and assert **no `tpm2_nvdefine` and no `tpm2_nvundefine` appear in the recorded call list** — this
  is the shared-hardware safety test
- `tpm2_nvread` returns non-zero / `tpm2-tools` missing (`FileNotFoundError`) → `AnchorUnavailableError`

**(2) `tests/test_epoch_anchor.py` — vault-level, using an in-memory `FakeAnchor`.**
Cheaper and clearer than subprocess mocks for end-to-end behaviour; inject via the new
`VaultManager(anchor=...)` parameter.

- *normal rotation advances both*: `rotate_master_key()` and `rotate_dek()` each leave
  `anchor.read() == vault.key_epoch == keychain['key_epoch']`, and the TPM increment is observed to
  happen **before** the DB write (assert on a recorded call order, so the commit-point ordering is
  regression-protected)
- *the acceptance-criteria test — epoch regression*: build a vault, `rotate_master_key()` (anchor and
  both files now at N+1), snapshot **both** `vault.db` and `keychain.json`; rotate again to N+2;
  restore the consistent N+1 pair; reopen → `EpochRollbackError`, and an `audit_logs` row exists with
  action `EPOCH_ROLLBACK_DETECTED` and `"severity": "critical"` in `details`. This is the case the
  current code silently accepts, so the test must be verified to **fail against `master`**.
- *counter < db epoch* → `EPOCH_ANCHOR_DESYNC`, refuse
- *anchor unavailable at load* (`FakeAnchor` raising `AnchorUnavailableError`) → vault refuses to
  open; explicitly assert it does **not** fall back
- *first run* → fresh vault claims the anchor, DB epoch equals `C0` (use a `FakeAnchor` with a large
  non-1 `C0`, e.g. 4711, to catch any code that assumes epochs start at 1)
- *downgrade* → keychain records `tpm`, environment requests `none` → `EPOCH_ANCHOR_DOWNGRADE`

**(3) `tests/test_tpm_live.py` — real hardware, double-gated.**
The existing file skips on `os.access("/dev/tpmrm0", R_OK|W_OK)`. NV define/undefine has **persistent,
irreversible side effects on shared hardware** (an index consumed, and the TPM's max-counter
watermark permanently raised), so live NV tests get a second gate — `RGT_VAULT_TPM_LIVE_NV=1` — and
use a dedicated scratch index `0x0180001F` from the reserved band, cleaning up with
`tpm2_nvundefine` in a fixture teardown. One live test is worth having: **claim → read → increment →
undefine → re-claim, asserting the re-claimed value is ≥ the pre-undefine value**, which empirically
validates risk R2 (§7) on the actual hardware.

`tests/conftest.py` supplies an `AnchorStrength.SOFTWARE` in-memory anchor to the shared `vault`
fixture so the rest of the suite keeps running on TPM-less machines.

---

## 7. Open questions and risks

**R1 — Disaster recovery becomes an operator ceremony (highest operational risk).**
Once the epoch is TPM-bound, restoring a legitimate backup onto *new hardware* is indistinguishable
from the attack and will be refused. Every legitimate restore, hardware replacement, or motherboard
swap now requires the `rgt-vault epoch anchor --init` re-anchor ceremony. If that procedure is not
written, rehearsed, and reachable by whoever is on call, the first real outage turns this control
into "the thing that ate the vault", and the pressure will be to add a bypass flag — which recreates
the vulnerability. **A documented, tested DR runbook should be a merge blocker for the
implementation PR**, and the re-anchor path needs its own security review (it is, by construction, a
sanctioned way to accept a lower epoch).

**R2 — Counter-redefinition semantics are assumed, not verified.**
The whole design leans on "a newly-defined NV counter starts above the TPM's historical maximum" to
defeat undefine/redefine. It is spec-mandated, but real firmware varies, and it is unclear whether
`TPM2_Clear` on the owner hierarchy resets the watermark. Needs empirical verification on juzu's
actual TPM (and ideally on the CI hardware) before implementation is accepted — see the live test in
§6(3). If the property does not hold, the design needs an additional binding (most likely folding
`anchor_id()`, which includes the NV name, into the DEK AAD — see R4).

**R3 — Forward-increment DoS and alert fatigue.**
With owner auth empty (the default on Linux), *any* local process can `tpm2_nvincrement` our index.
That cannot roll the vault back, but it can push the counter ahead of the DB, which under §3 case B
locks the vault closed until an operator runs `epoch reconcile` — and does so while emitting a
CRITICAL "rollback detected" alert that is, in that instance, a false positive. Repeatable at will.
Open question for review: is the right answer (i) require non-empty owner auth in production and
document it, (ii) accept the DoS as strictly better than a silent bypass, or (iii) add a
`TPMA_NV_POLICYWRITE` policy despite the brittleness argued in §1.3? Current recommendation is (i)+(ii),
but this is exactly the trade a second reviewer should weigh.

**R4 — Should `anchor_id` enter the DEK-wrap AAD?**
Changing the AAD from `f"{vault_id}:{epoch}"` to `f"{vault_id}:{epoch}:{anchor_id}"` would
cryptographically bind the wrapped DEK to one specific NV index on one specific TPM, closing the
"repoint at a fresh index" family of attacks by construction rather than by comparison. Cost: a
`keychain.json` format bump to `version: 2` with a migration path, and it worsens R1 (recovery onto
new hardware would then require a full DEK rewrap, not just a re-anchor). Deliberately left out of
the v1 scope; wants an explicit decision.

**R5 — macOS and Windows have no hardware answer in v1.**
Both fall back to `file` (§4), which means the ticket's actual guarantee is Linux-only for now. Is
that acceptable for the v1 milestone, or does Windows TBS need to land in the same release? Also
unresolved: whether the `file` anchor's HMAC key should be the master secret (simple, but ties anchor
verification to master-secret availability and creates an ordering dependency during startup) or a
separate platform-sealed key.

**R6 — Minor: NV write endurance.**
TPM NV memory has finite write endurance (vendor-specified, typically ≥ 100k writes per index in
practice but not always documented). One write per epoch rotation is negligible for any realistic
rotation cadence, but `_record_dek_usage_and_maybe_rotate` (`python/vault.py:1120`) can trigger
*automatic* DEK rotation on a usage threshold. Confirm that threshold cannot produce pathological
rotation rates before shipping.
