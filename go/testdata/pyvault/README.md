# Python-generated compatibility fixtures for the Go port (batch G0)

Everything here was produced by the **real Python code** (`rgt_vault`: `VaultManager`, `StorageBackend`,
`HardenedDEKManager`, `HMACTokenVerifier`, `TwoFactorHook`, `totp`, `ABACPolicyEngine`, `input_validation`) and is
committed as **static files**, so the Go tests keep working after `python/` is removed. Python is frozen and is the
reference the Go port must match byte for byte (see `docs/` / the Go parity plan: "port faithfully, harden separately").

> **All secrets in here are fixed test fixtures, not real secrets.** The master secrets, HMAC keys, DEKs and TOTP
> seeds are derived from public labels (`sha256("rgt-vault-g0-...")`) on purpose. The repo's shared `.gitleaks.toml`
> allow-lists this directory and `tests/compat/` only.

Total committed size: **3.8 MB** (`small/` 3.0 MB because of the 1 MiB secret and its export, `default/` 59 KB,
`epoch1/` 56 KB, `edge/` ~0.4 MB, `vectors/` ~0.2 MB).

## Regenerate

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[server,dev]'
.venv/bin/python tests/compat/gen_go_fixtures.py                  # everything, ~3 s
.venv/bin/python tests/compat/gen_go_fixtures.py --only vectors   # subset: small,default,epoch1,edge,vectors
.venv/bin/pytest tests/compat                                     # proves the committed files are valid
```

Regenerate only when a Python behaviour the Go port mirrors has changed. Vault salts, DEKs, nonces, UUIDs-per-secret and
wall-clock timestamps are random (not seedable), so a re-run changes the bytes of `small/ default/ epoch1/`
(the manifests' *expectations* stay equivalent). `vectors/` is fully deterministic. `edge/` is deterministic except
`legacy_dek0.db` (wall-clock audit timestamp, random Fernet IV).

`tests/compat/test_fixtures_selfcheck.py` re-opens every vault with Python and re-evaluates every vector with the real
Python code, then compares with the committed manifests/vectors. Its `eval_*` functions live in
`tests/compat/gen_go_fixtures.py` (the generator derives each expectation with the same function).

## How a Go test should consume the vaults

* **Copy the directory to a temp dir first.** `vault.db` is in SQLite WAL mode (like every Python-written vault), so opening
  it may create `-wal`/`-shm` files; and opening/reading a vault appends audit rows (every read is audited).
  The committed `vault.db` files have no `-wal`/`-shm` (checkpointed) and are single self-contained files.
* Master secret = the raw 32 bytes of `master.bin` (what a platform provider returns). `policy.yaml` is the exact text
  given to `VaultManager(policy_yaml=...)`; `policy_hash` in the manifest = `sha256(policy.yaml)[:16]`
  (hex) and it is stored in the audit rows.
* The repo `.gitignore` ignores `*.db` and `keychain.json`; `go/testdata/pyvault/.gitignore` un-ignores them and
  `.gitattributes` marks everything `-text`/binary (no CRLF conversion: `policy.yaml` is hashed).

## Vault directories

Each of `small/`, `default/`, `epoch1/` contains:

| file | content / what it proves |
|---|---|
| `vault.db` | SQLite file exactly as Python wrote it (all 5 migrations applied, `schema_migrations` bookkeeping, WAL mode). Go's store must open it read/write. |
| `keychain.json` | `HardenedDEKManager` v1 file: base64 `argon2_salt`, Argon2 params, `wrapped_dek` (std base64 of ciphertext‖tag, **no nonce**), `created_at` (isoformat), `key_epoch`. |
| `master.bin` | The 32-byte master secret that unwraps the DEK (fixed-master stub provider). |
| `policy.yaml` | The ABAC policy the vault was opened with (allow all, deny agent `intruder` on read). |
| `export.b64` | `VaultManager.export_vault()` output: `base64(json.dumps(..., indent=2))` with `secrets`, `audit_logs`, `honeytokens`, `vault_id`. Python can import it back (checked by the self-check). |
| `manifest.json` | Expected state (below). |

| vault | Argon2 | epoch | what is in it |
|---|---|---|---|
| `small/` | 4096 / 2 / 2 (fast; all three ≠ 1 so a Go reader that hard-codes a parameter fails) | **3** (`rotate_master_key` then `rotate_dek`) | 16 secret rows: SUPERSEDED, REVOKED, `note`, `require_2fa`, a honeytoken (decoy row + `honeytokens` entry, triggered once), unicode values (NFC and NFD kept un-normalised), CRLF/tab/padded values, a **1 MiB** value, rows written after each rotation; 52 audit rows incl. rows with `policy_hash = ""` (a denied write under an empty policy), `HOOK_*`, `HONEYTOKEN_TRIGGERED`, `POLICY_DENIED`, `LEASE_*`, `ROTATE`. |
| `default/` | **262144 / 4 / 4** (production defaults) | 2 (`rotate_master_key`) | 5 secrets (a SUPERSEDED version, a `require_2fa`, unicode, a post-rotation write). One vault proving Go reads default-cost keychains. |
| `epoch1/` | 4096 / 2 / 2 | 1 | 4 rows, never rotated. Use for the simple load path, and as the "rolled-back keychain" donor: its `keychain.json` next to `small/vault.db` must fail with *Rollback attack detected* (epoch 1 ≠ 3). |

`manifest.json` fields: `vault_id`, `key_epoch`, `keychain` (parsed file), `master_hex`, `dek_hex` (the unwrapped DEK, so a
test can check the unwrap output and decrypt rows without re-running the KDF), `policy_hash`, `policy_hashes_in_chain`,
`metadata` (the `metadata` table incl. `dek_encrypt_count/bytes`), `migrations_applied`, `row_counts`, `honeytokens`,
`audit` (`verify_audit_chain` verdict from Python's own `VaultManager.verify_audit_chain`, first/last hash, action
histogram), `export` (sha256 + counts), and `secrets[]` with, per stored row: `id`, `secret_id`, `namespace`, `name`,
`version`, `status`, `dek_version`, `note`, `require_2fa`, `honeytoken`, timestamps, `checksum`, `fingerprint`
(`checksum[:8]`), `ciphertext_len`, `aad` (`vault_id:namespace:name`), `decrypts_with_current_dek`, `read_latest`,
`read_by_version`, and `plaintext` (or `plaintext_sha256` + `plaintext_gen` for the 1 MiB value).

Semantics pinned by the manifest (and re-checked by the self-check):

* A read of the *latest* version only sees the ACTIVE row; a name whose only row is REVOKED gives `SecretNotFoundError`.
  A read **by explicit version ignores status** (but still hits the honeytoken check first).
* **`rotate_dek` re-encrypts only ACTIVE rows.** SUPERSEDED/REVOKED rows written before it keep ciphertext under the OLD
  DEK and no longer decrypt (`decrypts_with_current_dek: false`, `DecryptionError`). Rows written after it decrypt.
* `rotate_master_key` re-wraps the same DEK (new salt, new epoch) and, like `rotate_dek`, **always writes the default
  Argon2 params** (the generator swaps only those defaults for the small vaults; the params are read back from the file).
* A honeytoken name raises `PermissionError` on lease/fingerprint and writes `HONEYTOKEN_TRIGGERED`.
* Secret AAD is `vault_id:namespace:name`; keychain AAD is `vault_id:epoch`; KDF binding context is `rgt-vault:vault_id`.

## `edge/` — audit-chain databases and Python's own verdicts

`edge/manifest.json` lists every database with Python's `verify_audit_chain` verdict, the 0-based `first_bad_index`
(rows by `id` ascending), and **all rows** with the hash the verifier computes for each (`expected_hash`), so the audit
package can be unit-tested without a DB. Hash input: `prev_entry_hash|timestamp|action|secret_name or ''|details|policy_hash`
(sha256 hex; `agent_id` is not hashed; `details`/`policy_hash` are rendered with `str()` of the stored value, so **NULL
becomes the literal `None`**, while a NULL `secret_name` becomes `''`).

| db | verdict | proves |
|---|---|---|
| `chain_ok.db` | True | rows from the real `log_audit`: NULL secret_name, empty details/policy_hash, CRLF/tab sanitisation in action and details, unicode, `microsecond == 0` timestamps. |
| `null_details_policy_ok.db` | True | NULL details / NULL policy_hash rows hashed as `"None"` verify. |
| `null_details_hashed_empty.db` | **False** (index 3) | NULL details hashed as `''` (what an exporter would have written) are reported as a broken chain: the quirk Go must reproduce. |
| `tampered_details.db`, `tampered_entry_hash.db`, `tampered_timestamp.db`, `deleted_middle.db` | False | one deliberately tampered/removed row each (`first_bad_index` 4, 2, 0, 3). |
| `agent_id_not_hashed.db` | True | rewriting `agent_id` (and `prev_hash`) does not break the chain. |
| `empty.db` | True | schema only; an empty log is vacuously valid. |
| `legacy_dek0.db` | (n/a) | one ACTIVE row with `dek_version = 0` (Fernet; key in the manifest). Python migrates these on open; Go refuses them (decision D3). |

## `vectors/`

Conventions: strings are plain JSON strings; a typed object `{"type": "cps"|"repeat"|"bytes"|"int"|"float"|"bool"|"null"|"list", ...}`
is used where JSON cannot say it (lone surrogates, 1 MiB strings, bytes, wrong types). Where a case has `expect`, it is the real
Python result; `message` fields are informational (do not compare them). `why` explains the case.

| file | proves / used by |
|---|---|
| `tokens_v2.json` | **v2 capability tokens** (`b64url(payload).b64url(hmac-sha256)`, no padding; `json.dumps(sort_keys, separators=(',',':'))` with `ensure_ascii`; `token_id = sha256(payload)[:16]`). Fixed key, `exp` 4102444800 (2100). `verify[]` (55 cases with an injected `now`: valid incl. unicode/`<>&`/DEL/astral escaping, tampered, wrong key, malformed envelopes, version errors, lenient base64, Python's `int()`/`str()` coercions, `exp <= 0` never expires, expiry boundary), `sign[]` (real `sign()` with a frozen clock → exact token + payload JSON), `sign_errors[]`, `check_context[]` (binding equality: `1 == 1.0 == True`), `is_expired[]`, `hook_v2.cases[]` (`TwoFactorHook` capability-path decisions incl. replay). |
| `tokens_v1.json` | **legacy v1 tokens** through the real `TwoFactorHook` (payload keys `a n c i x t`, HMAC under the shared secret): allow/deny per operation, namespace, wildcard (`*`), validity window (inclusive), tampering, replay. |
| `totp.json` | RFC 6238 Appendix B vectors (SHA1/256/512, 8 digits; asserted against the RFC by the generator), 6/7/8/10 digits, periods 15/30/45/60, fractional timestamps, secret spellings, `verify` windows 0/1/2 and malformed codes, `ReplayGuardedVerifier` sequences, `provisioning_uri` percent-encoding (`urllib.parse.quote`, `/` stays literal). |
| `abac.json` | 67 `(policy, agent, namespace, purpose, action)` → `allowed / reason / matched_rule_index / ttl` cases over 14 named policies (`*`, `?`, `[seq]`, `[!seq]`, `/` inside purpose and namespace, deny precedence, case sensitivity, unicode, effect spelling), `ttl_cases` for `get_lease_ttl` ordering and bad TTL values, `policy_shapes` (list / `{rules:}` / scalar / null / invalid YAML / 1 MiB cap). |
| `fnmatch.json` | ~65 raw `fnmatch.fnmatchcase(value, pattern)` results (the matcher Go must port; `*` and `?` cross `/` and newlines, `[]]`, `[!]]`, unterminated `[`, `\` is literal). |
| `validation.json` | ~230 accept/reject cases for `validate_name/namespace/agent/free_text/int_bound`, `normalize_unicode` (NFC + category allowlist), `VaultManager._validate_string_param` and `_normalize_value_param` (1 MiB cap, whitespace rules). |
| `timestamps.json` | `datetime(..., tzinfo=UTC).isoformat()` strings with `unix_micro`: `+00:00`, **no fractional part when microsecond == 0**, else exactly 6 digits, 4-digit zero-padded years. |
| `audit_vectors.json` | a chain of rows through the real `log_audit` (injected clock) with the stored `entry_hash`/`prev_hash`, plus `_sanitize_log_field` vectors (`\r \n \t` → two-char escapes only). |
| `keychain_wrap.json` | real `HardenedDEKManager.initialize_dek` with fixed DEK/salt/clock: exact `keychain.json` text, `kek_hex`, `nonce_hex`, AAD, binding context, for small and default params. Proves the **nonce is the KDF output and is not stored**. |

## Python behaviours pinned here that a Go port would silently get wrong

Each is covered by at least one case; they are pinned as-is (port faithfully, harden separately).

1. `verify_audit_chain` renders a NULL `details`/`policy_hash` as `"None"` (`edge/`).
2. `isoformat()` has no fractional part when microsecond is 0 (`timestamps.json`, `edge/chain_ok.db`).
3. Keychain wrap = AES-GCM with the KDF nonce, ciphertext‖tag stored, nonce **not** stored (`keychain_wrap.json`).
4. `rotate_dek` leaves SUPERSEDED/REVOKED rows under the old DEK (`small/`).
5. `rotate_master_key` / `rotate_dek` rewrap with the **default** Argon2 params regardless of the previous file.
6. `fnmatch`: `*`/`?` cross `/` and newlines; Go's `path.Match` does not (`abac.json`, `fnmatch.json`).
7. Token signing uses `ensure_ascii` (`é`, surrogate pairs, DEL as `\u007f`) and leaves `<>&` raw; Go's `json.Marshal` does the opposite.
8. v2 `verify` accepts padded / standard-alphabet / newline-containing base64 and coerces with `int()`/`str()`; `int(None)` leaks a `TypeError` (not a `TokenError`); `exp <= 0` never expires; bindings compare with Python equality (`True == 1 == 1.0`).
9. **v1 tokens minted by `TwoFactorHook.issue(...).to_compact()` are signed with an empty key** (a leftover placeholder) and can never verify under the hook's shared secret (`tokens_v1.json`, case `issue_to_compact_is_signed_with_empty_key`). The valid v1 vectors are signed the way `_consult_v1` verifies.
10. Name/namespace/agent validators use `^...$` with `re.match`, so a **single trailing `\n` is accepted** (`"abc\n"`); `validate_*` do not NFC-normalise (non-ASCII is simply rejected); free text is NFC-normalised before the length check.
11. `_normalize_value_param` uses `bytes.strip()` (ASCII whitespace only: `0x0b`/`0x0c` count, UTF-8 NBSP does not); Go's `bytes.TrimSpace` would reject NBSP-only values.
12. `totp.verify` lets a `TypeError` escape for non-ASCII digit strings (`hmac.compare_digest`); explicitly padded secrets are re-padded and fail.
13. `ABACPolicyEngine` with `rules:` null / a list of scalars fails at `evaluate()` (`TypeError`/`AttributeError`), not at construction (`policy_shapes`).
14. The vault itself never fills `audit_logs.agent_id` (all rows `NULL`); `agent_id` is not part of the hash anyway.

## Which Go batch uses what

G1 audit: `edge/`, `vectors/audit_vectors.json`, `timestamps.json` · G2 keychain: `keychain_wrap.json`, `small/ default/ epoch1/` keychains ·
G3 store: all `vault.db` + `edge/*.db` · G4 policy/validation: `abac.json`, `fnmatch.json`, `validation.json` ·
G5 captoken/totp/approval: `tokens_v*.json`, `totp.json` · G7 vault core / G12 compat suite: the three vaults and their manifests/exports.
