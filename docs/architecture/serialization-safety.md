# Serialization Safety Audit

## RGT-377: Serialized Object Integrity (ASVS 5.5.1 / CWE-502)

All serialized data in rgt-vault is either:

1. **JSON via `json.loads` / `json.dumps`** (standard library, no code execution).
   Used for: audit log entries, vault export/import payloads, capability tokens,
   hook request metadata.

2. **YAML via `yaml.safe_load`** (PyYAML safe loader, no Python object deserialization).
   Used for: ABAC policy parsing in `python/auth.py`.

3. **SQLite rows** deserialized by the `sqlite3` standard-library driver.
   Column types are explicitly declared; no arbitrary object deserialization occurs.

4. **AES-256-GCM authenticated encryption** for ciphertext blobs. The GCM tag
   is verified before any plaintext is returned, so a tampered ciphertext raises
   `InvalidTag` and is refused. This provides the integrity check required by
   ASVS 5.5.1 for serialized secret material.

**Status:** Compliant.

---

## RGT-378: XXE — XML Parser Configuration (ASVS 5.5.2 / CWE-611)

rgt-vault does not parse XML from untrusted sources. The only XML emitted by
the application is the restrictive Flash/Silverlight cross-domain policy at
`GET /crossdomain.xml`, which is a static string, not parsed.

The `crossdomain.xml` endpoint returns a policy that denies all cross-domain
access (`permitted-cross-domain-policies="none"`) and is served with a 404
status to discourage reliance on it.

**Status:** Not applicable — no XML parsing of untrusted input is performed.

---

## RGT-379: Deserialization of Untrusted Data (ASVS 5.5.3 / CWE-502)

The following deserialization surfaces exist and are audited:

| Deserializer     | Location                      | Input source       | Safe? |
|-----------------|-------------------------------|--------------------|-------|
| `json.loads`    | `vault.import_vault`          | Operator-supplied  | Yes — no code exec |
| `json.loads`    | `storage/sqlite.py` audit log | Internal DB        | Yes |
| `yaml.safe_load`| `auth.py` policy engine       | Operator YAML      | Yes — safe loader |
| `base64.b64decode` | `vault.import_vault`       | Operator-supplied  | Yes — decode only |

`pickle` is not imported anywhere in the codebase. `eval()` is not called on
any untrusted input. The `ast.literal_eval` function is not used.

---

## RGT-380: JSON Parsing — No eval() (ASVS 5.5.4 / CWE-95)

Python's `json.loads` is used for all JSON deserialization. There is no
`eval()` call on JSON-shaped data anywhere in the codebase. JavaScript's
`eval()`-for-JSON antipattern has no Python equivalent in this codebase.

**Status:** Compliant.
