# Memory Safety, Format Strings, and Integer Overflow

## RGT-374: Memory-Safe String and Pointer Operations (ASVS 5.4.1)

rgt-vault is implemented in Python, a memory-managed language. Python provides
automatic bounds-checking on all string and array accesses; there are no raw
pointer operations, no manual memory allocation, and no buffer-overflow risk
from string copies. The runtime raises `IndexError` or `ValueError` before any
out-of-bounds access can propagate.

The only deliberate use of a mutable buffer is the `bytearray` used to hold
decrypted secrets (`vault.lease_secret`). This is zeroized via
`crypto.zeroize_bytearray` immediately after use. The zeroization is in a
`finally` block so it runs even if the consumer raises.

**Status:** Compliant by language design. No C extensions are used in the
trust boundary. All dependencies are reviewed via SBOM (see `test_sbom.py`).

---

## RGT-375: Format String Safety (CWE-134)

Python's f-strings and `str.format()` are not equivalent to C `printf`-style
format strings. There is no mechanism by which a user-supplied string can cause
arbitrary memory reads or code execution via a Python format operation.
User-controlled data is never interpolated into a format specifier; it is
always passed as a positional argument or embedded in a pre-constructed string.

Audit result: a grep of `python/` for `%` formatting with untrusted input
showed zero instances where the format string itself originates from user input.

**Status:** Not applicable — Python format strings do not share the CWE-134
attack surface.

---

## RGT-376: Integer Overflow (ASVS 5.4.3)

Python integers are arbitrary precision; there is no integer overflow in pure
Python code. Bound checks are applied at the API boundary by `_validate_string_param`
and `_normalize_value_param` in `VaultManager`, and by the HTTP layer
(`limit`/`offset` checks in `/v1/secrets` and `/v1/audit`).

All integer parameters that cross the HTTP boundary have explicit bounds checks:

| Parameter      | Endpoint        | Lower bound | Upper bound |
|---------------|-----------------|-------------|-------------|
| `limit`       | GET /v1/secrets | 1           | 1000        |
| `offset`      | GET /v1/secrets | 0           | (none)      |
| `limit`       | GET /v1/audit   | 1           | 1000        |
| `max_len`     | _validate_string_param | 1  | (caller-set)|

**Status:** Compliant. Bound checks are enforced server-side. Tests in
`tests/test_input_validation_epic.py` verify integer bound enforcement.
