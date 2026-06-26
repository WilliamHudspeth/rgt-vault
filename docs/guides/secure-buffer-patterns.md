# SecureBuffer Patterns for Partial Zeroization

This guide provides developer guidelines for minimizing plaintext exposure within the Python runtime of `rgt-vault`. Because Python's memory management handles standard strings immutably and opaquely, we must use specialized patterns to ensure sensitive material (like Master Keys, DEKs, and unsealed secret payloads) is not leaked to disk via swapping, or left dangling in memory.

## The Problem with `str` and `bytes`
In Python:
1. `str` and `bytes` objects are immutable. Modifying them creates a new object.
2. The runtime frequently interns small strings, making them impossible to deterministically garbage collect or wipe.
3. Memory allocated by the Python allocator can be paged out to disk (swap) by the OS at any time.

## Introducing `SecureBuffer`
`SecureBuffer` is our internal abstraction for handling highly sensitive plaintext. Under the hood, it allocates a mutable `bytearray`, and optionally calls `mlock(2)` on Unix systems to pin the memory page, preventing it from being swapped to disk.

### Pattern 1: Context Managers (Recommended)
The safest way to use a `SecureBuffer` is via a context manager. This guarantees that the memory is explicitly zeroized (overwritten with null bytes) the moment the `with` block exits, regardless of exceptions or normal control flow.

```python
from rgt_vault.crypto.buffer import SecureBuffer

def process_secret(encrypted_payload):
    # Allocate a SecureBuffer. The memory is pinned.
    with SecureBuffer(size=32) as plaintext_buf:
        # Decrypt directly into the mutable buffer
        cipher.decrypt_into(encrypted_payload, plaintext_buf)
        
        # Use the secret via memoryview to avoid copies
        submit_to_api(memoryview(plaintext_buf))
        
    # <-- At this indentation level, plaintext_buf is completely zeroized.
```

### Pattern 2: Explicit Zeroization
If you must hold a secret outside of a localized scope (e.g., caching the DEK in the VaultManager), you must explicitly zeroize it during teardown or rotation.

```python
class VaultManager:
    def __init__(self):
        self._dek = SecureBuffer(size=32)
        
    def rotate_dek(self, new_dek_bytes):
        # Zeroize the old DEK explicitly before pointing to the new one
        self._dek.zeroize()
        self._dek = SecureBuffer.from_bytes(new_dek_bytes)

    def shutdown(self):
        self._dek.zeroize()
```

### Pattern 3: Avoid Accidental Copies
A `SecureBuffer` is useless if you accidentally duplicate its contents into a standard `str` or `bytes` object.
* **Bad**: `submit_to_api(plaintext_buf.to_bytes())` (Creates an unmanaged `bytes` copy)
* **Good**: `submit_to_api(memoryview(plaintext_buf))` (Passes a view of the pinned memory)
* **Bad**: `log.debug(f"Loaded secret: {plaintext_buf}")` (Leaks secret to logs and creates a string copy)

## Conclusion
By consistently using `SecureBuffer` context managers and `memoryview` passing, we can achieve "partial zeroization"—drastically reducing the window of time plaintext exists in memory and ensuring it never touches the swap file.
