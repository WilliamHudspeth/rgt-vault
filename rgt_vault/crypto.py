from __future__ import annotations

import ctypes
import os
import sys
from types import TracebackType
from typing import Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from rgt_vault.exceptions import DecryptionError, ValidationError


def encrypt(data: Union[str, bytes, bytearray], dek: bytes, aad: bytes) -> bytes:
    """
    Encrypt data using AES-256-GCM.
    A unique 96-bit (12-byte) nonce is generated and prepended to the ciphertext.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(aad, (bytes, bytearray)):
        raise ValidationError("AAD must be bytes or bytearray.")
    if not isinstance(dek, (bytes, bytearray)) or len(dek) != 32:
        raise ValidationError("DEK must be exactly 32 bytes.")

    nonce = os.urandom(12)
    cipher = AESGCM(dek)
    ciphertext = cipher.encrypt(nonce, data, aad)
    return nonce + ciphertext


def decrypt(token: bytes, dek: bytes, aad: bytes) -> bytes:
    """
    Decrypt data using AES-256-GCM.
    Expects the first 12 bytes to be the nonce.

    Raises :class:`rgt_vault.exceptions.DecryptionError` on any failure (bad
    AAD, wrong key, malformed input, or authentication tag mismatch). The
    original cause is chained via ``__cause__`` for internal logging.
    """
    # Reject non-bytes input explicitly so callers can't smuggle a `str` and
    # accidentally hit a `TypeError` deep inside the AESGCM path.
    if not isinstance(token, (bytes, bytearray)):
        raise DecryptionError("Ciphertext must be bytes or bytearray.")
    if not isinstance(aad, (bytes, bytearray)):
        raise DecryptionError("AAD must be bytes or bytearray.")
    if not isinstance(dek, (bytes, bytearray)) or len(dek) != 32:
        raise DecryptionError("DEK must be exactly 32 bytes.")

    if len(token) < 12 + 16:  # 12 bytes nonce + 16 bytes tag
        raise DecryptionError("Ciphertext is too short to be valid.")

    nonce = bytes(token[:12])
    ciphertext = bytes(token[12:])

    try:
        cipher = AESGCM(dek)
        return cipher.decrypt(nonce, ciphertext, aad)
    except InvalidTag as e:
        # Do not leak *why* decryption failed (bad AAD, wrong key, tampering)
        # to a public caller; the chain preserves the cause for debug logs.
        raise DecryptionError("Decryption failed: ciphertext is invalid or tampered with.") from e


def zeroize_bytearray(b: bytearray) -> None:
    """Aggressively wipe secrets from memory using ctypes.memset."""
    if not isinstance(b, bytearray):
        raise TypeError("zeroize_bytearray requires a bytearray")

    buffer_size = len(b)
    if buffer_size == 0:
        return

    try:
        buffer_type = ctypes.c_char * buffer_size
        ctypes.memset(buffer_type.from_buffer(b), 0, buffer_size)
    except Exception:
        # Fallback if ctypes.memset fails
        for i in range(buffer_size):
            b[i] = 0


class SecureBuffer:
    """
    Fixed-size, mlocked native buffer for secrets.
    Use ONLY inside a context manager — guarantees zeroization.
    """

    def __init__(self, size: int, *, lock: bool = True):
        if size <= 0:
            raise ValueError("size must be >0")
        self.size = int(size)
        self._buf = ctypes.create_string_buffer(self.size)
        self._addr = ctypes.addressof(self._buf)
        self._locked = False
        self._closed = False

        if lock:
            self._lock_memory()

        self.zeroize()  # start clean

    # --- platform locking ---
    def _lock_memory(self) -> None:
        try:
            if sys.platform == "win32":
                kernel32 = ctypes.windll.kernel32
                if not kernel32.VirtualLock(ctypes.c_void_p(self._addr), ctypes.c_size_t(self.size)):
                    raise OSError(ctypes.get_last_error(), "VirtualLock failed")
                self._locked = True
            else:
                libc = ctypes.CDLL(None, use_errno=True)
                # mlock requires page alignment on some kernels — create_string_buffer is usually fine
                if libc.mlock(ctypes.c_void_p(self._addr), ctypes.c_size_t(self.size)) != 0:
                    errno = ctypes.get_errno()
                    # Don't crash in dev, but log — production should run with CAP_IPC_LOCK
                    raise OSError(errno, "mlock failed - run with CAP_IPC_LOCK or increase ulimit -l")
                self._locked = True
        except Exception:
            # Fail-open for portability, but mark unlocked
            self._locked = False

    def _unlock_memory(self) -> None:
        if not self._locked:
            return
        try:
            if sys.platform == "win32":
                ctypes.windll.kernel32.VirtualUnlock(ctypes.c_void_p(self._addr), ctypes.c_size_t(self.size))
            else:
                libc = ctypes.CDLL(None, use_errno=True)
                libc.munlock(ctypes.c_void_p(self._addr), ctypes.c_size_t(self.size))
        finally:
            self._locked = False

    # --- core ops ---
    def zeroize(self) -> None:
        """Overwrite buffer with zeros using non-optimizable primitive."""
        if self._closed:
            return
        if sys.platform == "win32":
            # RtlSecureZeroMemory = SecureZeroMemory
            ctypes.windll.kernel32.RtlSecureZeroMemory(ctypes.c_void_p(self._addr), ctypes.c_size_t(self.size))
        else:
            # libc memset is not elided when called via ctypes
            libc = ctypes.CDLL(None)
            libc.memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
            libc.memset(ctypes.c_void_p(self._addr), 0, ctypes.c_size_t(self.size))

    def write(self, data: bytes, offset: int = 0) -> None:
        if self._closed:
            raise ValueError("buffer closed")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        n = len(data)
        if offset < 0 or offset + n > self.size:
            raise ValueError("write exceeds buffer")
        ctypes.memmove(self._addr + offset, bytes(data), n)

    def read(self, n: Optional[int] = None, offset: int = 0) -> bytes:
        if self._closed:
            raise ValueError("buffer closed")
        n = self.size - offset if n is None else n
        if offset < 0 or offset + n > self.size:
            raise ValueError("read exceeds buffer")
        return ctypes.string_at(self._addr + offset, n)

    def wipe_and_close(self) -> None:
        if not self._closed:
            self.zeroize()
            self._unlock_memory()
            self._closed = True

    # --- context manager ---
    def __enter__(self) -> "SecureBuffer":
        return self

    def __exit__(self, exc_type, exc, tb: Optional[TracebackType]) -> None:
        self.wipe_and_close()

    def __del__(self):
        # best-effort, __del__ not guaranteed
        try:
            self.wipe_and_close()
        except Exception:
            pass

    # prevent accidental repr leaks
    def __repr__(self):
        return f"<SecureBuffer size={self.size} locked={self._locked} closed={self._closed}>"
