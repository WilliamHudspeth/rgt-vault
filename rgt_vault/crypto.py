import ctypes
import os
from typing import Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from rgt_vault.exceptions import DecryptionError, ValidationError


def encrypt(data: Union[str, bytes, bytearray], dek: bytes, aad: bytes) -> bytes:
    """
    Encrypt data using AES-256-GCM.
    A unique 96-bit (12-byte) nonce is generated and prepended to the ciphertext.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
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
