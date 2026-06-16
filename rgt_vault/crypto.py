import ctypes
import os
from typing import Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(data: Union[str, bytes], dek: bytes, aad: bytes) -> bytes:
    """
    Encrypt data using AES-256-GCM.
    A unique 96-bit (12-byte) nonce is generated and prepended to the ciphertext.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    nonce = os.urandom(12)
    cipher = AESGCM(dek)
    ciphertext = cipher.encrypt(nonce, data, aad)
    return nonce + ciphertext

def decrypt(token: bytes, dek: bytes, aad: bytes) -> bytes:
    """
    Decrypt data using AES-256-GCM.
    Expects the first 12 bytes to be the nonce.
    """
    if len(token) < 12 + 16: # 12 bytes nonce + 16 bytes tag
        raise ValueError("Invalid token length")
        
    nonce = token[:12]
    ciphertext = token[12:]
    
    cipher = AESGCM(dek)
    return cipher.decrypt(nonce, ciphertext, aad)

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
