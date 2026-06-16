import base64
import os
import sys
from pathlib import Path
from typing import Optional

from .base import MasterSecretProvider

if sys.platform == "win32":
    import win32crypt
else:
    win32crypt = None  # type: ignore

class WindowsDPAPIProvider(MasterSecretProvider):
    def __init__(self, blob_path: str, entropy: Optional[bytes] = None):
        self.blob_path = Path(blob_path)
        self.entropy = entropy

        if not self.blob_path.is_file():
            raise FileNotFoundError(f"DPAPI blob not found: {self.blob_path}")

    def get_secret(self) -> bytes:
        if win32crypt is None:
            raise RuntimeError("This provider only works on Windows.")

        with open(self.blob_path, encoding="utf-8") as f:
            b64data = f.read()

        encrypted_blob = base64.b64decode(b64data)

        try:
            decrypted = win32crypt.CryptUnprotectData(
                encrypted_blob,
                self.entropy,
                None,
                None,
                4  # CRYPTPROTECT_LOCAL_MACHINE
            )
        except Exception as e:
            raise PermissionError(f"DPAPI decryption failed: {e}")

        # CryptUnprotectData returns a tuple (description, data)
        # Check if it returns tuple or bytes depending on pywin32 version
        if isinstance(decrypted, tuple):
            return decrypted[1]
        return decrypted

def seal_master_secret(
    master_secret: bytes,
    output_path: str,
    entropy: Optional[bytes] = None
) -> None:
    if win32crypt is None:
        raise RuntimeError("This function only works on Windows.")

    encrypted = win32crypt.CryptProtectData(
        master_secret,
        "Vault Master Secret",
        entropy,
        None,
        None,
        4  # CRYPTPROTECT_LOCAL_MACHINE
    )

    b64data = base64.b64encode(encrypted).decode("utf-8")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(b64data)
