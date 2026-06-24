import base64
import os
from pathlib import Path
from typing import Optional

from .base import MasterSecretProvider


def _load_win32crypt():
    """Import win32crypt on demand.

    pywin32 ships only with the optional ``rgt-vault[windows]`` extra, so the
    import is deferred to call time: the module must stay importable on any
    platform (and on Windows without pywin32) so the package and its test
    suite load cleanly. Raises a clear error only when the provider is used.
    """
    try:
        import win32crypt
    except ImportError as e:
        raise RuntimeError(
            "WindowsDPAPIProvider requires pywin32. Install it with: pip install 'rgt-vault[windows]'"
        ) from e
    return win32crypt


class WindowsDPAPIProvider(MasterSecretProvider):
    def __init__(self, blob_path: str, entropy: Optional[bytes] = None):
        self.blob_path = Path(blob_path)
        self.entropy = entropy

        if not self.blob_path.is_file():
            raise FileNotFoundError(f"DPAPI blob not found: {self.blob_path}")

    def get_secret(self) -> bytes:
        win32crypt = _load_win32crypt()

        with open(self.blob_path, encoding="utf-8") as f:
            b64data = f.read()

        encrypted_blob = base64.b64decode(b64data)

        try:
            decrypted = win32crypt.CryptUnprotectData(
                encrypted_blob,
                self.entropy,
                None,
                None,
                4,  # CRYPTPROTECT_LOCAL_MACHINE
            )
        except Exception as e:
            raise PermissionError(f"DPAPI decryption failed: {e}")

        # CryptUnprotectData returns a tuple (description, data)
        # Check if it returns tuple or bytes depending on pywin32 version
        if isinstance(decrypted, tuple):
            return decrypted[1]
        return decrypted


def seal_master_secret(master_secret: bytes, output_path: str, entropy: Optional[bytes] = None) -> None:
    win32crypt = _load_win32crypt()

    encrypted = win32crypt.CryptProtectData(
        master_secret,
        "Vault Master Secret",
        entropy,
        None,
        None,
        4,  # CRYPTPROTECT_LOCAL_MACHINE
    )

    b64data = base64.b64encode(encrypted).decode("utf-8")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(b64data)
