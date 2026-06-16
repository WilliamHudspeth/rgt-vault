import os
import subprocess
import tempfile

from .base import MasterSecretProvider


class MacOSKeychainProvider(MasterSecretProvider):
    def __init__(self, service_name: str, account_name: str):
        self.service_name = service_name
        self.account_name = account_name

    def get_secret(self) -> bytes:
        try:
            result = subprocess.run(
                [
                    "security", "find-generic-password",
                    "-s", self.service_name,
                    "-a", self.account_name,
                    "-w"
                ],
                capture_output=True,
                text=True,
                check=True
            )
            secret = result.stdout.strip()
            if not secret:
                raise PermissionError("Keychain item exists but password is empty.")
            return secret.encode("utf-8")
        except subprocess.CalledProcessError as e:
            raise PermissionError(
                f"Failed to read keychain item: {e.stderr.strip()}"
            )

def seal_master_secret(
    master_secret: bytes,
    service_name: str,
    account_name: str,
    updatable: bool = False
) -> None:
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
        tmp.write(master_secret.decode("utf-8") if isinstance(master_secret, bytes) else master_secret)
        tmp_path = tmp.name

    try:
        cmd = [
            "security", "add-generic-password",
            "-s", service_name,
            "-a", account_name,
            "-w", tmp_path,
            "-T", "/usr/bin/security"
        ]
        if updatable:
            cmd.append("-U")

        subprocess.run(cmd, check=True)
    finally:
        os.unlink(tmp_path)
