import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from .base import MasterSecretProvider


class TPMError(Exception):
    """Raised when a TPM operation fails."""

def _run_tpm_cmd(args: List[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            cwd=str(cwd) if cwd else None,
            check=False
        )
        if result.returncode != 0:
            raise TPMError(
                f"TPM command failed: {' '.join(args)}\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )
        return result
    except FileNotFoundError:
        raise TPMError(
            "tpm2-tools not found. Please install: sudo apt install tpm2-tools"
        )
    except PermissionError:
        raise TPMError(
            "Permission denied. Ensure you have access to the TPM device "
            "(/dev/tpmrm0) or run with appropriate privileges (e.g., tpm2_* group)."
        )

class LinuxTPMProvider(MasterSecretProvider):
    def __init__(
        self,
        sealed_private_path: str,
        sealed_public_path: str,
        pcr_bank: str = "sha256",
        tpm_device: str = "/dev/tpmrm0"
    ):
        self.private_path = Path(sealed_private_path)
        self.public_path = Path(sealed_public_path)
        self.pcr_bank = pcr_bank
        self.tpm_device = tpm_device

        if not self.private_path.is_file():
            raise FileNotFoundError(f"Sealed private blob not found: {self.private_path}")
        if not self.public_path.is_file():
            raise FileNotFoundError(f"Sealed public blob not found: {self.public_path}")

    def get_secret(self) -> bytes:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_out:
            out_path = tmp_out.name
            
        ctx_path = str(Path(out_path).with_suffix(".ctx"))

        try:
            _run_tpm_cmd([
                "tpm2_load",
                "-T", self.tpm_device,
                "-C", "0x40000001",
                "-u", str(self.public_path),
                "-r", str(self.private_path),
                "-c", ctx_path
            ])

            _run_tpm_cmd([
                "tpm2_unseal",
                "-T", self.tpm_device,
                "-c", ctx_path,
                "-o", out_path,
                "-p", f"pcr:{self.pcr_bank}:0,7"
            ])

            with open(out_path, "rb") as f:
                secret = f.read()

            if not secret:
                raise TPMError("Unsealed empty secret \u2013 PCR policy may have rejected release.")

            return secret

        finally:
            for tmp_file in (out_path, ctx_path):
                try:
                    os.unlink(tmp_file)
                except OSError:
                    pass
            try:
                _run_tpm_cmd([
                    "tpm2_flushcontext",
                    "-T", self.tpm_device,
                    "-c", ctx_path
                ])
            except TPMError:
                pass


def seal_master_secret(
    master_secret: bytes,
    output_dir: str,
    pcr_list: List[int] = [0, 7],
    pcr_bank: str = "sha256"
) -> tuple[Path, Path]:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    private_path = out_dir / "master_secret.priv"
    public_path = out_dir / "master_secret.pub"

    with tempfile.NamedTemporaryFile(delete=False) as tmp_secret:
        tmp_secret.write(master_secret)
        secret_file = tmp_secret.name

    try:
        policy_digest_path = str(out_dir / "policy.digest")
        pcr_spec = ",".join(f"{pcr_bank}:{p}" for p in pcr_list)

        _run_tpm_cmd([
            "tpm2_createpolicy",
            "--policy-pcr",
            "-l", pcr_spec,
            "-L", policy_digest_path
        ])

        _run_tpm_cmd([
            "tpm2_create",
            "-C", "0x40000001",
            "-i", secret_file,
            "-u", str(public_path),
            "-r", str(private_path),
            "-L", policy_digest_path,
            "-g", "sha256",
            "-G", "aes"
        ])

        try:
            os.unlink(policy_digest_path)
        except OSError:
            pass

        return private_path, public_path

    finally:
        os.unlink(secret_file)
