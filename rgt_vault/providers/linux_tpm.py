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

        # The PCR list is sealed into the policy at seal time; we need to
        # assert the same list at unseal time or the policy check fails.
        # ``seal_master_secret`` writes it next to the blobs as
        # ``<basename>.pcrs`` -- one line, space-separated integers.
        # Fall back to [0, 7] for backward compat with blobs sealed before
        # this file was added, or if the file is unreadable for any
        # reason (e.g. wrong permissions, race with another process).
        pcr_file = self.private_path.with_suffix(".pcrs")
        self.pcr_list = [0, 7]
        if pcr_file.is_file():
            try:
                self.pcr_list = [
                    int(x) for x in pcr_file.read_text().strip().split()
                ]
                if not self.pcr_list:
                    self.pcr_list = [0, 7]
            except (OSError, ValueError):
                # Unreadable / malformed -- fall back rather than crash.
                # The worst case is a PCR-policy mismatch at unseal time,
                # which fails closed with a clear TPM error.
                self.pcr_list = [0, 7]

    def get_secret(self) -> bytes:
        # P0-1 audit fix: create the unseal-target file in the same directory
        # as the sealed blobs (which should be 0700 -- it contains sealed
        # secret material) with explicit 0600 permissions. The previous code
        # used ``NamedTemporaryFile(delete=False)`` which left the file at
        # the process umask (typically 022, giving 0644 world-readable),
        # exposing the plaintext master secret to any local user between
        # ``tpm2_unseal`` writing it and Python reading it.
        tmp_fd, out_path = tempfile.mkstemp(
            prefix=".rgt-unseal-",
            dir=str(self.private_path.parent),
        )
        os.close(tmp_fd)
        try:
            os.chmod(out_path, 0o600)
        except OSError:
            # If we can't chmod (e.g. mounted FS without chmod support),
            # refuse to continue -- the alternative is silently writing
            # the master secret to a world-readable file.
            os.unlink(out_path)
            raise TPMError(
                f"Could not set 0600 permissions on {out_path}; refusing to "
                "unseal master secret to a file with permissive mode."
            )

        # Use the private path's parent as scratch for the primary and
        # loaded-child context files; ensures cleanup is simple.
        scratch_dir = self.private_path.parent
        ctx_path = str(scratch_dir / f".{os.getpid()}_child.ctx")
        primary_ctx = str(scratch_dir / f".{os.getpid()}_primary.ctx")
        session_path = str(scratch_dir / f".{os.getpid()}_session.ctx")

        try:
            # Modern tpm2-tools requires an explicit primary for both
            # tpm2_load and the parent handle; the legacy 0x40000001
            # transient handle is no longer supported.
            # We deliberately do NOT pass -T here: tpm2-tools' built-in
            # TCTI auto-discovery is more reliable than the explicit
            # -T /dev/tpmrm0 form when invoked via subprocess.
            _run_tpm_cmd([
                "tpm2_createprimary",
                "-C", "o",
                "-G", "rsa",
                "-c", primary_ctx,
            ])

            _run_tpm_cmd([
                "tpm2_load",
                "-C", primary_ctx,
                "-u", str(self.public_path),
                "-r", str(self.private_path),
                "-c", ctx_path,
            ])

            # Build a policy session explicitly. The shorthand
            # `tpm2_unseal -p pcr:sha256:0,7` is unreliable in modern
            # tpm2-tools when more than one PCR is listed; the explicit
            # session path is the supported pattern.
            pcr_spec = "+".join(f"{self.pcr_bank}:{p}" for p in self.pcr_list)
            _run_tpm_cmd([
                "tpm2_startauthsession",
                "--policy-session",
                "-S", session_path,
            ])
            _run_tpm_cmd([
                "tpm2_policypcr",
                "-S", session_path,
                "-l", pcr_spec,
            ])
            _run_tpm_cmd([
                "tpm2_unseal",
                "-c", ctx_path,
                "-o", out_path,
                "-p", f"session:{session_path}",
            ])

            with open(out_path, "rb") as f:
                secret = f.read()

            if not secret:
                raise TPMError("Unsealed empty secret \u2013 PCR policy may have rejected release.")

            return secret

        finally:
            for tmp_file in (out_path, ctx_path, primary_ctx, session_path):
                try:
                    os.unlink(tmp_file)
                except OSError:
                    pass
            for handle in (ctx_path, primary_ctx, session_path):
                try:
                    _run_tpm_cmd([
                        "tpm2_flushcontext",
                        "-c", handle,
                    ])
                except TPMError:
                    pass


def seal_master_secret(
    master_secret: bytes,
    output_dir: str,
    pcr_list: List[int] = [0, 7],
    pcr_bank: str = "sha256"
) -> tuple[Path, Path]:
    """Seal a master secret to a PCR policy.

    Creates a transient RSA primary under the owner hierarchy, then seals
    the secret as a child key bound to the PCR policy. The transient
    primary is flushed before returning; only the .priv / .pub blobs need
    to be persisted.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    private_path = out_dir / "master_secret.priv"
    public_path = out_dir / "master_secret.pub"

    # P0-1 (seal-side) audit fix: use mkstemp + chmod 0600 to ensure the
    # plaintext master secret never sits on disk with permissive mode.
    # ``tpm2_create -i <file>`` reads the secret from this file.
    sec_fd, secret_file = tempfile.mkstemp(
        prefix=".rgt-seal-",
        dir=str(out_dir),
    )
    try:
        os.write(sec_fd, master_secret)
    finally:
        os.close(sec_fd)
    try:
        os.chmod(secret_file, 0o600)
    except OSError as e:
        os.unlink(secret_file)
        raise TPMError(f"Could not set 0600 on seal scratch file: {e}")

    primary_ctx = str(out_dir / "primary.ctx")
    try:
        policy_digest_path = str(out_dir / "policy.digest")
        # tpm2_createpolicy expects PCR list items to be '+'-separated
        # (e.g. "sha256:0+sha256:7"); the older tpm2_unseal/load tools
        # accept the comma form, so this is the only place that needs '+'.
        pcr_spec = "+".join(f"{pcr_bank}:{p}" for p in pcr_list)

        _run_tpm_cmd([
            "tpm2_createpolicy",
            "--policy-pcr",
            "-l", pcr_spec,
            "-L", policy_digest_path,
        ])

        # Create a transient RSA primary under the owner hierarchy. Modern
        # tpm2-tools (>=5.0) refuses the legacy transient handle 0x40000001,
        # so we go through an explicit primary context instead.
        _run_tpm_cmd([
            "tpm2_createprimary",
            "-C", "o",
            "-G", "rsa",
            "-c", primary_ctx,
        ])

        _run_tpm_cmd([
            "tpm2_create",
            "-C", primary_ctx,
            "-i", secret_file,
            "-u", str(public_path),
            "-r", str(private_path),
            "-L", policy_digest_path,
            "-g", "sha256",
        ])

        # Persist the PCR list next to the blobs so the unseal code can
        # reconstruct the same policy. Without this, the provider would
        # have to guess (and could guess wrong).
        pcr_record = private_path.with_suffix(".pcrs")
        pcr_record.write_text(" ".join(str(p) for p in pcr_list) + "\n")

        try:
            os.unlink(policy_digest_path)
        except OSError:
            pass

        return private_path, public_path

    finally:
        for path in (secret_file, primary_ctx):
            try:
                os.unlink(path)
            except OSError:
                pass
        # Flush the primary from TPM memory.
        try:
            subprocess.run(
                ["tpm2_flushcontext", "-t"],
                capture_output=True, check=False,
            )
        except FileNotFoundError:
            pass
