"""TPM provider tests that run against a real /dev/tpmrm0.

Skipped automatically if the device isn't readable in the current
environment. The test seals and unseals a master secret, then exercises
the full VaultManager stack (set / execute / rotate_dek) on top of it.

Run with:
    sg tss -c "pytest tests/test_tpm_live.py -v"
"""

import os
import shutil
import tempfile

import pytest

from rgt_vault.providers.linux_tpm import (
    LinuxTPMProvider,
    seal_master_secret,
)
from rgt_vault.vault import VaultManager


def _tpm_available():
    """Return True iff the user can read /dev/tpmrm0."""
    try:
        return os.access("/dev/tpmrm0", os.R_OK | os.W_OK)
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _tpm_available(),
    reason="/dev/tpmrm0 not readable in this environment (run as a member of the 'tss' group)",
)


@pytest.fixture
def tpm_workdir():
    d = tempfile.mkdtemp(prefix="rgt-tpm-test-")
    yield d
    shutil.rmtree(d, ignore_errors=True)


def test_seal_unseal_roundtrip(tpm_workdir):
    """Seal a 32-byte secret under PCR 0+7 policy, then unseal and verify
    exact byte equality."""
    secret = os.urandom(32)
    priv, pub = seal_master_secret(secret, tpm_workdir)
    assert priv.exists() and pub.exists()
    assert (priv.parent / f"{priv.name}.pcrs").exists() or (priv.with_suffix(".pcrs")).exists()

    provider = LinuxTPMProvider(str(priv), str(pub))
    unsealed = provider.get_secret()
    assert unsealed == secret


def test_pcr_list_persisted(tpm_workdir):
    """The provider reads the PCR list from a sidecar file written at
    seal time, so the unseal policy matches the seal policy exactly."""
    secret = os.urandom(32)
    priv, pub = seal_master_secret(secret, tpm_workdir, pcr_list=[0, 7])

    provider = LinuxTPMProvider(str(priv), str(pub))
    assert provider.pcr_list == [0, 7]
    # Unseal must succeed end-to-end.
    assert provider.get_secret() == secret


def test_vaultmanager_set_get_via_tpm(tpm_workdir):
    """A full VaultManager.set_secret() / .execute() round-trip with the
    master secret held in a real TPM. Verifies that Argon2id + AES-256-GCM
    + PCR-sealed unseal all play together."""
    secret = os.urandom(32)
    priv, pub = seal_master_secret(secret, tpm_workdir)

    db = os.path.join(tpm_workdir, "vault.db")
    provider = LinuxTPMProvider(str(priv), str(pub))
    policy = "rules:\n  - effect: allow\n    agent: t\n    namespace: '*'\n    action: '*'\n"
    vault = VaultManager(
        db_path=db,
        policy_yaml=policy,
        master_provider=provider,
    )
    vault.set_secret("KEY", "value", namespace="demo", agent="t")
    out = vault.execute("t", "demo", "use", "KEY", lambda b: bytes(b))
    assert out == b"value"
    assert vault.verify_audit_chain() is True


def test_rotate_dek_via_tpm(tpm_workdir):
    """rotate_dek() must work end-to-end against the TPM provider --
    the new DEK is generated and re-encrypted under the same TPM-sealed
    master secret; existing secrets must remain readable."""
    secret = os.urandom(32)
    priv, pub = seal_master_secret(secret, tpm_workdir)
    provider = LinuxTPMProvider(str(priv), str(pub))

    db = os.path.join(tpm_workdir, "vault.db")
    policy = "rules:\n  - effect: allow\n    agent: t\n    namespace: '*'\n    action: '*'\n"
    vault = VaultManager(
        db_path=db,
        policy_yaml=policy,
        master_provider=provider,
    )
    vault.set_secret("K1", "v1", namespace="ns", agent="t")
    vault.rotate_dek()
    out = vault.execute("t", "ns", "use", "K1", lambda b: bytes(b))
    assert out == b"v1"
