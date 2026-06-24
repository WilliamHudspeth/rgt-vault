"""Property-based / fuzz tests (Hypothesis).

Targets the parsing and cryptographic surfaces that attacker-controlled or
corrupted bytes can reach: AES-256-GCM decrypt, DEK unwrap, and import_vault.
The invariants: never return wrong plaintext, never raise an *unexpected*
exception type, never crash the interpreter.
"""

import os
import tempfile

import pytest
from cryptography.exceptions import InvalidTag
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from rgt_vault.crypto import decrypt, encrypt
from rgt_vault.exceptions import DecryptionError, ValidationError
from rgt_vault.keychain import AES256GCMWrapper
from rgt_vault.vault import VaultManager

# --- AES-256-GCM (crypto.encrypt/decrypt) ----------------------------------


@settings(max_examples=200, deadline=None)
@given(data=st.binary(min_size=0, max_size=4096), aad=st.binary(max_size=256))
def test_encrypt_decrypt_roundtrip(data, aad):
    key = os.urandom(32)
    assert decrypt(encrypt(data, key, aad), key, aad) == data


@settings(max_examples=200, deadline=None)
@given(token=st.binary(max_size=80), aad=st.binary(max_size=64))
def test_decrypt_arbitrary_bytes_never_returns_plaintext(token, aad):
    """Random bytes must raise DecryptionError, never silently authenticate.

    The public crypto.decrypt entry point is contracted to raise
    :class:`DecryptionError` (a ``VaultError``) for *any* failure mode so
    callers can't accidentally distinguish "bad AAD" from "wrong key" via the
    exception type. AES256GCMWrapper.unwrap is the low-level internal helper
    and still raises ``InvalidTag``; that path is exercised separately.
    """
    key = os.urandom(32)
    with pytest.raises(DecryptionError):
        decrypt(token, key, aad)


@settings(max_examples=200, deadline=None)
@given(data=st.binary(max_size=512), aad=st.binary(max_size=64), other=st.binary(max_size=64))
def test_decrypt_rejects_wrong_aad(data, aad, other):
    if aad == other:
        return
    key = os.urandom(32)
    ct = encrypt(data, key, aad)
    with pytest.raises(DecryptionError):
        decrypt(ct, key, other)


@settings(max_examples=100, deadline=None)
@given(data=st.binary(max_size=512), aad=st.binary(max_size=64))
def test_decrypt_rejects_wrong_key(data, aad):
    ct = encrypt(data, os.urandom(32), aad)
    with pytest.raises(DecryptionError):
        decrypt(ct, os.urandom(32), aad)


# --- DEK unwrap (AES256GCMWrapper.unwrap) ----------------------------------


@settings(max_examples=150, deadline=None)
@given(blob=st.binary(max_size=128))
def test_unwrap_arbitrary_blob_raises(blob):
    wrapper = AES256GCMWrapper()
    kek = os.urandom(32)
    nonce = os.urandom(12)
    with pytest.raises((ValueError, InvalidTag)):
        wrapper.unwrap(blob, kek, nonce, b"aad")


# --- import_vault (untrusted payload parsing) ------------------------------


@pytest.fixture(scope="module")
def fuzz_vault():
    # Build once: VaultManager runs Argon2id (256 MB) at init, too costly per example.
    class _Bytes:
        def get_secret(self):
            return b"\x07" * 32

    with tempfile.TemporaryDirectory() as tmp:
        yield VaultManager(
            db_path=os.path.join(tmp, "vault.db"),
            policy_yaml="rules:\n  - effect: allow\n",
            master_provider=_Bytes(),
        )


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(blob=st.binary(max_size=1024))
def test_import_vault_only_raises_validation(fuzz_vault, blob):
    """Arbitrary bytes into import_vault must fail cleanly, never with an
    unexpected exception (which would indicate an unhandled parse path)."""
    try:
        fuzz_vault.import_vault(blob)
    except (ValidationError, ValueError):
        pass  # expected, controlled failure


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    payload=st.dictionaries(
        keys=st.sampled_from(["secrets", "audit_logs", "honeytokens", "vault_id", "junk"]),
        values=st.recursive(
            st.none() | st.booleans() | st.integers() | st.text(max_size=8),
            lambda c: st.lists(c, max_size=3) | st.dictionaries(st.text(max_size=4), c, max_size=3),
            max_leaves=5,
        ),
        max_size=4,
    )
)
def test_import_data_structured_garbage(fuzz_vault, payload):
    """Structurally-plausible but malformed dicts must raise ValueError, not crash."""
    try:
        fuzz_vault.storage.import_data(payload)
    except (ValueError, ValidationError):
        pass
