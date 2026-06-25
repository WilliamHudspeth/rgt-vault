"""Tests for the RFC 6238 TOTP second-factor module."""

import time

import pytest
from rgt_vault import totp


def test_generate_secret_is_valid_base32_and_unique():
    a = totp.generate_secret()
    b = totp.generate_secret()
    assert a != b
    # Decodes without error (padding handled internally).
    totp._b32decode(a)


def test_rfc6238_sha1_reference_vector():
    # RFC 6238 Appendix B test vector: ASCII secret "12345678901234567890",
    # base32-encoded, SHA1, 8 digits, at T=59 -> 94287082.
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    code = totp.generate(secret, timestamp=59, digits=8)
    assert code == "94287082"


def test_generate_and_verify_roundtrip():
    secret = totp.generate_secret()
    now = time.time()
    code = totp.generate(secret, timestamp=now)
    assert totp.verify(secret, code, timestamp=now)


def test_verify_rejects_wrong_code():
    secret = totp.generate_secret()
    now = time.time()
    assert not totp.verify(secret, "000000", timestamp=now) or \
        totp.generate(secret, timestamp=now) == "000000"


def test_verify_allows_one_step_of_skew():
    secret = totp.generate_secret()
    now = 1_000_000.0
    prev_code = totp.generate(secret, timestamp=now - 30)
    next_code = totp.generate(secret, timestamp=now + 30)
    assert totp.verify(secret, prev_code, timestamp=now, window=1)
    assert totp.verify(secret, next_code, timestamp=now, window=1)


def test_verify_rejects_outside_window():
    secret = totp.generate_secret()
    now = 1_000_000.0
    far_code = totp.generate(secret, timestamp=now - 300)
    assert not totp.verify(secret, far_code, timestamp=now, window=1)


@pytest.mark.parametrize("bad", ["", "   ", "abcdef", "12ab56", None])
def test_verify_rejects_malformed_input(bad):
    secret = totp.generate_secret()
    assert totp.verify(secret, bad) is False


def test_replay_guarded_verifier_rejects_reuse():
    secret = totp.generate_secret()
    v = totp.ReplayGuardedVerifier(secret)
    now = 1_000_000.0
    code = totp.generate(secret, timestamp=now)
    # First use accepts; immediate reuse of the same code is rejected.
    assert v(code, timestamp=now) is True
    assert v(code, timestamp=now) is False
    # A fresh code from a later step is accepted.
    later = now + 60
    assert v(totp.generate(secret, timestamp=later), timestamp=later) is True


def test_replay_guarded_verifier_rejects_older_counter():
    secret = totp.generate_secret()
    v = totp.ReplayGuardedVerifier(secret)
    now = 2_000_000.0
    # Consume the current step, then a code from a prior step must be rejected.
    assert v(totp.generate(secret, timestamp=now), timestamp=now) is True
    old = totp.generate(secret, timestamp=now - 60)
    assert v(old, timestamp=now) is False


def test_provisioning_uri_shape():
    secret = totp.generate_secret()
    uri = totp.provisioning_uri(secret, "alice@example.com", issuer="rgt-vault")
    assert uri.startswith("otpauth://totp/rgt-vault:alice%40example.com?")
    assert f"secret={secret}" in uri
    assert "issuer=rgt-vault" in uri
    assert "period=30" in uri and "digits=6" in uri
