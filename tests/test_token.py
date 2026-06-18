"""Tests for ``rgt_vault.token``.

Covers token types, HMAC sign/verify, expiry, malformed input,
context binding checks, and the Ed25519 stub.
"""

import time
import uuid
from dataclasses import FrozenInstanceError

import pytest

from rgt_vault.exceptions import (
    TokenExpiredError,
    TokenSignatureError,
    TokenMalformedError,
    TokenVersionError,
    TokenBindingError,
)
from rgt_vault.token import (
    HMACTokenVerifier,
    Ed25519TokenVerifier,
    CapabilityV2Token,
    check_context,
)


_SECRET = b"a" * 32


def _make_token(**overrides) -> CapabilityV2Token:
    now = int(time.time())
    defaults = dict(
        agent_id="test-agent",
        capability="secrets.echo",
        capability_version=1,
        context_bindings={"repo": "org/repo"},
        expires_at=now + 300,
        token_id=str(uuid.uuid4()),
        issued_at=now,
    )
    defaults.update(overrides)
    return CapabilityV2Token(**defaults)


# ------------------------------------------------------------------
# Token creation / frozen
# ------------------------------------------------------------------


def test_token_is_frozen():
    t = _make_token()
    with pytest.raises(FrozenInstanceError):
        t.agent_id = "other-agent"


def test_token_to_json_roundtrip():
    t = _make_token()
    json_str = t.to_json()
    t2 = CapabilityV2Token.from_json(json_str)
    assert t == t2


def test_token_from_json_missing_field():
    with pytest.raises(TokenMalformedError):
        CapabilityV2Token.from_json('{"v": 2, "agent_id": "x"}')


def test_token_from_json_bad_json():
    with pytest.raises(TokenMalformedError):
        CapabilityV2Token.from_json("not-json")


def test_token_from_json_wrong_version():
    with pytest.raises(TokenVersionError):
        CapabilityV2Token.from_json(
            '{"v": 1, "agent_id": "x", "capability": "c", '
            '"capability_version": 1, "context_bindings": {}, '
            '"exp": 100, "jti": "x", "iat": 50}'
        )


# ------------------------------------------------------------------
# HMAC sign / verify
# ------------------------------------------------------------------


def test_hmac_sign_verify_roundtrip():
    v = HMACTokenVerifier(_SECRET)
    t = _make_token()
    envelope = v.sign(t)
    t2 = v.verify(envelope)
    assert t == t2


def test_hmac_tampered_signature():
    v = HMACTokenVerifier(_SECRET)
    t = _make_token()
    envelope = bytearray(v.sign(t))
    envelope[-1] ^= 0xFF  # flip a bit in the sig
    with pytest.raises(TokenSignatureError):
        v.verify(bytes(envelope))


def test_hmac_tampered_payload():
    v = HMACTokenVerifier(_SECRET)
    t = _make_token()
    envelope = bytearray(v.sign(t))
    # Find the dot separator and modify a payload byte
    dot = envelope.rfind(b".")
    envelope[dot // 2] ^= 0x01
    with pytest.raises(TokenSignatureError):
        v.verify(bytes(envelope))


def test_hmac_expired_token():
    v = HMACTokenVerifier(_SECRET)
    t = _make_token(expires_at=int(time.time()) - 10, issued_at=int(time.time()) - 60)
    envelope = v.sign(t)
    with pytest.raises(TokenExpiredError):
        v.verify(envelope)


def test_hmac_future_iat():
    v = HMACTokenVerifier(_SECRET)
    t = _make_token(issued_at=int(time.time()) + 9999)
    envelope = v.sign(t)
    with pytest.raises(TokenMalformedError):
        v.verify(envelope)


def test_hmac_exp_before_iat():
    v = HMACTokenVerifier(_SECRET)
    t = _make_token(expires_at=100, issued_at=200)
    envelope = v.sign(t)
    with pytest.raises(TokenMalformedError):
        v.verify(envelope)


def test_hmac_short_secret():
    with pytest.raises(TokenMalformedError):
        HMACTokenVerifier(b"tooshort")


def test_hmac_non_bytes_envelope():
    v = HMACTokenVerifier(_SECRET)
    with pytest.raises(TokenMalformedError):
        v.verify(b"no-dot-separator")


def test_hmac_non_json_envelope():
    v = HMACTokenVerifier(_SECRET)
    # Envelope with invalid base64 characters (not valid base64url)
    with pytest.raises(TokenMalformedError):
        v.verify(b"!!!invalid-base64!!!.!!!signature!!!")


def test_hmac_different_secrets_dont_cross_verify():
    v1 = HMACTokenVerifier(b"b" * 32)
    v2 = HMACTokenVerifier(b"c" * 32)
    t = _make_token()
    envelope = v1.sign(t)
    with pytest.raises(TokenSignatureError):
        v2.verify(envelope)


# ------------------------------------------------------------------
# Context binding checks
# ------------------------------------------------------------------


def test_check_context_matching():
    t = _make_token(context_bindings={"repo": "org/repo"})
    check_context(t, {"repo": "org/repo"})  # no raise


def test_check_context_missing_key():
    t = _make_token(context_bindings={"repo": "org/repo"})
    with pytest.raises(TokenBindingError):
        check_context(t, {})


def test_check_context_mismatched_value():
    t = _make_token(context_bindings={"repo": "org/repo"})
    with pytest.raises(TokenBindingError):
        check_context(t, {"repo": "wrong/value"})


def test_check_context_empty_bindings():
    t = _make_token(context_bindings={})
    check_context(t, {"anything": "goes"})  # no raise


# ------------------------------------------------------------------
# Ed25519 stub
# ------------------------------------------------------------------


def test_ed25519_sign_raises():
    v = Ed25519TokenVerifier()
    with pytest.raises(NotImplementedError):
        v.sign(_make_token())


def test_ed25519_verify_raises():
    v = Ed25519TokenVerifier()
    with pytest.raises(NotImplementedError):
        v.verify(b"dummy")
