"""Capability token types and verification for rgt-vault.

This module defines the token model (``CapabilityV2Token``), the
verifier interface (``TokenVerifier``), and two implementations:

- **HMACTokenVerifier** (v0.3): symmetric HMAC-SHA256 over a
  compact JWS-ish envelope. Simple, no new dependencies, suitable
  for single-vault deployments where the issuer and verifier share
  a secret.
- **Ed25519TokenVerifier** (v0.4 stub): asymmetric Ed25519 per
  ADR-0001. Raised ``NotImplementedError`` until the per-vault
  signing key is plumbed into the key hierarchy.

The wire format is::

    base64url(json_payload).base64url(hmac_signature)

where ``json_payload`` is a canonical JSON serialisation of the
``CapabilityV2Token`` fields.

Usage (v0.3)::

    verifier = HMACTokenVerifier(b"a-32-byte-secret...")
    token = CapabilityV2Token(
        agent_id="research-agent",
        capability="github.read_repo",
        capability_version=1,
        context_bindings={"repo": "org/research"},
        expires_at=int(time.time()) + 300,
        token_id=str(uuid4()),
        issued_at=int(time.time()),
    )
    envelope = verifier.sign(token)
    decoded = verifier.verify(envelope)
"""

import base64
import json
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac

from rgt_vault.exceptions import (
    VaultError,
    TokenError,
    TokenExpiredError,
    TokenSignatureError,
    TokenMalformedError,
    TokenVersionError,
    TokenBindingError,
)


# ---------------------------------------------------------------------------
# Token data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityV2Token:
    """A signed capability token for v0.3+.

    Every field is required. The dataclass is frozen so callers cannot
    mutate a verified token after the verifier returns it.
    """

    agent_id: str
    capability: str
    capability_version: int
    context_bindings: Dict[str, str]
    expires_at: int            # unix seconds
    token_id: str              # for replay protection (UUID4)
    issued_at: int             # unix seconds

    def to_json(self) -> str:
        """Canonical JSON representation (sorted keys, no whitespace)."""
        return json.dumps(
            {
                "v": 2,
                "agent_id": self.agent_id,
                "capability": self.capability,
                "capability_version": self.capability_version,
                "context_bindings": self.context_bindings,
                "exp": self.expires_at,
                "iat": self.issued_at,
                "jti": self.token_id,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, payload: str) -> "CapabilityV2Token":
        """Parse a JSON string back into a token (no signature check)."""
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as e:
            raise TokenMalformedError(f"Invalid token JSON: {e}") from e

        version = data.get("v")
        if version != 2:
            raise TokenVersionError(
                f"Unsupported token version {version!r}; expected 2"
            )

        try:
            return cls(
                agent_id=data["agent_id"],
                capability=data["capability"],
                capability_version=data["capability_version"],
                context_bindings=data.get("context_bindings", {}),
                expires_at=data["exp"],
                token_id=data["jti"],
                issued_at=data["iat"],
            )
        except KeyError as e:
            raise TokenMalformedError(f"Missing required field: {e}") from e
        except (TypeError, ValueError) as e:
            raise TokenMalformedError(f"Invalid field value: {e}") from e


# ---------------------------------------------------------------------------
# Verifier interface
# ---------------------------------------------------------------------------


class TokenVerifier(ABC):
    """Abstract base for token signers and verifiers."""

    @abstractmethod
    def sign(self, token: CapabilityV2Token) -> bytes:
        """Produce a signed envelope from a ``CapabilityV2Token``."""
        ...

    @abstractmethod
    def verify(self, envelope: bytes) -> CapabilityV2Token:
        """Decode and verify an envelope, returning the validated token.

        Raises ``TokenError`` on any failure (expired, bad sig,
        malformed).
        """
        ...


# ---------------------------------------------------------------------------
# HMAC-SHA256 verifier (v0.3)
# ---------------------------------------------------------------------------


class HMACTokenVerifier(TokenVerifier):
    """Symmetric HMAC-SHA256 token signer/verifier.

    Uses a shared 32-byte (minimum) secret. The envelope format is::

        base64url(json_payload).base64url(h签名ature)

    **Security note:** this is a symmetric-key scheme. Every caller
    who knows the shared secret can forge tokens. For single-vault
    deployments where the vault itself generates and consumes
    tokens, this is acceptable. For multi-vault trust, use
    ``Ed25519TokenVerifier`` (v0.4+).
    """

    _MIN_SECRET_LENGTH = 32

    def __init__(self, secret: bytes) -> None:
        if len(secret) < self._MIN_SECRET_LENGTH:
            raise TokenMalformedError(
                f"HMAC secret must be at least {self._MIN_SECRET_LENGTH} bytes; "
                f"got {len(secret)}"
            )
        self._secret = secret

    def sign(self, token: CapabilityV2Token) -> bytes:
        payload = token.to_json()
        payload_bytes = payload.encode("utf-8")
        sig = self._hmac(payload_bytes)
        return self._encode(payload_bytes, sig)

    def verify(self, envelope: bytes) -> CapabilityV2Token:
        try:
            payload_b64, sig_b64 = envelope.rsplit(b".", 1)
            payload = base64.urlsafe_b64decode(payload_b64 + b"==")
            sig = base64.urlsafe_b64decode(sig_b64 + b"==")
        except (ValueError, base64.binascii.Error) as e:
            raise TokenMalformedError(f"Invalid envelope encoding: {e}") from e

        # Verify signature before parsing to avoid timing oracle on payload
        expected = self._hmac(payload)
        if not _constant_time_compare(sig, expected):
            raise TokenSignatureError("Token signature mismatch")

        token = CapabilityV2Token.from_json(payload.decode("utf-8"))

        # Structural checks (before time-based checks)
        if token.expires_at <= token.issued_at:
            raise TokenMalformedError(
                f"expires_at ({token.expires_at}) must be after issued_at "
                f"({token.issued_at})"
            )

        # Expiry check
        now = int(time.time())
        if token.expires_at <= now:
            raise TokenExpiredError(
                f"Token expired at {token.expires_at} (now={now})"
            )
        if token.issued_at > now:
            raise TokenMalformedError(
                f"Token issued_at ({token.issued_at}) is in the future (now={now})"
            )
        if token.expires_at <= token.issued_at:
            raise TokenMalformedError(
                f"expires_at ({token.expires_at}) must be after issued_at "
                f"({token.issued_at})"
            )

        return token

    def _hmac(self, payload: bytes) -> bytes:
        h = hmac.HMAC(self._secret, hashes.SHA256())
        h.update(payload)
        return h.finalize()

    @staticmethod
    def _encode(payload: bytes, sig: bytes) -> bytes:
        return (
            base64.urlsafe_b64encode(payload).rstrip(b"=") + b"." +
            base64.urlsafe_b64encode(sig).rstrip(b"=")
        )


# ---------------------------------------------------------------------------
# Ed25519 verifier (v0.4 stub)
# ---------------------------------------------------------------------------


class Ed25519TokenVerifier(TokenVerifier):
    """Asymmetric Ed25519 token signer/verifier (v0.4 placeholder).

    Raises ``NotImplementedError``. The class exists so that callers
    can reference it and the HMAC->Ed25519 migration path is clearly
    scoped (one subclass swap). A real implementation will use
    ``cryptography.hazmat.primitives.asymmetric.ed25519`` and a
    per-vault signing key persisted in ``keychain.json``.
    """

    def sign(self, token: CapabilityV2Token) -> bytes:
        raise NotImplementedError(
            "Ed25519TokenVerifier is a v0.4 placeholder"
        )

    def verify(self, envelope: bytes) -> CapabilityV2Token:
        raise NotImplementedError(
            "Ed25519TokenVerifier is a v0.4 placeholder"
        )


# ---------------------------------------------------------------------------
# Context binding helpers
# ---------------------------------------------------------------------------


def check_context(
    token: CapabilityV2Token,
    request_context: Mapping[str, str],
) -> None:
    """Verify that every context binding in *token* is present and
    matches in *request_context*.

    Raises ``TokenBindingError`` if any binding key is missing from the
    request, or if the values differ. Only the keys declared in
    ``token.context_bindings`` are checked — extra keys in the request
    are ignored (the token is the authority on what is required).
    """
    for key, expected_value in token.context_bindings.items():
        actual_value = request_context.get(key)
        if actual_value is None:
            raise TokenBindingError(
                f"Missing required context binding: {key!r}"
            )
        if actual_value != expected_value:
            raise TokenBindingError(
                f"Context binding mismatch for {key!r}: "
                f"expected {expected_value!r}, got {actual_value!r}"
            )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing side-channels."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
