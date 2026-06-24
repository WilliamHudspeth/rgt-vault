"""Capability token primitives for the rgt-vault.

This module owns the **wire format** of a capability token and the
abstract verifier hierarchy. The vault's hook layer and the new
``execute_capability()`` path both call into here.

Design notes
============

The original ``CapabilityToken`` (in ``rgt_vault/hook.py``) is a
namespace-scoped, operation-list token. The new format is **action-scoped**:
each token authorizes exactly one capability (e.g. ``github.read_repo``)
plus an optional context-binding dict (e.g. ``{"repo": "org/research"}``)
that constrains which arguments the request may carry. This narrows the
replay window (stolen tokens are useful for fewer calls) and the blast
radius (a stolen token for ``github.read_repo`` cannot be replayed against
``github.write_issue``).

Token shape (v2)::

    {
      "v": 2,                          # token format version
      "agent_id": "research-agent",
      "capability": "github.read_repo",
      "capability_version": 1,         # the schema version of the capability
      "context_bindings": {"repo": "org/research"},
      "exp": 1735689600                # unix seconds
    }

Signed format on the wire::

    base64url(payload_json) + "." + base64url(hmac_or_signature)

Future format versions must continue to use the same wire envelope
("base64.body.signature"); only ``v`` and the verifier dispatch change.
"""

from __future__ import annotations

import abc
import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from rgt_vault.exceptions import ValidationError

# Token format version. Bump when the wire schema changes; verifiers
# dispatch on this value.
TOKEN_FORMAT_VERSION = 2


class TokenError(Exception):
    """Base for all token-verification failures. Never embeds the token."""


class TokenExpiredError(TokenError):
    """The token's ``exp`` is in the past."""


class TokenSignatureError(TokenError):
    """The signature did not verify against the configured key."""


class TokenMalformedError(TokenError):
    """The token envelope or payload is not well-formed."""


class TokenVersionError(TokenError):
    """The token's capability version is not supported by the registry."""


class TokenBindingError(TokenError):
    """The request's arguments violate the token's context bindings."""


@dataclass(frozen=True)
class CapabilityV2Token:
    """A v2 capability token, after signature verification.

    Verifier implementations return instances of this class; the rest
    of the vault (the hook layer, ``execute_capability``) only ever sees
    verified tokens.

    The ``token_id`` field is a server-minted, deterministic identifier
    (sha256 of the canonical payload) so the audit chain can correlate
    individual token uses without ever recording the secret material.
    """

    agent_id: str
    capability: str
    capability_version: int
    context_bindings: Mapping[str, Any] = field(default_factory=dict)
    expires_at: int = 0  # unix seconds
    token_id: str = ""

    def is_expired(self, now: Optional[int] = None) -> bool:
        if self.expires_at <= 0:
            return False
        return (now if now is not None else int(time.time())) > self.expires_at

    def check_context(self, request_context: Mapping[str, Any]) -> None:
        """Raise :class:`TokenBindingError` if ``request_context`` violates
        any binding declared on the token.

        Bindings are interpreted as **equality constraints**: every
        key/value in ``context_bindings`` must appear in
        ``request_context`` with the same value. Extra keys in
        ``request_context`` are allowed (the binding constrains a
        subset, not the whole request).

        A token with no bindings is a free pass on context: any
        arguments to the capability are acceptable.
        """
        if not self.context_bindings:
            return
        for key, expected in self.context_bindings.items():
            if key not in request_context:
                raise TokenBindingError(f"capability {self.capability!r} requires context key {key!r} in the request")
            if request_context[key] != expected:
                raise TokenBindingError(
                    f"capability {self.capability!r} context binding failed "
                    f"for {key!r}: expected {expected!r}, got "
                    f"{request_context[key]!r}"
                )


def _canonical_payload(
    agent_id: str,
    capability: str,
    capability_version: int,
    context_bindings: Mapping[str, Any],
    expires_at: int,
) -> bytes:
    """Build the canonical JSON bytes that get signed.

    Sort keys so two equivalent tokens (same claims, different key order
    in the caller's input) produce the same signature.
    """
    return json.dumps(
        {
            "v": TOKEN_FORMAT_VERSION,
            "agent_id": agent_id,
            "capability": capability,
            "capability_version": capability_version,
            "context_bindings": dict(context_bindings),
            "exp": int(expires_at),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _envelope(payload: bytes, signature: bytes) -> str:
    """Wrap ``payload`` and ``signature`` into the wire string."""
    body = base64.urlsafe_b64encode(payload).rstrip(b"=")
    sig = base64.urlsafe_b64encode(signature).rstrip(b"=")
    return (body + b"." + sig).decode("ascii")


def _open_envelope(token: str) -> tuple[bytes, bytes]:
    """Reverse of :func:`_envelope`. Raises :class:`TokenMalformedError`."""
    if not isinstance(token, str):
        raise TokenMalformedError("token must be a string")
    parts = token.split(".")
    if len(parts) != 2:
        raise TokenMalformedError("token must be 'payload.signature'")
    body_b64, sig_b64 = parts
    try:
        payload = base64.urlsafe_b64decode(_pad_b64(body_b64))
        sig = base64.urlsafe_b64decode(_pad_b64(sig_b64))
    except Exception as e:  # base64 raises binascii.Error
        raise TokenMalformedError(f"token base64 decode failed: {e}") from e
    if not payload or not sig:
        raise TokenMalformedError("token payload or signature empty")
    return payload, sig


def _pad_b64(s: str) -> str:
    """Restore base64 padding stripped by the envelope format."""
    return s + "=" * (-len(s) % 4)


# ---------------------------------------------------------------------
# Verifier hierarchy
# ---------------------------------------------------------------------


class TokenVerifier(abc.ABC):
    """Abstract signer + verifier for v2 capability tokens.

    The vault holds a single configured verifier; the hook layer and
    ``execute_capability`` both call ``verify()`` on every request.
    Concrete implementations encapsulate the trust anchor (shared
    secret, public key, etc.) so callers never see raw key material.
    """

    @abc.abstractmethod
    def sign(
        self,
        agent_id: str,
        capability: str,
        capability_version: int,
        context_bindings: Optional[Mapping[str, Any]] = None,
        ttl_seconds: int = 60,
    ) -> str:
        """Mint a signed token. Used by the harness / operator tooling."""

    @abc.abstractmethod
    def verify(self, token: str) -> CapabilityV2Token:
        """Verify ``token`` and return its claims. Raise on any failure.

        Implementations MUST:

        * Reject expired tokens with :class:`TokenExpiredError`.
        * Reject signature mismatches with :class:`TokenSignatureError`.
        * Reject malformed envelopes with :class:`TokenMalformedError`.
        * Reject unsupported format versions with :class:`TokenVersionError`.
        """


class HMACTokenVerifier(TokenVerifier):
    """HMAC-SHA256 verifier (v1 implementation).

    The shared secret is the trust anchor: whoever holds it can mint
    tokens for any agent and any capability. The minimum acceptable
    length is 32 bytes (256 bits), matching :class:`TwoFactorHook`.
    """

    def __init__(self, shared_secret: bytes) -> None:
        if not isinstance(shared_secret, (bytes, bytearray)):
            raise ValidationError("shared_secret must be bytes")
        if len(shared_secret) < 32:
            raise ValidationError("shared_secret must be at least 32 bytes of random material")
        self._secret = bytes(shared_secret)

    def sign(
        self,
        agent_id: str,
        capability: str,
        capability_version: int = 1,
        context_bindings: Optional[Mapping[str, Any]] = None,
        ttl_seconds: int = 60,
    ) -> str:
        if ttl_seconds <= 0:
            raise ValidationError("ttl_seconds must be > 0")
        if not isinstance(agent_id, str) or not agent_id:
            raise ValidationError("agent_id is required")
        if not isinstance(capability, str) or not capability:
            raise ValidationError("capability is required")
        if not isinstance(capability_version, int) or capability_version < 1:
            raise ValidationError("capability_version must be a positive int")

        now = int(time.time())
        payload = _canonical_payload(
            agent_id=agent_id,
            capability=capability,
            capability_version=capability_version,
            context_bindings=context_bindings or {},
            expires_at=now + ttl_seconds,
        )
        sig = hmac.new(self._secret, payload, hashlib.sha256).digest()
        return _envelope(payload, sig)

    def verify(self, token: str) -> CapabilityV2Token:
        payload, sig = _open_envelope(token)
        expected = hmac.new(self._secret, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, sig):
            raise TokenSignatureError("token signature did not verify")

        try:
            data = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise TokenMalformedError(f"token payload not valid JSON: {e}")

        if not isinstance(data, dict):
            raise TokenMalformedError("token payload must be a JSON object")
        version = int(data.get("v", 0))
        if version != TOKEN_FORMAT_VERSION:
            raise TokenVersionError(
                f"token format version {version} not supported; this verifier only handles v{TOKEN_FORMAT_VERSION}"
            )

        try:
            agent_id = str(data["agent_id"])
            capability = str(data["capability"])
            capability_version = int(data["capability_version"])
            context_bindings = data.get("context_bindings") or {}
            expires_at = int(data["exp"])
        except (KeyError, TypeError, ValueError) as e:
            raise TokenMalformedError(f"token payload missing field: {e}")

        if not isinstance(context_bindings, dict):
            raise TokenMalformedError("context_bindings must be a JSON object")

        # token_id is the sha256 of the canonical payload, so it's
        # deterministic for a given signed token and safe to log.
        token_id = hashlib.sha256(payload).hexdigest()[:16]

        result = CapabilityV2Token(
            agent_id=agent_id,
            capability=capability,
            capability_version=capability_version,
            context_bindings=dict(context_bindings),
            expires_at=expires_at,
            token_id=token_id,
        )
        if result.is_expired():
            raise TokenExpiredError(f"token for {capability!r} expired at {expires_at}")
        return result


class Ed25519TokenVerifier(TokenVerifier):
    """Stub verifier for Ed25519 capability tokens.

    Architectural readiness only: this class exists so callers (and
    future PRs) can wire Ed25519 verification without changing the
    ``execute_capability`` / hook call sites. The v1 deployment ships
    with :class:`HMACTokenVerifier`; Ed25519 is a future-work item per
    the ROADMAP. We deliberately do not pull in ``cryptography``'s
    Ed25519 primitives here -- adding the dependency before the
    implementation lands would broaden the supply chain for no gain.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError(
            "Ed25519TokenVerifier is an architectural stub; use HMACTokenVerifier for the v1 deployment."
        )

    def sign(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
        raise NotImplementedError

    def verify(self, token: str) -> CapabilityV2Token:  # pragma: no cover
        raise NotImplementedError


__all__ = [
    "TOKEN_FORMAT_VERSION",
    "CapabilityV2Token",
    "TokenVerifier",
    "HMACTokenVerifier",
    "Ed25519TokenVerifier",
    "TokenError",
    "TokenExpiredError",
    "TokenSignatureError",
    "TokenMalformedError",
    "TokenVersionError",
    "TokenBindingError",
]
