"""Email address verification via single-use CSPRNG tokens.

Implements ASVS 1.2.3 / RGT-392: semantic email validation requires
proof of ownership via a cryptographically random, single-use,
time-limited token rather than trusting syntactic checks alone.

Token properties
----------------
- Generated with ``secrets.token_urlsafe(32)``, yielding ≥ 43 URL-safe
  characters of CSPRNG entropy (256 bits).
- Verified with ``hmac.compare_digest`` to prevent timing-oracle attacks.
- Expires after ``ttl_seconds`` (default 8 hours = 28800 s).
- Single-use: callers are responsible for deleting the stored token after
  a successful verification so it cannot be replayed.

Usage
-----
    import time
    from rgt_vault.email_verification import generate_token, verify_token, is_valid_email_syntax

    # Registration flow
    if not is_valid_email_syntax(email):
        raise ValueError("invalid email")
    token, expires_at = generate_token()
    # persist (token, expires_at) bound to email in your store …
    # send token to the user's inbox …

    # Verification flow (on callback)
    try:
        verify_token(submitted_token, stored_token, expires_at)
        # success — delete (token, expires_at) from store (single-use)
    except EmailVerificationError as exc:
        # reject
"""

from __future__ import annotations

import hmac
import re
import secrets
import time


_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
    re.ASCII,
)

_MIN_TOKEN_BYTES = 32
_DEFAULT_TTL = 8 * 3600  # 8 hours in seconds


class EmailVerificationError(Exception):
    """Raised when a submitted token is invalid, expired, or mismatched."""


def is_valid_email_syntax(email: str) -> bool:
    """Return True if *email* passes basic syntactic checks.

    This is a lightweight allowlist filter (RFC 5321 simplified).
    It is intentionally conservative: it rejects unusual-but-valid
    addresses rather than risking injection via exotic syntax.
    """
    if not isinstance(email, str):
        return False
    if len(email) > 254:
        return False
    if ".." in email:
        return False
    return bool(_EMAIL_RE.match(email))


def generate_token(ttl_seconds: int = _DEFAULT_TTL) -> tuple[str, float]:
    """Mint a single-use CSPRNG verification token.

    Returns ``(token, expires_at)`` where ``expires_at`` is a POSIX
    timestamp (float).  Store both values alongside the email address;
    pass them to :func:`verify_token` on callback.
    """
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be > 0")
    token = secrets.token_urlsafe(_MIN_TOKEN_BYTES)
    expires_at = time.time() + ttl_seconds
    return token, expires_at


def verify_token(
    submitted: str,
    stored: str,
    expires_at: float,
    *,
    now: float | None = None,
) -> None:
    """Verify *submitted* against the stored token and expiry.

    Raises :class:`EmailVerificationError` on any failure (expired,
    mismatch, or invalid type).  On success, the caller MUST delete
    ``(stored, expires_at)`` from their store to prevent replay.

    ``now`` is injectable for testing; defaults to ``time.time()``.
    """
    current = now if now is not None else time.time()

    if not isinstance(submitted, str) or not isinstance(stored, str):
        raise EmailVerificationError("Token must be a string.")

    if current > expires_at:
        raise EmailVerificationError("Verification token has expired.")

    submitted_bytes = submitted.encode("utf-8")
    stored_bytes = stored.encode("utf-8")
    if len(submitted_bytes) != len(stored_bytes) or not hmac.compare_digest(submitted_bytes, stored_bytes):
        raise EmailVerificationError("Verification token is invalid.")


__all__ = [
    "EmailVerificationError",
    "is_valid_email_syntax",
    "generate_token",
    "verify_token",
]
