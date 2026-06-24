"""RFC 6238 TOTP — second factor for approving agent secret requests.

Pure standard library (hmac/hashlib/base64); no third-party dependency.
Used by the approval broker: high-sensitivity secrets can require the
operator to enter a valid time-based code before an agent request is
granted.

Typical flow::

    secret = generate_secret()                 # enroll once, show QR/URI
    uri = provisioning_uri(secret, "alice", issuer="rgt-vault")
    ...
    verify(secret, code_from_authenticator_app) -> bool
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DEFAULT_DIGITS = 6
DEFAULT_PERIOD = 30
DEFAULT_ALGORITHM = "SHA1"

_ALGOS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def generate_secret(length: int = 20) -> str:
    """Return a fresh base32 TOTP secret (no padding).

    20 bytes (160 bits) is the RFC 4226 recommended key length for SHA1.
    """
    raw = secrets.token_bytes(length)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _b32decode(secret: str) -> bytes:
    # Authenticator apps present secrets without padding and case-insensitively.
    s = secret.strip().replace(" ", "").upper()
    pad = (-len(s)) % 8
    return base64.b32decode(s + "=" * pad)


def _hotp(key: bytes, counter: int, *, digits: int, algorithm: str) -> str:
    digest_fn = _ALGOS[algorithm]
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, digest_fn).digest()
    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10 ** digits)).zfill(digits)


def generate(
    secret: str,
    *,
    timestamp: float | None = None,
    digits: int = DEFAULT_DIGITS,
    period: int = DEFAULT_PERIOD,
    algorithm: str = DEFAULT_ALGORITHM,
) -> str:
    """Return the TOTP code for ``secret`` at ``timestamp`` (default now)."""
    if timestamp is None:
        timestamp = time.time()
    counter = int(timestamp // period)
    return _hotp(_b32decode(secret), counter, digits=digits, algorithm=algorithm)


def verify(
    secret: str,
    code: str,
    *,
    timestamp: float | None = None,
    digits: int = DEFAULT_DIGITS,
    period: int = DEFAULT_PERIOD,
    algorithm: str = DEFAULT_ALGORITHM,
    window: int = 1,
) -> bool:
    """Constant-time check of ``code`` against ``secret``.

    ``window`` allows +/- that many ``period`` steps of clock skew (default
    one step = 30s either side). Returns False on any malformed input rather
    than raising, so callers can treat it as a plain predicate.
    """
    if not code or not code.strip().isdigit():
        return False
    code = code.strip()
    if timestamp is None:
        timestamp = time.time()
    counter = int(timestamp // period)
    try:
        key = _b32decode(secret)
    except Exception:
        return False
    for offset in range(-window, window + 1):
        candidate = _hotp(key, counter + offset, digits=digits, algorithm=algorithm)
        if hmac.compare_digest(candidate, code):
            return True
    return False


def provisioning_uri(
    secret: str,
    account_name: str,
    *,
    issuer: str = "rgt-vault",
    digits: int = DEFAULT_DIGITS,
    period: int = DEFAULT_PERIOD,
    algorithm: str = DEFAULT_ALGORITHM,
) -> str:
    """Build an ``otpauth://`` URI for QR enrollment in an authenticator app."""
    # The colon is the issuer/account label separator and stays literal;
    # only the two components are percent-encoded.
    label = f"{quote(issuer)}:{quote(account_name)}"
    params = (
        f"secret={secret}"
        f"&issuer={quote(issuer)}"
        f"&algorithm={algorithm}"
        f"&digits={digits}"
        f"&period={period}"
    )
    return f"otpauth://totp/{label}?{params}"
