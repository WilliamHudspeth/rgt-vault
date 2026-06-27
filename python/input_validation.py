"""Server-side input validation utilities for rgt-vault.

Covers tickets RGT-381 through RGT-385:
  RGT-381: Strict server-side validation enforced before processing any data.
  RGT-382: Syntactic (type/length/format) + semantic (boundary/relationship) checks.
  RGT-383: Allowlist-based positive validation.
  RGT-384: Unicode normalization (NFC) and Unicode category checks.
  RGT-385: ReDoS-resistant regex evaluation with timeout guard.

All validation is applied server-side. Client-supplied values are treated as
untrusted until validated by one of the functions in this module.
"""

from __future__ import annotations

import re
import signal
import sys
import unicodedata
from typing import Any, Container, Optional

from rgt_vault.exceptions import ValidationError


# ---------------------------------------------------------------------------
# RGT-383: Allowlist-based positive validation
# ---------------------------------------------------------------------------

#: Allowlist of characters permitted in secret *names* and *namespaces*.
#: Rationale: printable ASCII minus shell metacharacters and path separators.
#: Unicode names are not supported here; use base64 or percent-encoding.
_NAME_ALLOWLIST_RE = re.compile(r"^[a-zA-Z0-9_.\- ]+$")

#: Allowlist for agent identifiers.
_AGENT_ALLOWLIST_RE = re.compile(r"^[a-zA-Z0-9_.\-@]+$")

#: Allowlist for namespace identifiers.
_NAMESPACE_ALLOWLIST_RE = re.compile(r"^[a-zA-Z0-9_.\-]+$")


def validate_name(value: str) -> str:
    """Return *value* if it passes the secret-name allowlist; raise ValidationError otherwise.

    Enforces:
    - Must be a str (RGT-381: type check).
    - 1–256 characters (RGT-382: length bound).
    - Characters in [a-zA-Z0-9_.\\-] only (RGT-383: allowlist).
    """
    if not isinstance(value, str):
        raise ValidationError(f"'name' must be a string; got {type(value).__name__}.")
    if not value or not value.strip():
        raise ValidationError("'name' cannot be empty or whitespace.")
    if len(value) > 256:
        raise ValidationError("'name' exceeds the maximum allowed length of 256 characters.")
    if not _NAME_ALLOWLIST_RE.match(value):
        raise ValidationError(
            "'name' contains characters not permitted by the allowlist "
            "(allowed: a-z A-Z 0-9 _ . -)."
        )
    return value


def validate_namespace(value: str) -> str:
    """Return *value* if it passes the namespace allowlist; raise ValidationError otherwise."""
    if not isinstance(value, str):
        raise ValidationError(f"'namespace' must be a string; got {type(value).__name__}.")
    if not value or not value.strip():
        raise ValidationError("'namespace' cannot be empty or whitespace.")
    if len(value) > 128:
        raise ValidationError("'namespace' exceeds the maximum allowed length of 128 characters.")
    if not _NAMESPACE_ALLOWLIST_RE.match(value):
        raise ValidationError(
            "'namespace' contains characters not permitted by the allowlist "
            "(allowed: a-z A-Z 0-9 _ . -)."
        )
    return value


def validate_agent(value: str) -> str:
    """Return *value* if it passes the agent-id allowlist; raise ValidationError otherwise."""
    if not isinstance(value, str):
        raise ValidationError(f"'agent' must be a string; got {type(value).__name__}.")
    if not value or not value.strip():
        raise ValidationError("'agent' cannot be empty or whitespace.")
    if len(value) > 128:
        raise ValidationError("'agent' exceeds the maximum allowed length of 128 characters.")
    if not _AGENT_ALLOWLIST_RE.match(value):
        raise ValidationError(
            "'agent' contains characters not permitted by the allowlist "
            "(allowed: a-z A-Z 0-9 _ . - @)."
        )
    return value


# ---------------------------------------------------------------------------
# RGT-376 / RGT-382: Integer bound validation
# ---------------------------------------------------------------------------

def validate_int_bound(
    param_name: str,
    value: Any,
    *,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
) -> int:
    """Validate that *value* is an integer within [min_val, max_val].

    Raises ValidationError if:
    - value is not an int (or bool, which is a subclass of int).
    - value < min_val (if min_val is set).
    - value > max_val (if max_val is set).

    Python integers are arbitrary precision (no overflow), but untrusted
    inputs can still be semantically out-of-range (e.g. a negative limit).
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(
            f"'{param_name}' must be an integer; got {type(value).__name__}."
        )
    if min_val is not None and value < min_val:
        raise ValidationError(
            f"'{param_name}' must be >= {min_val}; got {value}."
        )
    if max_val is not None and value > max_val:
        raise ValidationError(
            f"'{param_name}' must be <= {max_val}; got {value}."
        )
    return value


# ---------------------------------------------------------------------------
# RGT-384: Unicode normalization and category filtering
# ---------------------------------------------------------------------------

#: Unicode general categories considered safe for free-form text fields
#: (notes, purpose strings).  Excludes control characters (Cc), surrogates
#: (Cs), private-use (Co), and unassigned (Cn).
_SAFE_UNICODE_CATEGORIES = frozenset(
    {
        "Lu",  # Uppercase letter
        "Ll",  # Lowercase letter
        "Lt",  # Titlecase letter
        "Lm",  # Modifier letter
        "Lo",  # Other letter
        "Nd",  # Decimal digit
        "Nl",  # Letter number
        "No",  # Other number
        "Pc",  # Connector punctuation
        "Pd",  # Dash punctuation
        "Ps",  # Open punctuation
        "Pe",  # Close punctuation
        "Pi",  # Initial quote punctuation
        "Pf",  # Final quote punctuation
        "Po",  # Other punctuation
        "Sm",  # Math symbol
        "Sc",  # Currency symbol
        "Sk",  # Modifier symbol
        "So",  # Other symbol
        "Zs",  # Space separator
    }
)


def normalize_unicode(text: str, form: str = "NFC") -> str:
    """Return *text* after Unicode normalization to *form* (default: NFC).

    NFC normalization prevents homograph attacks where visually identical
    characters have different Unicode code points (e.g. composed vs.
    decomposed forms of accented letters).

    Raises ValidationError if any character falls outside the safe category
    set (i.e. control characters, surrogates, private-use code points).
    """
    if not isinstance(text, str):
        raise ValidationError(f"Expected str for Unicode normalization; got {type(text).__name__}.")
    normalized = unicodedata.normalize(form, text)
    for i, ch in enumerate(normalized):
        cat = unicodedata.category(ch)
        if cat not in _SAFE_UNICODE_CATEGORIES:
            raise ValidationError(
                f"Character at position {i} (U+{ord(ch):04X}, category {cat!r}) "
                f"is not permitted in this field."
            )
    return normalized


def validate_free_text(value: str, max_len: int = 512) -> str:
    """Validate and normalize a free-text field (note, purpose, description).

    Applies:
    - Type check (must be str).
    - Length check (max_len characters, post-normalization).
    - Unicode NFC normalization.
    - Unicode category allowlist (excludes control characters and surrogates).
    """
    if not isinstance(value, str):
        raise ValidationError(f"Expected str; got {type(value).__name__}.")
    normalized = normalize_unicode(value)
    if len(normalized) > max_len:
        raise ValidationError(
            f"Field exceeds maximum length of {max_len} characters after normalization."
        )
    return normalized


# ---------------------------------------------------------------------------
# RGT-385: ReDoS-resistant regex execution
# ---------------------------------------------------------------------------

class _TimeoutError(Exception):
    """Raised when a regex match times out."""


def _alarm_handler(signum: int, frame: Any) -> None:
    raise _TimeoutError("regex match timed out")


def safe_regex_match(
    pattern: re.Pattern,
    text: str,
    timeout_seconds: int = 1,
) -> Optional[re.Match]:
    """Execute a compiled regex match with a wall-clock timeout.

    This guards against ReDoS when a regex with polynomial or exponential
    backtracking complexity is applied to a long or crafted input string.

    On POSIX systems, uses SIGALRM to enforce the timeout. On non-POSIX
    systems (Windows), the timeout is best-effort via a threading wrapper
    (see _safe_regex_match_threaded).

    Parameters
    ----------
    pattern:
        A pre-compiled ``re.Pattern``.  The pattern itself is operator-
        controlled (not user-supplied); user input is only the *text*.
    text:
        The string to match.
    timeout_seconds:
        Maximum wall-clock seconds before raising ValidationError.

    Returns
    -------
    A ``re.Match`` object on success, or ``None`` if the pattern does not match.

    Raises
    ------
    ValidationError
        If the match exceeds ``timeout_seconds``.
    """
    if sys.platform != "win32":
        return _safe_regex_match_sigalrm(pattern, text, timeout_seconds)
    return _safe_regex_match_threaded(pattern, text, timeout_seconds)


def _safe_regex_match_sigalrm(
    pattern: re.Pattern,
    text: str,
    timeout_seconds: int,
) -> Optional[re.Match]:
    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(max(1, timeout_seconds))
    try:
        return pattern.match(text)
    except _TimeoutError:
        raise ValidationError(
            f"Regex match aborted: exceeded {timeout_seconds}s timeout. "
            "The input may be causing catastrophic backtracking."
        )
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def _safe_regex_match_threaded(
    pattern: re.Pattern,
    text: str,
    timeout_seconds: int,
) -> Optional[re.Match]:
    """Threaded timeout fallback for non-POSIX platforms."""
    import threading

    result: list = [None]
    exc: list = [None]

    def _run() -> None:
        try:
            result[0] = pattern.match(text)
        except Exception as e:
            exc[0] = e

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=timeout_seconds)
    if t.is_alive():
        raise ValidationError(
            f"Regex match aborted: exceeded {timeout_seconds}s timeout. "
            "The input may be causing catastrophic backtracking."
        )
    if exc[0] is not None:
        raise exc[0]
    return result[0]


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

__all__ = [
    "validate_name",
    "validate_namespace",
    "validate_agent",
    "validate_int_bound",
    "normalize_unicode",
    "validate_free_text",
    "safe_regex_match",
]
