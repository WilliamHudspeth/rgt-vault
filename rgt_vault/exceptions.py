class VaultError(Exception):
    """Base exception for all rgt-vault errors."""
    pass

class PolicyDeniedError(VaultError):
    """Raised when access is denied by an ABAC policy."""
    pass

class SecretNotFoundError(VaultError):
    """Raised when a requested secret is not found."""
    pass

class ChecksumError(VaultError):
    """Raised when a checksum validation fails."""
    pass

class ValidationError(VaultError):
    """Raised when input validation fails."""
    pass

class DecryptionError(VaultError):
    """Raised when a ciphertext fails to decrypt (bad AAD, wrong key, tampering,
    or malformed input). Hides the underlying cause from attackers probing the
    vault via the public API; the original exception is chained in ``__cause__``
    for debug logs.
    """
    pass

class ServerAuthError(VaultError):
    """Raised by the HTTP server when a caller fails to present a valid token,
    presents a token from a different vault, or hits a server-internal auth
    path (e.g. trying to start ``serve`` without a token file). Mapped to
    HTTP 401 by the FastAPI exception handler.
    """
    pass

class ActionNotFoundError(VaultError):
    """Raised by the HTTP server's ``/use`` endpoint when the requested
    action name is not registered. Mapped to HTTP 404.
    """
    pass

class ActionExecutionError(VaultError):
    """Raised when a registered server-side action throws while it holds the
    leased secret buffer. The vault still zeroizes the buffer (the lease
    context manager guarantees that); the original exception is chained in
    ``__cause__``. Mapped to HTTP 500 by the FastAPI exception handler.
    """
    pass

class MasterSecretUnavailableError(VaultError):
    """Raised when the platform master-secret provider cannot return the
    existing master secret (e.g. OS keyring entry deleted, TPM reset).

    This is intentionally a hard failure: regenerating the master secret on
    the fly would render the entire vault permanently unreadable, since the
    DEK is wrapped under the previous master secret.
    """
    pass


# ---------------------------------------------------------------------------
# Token errors (re-exported from rgt_vault.token for convenience)
# ---------------------------------------------------------------------------


class TokenError(VaultError):
    """Base exception for all token-related errors."""
    pass


class TokenExpiredError(TokenError):
    """Raised when the token's ``expires_at`` is in the past."""
    pass


class TokenSignatureError(TokenError):
    """Raised when the HMAC signature is invalid."""
    pass


class TokenMalformedError(TokenError):
    """Raised when the envelope is structurally invalid."""
    pass


class TokenVersionError(TokenError):
    """Raised when the envelope version is not supported."""
    pass


class TokenBindingError(TokenError):
    """Raised when a context binding does not match."""
    pass


# ---------------------------------------------------------------------------
# Capability errors (re-exported from rgt_vault.capabilities for convenience)
# ---------------------------------------------------------------------------


class CapabilityError(VaultError):
    """Base exception for all capability-related errors."""
    pass


class CapabilityNotFoundError(CapabilityError):
    """Raised when ``execute_capability`` references an unregistered capability."""
    pass


class CapabilityVersionError(CapabilityError):
    """Raised when the requested capability version is not supported."""
    pass


class CapabilityExecutionError(CapabilityError):
    """Raised when a capability handler raises an exception.

    The original exception is chained in ``__cause__`` for debug logs,
    but the public message is sanitised (never contains secret material).
    """
    pass

class RotateNotSupportedError(VaultError):
    """Raised when ``rotate_master_key`` is called on a provider that does not
    support automated master-secret rotation (e.g. DPAPI/TPM, where
    re-sealing is an out-of-band operation).

    Prevents the vault from incrementing the key epoch without producing a
    new wrapped DEK, which would otherwise leave the vault in an inconsistent
    state on restart.
    """
    pass

class VaultImportError(VaultError):
    """Raised when an imported vault payload is rejected (e.g. cross-vault
    import, malformed payload). Distinct from built-in ``ImportError`` so
    callers can catch vault-specific import problems without swallowing
    stdlib ``ImportError``.
    """
    pass
