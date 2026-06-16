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
