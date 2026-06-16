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
