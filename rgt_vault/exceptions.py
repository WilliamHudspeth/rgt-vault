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
