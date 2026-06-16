from abc import ABC, abstractmethod
from typing import Union


class MasterSecretProvider(ABC):
    """Abstract source of the root-of-trust master secret.

    Implementations may return raw ``bytes`` or a ``MasterSecret`` wrapper;
    ``VaultManager`` normalizes either form at the trust boundary.
    """

    @abstractmethod
    def get_secret(self) -> Union[bytes, "object"]:
        """Return the master secret (raw bytes or a MasterSecret)."""
        ...

    def rotate_secret(self) -> Union[bytes, "object"]:
        """Generate and persist a new master secret, returning it.

        Not all providers support automated rotation (e.g. DPAPI/TPM sealing
        is performed out-of-band). Such providers must re-seal manually.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support automated master-key rotation; "
            "re-seal the master secret out-of-band and increment the key epoch."
        )

    def bootstrap_master_secret(self):
        """Create a fresh master secret if one does not already exist.

        Default implementation: no-op (assumes the secret is already sealed
        by an out-of-band process -- e.g. TPM/DPAPI/macOS Keychain). Providers
        whose backing store supports atomic create-if-missing (currently
        only :class:`rgt_vault.keychain.KeyringProvider`) override this.

        Called by :class:`VaultManager` only on first-time initialization
        (no keychain.json present). Returning a value is not required --
        ``get_secret`` will be called immediately after, and that is the
        authoritative read path.
        """
        return None
