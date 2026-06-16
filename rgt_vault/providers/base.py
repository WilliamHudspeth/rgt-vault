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
