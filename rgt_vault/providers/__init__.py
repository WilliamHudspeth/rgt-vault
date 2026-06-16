import os
import sys

from .base import MasterSecretProvider


def create_platform_provider() -> MasterSecretProvider:
    """Return a MasterSecretProvider for the current platform."""
    if sys.platform == "win32":
        from .windows_dpapi import WindowsDPAPIProvider
        return WindowsDPAPIProvider(
            os.environ.get("VAULT_DPAPI_BLOB", "C:\\ProgramData\\vault\\sealed.bin")
        )
    elif sys.platform == "darwin":
        from .macos_keychain import MacOSKeychainProvider
        return MacOSKeychainProvider(
            os.environ.get("VAULT_KEYCHAIN_SERVICE", "com.agentvault.master"),
            os.environ.get("VAULT_KEYCHAIN_ACCOUNT", "master-key")
        )
    else:  # Linux and others
        from .linux_tpm import LinuxTPMProvider
        return LinuxTPMProvider(
            os.environ.get("VAULT_TPM_PRIV", "/etc/vault/sealed/master_secret.priv"),
            os.environ.get("VAULT_TPM_PUB", "/etc/vault/sealed/master_secret.pub")
        )
