"""
Test suite for platform‑specific master secret providers
--------------------------------------------------------
Covers: LinuxTPMProvider, WindowsDPAPIProvider, MacOSKeychainProvider,
        their respective seal helpers, and the create_platform_provider factory.
All external dependencies are mocked \u2013 no real TPM, DPAPI, or keychain needed.
"""

import base64
from pathlib import Path
from unittest import mock

import pytest

from rgt_vault.providers import create_platform_provider

# Import the providers and factory
from rgt_vault.providers.linux_tpm import LinuxTPMProvider
from rgt_vault.providers.linux_tpm import seal_master_secret as tpm_seal
from rgt_vault.providers.macos_keychain import MacOSKeychainProvider
from rgt_vault.providers.macos_keychain import seal_master_secret as keychain_seal
from rgt_vault.providers.windows_dpapi import WindowsDPAPIProvider
from rgt_vault.providers.windows_dpapi import seal_master_secret as dpapi_seal


# ------------------------------------------------------------------
#  Fixtures
# ------------------------------------------------------------------
@pytest.fixture
def temp_dir(tmp_path):
    return tmp_path


@pytest.fixture
def dummy_master_secret():
    """A 32\u2011byte master secret used for sealing/unsealing tests."""
    return b"0123456789abcdef0123456789abcdef"  # exactly 32 bytes


# ------------------------------------------------------------------
#  Tests: LinuxTPMProvider
# ------------------------------------------------------------------
class TestLinuxTPMProvider:
    def test_successful_unseal(self, temp_dir, dummy_master_secret):
        """Simulate a working TPM unseal operation."""
        priv_file = temp_dir / "master.priv"
        pub_file = temp_dir / "master.pub"
        priv_file.write_text("private_blob")
        pub_file.write_text("public_blob")

        def fake_run(args, **kwargs):
            if "tpm2_unseal" in args[0] if isinstance(args[0], str) else any("tpm2_unseal" in a for a in args[0]):
                out_path = None
                cmd = args if isinstance(args, list) else args[0]
                if "-o" in cmd:
                    out_idx = cmd.index("-o") + 1
                    out_path = cmd[out_idx]
                if out_path:
                    with open(out_path, "wb") as f:
                        f.write(dummy_master_secret)
                return mock.MagicMock(returncode=0)
            return mock.MagicMock(returncode=0)

        with mock.patch("subprocess.run", side_effect=fake_run):
            provider = LinuxTPMProvider(str(priv_file), str(pub_file))
            secret = provider.get_secret()

        assert secret == dummy_master_secret

    def test_missing_private_file(self, temp_dir):
        """If the private blob doesn't exist, expect FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            provider = LinuxTPMProvider(str(temp_dir / "nonexistent.priv"), str(temp_dir / "dummy.pub"))
            provider.get_secret()

    def test_missing_public_file(self, temp_dir):
        """If the public blob doesn't exist, expect FileNotFoundError."""
        priv = temp_dir / "master.priv"
        priv.write_text("dummy")
        with pytest.raises(FileNotFoundError):
            provider = LinuxTPMProvider(str(priv), str(temp_dir / "missing.pub"))
            provider.get_secret()

    def test_tpm_command_failure(self, temp_dir):
        """TPM command (tpm2_load) returns non\u2011zero -> TPMError."""
        priv = temp_dir / "master.priv"
        pub = temp_dir / "master.pub"
        priv.write_text("priv")
        pub.write_text("pub")

        def fake_run(args, **kwargs):
            if "tpm2_load" in str(args):
                return mock.MagicMock(returncode=1, stdout="", stderr="TPM error")
            return mock.MagicMock(returncode=0)

        with mock.patch("subprocess.run", side_effect=fake_run):
            provider = LinuxTPMProvider(str(priv), str(pub))
            with pytest.raises(Exception) as exc_info:  # TPMError
                provider.get_secret()
            assert "TPM command failed" in str(exc_info.value)

    def test_unseal_empty_secret(self, temp_dir, dummy_master_secret):
        """If the unsealed file is empty, a TPMError is raised."""
        priv = temp_dir / "master.priv"
        pub = temp_dir / "master.pub"
        priv.write_text("priv")
        pub.write_text("pub")

        def fake_run(args, **kwargs):
            if "tpm2_unseal" in str(args):
                cmd = args if isinstance(args, list) else args[0]
                out_path = cmd[cmd.index("-o") + 1]
                Path(out_path).write_bytes(b"")
                return mock.MagicMock(returncode=0)
            return mock.MagicMock(returncode=0)

        with mock.patch("subprocess.run", side_effect=fake_run):
            provider = LinuxTPMProvider(str(priv), str(pub))
            with pytest.raises(Exception) as exc_info:
                provider.get_secret()
            assert "Unsealed empty secret" in str(exc_info.value)


# ------------------------------------------------------------------
#  Tests: WindowsDPAPIProvider
# ------------------------------------------------------------------
class TestWindowsDPAPIProvider:
    def test_successful_unprotect(self, temp_dir, dummy_master_secret):
        """DPAPI decrypt works and returns the master secret."""
        sealed_file = temp_dir / "sealed.bin"
        sealed_file.write_text(base64.b64encode(b"fake_blob").decode())

        mock_win32crypt = mock.MagicMock()
        mock_win32crypt.CryptUnprotectData.return_value = dummy_master_secret
        mock_win32crypt.CRYPTPROTECT_LOCAL_MACHINE = 4

        with mock.patch("rgt_vault.providers.windows_dpapi._load_win32crypt", return_value=mock_win32crypt):
            provider = WindowsDPAPIProvider(str(sealed_file))
            secret = provider.get_secret()

        assert secret == dummy_master_secret

    def test_missing_file(self, temp_dir):
        """FileNotFoundError if the sealed blob doesn't exist."""
        from rgt_vault.providers.windows_dpapi import WindowsDPAPIProvider

        with pytest.raises(FileNotFoundError):
            WindowsDPAPIProvider(str(temp_dir / "nonexistent.bin"))

    def test_dpapi_failure(self, temp_dir):
        """If CryptUnprotectData raises, PermissionError is thrown."""
        sealed_file = temp_dir / "sealed.bin"
        sealed_file.write_text(base64.b64encode(b"fake_blob").decode())

        mock_win32crypt = mock.MagicMock()
        mock_win32crypt.CryptUnprotectData.side_effect = Exception("DPAPI failed")
        # CRYPTPROTECT_LOCAL_MACHINE is 4
        mock_win32crypt.CRYPTPROTECT_LOCAL_MACHINE = 4

        with mock.patch("rgt_vault.providers.windows_dpapi._load_win32crypt", return_value=mock_win32crypt):
            provider = WindowsDPAPIProvider(str(sealed_file))
            with pytest.raises(PermissionError, match="DPAPI decryption failed"):
                provider.get_secret()


# ------------------------------------------------------------------
#  Tests: MacOSKeychainProvider
# ------------------------------------------------------------------
class TestMacOSKeychainProvider:
    def test_successful_find(self, dummy_master_secret):
        """Simulate a working 'security' call returning the secret."""

        def fake_run(args, **kwargs):
            if "find-generic-password" in args:
                return mock.MagicMock(returncode=0, stdout=dummy_master_secret.decode("utf-8") + "\n", stderr="")
            return mock.MagicMock(returncode=0)

        with mock.patch("subprocess.run", side_effect=fake_run):
            provider = MacOSKeychainProvider("com.test.service", "test_account")
            secret = provider.get_secret()

        assert secret == dummy_master_secret

    def test_keychain_access_denied(self):
        """If security command fails (non\u2011zero), PermissionError raised."""
        import subprocess

        def fake_run(args, **kwargs):
            if "find-generic-password" in args:
                raise subprocess.CalledProcessError(
                    returncode=1, cmd=args, output="", stderr="The specified item could not be found in the keychain."
                )
            return mock.MagicMock(returncode=0)

        with mock.patch("subprocess.run", side_effect=fake_run):
            provider = MacOSKeychainProvider("com.test.service", "test_account")
            with pytest.raises(PermissionError, match="Failed to read keychain item"):
                provider.get_secret()


# ------------------------------------------------------------------
#  Seal helpers (optional, but test basic logic)
# ------------------------------------------------------------------
def test_tpm_seal(temp_dir, dummy_master_secret):
    """Run seal_master_secret and verify it writes .priv and .pub files."""

    def fake_run(args, **kwargs):
        return mock.MagicMock(returncode=0)

    with mock.patch("subprocess.run", side_effect=fake_run):
        priv, pub = tpm_seal(dummy_master_secret, str(temp_dir))
        assert priv.parent == temp_dir
        assert pub.parent == temp_dir


def test_dpapi_seal(temp_dir, dummy_master_secret):
    """Seal writes a base64 blob to the output file."""
    output = temp_dir / "sealed.bin"
    mock_win32crypt = mock.MagicMock()
    mock_win32crypt.CryptProtectData.return_value = b"encrypted_data"
    mock_win32crypt.CRYPTPROTECT_LOCAL_MACHINE = 4

    with mock.patch("rgt_vault.providers.windows_dpapi._load_win32crypt", return_value=mock_win32crypt):
        dpapi_seal(dummy_master_secret, str(output))
        assert output.exists()
        content = output.read_text()
        assert base64.b64decode(content) == b"encrypted_data"


def test_keychain_seal(dummy_master_secret):
    """Seal calls the security command with appropriate arguments."""

    def fake_run(args, **kwargs):
        assert "add-generic-password" in args
        return mock.MagicMock(returncode=0)

    with mock.patch("subprocess.run", side_effect=fake_run) as mock_run:
        keychain_seal(dummy_master_secret, "com.test.seal", "account")
        calls = mock_run.call_args_list
        assert len(calls) == 1
        call_args = calls[0][0][0]
        assert "-s" in call_args and "com.test.seal" in call_args
        assert "-a" in call_args and "account" in call_args


# ------------------------------------------------------------------
#  Factory: create_platform_provider
# ------------------------------------------------------------------
class TestPlatformFactory:
    def test_windows_platform(self, temp_dir):
        """On Windows, should return WindowsDPAPIProvider."""
        blob = temp_dir / "sealed.bin"
        blob.write_text(base64.b64encode(b"dummy").decode())
        with mock.patch("sys.platform", "win32"), mock.patch.dict("os.environ", {"VAULT_DPAPI_BLOB": str(blob)}):
            provider = create_platform_provider()
            assert isinstance(provider, WindowsDPAPIProvider)

    def test_macos_platform(self):
        """On macOS, returns MacOSKeychainProvider."""
        with (
            mock.patch("sys.platform", "darwin"),
            mock.patch("subprocess.run", return_value=mock.MagicMock(returncode=0, stdout="test")),
        ):
            provider = create_platform_provider()
            assert isinstance(provider, MacOSKeychainProvider)

    def test_linux_platform(self, temp_dir):
        """On Linux, returns LinuxTPMProvider."""
        priv = temp_dir / "master.priv"
        pub = temp_dir / "master.pub"
        priv.write_text("priv")
        pub.write_text("pub")
        with (
            mock.patch("sys.platform", "linux"),
            mock.patch.dict("os.environ", {"VAULT_TPM_PRIV": str(priv), "VAULT_TPM_PUB": str(pub)}),
            mock.patch("subprocess.run", return_value=mock.MagicMock(returncode=0)),
        ):
            provider = create_platform_provider()
            assert isinstance(provider, LinuxTPMProvider)

    def test_fallback_if_paths_not_set(self, temp_dir):
        """The factory uses default paths if env vars are missing."""
        with (
            mock.patch("sys.platform", "linux"),
            mock.patch("subprocess.run", return_value=mock.MagicMock(returncode=0)),
        ):
            with mock.patch.object(Path, "is_file", return_value=True):
                provider = create_platform_provider()
                assert isinstance(provider, LinuxTPMProvider)
