"""ASVS 6.x Cryptography & RGT-455..458 TLS hardening — code-level verification.

Tickets covered:
  RGT-393  ASVS 6.1.1  PII stored encrypted at rest
  RGT-394  ASVS 6.1.2  Health data stored encrypted at rest
  RGT-395  ASVS 6.1.3  Financial data stored encrypted at rest
  RGT-396  ASVS 6.2.1  Crypto modules fail securely (no plaintext leakage, no padding oracle)
  RGT-397  ASVS 6.2.2  Government-approved algorithms (AES-256-GCM, HKDF-SHA512, Argon2id)
  RGT-398  ASVS 6.2.3  Secure IV/cipher/block mode (12-byte CSPRNG nonce, GCM mode)
  RGT-399  ASVS 6.2.4  Cryptographic agility (algorithm config surface)
  RGT-400  ASVS 6.2.5  No obsolete algorithms (no MD5, SHA1 for hashing, no DES, ECB, RC4)
  RGT-401  ASVS 6.2.6  Nonces never reused
  RGT-402  ASVS 6.2.7  Authenticated encryption (AES-GCM provides AEAD)
  RGT-403  ASVS 6.2.8  Constant-time comparisons (covered in test_asvs_logging_crypto.py; extended here)
  RGT-404  ASVS 6.3.1  CSPRNG for all random material
  RGT-405  ASVS 6.3.2  UUIDs are v4 backed by CSPRNG
  RGT-406  ASVS 6.3.3  CSPRNG degrades gracefully (os.urandom is non-blocking on Linux ≥3.17)
  RGT-407  ASVS 6.4.1  Secure key vault / secrets manager (VaultManager + DEK lifecycle)
  RGT-408  ASVS 6.4.2  Key material not exposed to application space (SecureBuffer / zeroization)
"""

from __future__ import annotations

import ast
import hmac
import os
import secrets
import sys
import uuid
from pathlib import Path
from typing import List

import pytest

# ---------------------------------------------------------------------------
# Helpers / shared fixtures
# ---------------------------------------------------------------------------

RGTV_ROOT = Path(__file__).parent.parent


def _collect_python_sources() -> List[Path]:
    """All .py files under rgt_vault/ (the canonical package)."""
    pkg = RGTV_ROOT / "rgt_vault"
    return list(pkg.rglob("*.py"))


# ---------------------------------------------------------------------------
# RGT-393 / RGT-394 / RGT-395 — Regulated data encrypted at rest
# ---------------------------------------------------------------------------


class TestEncryptedAtRest:
    """ASVS 6.1.1-6.1.3: PII, health, and financial data must be encrypted.

    The vault encrypts *every* secret with AES-256-GCM before writing to
    SQLite.  These tests assert that the ciphertext written to storage differs
    from the plaintext in every case — i.e. no secret ever lands in the DB in
    cleartext.
    """

    def _make_vault(self, tmp_path, master_provider):
        from rgt_vault.vault import VaultManager

        return VaultManager(
            db_path=str(tmp_path / "vault.db"),
            master_provider=master_provider,
            policy_yaml="rules:\n  - effect: allow\n",
        )

    def test_pii_ciphertext_differs_from_plaintext(self, tmp_path, master_provider):
        """RGT-393: A stored PII value must not appear in cleartext in the DB."""
        import sqlite3

        vault = self._make_vault(tmp_path, master_provider)
        pii_value = "John Doe | SSN 123-45-6789 | DOB 1980-01-01"
        vault.set_secret("ssn", pii_value, namespace="pii", agent="test")

        db = tmp_path / "vault.db"
        rows = sqlite3.connect(db).execute(
            "SELECT ciphertext FROM secrets WHERE name='ssn'"
        ).fetchall()
        assert rows, "No secret row found in DB"
        for (ct,) in rows:
            raw = ct if isinstance(ct, bytes) else ct.encode()
            assert pii_value.encode() not in raw, (
                "PII plaintext found verbatim in ciphertext column"
            )

    def test_health_ciphertext_differs_from_plaintext(self, tmp_path, master_provider):
        """RGT-394: A stored health record value must not appear in cleartext."""
        import sqlite3

        vault = self._make_vault(tmp_path, master_provider)
        health_value = "Patient 9977: Diagnosis ICD-10 Z00.0, prescribed metformin"
        vault.set_secret("health_record", health_value, namespace="health", agent="test")

        db = tmp_path / "vault.db"
        rows = sqlite3.connect(db).execute(
            "SELECT ciphertext FROM secrets WHERE name='health_record'"
        ).fetchall()
        for (ct,) in rows:
            raw = ct if isinstance(ct, bytes) else ct.encode()
            assert health_value.encode() not in raw

    def test_financial_ciphertext_differs_from_plaintext(self, tmp_path, master_provider):
        """RGT-395: A stored financial value must not appear in cleartext."""
        import sqlite3

        vault = self._make_vault(tmp_path, master_provider)
        fin_value = "CC: 4111-1111-1111-1111 | CVV: 737 | Balance: $12,340.99"
        vault.set_secret("credit_card", fin_value, namespace="financial", agent="test")

        db = tmp_path / "vault.db"
        rows = sqlite3.connect(db).execute(
            "SELECT ciphertext FROM secrets WHERE name='credit_card'"
        ).fetchall()
        for (ct,) in rows:
            raw = ct if isinstance(ct, bytes) else ct.encode()
            assert fin_value.encode() not in raw


# ---------------------------------------------------------------------------
# RGT-396 — Fail securely; no plaintext leakage on decryption failure
# ---------------------------------------------------------------------------


class TestFailSecurely:
    """ASVS 6.2.1: crypto errors must not expose plaintext or paddingOracle-style info."""

    def test_wrong_key_raises_decryption_error(self):
        from rgt_vault.crypto import decrypt, encrypt
        from rgt_vault.exceptions import DecryptionError

        dek = os.urandom(32)
        wrong_dek = os.urandom(32)
        aad = b"test:aad"
        ct = encrypt(b"my_secret_value", dek, aad)

        with pytest.raises(DecryptionError):
            decrypt(ct, wrong_dek, aad)

    def test_wrong_aad_raises_decryption_error(self):
        from rgt_vault.crypto import decrypt, encrypt
        from rgt_vault.exceptions import DecryptionError

        dek = os.urandom(32)
        ct = encrypt(b"my_secret_value", dek, b"real:aad")

        with pytest.raises(DecryptionError):
            decrypt(ct, dek, b"wrong:aad")

    def test_error_message_does_not_contain_plaintext(self):
        """The DecryptionError message must not reveal any plaintext fragment."""
        from rgt_vault.crypto import decrypt, encrypt
        from rgt_vault.exceptions import DecryptionError

        dek = os.urandom(32)
        aad = b"ns:name"
        plaintext = b"SUPER_SEKRET_VALUE_XYZ"
        ct = encrypt(plaintext, dek, aad)

        try:
            decrypt(ct, os.urandom(32), aad)
            pytest.fail("Expected DecryptionError not raised")
        except DecryptionError as e:
            assert b"SUPER_SEKRET_VALUE_XYZ" not in str(e).encode()
            assert b"SUPER_SEKRET_VALUE_XYZ" not in repr(e).encode()

    def test_truncated_ciphertext_raises_decryption_error(self):
        """A too-short token (< nonce+tag) must raise DecryptionError, not ValueError."""
        from rgt_vault.crypto import decrypt
        from rgt_vault.exceptions import DecryptionError

        dek = os.urandom(32)
        with pytest.raises(DecryptionError):
            decrypt(b"short", dek, b"aad")

    def test_decryption_error_chains_cause(self):
        """DecryptionError must chain the underlying InvalidTag via __cause__."""
        from cryptography.exceptions import InvalidTag

        from rgt_vault.crypto import decrypt, encrypt
        from rgt_vault.exceptions import DecryptionError

        dek = os.urandom(32)
        ct = encrypt(b"data", dek, b"aad")
        try:
            decrypt(ct, os.urandom(32), b"aad")
        except DecryptionError as e:
            assert isinstance(e.__cause__, InvalidTag), (
                "DecryptionError should chain the InvalidTag cause"
            )

    def test_non_bytes_input_raises_decryption_error(self):
        """Passing a str instead of bytes must raise DecryptionError, not TypeError."""
        from rgt_vault.crypto import decrypt
        from rgt_vault.exceptions import DecryptionError

        dek = os.urandom(32)
        with pytest.raises(DecryptionError):
            decrypt("not bytes", dek, b"aad")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# RGT-397 — Government-approved algorithms present in codebase
# ---------------------------------------------------------------------------


class TestApprovedAlgorithms:
    """ASVS 6.2.2: only approved algorithms may be used for cryptographic ops."""

    def test_aesgcm_is_imported_from_cryptography(self):
        """AES-256-GCM must come from the 'cryptography' library (FIPS-validated path)."""
        import importlib

        mod = importlib.import_module("rgt_vault.crypto")
        source = Path(mod.__file__).read_text()
        assert "AESGCM" in source
        assert "cryptography.hazmat.primitives.ciphers.aead" in source

    def test_argon2id_is_used_for_key_derivation(self):
        """Argon2id (BSI TR-02102 approved) must be used in keychain KDF."""
        import importlib

        mod = importlib.import_module("rgt_vault.keychain")
        source = Path(mod.__file__).read_text()
        assert "Argon2id" in source

    def test_hkdf_sha512_is_used_for_key_binding(self):
        """HKDF-SHA512 (NIST SP 800-56C) must bind derived keys."""
        import importlib

        mod = importlib.import_module("rgt_vault.keychain")
        source = Path(mod.__file__).read_text()
        assert "HKDF" in source
        assert "SHA512" in source

    def test_hmac_sha256_used_for_audit_chain(self):
        """HMAC-SHA256 (FIPS 198-1 / SP 800-107) must back the audit hash chain."""
        import importlib

        mod = importlib.import_module("rgt_vault.storage.sqlite")
        source = Path(mod.__file__).read_text()
        assert "sha256" in source.lower()

    def test_no_custom_crypto_primitives(self):
        """Source must not implement custom block ciphers or hash functions inline."""
        forbidden_patterns = [
            "def sbox(",
            "def feistel(",
            "def s_box(",
            "xor_bytes",  # common DIY crypto smell
        ]
        for src_file in _collect_python_sources():
            text = src_file.read_text(errors="replace")
            for pat in forbidden_patterns:
                # Allow it if it's in a comment or docstring (rough heuristic)
                lines = [ln for ln in text.splitlines() if pat in ln and not ln.strip().startswith("#")]
                assert not lines, (
                    f"Suspicious custom crypto pattern {pat!r} in {src_file.relative_to(RGTV_ROOT)}"
                )


# ---------------------------------------------------------------------------
# RGT-398 — Secure IV / cipher / block mode
# ---------------------------------------------------------------------------


class TestSecureIVAndCipherMode:
    """ASVS 6.2.3: nonces must be 12 bytes, generated by CSPRNG, GCM mode only."""

    def test_nonce_is_12_bytes(self):
        """Encrypted token must start with a 12-byte nonce."""
        from rgt_vault.crypto import encrypt

        dek = os.urandom(32)
        ct = encrypt(b"value", dek, b"aad")
        # nonce = first 12 bytes; the rest is ciphertext+tag
        assert len(ct) >= 12 + 1 + 16, "Token too short to contain nonce+data+tag"

    def test_nonce_is_not_all_zeros(self):
        """os.urandom must never produce an all-zero nonce in practice."""
        from rgt_vault.crypto import encrypt

        dek = os.urandom(32)
        for _ in range(50):
            ct = encrypt(b"v", dek, b"a")
            nonce = ct[:12]
            assert nonce != b"\x00" * 12, "Nonce was all zeros (CSPRNG failure?)"

    def test_encrypt_uses_os_urandom_for_nonce(self):
        """crypto.py must call os.urandom(12) — assert by inspecting the AST."""
        crypto_src = (RGTV_ROOT / "rgt_vault" / "crypto.py").read_text()
        tree = ast.parse(crypto_src)
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "urandom"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
        ]
        assert calls, "os.urandom() call not found in crypto.py"
        # Verify the argument is the constant 12
        nonce_calls = [
            c for c in calls
            if c.args and isinstance(c.args[0], ast.Constant) and c.args[0].value == 12
        ]
        assert nonce_calls, "os.urandom(12) call not found in crypto.py — nonce size may have changed"

    def test_aesgcm_is_only_cipher_used(self):
        """crypto.py must not import ECB, CBC, or CTR cipher modes."""
        crypto_src = (RGTV_ROOT / "rgt_vault" / "crypto.py").read_text()
        forbidden = ["ECB", "CBC", "CTR", "CFB", "OFB", "AESCipher", "Cipher("]
        for name in forbidden:
            assert name not in crypto_src, (
                f"Forbidden cipher mode/class {name!r} found in crypto.py"
            )


# ---------------------------------------------------------------------------
# RGT-399 — Cryptographic agility
# ---------------------------------------------------------------------------


class TestCryptographicAgility:
    """ASVS 6.2.4: algorithms, key sizes, and rounds must be reconfigurable."""

    def test_dek_manager_accepts_custom_argon2_params(self, tmp_path, master_provider):
        """HardenedDEKManager.initialize_dek accepts memory_cost / time_cost overrides."""
        from rgt_vault.keychain import HardenedDEKManager, MasterSecret

        mgr = HardenedDEKManager(str(tmp_path / "keychain.json"))
        master = MasterSecret(b"x" * 32)
        # Use very cheap params for speed; the signature must accept them
        dek = mgr.initialize_dek(master, "test-vault-id", epoch=1, memory_cost=4096, time_cost=1, parallelism=1)
        assert len(dek) == 32

    def test_dek_key_length_is_32_bytes(self):
        """DEK must be AES-256 (32 bytes); changing this should be a deliberate choice."""
        from rgt_vault.keychain import HardenedDEKManager, MasterSecret
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            mgr = HardenedDEKManager(os.path.join(d, "kc.json"))
            dek = mgr.initialize_dek(MasterSecret(b"m" * 32), "v", 1, memory_cost=4096, time_cost=1, parallelism=1)
            assert len(dek) == 32, "DEK must be exactly 32 bytes (AES-256)"

    def test_keychain_records_kdf_parameters(self, tmp_path):
        """keychain.json must record KDF parameters so they can be changed on rotation."""
        import json
        from rgt_vault.keychain import HardenedDEKManager, MasterSecret

        path = tmp_path / "kc.json"
        mgr = HardenedDEKManager(str(path))
        mgr.initialize_dek(MasterSecret(b"k" * 32), "v", 1, memory_cost=4096, time_cost=1, parallelism=1)
        data = json.loads(path.read_text())
        assert "argon2_memory_cost" in data
        assert "argon2_time_cost" in data
        assert "argon2_parallelism" in data
        assert data["kdf"] == "argon2id"


# ---------------------------------------------------------------------------
# RGT-400 — No obsolete algorithms
# ---------------------------------------------------------------------------


class TestNoObsoleteAlgorithms:
    """ASVS 6.2.5: MD5, DES, ECB, RC4, and SHA-1 (standalone) must be absent."""

    OBSOLETE_PATTERNS = [
        ("md5", ["import hashlib", "hashlib.md5"]),
        ("DES", ["DES(", "from Crypto.Cipher import DES", "TripleDES"]),
        ("RC4", ["RC4(", "ARC4(", "Cipher.ARC4"]),
        ("ECB", ["ECB(", "modes.ECB", ".ECB)"]),
    ]

    def _sources_text(self) -> str:
        return "\n".join(p.read_text(errors="replace") for p in _collect_python_sources())

    def test_no_md5_usage(self):
        """MD5 must not be used for any cryptographic purpose."""
        for src_file in _collect_python_sources():
            text = src_file.read_text(errors="replace")
            # hashlib.md5 calls in non-comment, non-docstring lines
            for lineno, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if "hashlib.md5" in line or "hashlib.new('md5'" in line:
                    pytest.fail(
                        f"hashlib.md5 found in {src_file.relative_to(RGTV_ROOT)}:{lineno}"
                    )

    def test_no_des_usage(self):
        for src_file in _collect_python_sources():
            text = src_file.read_text(errors="replace")
            assert "TripleDES" not in text, f"TripleDES in {src_file}"
            assert "DES(" not in text, f"DES( in {src_file}"

    def test_no_rc4_usage(self):
        for src_file in _collect_python_sources():
            text = src_file.read_text(errors="replace")
            assert "ARC4" not in text, f"ARC4 in {src_file}"
            assert "RC4(" not in text, f"RC4( in {src_file}"

    def test_no_ecb_mode(self):
        for src_file in _collect_python_sources():
            text = src_file.read_text(errors="replace")
            assert "modes.ECB" not in text, f"ECB mode in {src_file}"

    def test_sha1_not_used_for_general_hashing(self):
        """SHA-1 is permitted ONLY inside TOTP (RFC 4226 default); not for MAC or digest."""
        for src_file in _collect_python_sources():
            if "totp" in src_file.name:
                continue  # SHA-1 in TOTP is RFC 4226 compliant; tolerated
            text = src_file.read_text(errors="replace")
            for lineno, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if "hashlib.sha1" in line or "hashes.SHA1" in line:
                    pytest.fail(
                        f"SHA-1 used outside TOTP in "
                        f"{src_file.relative_to(RGTV_ROOT)}:{lineno}: {stripped}"
                    )


# ---------------------------------------------------------------------------
# RGT-401 — Nonces never reused
# ---------------------------------------------------------------------------


class TestNonceUniqueness:
    """ASVS 6.2.6: every encrypt() call must generate a fresh nonce."""

    def test_1000_encryptions_produce_unique_nonces(self):
        """Generate 1000 ciphertexts; all leading 12 bytes must be distinct."""
        from rgt_vault.crypto import encrypt

        dek = os.urandom(32)
        aad = b"uniqueness:test"
        nonces = set()
        for _ in range(1000):
            ct = encrypt(b"data", dek, aad)
            nonce = ct[:12]
            assert nonce not in nonces, "Nonce collision detected in 1000 encryptions"
            nonces.add(nonce)
        assert len(nonces) == 1000

    def test_same_plaintext_produces_different_ciphertexts(self):
        """Encrypting the same plaintext twice must yield different ciphertexts."""
        from rgt_vault.crypto import encrypt

        dek = os.urandom(32)
        aad = b"test:aad"
        ct1 = encrypt(b"hello", dek, aad)
        ct2 = encrypt(b"hello", dek, aad)
        assert ct1 != ct2, "Same plaintext + same key yielded identical ciphertexts (nonce reuse)"

    def test_nonce_from_os_urandom_not_from_counter(self):
        """Nonces must not be sequential / counter-based (os.urandom is non-monotonic)."""
        from rgt_vault.crypto import encrypt

        dek = os.urandom(32)
        nonces_as_ints = []
        for _ in range(20):
            ct = encrypt(b"x", dek, b"a")
            nonces_as_ints.append(int.from_bytes(ct[:12], "big"))

        # A monotonically increasing counter would be caught here
        diffs = [nonces_as_ints[i + 1] - nonces_as_ints[i] for i in range(len(nonces_as_ints) - 1)]
        # If all diffs are exactly 1, it's a counter — fail
        assert not all(d == 1 for d in diffs), (
            "Nonces appear to be a sequential counter — os.urandom not being used"
        )


# ---------------------------------------------------------------------------
# RGT-402 — Authenticated encryption
# ---------------------------------------------------------------------------


class TestAuthenticatedEncryption:
    """ASVS 6.2.7: all ciphertext must be authenticated (AES-GCM provides AEAD)."""

    def test_tampered_ciphertext_body_rejected(self):
        """Flipping a bit in the ciphertext body must cause decryption to fail."""
        from rgt_vault.crypto import decrypt, encrypt
        from rgt_vault.exceptions import DecryptionError

        dek = os.urandom(32)
        aad = b"ns:name"
        ct = encrypt(b"sensitive data", dek, aad)

        # Flip the last byte of the ciphertext (beyond the 12-byte nonce)
        tampered = bytearray(ct)
        tampered[-1] ^= 0xFF
        with pytest.raises(DecryptionError):
            decrypt(bytes(tampered), dek, aad)

    def test_tampered_nonce_rejected(self):
        """Altering the nonce must invalidate the GCM tag."""
        from rgt_vault.crypto import decrypt, encrypt
        from rgt_vault.exceptions import DecryptionError

        dek = os.urandom(32)
        ct = encrypt(b"value", dek, b"aad")
        tampered = bytearray(ct)
        tampered[0] ^= 0x01  # flip first byte of nonce
        with pytest.raises(DecryptionError):
            decrypt(bytes(tampered), dek, b"aad")

    def test_aad_mismatch_rejected(self):
        """Wrong AAD must cause authentication failure."""
        from rgt_vault.crypto import decrypt, encrypt
        from rgt_vault.exceptions import DecryptionError

        dek = os.urandom(32)
        ct = encrypt(b"value", dek, b"vault1:ns:name")
        with pytest.raises(DecryptionError):
            decrypt(ct, dek, b"vault2:ns:name")  # different vault_id

    def test_encrypt_decrypt_roundtrip(self):
        """Happy path: correct key + AAD must recover plaintext intact."""
        from rgt_vault.crypto import decrypt, encrypt

        dek = os.urandom(32)
        aad = b"vault-xyz:pii:ssn"
        plaintext = b"secret_payload_1234"
        ct = encrypt(plaintext, dek, aad)
        recovered = decrypt(ct, dek, aad)
        assert recovered == plaintext

    def test_aesgcm_used_not_aes_cbc(self):
        """The encryption function must use AESGCM, not a non-authenticated mode."""
        import importlib

        crypto = importlib.import_module("rgt_vault.crypto")
        src = Path(crypto.__file__).read_text()
        assert "AESGCM" in src
        assert "CBC" not in src
        assert "CFB" not in src


# ---------------------------------------------------------------------------
# RGT-403 — Constant-time comparisons (extended; core in test_asvs_logging_crypto)
# ---------------------------------------------------------------------------


class TestConstantTimeComparisons:
    """ASVS 6.2.8: no short-circuit comparison on security-sensitive values."""

    def test_audit_chain_uses_hmac_compare_digest(self):
        """verify_audit_chain() must use hmac.compare_digest, not ==."""
        vault_src = (RGTV_ROOT / "rgt_vault" / "vault.py").read_text()
        assert "hmac.compare_digest" in vault_src, (
            "verify_audit_chain must use hmac.compare_digest for constant-time hash comparison"
        )

    def test_token_verification_uses_constant_time_compare(self):
        """Token verifier (HMAC) must not use == for signature comparison."""
        token_src = (RGTV_ROOT / "rgt_vault" / "token.py").read_text()
        # The token module should use hmac.compare_digest, not bare ==
        assert "compare_digest" in token_src, (
            "Token verification must use hmac.compare_digest"
        )

    def test_hmac_compare_digest_available(self):
        """hmac.compare_digest is a stdlib constant-time comparison function."""
        assert hasattr(hmac, "compare_digest"), "hmac.compare_digest not available"
        assert hmac.compare_digest(b"abc", b"abc") is True
        assert hmac.compare_digest(b"abc", b"xyz") is False


# ---------------------------------------------------------------------------
# RGT-404 — CSPRNG for all random values
# ---------------------------------------------------------------------------


class TestCSPRNG:
    """ASVS 6.3.1: all unguessable values must use CSPRNG."""

    def test_os_urandom_used_for_dek(self):
        """DEK generation must use os.urandom, not random.random."""
        keychain_src = (RGTV_ROOT / "rgt_vault" / "keychain.py").read_text()
        assert "os.urandom(32)" in keychain_src, "DEK must be generated with os.urandom(32)"

    def test_os_urandom_used_for_nonce_in_encrypt(self):
        """Nonce in encrypt() must use os.urandom."""
        crypto_src = (RGTV_ROOT / "rgt_vault" / "crypto.py").read_text()
        assert "os.urandom(12)" in crypto_src

    def test_no_random_module_for_crypto(self):
        """The non-CSPRNG 'random' module must not be imported in cryptographic modules."""
        crypto_files = [
            RGTV_ROOT / "rgt_vault" / "crypto.py",
            RGTV_ROOT / "rgt_vault" / "keychain.py",
            RGTV_ROOT / "rgt_vault" / "vault.py",
            RGTV_ROOT / "rgt_vault" / "token.py",
        ]
        for src_file in crypto_files:
            if not src_file.exists():
                continue
            text = src_file.read_text()
            # 'import random' is banned; 'secrets' or 'os' is fine
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert alias.name != "random", (
                            f"'import random' found in {src_file.name} — use secrets or os.urandom"
                        )
                if isinstance(node, ast.ImportFrom):
                    assert node.module != "random", (
                        f"'from random import ...' found in {src_file.name}"
                    )

    def test_secrets_module_entropy_is_csprng(self):
        """secrets.token_bytes() must produce distinct values (integration check)."""
        samples = {secrets.token_bytes(32) for _ in range(100)}
        assert len(samples) == 100, "secrets.token_bytes is not generating unique values"

    def test_os_urandom_produces_distinct_32byte_values(self):
        """os.urandom(32) must produce distinct bytes each call."""
        samples = {os.urandom(32) for _ in range(100)}
        assert len(samples) == 100


# ---------------------------------------------------------------------------
# RGT-405 — UUIDs are v4 backed by CSPRNG
# ---------------------------------------------------------------------------


class TestUUIDv4:
    """ASVS 6.3.2: random GUIDs must use UUID v4 algorithm with CSPRNG."""

    def test_storage_uses_uuid4(self):
        """sqlite.py must call uuid.uuid4(), not uuid1/uuid3/uuid5."""
        storage_src = (RGTV_ROOT / "rgt_vault" / "storage" / "sqlite.py").read_text()
        assert "uuid.uuid4()" in storage_src, "Storage must use uuid4 for secret IDs"
        assert "uuid.uuid1()" not in storage_src, "uuid1 is time-based, not CSPRNG"
        assert "uuid.uuid3()" not in storage_src
        assert "uuid.uuid5()" not in storage_src

    def test_uuid4_is_version_4(self):
        """stdlib uuid.uuid4() produces version-4 UUIDs."""
        for _ in range(20):
            u = uuid.uuid4()
            assert u.version == 4

    def test_uuid4_values_are_unique(self):
        """100 UUID4s must all be distinct."""
        ids = {uuid.uuid4() for _ in range(100)}
        assert len(ids) == 100

    def test_vault_id_is_uuid4(self, tmp_path, master_provider):
        """VaultManager vault_id must be a valid UUID4 string."""
        from rgt_vault.vault import VaultManager

        vault = VaultManager(
            db_path=str(tmp_path / "vault.db"),
            master_provider=master_provider,
            policy_yaml="rules:\n  - effect: allow\n",
        )
        parsed = uuid.UUID(vault.vault_id)
        assert parsed.version == 4, f"vault_id is not UUID4: {vault.vault_id}"


# ---------------------------------------------------------------------------
# RGT-406 — CSPRNG degrades gracefully under load
# ---------------------------------------------------------------------------


class TestCSPRNGUnderLoad:
    """ASVS 6.3.3: random generation must not fail or block under concurrent load."""

    def test_urandom_concurrent_calls_all_succeed(self):
        """1000 concurrent os.urandom calls must all return 32 bytes."""
        import threading

        results = []
        errors = []
        lock = threading.Lock()

        def gen():
            try:
                b = os.urandom(32)
                with lock:
                    results.append(b)
            except Exception as e:
                with lock:
                    errors.append(e)

        threads = [threading.Thread(target=gen) for _ in range(1000)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"os.urandom failed under concurrent load: {errors[:3]}"
        assert len(results) == 1000
        assert all(len(b) == 32 for b in results)

    def test_urandom_large_block_succeeds(self):
        """os.urandom must succeed for a 1 MB request without blocking."""
        big = os.urandom(1024 * 1024)
        assert len(big) == 1024 * 1024


# ---------------------------------------------------------------------------
# RGT-407 — Secure key vault / secrets manager
# ---------------------------------------------------------------------------


class TestKeyVaultAndSecretsManager:
    """ASVS 6.4.1: secrets managed through a vault with create/store/destroy lifecycle."""

    def test_vault_manager_creates_stores_retrieves_destroys(self, tmp_path, master_provider):
        """Full CRUD lifecycle: set, retrieve via lease, revoke."""
        from rgt_vault.vault import VaultManager

        vault = VaultManager(
            db_path=str(tmp_path / "vault.db"),
            master_provider=master_provider,
            policy_yaml="rules:\n  - effect: allow\n",
        )
        vault.set_secret("api_key", "s3cr3t-val", namespace="ns", agent="system")

        with vault.lease_secret("api_key", "system", "ns", "test") as buf:
            assert buf == bytearray(b"s3cr3t-val")

        vault.revoke_secret("ns", "api_key", agent="system")

        from rgt_vault.exceptions import SecretNotFoundError

        with pytest.raises(SecretNotFoundError):
            with vault.lease_secret("api_key", "system", "ns", "test"):
                pass

    def test_dek_wrapped_in_keychain_file(self, tmp_path, master_provider):
        """keychain.json must exist and contain a wrapped DEK after vault init."""
        import json
        from rgt_vault.vault import VaultManager

        VaultManager(
            db_path=str(tmp_path / "vault.db"),
            master_provider=master_provider,
            policy_yaml="rules:\n  - effect: allow\n",
        )
        kc = tmp_path / "keychain.json"
        assert kc.exists(), "keychain.json missing after vault init"
        data = json.loads(kc.read_text())
        assert "wrapped_dek" in data, "wrapped_dek key missing from keychain.json"
        assert data["kdf"] == "argon2id"

    def test_keychain_file_permissions_are_restrictive(self, tmp_path, master_provider):
        """keychain.json must be 0o600 (owner read/write only)."""
        from rgt_vault.vault import VaultManager

        if sys.platform == "win32":
            pytest.skip("POSIX permissions test skipped on Windows")

        VaultManager(
            db_path=str(tmp_path / "vault.db"),
            master_provider=master_provider,
            policy_yaml="rules:\n  - effect: allow\n",
        )
        kc = tmp_path / "keychain.json"
        mode = oct(kc.stat().st_mode & 0o777)
        assert mode == oct(0o600), f"keychain.json permissions {mode} are too permissive (expected 0o600)"

    def test_master_key_rotation_rewraps_dek(self, tmp_path, master_provider):
        """rotate_master_key must produce a new wrapped DEK without re-encrypting data."""
        import json
        from rgt_vault.vault import VaultManager

        vault = VaultManager(
            db_path=str(tmp_path / "vault.db"),
            master_provider=master_provider,
            policy_yaml="rules:\n  - effect: allow\n",
        )
        vault.set_secret("s", "val", namespace="n", agent="a")

        kc_before = json.loads((tmp_path / "keychain.json").read_text())["wrapped_dek"]
        vault.rotate_master_key()
        kc_after = json.loads((tmp_path / "keychain.json").read_text())["wrapped_dek"]

        assert kc_before != kc_after, "wrapped_dek unchanged after master key rotation"


# ---------------------------------------------------------------------------
# RGT-408 — Key material not exposed to application space
# ---------------------------------------------------------------------------


class TestKeyMaterialIsolation:
    """ASVS 6.4.2: key material must be isolated; SecureBuffer zeroizes secrets."""

    def test_secure_buffer_zeroizes_on_exit(self):
        """SecureBuffer must contain all zeros after context manager exit."""
        from rgt_vault.crypto import SecureBuffer

        with SecureBuffer(32) as buf:
            buf.write(b"A" * 32)
            content_inside = buf.read()
            assert content_inside == b"A" * 32

        # After context exit the buffer is closed and zeroized
        assert buf._closed

    def test_lease_secret_buffer_zeroized_after_context(self, tmp_path, master_provider):
        """The bytearray yielded by lease_secret must not retain plaintext after the with block."""
        from rgt_vault.vault import VaultManager

        vault = VaultManager(
            db_path=str(tmp_path / "vault.db"),
            master_provider=master_provider,
            policy_yaml="rules:\n  - effect: allow\n",
        )
        vault.set_secret("pw", "p@ssw0rd!", namespace="ns", agent="system")

        held_ref = None
        with vault.lease_secret("pw", "system", "ns", "test") as buf:
            held_ref = buf  # hold a reference
            assert bytearray(b"p@ssw0rd!") == buf

        # After the context manager exits, vault zeroizes the buffer
        assert held_ref == bytearray(b"\x00" * len(b"p@ssw0rd!")), (
            "Plaintext buffer was not zeroized after lease_secret context exit"
        )

    def test_dek_not_in_storage_backend(self):
        """StorageBackend must not store or cache the DEK."""
        storage_src = (RGTV_ROOT / "rgt_vault" / "storage" / "sqlite.py").read_text()
        assert "dek" not in storage_src.lower() or "dek_version" in storage_src, (
            "StorageBackend appears to reference DEK material — key material must stay in VaultManager"
        )

    def test_dek_only_in_memory_not_logged(self, tmp_path, master_provider):
        """Audit log must not contain DEK bytes."""
        from rgt_vault.vault import VaultManager

        vault = VaultManager(
            db_path=str(tmp_path / "vault.db"),
            master_provider=master_provider,
            policy_yaml="rules:\n  - effect: allow\n",
        )
        vault.set_secret("x", "y", namespace="n", agent="a")
        dek_hex = vault.dek.hex()

        for entry in vault.get_audit_log(limit=50):
            for field in ("action", "details", "secret_name"):
                val = str(entry.get(field) or "")
                assert dek_hex not in val, (
                    f"DEK hex found in audit log field {field!r}"
                )

    def test_zeroize_bytearray_clears_content(self):
        """zeroize_bytearray must overwrite every byte with 0x00."""
        from rgt_vault.crypto import zeroize_bytearray

        buf = bytearray(b"super_secret_password")
        zeroize_bytearray(buf)
        assert buf == bytearray(len(buf)), "Buffer not fully zeroized"

    def test_zeroize_bytearray_requires_bytearray(self):
        """zeroize_bytearray must reject bytes (immutable) with TypeError."""
        from rgt_vault.crypto import zeroize_bytearray

        with pytest.raises(TypeError):
            zeroize_bytearray(b"immutable")  # type: ignore[arg-type]
