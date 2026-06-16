import base64
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import keyring
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from rgt_vault.providers.base import MasterSecretProvider

# ============================================================
# Dataclasses & Interfaces
# ============================================================

@dataclass(frozen=True)
class MasterSecret:
    value: bytes

@dataclass(frozen=True)
class DerivedKeyMaterial:
    key: bytes
    nonce: bytes

class KeyringProvider(MasterSecretProvider):
    def __init__(self, service_name: str = "rgt_vault", username: str = "master_key"):
        self.service_name = service_name
        self.username = username

    def get_secret(self) -> MasterSecret:
        encoded = keyring.get_password(self.service_name, self.username)
        if not encoded:
            # Generate one if missing (32 bytes entropy)
            raw = os.urandom(32)
            encoded = base64.urlsafe_b64encode(raw).decode('utf-8')
            keyring.set_password(self.service_name, self.username, encoded)
            return MasterSecret(raw)
        
        # Add padding if needed for older Fernet keys
        padding = (4 - (len(encoded) % 4)) % 4
        if padding != 0:
            encoded += "=" * padding
        return MasterSecret(base64.urlsafe_b64decode(encoded))
        
    def rotate_secret(self) -> MasterSecret:
        raw = os.urandom(32)
        encoded = base64.urlsafe_b64encode(raw).decode('utf-8')
        keyring.set_password(self.service_name, self.username, encoded)
        return MasterSecret(raw)

# ============================================================
# Cryptographic Primitives
# ============================================================

def _argon2_id_kdf(
    password: MasterSecret,
    salt: bytes,
    length: int = 32,
    memory_cost: int = 262144, # 256MB
    time_cost: int = 4,
    parallelism: int = 4
) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=length,
        memory_cost=memory_cost,
        iterations=time_cost,
        lanes=parallelism,
    )
    return kdf.derive(password.value)

def _hkdf_expand(
    input_key_material: bytes,
    info: bytes,
    length: int = 32,
    hash_algorithm=hashes.SHA256()
) -> bytes:
    hkdf = HKDF(
        algorithm=hash_algorithm,
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(input_key_material)

class AES256GCMWrapper:
    def wrap(self, plaintext: bytes, kek: bytes, nonce: bytes, aad: bytes) -> bytes:
        cipher = AESGCM(kek)
        return cipher.encrypt(nonce, plaintext, aad)

    def unwrap(self, ciphertext: bytes, kek: bytes, nonce: bytes, aad: bytes) -> bytes:
        cipher = AESGCM(kek)
        return cipher.decrypt(nonce, ciphertext, aad)

# ============================================================
# Orchestration
# ============================================================

class KeyDerivationOrchestrator:
    def __init__(self, memory_cost: int, time_cost: int, parallelism: int):
        self.memory_cost = memory_cost
        self.time_cost = time_cost
        self.parallelism = parallelism

    def _stage1_argon2_stretch(self, master: MasterSecret, salt: bytes) -> bytes:
        return _argon2_id_kdf(
            master, salt, 
            memory_cost=self.memory_cost, 
            time_cost=self.time_cost, 
            parallelism=self.parallelism
        )

    def _stage2_hkdf_extract_binding(self, intermediate: bytes, context: bytes, length: int = 64) -> bytes:
        hkdf = HKDF(algorithm=hashes.SHA512(), length=length, salt=None, info=context)
        return hkdf.derive(intermediate)

    def _stage3_derive_ops_key_and_nonce(self, binding_material: bytes) -> DerivedKeyMaterial:
        if len(binding_material) != 64:
            raise ValueError("Binding material must be exactly 64 bytes.")
        kek = binding_material[:32]
        nonce_raw = binding_material[32:]
        nonce = _hkdf_expand(nonce_raw, b"nonce expansion", length=12)
        return DerivedKeyMaterial(key=kek, nonce=nonce)

    def derive_wrapping_key_and_nonce(self, master: MasterSecret, salt: bytes, binding_context: bytes) -> DerivedKeyMaterial:
        intermediate = self._stage1_argon2_stretch(master, salt)
        binding = self._stage2_hkdf_extract_binding(intermediate, binding_context)
        return self._stage3_derive_ops_key_and_nonce(binding)

# ============================================================
# DEK Manager
# ============================================================

class HardenedDEKManager:
    def __init__(self, keychain_path: str):
        self.keychain_path = keychain_path
        self._dek: Optional[bytes] = None

    def initialize_dek(self, master: MasterSecret, vault_id: str, epoch: int,
                       memory_cost: int = 262144, time_cost: int = 4, parallelism: int = 4) -> bytes:
        dek = os.urandom(32)
        salt = os.urandom(32)
        
        orchestrator = KeyDerivationOrchestrator(memory_cost, time_cost, parallelism)
        binding_context = f"rgt-vault:{vault_id}".encode()
        
        key_mat = orchestrator.derive_wrapping_key_and_nonce(master, salt, binding_context)
        
        aad = f"{vault_id}:{epoch}".encode()
        wrapped = AES256GCMWrapper().wrap(dek, key_mat.key, key_mat.nonce, aad)
        
        data = {
            "version": 1,
            "kdf": "argon2id",
            "argon2_salt": base64.b64encode(salt).decode("utf-8"),
            "argon2_memory_cost": memory_cost,
            "argon2_time_cost": time_cost,
            "argon2_parallelism": parallelism,
            "wrapped_dek": base64.b64encode(wrapped).decode("utf-8"),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "key_epoch": epoch
        }
        
        os.makedirs(os.path.dirname(self.keychain_path), exist_ok=True)
        with open(self.keychain_path, "w") as f:
            json.dump(data, f, indent=2)
            
        self._dek = dek
        return dek

    def load_dek(self, master: MasterSecret, vault_id: str, expected_epoch: int) -> bytes:
        if not os.path.exists(self.keychain_path):
            raise FileNotFoundError("Keychain file not found.")
            
        with open(self.keychain_path) as f:
            data = json.load(f)
            
        if data.get("key_epoch") != expected_epoch:
            raise ValueError(f"Rollback attack detected! DB epoch {expected_epoch} does not match keychain epoch {data.get('key_epoch')}")
            
        salt = base64.b64decode(data["argon2_salt"])
        wrapped = base64.b64decode(data["wrapped_dek"])
        
        orchestrator = KeyDerivationOrchestrator(
            data["argon2_memory_cost"],
            data["argon2_time_cost"],
            data["argon2_parallelism"]
        )
        binding_context = f"rgt-vault:{vault_id}".encode()
        key_mat = orchestrator.derive_wrapping_key_and_nonce(master, salt, binding_context)
        
        aad = f"{vault_id}:{expected_epoch}".encode()
        dek = AES256GCMWrapper().unwrap(wrapped, key_mat.key, key_mat.nonce, aad)
        
        self._dek = dek
        return dek

    def rewrap_dek(self, master: MasterSecret, vault_id: str, epoch: int,
                   memory_cost: int = 262144, time_cost: int = 4, parallelism: int = 4) -> None:
        if not self._dek:
            raise ValueError("DEK must be loaded to rewrap it.")
            
        salt = os.urandom(32)
        orchestrator = KeyDerivationOrchestrator(memory_cost, time_cost, parallelism)
        binding_context = f"rgt-vault:{vault_id}".encode()
        
        key_mat = orchestrator.derive_wrapping_key_and_nonce(master, salt, binding_context)
        aad = f"{vault_id}:{epoch}".encode()
        wrapped = AES256GCMWrapper().wrap(self._dek, key_mat.key, key_mat.nonce, aad)
        
        data = {
            "version": 1,
            "kdf": "argon2id",
            "argon2_salt": base64.b64encode(salt).decode("utf-8"),
            "argon2_memory_cost": memory_cost,
            "argon2_time_cost": time_cost,
            "argon2_parallelism": parallelism,
            "wrapped_dek": base64.b64encode(wrapped).decode("utf-8"),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "key_epoch": epoch
        }
        
        with open(self.keychain_path, "w") as f:
            json.dump(data, f, indent=2)
        
    def get_active_dek(self) -> bytes:
        if not self._dek:
            raise ValueError("DEK is not loaded.")
        return self._dek

# ============================================================
# Crypto Self-Test
# ============================================================

def run_crypto_selftest() -> None:
    try:
        # Test Argon2
        master = MasterSecret(b"selftest_master")
        salt = b"selftest_salt" * 4
        orch = KeyDerivationOrchestrator(memory_cost=1024, time_cost=1, parallelism=1)
        kmat = orch.derive_wrapping_key_and_nonce(master, salt, b"test_context")
        
        # Test AESGCM
        wrapper = AES256GCMWrapper()
        plaintext = b"test_dek"
        aad = b"test_aad"
        ct = wrapper.wrap(plaintext, kmat.key, kmat.nonce, aad)
        pt = wrapper.unwrap(ct, kmat.key, kmat.nonce, aad)
        assert plaintext == pt, "AESGCM unwrap failed"
        
        # Test AAD integrity
        try:
            wrapper.unwrap(ct, kmat.key, kmat.nonce, b"wrong_aad")
            raise AssertionError("AESGCM allowed bad AAD")
        except InvalidTag:
            pass
            
    except Exception as e:
        raise RuntimeError(f"Cryptographic self-test failed: {e}")
