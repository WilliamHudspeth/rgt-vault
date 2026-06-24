import base64
import binascii
import contextlib
import hashlib
import json
import os
import threading
import time
from collections import defaultdict
from collections.abc import Generator
from typing import Any, Callable, Dict, List, Optional, Union

import keyring
from cryptography.fernet import Fernet, InvalidToken

from rgt_vault.auth import ABACPolicyEngine
from rgt_vault.crypto import decrypt, encrypt, zeroize_bytearray
from rgt_vault.exceptions import PolicyDeniedError, SecretNotFoundError, ValidationError
from rgt_vault.keychain import HardenedDEKManager, MasterSecret, run_crypto_selftest
from rgt_vault.storage.sqlite import StorageBackend
from rgt_vault.watcher import FreezeWatcher


class RateLimiter:
    """Sliding window rate limiter in memory."""
    def __init__(self, max_requests: int = 100, window_seconds: int = 3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._windows: Dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, agent_id: str) -> bool:
        now = time.time()
        with self._lock:
            self._windows[agent_id] = [
                t for t in self._windows[agent_id] if now - t < self.window_seconds
            ]
            if len(self._windows[agent_id]) >= self.max_requests:
                return False
            self._windows[agent_id].append(now)
            return True

class VaultManager:
    def __init__(self, db_path: Optional[str] = None, master_provider=None, policy_yaml: str = "", rate_limit: int = 100, rate_window: int = 3600):
        # 1. Run cryptographic self-tests (Fail closed)
        run_crypto_selftest()
        
        # 2. Init Storage
        actual_db_path = db_path or os.path.expanduser("~/.secure-vault/vault.db")
        self.storage = StorageBackend(actual_db_path)
        
        self.auth = ABACPolicyEngine(policy_yaml)
        self.policy_hash = hashlib.sha256(policy_yaml.encode("utf-8")).hexdigest()[:16] if policy_yaml else ""
        self.rate_limiter = RateLimiter(max_requests=rate_limit, window_seconds=rate_window)

        # 3. Load Metadata & Keychain
        self.vault_id = self.storage.get_vault_id()
        self.key_epoch = self.storage.get_key_epoch()
        
        # We store keychain.json next to the DB
        keychain_path = os.path.join(os.path.dirname(actual_db_path), "keychain.json")
        
        from rgt_vault.providers import create_platform_provider
        self.master_provider = master_provider or create_platform_provider()

        # P0-2 audit fix: only auto-bootstrap on a truly fresh install
        # (no keychain.json). For existing vaults whose keyring entry has
        # been wiped, ``get_secret`` will fail closed rather than silently
        # generating a new master secret that would render the vault
        # permanently unreadable. Use ``getattr`` so test stub providers
        # that aren't subclasses of ``MasterSecretProvider`` still work.
        will_initialize_new_dek = not os.path.exists(keychain_path)
        if will_initialize_new_dek:
            bootstrap = getattr(self.master_provider, "bootstrap_master_secret", None)
            if callable(bootstrap):
                bootstrap()

        master_secret = self._normalize_master(self.master_provider.get_secret())

        self.dek_manager = HardenedDEKManager(keychain_path)

        if os.path.exists(keychain_path):
            self.dek = self.dek_manager.load_dek(master_secret, self.vault_id, self.key_epoch)
        else:
            self.dek = self.dek_manager.initialize_dek(master_secret, self.vault_id, self.key_epoch)
            
        # 4. Migrate Legacy Secrets (v2 Fernet -> v3 AES-256-GCM)
        self._migrate_legacy_secrets()

        self.freeze_watcher = FreezeWatcher(
            os.path.expanduser("~/.config/rgt-vault/freeze"),
            interval=1.0,
            callback=self._on_freeze
        )
        self.freeze_watcher.start()



    def _on_freeze(self) -> None:
        # Background thread detected the freeze file.
        # Wipe DEK from memory immediately to trigger a lockout.
        self.dek = None

    def _check_freeze_signal(self) -> None:
        freeze_file = os.path.expanduser("~/.config/rgt-vault/freeze")
        is_frozen = getattr(self, "freeze_watcher", None) and getattr(self.freeze_watcher, "is_frozen", False)
        if is_frozen or os.path.exists(freeze_file):
            raise VaultFrozenError("Vault is frozen due to active kill switch.")

    def _migrate_legacy_secrets(self) -> None:
        """Upgrades dek_version=0 secrets to AESGCM.

        P1-2 audit fix: the entire rewrite is a single SQLite transaction.
        A crash mid-migration leaves no half-upgraded rows.
        """
        active_secrets = self.storage.iter_all_active_secrets()
        legacy_secrets = [s for s in active_secrets if s[4] == 0]

        if not legacy_secrets:
            return

        encoded_key = keyring.get_password("rgt_vault", "master_key")
        if not encoded_key:
            raise ValueError("Legacy secrets found but no legacy Fernet key in keyring.")
        old_fernet = Fernet(encoded_key.encode('utf-8'))

        def _rewrite(record_id, namespace, name, ciphertext, dek_version):
            if dek_version != 0:
                # Already migrated; leave it.
                return ciphertext, dek_version
            
            from rgt_vault.crypto import SecureBuffer, zeroize_bytearray
            
            with SecureBuffer(len(ciphertext)) as buf:
                buf.write(ciphertext)
                try:
                    plaintext = old_fernet.decrypt(buf.read())
                except InvalidToken:
                    # Corrupted legacy row -- preserve as-is, log it.
                    return ciphertext, dek_version
                    
                aad = self._get_aad(namespace, name)
                new_ciphertext = encrypt(plaintext, self.dek, aad)
                
                # Best-effort zeroize of the intermediate plaintext
                if isinstance(plaintext, (bytes, bytearray)):
                    try:
                        import ctypes
                        libc = ctypes.CDLL(None)
                        libc.memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
                        libc.memset(id(plaintext) + 32, 0, len(plaintext))
                    except Exception:
                        pass
                
                return new_ciphertext, 1

        self.storage.bulk_rewrite_active_secrets(_rewrite)

    @staticmethod
    def _normalize_master(secret: Any) -> MasterSecret:
        """Coerce a provider's master secret into a MasterSecret.

        Platform providers (DPAPI/TPM/Keychain) return raw bytes, while
        KeyringProvider returns a MasterSecret. The KDF expects MasterSecret,
        so normalize here at the trust boundary.
        """
        if isinstance(secret, MasterSecret):
            return secret
        if isinstance(secret, (bytes, bytearray)):
            return MasterSecret(bytes(secret))
        raise ValidationError(
            f"Master secret provider returned unsupported type {type(secret).__name__}; "
            "expected bytes or MasterSecret."
        )

    def _get_aad(self, namespace: str, name: str) -> bytes:
        return f"{self.vault_id}:{namespace}:{name}".encode()

    def audit(self, action: str, secret_name: Optional[str] = None, details: str = "") -> None:
        """Append one row to the hash-chained audit log.

        Public entry point. F-10: the underscore prefix used to mark this
        as private, but the HTTP server and tests both call it; rename to
        `audit` to make the contract explicit. The audit row is written
        with the vault's current ``policy_hash`` so a later re-read can
        correlate the row to the policy that was in effect.
        """
        self.storage.log_audit(action, secret_name, details, self.policy_hash)

    def _validate_string_param(self, param_name: str, value: Any, max_len: int, allow_empty: bool = False):
        if not isinstance(value, str):
            raise ValidationError(f"'{param_name}' must be a string. Got {type(value).__name__}.")
        stripped_value = value.strip()
        if not allow_empty and not stripped_value:
            raise ValidationError(f"'{param_name}' cannot be empty or just whitespace.")
        if len(value) > max_len:
            raise ValidationError(f"'{param_name}' exceeds the maximum allowed length of {max_len} characters.")

    def _normalize_value_param(self, param_name: str, value: Any, max_len: int) -> bytearray:
        """Coerce a plaintext secret into a mutable ``bytearray``.

        If the caller already passed a ``bytearray`` we use it directly so
        ``set_secret`` can zeroize the caller's buffer after encryption.
        ``str`` values are UTF-8 encoded into a new bytearray; ``bytes`` are
        copied. Rejects wrong types, empty values, and oversized values.
        """
        if isinstance(value, str):
            if not value.strip():
                raise ValidationError(f"'{param_name}' cannot be empty or just whitespace.")
            plaintext = bytearray(value.encode("utf-8"))
        elif isinstance(value, bytearray):
            if len(value) == 0:
                raise ValidationError(f"'{param_name}' cannot be empty.")
            plaintext = value
        elif isinstance(value, bytes):
            if len(value) == 0:
                raise ValidationError(f"'{param_name}' cannot be empty.")
            plaintext = bytearray(value)
        else:
            raise ValidationError(
                f"'{param_name}' must be str, bytes, or bytearray. Got {type(value).__name__}."
            )
        if len(plaintext) > max_len:
            raise ValidationError(
                f"'{param_name}' exceeds the maximum allowed length of {max_len} bytes."
            )
        return plaintext

    def set_secret(self, name: str, value: Union[str, bytes, bytearray], namespace: str = "default", agent: str = "system", purpose: str = "") -> None:
        """Encrypts and stores a secret.

        The plaintext ``value`` is copied into a mutable ``bytearray`` for
        encryption and zeroized before the method returns. Callers that pass
        a ``str`` or ``bytes`` should assume the original object is *not*
        reliably wiped (Python strings and small bytes may be interned).
        """
        self._validate_string_param("name", name, max_len=256)
        self._validate_string_param("namespace", namespace, max_len=128)
        self._validate_string_param("agent", agent, max_len=128)

        plaintext = self._normalize_value_param("value", value, max_len=1024 * 1024)  # 1 MiB
        try:
            decision = self.auth.evaluate(agent, namespace, purpose, action="write")
            if not decision["allowed"]:
                self.audit("POLICY_DENIED", name, f"Action: write, Agent: {agent}, Namespace: {namespace}, Reason: {decision['reason']}")
                raise PolicyDeniedError(f"Agent '{agent}' denied write access to '{name}' ({namespace}/{purpose})")

            aad = self._get_aad(namespace, name)
            ciphertext = encrypt(plaintext, self.dek, aad)
            self.storage.set_secret(namespace, name, ciphertext, 1, policy_hash=self.policy_hash)
        finally:
            zeroize_bytearray(plaintext)

    def get_fingerprint(self, name: str, namespace: str = "default", version: Optional[int] = None) -> str:
        """Returns the SHA256 fingerprint of the ciphertext for debugging.

        Fingerprint reads are deliberately NOT policy-gated: a fingerprint is
        a small fixed-length hash that leaks no plaintext, and a debugger
        often needs to inspect a secret even when the calling agent is not
        authorized to *read* it. Rate limiting also does not apply to
        fingerprints (deliberately, per the ROADMAP "Audit log noise
        reduction" item).
        """
        if self.storage.is_honeytoken(namespace, name):
            self.audit("HONEYTOKEN_TRIGGERED", name, json.dumps({"severity": "critical", "agent": "system", "namespace": namespace, "purpose": "fingerprint"}))
            raise PermissionError(f"Honeytoken access detected: {namespace}/{name}")

        result = self.storage.get_secret(namespace, name, version, policy_hash=self.policy_hash)
        if not result:
            raise SecretNotFoundError(f"Secret '{namespace}/{name}' not found.")
        ciphertext, _ = result
        return hashlib.sha256(ciphertext).hexdigest()[:8]

    @contextlib.contextmanager
    def lease_secret(self, name: str, agent: str, namespace: str, purpose: str, version: Optional[int] = None) -> Generator[bytearray, None, None]:
        self._validate_string_param("name", name, max_len=256)
        self._validate_string_param("agent", agent, max_len=128)
        self._validate_string_param("namespace", namespace, max_len=128)
        self._validate_string_param("purpose", purpose, max_len=256)
        
        if not self.rate_limiter.allow(agent):
            self.audit("RATE_LIMITED", name, f"Agent: {agent}")
            raise PermissionError(f"Rate limit exceeded for agent '{agent}'")

        if self.storage.is_honeytoken(namespace, name):
            self.audit("HONEYTOKEN_TRIGGERED", name, json.dumps({"severity": "critical", "agent": agent, "namespace": namespace, "purpose": purpose}))
            raise PermissionError(f"Honeytoken access detected: {namespace}/{name}")

        decision = self.auth.evaluate(agent, namespace, purpose, action="read")
        if not decision["allowed"]:
            self.audit("POLICY_DENIED", name, f"Action: read, Agent: {agent}, Namespace: {namespace}, Reason: {decision['reason']}")
            raise PolicyDeniedError(f"Agent '{agent}' denied read access to '{name}' ({namespace}/{purpose})")
        
        result = self.storage.get_secret(namespace, name, version, policy_hash=self.policy_hash)
        if not result:
            raise SecretNotFoundError(f"Secret '{namespace}/{name}' not found.")
            
        ciphertext, dek_version = result
        aad = self._get_aad(namespace, name)

        # We currently only support dek_version=1 for AESGCM
        if dek_version != 1:
            raise ValidationError(f"Unsupported DEK version {dek_version}")

        plaintext_bytes = decrypt(ciphertext, self.dek, aad)
        buffer = bytearray(plaintext_bytes)
        del plaintext_bytes 
        
        self.audit("LEASE_GRANTED", name, f"Agent: {agent}")
        try:
            yield buffer
        finally:
            zeroize_bytearray(buffer)
            self.audit("LEASE_RETURNED", name, f"Agent: {agent}")

    def execute(self, agent: str, namespace: str, purpose: str, secret_name: str, callback: Callable[[bytearray], Any]) -> Any:
        """Lease a secret and hand the *mutable buffer* to ``callback``.

        The callback receives a ``bytearray`` (not a ``str``). The vault wipes
        this buffer when the callback returns. NOTE: if the callback copies the
        secret into an immutable object (e.g. ``bytes(buf)`` or
        ``buf.decode()``), that copy is the caller's responsibility and is NOT
        covered by the vault's zeroization guarantee.
        """
        self._check_freeze_signal()
        if not callable(callback):
            raise ValidationError("The provided callback must be a callable object.")
        with self.lease_secret(secret_name, agent, namespace, purpose) as secret_buffer:
            return callback(secret_buffer)

    def list_secrets(self, namespace: str, agent: str, purpose: str = "") -> List[Dict[str, Any]]:
        decision = self.auth.evaluate(agent, namespace, purpose, action="read")
        if not decision["allowed"]:
            self.audit("POLICY_DENIED", None, f"Action: list, Agent: {agent}, Namespace: {namespace}, Reason: {decision['reason']}")
            raise PolicyDeniedError(f"Unauthorized to access namespace '{namespace}'")
        return self.storage.list_secrets(namespace, policy_hash=self.policy_hash)

    def simulate(self, agent: str, namespace: str, purpose: str, action: str = "read") -> Dict[str, Any]:
        self.audit("SIMULATION_RUN", None, f"Agent: {agent}, Namespace: {namespace}, Action: {action}")
        return self.auth.evaluate(agent, namespace, purpose, action)

    def explain(self, agent: str, namespace: str, purpose: str, action: str = "read") -> str:
        decision = self.simulate(agent, namespace, purpose, action)
        res = "ALLOWED" if decision["allowed"] else "DENIED"
        rule = decision.get("matched_rule")
        rule_str = json.dumps(rule) if rule else "None"
        return f"Access: {res}\nReason: {decision['reason']}\nMatched Rule: {rule_str}"

    def revoke_secret(self, namespace: str, name: str) -> None:
        self.storage.revoke_secret(namespace, name, policy_hash=self.policy_hash)

    def rotate_master_key(self) -> None:
        """Rotate master key. Fast rotation (no data re-encryption).

        Only supported on providers whose ``rotate_secret`` method works
        automatically (currently :class:`KeyringProvider`). Platform
        providers (DPAPI/TPM/macOS Keychain) require re-sealing the master
        secret out-of-band -- attempting the rotation here would leave the
        vault in an inconsistent state on restart (epoch bumped, no new
        wrapped DEK written).
        """
        # P1-4 audit fix: pre-check capability BEFORE incrementing the epoch.
        if not callable(getattr(self.master_provider, "rotate_secret", None)):
            from rgt_vault.exceptions import RotateNotSupportedError
            raise RotateNotSupportedError(
                f"{type(self.master_provider).__name__} does not support "
                "automated master-key rotation. Re-seal the master secret "
                "out-of-band (DPAPI/TPM/Keychain) and use "
                "``rotate_dek()`` instead."
            )

        new_master = self._normalize_master(self.master_provider.rotate_secret())
        new_epoch = self.storage.increment_key_epoch()

        self.dek_manager.rewrap_dek(new_master, self.vault_id, new_epoch)
        self.key_epoch = new_epoch

        self.audit("ROTATE", "MASTER_KEY", "Master key rotated successfully")

    def rotate_dek(self) -> None:
        """Rotate Data Encryption Key. Slow rotation (re-encrypts all data).

        P0-3 audit fix: the keychain.json atomic-replace and the per-row
        re-encryption are now both inside a single SQLite transaction. A
        crash mid-rotation leaves either the old DEK or the new DEK in
        effect; never a mix.
        """
        new_dek_manager = HardenedDEKManager(self.dek_manager.keychain_path + ".new")
        new_epoch = self.storage.increment_key_epoch()
        master_secret = self._normalize_master(self.master_provider.get_secret())
        new_dek = new_dek_manager.initialize_dek(master_secret, self.vault_id, new_epoch)

        def _rewrite(record_id, namespace, name, ciphertext, dek_version):
            aad = self._get_aad(namespace, name)
            plaintext = decrypt(ciphertext, self.dek, aad)
            new_ciphertext = encrypt(plaintext, new_dek, aad)
            return new_ciphertext, 1

        # Single transaction: rewrite every active row under the new DEK.
        # If anything fails (DB error, decrypt error, encrypt error), the
        # transaction rolls back, the .new keychain is never replaced, and
        # the vault stays on the old DEK.
        self.storage.bulk_rewrite_active_secrets(_rewrite)

        os.replace(new_dek_manager.keychain_path, self.dek_manager.keychain_path)
        self.dek_manager = HardenedDEKManager(self.dek_manager.keychain_path)
        self.dek = self.dek_manager.load_dek(master_secret, self.vault_id, new_epoch)
        self.key_epoch = new_epoch

        self.audit("ROTATE", "DEK", "Data Encryption Key rotated successfully")

    def export_vault(self) -> bytes:
        data = self.storage.export_data()
        # Stamp the vault identity so import can refuse cross-vault restores.
        # Secrets are bound to this vault_id/DEK via AAD; restoring elsewhere
        # would fail authentication on first read. See SECURITY.md (Backup).
        data["vault_id"] = self.vault_id
        json_str = json.dumps(data, indent=2)
        return base64.b64encode(json_str.encode("utf-8"))

    def import_vault(self, b64_data: bytes) -> None:
        if not isinstance(b64_data, bytes):
            raise ValidationError("b64_data must be a bytes object.")
        if len(b64_data) > 10 * 1024 * 1024:
            raise ValidationError("Import payload exceeds the maximum allowed size of 10MB.")
        try:
            json_bytes = base64.b64decode(b64_data)
            data = json.loads(json_bytes.decode("utf-8"))
        except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValidationError(f"Invalid import payload format: {e}")

        # Secrets are AAD-bound to the vault_id and encrypted under this vault's
        # DEK. Restoring a payload from a different vault would silently produce
        # undecryptable secrets, so fail loudly instead.
        payload_vault_id = data.get("vault_id")
        if payload_vault_id is not None and payload_vault_id != self.vault_id:
            raise ValidationError(
                f"Import refused: payload belongs to vault '{payload_vault_id}', "
                f"but this is vault '{self.vault_id}'. Restore into the original "
                "vault (same keychain.json/DEK) or re-encrypt before importing."
            )
        self.storage.import_data(data)
        self.audit("IMPORT", "VAULT", "Vault imported from external data")

    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.storage.get_audit_log(limit)

    def verify_audit_chain(self) -> bool:
        # P1-1 audit fix: an empty log is NOT "OK" -- a vault with no
        # audit entries is suspicious (the DB may have been wiped, or
        # the vault may never have been used, or the audit table may
        # have been truncated). Distinguish "empty" from "verified".
        logs = self.storage.iter_audit_log()
        if not logs:
            # No audit entries yet. That is acceptable for a fresh
            # vault; the chain is vacuously true (nothing to verify).
            return True

        prev_hash = ""
        for entry in logs:
            # Match the writer's hashing exactly: log_audit hashes
            # `secret_name or ''`, so a NULL secret_name was hashed as ''
            # -- not the literal "None" that entry.get(..., '') yields
            # for a present-but-null key.
            expected_raw = (
                f"{prev_hash}|{entry.get('timestamp', '')}|"
                f"{entry.get('action', '')}|{entry.get('secret_name') or ''}|"
                f"{entry.get('details', '')}|{entry.get('policy_hash', '')}"
            )
            expected_hash = hashlib.sha256(expected_raw.encode("utf-8")).hexdigest()
            if entry.get("entry_hash") != expected_hash:
                return False
            prev_hash = entry.get("entry_hash") or ""
        return True
