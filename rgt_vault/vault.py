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
from typing import Any, Callable, Dict, List, Optional

import keyring
from cryptography.fernet import Fernet, InvalidToken

from rgt_vault.auth import ABACPolicyEngine
from rgt_vault.capabilities import (
    CapabilityContext,
    CapabilityRegistry,
    register_builtin_capabilities,
)
from rgt_vault.crypto import decrypt, encrypt, zeroize_bytearray
from rgt_vault.exceptions import (
    CapabilityVersionError,
    PolicyDeniedError,
    SecretNotFoundError,
    ValidationError,
)
from rgt_vault.hook import AuditHook, HookDecision, HookRequest, OffHook
from rgt_vault.keychain import HardenedDEKManager, MasterSecret, run_crypto_selftest
from rgt_vault.shadow import NullShadowWriter, ShadowWriter
from rgt_vault.storage.sqlite import StorageBackend
from rgt_vault.token import (
    CapabilityV2Token,
    TokenBindingError,
    TokenError,
    TokenVerifier,
)


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
            self._windows[agent_id] = [t for t in self._windows[agent_id] if now - t < self.window_seconds]
            if len(self._windows[agent_id]) >= self.max_requests:
                return False
            self._windows[agent_id].append(now)
            return True


class VaultManager:
    def __init__(
        self,
        db_path: Optional[str] = None,
        master_provider=None,
        policy_yaml: str = "",
        rate_limit: int = 100,
        rate_window: int = 3600,
        hook: Optional[AuditHook] = None,
        capability_registry: Optional[CapabilityRegistry] = None,
        token_verifier: Optional[TokenVerifier] = None,
        shadow_writer: Optional["ShadowWriter"] = None,
    ):
        # 1. Run cryptographic self-tests (Fail closed)
        run_crypto_selftest()

        # 2. Init Storage
        actual_db_path = db_path or os.path.expanduser("~/.secure-vault/vault.db")
        self.storage = StorageBackend(actual_db_path)

        self.auth = ABACPolicyEngine(policy_yaml)
        self.policy_hash = hashlib.sha256(policy_yaml.encode("utf-8")).hexdigest()[:16] if policy_yaml else ""
        self.rate_limiter = RateLimiter(max_requests=rate_limit, window_seconds=rate_window)

        # Audit hook layer. Default is OffHook -- the vault behaves
        # exactly as it did before this layer existed. Operators
        # opt into a stricter hook at deploy time via the CLI flag
        # or programmatic construction.
        self.hook: AuditHook = hook if hook is not None else OffHook()

        # v0.3 capability path. The registry holds every callable
        # capability the vault can execute; the verifier is the trust
        # anchor for v2 capability tokens. Both are pluggable so tests
        # can pass fakes; in production the default verifier is the
        # HMAC one, which requires a shared secret to be set via the
        # ``RGT_VAULT_HARNESS_KEY`` env var. If no verifier is
        # configured, ``execute_capability`` will refuse to run --
        # capability execution MUST be authorized, and "no verifier"
        # is a hard fail-closed state.
        self.capability_registry: CapabilityRegistry = (
            capability_registry if capability_registry is not None else CapabilityRegistry()
        )
        if not list(self.capability_registry.list()):
            # Bootstrap the built-in capabilities on a fresh registry
            # so ``execute_capability("secrets.echo", ...)`` works
            # out of the box for operators wiring the system together.
            register_builtin_capabilities(self.capability_registry)
        self.token_verifier: Optional[TokenVerifier] = token_verifier

        # RGT-161 dual-write: optional shadow writer mirrors set/revoke to a
        # co-located Go server. Default is a disabled no-op so behaviour is
        # identical when shadowing is off. Python is always the source of
        # truth; shadow failures are recorded as divergences, never raised.
        self.shadow: ShadowWriter = shadow_writer if shadow_writer is not None else NullShadowWriter()

        # The action registry backs the ``secrets.use`` bridge
        # capability, which leases a stored secret and runs a v0.2
        # action against it. The vault owns the registry so the
        # bridge works in-process; the HTTP server's
        # ``build_app`` replaces it with its own (larger) registry
        # when the server is constructed.
        from rgt_vault.server.actions import (
            ActionRegistry as _AR,
        )
        from rgt_vault.server.actions import (
            register_builtin_actions as _reg_actions,
        )

        self.action_registry: _AR = _AR()
        _reg_actions(self.action_registry)

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
        old_fernet = Fernet(encoded_key.encode("utf-8"))

        def _rewrite(record_id, namespace, name, ciphertext, dek_version):
            if dek_version != 0:
                # Already migrated; leave it.
                return ciphertext, dek_version
            try:
                plaintext = old_fernet.decrypt(ciphertext)
            except InvalidToken:
                # Corrupted legacy row -- preserve as-is, log it. The audit
                # chain is unaffected because the rewrite is atomic and this
                # row's ciphertext+checksum remain unchanged.
                return ciphertext, dek_version
            aad = self._get_aad(namespace, name)
            new_ciphertext = encrypt(plaintext, self.dek, aad)
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
            f"Master secret provider returned unsupported type {type(secret).__name__}; expected bytes or MasterSecret."
        )

    def _get_aad(self, namespace: str, name: str) -> bytes:
        return f"{self.vault_id}:{namespace}:{name}".encode()

    def audit(self, event: str, secret_name: Optional[str], details: str) -> None:
        self._log_audit(event, secret_name, details)

    def _log_audit(self, action: str, secret_name: Optional[str] = None, details: str = "") -> None:
        self.storage.log_audit(action, secret_name, details, self.policy_hash)

    def _validate_string_param(self, param_name: str, value: Any, max_len: int, allow_empty: bool = False):
        if not isinstance(value, str):
            raise ValidationError(f"'{param_name}' must be a string. Got {type(value).__name__}.")
        stripped_value = value.strip()
        if not allow_empty and not stripped_value:
            raise ValidationError(f"'{param_name}' cannot be empty or just whitespace.")
        if len(value) > max_len:
            raise ValidationError(f"'{param_name}' exceeds the maximum allowed length of {max_len} characters.")

    def _hook_consult(
        self,
        operation: str,
        agent: str,
        namespace: str,
        purpose: str = "",
        secret_name: Optional[str] = None,
        capability_token: Optional[str] = None,
    ) -> None:
        """Consult the audit hook and raise on deny. Records the
        hook decision in the audit chain regardless of outcome.

        Called BEFORE the ABAC engine so that a harness can veto an
        op even if local policy would have allowed it (defense in
        depth: harness is the outer gate, ABAC is the local gate).

        This is the **legacy secret-access** hook consult path --
        the new :meth:`execute_capability` calls a sibling
        :meth:`_hook_consult_capability` instead. The two paths
        share the same hook instance; only the request shape differs.
        """
        req = HookRequest(
            operation=operation,
            agent=agent,
            namespace=namespace,
            purpose=purpose,
            secret_name=secret_name,
            capability_token=capability_token or "",
        )
        resp = self.hook.pre_op_check(req)
        # Record the hook decision. We log this separately from the
        # ABAC decision so the audit chain shows both layers.
        self._log_audit(
            f"HOOK_{operation.upper()}",
            secret_name,
            json.dumps(
                {
                    "hook_id": self.hook.hook_id,
                    **resp.to_audit_dict(),
                }
            ),
        )
        if resp.decision is not HookDecision.ALLOW:
            raise PolicyDeniedError(
                f"hook {self.hook.hook_id!r} denied {operation} for agent {agent!r}: {resp.reason or 'no reason given'}"
            )

    def _hook_consult_capability(
        self,
        *,
        agent: str,
        capability: str,
        capability_version: int,
        payload: Dict[str, Any],
        token_metadata: Dict[str, Any],
        capability_token: str,
    ) -> None:
        """Consult the audit hook on the capability path.

        Builds a capability-shaped :class:`HookRequest` and runs the
        same hook instance that backs the legacy secret-access path.
        Hooks that only care about secret access (e.g. legacy custom
        hooks) see the new fields as empty / "capability" operation
        and may deny; hooks that have been updated for the capability
        model can branch on ``req.is_capability``.

        When the hook is **frozen**, this raises immediately, before
        any token verification or capability dispatch -- matching the
        "kill switch" semantics the spec requires for ``execute_capability``.
        """
        # Freeze check happens first; ``pre_op_check`` returns a
        # FREEZE response which we then map to PolicyDeniedError
        # below. Doing the check separately here makes the intent
        # obvious in the audit log.
        if self.hook.frozen:
            self._log_audit(
                "HOOK_CAPABILITY",
                None,
                json.dumps(
                    {
                        "hook_id": self.hook.hook_id,
                        "decision": "freeze",
                        "reason": "vault frozen by hook",
                        "agent": agent,
                        "capability": capability,
                        "capability_version": capability_version,
                    }
                ),
            )
            raise PolicyDeniedError("vault frozen by hook")

        req = HookRequest(
            operation="capability",
            agent=agent,
            capability=capability,
            capability_version=capability_version,
            payload=payload,
            token_metadata=token_metadata,
            capability_token=capability_token or "",
        )
        resp = self.hook.pre_op_check(req)
        self._log_audit(
            "HOOK_CAPABILITY",
            None,
            json.dumps(
                {
                    "hook_id": self.hook.hook_id,
                    "agent": agent,
                    "capability": capability,
                    "capability_version": capability_version,
                    **resp.to_audit_dict(),
                }
            ),
        )
        if resp.decision is not HookDecision.ALLOW:
            raise PolicyDeniedError(
                f"hook {self.hook.hook_id!r} denied capability {capability!r} "
                f"for agent {agent!r}: {resp.reason or 'no reason given'}"
            )

    # ------------------------------------------------------------------
    # v0.3 capability execution path
    # ------------------------------------------------------------------

    def execute_capability(self, *args, **kwargs) -> Any:
        if args:
            capability_name = args[0]
            payload = args[1] if len(args) > 1 else {}
            agent_id = args[2] if len(args) > 2 else kwargs.get("agent_id")
            capability_token = args[3] if len(args) > 3 else kwargs.get("capability_token")
            capability_version = kwargs.get("capability_version", kwargs.get("version", 1))
            bypass_verification = kwargs.get("bypass_verification", False)
        else:
            agent_id = kwargs.get("agent_id")
            capability_name = kwargs.get("capability_id") or kwargs.get("capability_name")
            payload = kwargs.get("parameters") if "parameters" in kwargs else kwargs.get("payload", {})
            capability_token = kwargs.get("capability_token")
            capability_version = kwargs.get("capability_version", kwargs.get("version", 1))
            bypass_verification = kwargs.get("bypass_verification", False)
        capability_version = int(capability_version)
        """Execute a registered capability on behalf of an agent.

        This is the **new primary enforcement point** of the v0.3
        security model. The agent presents a v2 capability token
        (issued by the harness via
        :meth:`rgt_vault.token.HMACTokenVerifier.sign`) and the
        vault:

          1. Checks freeze state (kill switch).
          2. Verifies the token's signature, expiration, and that
             its ``agent_id``, ``capability``, and
             ``capability_version`` match the request.
          3. Enforces the token's context bindings against the
             payload (every key the token pins must appear with the
             same value in the payload; the payload may have extras).
          4. Consults the configured audit hook with a
             capability-shaped :class:`HookRequest`. Hooks that have
             been updated for the capability model can gate per-
             capability; legacy hooks see ``operation="capability"``
             and may deny.
          5. Looks up the capability handler in the registry and
             checks the registry accepts the requested version.
          6. Validates the payload against the handler's declared
             ``params_schema``.
          7. Applies the agent's rate limit.
          8. Invokes the handler. The handler receives a
             :class:`rgt_vault.capabilities.CapabilityContext` that
             includes the vault, the agent id, the token id, the
             capability name, the version, and a copy of the token's
             claims. Secret material never crosses this boundary.

        Audit chain
        -----------

        Every execution writes a single ``CAPABILITY_EXECUTED`` row
        (or ``CAPABILITY_DENIED`` for any failure path) with the
        agent, capability, version, hook decision, the reason
        (free-form), and a SHA-256 of the canonical payload (so the
        operator can correlate a row with a specific request without
        recording the payload contents in the audit log).
        """
        if not isinstance(capability_name, str) or not capability_name.strip():
            raise ValidationError("capability_name must be a non-empty string")
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ValidationError("agent_id must be a non-empty string")
        if not bypass_verification and (not isinstance(capability_token or "", str) or not capability_token):
            raise ValidationError("capability_token is required")
        if not isinstance(payload, dict):
            raise ValidationError("payload must be a dict")

        # 1. Freeze check. The hook's frozen property reads the
        # freeze file under a lock; consult it first so a frozen
        # vault fails closed before we do any token verification
        # (which would be wasted work and would also log a misleading
        # "token signature invalid" if the harness can't currently
        # reach us).
        if self.hook.frozen:
            self._log_audit(
                "CAPABILITY_DENIED",
                None,
                json.dumps(
                    {
                        "agent": agent_id,
                        "capability": capability_name,
                        "capability_version": capability_version,
                        "reason": "vault frozen",
                    }
                ),
            )
            raise PolicyDeniedError("vault frozen")

        # 2. Token verification. The verifier is the trust anchor;
        # without one configured, refuse to run.
        token_metadata = {}
        token_id = "bypass"

        if not bypass_verification:
            if self.token_verifier is None:
                self._log_audit(
                    "CAPABILITY_DENIED",
                    None,
                    json.dumps(
                        {
                            "agent": agent_id,
                            "capability": capability_name,
                            "capability_version": capability_version,
                            "reason": "no token verifier configured",
                        }
                    ),
                )
                raise ValidationError(
                    "execute_capability requires a configured token_verifier; "
                    "pass one to VaultManager(..., token_verifier=...)"
                )
            if capability_token is None:
                raise ValidationError("capability_token is required")
            try:
                tok: CapabilityV2Token = self.token_verifier.verify(capability_token)
            except TokenError as e:
                self._log_audit(
                    "CAPABILITY_DENIED",
                    None,
                    json.dumps(
                        {
                            "agent": agent_id,
                            "capability": capability_name,
                            "capability_version": capability_version,
                            "reason": f"token: {type(e).__name__}",
                        }
                    ),
                )
                raise PolicyDeniedError(f"capability token rejected: {e}") from None

            # 3. Token -> request consistency.
            if tok.agent_id != agent_id:
                self._log_audit(
                    "CAPABILITY_DENIED",
                    None,
                    json.dumps(
                        {
                            "agent": agent_id,
                            "capability": capability_name,
                            "capability_version": capability_version,
                            "reason": "agent mismatch",
                        }
                    ),
                )
                raise PolicyDeniedError(f"token bound to agent {tok.agent_id!r}, caller claimed {agent_id!r}")
            if tok.capability != capability_name:
                self._log_audit(
                    "CAPABILITY_DENIED",
                    None,
                    json.dumps(
                        {
                            "agent": agent_id,
                            "capability": capability_name,
                            "capability_version": capability_version,
                            "reason": "capability mismatch",
                            "token_capability": tok.capability,
                        }
                    ),
                )
                raise PolicyDeniedError(f"token authorizes {tok.capability!r}, request asked for {capability_name!r}")
            if tok.capability_version != capability_version:
                self._log_audit(
                    "CAPABILITY_DENIED",
                    None,
                    json.dumps(
                        {
                            "agent": agent_id,
                            "capability": capability_name,
                            "capability_version": capability_version,
                            "reason": "version mismatch",
                            "token_version": tok.capability_version,
                        }
                    ),
                )
                raise PolicyDeniedError(
                    f"token capability_version={tok.capability_version}, request asked for {capability_version}"
                )

            # 4. Context binding. Every key the token pins must appear
            # in the payload with the same value.
            token_metadata = {
                "token_id": tok.token_id,
                "exp": tok.expires_at,
                "context_bindings": dict(tok.context_bindings),
            }
            token_id = tok.token_id
            try:
                tok.check_context(payload)
            except TokenBindingError as e:
                self._log_audit(
                    "CAPABILITY_DENIED",
                    None,
                    json.dumps(
                        {
                            "agent": agent_id,
                            "capability": capability_name,
                            "capability_version": capability_version,
                            "reason": f"context binding: {e}",
                        }
                    ),
                )
                raise

        # 5. Hook consult on the capability path. The hook sees the
        # same fields the token authorized, plus a flag in the
        # request id so the harness can correlate.
        self._hook_consult_capability(
            agent=agent_id,
            capability=capability_name,
            capability_version=capability_version,
            payload=payload,
            token_metadata=token_metadata,
            capability_token=capability_token or "",
        )

        # 6. Registry lookup + version check.
        spec = self.capability_registry.get(capability_name)
        if not spec.supports_version(capability_version):
            self._log_audit(
                "CAPABILITY_DENIED",
                None,
                json.dumps(
                    {
                        "agent": agent_id,
                        "capability": capability_name,
                        "capability_version": capability_version,
                        "reason": "version not supported by registered handler",
                        "supported_versions": sorted(spec.supported_versions),
                    }
                ),
            )
            raise CapabilityVersionError(
                f"capability {capability_name!r} does not support version "
                f"{capability_version}; supported: {sorted(spec.supported_versions)}"
            )

        # 7. Payload validation. Handlers do their own deep checks
        # (e.g. URL parsing, sub-schemas) -- this is just the gate
        # at the vault boundary.
        try:
            spec.validate_payload(payload)
        except ValidationError as e:
            self._log_audit(
                "CAPABILITY_DENIED",
                None,
                json.dumps(
                    {
                        "agent": agent_id,
                        "capability": capability_name,
                        "capability_version": capability_version,
                        "reason": f"payload: {e}",
                    }
                ),
            )
            raise

        # 8. Rate limit. Reuse the existing in-process limiter; a
        # future refactor can split capability and secret-access
        # limits into separate buckets, but the threat model is the
        # same: an agent hammering the vault should be throttled
        # before the handler runs.
        if not self.rate_limiter.allow(agent_id):
            self._log_audit(
                "CAPABILITY_DENIED",
                None,
                json.dumps(
                    {
                        "agent": agent_id,
                        "capability": capability_name,
                        "capability_version": capability_version,
                        "reason": "rate limited",
                    }
                ),
            )
            raise PermissionError(f"Rate limit exceeded for agent {agent_id!r}")

        # 9. Execute. The context exposes the vault, the agent id,
        # the token id, and the token metadata. Secret material is
        # never put on the context -- handlers that need a secret
        # lease it themselves via the vault's existing primitives.
        ctx = CapabilityContext(
            vault=self,
            agent_id=agent_id,
            token_id=token_id,
            capability=capability_name,
            capability_version=capability_version,
            token_metadata=token_metadata,
        )
        # Canonical payload hash: same shape the token is signed over,
        # so an operator verifying the chain can reproduce it.
        context_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()[:16]
        try:
            result = spec.handler(payload, ctx)
        except Exception as e:
            # Handlers are operator code; an unhandled exception is a
            # server fault, not an auth failure. We log it with a
            # sanitized reason (class name only) and re-raise -- the
            # caller's exception type is preserved so they can react
            # appropriately.
            self._log_audit(
                "CAPABILITY_FAILED",
                None,
                json.dumps(
                    {
                        "agent": agent_id,
                        "capability": capability_name,
                        "capability_version": capability_version,
                        "reason": f"handler: {type(e).__name__}",
                        "context_hash": context_hash,
                    }
                ),
            )
            raise

        self._log_audit(
            "CAPABILITY_EXECUTED",
            None,
            json.dumps(
                {
                    "agent": agent_id,
                    "capability": capability_name,
                    "capability_version": capability_version,
                    "hook": self.hook.hook_id,
                    "allowed": True,
                    "context_hash": context_hash,
                }
            ),
        )
        return result

    def _normalize_value_param(self, param_name: str, value: Any, max_len: int) -> bytearray:
        """Coerce a plaintext secret into a mutable ``bytearray``."""
        if isinstance(value, str):
            b = bytearray(value.encode("utf-8"))
        elif isinstance(value, bytes):
            b = bytearray(value)
        elif isinstance(value, bytearray):
            b = value
        else:
            raise ValidationError(f"'{param_name}' must be str, bytes, or bytearray.")
        if not b.strip():
            raise ValidationError(f"'{param_name}' cannot be empty or whitespace.")
        if len(b) > max_len:
            raise ValidationError(f"'{param_name}' exceeds {max_len} bytes.")
        return b

    def set_secret(
        self, name: str, value: Any, namespace: str = "default", agent: str = "system", purpose: str = ""
    ) -> None:
        """Encrypts and stores a secret."""
        self._validate_string_param("name", name, max_len=256)
        self._validate_string_param("namespace", namespace, max_len=128)
        self._validate_string_param("agent", agent, max_len=128)

        plaintext = self._normalize_value_param("value", value, max_len=1024 * 1024)

        self._hook_consult("write", agent, namespace, purpose, secret_name=name)

        try:
            decision = self.auth.evaluate(agent, namespace, purpose, action="write")
            if not decision["allowed"]:
                self._log_audit(
                    "POLICY_DENIED",
                    name,
                    f"Action: write, Agent: {agent}, Namespace: {namespace}, Reason: {decision['reason']}",
                )
                raise PolicyDeniedError(f"Agent '{agent}' denied write access to '{name}' ({namespace}/{purpose})")

            aad = self._get_aad(namespace, name)
            ciphertext = encrypt(plaintext, self.dek, aad)
            self.storage.set_secret(namespace, name, ciphertext, 1, policy_hash=self.policy_hash)
        finally:
            zeroize_bytearray(plaintext)

        if getattr(self, "shadow", None) and self.shadow.enabled:
            ok = self.shadow.mirror_set(namespace, name, value, agent=agent, purpose=purpose)
            self._log_audit(
                "SHADOW_WRITE" if ok else "SHADOW_DIVERGENCE",
                name,
                json.dumps({"op": "set", "namespace": namespace}),
            )

    def get_fingerprint(self, name: str, namespace: str = "default", version: Optional[int] = None) -> str:
        """Returns the SHA256 fingerprint of the ciphertext for debugging.

        Fingerprint reads are deliberately NOT policy-gated: a fingerprint is
        a small fixed-length hash that leaks no plaintext, and a debugger
        often needs to inspect a secret even when the calling agent is not
        authorized to *read* it. Rate limiting also does not apply to
        fingerprints (deliberately, per the ROADMAP "Audit log noise
        reduction" item).
        """
        # Note: ``get_fingerprint`` does NOT consult the hook, because
        # the fingerprint leaks no plaintext. Operators who want
        # even fingerprint reads gated can wrap the call themselves.
        if self.storage.is_honeytoken(namespace, name):
            self._log_audit(
                "HONEYTOKEN_TRIGGERED",
                name,
                json.dumps(
                    {"severity": "critical", "agent": "system", "namespace": namespace, "purpose": "fingerprint"}
                ),
            )
            raise PermissionError(f"Honeytoken access detected: {namespace}/{name}")

        result = self.storage.get_secret(namespace, name, version, policy_hash=self.policy_hash)
        if not result:
            raise SecretNotFoundError(f"Secret '{namespace}/{name}' not found.")
        ciphertext, _ = result
        return hashlib.sha256(ciphertext).hexdigest()[:8]

    @contextlib.contextmanager
    def lease_secret(
        self, name: str, agent: str, namespace: str, purpose: str, version: Optional[int] = None
    ) -> Generator[bytearray, None, None]:
        self._validate_string_param("name", name, max_len=256)
        self._validate_string_param("agent", agent, max_len=128)
        self._validate_string_param("namespace", namespace, max_len=128)
        self._validate_string_param("purpose", purpose, max_len=256)

        # Hook fires BEFORE rate limit + ABAC. The harness is the
        # outer gate; it can lock out an agent before the local
        # rate limiter even records the request.
        self._hook_consult("read", agent, namespace, purpose, secret_name=name)

        if not self.rate_limiter.allow(agent):
            self._log_audit("RATE_LIMITED", name, f"Agent: {agent}")
            raise PermissionError(f"Rate limit exceeded for agent '{agent}'")

        if self.storage.is_honeytoken(namespace, name):
            self._log_audit(
                "HONEYTOKEN_TRIGGERED",
                name,
                json.dumps({"severity": "critical", "agent": agent, "namespace": namespace, "purpose": purpose}),
            )
            raise PermissionError(f"Honeytoken access detected: {namespace}/{name}")

        decision = self.auth.evaluate(agent, namespace, purpose, action="read")
        if not decision["allowed"]:
            self._log_audit(
                "POLICY_DENIED",
                name,
                f"Action: read, Agent: {agent}, Namespace: {namespace}, Reason: {decision['reason']}",
            )
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

        self._log_audit("LEASE_GRANTED", name, f"Agent: {agent}")
        try:
            yield buffer
        finally:
            zeroize_bytearray(buffer)
            self._log_audit("LEASE_RETURNED", name, f"Agent: {agent}")

    def execute(
        self, agent: str, namespace: str, purpose: str, secret_name: str, callback: Callable[[bytearray], Any]
    ) -> Any:
        """Lease a secret and hand the *mutable buffer* to ``callback``.

        The callback receives a ``bytearray`` (not a ``str``). The vault wipes
        this buffer when the callback returns. NOTE: if the callback copies the
        secret into an immutable object (e.g. ``bytes(buf)`` or
        ``buf.decode()``), that copy is the caller's responsibility and is NOT
        covered by the vault's zeroization guarantee.
        """
        if not callable(callback):
            raise ValidationError("The provided callback must be a callable object.")
        with self.lease_secret(secret_name, agent, namespace, purpose) as secret_buffer:
            return callback(secret_buffer)

    def list_secrets(self, namespace: str, agent: str, purpose: str = "") -> List[Dict[str, Any]]:
        self._hook_consult("list", agent, namespace, purpose)
        decision = self.auth.evaluate(agent, namespace, purpose, action="read")
        if not decision["allowed"]:
            self._log_audit(
                "POLICY_DENIED",
                None,
                f"Action: list, Agent: {agent}, Namespace: {namespace}, Reason: {decision['reason']}",
            )
            raise PolicyDeniedError(f"Unauthorized to access namespace '{namespace}'")
        return self.storage.list_secrets(namespace, policy_hash=self.policy_hash)

    def revoke_secret(self, namespace: str, name: str, agent: str = "system") -> None:
        self._hook_consult("revoke", agent, namespace, secret_name=name)
        self.storage.revoke_secret(namespace, name, policy_hash=self.policy_hash)

        # RGT-161 dual-write: mirror the revoke to the Go shadow server.
        if self.shadow.enabled:
            ok = self.shadow.mirror_revoke(namespace, name)
            self._log_audit(
                "SHADOW_WRITE" if ok else "SHADOW_DIVERGENCE",
                name,
                json.dumps({"op": "revoke", "namespace": namespace}),
            )

    def simulate(self, agent: str, namespace: str, purpose: str, action: str = "read") -> Dict[str, Any]:
        self._hook_consult("simulate", agent, namespace, purpose)
        self._log_audit("SIMULATION_RUN", None, f"Agent: {agent}, Namespace: {namespace}, Action: {action}")
        return self.auth.evaluate(agent, namespace, purpose, action)

    def explain(self, agent: str, namespace: str, purpose: str, action: str = "read") -> str:
        decision = self.simulate(agent, namespace, purpose, action)
        res = "ALLOWED" if decision["allowed"] else "DENIED"
        rule = decision.get("matched_rule")
        rule_str = json.dumps(rule) if rule else "None"
        return f"Access: {res}\nReason: {decision['reason']}\nMatched Rule: {rule_str}"

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

        # Hook consult. Rotation is an administrative op -- only an
        # operator identity should typically be allowed.
        self._hook_consult("rotate", "system", "_admin", "rotate_master_key")

        new_master = self._normalize_master(self.master_provider.rotate_secret())
        new_epoch = self.storage.increment_key_epoch()

        self.dek_manager.rewrap_dek(new_master, self.vault_id, new_epoch)
        self.key_epoch = new_epoch

        self._log_audit("ROTATE", "MASTER_KEY", "Master key rotated successfully")

    def rotate_dek(self) -> None:
        """Rotate Data Encryption Key. Slow rotation (re-encrypts all data).

        P0-3 audit fix: the keychain.json atomic-replace and the per-row
        re-encryption are now both inside a single SQLite transaction. A
        crash mid-rotation leaves either the old DEK or the new DEK in
        effect; never a mix.
        """
        # Hook consult.
        self._hook_consult("rotate", "system", "_admin", "rotate_dek")

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

        self._log_audit("ROTATE", "DEK", "Data Encryption Key rotated successfully")

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
        self._log_audit("IMPORT", "VAULT", "Vault imported from external data")

    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.storage.get_audit_log(limit)

    def verify_audit_chain(self) -> bool:
        """Verify the integrity of the audit log hash chain.

        Walks every row in audit_logs in sequence order and recomputes the
        SHA-256 chain hash from (prev_hash, timestamp, action, secret_name,
        details, policy_hash). Returns True only if every link matches the
        stored value.

        Detects: insertion of rows between existing entries, modification of
        any audited field on any row, and deletion of rows from the middle of
        the chain.

        Does NOT detect a root-level offline replacement: a user with
        filesystem access can copy vault.db, truncate audit_logs, rebuild a
        fresh internally-consistent chain from scratch, and replace the file.
        verify_audit_chain() will return True because the chain is valid — it
        cannot distinguish a legitimate chain from a fabricated one with no
        prior history.

        Production hardening: persist the current tail hash out-of-band after
        every write — for example, to the OS keychain via the platform
        secret-store provider, a TPM NV counter, or an append-only remote
        syslog sink. On verification, compare the stored tail hash against the
        external anchor before trusting the chain. See SECURITY.md §Audit Chain
        Limitations.
        """
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


class AgentVaultClient:
    def __init__(self, vault_manager: VaultManager):
        self._vault = vault_manager

    def execute(
        self, agent: str, namespace: str, purpose: str, secret_name: str, callback: Callable[[bytearray], Any]
    ) -> Any:
        return self._vault.execute(agent, namespace, purpose, secret_name, callback)

    @contextlib.contextmanager
    def lease_secret(
        self, name: str, agent: str, namespace: str, purpose: str, version: Optional[int] = None
    ) -> Generator[bytearray, None, None]:
        with self._vault.lease_secret(name, agent, namespace, purpose, version) as secret_buffer:
            yield secret_buffer
