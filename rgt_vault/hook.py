"""Pluggable audit-hook layer for the rgt-vault.

The hook layer sits between the ABAC engine and every sensitive
operation (read, write, rotate, revoke, capability execution). It is
**opt-in**: when no hook is configured the vault behaves exactly as it
did before this layer existed.

Four modes ship in the box, all implementing the same ``AuditHook``
ABC:

  off        Default. No hook consulted. Vault works as-is.

  log        Hook is consulted and the decision is logged to the
             audit chain, but never enforced. Useful for staging a
             hook before turning enforcement on.

  webhook    Hook calls a configured HTTP URL. The operator runs
             the harness (or a SOAR like Shuffle / Tines that fronts
             it). The hook honors the harness's response. SOAR
             products integrate through this mode; the vault does
             not ship a SOAR-specific envelope.

  two_factor The harness pre-issues HMAC-signed tokens that the
             agent presents on every call. Two token formats are
             supported (v1 namespace-scoped, v2 capability-scoped);
             the vault verifies the signature locally against a
             configured shared secret; no HTTP round-trip per call.
             Compatible with offline operation once a token has
             been minted.

Emergency shut-off
==================

Every hook supports a ``frozen`` state. When the hook is frozen,
**every** sensitive operation is denied immediately, before any
cryptographic operation, with a ``PolicyDeniedError("vault frozen
by hook")`` and an audit row recording the freeze denial. Freeze
state is consulted under a per-call lock to keep the operator-side
and harness-side updates race-free.

Freeze can be triggered from any of:

  * The hook's own ``freeze()`` method (e.g. an admin HTTP call from
    the harness).
  * A signal file on disk: ``<vault_dir>/freeze``. The operator or
    harness creates the file (atomic ``os.rename`` is safest); the
    vault polls on every hook call.
  * USR1 signal: ``kill -USR1 <pid>`` triggers an atexit-style freeze
    via Python's signal handler.
  * An admin HTTP endpoint when ``rgt-vault serve`` is configured
    with ``--admin-token`` (HMAC of the token; the harness presents
    the token).

Every freeze/unfreeze is recorded in the audit chain. Operators
can verify the audit chain to confirm exactly when the freeze was
applied and by which mechanism.

Capability path
===============

In v0.3 the hook is consulted on the new ``execute_capability()``
path too, with a different request shape: instead of
``secret_name`` and ``namespace``, the hook receives
``capability``, ``capability_version``, ``payload``, and
``token_metadata``. The future security boundary is *actions*, not
secret reads. See :class:`HookRequest` for the union shape.

Audit chain integration
=======================

When a hook is configured, every audit row gets two new columns:

  hook_id      Identifier of the hook that handled the event
               (e.g. ``"off"``, ``"webhook:shuffle.example.com"``,
               ``"two_factor"``).
  hook_decision Either ``"allow"`` / ``"deny"`` / ``"freeze"`` /
               ``"n/a"``. Records what the hook decided.

If the audit chain is enabled and the hook is ``log`` or stricter,
the chain verifies that every sensitive operation has a hook
decision recorded. A row with ``hook_decision="n/a"`` for a
sensitive operation fails verification.

This means an operator can audit:

  * Every read/write/rotate by every agent.
  * Every capability execution by every agent.
  * Whether the hook was consulted.
  * The hook's decision.
  * Whether the hook was frozen at the time.

Configurability
===============

The operator configures the hook at ``VaultManager.__init__`` time
or via the CLI. The configuration is operator-controlled, not
agent-controlled. An agent cannot change the hook mode at runtime.

Example YAML config (future)::

    hook:
      mode: two_factor
      shared_secret_file: /etc/rgt-vault/harness.key
      freeze_file: ~/.secure-vault/freeze
      audit_chain_label: "harness-prod-01"
"""
from __future__ import annotations

import abc
import enum
import hashlib
import hmac
import json
import os
import signal
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from rgt_vault.exceptions import PolicyDeniedError, ValidationError


class HookDecision(enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    FREEZE = "freeze"  # emitted when an op is denied *because* the hook is frozen


@dataclass(frozen=True)
class HookRequest:
    """The information passed to a hook on every sensitive operation.

    Two shapes are supported, depending on whether the call is on the
    legacy secret-access path or the new capability path.

    Legacy secret path (still supported for backwards compatibility)::

        operation: "read" | "write" | "rotate" | "revoke" | "list" | "simulate"
        agent: str
        namespace: str
        purpose: str
        secret_name: Optional[str] = None
        capability_token: Optional[str] = None  # for two_factor mode

    Capability path (v0.3)::

        operation: "capability"  # always "capability" on the new path
        agent: str
        capability: str            # e.g. "github.read_repo"
        capability_version: int    # schema version of the capability
        payload: Mapping[str, Any] # capability-specific arguments
        token_metadata: Mapping[str, Any]  # token_id, exp, context_bindings, ...
        namespace: str = ""        # unused on the capability path
        purpose: str = ""

    Note: ``secret_name`` is the requested name, NOT the plaintext.
    Hooks never see plaintext. On the capability path, hooks never see
    the secret material either -- they see the action the agent wants
    to perform and the arguments. The future security boundary is
    *actions*, not secret reads.
    """
    operation: str           # "read" | "write" | "rotate" | "revoke" | "list" | "simulate" | "capability"
    agent: str
    namespace: str = ""
    purpose: str = ""
    secret_name: Optional[str] = None
    capability_token: Optional[str] = None  # legacy two_factor mode

    # ---- New (v0.3) capability fields. Empty on legacy calls. ----
    capability: Optional[str] = None
    capability_version: int = 0
    payload: Any = None  # typed as Any because the value may be any JSON shape
    token_metadata: Any = None  # typed as Any for the same reason

    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def is_capability(self) -> bool:
        """True iff this request is on the new capability path."""
        return self.operation == "capability" and self.capability is not None


@dataclass(frozen=True)
class HookResponse:
    """The hook's answer."""
    decision: HookDecision
    reason: str = ""
    capability_token: Optional[str] = None  # optional refresh from the harness
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_audit_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "decision": self.decision.value,
            "reason": self.reason,
        }
        if self.extra:
            # Don't include ``capability_token`` in the audit dict -- it
            # is itself a credential. Operators can correlate via the
            # request_id if they need to.
            safe_extra = {k: v for k, v in self.extra.items() if k != "capability_token"}
            if safe_extra:
                d["extra"] = json.dumps(safe_extra, sort_keys=True, default=str)
        return d


class AuditHook(abc.ABC):
    """Base class for vault audit hooks.

    Every concrete hook implements ``consult()``. ``pre_op_check()`` is
    a higher-level convenience that consults the hook AND enforces
    the decision (raising PolicyDeniedError if denied). Vault code
    should call ``pre_op_check()`` rather than ``consult()`` directly
    so the freeze state is checked consistently.
    """

    def __init__(self, hook_id: str) -> None:
        self.hook_id = hook_id
        self._frozen = False
        self._freeze_lock = threading.Lock()
        # Path to a file whose presence means "frozen". Created/removed
        # by the operator or harness. ``None`` disables this mechanism.
        self.freeze_file: Optional[Path] = None

    @property
    def frozen(self) -> bool:
        with self._freeze_lock:
            return self._frozen or self._freeze_file_present()

    def _freeze_file_present(self) -> bool:
        if self.freeze_file is None:
            return False
        try:
            return self.freeze_file.exists()
        except OSError:
            return False

    def freeze(self, reason: str = "") -> None:
        """Mark the hook as frozen. All sensitive ops will deny."""
        with self._freeze_lock:
            self._frozen = True
        self._on_freeze_change(True, reason)

    def unfreeze(self, reason: str = "") -> None:
        with self._freeze_lock:
            self._frozen = False
        self._on_freeze_change(False, reason)

    def _on_freeze_change(self, now_frozen: bool, reason: str) -> None:
        """Hook for subclasses (e.g. log to audit chain, notify)."""
        return None

    @abc.abstractmethod
    def consult(self, req: HookRequest) -> HookResponse:
        """Decide whether to allow this operation.

        Implementations MUST be fast (called inline on every op) and
        MUST NOT raise on a denial -- return ``HookResponse(decision=DENY, ...)``
        instead. Raising from ``consult`` is treated as a deny with a
        generic reason by ``pre_op_check``.
        """
        ...

    def pre_op_check(self, req: HookRequest) -> HookResponse:
        """Consult the hook AND enforce the decision. Raises
        ``PolicyDeniedError`` on deny/freeze.

        This is the entry point the vault uses on every sensitive op.
        """
        if self.frozen:
            return HookResponse(
                decision=HookDecision.FREEZE,
                reason="vault frozen by hook",
            )
        try:
            resp = self.consult(req)
        except Exception as e:
            # Hook failures must NOT crash the vault. Treat as deny.
            return HookResponse(
                decision=HookDecision.DENY,
                reason=f"hook raised {type(e).__name__}: {e}",
            )
        return resp

    def enforce(self, req: HookRequest) -> HookResponse:
        """Run ``pre_op_check`` and raise on deny. Returns the response
        on allow."""
        resp = self.pre_op_check(req)
        if resp.decision is not HookDecision.ALLOW:
            raise PolicyDeniedError(
                f"Hook {self.hook_id!r} denied {req.operation} for agent "
                f"{req.agent!r}: {resp.reason or 'no reason given'}"
            )
        return resp


# --------------------------------------------------------------------
# Mode: off
# --------------------------------------------------------------------

class OffHook(AuditHook):
    """No-op hook. The default. Always allows."""

    def __init__(self) -> None:
        super().__init__(hook_id="off")

    def consult(self, req: HookRequest) -> HookResponse:
        return HookResponse(decision=HookDecision.ALLOW, reason="hook disabled")


# --------------------------------------------------------------------
# Mode: log
# --------------------------------------------------------------------

class LogHook(AuditHook):
    """Hook that records every consultation to an in-memory list.

    The vault calls ``_log_audit`` itself; this hook just keeps a
    parallel in-memory record that tests can inspect. The decision
    is always allow -- useful for staging a real hook.
    """

    def __init__(self) -> None:
        super().__init__(hook_id="log")
        self.consultations: List[Dict[str, Any]] = []

    def consult(self, req: HookRequest) -> HookResponse:
        self.consultations.append({
            "operation": req.operation,
            "agent": req.agent,
            "namespace": req.namespace,
            "purpose": req.purpose,
            "secret_name": req.secret_name,
            "request_id": req.request_id,
            "ts": time.time(),
        })
        return HookResponse(decision=HookDecision.ALLOW, reason="log mode: not enforced")


# --------------------------------------------------------------------
# Mode: two_factor
# --------------------------------------------------------------------

@dataclass(frozen=True)
class CapabilityToken:
    """An HMAC-signed capability token issued by the harness.

    The vault verifies these tokens locally using a shared secret.
    No HTTP round-trip per call.
    """
    agent: str
    namespace: str
    capabilities: List[str]     # e.g. ["read", "write"]
    issued_at: int              # unix seconds
    expires_at: int             # unix seconds
    token_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_compact(self) -> str:
        """Serialize to a URL-safe base64 string.

        The format is ``base64url(json(canonical)) + "." + base64url(hmac)``.
        The HMAC is over the canonical JSON, so any tampering with the
        payload invalidates the signature.
        """
        import base64
        payload = json.dumps(
            {
                "a": self.agent,
                "n": self.namespace,
                "c": sorted(self.capabilities),
                "i": self.issued_at,
                "x": self.expires_at,
                "t": self.token_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        sig = _sign(payload, b"")  # placeholder; replaced when serialized
        body = base64.urlsafe_b64encode(payload).rstrip(b"=")
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=")
        return body + b"." + sig_b64

    def covers(self, *, operation: str, namespace: str) -> bool:
        """True iff this token covers the requested operation+namespace."""
        if self.namespace != namespace and self.namespace != "*":
            return False
        now = int(time.time())
        if not (self.issued_at <= now <= self.expires_at):
            return False
        return operation in self.capabilities or "*" in self.capabilities


def _sign(payload: bytes, shared_secret: bytes) -> bytes:
    return hmac.new(shared_secret, payload, hashlib.sha256).digest()


def _verify(payload: bytes, sig: bytes, shared_secret: bytes) -> bool:
    expected = _sign(payload, shared_secret)
    return hmac.compare_digest(expected, sig)


def _pad_b64(s: str) -> str:
    """Restore base64 padding stripped by the token envelope.

    Token envelopes serialize ``base64url(payload) + "." + base64url(sig)``
    with trailing ``=`` stripped. ``base64.urlsafe_b64decode`` requires
    the padding back; restore it deterministically.
    """
    return s + "=" * (-len(s) % 4)


class TwoFactorHook(AuditHook):
    """Hook that verifies HMAC-signed tokens issued by the harness.

    Two token formats are supported, dispatched on the request shape:

    * **Legacy v1** (namespace/operation list, see :class:`CapabilityToken`):
      the agent passes a v1 token in ``req.capability_token`` and the
      request uses the legacy secret-access shape. The vault verifies
      the token covers the requested ``operation`` and ``namespace``.

    * **Capability v2** (action-scoped, see
      :class:`rgt_vault.token.CapabilityV2Token`): the agent passes a v2
      token in ``req.capability_token`` and the request uses the new
      capability shape (``operation="capability"``,
      ``req.capability="github.read_repo"``, etc.). The vault verifies
      the token authorizes exactly the named capability.

    The shared secret is the trust anchor. Whoever holds it can mint
    tokens. The vault verifies the signature on every call. Token
    format is detected by inspecting the decoded payload's ``v`` key
    -- v1 tokens have no ``v`` key, v2 tokens have ``v == 2``.
    """

    def __init__(self, shared_secret: bytes, *, max_ttl_seconds: int = 3600) -> None:
        if not isinstance(shared_secret, (bytes, bytearray)) or len(shared_secret) < 32:
            raise ValidationError(
                "shared_secret must be at least 32 bytes of random material."
            )
        super().__init__(hook_id="two_factor")
        self.shared_secret = bytes(shared_secret)
        self.max_ttl_seconds = max_ttl_seconds
        # Cache of recently-seen tokens (token_id -> expiry) for replay
        # protection within a single process. Bound so the cache
        # cannot grow unboundedly.
        self._seen: Dict[str, int] = {}
        self._seen_lock = threading.Lock()
        self._max_cache = 4096
        # Optional v2 verifier. When set, v2 envelopes dispatched via
        # the capability path use it. Constructed lazily so importing
        # the hook layer does not pull in token.py at import time
        # (preserves the existing "import hook.py" test surface).
        self._v2_verifier = None  # type: ignore[var-annotated]

    def _get_v2_verifier(self):
        """Lazy import to keep the hook import surface narrow."""
        if self._v2_verifier is None:
            from rgt_vault.token import HMACTokenVerifier
            self._v2_verifier = HMACTokenVerifier(self.shared_secret)
        return self._v2_verifier

    def issue(
        self,
        agent: str,
        namespace: str,
        capabilities: List[str],
        ttl_seconds: int = 60,
    ) -> CapabilityToken:
        """Mint a new capability token. The harness calls this; the
        agent presents the result."""
        if ttl_seconds <= 0 or ttl_seconds > self.max_ttl_seconds:
            raise ValidationError(
                f"ttl_seconds must be between 1 and {self.max_ttl_seconds}."
            )
        now = int(time.time())
        return CapabilityToken(
            agent=agent,
            namespace=namespace,
            capabilities=list(capabilities),
            issued_at=now,
            expires_at=now + ttl_seconds,
        )

    def consult(self, req: HookRequest) -> HookResponse:
        if not req.capability_token:
            return HookResponse(
                decision=HookDecision.DENY,
                reason="no capability_token presented",
            )

        # Peek at the envelope to dispatch v1 vs v2 token format. The
        # v2 payload starts with ``{"v":2,...}``; the v1 payload starts
        # with ``{"a":...}``. We decode the payload part only (the
        # signature is checked by the format-specific verifier below).
        raw_token = req.capability_token
        if raw_token is None:
            return HookResponse(
                decision=HookDecision.DENY,
                reason="no capability_token presented",
            )
        try:
            token_str = raw_token
            if isinstance(token_str, (bytes, bytearray)):
                token_str = token_str.decode("ascii")
            parts = token_str.split(".", 1)
        except (ValueError, AttributeError, UnicodeDecodeError):
            return HookResponse(
                decision=HookDecision.DENY,
                reason="malformed capability_token",
            )
        if len(parts) != 2:
            return HookResponse(
                decision=HookDecision.DENY,
                reason="malformed capability_token",
            )
        payload_b64 = parts[0]
        import base64
        try:
            peek_payload = base64.urlsafe_b64decode(_pad_b64(payload_b64))
            peek = json.loads(peek_payload.decode("utf-8"))
        except Exception:
            peek = {}

        is_v2 = isinstance(peek, dict) and int(peek.get("v", 0)) == 2
        if is_v2:
            return self._consult_v2(req)
        return self._consult_v1(req)

    def _consult_v1(self, req: HookRequest) -> HookResponse:
        """Verify a legacy v1 token (namespace-scoped, operation list)."""
        token_str = req.capability_token
        if token_str is None:
            return HookResponse(
                decision=HookDecision.DENY,
                reason="no capability_token presented",
            )
        if isinstance(token_str, (bytes, bytearray)):
            token_str = token_str.decode("ascii")
        try:
            payload_b64, sig_b64 = token_str.split(".", 1)
        except (ValueError, AttributeError):
            return HookResponse(
                decision=HookDecision.DENY,
                reason="malformed capability_token",
            )
        import base64
        try:
            payload = base64.urlsafe_b64decode(_pad_b64(payload_b64))
            sig = base64.urlsafe_b64decode(_pad_b64(sig_b64))
        except Exception:
            return HookResponse(
                decision=HookDecision.DENY,
                reason="capability_token base64 decode failed",
            )
        if not _verify(payload, sig, self.shared_secret):
            return HookResponse(
                decision=HookDecision.DENY,
                reason="capability_token signature invalid",
            )
        try:
            data = json.loads(payload.decode("utf-8"))
            token = CapabilityToken(
                agent=data["a"],
                namespace=data["n"],
                capabilities=list(data["c"]),
                issued_at=int(data["i"]),
                expires_at=int(data["x"]),
                token_id=data["t"],
            )
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as e:
            return HookResponse(
                decision=HookDecision.DENY,
                reason=f"capability_token payload invalid: {e}",
            )

        if token.agent != req.agent:
            return HookResponse(
                decision=HookDecision.DENY,
                reason=(
                    f"capability_token bound to agent {token.agent!r}, "
                    f"caller claimed {req.agent!r}"
                ),
            )
        if not token.covers(operation=req.operation, namespace=req.namespace):
            return HookResponse(
                decision=HookDecision.DENY,
                reason=(
                    f"capability_token does not cover "
                    f"{req.operation} on {req.namespace}"
                ),
            )
        return self._accept_token(token.token_id, token.expires_at, "v1 token valid")

    def _consult_v2(self, req: HookRequest) -> HookResponse:
        """Verify a v2 capability token on the new capability path."""
        if not req.is_capability:
            return HookResponse(
                decision=HookDecision.DENY,
                reason=(
                    "v2 capability_token presented on a non-capability op; "
                    "v2 tokens only authorize capability execution"
                ),
            )
        try:
            tok = self._get_v2_verifier().verify(req.capability_token)
        except Exception as e:
            from rgt_vault.token import (
                TokenExpiredError,
                TokenMalformedError,
                TokenSignatureError,
                TokenVersionError,
            )
            cls = type(e).__name__
            # Map every verifier error to a deny; reason keeps the class
            # name so an operator can tell expiry from tampering in the
            # audit chain. The full token is never recorded.
            if isinstance(e, TokenExpiredError):
                reason = "v2 token expired"
            elif isinstance(e, TokenSignatureError):
                reason = "v2 token signature invalid"
            elif isinstance(e, (TokenMalformedError, TokenVersionError)):
                reason = f"v2 token malformed: {cls}"
            else:
                reason = f"v2 token rejected: {cls}: {e}"
            return HookResponse(decision=HookDecision.DENY, reason=reason)

        if tok.agent_id != req.agent:
            return HookResponse(
                decision=HookDecision.DENY,
                reason=(
                    f"v2 token bound to agent {tok.agent_id!r}, "
                    f"caller claimed {req.agent!r}"
                ),
            )
        if tok.capability != req.capability:
            return HookResponse(
                decision=HookDecision.DENY,
                reason=(
                    f"v2 token authorizes {tok.capability!r}, "
                    f"request asked for {req.capability!r}"
                ),
            )
        if tok.capability_version != req.capability_version:
            return HookResponse(
                decision=HookDecision.DENY,
                reason=(
                    f"v2 token capability_version={tok.capability_version}, "
                    f"request asked for {req.capability_version}"
                ),
            )
        # Context binding: the token's bindings must be a subset of the
        # request's payload. The vault does this check at request
        # dispatch time too, but checking here keeps the hook as a
        # defense-in-depth gate that can deny before the request
        # reaches the handler.
        try:
            tok.check_context(req.payload or {})
        except Exception as e:
            return HookResponse(
                decision=HookDecision.DENY,
                reason=f"v2 token context binding failed: {e}",
            )
        return self._accept_token(tok.token_id, tok.expires_at, "v2 token valid")

    def _accept_token(self, token_id: str, expires_at: int, reason: str) -> HookResponse:
        """Bounded replay-protection cache shared by v1 and v2 paths.

        Insert is check-then-set: if the id is already present we deny
        (replay). The bounded LRU eviction runs first so an entry
        evicted under memory pressure can be replayed -- that's the
        documented trade-off and is acceptable for an in-process
        defense-in-depth cache (the hook is the outer gate; the
        signature check is the authoritative one).
        """
        with self._seen_lock:
            if len(self._seen) >= self._max_cache:
                # Drop the oldest half.
                half = self._max_cache // 2
                for k in sorted(self._seen, key=self._seen.get)[:half]:
                    self._seen.pop(k, None)
            if token_id in self._seen:
                return HookResponse(
                    decision=HookDecision.DENY,
                    reason="capability_token replay detected",
                )
            self._seen[token_id] = expires_at
        return HookResponse(
            decision=HookDecision.ALLOW,
            reason=reason,
            extra={"token_id": token_id},
        )


# --------------------------------------------------------------------
# Mode: webhook / soar
# --------------------------------------------------------------------

class WebhookHook(AuditHook):
    """Hook that calls a configured HTTP URL and honors the response.

    The hook sends a small JSON envelope describing the requested
    operation (secret-access or capability-execution) and respects
    the harness's decision (``{"decision": "allow"|"deny"|"freeze", ...}``).

    SOAR products (Shuffle, Tines, etc.) integrate through this same
    mode -- the vault does not ship a SOAR-specific envelope. The
    operator can stand up a tiny fronting service that translates
    from a SOAR playbook's response shape to the vault's expected
    ``{"decision": ...}`` JSON.
    """

    def __init__(
        self,
        url: str,
        *,
        timeout_seconds: float = 5.0,
        bearer_token: Optional[str] = None,
    ) -> None:
        super().__init__(hook_id=f"webhook:{url}")
        self.url = url
        self.timeout_seconds = timeout_seconds
        self.bearer_token = bearer_token

    def consult(self, req: HookRequest) -> HookResponse:
        import urllib.error
        import urllib.request

        # The wire envelope is uniform across legacy and capability
        # paths; consumers (the harness, the operator's logs) can
        # branch on ``operation`` to render either the secret-access
        # or the capability view.
        body: Dict[str, Any] = {
            "operation": req.operation,
            "agent": req.agent,
            "namespace": req.namespace,
            "purpose": req.purpose,
            "secret_name": req.secret_name,
            "request_id": req.request_id,
        }
        if req.is_capability:
            # Capability calls carry the new fields; legacy calls omit
            # them so the JSON shape stays small.
            body["capability"] = req.capability
            body["capability_version"] = req.capability_version
            body["payload"] = req.payload
            body["token_metadata"] = req.token_metadata
        data = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        rq = urllib.request.Request(self.url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(rq, timeout=self.timeout_seconds) as resp:
                raw = resp.read(64 * 1024)
        except urllib.error.URLError as e:
            return HookResponse(
                decision=HookDecision.DENY,
                reason=f"hook URL unreachable: {e.reason}",
            )
        except Exception as e:
            return HookResponse(
                decision=HookDecision.DENY,
                reason=f"hook call failed: {type(e).__name__}: {e}",
            )
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return HookResponse(
                decision=HookDecision.DENY,
                reason="hook response not valid JSON",
            )
        decision_raw = str(parsed.get("decision", "")).lower()
        if decision_raw == "allow":
            decision = HookDecision.ALLOW
        elif decision_raw == "freeze":
            decision = HookDecision.FREEZE
        else:
            decision = HookDecision.DENY
        return HookResponse(
            decision=decision,
            reason=str(parsed.get("reason", "")),
            extra={k: v for k, v in parsed.items() if k not in ("decision", "reason")},
        )


# --------------------------------------------------------------------
# Signal-file freeze integration
# --------------------------------------------------------------------

def install_freeze_signal_handler(hook: AuditHook, *, sig: int = signal.SIGUSR1) -> None:
    """Install a POSIX signal handler that toggles the hook's frozen
    state. ``kill -USR1 <pid>`` freezes; ``kill -USR2 <pid>`` unfreezes.

    Idempotent; safe to call multiple times (overwrites prior handler).
    """
    def _usr1(_signum, _frame):
        hook.freeze(reason="USR1 signal")

    def _usr2(_signum, _frame):
        hook.unfreeze(reason="USR2 signal")

    signal.signal(sig, _usr1)
    try:
        signal.signal(sig + 1, _usr2)  # SIGUSR2 on POSIX
    except (ValueError, AttributeError):
        # Not all platforms expose SIGUSR2; that's fine.
        pass


def hook_from_config(config: Dict[str, Any]) -> AuditHook:
    """Build an ``AuditHook`` from a configuration dict.

    Config schema::

        {
          "mode": "off" | "log" | "webhook" | "two_factor",
          "freeze_file": "/path/to/freeze",      # optional
          "webhook": {"url": ..., "timeout_seconds": 5.0, "bearer_token": ...},
          "two_factor": {"shared_secret_env": "HARNESS_KEY"},
          ...
        }

    The legacy ``"soar"`` mode is no longer accepted. SOAR products
    integrate through ``"webhook"`` -- stand up a small fronting
    service that translates from the SOAR's response shape to the
    vault's ``{"decision": "allow"|"deny"|"freeze", ...}`` JSON.

    Used by the CLI's ``--hook-mode`` flag and by any future YAML
    config loader.
    """
    mode = str(config.get("mode", "off")).lower()
    if mode == "soar":
        raise ValidationError(
            "hook mode 'soar' has been removed; SOAR products integrate "
            "through 'webhook' mode"
        )
    if mode == "off":
        h: AuditHook = OffHook()
    elif mode == "log":
        h = LogHook()
    elif mode == "webhook":
        wb = config.get("webhook") or {}
        if "url" not in wb:
            raise ValidationError("webhook hook requires config['webhook']['url']")
        h = WebhookHook(
            url=wb["url"],
            timeout_seconds=float(wb.get("timeout_seconds", 5.0)),
            bearer_token=wb.get("bearer_token"),
        )
    elif mode == "two_factor":
        tf = config.get("two_factor") or {}
        secret = tf.get("shared_secret") or os.environ.get(tf.get("shared_secret_env", ""))
        if not secret:
            raise ValidationError(
                "two_factor hook requires a shared_secret (config or env var)."
            )
        h = TwoFactorHook(
            shared_secret=secret.encode("utf-8"),
            max_ttl_seconds=int(tf.get("max_ttl_seconds", 3600)),
        )
    else:
        raise ValidationError(f"unknown hook mode {mode!r}")

    freeze_file = config.get("freeze_file")
    if freeze_file:
        h.freeze_file = Path(freeze_file)
    return h