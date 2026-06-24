"""Capability registry: name -> handler dispatch for the v0.3 security model.

A capability is a **named, parameterized action** that the vault executes
on behalf of an agent. The registry is the single point of dispatch:
``VaultManager.execute_capability()`` looks up the capability, runs the
context-binding check, and invokes the handler.

Why a registry (and not an ``if/elif`` ladder)?
================================================

The original ``VaultManager.execute()`` accepts a callback from the
caller and hands it a leased secret buffer. That model lets the caller
run arbitrary code inside the vault; useful for tests, dangerous in
production. The capability model inverts that: the vault holds the
handlers, the caller picks one by name. The attack surface is now
*the set of registered capability names*, which is enumerable,
auditable, and small.

Capability names are first-class strings. The convention is
``<service>.<verb>`` (e.g. ``github.read_repo``,
``openai.chat_completion``). The registry is open: an operator can
register any number of additional capabilities via
:meth:`CapabilityRegistry.register`. Built-in capabilities (shipped in
the box) are listed in :func:`register_builtin_capabilities`.

Versioning
==========

Each capability declares the **schema versions** it understands
(``capability_version``). A token must declare a version the registry
recognizes, otherwise :meth:`VaultManager.execute_capability` denies
with a :class:`rgt_vault.exceptions.CapabilityVersionError`. This
lets operators evolve a capability's parameter shape over time without
breaking older tokens that the harness already minted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Set

from rgt_vault.exceptions import (
    CapabilityNotFoundError,
    CapabilityVersionError,
    ValidationError,
)

# ---------------------------------------------------------------------
# CapabilityContext: the handler's view of "what's going on"
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityContext:
    """Read-only context passed to every capability handler.

    The handler can use ``vault`` to perform supporting operations
    (look up another capability, lease a secret). It can use ``agent_id``
    and ``token_metadata`` for audit and logging. The context deliberately
    does NOT expose the raw token: handlers reason about *capability*,
    not *credentials*.
    """

    vault: Any  # forward-declared; the real type is VaultManager
    agent_id: str
    token_id: str
    capability: str
    capability_version: int
    token_metadata: Mapping[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------
# Spec + Registry
# ---------------------------------------------------------------------


@dataclass
class CapabilitySpec:
    """A single registered capability.

    ``supported_versions`` declares which ``capability_version`` values
    this handler accepts. ``handler`` is the callable that actually
    does the work; ``description`` and ``params_schema`` are
    documentation surfaces (also enforced by :meth:`validate_payload`).
    """

    name: str
    handler: Callable[[Dict[str, Any], CapabilityContext], Any]
    description: str = ""
    supported_versions: Set[int] = field(default_factory=lambda: {1})
    params_schema: List[str] = field(default_factory=list)

    def supports_version(self, version: int) -> bool:
        return int(version) in self.supported_versions

    def validate_payload(self, payload: Mapping[str, Any]) -> None:
        """Lightweight payload validation.

        We don't pull in pydantic / jsonschema just for this. The check
        is: ``payload`` is a dict, every key is in ``params_schema`` if
        a schema was declared, and every value is one of the basic
        JSON types. Handlers do their own type-specific checks.
        """
        if not isinstance(payload, Mapping):
            raise ValidationError("capability payload must be a dict")
        if not self.params_schema:
            return
        unknown = set(payload) - set(self.params_schema)
        if unknown:
            raise ValidationError(
                f"capability {self.name!r} got unknown param(s): "
                f"{sorted(unknown)}. Allowed: {sorted(self.params_schema)}"
            )


class CapabilityRegistry:
    """In-process registry of capabilities.

    Thread-safety: a single ``threading.Lock`` guards both ``register``
    and the internal dict. Reads via :meth:`get` are lock-free (the
    ``_specs`` dict is replaced atomically on every write).
    """

    def __init__(self) -> None:
        import threading

        self._lock = threading.Lock()
        self._specs: Dict[str, CapabilitySpec] = {}

    def register(
        self,
        name: str,
        handler: Callable[[Dict[str, Any], CapabilityContext], Any],
        *,
        description: str = "",
        supported_versions: Optional[Iterable[int]] = None,
        params_schema: Optional[Iterable[str]] = None,
    ) -> None:
        """Register a capability.

        Re-registering an existing name is a programming error: it would
        silently shadow a security-relevant handler. Refuse loudly.
        """
        if not isinstance(name, str) or not name:
            raise ValueError("capability name must be a non-empty string")
        if not callable(handler):
            raise ValueError("capability handler must be callable")
        versions = set(int(v) for v in (supported_versions or {1}))
        if not versions or any(v < 1 for v in versions):
            raise ValueError("supported_versions must be positive ints")
        spec = CapabilitySpec(
            name=name,
            handler=handler,
            description=description,
            supported_versions=versions,
            params_schema=list(params_schema or []),
        )
        with self._lock:
            if name in self._specs:
                raise ValueError(f"capability {name!r} is already registered")
            self._specs[name] = spec

    def unregister(self, name: str) -> None:
        """Remove a capability. Used by tests; not exposed over HTTP."""
        with self._lock:
            self._specs.pop(name, None)

    def get(self, name: str) -> CapabilitySpec:
        try:
            return self._specs[name]
        except KeyError:
            raise CapabilityNotFoundError(
                f"unknown capability {name!r}. "
                f"Registered: {sorted(self._specs)}"
            ) from None

    def has(self, name: str) -> bool:
        return name in self._specs

    def list(self) -> List[CapabilitySpec]:
        return list(self._specs.values())

    def check_version(self, name: str, version: int) -> None:
        """Raise :class:`CapabilityVersionError` if ``version`` is not
        supported by the registered handler for ``name``."""
        spec = self.get(name)
        if not spec.supports_version(version):
            raise CapabilityVersionError(
                f"capability {name!r} version {version} is not supported; "
                f"supported versions: {sorted(spec.supported_versions)}"
            )


# ---------------------------------------------------------------------
# Built-in capabilities
# ---------------------------------------------------------------------


def _cap_echo(payload: Mapping[str, Any], ctx: CapabilityContext) -> Dict[str, Any]:
    """A diagnostic capability that proves the path end-to-end.

    Returns a fixed shape; never includes secrets. Useful for operators
    wiring the system together before they register any real handlers.
    """
    message = str(payload.get("message", ""))
    return {
        "ok": True,
        "capability": ctx.capability,
        "agent_id": ctx.agent_id,
        "token_id": ctx.token_id,
        "message": message,
    }


def _cap_secrets_use(payload: Mapping[str, Any], ctx: CapabilityContext) -> Dict[str, Any]:
    """Lease a secret and run a legacy action (e.g. ``openai_chat``)
    against it through the new capability path.

    This bridges v0.2 server-side actions into the v0.3 capability
    model: the capability gets a name and a token; underneath it
    dispatches to the same action registry the HTTP ``/use`` endpoint
    uses, so behavior is identical and the secret never crosses the
    boundary.
    """
    from rgt_vault.server.actions import ActionExecutionError, ActionRegistry

    secret_name = payload.get("secret_name")
    namespace = payload.get("namespace", "default")
    action_name = payload.get("action")
    action_params = payload.get("params") or {}
    if not secret_name or not isinstance(secret_name, str):
        raise ActionExecutionError("'secret_name' is required")
    if not action_name or not isinstance(action_name, str):
        raise ActionExecutionError("'action' is required")
    if not isinstance(action_params, dict):
        raise ActionExecutionError("'params' must be a dict")

    registry: ActionRegistry = getattr(ctx.vault, "action_registry", None) or ActionRegistry()
    spec = registry.get(action_name)
    spec.validate_params(action_params)

    def _run(buf: bytearray) -> Any:
        try:
            return spec.fn(buf, action_params, registry=registry)
        except Exception as e:
            raise ActionExecutionError(
                f"action {action_name!r} failed; see server logs for details"
            ) from e

    result = ctx.vault.execute(
        agent=ctx.agent_id,
        namespace=namespace,
        purpose=f"capability:{ctx.capability}",
        secret_name=secret_name,
        callback=_run,
    )
    return {"ok": True, "action": action_name, "result": result}


def register_builtin_capabilities(registry: CapabilityRegistry) -> None:
    """Register the built-in capabilities shipped with the vault.

    Idempotent: re-registering raises ``ValueError`` from the registry,
    so this function is safe to call exactly once at startup.
    """
    registry.register(
        name="secrets.echo",
        handler=_cap_echo,
        description="Diagnostic capability. Returns a fixed shape; never includes secrets.",
        supported_versions={1},
        params_schema=["message"],
    )
    registry.register(
        name="secrets.use",
        handler=_cap_secrets_use,
        description=(
            "Lease a stored secret and run a registered v0.2 action against it. "
            "Bridges legacy server-side actions into the capability model."
        ),
        supported_versions={1},
        params_schema=["secret_name", "namespace", "action", "params"],
    )


__all__ = [
    "CapabilityContext",
    "CapabilitySpec",
    "CapabilityRegistry",
    "register_builtin_capabilities",
]
