"""Capability registry and execution model for rgt-vault.

This module defines the three core types of the v0.3 capability
execution model:

- **CapabilitySpec**: what a capability *is* (name, handler, version,
  input schema).
- **CapabilityRegistry**: where capabilities live (register, get,
  list, unregister, version check, payload validation).
- **CapabilityContext**: what the handler receives — the vault
  reference, caller identity, token metadata — without exposing the
  vault's secret surface.

Built-in capabilities shipped with every registry:

- ``secrets.echo`` — diagnostic; returns ``{"ok": true}``. No secret
  read. Useful for harness wiring tests.
- ``secrets.use`` — bridge to the existing ``ActionRegistry``
  (v0.2.x backwards compat). Leases a secret, runs the action,
  zeroizes the buffer, returns the result.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from rgt_vault.exceptions import (
    VaultError,
    CapabilityError,
    CapabilityNotFoundError,
    CapabilityVersionError,
    CapabilityExecutionError,
)


# ---------------------------------------------------------------------------
# Core data types
# ---------------------------------------------------------------------------


@dataclass
class CapabilityContext:
    """What a capability handler receives when invoked.

    **No secret material is reachable from this object.** The
    ``vault`` reference is a ``VaultManager`` instance, but the
    capability handler accesses it only to call``execute()`` or
    ``lease_secret()`` — the same public API any caller has. The
    handler does NOT receive the secret buffer directly; the bridge
    (``secrets.use``) calls ``vault.execute`` on its behalf.
    """

    vault: Any  # VaultManager — avoided import cycle with forward ref
    agent_id: str
    capability: str
    token_id: str
    token_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CapabilitySpec:
    """Declaration of a registered capability.

    :param name: unique dot-separated name (e.g. ``secrets.echo``)
    :param handler: callable receiving ``(context, params)``
    :param description: human-readable help text
    :param supported_versions: tuple of int version numbers (default ``(1,)``)
    :param params_schema: optional dict describing expected params shape
        (simple validation: required keys, type checks, max length).
        ``None`` means no schema validation.
    """

    name: str
    handler: Callable[[CapabilityContext, Dict[str, Any]], Any]
    description: str = ""
    supported_versions: Tuple[int, ...] = (1,)
    params_schema: Optional[Dict[str, Any]] = None

    def validate_payload(self, payload: Dict[str, Any]) -> None:
        """Validate *payload* against ``params_schema`` (if set).

        Raises ``ValidationError`` (from ``rgt_vault.exceptions``)
        on failure. Simple validation only: required keys, type
        checks, max string length.
        """
        if self.params_schema is None:
            return

        from rgt_vault.exceptions import ValidationError

        required = self.params_schema.get("required", [])
        for key in required:
            if key not in payload:
                raise ValidationError(
                    f"Missing required param: {key!r} for capability {self.name!r}"
                )

        types = self.params_schema.get("types", {})
        for key, expected_type in types.items():
            if key in payload:
                val = payload[key]
                if expected_type == "str" and not isinstance(val, str):
                    raise ValidationError(
                        f"Param {key!r} must be a string, got {type(val).__name__}"
                    )
                if expected_type == "int" and not isinstance(val, int):
                    raise ValidationError(
                        f"Param {key!r} must be an integer, got {type(val).__name__}"
                    )

        max_length = self.params_schema.get("max_length", {})
        for key, limit in max_length.items():
            if key in payload and isinstance(payload[key], str):
                if len(payload[key]) > limit:
                    raise ValidationError(
                        f"Param {key!r} exceeds max length {limit} "
                        f"(got {len(payload[key])})"
                    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class CapabilityRegistry:
    """A container for registered capabilities.

    Thread-safe only if no concurrent ``register`` / ``unregister``
    calls happen during ``execute_capability`` (same as the rest of
    the vault). ``register`` and ``unregister`` are not designed for
    hot-reload.
    """

    def __init__(self) -> None:
        self._specs: Dict[str, CapabilitySpec] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, spec: CapabilitySpec) -> None:
        """Register a capability spec.

        Raises ``ValidationError`` if the name is empty, the handler
        is not callable, or the name is already registered.
        """
        from rgt_vault.exceptions import ValidationError

        if not spec.name:
            raise ValidationError("Capability name must not be empty")
        if spec.name in self._specs:
            raise ValidationError(
                f"Capability {spec.name!r} is already registered"
            )
        if not callable(spec.handler):
            raise ValidationError(
                f"Handler for {spec.name!r} must be callable, "
                f"got {type(spec.handler).__name__}"
            )
        self._specs[spec.name] = spec

    def unregister(self, name: str) -> None:
        """Remove a capability from the registry.

        Raises ``CapabilityNotFoundError`` if the name is not
        registered.
        """
        if name not in self._specs:
            raise CapabilityNotFoundError(
                f"Capability {name!r} not found in registry"
            )
        del self._specs[name]

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, name: str) -> CapabilitySpec:
        """Look up a capability by name.

        Raises ``CapabilityNotFoundError`` if not registered.
        """
        spec = self._specs.get(name)
        if spec is None:
            raise CapabilityNotFoundError(
                f"Capability {name!r} is not registered. "
                f"Registered: {self._formatted_names()}"
            )
        return spec

    def has(self, name: str) -> bool:
        """Check if a capability is registered."""
        return name in self._specs

    def list(self) -> List[CapabilitySpec]:
        """Return all registered capabilities (ordered by name)."""
        return [self._specs[n] for n in sorted(self._specs)]

    def supports_version(self, name: str, version: int) -> bool:
        """Check if a registered capability supports a given version."""
        spec = self.get(name)
        return version in spec.supported_versions

    def _formatted_names(self) -> str:
        names = sorted(self._specs)
        if not names:
            return "(empty)"
        return ", ".join(names)


# ---------------------------------------------------------------------------
# Built-in capabilities
# ---------------------------------------------------------------------------


def _secrets_echo(ctx: CapabilityContext, params: Dict[str, Any]) -> Dict[str, Any]:
    """Diagnostic capability: returns ``{"ok": true}``.

    Does NOT read any secret. Useful for connectivity / wiring
    tests in agent frameworks.
    """
    return {"ok": True}


def _secrets_use(ctx: CapabilityContext, params: Dict[str, Any]) -> Any:
    """Bridge to the existing ``ActionRegistry`` (v0.2.x compat).

    Expected ``params`` shape::

        {
            "action": "openai_chat",
            "params": {...},
            "secret": {"namespace": "default", "name": "openai-key"}
        }

    This capability leases the specified secret, runs the requested
    action with it, zeroizes the buffer, and returns the action's
    result. Reuses every existing safety property (ABAC policy,
    rate limiting, audit log, zeroization).
    """
    action_name = params.get("action")
    if not action_name:
        raise ValueError("'action' is required in params")

    action_params = params.get("params", {})
    secret_ref = params.get("secret", {})
    ns = secret_ref.get("namespace", "default")
    name = secret_ref.get("name")

    if not name:
        raise ValueError("'secret.name' is required in params")

    # Access the vault's action registry via the context
    try:
        action_spec = ctx.vault._action_registry.get(action_name)
    except AttributeError as e:
        raise CapabilityExecutionError(
            "Vault is not configured with an ActionRegistry"
        ) from e

    action_params = params.get("params", {})
    if hasattr(action_spec, "validate_params"):
        action_spec.validate_params(action_params)

    def _run(buf: bytearray) -> Any:
        return action_spec.fn(buf, action_params, registry=ctx.vault._action_registry)

    purpose = ctx.token_metadata.get("purpose", "")
    return ctx.vault.execute(
        ctx.agent_id, ns, purpose, name, _run
    )


def _register_builtins(registry: CapabilityRegistry) -> None:
    """Register the built-in capabilities that ship with every vault.

    Called by ``VaultManager.__init__`` when no custom registry is
    provided.
    """
    registry.register(CapabilitySpec(
        name="secrets.echo",
        handler=_secrets_echo,
        description="Diagnostic: returns {'ok': true}. Does not read any secret.",
        supported_versions=(1,),
        params_schema=None,
    ))
    registry.register(CapabilitySpec(
        name="secrets.use",
        handler=_secrets_use,
        description="Bridge to the v0.2.x ActionRegistry. "
                    "Leases a secret and runs an action server-side.",
        supported_versions=(1,),
        params_schema={
            "required": ["action", "secret"],
            "types": {"action": "str"},
            "max_length": {"action": 128},
        },
    ))
