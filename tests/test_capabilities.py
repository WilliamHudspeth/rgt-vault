"""Tests for ``rgt_vault.capabilities``.

Covers CapabilityRegistry registration, lookup, version checks,
payload validation, built-in capabilities, and the CapabilityContext
security invariant.
"""

from dataclasses import dataclass

import pytest

from rgt_vault.exceptions import ValidationError
from rgt_vault.capabilities import (
    CapabilitySpec,
    CapabilityContext,
    CapabilityRegistry,
    CapabilityNotFoundError,
    CapabilityVersionError,
    CapabilityExecutionError,
    _register_builtins,
    _secrets_echo,
    _secrets_use,
)


def _dummy_handler(ctx, params):
    return {"ok": True}


# ------------------------------------------------------------------
# Registration
# ------------------------------------------------------------------


def test_register_and_get():
    reg = CapabilityRegistry()
    spec = CapabilitySpec(name="test.cap", handler=_dummy_handler)
    reg.register(spec)
    assert reg.get("test.cap") is spec


def test_register_duplicate():
    reg = CapabilityRegistry()
    reg.register(CapabilitySpec(name="dup", handler=_dummy_handler))
    with pytest.raises(ValidationError, match="already registered"):
        reg.register(CapabilitySpec(name="dup", handler=_dummy_handler))


def test_register_empty_name():
    reg = CapabilityRegistry()
    with pytest.raises(ValidationError, match="must not be empty"):
        reg.register(CapabilitySpec(name="", handler=_dummy_handler))


def test_register_non_callable_handler():
    reg = CapabilityRegistry()
    with pytest.raises(ValidationError, match="must be callable"):
        reg.register(CapabilitySpec(name="bad", handler="not-callable"))


# ------------------------------------------------------------------
# Unregister
# ------------------------------------------------------------------


def test_unregister():
    reg = CapabilityRegistry()
    reg.register(CapabilitySpec(name="gone", handler=_dummy_handler))
    reg.unregister("gone")
    assert not reg.has("gone")


def test_unregister_unknown():
    reg = CapabilityRegistry()
    with pytest.raises(CapabilityNotFoundError):
        reg.unregister("nope")


# ------------------------------------------------------------------
# Lookup
# ------------------------------------------------------------------


def test_has_registered():
    reg = CapabilityRegistry()
    reg.register(CapabilitySpec(name="exists", handler=_dummy_handler))
    assert reg.has("exists")
    assert not reg.has("missing")


def test_get_unknown():
    reg = CapabilityRegistry()
    with pytest.raises(CapabilityNotFoundError):
        reg.get("nonexistent")


def test_list_order():
    reg = CapabilityRegistry()
    reg.register(CapabilitySpec(name="z.last", handler=_dummy_handler))
    reg.register(CapabilitySpec(name="a.first", handler=_dummy_handler))
    names = [s.name for s in reg.list()]
    assert names == ["a.first", "z.last"]


# ------------------------------------------------------------------
# Version support
# ------------------------------------------------------------------


def test_supports_version_in_range():
    reg = CapabilityRegistry()
    reg.register(CapabilitySpec(
        name="vtest", handler=_dummy_handler, supported_versions=(1, 2, 3)
    ))
    assert reg.supports_version("vtest", 2)
    assert not reg.supports_version("vtest", 4)


def test_supports_version_unknown_capability():
    reg = CapabilityRegistry()
    with pytest.raises(CapabilityNotFoundError):
        reg.supports_version("missing", 1)


# ------------------------------------------------------------------
# Payload validation
# ------------------------------------------------------------------


def test_validate_payload_missing_required():
    spec = CapabilitySpec(
        name="test",
        handler=_dummy_handler,
        params_schema={"required": ["name", "action"]},
    )
    with pytest.raises(ValidationError, match="Missing required"):
        spec.validate_payload({"name": "x"})


def test_validate_payload_type_check():
    spec = CapabilitySpec(
        name="test",
        handler=_dummy_handler,
        params_schema={"types": {"count": "int"}},
    )
    with pytest.raises(ValidationError, match="must be an integer"):
        spec.validate_payload({"count": "not-int"})


def test_validate_payload_max_length():
    spec = CapabilitySpec(
        name="test",
        handler=_dummy_handler,
        params_schema={"max_length": {"name": 5}},
    )
    with pytest.raises(ValidationError, match="exceeds max length"):
        spec.validate_payload({"name": "toolonggg"})


def test_validate_payload_no_schema():
    spec = CapabilitySpec(name="test", handler=_dummy_handler, params_schema=None)
    spec.validate_payload({"anything": "goes"})  # no raise


# ------------------------------------------------------------------
# Built-in capabilities
# ------------------------------------------------------------------


def test_builtins_registered():
    reg = CapabilityRegistry()
    _register_builtins(reg)
    assert reg.has("secrets.echo")
    assert reg.has("secrets.use")


def test_secrets_echo_returns_ok():
    reg = CapabilityRegistry()
    _register_builtins(reg)
    ctx = CapabilityContext(vault=None, agent_id="tester", capability="secrets.echo", token_id="x")
    result = reg.get("secrets.echo").handler(ctx, {})
    assert result == {"ok": True}


def test_secrets_use_params_schema():
    """The secrets.use built-in requires 'action' and 'secret' params."""
    reg = CapabilityRegistry()
    _register_builtins(reg)
    spec = reg.get("secrets.use")
    # Missing 'action'
    with pytest.raises(ValidationError, match="Missing required param"):
        spec.validate_payload({"secret": {"name": "x"}})
    # Missing 'secret'
    with pytest.raises(ValidationError, match="Missing required param"):
        spec.validate_payload({"action": "echo"})
    # 'action' has a max_length of 128
    with pytest.raises(ValidationError, match="exceeds max length"):
        spec.validate_payload({
            "action": "x" * 129,
            "secret": {"name": "x"},
        })


# ------------------------------------------------------------------
# CapabilityContext security invariant
# ------------------------------------------------------------------


def test_capability_context_has_no_secret_surface():
    """CapabilityContext should not expose lease_secret/set_secret/revoke_secret
    directly (the secret-never-leaves guarantee is that the handler does not
    receive a secret buffer in its arguments; the bridge calls vault.execute
    internally)."""
    ctx = CapabilityContext(vault=None, agent_id="a", capability="c", token_id="t")
    # No secret methods on the context itself
    assert not hasattr(ctx, "lease_secret")
    assert not hasattr(ctx, "set_secret")
    assert not hasattr(ctx, "revoke_secret")


# ------------------------------------------------------------------
# Error type hierarchy
# ------------------------------------------------------------------


def test_capability_errors_are_vault_errors():
    from rgt_vault.exceptions import VaultError, CapabilityError
    assert issubclass(CapabilityError, VaultError)
    assert issubclass(CapabilityNotFoundError, CapabilityError)
    assert issubclass(CapabilityVersionError, CapabilityError)
    assert issubclass(CapabilityExecutionError, CapabilityError)
