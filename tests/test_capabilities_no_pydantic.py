"""RGT-493: capability registration/validation must work without pydantic."""
import builtins

import pytest

from rgt_vault.capabilities import CapabilityRegistry
from rgt_vault.exceptions import ValidationError


@pytest.fixture
def no_pydantic(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "pydantic" or name.startswith("pydantic."):
            raise ImportError("No module named 'pydantic'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_register_and_validate_without_pydantic(no_pydantic):
    reg = CapabilityRegistry()
    reg.register(
        "t.echo",
        lambda payload, ctx: payload,
        params_schema={"type": "object", "required": ["x"], "properties": {"x": {"type": "string"}}},
    )
    spec = reg.get("t.echo")
    spec.validate_payload({"x": "ok"})
    with pytest.raises(ValidationError):
        spec.validate_payload({})
