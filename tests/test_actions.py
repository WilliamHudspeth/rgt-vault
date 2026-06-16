"""Unit tests for the server-side action registry and built-in actions.

These never touch the network: the built-in HTTP actions validate their params
and raise before any request is made, so we test the failure paths and the
non-leaking ``echo`` action without a socket.
"""
import pytest

from rgt_vault.exceptions import ActionExecutionError, ActionNotFoundError
from rgt_vault.server.actions import ActionRegistry, register_builtin_actions


def _registry() -> ActionRegistry:
    r = ActionRegistry()
    register_builtin_actions(r)
    return r


def test_builtins_registered():
    names = {s.name for s in _registry().list()}
    assert names == {"openai_chat", "http_get_with_auth", "http_post_with_auth", "echo"}


def test_unknown_action_raises():
    with pytest.raises(ActionNotFoundError):
        _registry().get("does-not-exist")


def test_duplicate_register_raises():
    r = _registry()
    with pytest.raises(ValueError):
        register_builtin_actions(r)  # echo (et al.) already registered


def test_echo_does_not_leak_secret():
    spec = _registry().get("echo")
    buf = bytearray(b"super-secret-value")
    out = spec.fn(buf, {})
    assert out["leaked_secret"] is False
    assert out["secret_len"] == len(b"super-secret-value")
    assert "super-secret-value" not in str(out)


def test_validate_params_rejects_unknown():
    spec = _registry().get("echo")
    with pytest.raises(ActionExecutionError):
        spec.validate_params({"not_a_real_param": 1})


def test_openai_chat_requires_model_and_messages():
    spec = _registry().get("openai_chat")
    with pytest.raises(ActionExecutionError):
        spec.fn(bytearray(b"k"), {"messages": [{"role": "user", "content": "hi"}]})
    with pytest.raises(ActionExecutionError):
        spec.fn(bytearray(b"k"), {"model": "gpt-x"})


def test_http_get_requires_url():
    spec = _registry().get("http_get_with_auth")
    with pytest.raises(ActionExecutionError):
        spec.fn(bytearray(b"k"), {})
