"""Server-side actions for the vault's ``/use`` endpoint.

The HTTP server never returns the raw plaintext of a secret. Instead, the
caller asks the vault to perform a *named action* that consumes the secret
inside the server process. The action receives a mutable ``bytearray`` (the
same one the existing ``VaultManager.lease_secret`` context manager hands
out, with the same zeroization guarantee on return) and a ``params`` dict
from the JSON body. The action returns a JSON-serializable result.

The four built-in actions cover the most common "the LLM has a secret and
needs to call an external service" case without inventing anything new:

  - ``openai_chat``        POST to an OpenAI-compatible chat completions
                           endpoint, secret used as Bearer token.
  - ``http_get_with_auth`` Generic GET, secret used as Bearer token.
  - ``http_post_with_auth`` Generic POST, secret used as Bearer token,
                            optional JSON body.
  - ``echo``               Sanity check: does NOT return the secret. Returns
                           a fixed string confirming the lease worked. This
                            is the one a caller should use to test the
                            server end-to-end before pointing real LLM
                            traffic at it.

Adding a new action is a one-line registration against the
:class:`ActionRegistry`. There is no plugin discovery in v0.2.0 — every
action must be registered in-process by the application that started the
server.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from rgt_vault.exceptions import ActionExecutionError, ActionNotFoundError

ActionFn = Callable[[bytearray, Dict[str, Any]], Any]


@dataclass
class ActionSpec:
    name: str
    fn: ActionFn
    description: str
    params_schema: List[str]

    def validate_params(self, params: Dict[str, Any]) -> None:
        """Sanity-check the caller's ``params`` against ``params_schema``.

        We do not enforce types strictly here — that would require a JSON
        Schema or pydantic dependency just to be cute. We check that every
        declared param key is present and that the dict contains nothing
        else, and let the action itself raise if a value is the wrong type.
        Adding pydantic is a future-work item; see ROADMAP.
        """
        if not isinstance(params, dict):
            raise ActionExecutionError("'params' must be a JSON object.")
        unknown = set(params) - set(self.params_schema)
        if unknown:
            raise ActionExecutionError(
                f"Action '{self.name}' got unknown param(s): {sorted(unknown)}. "
                f"Allowed: {sorted(self.params_schema)}"
            )


class ActionRegistry:
    """A small name -> ActionSpec registry."""

    def __init__(self) -> None:
        self._actions: Dict[str, ActionSpec] = {}

    def register(self, spec: ActionSpec) -> None:
        if not spec.name or not isinstance(spec.name, str):
            raise ValueError("Action name must be a non-empty string.")
        if spec.name in self._actions:
            raise ValueError(f"Action '{spec.name}' is already registered.")
        self._actions[spec.name] = spec

    def get(self, name: str) -> ActionSpec:
        spec = self._actions.get(name)
        if spec is None:
            raise ActionNotFoundError(
                f"Unknown action '{name}'. "
                f"Registered: {sorted(self._actions)}"
            )
        return spec

    def list(self) -> List[ActionSpec]:
        return list(self._actions.values())


# ---------------------------------------------------------------------------
# Built-in actions
# ---------------------------------------------------------------------------


def _http_request(method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Dict[str, Any]:
    """Tiny urllib wrapper; we deliberately don't depend on requests."""
    req = urllib.request.Request(url=url, method=method, headers=headers, data=body)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            content_type = resp.headers.get_content_type()
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body_text": raw.decode("utf-8", errors="replace"),
                "content_type": content_type,
            }
    except urllib.error.HTTPError as e:
        # Read the body even on error so the caller can see the API's
        # explanation; never log or return the secret.
        raw = e.read()
        raise ActionExecutionError(
            f"Upstream {method} {url} returned HTTP {e.code}: "
            f"{raw.decode('utf-8', errors='replace')[:512]}"
        ) from e
    except urllib.error.URLError as e:
        raise ActionExecutionError(f"Upstream {method} {url} failed: {e.reason}") from e


def _action_openai_chat(secret_buf: bytearray, params: Dict[str, Any]) -> Dict[str, Any]:
    api_key = bytes(secret_buf).decode("utf-8")
    base_url = params.get("base_url", "https://api.openai.com").rstrip("/")
    url = f"{base_url}/v1/chat/completions"
    model = params.get("model")
    messages = params.get("messages")
    if not model or not isinstance(model, str):
        raise ActionExecutionError("'model' is required and must be a string.")
    if not messages or not isinstance(messages, list):
        raise ActionExecutionError("'messages' is required and must be a list.")
    body = json.dumps({"model": model, "messages": messages}).encode("utf-8")
    return _http_request(
        "POST",
        url,
        {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        body,
    )


def _action_http_get_with_auth(secret_buf: bytearray, params: Dict[str, Any]) -> Dict[str, Any]:
    api_key = bytes(secret_buf).decode("utf-8")
    url = params.get("url")
    if not url or not isinstance(url, str):
        raise ActionExecutionError("'url' is required and must be a string.")
    extra_headers = params.get("headers") or {}
    if not isinstance(extra_headers, dict):
        raise ActionExecutionError("'headers' must be a JSON object if provided.")
    headers = {**{k: str(v) for k, v in extra_headers.items()}, "Authorization": f"Bearer {api_key}"}
    return _http_request("GET", url, headers, None)


def _action_http_post_with_auth(secret_buf: bytearray, params: Dict[str, Any]) -> Dict[str, Any]:
    api_key = bytes(secret_buf).decode("utf-8")
    url = params.get("url")
    if not url or not isinstance(url, str):
        raise ActionExecutionError("'url' is required and must be a string.")
    body_obj = params.get("body")
    extra_headers = params.get("headers") or {}
    if not isinstance(extra_headers, dict):
        raise ActionExecutionError("'headers' must be a JSON object if provided.")
    if body_obj is None:
        body = b""
    elif isinstance(body_obj, str):
        body = body_obj.encode("utf-8")
    else:
        body = json.dumps(body_obj).encode("utf-8")
    headers = {
        **{k: str(v) for k, v in extra_headers.items()},
        "Authorization": f"Bearer {api_key}",
    }
    if body and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    return _http_request("POST", url, headers, body)


def _action_echo(secret_buf: bytearray, params: Dict[str, Any]) -> Dict[str, Any]:
    # Deliberately do NOT return the secret. This action exists so an
    # operator can confirm the lease + auth + policy path end-to-end.
    return {
        "ok": True,
        "leaked_secret": False,
        "secret_len": len(secret_buf),
        "message": params.get("message", "lease ok; secret NOT returned"),
    }


def register_builtin_actions(registry: ActionRegistry) -> None:
    """Register the four built-in actions. Idempotent within a single registry."""
    registry.register(
        ActionSpec(
            name="openai_chat",
            fn=_action_openai_chat,
            description=(
                "POST to an OpenAI-compatible /v1/chat/completions endpoint. "
                "The leased secret is sent as a Bearer token. Returns the "
                "upstream response (status, headers, body_text)."
            ),
            params_schema=["model", "messages", "base_url"],
        )
    )
    registry.register(
        ActionSpec(
            name="http_get_with_auth",
            fn=_action_http_get_with_auth,
            description="GET a URL with the leased secret as a Bearer token.",
            params_schema=["url", "headers"],
        )
    )
    registry.register(
        ActionSpec(
            name="http_post_with_auth",
            fn=_action_http_post_with_auth,
            description="POST to a URL with the leased secret as a Bearer token.",
            params_schema=["url", "body", "headers"],
        )
    )
    registry.register(
        ActionSpec(
            name="echo",
            fn=_action_echo,
            description=(
                "Diagnostic. Returns a fixed object confirming the lease "
                "worked; the secret is NEVER included in the response."
            ),
            params_schema=["message"],
        )
    )


__all__ = [
    "ActionFn",
    "ActionRegistry",
    "ActionSpec",
    "register_builtin_actions",
]
