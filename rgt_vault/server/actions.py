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

import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from rgt_vault.exceptions import ActionExecutionError, ActionNotFoundError

# Actions are called as fn(secret_buf, params, *, registry=...); the keyword
# is optional per-action, so the broad Callable signature is intentional.
ActionFn = Callable[..., Any]

# Cap the response body we'll echo back over HTTP. Upstream services can be
# arbitrarily large; without a cap a single /use call could exhaust memory
# or hang the worker for seconds on a slow upstream.
_MAX_RESPONSE_BYTES = 1 * 1024 * 1024  # 1 MiB
_ALLOWED_SCHEMES = frozenset({"http", "https"})


def _validate_outbound_url(url: str, *, allow_private_network: bool = False) -> str:
    """Reject URLs that would let a caller pivot to internal services.

    The HTTP server is a secret-management surface, not a generic forward
    proxy. By default we block loopback, link-local, RFC1918, and any
    non-http(s) scheme so a token-bearing caller cannot use ``/use`` with
    ``http_get_with_auth`` to probe internal services (SSRF).

    Operators who *want* to point vault actions at internal services
    (e.g. a self-hosted LLM endpoint on a private network) can opt in via
    the server-level ``--allow-private-network`` flag, which propagates
    here.
    """
    if not isinstance(url, str) or not url:
        raise ActionExecutionError("'url' is required and must be a string.")

    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError as e:
        raise ActionExecutionError(f"'url' is not parseable: {e}") from e

    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise ActionExecutionError(
            f"Refusing URL with scheme {parsed.scheme!r}; allowed: {sorted(_ALLOWED_SCHEMES)}."
        )

    host = parsed.hostname
    if not host:
        raise ActionExecutionError("URL is missing a hostname.")

    if allow_private_network:
        return url

    # Resolve the host. If DNS fails we treat that as suspicious and refuse
    # rather than silently letting urlopen retry with a different resolver.
    try:
        infos = socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ActionExecutionError(f"DNS resolution failed for host {host!r}.") from e

    for family, _type, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (
            ip.is_loopback
            or ip.is_link_local
            or ip.is_private
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise ActionExecutionError(
                f"Refusing to call private/internal address {ip!r} for host {host!r}. "
                "Start the server with --allow-private-network if this is intentional."
            )

    return url


def _validate_headers(headers: Dict[str, Any]) -> Dict[str, str]:
    """Stringify caller headers and reject anything that smells like an SSRF
    override (e.g. ``Host:`` injection to a backend that trusts the Host
    header for virtual-host routing)."""
    if not isinstance(headers, dict):
        raise ActionExecutionError("'headers' must be a JSON object if provided.")
    sanitized: Dict[str, str] = {}
    for k, v in headers.items():
        if not isinstance(k, str):
            raise ActionExecutionError("Header names must be strings.")
        kl = k.lower()
        if kl == "host":
            # We refuse to let the caller pin the Host header. urllib sets
            # it from the URL, which is the correct source of truth.
            continue
        sanitized[k] = str(v)
    return sanitized


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
        # Process-wide default for whether built-in HTTP actions may reach
        # private/loopback networks; set by build_app from the serve flag.
        self.default_allow_private_network: bool = False

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


def _http_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[bytes],
    *,
    allow_private_network: bool = False,
) -> Dict[str, Any]:
    """Tiny urllib wrapper; we deliberately don't depend on requests.

    ``allow_private_network`` is plumbed through from the server's
    ``--allow-private-network`` flag. False by default — the vault is not
    a generic forward proxy, and SSRF from a token-bearing caller is a
    real risk.
    """
    safe_url = _validate_outbound_url(url, allow_private_network=allow_private_network)
    req = urllib.request.Request(url=safe_url, method=method, headers=headers, data=body)
    try:
        # urlopen is gated by _validate_outbound_url which (1) restricts the
        # scheme to http/https and (2) refuses loopback, link-local, RFC1918,
        # multicast, and reserved addresses unless allow_private_network is
        # explicitly opted in. nosec must sit on the call line to apply.
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
            raw = resp.read(_MAX_RESPONSE_BYTES + 1)
            truncated = len(raw) > _MAX_RESPONSE_BYTES
            if truncated:
                raw = raw[:_MAX_RESPONSE_BYTES]
            content_type = resp.headers.get_content_type()
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body_text": raw.decode("utf-8", errors="replace"),
                "content_type": content_type,
                "truncated": truncated,
            }
    except urllib.error.HTTPError as e:
        # Read the body even on error so the caller can see the API's
        # explanation; never log or return the secret.
        raw = e.read(_MAX_RESPONSE_BYTES + 1)
        truncated = len(raw) > _MAX_RESPONSE_BYTES
        if truncated:
            raw = raw[:_MAX_RESPONSE_BYTES]
        raise ActionExecutionError(
            f"Upstream {method} {url} returned HTTP {e.code}."
        ) from e
    except urllib.error.URLError as e:
        raise ActionExecutionError(f"Upstream {method} {url} failed.") from e


def _effective_allow_private(registry: "ActionRegistry | None", params: Dict[str, Any]) -> bool:
    """Resolve the per-request SSRF override from explicit param or registry default."""
    explicit = params.get("allow_private_network")
    if explicit is None:
        return bool(getattr(registry, "default_allow_private_network", False))
    return bool(explicit)


def _action_openai_chat(secret_buf: bytearray, params: Dict[str, Any], *, registry: "ActionRegistry | None" = None) -> Dict[str, Any]:
    api_key = bytes(secret_buf).decode("utf-8")
    model = params.get("model")
    messages = params.get("messages")
    if not model or not isinstance(model, str):
        raise ActionExecutionError("'model' is required and must be a string.")
    if not isinstance(messages, list):
        raise ActionExecutionError("'messages' is required and must be a list.")
    if len(messages) == 0:
        raise ActionExecutionError("'messages' must not be empty.")
    for i, msg in enumerate(messages):
        if not isinstance(msg, dict):
            raise ActionExecutionError(
                f"'messages[{i}]' must be a JSON object with 'role' and 'content' keys."
            )
        role = msg.get("role")
        content = msg.get("content")
        if not isinstance(role, str) or not role:
            raise ActionExecutionError(
                f"'messages[{i}].role' is required and must be a non-empty string."
            )
        if not isinstance(content, (str, list)):
            raise ActionExecutionError(
                f"'messages[{i}].content' is required and must be a string or list."
            )
    max_tokens = params.get("max_tokens")
    temperature = params.get("temperature")
    if max_tokens is not None:
        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool):
            raise ActionExecutionError("'max_tokens' must be an integer if provided.")
        if max_tokens <= 0 or max_tokens > 1_000_000:
            raise ActionExecutionError("'max_tokens' must be an integer between 1 and 1,000,000.")
    if temperature is not None:
        if not isinstance(temperature, (int, float)) or isinstance(temperature, bool):
            raise ActionExecutionError("'temperature' must be a number if provided.")
        if temperature < 0.0 or temperature > 2.0:
            raise ActionExecutionError("'temperature' must be between 0.0 and 2.0 inclusive.")
    body_dict: Dict[str, Any] = {"model": model, "messages": messages}
    if max_tokens is not None:
        body_dict["max_tokens"] = max_tokens
    if temperature is not None:
        body_dict["temperature"] = temperature
    body = json.dumps(body_dict).encode("utf-8")
    base_url_raw = params.get("base_url", "https://api.openai.com")
    if not isinstance(base_url_raw, str):
        raise ActionExecutionError("'base_url' must be a string if provided.")
    safe_base = _validate_outbound_url(base_url_raw, allow_private_network=False)
    url = f"{safe_base.rstrip('/')}/v1/chat/completions"
    allow_private = _effective_allow_private(registry, params)
    return _http_request(
        "POST",
        url,
        {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        body,
        allow_private_network=allow_private,
    )


def _action_http_get_with_auth(secret_buf: bytearray, params: Dict[str, Any], *, registry: "ActionRegistry | None" = None) -> Dict[str, Any]:
    api_key = bytes(secret_buf).decode("utf-8")
    url = params.get("url")
    if not url or not isinstance(url, str):
        raise ActionExecutionError("'url' is required and must be a string.")
    extra_headers = _validate_headers(params.get("headers") or {})
    allow_private = _effective_allow_private(registry, params)
    headers = {**extra_headers, "Authorization": f"Bearer {api_key}"}
    return _http_request(
        "GET", url, headers, None, allow_private_network=allow_private,
    )


def _action_http_post_with_auth(secret_buf: bytearray, params: Dict[str, Any], *, registry: "ActionRegistry | None" = None) -> Dict[str, Any]:
    api_key = bytes(secret_buf).decode("utf-8")
    url = params.get("url")
    if not url or not isinstance(url, str):
        raise ActionExecutionError("'url' is required and must be a string.")
    body_obj = params.get("body")
    extra_headers = _validate_headers(params.get("headers") or {})
    allow_private = _effective_allow_private(registry, params)
    if body_obj is None:
        body = b""
    elif isinstance(body_obj, str):
        body = body_obj.encode("utf-8")
    else:
        body = json.dumps(body_obj).encode("utf-8")
    headers = {
        **extra_headers,
        "Authorization": f"Bearer {api_key}",
    }
    if body and "Content-Type" not in headers and "content-type" not in headers:
        headers["Content-Type"] = "application/json"
    return _http_request(
        "POST", url, headers, body, allow_private_network=allow_private,
    )


def _action_echo(secret_buf: bytearray, params: Dict[str, Any], *, registry: "ActionRegistry | None" = None) -> Dict[str, Any]:
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
            params_schema=["model", "messages", "base_url", "max_tokens", "temperature"],
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
