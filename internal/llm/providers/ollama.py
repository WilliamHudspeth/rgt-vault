"""Ollama provider (local daemon, OpenAI-compatible at /v1/chat/completions).

Works for both local Ollama (localhost:11434) and any remote Ollama with the
same API. Defaults to local; pass base_url to override.

Uses the shared _http.post_json helper for OPUS-102/103/104 hardening
(catches TimeoutError, ValueError on non-JSON, caps body read at 10 MiB).
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from .. import usage as usage_tracker
from ..types import Provider, Reply
from . import _http


def _validate_base_url(url: str, allow_remote: bool = False) -> str:
    """SSRF guard for provider base_url (RGT-109).

    Resolves the hostname once at construction time and rejects link-local /
    metadata addresses unconditionally, and non-loopback addresses unless
    allow_remote=True. NOTE: this is a resolve-then-connect check, so it does
    not close a DNS-rebinding TOCTOU window between validation and the actual
    request — that's an accepted gap here (the Go client handles this
    properly via net.Dialer.Control; see RGT-197).
    """
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Invalid scheme '{parsed.scheme}'. Must be 'http' or 'https'.")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname.")

    try:
        addrinfo = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as e:
        raise ValueError(f"Failed to resolve hostname: {parsed.hostname}") from e

    for info in addrinfo:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip.is_link_local:
            raise ValueError(f"Resolved IP {ip} is a link-local/metadata address, which is forbidden.")
        if not allow_remote and not ip.is_loopback:
            raise ValueError(f"Resolved IP {ip} is a non-loopback address. Set allow_remote=True to permit.")

    normalized = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    return normalized.rstrip("/")


class OllamaProvider(Provider):
    """Provider backed by an Ollama daemon.

    Parameters
    ----------
    model : str
        Ollama model tag (e.g. "qwen2.5:7b", "qwen2.5-coder:3b").
    base_url : str
        Daemon base URL. Default "http://localhost:11434".
    name : str
        Provider name for logging. Default uses model name.
    """

    def __init__(
        self,
        model: str,
        *,
        base_url: str = "http://localhost:11434",
        name: str | None = None,
        allow_remote: bool = False,
    ):
        self.model = model
        self.base_url = _validate_base_url(base_url, allow_remote=allow_remote)
        self.name = name or f"ollama:{model}"

    def is_available(self) -> bool:
        """Check whether this provider can serve a completion.

        Be tolerant of tag/alias variation: the configured `model` may be
        "qwen2.5:7b" but Ollama might have it under ":latest", ":7b-instruct",
        or with a different arch suffix. We accept the configured model if
        any installed model matches by:
          1. exact name match
          2. same family + any size tag (qwen2.5 matches qwen2.5:7b, :3b, :latest)
          3. configured name appears as a substring of an installed tag

        Returns True if the daemon responds AND the model is plausibly present.
        Returns False if the daemon is unreachable.

        Doctrine (HUD-485): we want local Ollama to be a *preferred* path.
        Returning False here would silently drop to the next chain link
        (cloud) which is exactly the failure mode we must avoid.
        """
        try:
            with urllib.request.urlopen(f"{self.base_url}/api/tags", timeout=3) as r:
                data = json.loads(r.read())
        except (
            urllib.error.URLError,
            TimeoutError,
            socket.timeout,
            json.JSONDecodeError,
            http.client.HTTPException,
            ssl.SSLError,
            ConnectionError,
        ) as e:
            usage_tracker.log(
                provider=self.name,
                model=self.model,
                ok=False,
                error=f"is_available probe failed: {type(e).__name__}: {e}",
            )
            return False
        tags = {m.get("name", "") for m in data.get("models", [])}
        if not tags:
            return False
        if self.model in tags:
            return True
        # Family match: configured "qwen2.5:7b" matches installed "qwen2.5:latest".
        family = self.model.split(":", 1)[0]
        for t in tags:
            if t.split(":", 1)[0] == family:
                return True
        return False

    def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        max_tokens: int = 600,
        temperature: float = 0.2,
        timeout: int = 120,
    ) -> Reply:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        body = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
            },
        }

        t0 = time.time()
        try:
            resp = _http.post_json(
                f"{self.base_url}/api/chat",
                body,
                timeout=timeout,
            )
        except _http.HTTPStatusError as e:
            latency = _http.timer_ms(t0)
            err = f"HTTP {e.status}: {e.body[:200]}" if e.status else e.body
            usage_tracker.log(provider=self.name, model=self.model, latency_ms=latency, ok=False, error=err)
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=latency,
                error=err,
            )

        latency = _http.timer_ms(t0)
        try:
            text = resp["message"]["content"]
        except (KeyError, TypeError) as e:
            usage_tracker.log(
                provider=self.name,
                model=self.model,
                latency_ms=latency,
                ok=False,
                error=f"unexpected response shape: {e}",
            )
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=latency,
                error=f"unexpected response shape: {e}",
                raw=resp,
            )
        in_tok = resp.get("prompt_eval_count", 0)
        out_tok = resp.get("eval_count", 0)
        usage_tracker.log(
            provider=self.name,
            model=self.model,
            input_tokens=in_tok,
            output_tokens=out_tok,
            latency_ms=latency,
            ok=True,
        )
        return Reply(
            text=text,
            provider=self.name,
            model=self.model,
            input_tokens=in_tok,
            output_tokens=out_tok,
            latency_ms=latency,
            raw=resp,
        )
