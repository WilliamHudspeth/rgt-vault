"""Ollama provider (local daemon, OpenAI-compatible at /v1/chat/completions).

Works for both local Ollama (localhost:11434) and any remote Ollama with the
same API. Defaults to local; pass base_url to override.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Optional

from ..types import Provider, Reply


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
        name: Optional[str] = None,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.name = name or f"ollama:{model}"

    def is_available(self) -> bool:
        try:
            with urllib.request.urlopen(f"{self.base_url}/api/tags", timeout=3) as r:
                data = json.loads(r.read())
            tags = {m.get("name") for m in data.get("models", [])}
            return self.model in tags
        except Exception:
            return False

    def complete(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
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
            req = urllib.request.Request(
                f"{self.base_url}/api/chat",
                data=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                resp = json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = e.read()[:300].decode("utf-8", errors="replace")
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=int((time.time() - t0) * 1000),
                error=f"HTTP {e.code}: {body[:200]}",
            )
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=int((time.time() - t0) * 1000),
                error=f"{type(e).__name__}: {e}",
            )

        latency = int((time.time() - t0) * 1000)
        try:
            text = resp["message"]["content"]
        except (KeyError, TypeError) as e:
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=latency,
                error=f"unexpected response shape: {e}",
                raw=resp,
            )
        return Reply(
            text=text,
            provider=self.name,
            model=self.model,
            input_tokens=resp.get("prompt_eval_count", 0),
            output_tokens=resp.get("eval_count", 0),
            latency_ms=latency,
            raw=resp,
        )
