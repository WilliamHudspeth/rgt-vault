"""Groq provider (api.groq.com/openai/v1/chat/completions).

Load key via:  set -a; . ~/.config/llm-review/keys.env; set +a
IMPORTANT: Groq is behind Cloudflare and 403s on the default urllib UA.
We always send a custom User-Agent header.
Free tier: 12,000 tokens/minute per request.
"""
from __future__ import annotations

import os
import time
from typing import Optional

from ..types import Provider, Reply
from ._http import HTTPStatusError, post_json, timer_ms


class GroqProvider(Provider):
    name = "groq"
    model = "llama-3.3-70b-versatile"

    def is_available(self) -> bool:
        return bool(os.environ.get("GROQ_API_KEY"))

    def complete(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        max_tokens: int = 600,
        temperature: float = 0.2,
        timeout: int = 30,
    ) -> Reply:
        key = os.environ.get("GROQ_API_KEY")
        if not key:
            return self._unavailable_reply("GROQ_API_KEY not set")

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        body = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        t0 = time.time()
        try:
            resp = post_json(
                "https://api.groq.com/openai/v1/chat/completions",
                body,
                headers={
                    "Authorization": f"Bearer {key}",
                    "User-Agent": "hermes-llm-review/1.0",
                },
                timeout=timeout,
            )
        except HTTPStatusError as e:
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=timer_ms(t0),
                error=f"HTTP {e.status}: {e.body[:200]}",
            )

        latency = timer_ms(t0)
        try:
            text = resp["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=latency,
                error=f"unexpected response shape: {e}",
                raw=resp,
            )
        usage = resp.get("usage", {})
        return Reply(
            text=text,
            provider=self.name,
            model=self.model,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            latency_ms=latency,
            raw=resp,
        )
