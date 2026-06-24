"""Cohere provider (api.cohere.com/v2/chat).

Load key via:  set -a; . ~/.config/llm-review/keys.env; set +a
Reply text lives at: message.content[].text
"""

from __future__ import annotations

import os
import time
from typing import Optional

from ..types import Provider, Reply
from ._http import HTTPStatusError, post_json, timer_ms
from .. import usage as usage_tracker


class CohereProvider(Provider):
    name = "cohere"
    model = "command-r-plus-08-2024"

    def is_available(self) -> bool:
        return bool(os.environ.get("COHERE_API_KEY"))

    def complete(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        max_tokens: int = 600,
        temperature: float = 0.2,
        timeout: int = 30,
    ) -> Reply:
        key = os.environ.get("COHERE_API_KEY")
        if not key:
            return self._unavailable_reply("COHERE_API_KEY not set")

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
                "https://api.cohere.com/v2/chat",
                body,
                headers={"Authorization": f"Bearer {key}"},
                timeout=timeout,
            )
        except HTTPStatusError as e:
            usage_tracker.log(
                provider=self.name,
                model=self.model,
                latency_ms=timer_ms(t0),
                ok=False,
                error=f"HTTP {e.status}: {e.body[:200]}",
            )
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=timer_ms(t0),
                error=f"HTTP {e.status}: {e.body[:200]}",
            )

        latency = timer_ms(t0)
        try:
            content = resp["message"]["content"]
            text = content[0]["text"] if isinstance(content, list) else str(content)
        except (KeyError, IndexError, TypeError) as e:
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
        usage = resp.get("usage", {})
        tokens = usage.get("tokens", {})
        in_tok = tokens.get("input_tokens", 0)
        out_tok = tokens.get("output_tokens", 0)
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
