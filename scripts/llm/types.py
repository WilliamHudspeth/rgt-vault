"""Shared types for the multi-LLM router.

A Provider is a single backend (Mistral, Cohere, Groq, Ollama local, Claude CLI, Gemini CLI).
A Provider returns a Reply with text + token usage + latency.
The Router picks a Provider for each TaskType with a fallback chain.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Reply:
    """Result of a single provider call."""

    text: str
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    error: Optional[str] = None  # populated when call failed
    raw: Optional[dict] = field(default=None, repr=False)

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass
class ProviderError(Exception):
    """Raised by a provider when it cannot complete a call."""

    provider: str
    reason: str
    original: Optional[Exception] = None


class Provider:
    """Base class for LLM providers.

    Subclasses override name, model, complete().
    """

    name: str = "base"
    model: str = "base"

    def complete(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        max_tokens: int = 600,
        temperature: float = 0.2,
        timeout: int = 60,
    ) -> Reply:
        raise NotImplementedError

    def is_available(self) -> bool:
        """Cheap check: can this provider make a call right now?

        Default: always available. Override to add credential checks etc.
        """
        return True

    def _unavailable_reply(self, reason: str) -> Reply:
        return Reply(
            text="",
            provider=self.name,
            model=self.model,
            error=reason,
        )
