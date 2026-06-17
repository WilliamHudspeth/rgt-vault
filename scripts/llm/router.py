"""Multi-LLM router with task-type routing and fallback chains.

The router picks a chain of providers for each TaskType and tries them in
order until one succeeds. The chain is configurable via routes.yaml.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

import yaml

from .providers import (
    ClaudeCLIProvider,
    CohereProvider,
    GeminiCLIProvider,
    GroqProvider,
    MistralProvider,
    OllamaProvider,
)
from .types import Provider, Reply

DEFAULT_ROUTES_PATH = Path(__file__).parent / "routes.yaml"


# ---------------------------------------------------------------------------
# Task types
# ---------------------------------------------------------------------------

# Canonical task types the kanban dispatch uses.
TASK_CODE_REVIEW = "code-review"          # fast code feedback (small model ok)
TASK_DESIGN_REVIEW = "design-review"      # deeper architecture/design critique
TASK_SECURITY_REVIEW = "security-review"  # threat-model / crypto check
TASK_FAST_QA = "fast-qa"                 # short yes/no or quick diagnosis
TASK_GENERAL = "general"                 # catch-all


# ---------------------------------------------------------------------------
# Routes file
# ---------------------------------------------------------------------------

@dataclass
class RouteConfig:
    """Parsed routes.yaml."""

    # task_type -> ordered list of provider names to try
    chains: dict = field(default_factory=dict)
    # provider name -> kwargs to pass to its constructor
    provider_args: dict = field(default_factory=dict)
    # provider name -> env-var override path
    env_path: Optional[str] = None

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "RouteConfig":
        path = path or DEFAULT_ROUTES_PATH
        if not path.exists():
            return cls.default()
        data = yaml.safe_load(path.read_text()) or {}
        return cls(
            chains=data.get("chains") or {},
            provider_args=data.get("providers") or {},
            env_path=data.get("env_path"),
        )

    @classmethod
    def default(cls) -> "RouteConfig":
        """Hard-coded fallback when routes.yaml is missing."""
        return cls(
            chains={
                TASK_CODE_REVIEW: [
                    "ollama:qwen2.5-coder:3b",   # local, free, code-tuned
                    "groq",                       # fast, free tier
                    "mistral",                    # fast, free tier
                    "cohere",                     # reliable fallback
                ],
                TASK_DESIGN_REVIEW: [
                    "claude-cli",                 # design critique
                    "gemini-cli",                 # second opinion
                ],
                TASK_SECURITY_REVIEW: [
                    "claude-cli",                 # deepest reasoning
                    "gemini-cli",
                    "groq",                       # sanity check
                ],
                TASK_FAST_QA: [
                    "ollama:qwen2.5:0.5b",        # tiny, fast
                    "groq",                       # if local fails
                    "mistral",
                ],
                TASK_GENERAL: [
                    "groq",
                    "mistral",
                    "ollama:qwen2.5:7b",
                    "claude-cli",
                ],
            },
            provider_args={},
        )


# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------

def build_provider(spec: str, args: Optional[dict] = None) -> Provider:
    """Build a Provider from a spec string like "groq" or "ollama:qwen2.5:7b"."""
    args = args or {}
    if spec.startswith("ollama:"):
        model = spec[len("ollama:"):]
        return OllamaProvider(model, **args)
    if spec == "groq":
        return GroqProvider(**args)
    if spec == "mistral":
        return MistralProvider(**args)
    if spec == "cohere":
        return CohereProvider(**args)
    if spec == "claude-cli":
        return ClaudeCLIProvider(**args)
    if spec == "gemini-cli":
        return GeminiCLIProvider(**args)
    raise ValueError(f"unknown provider spec: {spec!r}")


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

class Router:
    """Routes a task to the first available provider in its chain."""

    def __init__(self, config: Optional[RouteConfig] = None):
        self.config = config or RouteConfig.load()
        # Provider cache by spec -> instance
        self._cache: dict = {}

    def _get(self, spec: str) -> Provider:
        if spec not in self._cache:
            args = self.config.provider_args.get(spec, {})
            self._cache[spec] = build_provider(spec, args)
        return self._cache[spec]

    def chain_for(self, task_type: str) -> list:
        return self.config.chains.get(task_type) or self.config.chains.get(TASK_GENERAL, [])

    def available_chain(self, task_type: str) -> list:
        """Return the providers in the chain that report available."""
        out = []
        for spec in self.chain_for(task_type):
            try:
                p = self._get(spec)
                if p.is_available():
                    out.append(p)
            except Exception:
                continue
        return out

    def call(
        self,
        task_type: str,
        prompt: str,
        *,
        system: Optional[str] = None,
        max_tokens: int = 600,
        temperature: float = 0.2,
        timeout: int = 60,
        dry_run: bool = False,
    ) -> Reply:
        """Try each provider in the chain; return the first success."""
        chain = self.chain_for(task_type)
        if not chain:
            return Reply(
                text="",
                provider="<none>",
                model="<none>",
                error=f"no providers configured for task_type={task_type!r}",
            )

        attempts = []
        for spec in chain:
            try:
                provider = self._get(spec)
            except Exception as e:
                attempts.append((spec, f"build failed: {e}"))
                continue
            if not provider.is_available():
                attempts.append((spec, "unavailable"))
                continue
            if dry_run:
                return Reply(
                    text="",
                    provider=provider.name,
                    model=provider.model,
                    error="dry-run: not actually called",
                )
            reply = provider.complete(
                prompt,
                system=system,
                max_tokens=max_tokens,
                temperature=temperature,
                timeout=timeout,
            )
            if reply.ok:
                # Attach audit trail of skipped providers
                if attempts:
                    reply.raw = reply.raw or {}
                    reply.raw["_router_skipped"] = attempts
                return reply
            attempts.append((spec, reply.error or "unknown error"))

        # Nothing worked
        summary = "; ".join(f"{s}: {r}" for s, r in attempts) or "no providers in chain"
        return Reply(
            text="",
            provider="<chain-exhausted>",
            model="<chain-exhausted>",
            error=f"all providers failed: {summary}",
        )
