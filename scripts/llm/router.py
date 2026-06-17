"""Multi-LLM router with task-type routing and fallback chains.

The router picks a chain of providers for each TaskType and tries them in
order until one succeeds. The chain is configurable via routes.yaml.

Two modes:
  - call()       — sequential fallback. First success wins.
  - call_parallel() — fan-out. Calls every provider in parallel,
                       returns all replies. Used for 2-model cross-check.
  - review_pair() — convenience wrapper that picks a primary + secondary
                    provider and returns both replies.

Task types and chains are in routes.yaml under "chains:" (sequential) and
"pairs:" (2-model review).
"""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
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

TASK_CODE_REVIEW = "code-review"
TASK_DESIGN_REVIEW = "design-review"
TASK_SECURITY_REVIEW = "security-review"
TASK_FAST_QA = "fast-qa"
TASK_GENERAL = "general"


# ---------------------------------------------------------------------------
# Routes file
# ---------------------------------------------------------------------------

@dataclass
class RouteConfig:
    """Parsed routes.yaml."""

    chains: dict = field(default_factory=dict)            # task -> [spec, ...]
    pairs: dict = field(default_factory=dict)             # task -> {"primary": spec, "secondary": spec}
    writers: dict = field(default_factory=dict)           # task -> spec (the big model that writes/answers)
    provider_args: dict = field(default_factory=dict)     # spec -> kwargs
    env_path: Optional[str] = None

    @classmethod
    def load(cls, path: Optional[Path] = None, *, load_env: bool = True) -> "RouteConfig":
        """Load routes.yaml. Optionally load env_path into os.environ (OPUS-2).

        If load_env=True (default) AND env_path is set in yaml AND the file
        exists, source it into os.environ before loading chains/pairs.
        """
        path = path or DEFAULT_ROUTES_PATH
        if not path.exists():
            return cls.default()
        data = yaml.safe_load(path.read_text()) or {}
        env_path = data.get("env_path")
        if load_env and env_path:
            env_file = Path(env_path).expanduser()
            if env_file.exists():
                # Source KEY=VALUE lines (with optional 'export ') into os.environ.
                # Doesn't override existing keys.
                try:
                    for line in env_file.read_text().splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("export "):
                            line = line[len("export "):]
                        if "=" in line:
                            k, _, v = line.partition("=")
                            k = k.strip()
                            v = v.strip()
                            if k and k not in os.environ:
                                os.environ[k] = v
                except Exception as e:
                    import sys as _sys
                    print(f"Warning: failed to load env_path {env_file}: {e}",
                          file=_sys.stderr)
        return cls(
            chains=data.get("chains") or {},
            pairs=data.get("pairs") or {},
            writers=data.get("writers") or {},
            provider_args=data.get("providers") or {},
            env_path=env_path,
        )

    @classmethod
    def default(cls) -> "RouteConfig":
        """Hard-coded fallback when routes.yaml is missing."""
        return cls(
            chains={
                TASK_CODE_REVIEW: [
                    "ollama:qwen2.5-coder:3b",
                    "groq",
                    "mistral",
                    "cohere",
                ],
                TASK_DESIGN_REVIEW: ["gemini-cli", "claude-cli"],
                TASK_SECURITY_REVIEW: ["gemini-cli", "claude-cli", "groq"],
                TASK_FAST_QA: ["ollama:qwen2.5:0.5b", "groq", "mistral"],
                TASK_GENERAL: ["groq", "mistral", "ollama:qwen2.5:7b", "gemini-cli"],
            },
            # 2-model review pairs. Primary does the heavy thinking, secondary
            # cross-checks. Hermes synthesizes the final verdict.
            pairs={
                TASK_CODE_REVIEW: {
                    "primary": "gemini-cli",
                    "secondary": "ollama:qwen2.5-coder:3b",
                },
                TASK_DESIGN_REVIEW: {
                    "primary": "gemini-cli",
                    "secondary": "claude-cli",
                },
                TASK_SECURITY_REVIEW: {
                    "primary": "claude-cli",
                    "secondary": "gemini-cli",
                },
                TASK_FAST_QA: {
                    "primary": "groq",
                    "secondary": "ollama:qwen2.5:0.5b",
                },
                TASK_GENERAL: {
                    "primary": "groq",
                    "secondary": "mistral",
                },
            },
            # Big models for primary generation (write tasks).
            writers={
                TASK_CODE_REVIEW: "gemini-cli",
                TASK_DESIGN_REVIEW: "gemini-cli",
                TASK_SECURITY_REVIEW: "claude-cli",
                TASK_FAST_QA: "groq",
                TASK_GENERAL: "gemini-cli",
            },
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
    """Routes a task to providers via chain (sequential) or pair (fan-out)."""

    def __init__(self, config: Optional[RouteConfig] = None):
        self.config = config or RouteConfig.load()
        self._cache: dict = {}

    def _get(self, spec: str) -> Provider:
        if spec not in self._cache:
            args = self.config.provider_args.get(spec, {})
            self._cache[spec] = build_provider(spec, args)
        return self._cache[spec]

    # ---- chain accessors --------------------------------------------------

    def chain_for(self, task_type: str) -> list:
        return self.config.chains.get(task_type) or self.config.chains.get(TASK_GENERAL, [])

    def pair_for(self, task_type: str) -> dict:
        return self.config.pairs.get(task_type) or self.config.pairs.get(TASK_GENERAL, {})

    def writer_for(self, task_type: str) -> str:
        return self.config.writers.get(task_type) or self.config.writers.get(TASK_GENERAL, "groq")

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

    # ---- core call modes --------------------------------------------------

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
            # OPUS-1: an exception inside provider.complete() (not just
            # an ok=False reply) used to abort the whole chain. Catch
            # unexpected exceptions, treat as a failed attempt, fall
            # through to the next provider.
            try:
                reply = provider.complete(
                    prompt,
                    system=system,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    timeout=timeout,
                )
            except Exception as e:
                attempts.append((spec, f"exception: {type(e).__name__}: {e}"))
                continue
            if reply.ok:
                if attempts:
                    reply.raw = reply.raw or {}
                    reply.raw["_router_skipped"] = attempts
                return reply
            attempts.append((spec, reply.error or "unknown error"))

        summary = "; ".join(f"{s}: {r}" for s, r in attempts) or "no providers in chain"
        return Reply(
            text="",
            provider="<chain-exhausted>",
            model="<chain-exhausted>",
            error=f"all providers failed: {summary}",
        )

    def call_parallel(
        self,
        specs: Iterable[str],
        prompt: str,
        *,
        system: Optional[str] = None,
        max_tokens: int = 600,
        temperature: float = 0.2,
        timeout: int = 120,
    ) -> list:
        """Fan out to N providers in parallel; return one Reply per spec.

        Every spec is called (no early exit on success). Used for 2-model
        cross-check where we want both opinions regardless of agreement.
        """
        specs = list(specs)
        if not specs:
            return []

        def _one(spec: str) -> Reply:
            try:
                provider = self._get(spec)
            except Exception as e:
                return Reply(text="", provider=spec, model="?", error=f"build failed: {e}")
            if not provider.is_available():
                return Reply(text="", provider=spec, model="?", error="unavailable")
            return provider.complete(
                prompt,
                system=system,
                max_tokens=max_tokens,
                temperature=temperature,
                timeout=timeout,
            )

        # Use threads (providers are network-bound).
        # OPUS-3: enforce timeout at the executor boundary too. The
        # provider-level timeout may be ignored by buggy implementations;
        # future.result(timeout=...) guarantees we don't block forever.
        executor_timeout = max(1, timeout + 5)  # 5s grace beyond provider timeout
        with ThreadPoolExecutor(max_workers=max(1, len(specs))) as ex:
            futures = [ex.submit(_one, s) for s in specs]
            replies = []
            for spec, f in zip(specs, futures):
                try:
                    replies.append(f.result(timeout=executor_timeout))
                except TimeoutError:
                    # OPUS-3: provider ignored its own timeout; we caught
                    # it at the executor level. Must come before the
                    # broader Exception catch (TimeoutError is a subclass).
                    replies.append(Reply(
                        text="", provider=spec, model="?",
                        error=f"executor timeout after {executor_timeout}s",
                    ))
                except Exception as e:
                    # An exception inside the future (shouldn't happen
                    # now that _one catches its own, but defensively):
                    replies.append(Reply(
                        text="", provider=spec, model="?",
                        error=f"future exception: {type(e).__name__}: {e}",
                    ))

        # Preserve the original spec order so the caller can match
        # replies back to providers.
        return list(zip(specs, replies))

    def review_pair(
        self,
        task_type: str,
        prompt: str,
        *,
        system: Optional[str] = None,
        max_tokens: int = 600,
        temperature: float = 0.2,
        timeout: int = 120,
    ) -> dict:
        """Run a 2-model review (primary + secondary) for a task.

        Returns {"primary": (spec, Reply), "secondary": (spec, Reply),
                 "agreement": "agree|disagree|partial"}.
        Agreement is a simple heuristic: both non-empty replies, no
        obvious contradiction marker. Caller (Hermes) does the real
        synthesis.
        """
        pair = self.pair_for(task_type)
        if not pair:
            # No pair configured — fall back to a single call.
            only = self.chain_for(task_type)[0] if self.chain_for(task_type) else None
            if not only:
                return {"primary": (None, Reply(text="", provider="<none>", model="<none>", error="no providers")), "secondary": None, "agreement": "unknown"}
            reply = self.call(task_type, prompt, system=system, max_tokens=max_tokens, temperature=temperature, timeout=timeout)
            return {"primary": (only, reply), "secondary": None, "agreement": "unknown"}

        primary_spec = pair.get("primary")
        secondary_spec = pair.get("secondary")
        results = self.call_parallel(
            [s for s in (primary_spec, secondary_spec) if s],
            prompt,
            system=system,
            max_tokens=max_tokens,
            temperature=temperature,
            timeout=timeout,
        )
        reply_by_spec = dict(results)

        agreement = "unknown"
        primary_reply = reply_by_spec.get(primary_spec)
        secondary_reply = reply_by_spec.get(secondary_spec)
        if primary_reply and secondary_reply and primary_reply.ok and secondary_reply.ok:
            # Cheap agreement heuristic: do they share any obvious
            # positive/negative marker? This is a hint, not a verdict.
            agreement = _quick_agreement(primary_reply.text, secondary_reply.text)

        return {
            "primary": (primary_spec, primary_reply) if primary_spec else None,
            "secondary": (secondary_spec, secondary_reply) if secondary_spec else None,
            "agreement": agreement,
        }


def _quick_agreement(a: str, b: str) -> str:
    """Heuristic: do these two short responses agree?

    Looks for explicit agreement/disagreement markers. Otherwise 'partial'.
    """
    a_low, b_low = a.lower(), b.lower()
    # Explicit disagreement markers (any one in EITHER reply triggers partial)
    for marker in ("however", "but ", "disagree", "incorrect", "wrong", "actually"):
        if marker in a_low or marker in b_low:
            return "partial"
    # Explicit agreement markers (need at least one SHARED marker to count as agree)
    agree_markers = ("agree", "correct", "no issues", "looks good", "no concerns", "fine")
    if any(m in a_low for m in agree_markers) and any(m in b_low for m in agree_markers):
        return "agree"
    return "partial"
