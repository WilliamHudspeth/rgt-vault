"""Cost estimation for the multi-LLM router.

Per-token USD prices for each provider. These are list prices; check
the provider's site for current rates. Free tiers and per-request
minimums are noted in a separate "notes" field but not used in cost
arithmetic (cost is computed as if everything were paid).

To get a usage cost report:
    from scripts.llm import pricing
    from scripts.llm.usage import totals
    pricing.cost_report(totals())
"""
from __future__ import annotations

from typing import Optional


# Per-token USD prices. Keys: provider spec or model name.
# Prices are USD per 1 token (not per 1k). Multiply by 1M for per-1M.
PRICES = {
    # Mistral (https://mistral.ai/products/la-plateforme#pricing)
    "mistral-small-latest": {"in": 0.20 / 1_000_000, "out": 0.60 / 1_000_000},
    # Groq (free tier; nominal cost listed)
    "llama-3.3-70b-versatile": {"in": 0.59 / 1_000_000, "out": 0.79 / 1_000_000},
    # Cohere (command-r-plus)
    "command-r-plus-08-2024": {"in": 2.50 / 1_000_000, "out": 10.00 / 1_000_000},
    # Ollama local models: electricity cost only. Estimate $0.05 per kWh,
    # 7B model draws ~30W, ~50 tokens/s -> 60k tokens per kWh -> ~$0.000001
    # per token. Effectively free.
    "ollama-local": {"in": 0.0, "out": 0.0},
    # Gemini CLI: free tier (OAuth-personal). Quota unknown.
    "gemini-cli": {"in": 0.0, "out": 0.0},
    # Claude Code: subscription ($20/mo Pro), per-token cost effectively free
    # at the API rate. Rough Anthropic API pricing:
    "claude-cli": {"in": 3.00 / 1_000_000, "out": 15.00 / 1_000_000},
}


def _lookup_price(provider: str, model: str) -> dict:
    """Best-effort lookup; falls back to ollama-local / free defaults."""
    # Try model first
    if model in PRICES:
        return PRICES[model]
    # Then provider name
    if provider in PRICES:
        return PRICES[provider]
    # Common aliases
    if provider.startswith("ollama:"):
        return PRICES["ollama-local"]
    if provider == "gemini-cli":
        return PRICES["gemini-cli"]
    if provider == "claude-cli":
        return PRICES["claude-cli"]
    # Unknown — assume free
    return {"in": 0.0, "out": 0.0}


def estimate_cost(provider: str, model: str, input_tokens: int, output_tokens: int) -> float:
    """Return USD cost for a single call."""
    p = _lookup_price(provider, model)
    return input_tokens * p["in"] + output_tokens * p["out"]


def cost_report(totals: dict) -> str:
    """Render a cost summary from a totals() dict.

    totals shape: {(provider, model): {calls, ok, in_tok, out_tok, lat_ms}}
    """
    if not totals:
        return "no usage data"

    lines = ["Cost report:", ""]
    total_cost = 0.0
    rows = []
    for (provider, model), a in sorted(totals.items()):
        cost = estimate_cost(provider, model, a["input_tokens"], a["output_tokens"])
        total_cost += cost
        rows.append((provider, model, a["calls"], a["input_tokens"],
                     a["output_tokens"], cost))
    lines.append(f"{'provider':<28} {'model':<28} {'calls':>6} {'in_tok':>10} "
                 f"{'out_tok':>10} {'cost_usd':>12}")
    lines.append("-" * 100)
    for provider, model, calls, in_tok, out_tok, cost in rows:
        lines.append(
            f"{provider:<28} {model:<28} {calls:>6} {in_tok:>10} "
            f"{out_tok:>10} {cost:>12.6f}"
        )
    lines.append("-" * 100)
    lines.append(f"{'TOTAL':<28} {'':<28} {'':>6} {'':>10} {'':>10} {total_cost:>12.6f}")
    return "\n".join(lines)
