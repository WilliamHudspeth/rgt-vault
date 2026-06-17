# AFK Session Summary — 2026-06-17

While you were away, this happened.

## What was built

5 new commits pushed to master (in chronological order):

1. `feat(llm): multi-provider LLM router with kanban dispatch` — the foundation
2. `feat(llm): multi-model fan-out (1 big + 2 small in parallel) for reviews`
3. `feat(llm): AFK kanban_loop — multi-model review + Multica comment synthesis`
4. `feat(governance): Phase 3 hardening — ADRs, review checklists, security gates, CI`
5. `feat(llm): usage tracking + 'burn' CLI for quota exhaustion`
6. `feat(llm): streaming mode + 'stream' CLI`
7. `feat(llm): cost estimation per provider + integrated cost report in 'usage'`

(That's 7 actually; the governance one was rolled in separately earlier.)

## Provider inventory (live-tested 2026-06-17)

| Provider | Spec | Status | Best for |
|----------|------|--------|----------|
| Claude Code CLI | `claude-cli` | ACTIVE (OAuth) | Deep design review |
| Gemini CLI | `gemini-cli` | ACTIVE (OAuth-personal quota) | Primary writer/reviewer |
| Ollama local | `ollama:<model>` | OK on most models | Free local inference |
| Mistral API | `mistral` | OK | Fast + cheap |
| Cohere API | `cohere` | OK | Fallback |
| Groq API | `groq` | OK | Fastest (sub-second) |
| Gemini REST | (direct API key) | DEPLETED | Not usable |
| Ollama remote (Hanjo) | `http://10.10.88.83:11434` | slow cold start | — |

## Test coverage

- 38 unit tests in `scripts/llm/tests/`, all passing
- 13 router tests (chains, pairs, parallel call, fallback, dry-run)
- 5 usage-tracker tests (thread-safety, aggregation, summary)
- 7 stream tests (parse NDJSON, SSE chunks, done marker handling)
- 7 pricing tests (per-provider rates, aggregation, fallback)

## Multica activity

- 85 total comments posted
- 66 of them AFK-tagged from the parallel review loops
- 30 unique tickets reviewed
- 12 tickets remaining out of 42 originally open

## Background processes still running

```
PID 2496847: bash wrapper for burn loop
PID 2496861: python3 burn --provider gemini-cli --calls 500 --max-tokens 3000
PID 2505068: bash wrapper for loop A (kanban_loop)
PID 2505082: python3 kanban_loop --loop --sleep 0 --limit 30
PID 2505474: bash wrapper for loop B (deep-dive, max-tokens=1500)
PID 2505488: python3 ... loop B
PID 2505839: bash wrapper for loop C (max-tokens=4000)
PID 2505854: python3 ... loop C
```

State files in `/tmp/`:
- `rgt_kanban_loop_state.json` (loop A — standard)
- `rgt_kanban_loop_state_b.json` (loop B — deep-dive synthesis)
- `rgt_kanban_loop_state_c.json` (loop C — maxed-out)
- `rgt_llm_usage.csv` (every provider call logged)

## CLI commands now available

```bash
# Single-model (first available in chain)
python3 scripts/llm/cli.py code-review -f path/to/code.py

# Multi-model: 1 big + 2 small in parallel
python3 scripts/llm/cli.py review --big gemini-cli -f code.py

# Free-form parallel to any provider list
python3 scripts/llm/cli.py fanout \
    --provider gemini-cli \
    --provider ollama:qwen2.5-coder:3b \
    --provider groq \
    -p "Review this code"

# Streaming response (chunks as they arrive)
python3 scripts/llm/cli.py stream --provider groq -p "..."

# Drain quota (AFK use)
python3 scripts/llm/cli.py burn \
    --provider gemini-cli \
    --calls 500 \
    --max-tokens 3000

# Usage + cost report
python3 scripts/llm/cli.py usage

# Show configured chains / pairs
python3 scripts/llm/cli.py show-chains
python3 scripts/llm/cli.py show-pairs

# AFK kanban processor
python3 scripts/llm/kanban_loop.py --once --limit 5
python3 scripts/llm/kanban_loop.py --loop --sleep 60
python3 scripts/llm/kanban_review.py --identifier RGT-26  # one ticket
```

## Known issues

- **Ollama 404s intermittently**: `/api/chat` returns "model not found" even when `/api/tags` shows it. The daemon is in a degraded state; restart fixes it. Fallback chain handles it cleanly.
- **Loop A appears stuck at 8 tickets**: state file shows `last_run=08:21:09Z` (from before restart). It's processing tickets but state isn't being saved mid-pass. Will save when pass completes.
- **CLI providers don't report tokens**: subprocess wrappers (`claude-cli`, `gemini-cli`) don't expose token counts. Only REST API providers (mistral, cohere, groq) log real token counts. CLI providers log latency + ok/error but 0/0 for tokens.

## To stop the loops

```bash
kill 2496861 2505082 2505488 2505854
```

Or all of them at once:
```bash
pkill -f 'kanban_loop\|scripts/llm/cli.py burn'
```

## Files added

```
scripts/llm/__init__.py            (updated)
scripts/llm/types.py
scripts/llm/router.py              (fan-out + pairs)
scripts/llm/routes.yaml
scripts/llm/cli.py                 (review, fanout, burn, stream, usage)
scripts/llm/kanban_review.py       (one-ticket processor)
scripts/llm/kanban_loop.py         (AFK multi-ticket loop)
scripts/llm/usage.py               (CSV logger)
scripts/llm/pricing.py             (cost estimator)
scripts/llm/stream.py              (NDJSON + SSE streaming)
scripts/llm/providers/_http.py
scripts/llm/providers/cli.py
scripts/llm/providers/cohere.py
scripts/llm/providers/groq.py
scripts/llm/providers/mistral.py
scripts/llm/providers/ollama.py
scripts/llm/tests/test_router.py
scripts/llm/tests/test_usage.py
scripts/llm/tests/test_stream.py
scripts/llm/tests/test_pricing.py
```

Plus the Phase 3 governance hardening: 4 ADRs, 5 review checklists, 4 program docs, 1 CI workflow, 4 program scripts.
