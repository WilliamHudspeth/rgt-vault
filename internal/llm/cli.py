#!/usr/bin/env python3
"""CLI entry point for the multi-LLM router.

Usage:
  python3 scripts/llm/cli.py code-review -f path/to/code.py
  python3 scripts/llm/cli.py code-review --prompt "Review this Python: ..."
  python3 scripts/llm/cli.py fast-qa -p "Is the function below correct? ..."
  python3 scripts/llm/cli.py code-review --dry-run --show-chain
  python3 scripts/llm/cli.py list-tasks
  python3 scripts/llm/cli.py show-chains

Set keys before invoking (only the providers in the chosen chain need them):
  set -a; . ~/.config/llm-review/keys.env; set +a
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Allow running as a script without install
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from internal.llm.router import (
    TASK_CODE_REVIEW,
    TASK_DESIGN_REVIEW,
    TASK_FAST_QA,
    TASK_GENERAL,
    TASK_SECURITY_REVIEW,
    Router,
)

TASKS = [
    TASK_CODE_REVIEW,
    TASK_DESIGN_REVIEW,
    TASK_SECURITY_REVIEW,
    TASK_FAST_QA,
    TASK_GENERAL,
]


# Default system prompts per task
SYSTEM_PROMPTS = {
    TASK_CODE_REVIEW: (
        "You are a code reviewer. Find concrete bugs, security issues, "
        "and obvious style problems. Reply in 3-6 short bullets. Do not "
        "praise the code; only call out issues or risks. Be terse."
    ),
    TASK_DESIGN_REVIEW: (
        "You are a senior architect. Critique the design and call out "
        "risks, missing abstractions, and refactoring opportunities. "
        "Be specific and terse."
    ),
    TASK_SECURITY_REVIEW: (
        "You are a security engineer. Identify concrete security issues, "
        "threat-model gaps, and missing controls. Be specific about "
        "the attack and the fix."
    ),
    TASK_FAST_QA: "Answer concisely. One or two sentences max.",
    TASK_GENERAL: "You are a helpful assistant. Be concise.",
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Multi-LLM router CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Per-task subcommand (single-model: first-available)
    for task in TASKS:
        sp = sub.add_parser(task, help=f"Run a {task} prompt (single model)")
        _add_common_args(sp)

    # Multi-model review: 1 big model + 2 small models in parallel
    rev = sub.add_parser(
        "review",
        help="Multi-model review: 1 big (claude-cli/gemini-cli) + 2 small models in parallel",
    )
    _add_common_args(rev)
    rev.add_argument(
        "--big",
        default="claude-cli",
        help="Big model for primary review (default: claude-cli). Use gemini-cli for the free OAuth-personal quota.",
    )
    rev.add_argument(
        "--small",
        action="append",
        default=None,
        help="Small model for cross-check (repeatable). Default: ollama:qwen2.5-coder:3b, groq",
    )

    # Free-form parallel: any list of providers
    fan = sub.add_parser(
        "fanout",
        help="Fan out a prompt to an explicit list of providers in parallel",
    )
    _add_common_args(fan)
    fan.add_argument(
        "--provider",
        action="append",
        required=True,
        help="Provider spec (repeatable). e.g. --provider claude-cli --provider groq",
    )

    # Quota-burn mode: hammer a provider with auto-generated prompts.
    burn = sub.add_parser(
        "burn",
        help="Drain a provider's quota with auto-generated prompts (AFK use)",
    )
    burn.add_argument(
        "--provider",
        default="gemini-cli",
        help="Provider to drain (default: gemini-cli)",
    )
    burn.add_argument(
        "--calls",
        type=int,
        default=100,
        help="Number of calls to make (default 100)",
    )
    burn.add_argument(
        "--max-tokens",
        type=int,
        default=2000,
        help="Max output tokens per call (default 2000)",
    )
    burn.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Per-call timeout (default 120s)",
    )
    burn.add_argument(
        "--topics",
        nargs="+",
        default=None,
        help="List of topic seeds to rotate through; default = a built-in list",
    )
    burn.add_argument(
        "--sleep",
        type=float,
        default=0.0,
        help="Seconds to sleep between calls (default 0 = max throughput)",
    )

    # Streaming mode: print chunks as they arrive.
    st = sub.add_parser(
        "stream",
        help="Stream a prompt to a provider; print chunks as they arrive",
    )
    _add_common_args(st)
    st.add_argument(
        "--provider",
        default="ollama:qwen2.5:7b",
        help="Provider spec (default: ollama:qwen2.5:7b). Currently ollama and "
        "OpenAI-compatible (groq/mistral/cohere) are supported.",
    )

    # Usage summary: print the rolling totals from /tmp/rgt_llm_usage.csv
    sub.add_parser("usage", help="Print usage summary from /tmp/rgt_llm_usage.csv")

    sub.add_parser("list-tasks", help="List known task types")
    sub.add_parser("show-chains", help="Show configured provider chains")
    sub.add_parser("show-pairs", help="Show configured 2-model review pairs")
    return p


def _add_common_args(sp: argparse.ArgumentParser):
    src = sp.add_argument_group("input")
    src.add_argument("--prompt", "-p", help="Inline prompt")
    src.add_argument("--file", "-f", help="Read prompt from file")
    src.add_argument(
        "--system",
        "-s",
        help="Override the default system prompt for this task",
    )

    run = sp.add_argument_group("runtime")
    run.add_argument("--max-tokens", type=int, default=600)
    run.add_argument("--temperature", type=float, default=0.2)
    run.add_argument("--timeout", type=int, default=60)
    run.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the first-available provider without calling it",
    )
    run.add_argument(
        "--show-chain",
        action="store_true",
        help="Print the configured chain for this task before calling",
    )
    run.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON envelope instead of the raw reply text",
    )


def read_prompt(args) -> str:
    if args.prompt and args.file:
        raise SystemExit("use either --prompt or --file, not both")
    if args.file:
        return Path(args.file).read_text()
    if args.prompt:
        return args.prompt
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise SystemExit("no prompt: provide --prompt, --file, or pipe stdin")


def cmd_run(task: str, args) -> int:
    router = Router()
    chain = router.chain_for(task)

    if args.show_chain:
        print(f"# chain for {task}:")
        for spec in chain:
            avail = "?"
            try:
                p = router._get(spec)  # noqa: SLF001
                avail = "ok" if p.is_available() else "missing"
            except Exception as e:
                avail = f"err:{e}"
            print(f"  {spec}  [{avail}]")
        print()

    if args.dry_run:
        reply = router.call(task, "", system="", max_tokens=0, dry_run=True)
        print(
            json.dumps(
                {
                    "task": task,
                    "would_call_provider": reply.provider,
                    "would_call_model": reply.model,
                    "error": reply.error,
                },
                indent=2,
            )
        )
        return 0 if reply.provider != "<chain-exhausted>" else 1

    prompt = read_prompt(args)
    system = args.system or SYSTEM_PROMPTS.get(task, "")

    reply = router.call(
        task,
        prompt,
        system=system,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
        timeout=args.timeout,
    )

    if args.json:
        print(
            json.dumps(
                {
                    "task": task,
                    "ok": reply.ok,
                    "provider": reply.provider,
                    "model": reply.model,
                    "input_tokens": reply.input_tokens,
                    "output_tokens": reply.output_tokens,
                    "total_tokens": reply.total_tokens,
                    "latency_ms": reply.latency_ms,
                    "text": reply.text,
                    "error": reply.error,
                },
                indent=2,
            )
        )
    else:
        if reply.ok:
            print(reply.text)
            print(
                f"\n# {reply.provider}/{reply.model}  "
                f"in={reply.input_tokens} out={reply.output_tokens}  "
                f"{reply.latency_ms}ms",
                file=sys.stderr,
            )
        else:
            print(f"ERROR: {reply.error}", file=sys.stderr)

    return 0 if reply.ok else 1


def cmd_list_tasks(_args) -> int:
    for t in TASKS:
        print(t)
    return 0


# Default topic seeds for quota-burn mode.
DEFAULT_BURN_TOPICS = [
    "explain the design trade-offs of using a content-addressable storage layer for a vault project",
    "write a detailed threat model for an agent-based secret management system",
    "describe the failure modes of a SQLite-based audit log under high write load",
    "compare Ed25519 vs RSA-PSS for capability token signing in a multi-tenant environment",
    "outline a code review checklist specifically for cryptographic primitives in Python",
    "discuss why hash-linked audit chains are tamper-evident but not tamper-proof",
    "explain how to safely handle private key material in a long-running service process",
    "list common mistakes when implementing ABAC policies and how to avoid them",
    "design a token rotation strategy that minimizes the blast radius of a leaked credential",
    "compare the operational cost of running a local Ollama cluster vs hosted inference APIs",
]


def cmd_burn(args) -> int:
    """Drain a provider's quota by hammering it with prompts."""
    from internal.llm.router import build_provider

    try:
        provider = build_provider(args.provider)
    except Exception as e:
        print(f"ERROR building provider {args.provider!r}: {e}", file=sys.stderr)
        return 2

    if not provider.is_available():
        print(f"ERROR: provider {args.provider!r} not available", file=sys.stderr)
        return 2

    topics = args.topics or DEFAULT_BURN_TOPICS
    print(
        f"Burning {args.provider}/{provider.model}: {args.calls} calls, "
        f"max_tokens={args.max_tokens}, topics={len(topics)}",
        file=sys.stderr,
    )

    ok = 0
    errs = 0
    total_in = 0
    total_out = 0
    t_start = time.time()
    for i in range(args.calls):
        topic = topics[i % len(topics)]
        prompt = (
            f"You are helping drain a quota deliberately. "
            f"Provide a thorough, detailed response (the longer the better) "
            f"on the following topic. Include examples, edge cases, and "
            f"practical recommendations.\n\nTopic #{i + 1}: {topic}"
        )
        reply = provider.complete(
            prompt,
            max_tokens=args.max_tokens,
            timeout=args.timeout,
        )
        if reply.ok:
            ok += 1
            total_in += reply.input_tokens
            total_out += reply.output_tokens
            print(
                f"[{i + 1}/{args.calls}] {reply.provider}/{reply.model}  "
                f"in={reply.input_tokens} out={reply.output_tokens}  "
                f"{reply.latency_ms}ms  "
                f"total_in={total_in} total_out={total_out}",
                file=sys.stderr,
                flush=True,
            )
        else:
            errs += 1
            print(f"[{i + 1}/{args.calls}] ERROR: {reply.error}", file=sys.stderr, flush=True)
            time.sleep(min(5, 2 ** min(errs, 5)))
        if args.sleep:
            time.sleep(args.sleep)

    wall = int((time.time() - t_start) * 1000)
    print(
        f"\n=== BURN DONE: {ok}/{args.calls} ok, {errs} errors, "
        f"wall={wall}ms, tokens in={total_in} out={total_out} ===",
        file=sys.stderr,
    )
    return 0 if ok > 0 else 1


def cmd_usage(_args) -> int:
    """Print usage + cost summary from /tmp/rgt_llm_usage.csv."""
    from internal.llm import pricing, usage

    print(usage.summary())
    print()
    print(pricing.cost_report(usage.totals()))
    return 0


def cmd_stream(args) -> int:
    """Stream a prompt to a provider."""
    from internal.llm.stream import stream_ollama, stream_openai_chat

    prompt = read_prompt(args)
    system = args.system or ""
    spec = args.provider

    if spec.startswith("ollama:"):
        model = spec[len("ollama:") :]
        # No way to know the base_url here without re-reading routes.yaml;
        # we default to localhost which covers 95% of usage.
        try:
            for chunk in stream_ollama(
                "http://localhost:11434",
                model,
                prompt,
                system=system or None,
                max_tokens=args.max_tokens,
                timeout=args.timeout,
            ):
                print(chunk, end="", flush=True)
            print()
        except RuntimeError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        return 0

    # OpenAI-compatible: groq, mistral, cohere
    if spec in ("groq", "mistral", "cohere"):
        import os

        key_env = {"groq": "GROQ_API_KEY", "mistral": "MISTRAL_API_KEY", "cohere": "COHERE_API_KEY"}[spec]
        key = os.environ.get(key_env)
        if not key:
            print(f"ERROR: {key_env} not set", file=sys.stderr)
            return 1
        base_urls = {
            "groq": "https://api.groq.com/openai/v1",
            "mistral": "https://api.mistral.ai/v1",
            "cohere": "https://api.cohere.com/v1",
        }
        models = {
            "groq": "llama-3.3-70b-versatile",
            "mistral": "mistral-small-latest",
            "cohere": "command-r-plus-08-2024",
        }
        extra = {"User-Agent": "hermes-llm-review/1.0"} if spec == "groq" else None
        try:
            for chunk in stream_openai_chat(
                base_urls[spec],
                key,
                models[spec],
                prompt,
                system=system or None,
                max_tokens=args.max_tokens,
                timeout=args.timeout,
                extra_headers=extra,
            ):
                print(chunk, end="", flush=True)
            print()
        except RuntimeError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        return 0

    # Anything else (claude-cli, gemini-cli) — not yet wired for streaming
    print(f"ERROR: streaming not implemented for {spec!r}", file=sys.stderr)
    return 2


def cmd_show_chains(_args) -> int:
    router = Router()
    for task in TASKS:
        chain = router.chain_for(task)
        print(f"\n# {task}")
        for spec in chain:
            print(f"  {spec}")
    return 0


def cmd_show_pairs(_args) -> int:
    router = Router()
    for task in TASKS:
        pair = router.pair_for(task)
        print(f"\n# {task}")
        print(f"  primary:   {pair.get('primary')}")
        print(f"  secondary: {pair.get('secondary')}")
    return 0


def _print_review(replies, big_label="BIG"):
    """Pretty-print a list of (spec, Reply) tuples."""
    for spec, reply in replies:
        if reply is None:
            print(f"\n--- {spec}: <no reply>")
            continue
        if not reply.ok:
            print(f"\n--- {spec}: ERROR {reply.error}")
            continue
        print(f"\n{'=' * 60}")
        print(
            f"--- {spec} ({reply.provider}/{reply.model})  "
            f"in={reply.input_tokens} out={reply.output_tokens}  {reply.latency_ms}ms"
        )
        print(f"{'=' * 60}")
        print(reply.text)


def cmd_review(args) -> int:
    """Multi-model review: 1 big model + N small models in parallel."""
    big = args.big
    smalls = args.small or ["ollama:qwen2.5-coder:3b", "groq"]
    specs = [big] + list(smalls)

    if args.dry_run:
        router = Router()
        out = []
        for s in specs:
            try:
                p = router._get(s)  # noqa: SLF001
                out.append({"spec": s, "available": p.is_available()})
            except Exception as e:
                out.append({"spec": s, "available": False, "error": str(e)})
        print(json.dumps({"task": "review", "providers": out}, indent=2))
        return 0

    prompt = read_prompt(args)
    system = args.system or (
        "You are reviewing code. Find concrete bugs, security issues, "
        "and missing error handling. Be terse and specific. 3-6 bullets max."
    )

    router = Router()
    t0 = time.time()
    replies = router.call_parallel(
        specs,
        prompt,
        system=system,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
        timeout=args.timeout,
    )
    wall = int((time.time() - t0) * 1000)

    if args.json:
        print(
            json.dumps(
                {
                    "task": "review",
                    "big": big,
                    "small": smalls,
                    "wall_ms": wall,
                    "replies": [
                        {
                            "spec": spec,
                            "ok": r.ok,
                            "provider": r.provider,
                            "model": r.model,
                            "latency_ms": r.latency_ms,
                            "input_tokens": r.input_tokens,
                            "output_tokens": r.output_tokens,
                            "text": r.text,
                            "error": r.error,
                        }
                        for spec, r in replies
                    ],
                },
                indent=2,
            )
        )
    else:
        _print_review(replies, big_label=big)
        print(f"\n# wall: {wall}ms, big={big}, small={','.join(smalls)}", file=sys.stderr)

    # exit 0 if at least one model succeeded
    return 0 if any(r.ok for _, r in replies) else 1


def cmd_fanout(args) -> int:
    """Free-form parallel: any list of providers."""
    if args.dry_run:
        router = Router()
        out = []
        for s in args.provider:
            try:
                p = router._get(s)  # noqa: SLF001
                out.append({"spec": s, "available": p.is_available()})
            except Exception as e:
                out.append({"spec": s, "available": False, "error": str(e)})
        print(json.dumps({"providers": out}, indent=2))
        return 0

    prompt = read_prompt(args)
    system = args.system or ""
    router = Router()
    t0 = time.time()
    replies = router.call_parallel(
        args.provider,
        prompt,
        system=system,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
        timeout=args.timeout,
    )
    wall = int((time.time() - t0) * 1000)

    if args.json:
        print(
            json.dumps(
                {
                    "wall_ms": wall,
                    "replies": [
                        {
                            "spec": spec,
                            "ok": r.ok,
                            "provider": r.provider,
                            "model": r.model,
                            "latency_ms": r.latency_ms,
                            "input_tokens": r.input_tokens,
                            "output_tokens": r.output_tokens,
                            "text": r.text,
                            "error": r.error,
                        }
                        for spec, r in replies
                    ],
                },
                indent=2,
            )
        )
    else:
        _print_review(replies)
        print(f"\n# wall: {wall}ms", file=sys.stderr)

    return 0 if any(r.ok for _, r in replies) else 1


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "list-tasks":
        return cmd_list_tasks(args)
    if args.cmd == "show-chains":
        return cmd_show_chains(args)
    if args.cmd == "show-pairs":
        return cmd_show_pairs(args)
    if args.cmd == "review":
        return cmd_review(args)
    if args.cmd == "fanout":
        return cmd_fanout(args)
    if args.cmd == "burn":
        return cmd_burn(args)
    if args.cmd == "stream":
        return cmd_stream(args)
    if args.cmd == "usage":
        return cmd_usage(args)
    if args.cmd in TASKS:
        return cmd_run(args.cmd, args)

    parser.error(f"unknown command: {args.cmd}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
