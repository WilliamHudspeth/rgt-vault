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
from pathlib import Path

# Allow running as a script without install
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.llm.router import (
    Router,
    TASK_CODE_REVIEW,
    TASK_DESIGN_REVIEW,
    TASK_SECURITY_REVIEW,
    TASK_FAST_QA,
    TASK_GENERAL,
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

    # Per-task subcommand
    for task in TASKS:
        sp = sub.add_parser(task, help=f"Run a {task} prompt")
        _add_common_args(sp)

    sub.add_parser("list-tasks", help="List known task types")
    sub.add_parser("show-chains", help="Show configured provider chains")
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
        reply = router.call(
            task, "", system="", max_tokens=0, dry_run=True
        )
        print(json.dumps({
            "task": task,
            "would_call_provider": reply.provider,
            "would_call_model": reply.model,
            "error": reply.error,
        }, indent=2))
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
        print(json.dumps({
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
        }, indent=2))
    else:
        if reply.ok:
            print(reply.text)
            print(f"\n# {reply.provider}/{reply.model}  "
                  f"in={reply.input_tokens} out={reply.output_tokens}  "
                  f"{reply.latency_ms}ms", file=sys.stderr)
        else:
            print(f"ERROR: {reply.error}", file=sys.stderr)

    return 0 if reply.ok else 1


def cmd_list_tasks(_args) -> int:
    for t in TASKS:
        print(t)
    return 0


def cmd_show_chains(_args) -> int:
    router = Router()
    for task in TASKS:
        chain = router.chain_for(task)
        print(f"\n# {task}")
        for spec in chain:
            print(f"  {spec}")
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "list-tasks":
        return cmd_list_tasks(args)
    if args.cmd == "show-chains":
        return cmd_show_chains(args)
    if args.cmd in TASKS:
        return cmd_run(args.cmd, args)

    parser.error(f"unknown command: {args.cmd}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
