"""CLI providers: spawn `claude -p` and `gemini -p` as subprocesses.

These are useful when the binary already has auth baked in (via OAuth) so
no API key management is needed from us. They are slower than the API
providers but are the path of least resistance for design-level work.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import Optional

from ..types import Provider, Reply


class ClaudeCLIProvider(Provider):
    """Wraps the locally-installed `claude` (Claude Code) binary.

    Auth: ~/.claude/.credentials.json (managed by the claude CLI itself).
    Model: defaults to sonnet[1m] (set in ~/.claude/settings.json).
    """

    name = "claude-cli"
    model = "sonnet"

    def __init__(self, model: Optional[str] = None):
        if model:
            self.model = model

    def is_available(self) -> bool:
        return shutil.which("claude") is not None

    def complete(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        max_tokens: int = 600,
        temperature: float = 0.2,
        timeout: int = 180,
    ) -> Reply:
        if not self.is_available():
            return self._unavailable_reply("claude binary not on PATH")

        full = prompt if not system else f"{system}\n\n{prompt}"

        t0 = time.time()
        try:
            proc = subprocess.run(
                ["claude", "-p", "--model", self.model],
                input=full,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=os.environ,
            )
        except subprocess.TimeoutExpired:
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=int((time.time() - t0) * 1000),
                error=f"timeout after {timeout}s",
            )
        except Exception as e:
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=int((time.time() - t0) * 1000),
                error=f"{type(e).__name__}: {e}",
            )

        latency = int((time.time() - t0) * 1000)
        if proc.returncode != 0:
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=latency,
                error=f"claude exit {proc.returncode}: {proc.stderr.strip()[:300]}",
            )
        # claude -p returns just the text on stdout
        return Reply(
            text=proc.stdout.strip(),
            provider=self.name,
            model=self.model,
            latency_ms=latency,
        )


class GeminiCLIProvider(Provider):
    """Wraps the locally-installed `gemini` (Gemini CLI) binary.

    Auth: ~/.gemini/oauth_creds.json (OAuth-personal, separate quota from
    the API key which is currently depleted).
    """

    name = "gemini-cli"
    model = "default"  # CLI picks its own default

    def is_available(self) -> bool:
        return shutil.which("gemini") is not None

    def complete(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        max_tokens: int = 600,
        temperature: float = 0.2,
        timeout: int = 180,
    ) -> Reply:
        if not self.is_available():
            return self._unavailable_reply("gemini binary not on PATH")

        full = prompt if not system else f"{system}\n\n{prompt}"

        t0 = time.time()
        try:
            proc = subprocess.run(
                ["gemini", "-p", full],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=os.environ,
            )
        except subprocess.TimeoutExpired:
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=int((time.time() - t0) * 1000),
                error=f"timeout after {timeout}s",
            )
        except Exception as e:
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=int((time.time() - t0) * 1000),
                error=f"{type(e).__name__}: {e}",
            )

        latency = int((time.time() - t0) * 1000)
        if proc.returncode != 0:
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=latency,
                error=f"gemini exit {proc.returncode}: {proc.stderr.strip()[:300]}",
            )
        # gemini -p echoes "Warning: True color..." on stderr but puts the
        # answer on stdout. Strip blank lines and the warning from output.
        text = "\n".join(
            ln for ln in proc.stdout.splitlines() if ln.strip() and not ln.startswith("Warning:")
        ).strip()
        return Reply(
            text=text,
            provider=self.name,
            model=self.model,
            latency_ms=latency,
        )
