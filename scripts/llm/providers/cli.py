"""CLI providers: spawn `claude -p` and `gemini -p` as subprocesses.

These are useful when the binary already has auth baked in (via OAuth) so
no API key management is needed from us. They are slower than the API
providers but are the path of least resistance for design-level work.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import time
from typing import Optional

from .. import usage as usage_tracker
from ..types import Provider, Reply


def _subprocess_env() -> dict:
    """Curated env for CLI subprocesses (OPUS-10).

    Pass through only PATH (so the binary resolves) and HOME (so OAuth
    credentials at ~/.claude/, ~/.gemini/ are accessible). Everything else
    — API keys for other providers, Hermes env, debug flags — is
    deliberately excluded so a leaked prompt or hostile subprocess can't
    extract unrelated secrets from the parent's environment.
    """
    return {
        k: v
        for k, v in os.environ.items()
        if k in ("PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "TZ")
    }


# OPUS-11: patterns that look like secrets / paths we should redact
# from any subprocess stderr before it lands in Reply.error or a log.
_REDACT_PATTERNS = [
    # API keys / tokens (anything that looks like sk-..., ghp_..., ya29.,
    # eyJ... JWTs, etc.)
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"ya29\.[A-Za-z0-9_-]+"), "[REDACTED_TOKEN]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{50,}"), "[REDACTED_JWT]"),
    (re.compile(r"ghp_[A-Za-z0-9]+"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]+"), "[REDACTED_SLACK_TOKEN]"),
    # Home directory paths
    (re.compile(r"/home/[^/]+/"), "/home/USER/"),
    (re.compile(r"/Users/[^/]+/"), "/Users/USER/"),
    # Bearer tokens in headers
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._-]{20,}"), r"\1[REDACTED_TOKEN]"),
]


def _scrub(stderr: str) -> str:
    """Redact secrets and home paths from subprocess stderr (OPUS-11)."""
    out = stderr
    for pattern, replacement in _REDACT_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


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
        # OPUS-10: curated env (no API keys for other providers).
        # OPUS-8 (FIXED): use Popen + start_new_session=True so we can
        # actually killpg on timeout. The old code used subprocess.run,
        # which doesn't expose a handle, so _kill_pg() could never run
        # and grandchildren (Node helpers under claude) leaked in a new
        # session. We use proc.communicate(timeout=) to enforce the
        # deadline without subprocess.run's blocked read.
        proc = subprocess.Popen(
            ["claude", "-p", "--model", self.model],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_subprocess_env(),
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(input=full, timeout=timeout)
        except subprocess.TimeoutExpired:
            # OPUS-8: kill the whole process group to reap grandchildren.
            latency = int((time.time() - t0) * 1000)
            err = f"timeout after {timeout}s (process group killed)"
            _kill_pg(proc)
            # Drain pipes so the child doesn't block on a full pipe buffer.
            try:
                proc.communicate(timeout=1)
            except Exception:
                pass
            usage_tracker.log(provider=self.name, model=self.model, latency_ms=latency, ok=False, error=err)
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=latency,
                error=err,
            )
        except Exception as e:
            latency = int((time.time() - t0) * 1000)
            err = f"{type(e).__name__}: {e}"
            try:
                _kill_pg(proc)
            except Exception:
                pass
            usage_tracker.log(provider=self.name, model=self.model, latency_ms=latency, ok=False, error=err)
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=latency,
                error=err,
            )

        latency = int((time.time() - t0) * 1000)
        # OPUS-11 (FIXED): scrub BEFORE truncating. The old order
        # truncated stderr to 300 chars first, so a secret straddling
        # the cut could leave an unmatched partial token in the output.
        scrubbed_stderr = _scrub(stderr or "")[:300]
        if proc.returncode != 0:
            err = f"claude exit {proc.returncode}: {scrubbed_stderr}"
            usage_tracker.log(provider=self.name, model=self.model, latency_ms=latency, ok=False, error=err)
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=latency,
                error=err,
            )
        # OPUS-12: empty stdout with exit 0 is not a real success.
        if not (stdout or "").strip():
            err = "claude exit 0 with empty stdout (treated as failure)"
            usage_tracker.log(provider=self.name, model=self.model, latency_ms=latency, ok=False, error=err)
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=latency,
                error=err,
            )
        # claude -p returns just the text on stdout
        usage_tracker.log(provider=self.name, model=self.model, latency_ms=latency, ok=True)
        return Reply(
            text=(stdout or "").strip(),
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

    def __init__(self, model: Optional[str] = None):
        if model:
            self.model = model

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
        # OPUS-10: curated env (no API keys for other providers).
        # OPUS-8 (FIXED): use Popen + start_new_session=True so killpg
        # actually runs on timeout. subprocess.run never exposed the
        # handle. See ClaudeCLIProvider.complete for the full rationale.
        # OPUS-21: tried `--` separator; Gemini CLI rejects it. We
        # instead pre-pend a space if `full` starts with `-` so the
        # prompt can never be parsed as a flag.
        safe_full = full if not full.startswith("-") else " " + full
        # Build the argv. Pass --model when a non-default model was
        # configured. The old code silently dropped routes.yaml's
        # provider_args.model for Gemini and let the CLI's own default
        # win every time.
        argv = ["gemini", "-p", safe_full]
        if self.model and self.model != "default":
            argv += ["--model", self.model]

        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_subprocess_env(),
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(input=None, timeout=timeout)
        except subprocess.TimeoutExpired:
            # OPUS-8: kill the whole process group to reap grandchildren.
            latency = int((time.time() - t0) * 1000)
            err = f"timeout after {timeout}s (process group killed)"
            _kill_pg(proc)
            try:
                proc.communicate(timeout=1)
            except Exception:
                pass
            usage_tracker.log(provider=self.name, model=self.model, latency_ms=latency, ok=False, error=err)
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=latency,
                error=err,
            )
        except Exception as e:
            latency = int((time.time() - t0) * 1000)
            err = f"{type(e).__name__}: {e}"
            try:
                _kill_pg(proc)
            except Exception:
                pass
            usage_tracker.log(provider=self.name, model=self.model, latency_ms=latency, ok=False, error=err)
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=latency,
                error=err,
            )

        latency = int((time.time() - t0) * 1000)
        # OPUS-11 (FIXED): scrub BEFORE truncating.
        scrubbed_stderr = _scrub(stderr or "")[:300]
        if proc.returncode != 0:
            err = f"gemini exit {proc.returncode}: {scrubbed_stderr}"
            usage_tracker.log(provider=self.name, model=self.model, latency_ms=latency, ok=False, error=err)
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=latency,
                error=err,
            )
        # OPUS-12: empty stdout with exit 0 is not a real success.
        if not (stdout or "").strip():
            err = "gemini exit 0 with empty stdout (treated as failure)"
            usage_tracker.log(provider=self.name, model=self.model, latency_ms=latency, ok=False, error=err)
            return Reply(
                text="",
                provider=self.name,
                model=self.model,
                latency_ms=latency,
                error=err,
            )
        # OPUS-9 (FIXED): the "Warning: True color..." banner is on stderr
        # (not stdout). The old stdout filter was wrong AND lossy: it
        # silently deleted any real answer line that happened to begin
        # with "Warning:". Now we just use stdout as-is.
        usage_tracker.log(provider=self.name, model=self.model, latency_ms=latency, ok=True)
        return Reply(
            text=(stdout or "").strip(),
            provider=self.name,
            model=self.model,
            latency_ms=latency,
        )


def _kill_pg(proc: subprocess.Popen, grace_seconds: float = 1.0) -> None:
    """Best-effort terminate the subprocess's process group (OPUS-8).

    Only works if the subprocess was started with start_new_session=True
    (or preexec_fn=os.setsid). Falls back to terminating the direct child
    if the pgid isn't available.
    """
    import os

    pgid = getattr(proc, "pid", None)
    if pgid is None:
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.terminate()
        except Exception:
            return
    try:
        proc.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
