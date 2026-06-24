"""Streaming support for the multi-LLM router.

Currently only Ollama and OpenAI-compatible APIs support streaming.
The base `Provider.complete()` returns a full Reply. This module
adds `Provider.stream()` which yields partial text as it arrives.

Usage:
    for chunk in provider.stream("Tell me a story"):
        print(chunk, end="", flush=True)
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from typing import Iterator, Optional


def stream_ollama(
    base_url: str,
    model: str,
    prompt: str,
    *,
    system: Optional[str] = None,
    max_tokens: int = 600,
    temperature: float = 0.2,
    timeout: int = 120,
) -> Iterator[str]:
    """Yield chunks of text from an Ollama /api/chat streaming call."""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    body = {
        "model": model,
        "messages": messages,
        "stream": True,
        "options": {"num_predict": max_tokens, "temperature": temperature},
    }
    req = urllib.request.Request(
        f"{base_url}/api/chat",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            for raw in resp:
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                msg = obj.get("message") or {}
                chunk = msg.get("content", "")
                if obj.get("done"):
                    if chunk:
                        yield chunk
                    return
                if chunk:
                    yield chunk
    except urllib.error.URLError as e:
        raise RuntimeError(f"Ollama stream failed: {e.reason}") from e
    except (TimeoutError, socket.timeout) as e:
        # OPUS-102: socket.timeout is NOT a URLError subclass; catch it
        # explicitly so a slow stream doesn't crash the consumer.
        raise RuntimeError("Ollama stream timeout") from e
    except OSError as e:
        raise RuntimeError(f"Ollama stream OSError: {type(e).__name__}: {e}") from e


def stream_openai_chat(
    base_url: str,
    api_key: str,
    model: str,
    prompt: str,
    *,
    system: Optional[str] = None,
    max_tokens: int = 600,
    temperature: float = 0.2,
    timeout: int = 60,
    extra_headers: Optional[dict] = None,
) -> Iterator[str]:
    """Yield chunks from an OpenAI-compatible /chat/completions streaming endpoint.

    Works for Mistral, Cohere-via-OpenAI, Groq, OpenAI.
    """
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    body = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": True,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=json.dumps(body).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            for raw in resp:
                line = raw.decode("utf-8", errors="replace").strip()
                if not line or not line.startswith("data: "):
                    continue
                data = line[len("data: ") :]
                if data == "[DONE]":
                    return
                try:
                    obj = json.loads(data)
                except json.JSONDecodeError:
                    continue
                for choice in obj.get("choices", []):
                    delta = choice.get("delta") or {}
                    chunk = delta.get("content")
                    if chunk:
                        yield chunk
    except urllib.error.URLError as e:
        raise RuntimeError(f"OpenAI-compat stream failed: {e.reason}") from e
    except (TimeoutError, socket.timeout) as e:
        # OPUS-102: see Ollama stream above.
        raise RuntimeError("OpenAI-compat stream timeout") from e
    except OSError as e:
        raise RuntimeError(f"OpenAI-compat stream OSError: {type(e).__name__}: {e}") from e
