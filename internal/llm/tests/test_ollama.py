"""Tests for ollama provider hardening (OPUS deep audit 2026-06-17).

Fixes:
- is_available now uses family-tolerant match (qwen2.5:7b matches
  qwen2.5:latest, qwen2.5:3b, etc.) so a configured model resolves
  even if the installed tag differs.
- complete() routes through _http.post_json so:
    OPUS-102: TimeoutError is caught (previously escaped)
    OPUS-103: response body is capped at 10 MiB
    OPUS-104: ValueError on non-JSON body is caught
"""

import json
import urllib.error

# ----- is_available: tolerant match -----------------------------------


class FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_is_available_exact_match(monkeypatch):
    from internal.llm.providers.ollama import OllamaProvider

    def fake_urlopen(url, timeout=None):
        return FakeResponse(json.dumps({"models": [{"name": "qwen2.5:7b"}, {"name": "llama3.2:3b"}]}).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    p = OllamaProvider("qwen2.5:7b")
    assert p.is_available() is True


def test_is_available_family_match(monkeypatch):
    """qwen2.5:7b (configured) matches qwen2.5:latest (installed)."""
    from internal.llm.providers.ollama import OllamaProvider

    def fake_urlopen(url, timeout=None):
        return FakeResponse(json.dumps({"models": [{"name": "qwen2.5:latest"}, {"name": "llama3.2:3b"}]}).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    p = OllamaProvider("qwen2.5:7b")
    assert p.is_available() is True, "family match should accept qwen2.5:7b as available"


def test_is_available_daemon_unreachable(monkeypatch):
    from internal.llm.providers.ollama import OllamaProvider

    def fake_urlopen(url, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    p = OllamaProvider("qwen2.5:7b")
    assert p.is_available() is False


def test_is_available_no_models(monkeypatch):
    from internal.llm.providers.ollama import OllamaProvider

    def fake_urlopen(url, timeout=None):
        return FakeResponse(json.dumps({"models": []}).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    p = OllamaProvider("qwen2.5:7b")
    assert p.is_available() is False


def test_is_available_different_family(monkeypatch):
    """qwen2.5:7b should NOT match a llama family."""
    from internal.llm.providers.ollama import OllamaProvider

    def fake_urlopen(url, timeout=None):
        return FakeResponse(json.dumps({"models": [{"name": "llama3.2:3b"}, {"name": "mistral:7b"}]}).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    p = OllamaProvider("qwen2.5:7b")
    assert p.is_available() is False


# ----- complete: routes through _http.post_json ------------------------


def test_complete_success(monkeypatch):
    from internal.llm.providers import ollama

    def fake_post_json(url, body, *, headers=None, timeout=30):
        assert url.endswith("/api/chat")
        assert body["model"] == "qwen2.5:7b"
        return {
            "message": {"role": "assistant", "content": "hello back"},
            "prompt_eval_count": 5,
            "eval_count": 2,
        }

    monkeypatch.setattr(ollama._http, "post_json", fake_post_json)
    p = ollama.OllamaProvider("qwen2.5:7b")
    r = p.complete("hi", timeout=10)
    assert r.ok
    assert r.text == "hello back"
    assert r.input_tokens == 5
    assert r.output_tokens == 2


def test_complete_valueerror_on_non_json(monkeypatch):
    """A malformed JSON body must not crash the loop — it should return
    a failed Reply. (OPUS-104: previously uncaught.)"""
    from internal.llm.providers import _http, ollama

    def fake_post_json(url, body, *, headers=None, timeout=30):
        raise _http.HTTPStatusError(0, "non-JSON response: b'not json'")

    monkeypatch.setattr(ollama._http, "post_json", fake_post_json)
    p = ollama.OllamaProvider("qwen2.5:7b")
    r = p.complete("hi", timeout=10)
    assert not r.ok
    assert "non-JSON" in r.error or "HTTP 0" in r.error


def test_complete_timeout(monkeypatch):
    """A timeout must be reported as a failed Reply, not crash the loop.
    (OPUS-102: previously escaped through the catch block.)"""
    from internal.llm.providers import _http, ollama

    def fake_post_json(url, body, *, headers=None, timeout=30):
        raise _http.HTTPStatusError(0, f"timeout after {timeout}s")

    monkeypatch.setattr(ollama._http, "post_json", fake_post_json)
    p = ollama.OllamaProvider("qwen2.5:7b")
    r = p.complete("hi", timeout=2)
    assert not r.ok
    assert "timeout" in r.error


def test_complete_http_error(monkeypatch):
    from internal.llm.providers import _http, ollama

    def fake_post_json(url, body, *, headers=None, timeout=30):
        raise _http.HTTPStatusError(404, "model not found")

    monkeypatch.setattr(ollama._http, "post_json", fake_post_json)
    p = ollama.OllamaProvider("qwen2.5:7b")
    r = p.complete("hi", timeout=10)
    assert not r.ok
    assert "404" in r.error
    assert "model not found" in r.error
