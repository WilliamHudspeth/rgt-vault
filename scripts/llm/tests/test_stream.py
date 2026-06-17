"""Offline tests for stream.py — parse logic only, no real network calls."""
import json
import unittest
from unittest.mock import patch, MagicMock

from scripts.llm.stream import stream_ollama, stream_openai_chat


class _FakeResp:
    """Minimal file-like object that yields lines."""
    def __init__(self, lines):
        self._lines = list(lines)

    def __iter__(self):
        return iter(self._lines)


class StreamOllamaParseTests(unittest.TestCase):
    def test_parses_ndjson_chunks(self):
        # /api/chat with stream:true returns one JSON object per line
        lines = [
            b'{"message": {"content": "Hello "}, "done": false}\n',
            b'{"message": {"content": "world"}, "done": false}\n',
            b'{"message": {"content": "!"}, "done": true}\n',
        ]
        resp = _FakeResp(lines)
        ctx = MagicMock()
        ctx.__enter__ = lambda self: resp
        ctx.__exit__ = lambda self, *a: None
        with patch("urllib.request.urlopen", return_value=ctx):
            out = list(stream_ollama(
                "http://localhost:11434", "test-model", "hi", max_tokens=10
            ))
        self.assertEqual(out, ["Hello ", "world", "!"])

    def test_skips_empty_lines(self):
        lines = [
            b'',
            b'{"message": {"content": "ok"}, "done": true}',
        ]
        resp = _FakeResp(lines)
        ctx = MagicMock()
        ctx.__enter__ = lambda self: resp
        ctx.__exit__ = lambda self, *a: None
        with patch("urllib.request.urlopen", return_value=ctx):
            out = list(stream_ollama(
                "http://localhost:11434", "test-model", "hi", max_tokens=10
            ))
        self.assertEqual(out, ["ok"])

    def test_stops_on_done(self):
        # Per Ollama's protocol, the final chunk has done=true and may
        # still carry content. We yield that final content, then stop.
        lines = [
            b'{"message": {"content": "first"}, "done": false}',
            b'{"message": {"content": "last"}, "done": true}',
        ]
        resp = _FakeResp(lines)
        ctx = MagicMock()
        ctx.__enter__ = lambda self: resp
        ctx.__exit__ = lambda self, *a: None
        with patch("urllib.request.urlopen", return_value=ctx):
            out = list(stream_ollama(
                "http://localhost:11434", "test-model", "hi", max_tokens=10
            ))
        self.assertEqual(out, ["first", "last"])

    def test_stops_on_done_with_no_final_content(self):
        lines = [
            b'{"message": {"content": "first"}, "done": false}',
            b'{"message": {}, "done": true}',
        ]
        resp = _FakeResp(lines)
        ctx = MagicMock()
        ctx.__enter__ = lambda self: resp
        ctx.__exit__ = lambda self, *a: None
        with patch("urllib.request.urlopen", return_value=ctx):
            out = list(stream_ollama(
                "http://localhost:11434", "test-model", "hi", max_tokens=10
            ))
        self.assertEqual(out, ["first"])


class StreamOpenAITests(unittest.TestCase):
    def test_parses_sse_chunks(self):
        lines = [
            b'data: {"choices": [{"delta": {"content": "Hello "}}]}\n',
            b'data: {"choices": [{"delta": {"content": "world"}}]}\n',
            b'data: [DONE]\n',
        ]
        resp = _FakeResp(lines)
        ctx = MagicMock()
        ctx.__enter__ = lambda self: resp
        ctx.__exit__ = lambda self, *a: None
        with patch("urllib.request.urlopen", return_value=ctx):
            out = list(stream_openai_chat(
                "https://api.test/v1", "key", "model", "hi", max_tokens=10
            ))
        self.assertEqual(out, ["Hello ", "world"])

    def test_skips_non_data_lines(self):
        lines = [
            b': keepalive comment\n',
            b'\n',
            b'data: {"choices": [{"delta": {"content": "x"}}]}\n',
        ]
        resp = _FakeResp(lines)
        ctx = MagicMock()
        ctx.__enter__ = lambda self: resp
        ctx.__exit__ = lambda self, *a: None
        with patch("urllib.request.urlopen", return_value=ctx):
            out = list(stream_openai_chat(
                "https://api.test/v1", "key", "model", "hi", max_tokens=10
            ))
        self.assertEqual(out, ["x"])

    def test_handles_missing_delta(self):
        lines = [
            b'data: {"choices": [{"delta": {}}]}\n',  # no content
            b'data: {"choices": [{"delta": {"content": "y"}}]}\n',
        ]
        resp = _FakeResp(lines)
        ctx = MagicMock()
        ctx.__enter__ = lambda self: resp
        ctx.__exit__ = lambda self, *a: None
        with patch("urllib.request.urlopen", return_value=ctx):
            out = list(stream_openai_chat(
                "https://api.test/v1", "key", "model", "hi", max_tokens=10
            ))
        self.assertEqual(out, ["y"])


if __name__ == "__main__":
    unittest.main()
