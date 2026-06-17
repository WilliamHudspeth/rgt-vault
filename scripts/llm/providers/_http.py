"""Shared HTTP helpers for providers (urllib-based, zero deps)."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Optional


class HTTPStatusError(Exception):
    """Wraps an HTTP non-2xx response with status + body."""

    def __init__(self, status: int, body: str):
        # Base Exception's __init__ signature wants *args, so we call super
        # without passing the message and just attach attrs.
        super().__init__()
        self.status = status
        self.body = body
        self.args = (f"HTTP {status}: {body[:200]}",)


def post_json(
    url: str,
    body: dict,
    *,
    headers: Optional[dict] = None,
    timeout: int = 30,
) -> dict:
    """POST JSON body and return parsed JSON response. Raises HTTPStatusError on failure."""
    h: dict = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read()[:500].decode("utf-8", errors="replace")
        raise HTTPStatusError(e.code, body) from e
    except urllib.error.URLError as e:
        raise HTTPStatusError(0, f"URLError: {e.reason}") from e


def timer_ms(start: float) -> int:
    return int((time.time() - start) * 1000)
