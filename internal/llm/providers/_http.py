"""Shared HTTP helpers for providers (urllib-based, zero deps)."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Optional


class HTTPStatusError(Exception):
    """Wraps an HTTP non-2xx response with status + body."""

    def __init__(self, status: int, body: str, retry_after: Optional[float] = None):
        # Base Exception's __init__ signature wants *args, so we call super
        # without passing the message and just attach attrs.
        super().__init__()
        self.status = status
        self.body = body
        self.retry_after = retry_after
        self.args = (f"HTTP {status}: {body[:200]}",)


_RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})


def post_json(
    url: str,
    body: dict,
    *,
    headers: Optional[dict] = None,
    timeout: int = 30,
    retries: int = 0,
    backoff_base: float = 1.0,
    backoff_cap: float = 30.0,
) -> dict:
    """POST JSON body and return parsed JSON response. Raises HTTPStatusError on failure.

    RGT-107: when retries > 0, HTTP 429 honors the Retry-After header (falling
    back to bounded exponential backoff if absent), and 5xx statuses get
    bounded exponential backoff. Non-retryable statuses (4xx other than 429)
    fail immediately regardless of `retries`.
    """
    h: dict = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    data = json.dumps(body).encode("utf-8")

    attempt = 0
    while True:
        req = urllib.request.Request(url, data=data, headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            err_body = e.read()[:500].decode("utf-8", errors="replace")
            retry_after = None
            if e.code == 429:
                ra = e.headers.get("Retry-After") if e.headers else None
                if ra is not None:
                    try:
                        retry_after = float(ra)
                    except ValueError:
                        retry_after = None
            if attempt < retries and e.code in _RETRYABLE_STATUSES:
                if retry_after is not None:
                    sleep_for = min(retry_after, backoff_cap)
                else:
                    sleep_for = min(backoff_base * (2 ** attempt), backoff_cap)
                time.sleep(sleep_for)
                attempt += 1
                continue
            raise HTTPStatusError(e.code, err_body, retry_after=retry_after) from e
        except urllib.error.URLError as e:
            if attempt < retries:
                sleep_for = min(backoff_base * (2 ** attempt), backoff_cap)
                time.sleep(sleep_for)
                attempt += 1
                continue
            raise HTTPStatusError(0, f"URLError: {e.reason}") from e


def timer_ms(start: float) -> int:
    return int((time.time() - start) * 1000)
