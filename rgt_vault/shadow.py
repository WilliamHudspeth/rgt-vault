"""
Shadow Writer Module for rgt-vault.
Ticket reference: RGT-161.

Dual-write migration phase:
Mirror ("shadow") write operations from the Python VaultManager to a co-located
Go rgt-vault HTTP server.

INVARIANT:
Python is ALWAYS the source of truth. Every shadow failure must be swallowed and
recorded as a divergence — NEVER raised — so the primary Python operation always
succeeds even if the Go server is down or mid-crash.
"""

import os
import json
import threading
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, List, Tuple

@dataclass
class Divergence:
    op: str          # "set" or "revoke"
    namespace: str
    name: str
    reason: str      # human-readable cause
    timestamp: str   # ISO-8601 UTC, e.g. datetime.now(timezone.utc).isoformat()

def _http(method: str, url: str, token: str, body: Optional[dict], timeout: float = 2.0) -> Tuple[int, bytes]:
    """
    Private helper function to perform HTTP requests using urllib.
    On URLError (e.g. connection refused, network down, timeout), it re-raises
    so that the caller records it as a divergence. On HTTPError, it returns the
    status code and response body.
    """
    data = None
    headers = {
        "Authorization": f"Bearer {token}"
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as e:
        # e.read() reads the error body. e.code contains the status.
        return e.code, e.read()

class ShadowWriter:
    # Active writers are enabled; the VaultManager only emits SHADOW_* audit
    # rows when enabled is True, so the disabled (Null) path stays byte-for-byte
    # identical to pre-RGT-161 behaviour.
    enabled = True

    def __init__(self, base_url: str, token: str, timeout: float = 2.0):
        # strip trailing slash from base_url; store token, timeout;
        # self._divergences: list[Divergence] = []; self._lock = threading.Lock()
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._divergences: List[Divergence] = []
        self._lock = threading.Lock()

    def _add_divergence(self, op: str, namespace: str, name: str, reason: str) -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        div = Divergence(
            op=op,
            namespace=namespace,
            name=name,
            reason=reason,
            timestamp=timestamp
        )
        with self._lock:
            self._divergences.append(div)

    def mirror_set(self, namespace: str, name: str, value: str, agent: str = "system", purpose: str = "") -> bool:
        """
        Mirror a set operation to the shadow Go server.
        1. POST {base_url}/v1/secrets with headers and JSON body.
        2. GET {base_url}/v1/secrets?namespace=<ns>&name=<name> to verify.
        Returns True only if successfully acknowledged and value matches.
        On any exception, non-2xx code, or value mismatch, records a divergence
        and returns False (never raises).
        """
        try:
            # 1. POST
            post_url = f"{self.base_url}/v1/secrets"
            body = {
                "namespace": namespace,
                "name": name,
                "value": value,
                "agent": agent,
                "purpose": purpose
            }
            status, resp_bytes = _http("POST", post_url, self.token, body, self.timeout)
            if status not in (200, 201):
                reason = f"POST /v1/secrets returned non-2xx status: {status} (response: {resp_bytes.decode('utf-8', errors='replace')})"
                self._add_divergence("set", namespace, name, reason)
                return False

            # 2. GET and verify
            params = urllib.parse.urlencode({"namespace": namespace, "name": name})
            get_url = f"{self.base_url}/v1/secrets?{params}"
            status, resp_bytes = _http("GET", get_url, self.token, None, self.timeout)
            if status != 200:
                reason = f"GET /v1/secrets returned non-200 status: {status} (response: {resp_bytes.decode('utf-8', errors='replace')})"
                self._add_divergence("set", namespace, name, reason)
                return False

            try:
                data = json.loads(resp_bytes.decode("utf-8"))
            except Exception as json_err:
                reason = f"Failed to parse GET response JSON: {json_err} (raw: {resp_bytes})"
                self._add_divergence("set", namespace, name, reason)
                return False

            secrets = data.get("secrets")
            if not isinstance(secrets, list):
                reason = f"GET response key 'secrets' is not a list (got {type(secrets)})"
                self._add_divergence("set", namespace, name, reason)
                return False

            matching_secret = None
            for s in secrets:
                if isinstance(s, dict) and s.get("name") == name:
                    matching_secret = s
                    break

            if not matching_secret:
                reason = f"Secret '{name}' not found in GET response secrets list"
                self._add_divergence("set", namespace, name, reason)
                return False

            returned_value = matching_secret.get("value")
            if returned_value != value:
                reason = f"Secret value mismatch. Wrote '{value}', but GET returned '{returned_value}'"
                self._add_divergence("set", namespace, name, reason)
                return False

            return True

        except Exception as e:
            reason = f"Exception during mirror_set: {type(e).__name__}: {str(e)}"
            self._add_divergence("set", namespace, name, reason)
            return False

    def mirror_revoke(self, namespace: str, name: str) -> bool:
        """
        Mirror a revoke operation to the shadow Go server.
        POST {base_url}/v1/secrets/{namespace}/{name}/revoke.
        Returns True on 200/204 status. On any error, records a divergence
        and returns False (never raises).
        """
        try:
            safe_ns = urllib.parse.quote(namespace, safe='')
            safe_name = urllib.parse.quote(name, safe='')
            url = f"{self.base_url}/v1/secrets/{safe_ns}/{safe_name}/revoke"
            status, resp_bytes = _http("POST", url, self.token, {}, self.timeout)
            if status not in (200, 204):
                reason = f"POST revoke returned non-2xx status: {status} (response: {resp_bytes.decode('utf-8', errors='replace')})"
                self._add_divergence("revoke", namespace, name, reason)
                return False
            return True
        except Exception as e:
            reason = f"Exception during mirror_revoke: {type(e).__name__}: {str(e)}"
            self._add_divergence("revoke", namespace, name, reason)
            return False

    def divergences(self) -> list:
        # return a shallow copy of the divergence list, under self._lock
        with self._lock:
            return list(self._divergences)

    def divergence_count(self) -> int:
        # len under lock
        with self._lock:
            return len(self._divergences)

class NullShadowWriter(ShadowWriter):
    # Disabled no-op, used by default when shadowing is off.
    enabled = False

    def __init__(self) -> None:  # no args
        # init empty divergence list + lock, no base_url needed
        self._divergences = []
        self._lock = threading.Lock()
        self.base_url = ""
        self.token = ""
        self.timeout = 2.0

    def mirror_set(self, namespace: str, name: str, value: str, agent: str = "system", purpose: str = "") -> bool:
        return True

    def mirror_revoke(self, namespace: str, name: str) -> bool:
        return True

    def divergence_count(self) -> int:
        return 0

def shadow_from_env() -> "ShadowWriter":
    # Read RGT_VAULT_SHADOW_URL and RGT_VAULT_SHADOW_TOKEN from os.environ.
    # If RGT_VAULT_SHADOW_URL is empty/unset -> return NullShadowWriter().
    # Otherwise return ShadowWriter(url, token).
    url = os.environ.get("RGT_VAULT_SHADOW_URL", "").strip()
    token = os.environ.get("RGT_VAULT_SHADOW_TOKEN", "").strip()
    if not url:
        return NullShadowWriter()
    return ShadowWriter(url, token)
