"""HTTP client the TUI uses to talk to a running rgt-vault daemon.

Kept separate from the Textual UI so it can be unit-tested against the
in-process FastAPI app. Every call carries the operator bearer token; the
client only ever sees secret *titles* and request metadata, never values.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx


@dataclass
class PendingRequest:
    request_id: str
    agent: str
    namespace: str
    secret_name: str
    purpose: str
    action: str
    require_2fa: bool
    created_at: float

    @classmethod
    def from_json(cls, d: Dict[str, Any]) -> "PendingRequest":
        return cls(
            request_id=d["request_id"],
            agent=d["agent"],
            namespace=d["namespace"],
            secret_name=d["secret_name"],
            purpose=d["purpose"],
            action=d["action"],
            require_2fa=d["require_2fa"],
            created_at=d["created_at"],
        )


class VaultHTTPClient:
    """Thin, synchronous client for the operator-facing endpoints."""

    def __init__(
        self,
        base_url: str = "",
        token: str = "",
        *,
        client: Optional[httpx.Client] = None,
        timeout: float = 10.0,
    ):
        """Build a client, or wrap an existing one.

        Production callers pass ``base_url`` + operator ``token``. Tests pass a
        pre-configured ``client`` (e.g. a Starlette ``TestClient``) so the same
        code drives the in-process ASGI app over a sync transport.
        """
        if client is not None:
            self._client = client
        else:
            self._client = httpx.Client(
                base_url=base_url.rstrip("/"),
                headers={"Authorization": f"Bearer {token}"},
                timeout=timeout,
            )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "VaultHTTPClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- secret entry / listing --------------------------------------- #

    def set_secret(
        self,
        name: str,
        value: str,
        *,
        namespace: str = "default",
        agent: str = "operator",
        note: str = "",
        require_2fa: bool = False,
    ) -> Dict[str, Any]:
        r = self._client.post(
            "/v1/secrets",
            json={
                "name": name,
                "value": value,
                "namespace": namespace,
                "agent": agent,
                "note": note,
                "require_2fa": require_2fa,
            },
        )
        r.raise_for_status()
        return r.json()

    def list_secrets(self, namespace: str = "default", agent: str = "operator") -> List[Dict[str, Any]]:
        r = self._client.get("/v1/secrets", params={"namespace": namespace, "agent": agent})
        r.raise_for_status()
        return r.json()["secrets"]

    # ---- approval flow ------------------------------------------------- #

    def list_requests(self) -> List[PendingRequest]:
        r = self._client.get("/v1/requests")
        r.raise_for_status()
        return [PendingRequest.from_json(d) for d in r.json()["requests"]]

    def approve(self, request_id: str, *, totp_code: Optional[str] = None, operator: str = "operator") -> bool:
        r = self._client.post(
            f"/v1/requests/{request_id}/approve",
            json={"totp_code": totp_code, "operator": operator},
        )
        if r.status_code == 400:
            return False  # bad/missing 2FA or already-gone request
        r.raise_for_status()
        return True

    def deny(self, request_id: str, *, reason: str = "denied by operator", operator: str = "operator") -> bool:
        r = self._client.post(
            f"/v1/requests/{request_id}/deny",
            json={"reason": reason, "operator": operator},
        )
        if r.status_code == 400:
            return False
        r.raise_for_status()
        return True
