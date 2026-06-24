"""Live human-in-the-loop approval for agent secret requests.

The vault's static ABAC policy decides what an agent is *allowed* to ask
for. The approval broker adds a second, interactive gate: when an agent
leases a secret, the request is parked as *pending* and a human operator
approves or denies it in real time (optionally with a TOTP second factor)
from the TUI. The agent's call blocks until the operator decides or the
request times out (fail-closed: a timeout is a denial).

Design notes:

* ``ApprovalGate`` is the seam ``VaultManager`` consults. The default
  gate (``AutoAllowGate``) approves everything, so library/test callers
  that never wire a broker behave exactly as before.
* ``ApprovalBroker`` is thread-safe. The agent thread calls
  ``consult()`` and blocks; the operator thread (driven by the TUI/HTTP
  layer) calls ``list_pending()`` / ``approve()`` / ``deny()``.
* TOTP verification is injected as a callable so this module has no
  crypto dependency and the broker never holds the raw TOTP secret.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Protocol


@dataclass(frozen=True)
class ApprovalRequest:
    """An agent's pending request to use a secret."""

    agent: str
    namespace: str
    secret_name: str
    purpose: str
    action: str = "read"
    require_2fa: bool = False
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class ApprovalDecision:
    allowed: bool
    reason: str = ""
    decided_by: str = ""


class ApprovalGate(Protocol):
    """The interface ``VaultManager`` consults before unsealing a secret."""

    def consult(self, request: ApprovalRequest) -> ApprovalDecision:
        ...


class AutoAllowGate:
    """Default gate: approve everything. Preserves pre-broker behaviour."""

    def consult(self, request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(allowed=True, reason="auto-allow", decided_by="system")


class _Pending:
    __slots__ = ("request", "event", "decision")

    def __init__(self, request: ApprovalRequest):
        self.request = request
        self.event = threading.Event()
        self.decision: Optional[ApprovalDecision] = None


class ApprovalError(Exception):
    """Raised for operator-side mistakes (unknown id, bad/missing 2FA code)."""


class ApprovalBroker:
    """Thread-safe broker pairing blocking agent requests with operator decisions.

    Parameters
    ----------
    timeout:
        Seconds an agent request waits before it is auto-denied. Fail-closed.
    totp_verifier:
        ``Callable[[str], bool]`` that validates a TOTP code, or ``None`` to
        disable 2FA. When a request has ``require_2fa=True`` the operator must
        supply a code that this verifier accepts, or the approval is rejected.
    """

    def __init__(
        self,
        *,
        timeout: float = 120.0,
        totp_verifier: Optional[Callable[[str], bool]] = None,
    ):
        self._timeout = timeout
        self._totp_verifier = totp_verifier
        self._lock = threading.Lock()
        self._pending: Dict[str, _Pending] = {}

    # ---- agent side ---------------------------------------------------- #

    def consult(self, request: ApprovalRequest) -> ApprovalDecision:
        """Park ``request`` and block until an operator decides or it times out."""
        pending = _Pending(request)
        with self._lock:
            self._pending[request.request_id] = pending

        decided = pending.event.wait(timeout=self._timeout)
        with self._lock:
            self._pending.pop(request.request_id, None)

        if not decided or pending.decision is None:
            return ApprovalDecision(
                allowed=False,
                reason=f"approval timed out after {self._timeout:.0f}s",
                decided_by="system",
            )
        return pending.decision

    # ---- operator side ------------------------------------------------- #

    def list_pending(self) -> List[ApprovalRequest]:
        """Snapshot of currently waiting requests, oldest first."""
        with self._lock:
            return sorted((p.request for p in self._pending.values()), key=lambda r: r.created_at)

    def approve(self, request_id: str, *, totp_code: Optional[str] = None, operator: str = "operator") -> None:
        """Approve a pending request, enforcing 2FA when the request requires it."""
        with self._lock:
            pending = self._pending.get(request_id)
            if pending is None:
                raise ApprovalError(f"No pending request with id {request_id!r}")
            if pending.request.require_2fa:
                if self._totp_verifier is None:
                    raise ApprovalError("Request requires 2FA but no TOTP verifier is configured")
                if not totp_code or not self._totp_verifier(totp_code):
                    raise ApprovalError("Invalid or missing 2FA code")
            pending.decision = ApprovalDecision(allowed=True, reason="approved", decided_by=operator)
            pending.event.set()

    def deny(self, request_id: str, *, reason: str = "denied by operator", operator: str = "operator") -> None:
        with self._lock:
            pending = self._pending.get(request_id)
            if pending is None:
                raise ApprovalError(f"No pending request with id {request_id!r}")
            pending.decision = ApprovalDecision(allowed=False, reason=reason, decided_by=operator)
            pending.event.set()
