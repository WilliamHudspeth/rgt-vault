from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Mapping
from dataclasses import dataclass
import hashlib

@dataclass(frozen=True, slots=True)
class RequestContext:
    agent_id: str
    capability_id: str
    version: str
    timestamp_ns: int
    nonce: bytes
    
    def context_hash(self) -> str:
        h = hashlib.blake2b(digest_size=32)
        h.update(self.agent_id.encode())
        h.update(self.capability_id.encode())
        h.update(self.version.encode())
        h.update(str(self.timestamp_ns).encode())
        h.update(self.nonce)
        return h.hexdigest()

class AuditHook(ABC):
    """Stable hook interface for v0.2.0. Do not change method signatures."""

    @abstractmethod
    def on_capability_request(self, ctx: RequestContext, request: Mapping[str, Any]) -> None:
        """Called BEFORE policy enforcement in execute_capability(). Must not mutate request."""
        ...

    @abstractmethod
    def on_capability_grant(self, ctx: RequestContext, lease_ttl_s: int) -> None:
        """Called AFTER successful policy check, before execution. For RGT-29 leases."""
        ...

    @abstractmethod
    def on_secret_access(self, ctx: RequestContext, secret_id: str, operation: str) -> None:
        """Called on any read/write of a secret. Implement redaction here for RGT-28."""
        ...

    @abstractmethod
    def on_capability_complete(self, ctx: RequestContext, success: bool, error: str | None) -> None:
        """Always called, even on exception. Use for audit trail finalization."""
        ...

    # optional no-op default to keep interface stable
    def on_hook_error(self, hook_name: str, exc: BaseException) -> None:
        pass
