import logging
import re
from copy import deepcopy
from typing import Any, Mapping

from .audit import AuditHook, RequestContext

SENSITIVE_KEYS = re.compile(
    r"(?i)(pass|passwd|password|secret|token|api_key|apikey|access_key|"
    r"private|privkey|seed|mnemonic|credential|auth|bearer|jwt|key)"
)


def _is_high_entropy(s: str) -> bool:
    # simple heuristic: long base64/hex strings
    return len(s) > 24 and re.fullmatch(r"[A-Za-z0-9+/=_-]{24,}", s) is not None


def redact(obj: Any) -> Any:
    if isinstance(obj, Mapping):
        out = {}
        for k, v in obj.items():
            if SENSITIVE_KEYS.search(str(k)):
                out[k] = "[REDACTED]"
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, str) and _is_high_entropy(obj):
        return obj[:4] + "..." + "[REDACTED]"
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return f"<{len(obj)} bytes redacted>"
    return obj


class LogRedactionHook(AuditHook):
    """RGT-28: ensures logs never contain raw secrets."""

    def __init__(self, logger: logging.Logger | None = None):
        self.log = logger or logging.getLogger("rgt_vault.audit")
        # prevent log propagation to root which might print secrets
        self.log.propagate = False

    def on_capability_request(self, ctx: RequestContext, request: Mapping[str, Any]) -> None:
        safe_params = redact(deepcopy(request.get("parameters", {})))
        self.log.info(
            "capability_request: agent=%s cap=%s ver=%s ctx_hash=%s params=%s",
            ctx.agent_id,
            ctx.capability_id,
            ctx.version,
            ctx.context_hash(),
            safe_params,
        )

    def on_capability_grant(self, ctx: RequestContext, lease_ttl_s: int) -> None:
        self.log.info(
            "capability_grant: agent=%s cap=%s ttl=%s ctx_hash=%s",
            ctx.agent_id,
            ctx.capability_id,
            lease_ttl_s,
            ctx.context_hash(),
        )

    def on_secret_access(self, ctx: RequestContext, secret_id: str, operation: str) -> None:
        # NEVER log the secret value — only metadata
        self.log.info(
            "secret_access: agent=%s secret_id=%s op=%s ctx_hash=%s",
            ctx.agent_id,
            secret_id,
            operation,
            ctx.context_hash(),
        )

    def on_capability_complete(self, ctx: RequestContext, success: bool, error: str | None) -> None:
        safe_error = "[REDACTED]" if error and SENSITIVE_KEYS.search(error) else error
        self.log.info(
            "capability_complete: agent=%s cap=%s success=%s error=%s ctx_hash=%s",
            ctx.agent_id,
            ctx.capability_id,
            success,
            safe_error,
            ctx.context_hash(),
        )
