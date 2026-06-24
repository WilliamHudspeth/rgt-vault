"""FastAPI application for the rgt-vault HTTP server.

This module is only importable when the ``[server]`` extra (FastAPI + uvicorn)
is installed. Importing the rest of ``rgt_vault`` does not pull this in.

The app is a thin translation layer: every endpoint maps an HTTP request onto
an existing :class:`~rgt_vault.vault.VaultManager` method, so the ABAC policy
engine, rate limiter, honeytokens, and hash-chained audit log all apply exactly
as they do for in-process callers. The server adds no new authorization logic
of its own beyond the bearer-token gate in front of every endpoint.

Plaintext never crosses the HTTP boundary: ``/v1/secrets/{ns}/{name}/use``
leases the secret into a server-side ``bytearray`` and hands it to a registered
action, returning only the action's result.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
except ModuleNotFoundError as e:  # pragma: no cover - exercised only without extra
    raise ImportError(
        "The rgt-vault HTTP server requires the [server] extra. Install it with: pip install 'rgt-vault[server]'"
    ) from e

from rgt_vault.exceptions import (
    ActionExecutionError,
    ActionNotFoundError,
    CapabilityNotFoundError,
    CapabilityVersionError,
    PolicyDeniedError,
    SecretNotFoundError,
    ServerAuthError,
    ValidationError,
    VaultError,
)
from rgt_vault.server.actions import ActionRegistry, register_builtin_actions
from rgt_vault.server.auth import TokenStore
from rgt_vault.vault import VaultManager

logger = logging.getLogger("rgt_vault.server")


class SetSecretBody(BaseModel):
    name: str
    value: str
    namespace: str = "default"
    agent: str = "cli"
    purpose: str = ""


class UseBody(BaseModel):
    action: str
    agent: str
    purpose: str = ""
    params: Dict[str, Any] = Field(default_factory=dict)


class RotateBody(BaseModel):
    target: str  # "master" | "dek"


class SimulateBody(BaseModel):
    agent: str
    namespace: str
    purpose: str = ""
    action: str = "read"


class ExecuteCapabilityBody(BaseModel):
    """Body for the ``/v1/capabilities/execute`` endpoint.

    The ``capability_token`` is a v2 token string issued by the harness
    (typically via :class:`rgt_vault.token.HMACTokenVerifier`). The
    ``agent_id`` is the caller's identity claim; the vault compares it
    to the token's ``agent_id`` field and refuses on mismatch.
    """

    capability: str
    agent_id: str
    capability_token: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    capability_version: int = 1


# VaultError subclass -> HTTP status. PermissionError (honeytoken / rate limit)
# is handled separately because it is a builtin, not a VaultError.
_STATUS_MAP = {
    ServerAuthError: 401,
    PolicyDeniedError: 403,
    SecretNotFoundError: 404,
    ActionNotFoundError: 404,
    CapabilityNotFoundError: 404,
    CapabilityVersionError: 400,
    ValidationError: 400,
    ActionExecutionError: 500,
    VaultError: 400,  # catch-all base, matched last via MRO walk
}


def build_app(
    vault: VaultManager,
    token_store: TokenStore,
    registry: Optional[ActionRegistry] = None,
    *,
    allow_private_network: bool = False,
) -> "FastAPI":
    """Construct the FastAPI app over an existing vault, token store, and registry.

    ``allow_private_network``: when False (the default), the built-in
    ``http_get_with_auth`` / ``http_post_with_auth`` / ``openai_chat``
    actions refuse to call loopback, link-local, RFC1918, multicast, and
    reserved addresses. Operators who need to call a self-hosted LLM on a
    private network can set this to True (or call ``rgt-vault serve
    --allow-private-network``). The setting is process-wide; per-request
    override is also accepted via ``params["allow_private_network"]``.
    """
    if registry is None:
        registry = ActionRegistry()
        register_builtin_actions(registry)

    # Stash on the registry so per-action calls can consult the default.
    registry.default_allow_private_network = allow_private_network

    app = FastAPI(
        title="rgt-vault",
        version="0.2.0",
        description="Local HTTP surface for the rgt-vault secrets manager.",
    )

    def require_token(request: Request, authorization: Optional[str] = Header(None)) -> str:
        """Auth dependency: verify the bearer token and audit the request.

        Every authenticated request writes one ``HTTP_API`` line to the
        hash-chained audit log (token id + client IP + method + path), so an
        audit-chain verification covers HTTP traffic as well as CLI/in-process
        use. The token itself is never logged — only its 8-char id.
        """
        token_id = token_store.verify(authorization)  # raises ServerAuthError -> 401
        client = request.client.host if request.client else "?"
        vault.audit(
            "HTTP_API",
            None,
            f"token={token_id} ip={client} {request.method} {request.url.path}",
        )
        return token_id

    def _register_error(exc_type: type, status: int) -> None:
        async def handler(request: Request, exc: Exception) -> JSONResponse:
            return JSONResponse(
                status_code=status,
                content={"error": exc_type.__name__, "detail": str(exc)},
            )

        app.add_exception_handler(exc_type, handler)

    for exc_type, status in _STATUS_MAP.items():
        _register_error(exc_type, status)
    # Honeytoken access and rate-limit breaches raise builtin PermissionError.
    _register_error(PermissionError, 403)

    @app.get("/healthz")
    def healthz() -> Dict[str, Any]:
        return {
            "status": "ok",
            "vault_id": vault.vault_id,
            "key_epoch": vault.key_epoch,
            "actions": [s.name for s in registry.list()],
        }

    @app.post("/v1/secrets")
    def set_secret(request: Request, body: SetSecretBody, token_id: str = Depends(require_token)) -> Dict[str, Any]:
        vault.set_secret(
            body.name,
            body.value,
            namespace=body.namespace,
            agent=body.agent,
            purpose=body.purpose,
        )
        return {"ok": True, "namespace": body.namespace, "name": body.name}

    @app.post("/v1/secrets/{namespace}/{name}/use")
    def use_secret(
        request: Request,
        namespace: str,
        name: str,
        body: UseBody,
        token_id: str = Depends(require_token),
    ) -> Dict[str, Any]:
        spec = registry.get(body.action)  # raises ActionNotFoundError -> 404
        try:
            spec.validate_params(body.params)
        except ActionExecutionError as e:
            # A malformed param set is a client error, not a server fault.
            raise HTTPException(status_code=400, detail=str(e))

        def _run(buf: bytearray) -> Any:
            try:
                return spec.fn(buf, body.params, registry=registry)
            except VaultError:
                # VaultError subclasses already carry a sanitized message.
                raise
            except Exception:
                # P0-2 audit fix: NEVER embed the raw exception text in
                # the HTTP response. The plaintext secret could appear
                # in an exception message (e.g. an http library that
                # echoes the Authorization header). Log the full traceback
                # server-side for operators; tell the client only that the
                # action raised an error.
                logger.exception(
                    "Action %r raised an unhandled exception; details suppressed from response",
                    body.action,
                )
                raise ActionExecutionError(f"Action '{body.action}' failed; see server logs for details.")

        result = vault.execute(body.agent, namespace, body.purpose, name, _run)
        return {"ok": True, "action": body.action, "result": result}

    @app.get("/v1/secrets")
    def list_secrets(
        request: Request,
        namespace: str,
        agent: str,
        purpose: str = "",
        token_id: str = Depends(require_token),
    ) -> Dict[str, Any]:
        items = vault.list_secrets(namespace, agent=agent, purpose=purpose)
        return {"namespace": namespace, "secrets": items}

    @app.post("/v1/secrets/{namespace}/{name}/revoke")
    def revoke(
        request: Request,
        namespace: str,
        name: str,
        token_id: str = Depends(require_token),
    ) -> Dict[str, Any]:
        vault.revoke_secret(namespace, name)
        return {"ok": True, "namespace": namespace, "name": name}

    @app.post("/v1/rotate")
    def rotate(request: Request, body: RotateBody, token_id: str = Depends(require_token)) -> Dict[str, Any]:
        if body.target == "master":
            vault.rotate_master_key()
        elif body.target == "dek":
            vault.rotate_dek()
        else:
            raise HTTPException(status_code=400, detail="target must be 'master' or 'dek'")
        return {"ok": True, "target": body.target, "key_epoch": vault.key_epoch}

    @app.get("/v1/audit")
    def audit(
        request: Request,
        limit: int = 50,
        token_id: str = Depends(require_token),
    ) -> Dict[str, Any]:
        # Cap the per-call limit so an authenticated caller cannot exhaust
        # server memory by asking for an arbitrarily large audit dump.
        if limit < 1:
            raise HTTPException(status_code=400, detail="'limit' must be >= 1.")
        if limit > 1000:
            raise HTTPException(
                status_code=400,
                detail="'limit' must be <= 1000. Use /v1/audit/verify and a tail query tool to walk larger histories.",
            )
        return {"entries": vault.get_audit_log(limit=limit)}

    @app.post("/v1/audit/verify")
    def audit_verify(request: Request, token_id: str = Depends(require_token)) -> Dict[str, Any]:
        return {"ok": vault.verify_audit_chain()}

    @app.post("/v1/policy/simulate")
    def policy_simulate(request: Request, body: SimulateBody, token_id: str = Depends(require_token)) -> Dict[str, Any]:
        return vault.simulate(body.agent, body.namespace, body.purpose, body.action)

    @app.post("/v1/capabilities/execute")
    def execute_capability(
        request: Request,
        body: ExecuteCapabilityBody,
        token_id: str = Depends(require_token),
    ) -> Dict[str, Any]:
        """Execute a registered capability on behalf of the named agent.

        The endpoint is the v0.3 primary surface for capability-based
        work. The legacy ``/v1/secrets/{ns}/{name}/use`` path remains
        available for backwards compatibility; new integrations should
        register a capability and call this endpoint.

        Failure modes
        -------------

        * 401: missing or invalid bearer token.
        * 400: malformed body, missing verifier on the server, or
          ``CapabilityVersionError`` (the requested version is not
          supported by the registered handler).
        * 403: the capability token failed signature/expiry/binding
          checks, the hook denied the call, or the vault is frozen.
        * 404: the capability name is not registered.
        * 500: the handler raised an unhandled exception (the
          response body is sanitized; the full traceback is in the
          server log).
        """
        try:
            result = vault.execute_capability(
                capability_name=body.capability,
                payload=body.payload,
                agent_id=body.agent_id,
                capability_token=body.capability_token,
                capability_version=body.capability_version,
            )
        except (ValidationError, CapabilityVersionError):
            # Both map to 400 via the exception handler below.
            raise
        except (PolicyDeniedError, CapabilityNotFoundError):
            # Map cleanly to 403 / 404. The exception handler below
            # converts these; we re-raise so the structured error
            # response reaches the client.
            raise
        except Exception:
            # Handler exceptions are server faults. Log the full
            # traceback server-side; tell the client only the class
            # name so a misuse of an action's exception text can never
            # leak a secret value.
            logger.exception(
                "capability %r raised an unhandled exception; details suppressed from response",
                body.capability,
            )
            raise ActionExecutionError(f"capability {body.capability!r} failed; see server logs for details")
        return {"ok": True, "capability": body.capability, "result": result}

    @app.get("/v1/capabilities")
    def list_capabilities(token_id: str = Depends(require_token)) -> Dict[str, Any]:
        """List the registered capabilities and the versions each one supports.

        The endpoint is intentionally read-only: it does NOT expose the
        handler bodies or any secret material. An operator can use it
        to verify that the harness's view of the registry matches the
        vault's.
        """
        specs = vault.capability_registry.list()
        return {
            "capabilities": [
                {
                    "name": s.name,
                    "description": s.description,
                    "supported_versions": sorted(s.supported_versions),
                    "params_schema": list(s.params_schema),
                }
                for s in specs
            ]
        }

    return app


__all__ = ["build_app"]
