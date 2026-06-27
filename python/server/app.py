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
import uuid
from typing import Any, Dict, Optional

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request, status, Response
    from fastapi.responses import JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.trustedhost import TrustedHostMiddleware
    from pydantic import BaseModel, Field
except ModuleNotFoundError as e:  # pragma: no cover - exercised only without extra
    raise ImportError(
        "The rgt-vault HTTP server requires the [server] extra. Install it with: pip install 'rgt-vault[server]'"
    ) from e

from rgt_vault.approval import ApprovalBroker, ApprovalError
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


class StrictURLNormalizationMiddleware:
    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> Any:
        if scope["type"] == "http":
            import urllib.parse
            path = scope.get("path", "")
            raw_path = scope.get("raw_path", b"").decode("utf-8", errors="ignore")
            decoded_raw_path = urllib.parse.unquote(raw_path)

            for p in (path, decoded_raw_path):
                has_control = any(ord(c) < 32 or ord(c) == 127 for c in p)
                if ".." in p or "\\" in p or "//" in p or has_control:
                    response_body = b'{"error":"BadRequest","detail":"Invalid URI path"}'
                    await send({
                        "type": "http.response.start",
                        "status": 400,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(response_body)).encode("ascii")),
                        ]
                    })
                    await send({
                        "type": "http.response.body",
                        "body": response_body,
                    })
                    return
        await self.app(scope, receive, send)


class SetSecretBody(BaseModel):
    name: str
    value: str
    namespace: str = "default"
    agent: str = "cli"
    purpose: str = ""
    note: str = ""
    require_2fa: bool = False


class ApproveBody(BaseModel):
    totp_code: Optional[str] = None
    operator: str = "operator"


class DenyBody(BaseModel):
    reason: str = "denied by operator"
    operator: str = "operator"


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
    operator_token_store: Optional[TokenStore] = None,
    broker: Optional["ApprovalBroker"] = None,
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

    # Resolve the approval broker: explicit arg wins, else adopt the vault's
    # gate if it happens to be a broker. None means single-process/no live
    # approval (the operator request endpoints then report nothing pending).
    from rgt_vault.approval import ApprovalBroker as _Broker

    active_broker: Optional[_Broker] = broker
    if active_broker is None and isinstance(getattr(vault, "approval_gate", None), _Broker):
        active_broker = vault.approval_gate

    import os
    is_prod = os.getenv("APP_ENV") == "production"

    app = FastAPI(
        title="rgt-vault",
        version="0.2.0" if not is_prod else "",
        description="Local HTTP surface for the rgt-vault secrets manager.",
        debug=os.getenv("RGT_VAULT_DEBUG", "0") == "1",
        docs_url=None,
        redoc_url=None,
        openapi_url=None if is_prod else "/openapi.json",
    )

    if not is_prod:
        from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
        from fastapi.responses import HTMLResponse

        SWAGGER_UI_VERSION = "5.17.14"
        REDOC_VERSION = "2.1.3"
        SWAGGER_JS_INTEGRITY = "sha384-wmyclcVGX/WhUkdkATwhaK1X1JtiNrr2EoYJ+diV3vj4v6OC5yCeSu+yW13SYJep"
        SWAGGER_CSS_INTEGRITY = "sha384-wxLW6kwyHktdDGr6Pv1zgm/VGJh99lfUbzSn6HNHBENZlCN7W602k9VkGdxuFvPn"
        REDOC_JS_INTEGRITY = "sha384-R8e5ippgVo+kphHRsZE026R4rLIN/ORakEnRnOJ3S7BauiXHeD2EnvDpCcPYV4O/"

        @app.get("/docs", include_in_schema=False)
        async def custom_swagger_ui_html(request: Request) -> HTMLResponse:
            swagger_js = f"https://cdn.jsdelivr.net/npm/swagger-ui-dist@{SWAGGER_UI_VERSION}/swagger-ui-bundle.js"
            swagger_css = f"https://cdn.jsdelivr.net/npm/swagger-ui-dist@{SWAGGER_UI_VERSION}/swagger-ui.css"
            
            response = get_swagger_ui_html(
                openapi_url=app.openapi_url or "/openapi.json",
                title=app.title + " - Swagger UI",
                oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
                swagger_js_url=swagger_js,
                swagger_css_url=swagger_css,
                swagger_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
            )
            
            html = response.body.decode("utf-8")
            html = html.replace(
                f'href="{swagger_css}"',
                f'href="{swagger_css}" integrity="{SWAGGER_CSS_INTEGRITY}" crossorigin="anonymous"'
            )
            html = html.replace(
                f'src="{swagger_js}"',
                f'src="{swagger_js}" integrity="{SWAGGER_JS_INTEGRITY}" crossorigin="anonymous"'
            )
            return HTMLResponse(content=html, status_code=response.status_code)

        @app.get("/redoc", include_in_schema=False)
        async def custom_redoc_html(request: Request) -> HTMLResponse:
            redoc_js = f"https://cdn.jsdelivr.net/npm/redoc@{REDOC_VERSION}/bundles/redoc.standalone.js"
            
            response = get_redoc_html(
                openapi_url=app.openapi_url or "/openapi.json",
                title=app.title + " - ReDoc",
                redoc_js_url=redoc_js,
                redoc_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
            )
            
            html = response.body.decode("utf-8")
            html = html.replace(
                f'src="{redoc_js}"',
                f'src="{redoc_js}" integrity="{REDOC_JS_INTEGRITY}" crossorigin="anonymous"'
            )
            return HTMLResponse(content=html, status_code=response.status_code)


    # 1. RGT-436 / RGT-119: DNS Rebinding Protection
    # Rejects requests with suspicious Host headers. Default to loopback.
    # In production, these should be configurable.
    allowed_hosts = ["localhost", "127.0.0.1", "[::1]", "testserver"]
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=allowed_hosts,
    )

    # 2. RGT-436: CORS Hardening
    # By default, do not configure a permissive CORS policy.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    app.add_middleware(StrictURLNormalizationMiddleware)

    # CSRF Double-Submit Cookie Middleware (RGT-447)
    @app.middleware("http")
    async def csrf_middleware(request: Request, call_next):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            csrf_cookie = request.cookies.get("csrf_token")
            new_csrf_token = None
            if not csrf_cookie:
                import secrets
                new_csrf_token = secrets.token_urlsafe(32)

            response = await call_next(request)
            if new_csrf_token:
                response.set_cookie(
                    "csrf_token",
                    new_csrf_token,
                    httponly=False,
                    secure=True,
                    samesite="strict",
                )
            return response

        # For state-changing methods:
        # 1. Bypass validation for requests containing a valid Bearer token in the 'Authorization' header.
        auth_header = request.headers.get("authorization", "")
        is_valid_bearer = False
        if auth_header.startswith("Bearer "):
            try:
                token_store.verify(auth_header)
                is_valid_bearer = True
            except Exception:
                _op_store = operator_token_store or token_store
                try:
                    _op_store.verify(auth_header)
                    is_valid_bearer = True
                except Exception:
                    pass

        if is_valid_bearer:
            return await call_next(request)

        # 2. Perform Double-Submit Cookie CSRF check
        csrf_cookie = request.cookies.get("csrf_token")
        csrf_header = request.headers.get("x-csrf-token") or request.headers.get("x-xsrf-token")

        import hmac
        if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "Forbidden", "detail": "CSRF token validation failed"},
            )

        return await call_next(request)

    # 3. RGT-454 / RGT-453 / RGT-438: Security Headers, Content-Type Enforcement, and Cookies
    @app.middleware("http")
    async def secure_http_headers_middleware(request: Request, call_next):
        # Accept Header validation (RGT-445)
        accept_header = request.headers.get("accept", "")
        if accept_header and not any(mime in accept_header for mime in ("application/json", "*/*", "application/*")):
            return JSONResponse(
                status_code=status.HTTP_406_NOT_ACCEPTABLE,
                content={"error": "NotAcceptable", "detail": "Server only supports application/json responses"}
            )

        # A. Enforce Content-Type for POST, PUT, PATCH on API endpoints (RGT-453)
        if request.method in ("POST", "PUT", "PATCH") and request.url.path.startswith("/v1/"):
            content_type = request.headers.get("content-type", "")
            
            content_length = request.headers.get("content-length")
            is_chunked = request.headers.get("transfer-encoding", "").lower() == "chunked"
            has_body = (content_length and int(content_length) > 0) or is_chunked
            
            if has_body or content_type:
                if "application/json" not in content_type:
                    return JSONResponse(
                        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                        content={"error": "UnsupportedMediaType", "detail": "Content-Type must be application/json"},
                    )

        # Process the request
        response = await call_next(request)

        # B. HTTP Security Headers (RGT-454)
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"

        # C. Content Security Policy (RGT-454)
        # Apply strict sandbox policy to APIs, but allow resources for Docs page
        path = request.url.path
        if path in ("/docs", "/redoc"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' data: https://fastapi.tiangolo.com; "
                "frame-ancestors 'none';"
            )
        else:
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; sandbox;"

        # D. X-Content-Type-Options (RGT-453 / RGT-438)
        response.headers["X-Content-Type-Options"] = "nosniff"

        # E. Content-Disposition (RGT-453 / RGT-438)
        # Enforce attachment disposition for all API responses to prevent content sniffing and rendering in browsers.
        if not (path.startswith("/docs") or path.startswith("/redoc") or path == "/openapi.json"):
            if "Content-Disposition" not in response.headers:
                response.headers["Content-Disposition"] = 'attachment; filename="response.json"'

        # F. Secure Cookie Flags (RGT-453)
        # Scan and apply Secure, HttpOnly, and SameSite=Strict to any Set-Cookie headers
        cookie_headers = response.headers.getlist("set-cookie")
        if cookie_headers:
            del response.headers["set-cookie"]
            for cookie in cookie_headers:
                parts = [p.strip() for p in cookie.split(";") if p.strip()]
                has_httponly = any(p.lower() == "httponly" for p in parts)
                has_secure = any(p.lower() == "secure" for p in parts)
                has_samesite = any(p.lower().startswith("samesite") for p in parts)

                is_csrf = parts and parts[0].startswith("csrf_token=")
                if not has_httponly and not is_csrf:
                    parts.append("HttpOnly")
                if not has_secure:
                    parts.append("Secure")
                if not has_samesite:
                    parts.append("SameSite=Strict")

                response.headers.append("Set-Cookie", "; ".join(parts))

        for key in ("server", "x-powered-by"):
            if hasattr(response.headers, "pop"):
                response.headers.pop(key, None)
            elif key in response.headers:
                del response.headers[key]
        return response

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

    if is_prod and operator_token_store is None:
        logger.warning("OPERATOR TOKEN FALLBACK ACTIVE IN PRODUCTION — configure separate operator token store")
    _operator_store = operator_token_store or token_store

    def require_operator_token(request: Request, authorization: Optional[str] = Header(None)) -> str:
        token_id = _operator_store.verify(authorization)  # raises ServerAuthError -> 401
        client = request.client.host if request.client else "?"
        vault.audit(
            "HTTP_OPERATOR",
            None,
            f"token={token_id} ip={client} {request.method} {request.url.path}",
        )
        return token_id

    def _make_incident_id() -> str:
        return uuid.uuid4().hex[:12]

    def _register_error(exc_type: type, status_code: int) -> None:
        async def handler(request: Request, exc: Exception) -> JSONResponse:
            incident_id = _make_incident_id()
            logger.warning(
                "incident=%s status=%s error=%s path=%s",
                incident_id, status_code, exc_type.__name__, request.url.path,
            )
            return JSONResponse(
                status_code=status_code,
                content={
                    "error": exc_type.__name__,
                    "detail": str(exc),
                    "incident_id": incident_id,
                },
            )

        app.add_exception_handler(exc_type, handler)

    for exc_type, status_code in _STATUS_MAP.items():
        _register_error(exc_type, status_code)
    # Honeytoken access and rate-limit breaches raise builtin PermissionError.
    _register_error(PermissionError, 403)

    # RGT-420: global last-resort handler — catches any unhandled exception
    # so stack traces are never exposed in responses (RGT-421).
    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        incident_id = _make_incident_id()
        logger.exception("unhandled exception incident=%s path=%s", incident_id, request.url.path)
        return JSONResponse(
            status_code=500,
            content={
                "error": "InternalServerError",
                "detail": "An unexpected error occurred. Contact support.",
                "incident_id": incident_id,
            },
        )

    @app.get("/healthz")
    def healthz() -> Dict[str, Any]:
        return {
            "status": "ok",
            "vault_id": vault.vault_id,
            "key_epoch": vault.key_epoch,
            "actions": [s.name for s in registry.list()],
        }

    @app.get("/crossdomain.xml", response_class=Response)
    @app.get("/clientaccesspolicy.xml", response_class=Response)
    def serve_restrictive_xml_policy():
        """Disable Flash and Silverlight policies and prevent caching of response."""
        empty_policy = (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">\n'
            '<cross-domain-policy>\n'
            '  <site-control permitted-cross-domain-policies="none"/>\n'
            '</cross-domain-policy>'
        )
        headers = {
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
            "X-Content-Type-Options": "nosniff",
            "Content-Type": "application/xml"
        }
        return Response(content=empty_policy, status_code=404, headers=headers)

    @app.post("/v1/secrets")
    def set_secret(request: Request, body: SetSecretBody, token_id: str = Depends(require_token)) -> Dict[str, Any]:
        vault.set_secret(
            body.name,
            body.value,
            namespace=body.namespace,
            agent=body.agent,
            purpose=body.purpose,
            note=body.note,
            require_2fa=body.require_2fa,
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
        limit: int = 100,
        offset: int = 0,
        token_id: str = Depends(require_token),
    ) -> Dict[str, Any]:
        if limit < 1 or limit > 1000:
            raise HTTPException(status_code=400, detail="'limit' must be between 1 and 1000.")
        if offset < 0:
            raise HTTPException(status_code=400, detail="'offset' must be >= 0.")
        items = vault.list_secrets(namespace, agent=agent, purpose=purpose, limit=limit, offset=offset)
        return {"namespace": namespace, "secrets": items}

    # ---- operator approval endpoints (the TUI's back end) -------------- #

    def _require_broker() -> "ApprovalBroker":
        if active_broker is None:
            raise HTTPException(status_code=409, detail="No approval broker is active on this server.")
        return active_broker

    @app.get("/v1/requests")
    def list_requests(token_id: str = Depends(require_operator_token)) -> Dict[str, Any]:
        """Pending agent requests awaiting an operator decision (titles only —
        the secret value is never part of a request)."""
        pending = _require_broker().list_pending()
        return {
            "requests": [
                {
                    "request_id": r.request_id,
                    "agent": r.agent,
                    "namespace": r.namespace,
                    "secret_name": r.secret_name,
                    "purpose": r.purpose,
                    "action": r.action,
                    "require_2fa": r.require_2fa,
                    "created_at": r.created_at,
                }
                for r in pending
            ]
        }

    @app.post("/v1/requests/{request_id}/approve")
    def approve_request(
        request_id: str,
        body: ApproveBody,
        token_id: str = Depends(require_operator_token),
    ) -> Dict[str, Any]:
        try:
            _require_broker().approve(request_id, totp_code=body.totp_code, operator=body.operator)
        except ApprovalError as e:
            # Bad/missing 2FA or unknown id is a client error.
            raise HTTPException(status_code=400, detail=str(e))
        return {"ok": True, "request_id": request_id, "decision": "approved"}

    @app.post("/v1/requests/{request_id}/deny")
    def deny_request(
        request_id: str,
        body: DenyBody,
        token_id: str = Depends(require_operator_token),
    ) -> Dict[str, Any]:
        try:
            _require_broker().deny(request_id, reason=body.reason, operator=body.operator)
        except ApprovalError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return {"ok": True, "request_id": request_id, "decision": "denied"}

    @app.post("/v1/secrets/{namespace}/{name}/revoke")
    def revoke(
        request: Request,
        namespace: str,
        name: str,
        agent: str = "system",
        token_id: str = Depends(require_token),
    ) -> Dict[str, Any]:
        vault.revoke_secret(namespace, name, agent=agent)
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
    @app.get("/v1/capabilities/list")
    def list_authorized_capabilities(
        agent: str,
        namespace: str = "*",
        purpose: str = "*",
        token_id: str = Depends(require_token)
    ) -> Dict[str, Any]:
        """Discovery API for agents to see what capabilities they are authorized for.

        Evaluates the ABAC policy for the given agent (and optional namespace/purpose context)
        across all registered capabilities.
        """
        specs = vault.capability_registry.list()
        authorized = []
        for s in specs:
            decision = vault.auth.evaluate(agent, namespace, purpose, action=s.name)
            if decision.get("allowed"):
                authorized.append(
                    {
                        "name": s.name,
                        "description": s.description,
                        "supported_versions": sorted(s.supported_versions),
                        "params_schema": list(s.params_schema),
                    }
                )
        return {"agent": agent, "capabilities": authorized}

    app.vault = vault
    return app


__all__ = ["build_app"]
