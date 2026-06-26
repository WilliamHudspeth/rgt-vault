# Milestone 1: HTTP Headers & CORS Hardening - Detailed Analysis

This analysis report outlines the concrete plan and strategy to implement secure HTTP headers, CORS hardening, Content-Type enforcement, and DNS rebinding protections for the `rgt-vault` HTTP server as required by Milestone 1.

---

## 1. Exact Middleware and Code Additions in `python/server/app.py`

To enforce these controls on all routes (including success paths and validation error paths), we should add two standard middlewares directly to the FastAPI app constructed in `build_app`:
1. **`TrustedHostMiddleware`** (Starlette built-in): For DNS rebinding protection.
2. **`CORSMiddleware`** (Starlette built-in): Restricting cross-origin requests.
3. **Custom ASGI/HTTP Middleware**: For secure headers injection, Content-Type enforcement on requests, and cookie flag hardening.

### Proposed Code Additions in `python/server/app.py`

#### A. Imports (Add near line 23)
```python
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi import status
```

#### B. Middleware Setup in `build_app` (Add after `app = FastAPI(...)` near line 158)
```python
    # 1. RGT-436 / RGT-119: DNS Rebinding Protection
    # Rejects requests with suspicious Host headers. Default to loopback.
    # In production, these should be configurable.
    allowed_hosts = ["localhost", "127.0.0.1", "[::1]"]
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=allowed_hosts,
    )

    # 2. RGT-436: CORS Hardening
    # By default, do not configure a permissive CORS policy.
    # To support dashboards or cross-origin CLI tools, allowed origins can be
    # specified via configuration. If empty, CORS is disabled.
    allowed_origins: list[str] = []  # e.g., config.get("allowed_origins", [])
    if allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"],
        )

    # 3. RGT-454 / RGT-453 / RGT-438: Security Headers, Content-Type Enforcement, and Cookies
    @app.middleware("http")
    async def secure_http_headers_middleware(request: Request, call_next):
        # A. Enforce Content-Type for POST, PUT, PATCH on API endpoints (RGT-453)
        if request.method in ("POST", "PUT", "PATCH") and request.url.path.startswith("/v1/"):
            content_type = request.headers.get("content-type", "")
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
                response.headers["Content-Disposition"] = "attachment; filename=\"response.json\""

        # F. Secure Cookie Flags (RGT-453)
        # Scan and apply Secure, HttpOnly, and SameSite=Strict to any Set-Cookie headers
        cookie_headers = response.headers.getlist("set-cookie")
        if cookie_headers:
            del response.headers["set-cookie"]
            for cookie in cookie_headers:
                parts = [p.strip() for p in cookie.split(";")]
                has_httponly = any(p.lower() == "httponly" for p in parts)
                has_secure = any(p.lower() == "secure" for p in parts)
                has_samesite = any(p.lower().startswith("samesite") for p in parts)

                if not has_httponly:
                    parts.append("HttpOnly")
                if not has_secure:
                    parts.append("Secure")
                if not has_samesite:
                    parts.append("SameSite=Strict")

                response.headers.append("Set-Cookie", "; ".join(parts))

        return response
```

---

## 2. Best Practices for Configuring Headers in our FastAPI Server

1. **Security-by-Default Configuration**:
   - Out-of-the-box, the server should bind to loopback (`127.0.0.1` / `::1`) and enforce the strict list of hosts.
   - CORS should be disabled unless the operator overrides it via `--cors-origins` (which should accept a comma-separated list of allowed origins). Wildcards (`*`) must be rejected if credentials are permitted.

2. **Defense-in-Depth Headers**:
   - Applying `Content-Disposition: attachment` to API endpoints ensures that even if an attacker manages to bypass the `Content-Type` headers or uploads malicious HTML disguised as JSON, the browser will force-download the file instead of rendering it inside the security context of the vault server.
   - The CSP for API endpoints uses `default-src 'none'; sandbox;` to restrict the browser from executing any scripts or loading resources.

3. **Safe Hosting of Swagger UI / API Docs**:
   - By default, FastAPI loads Swagger UI resources (CSS and JS) from jsdelivr.net CDN. If the network environment is restricted (like CODE_ONLY) or needs offline support, the CSP will block the CDN assets unless explicitly allowed.
   - *Best Practice*: For high-security environments, FastAPI should be configured to host Swagger UI assets locally (packaged inside the static files directory) or documentation endpoints should be completely disabled in production (`docs_url=None`, `redoc_url=None`, `openapi_url=None`).

---

## 3. How to Verify These Programmatically in `tests/test_server_hardening.py`

The test suite must verify that the headers are applied correctly to both success path and error path responses. We can add the following tests using `fastapi.testclient.TestClient`:

```python
# ------------------------------------------------------------------
# Milestone 1: HTTP Headers & CORS Hardening Verification
# ------------------------------------------------------------------

def test_http_security_headers_are_present(server):
    """Verify that all standard security headers are applied to API responses."""
    app, token = server
    c = _authed(app, token)
    r = c.get("/healthz")
    assert r.status_code == 200

    # Strict-Transport-Security (RGT-454)
    assert r.headers["Strict-Transport-Security"] == "max-age=63072000; includeSubDomains; preload"
    
    # Referrer-Policy (RGT-454)
    assert r.headers["Referrer-Policy"] == "no-referrer"
    
    # X-Frame-Options (RGT-454)
    assert r.headers["X-Frame-Options"] == "DENY"
    
    # Content-Security-Policy (RGT-454)
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert "sandbox" in r.headers["Content-Security-Policy"]
    
    # X-Content-Type-Options (RGT-453 / RGT-438)
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    
    # Content-Disposition (RGT-453 / RGT-438)
    assert r.headers["Content-Disposition"] == 'attachment; filename="response.json"'


def test_docs_security_headers(server):
    """Verify that the Swagger UI (/docs) uses a specialized CSP but remains non-embeddable."""
    app, token = server
    c = _authed(app, token)
    r = c.get("/docs")
    assert r.status_code == 200
    
    csp = r.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "https://cdn.jsdelivr.net" in csp


def test_dns_rebinding_protection(server):
    """Verify that requests with unauthorized Host headers are rejected (RGT-436)."""
    app, token = server
    c = _authed(app, token)
    
    # Send request with an invalid Host header
    # By default, TrustedHostMiddleware returns 400 Bad Request
    r = c.get("/healthz", headers={"Host": "evil-domain.com"})
    assert r.status_code == 400


def test_post_request_enforces_json_content_type(server):
    """Verify that POST requests require Content-Type: application/json (RGT-453)."""
    app, token = server
    c = _authed(app, token)
    
    # Send POST request without application/json
    r = c.post(
        "/v1/secrets",
        headers={"Content-Type": "text/plain"},
        content="plain-text-payload"
    )
    assert r.status_code == 415
    assert "application/json" in r.json()["detail"]


def test_cors_disabled_by_default(server):
    """Verify that cross-origin requests are blocked/unallowed by default (RGT-436)."""
    app, token = server
    c = _authed(app, token)
    
    r = c.options("/healthz", headers={"Origin": "http://evil.com"})
    assert "Access-Control-Allow-Origin" not in r.headers


def test_secure_cookie_flags_enforced(server):
    """Verify that any Set-Cookie headers get secure flags appended automatically (RGT-453)."""
    app, token = server
    
    # Add a mock endpoint that sets a vulnerable cookie to verify middleware mitigation
    from fastapi import Response
    @app.get("/test-cookie-leak")
    def set_bad_cookie(response: Response):
        response.headers.append("Set-Cookie", "session=123")
        return {"ok": True}
        
    c = _authed(app, token)
    r = c.get("/test-cookie-leak")
    assert r.status_code == 200
    
    cookie_header = r.headers["set-cookie"]
    assert "HttpOnly" in cookie_header
    assert "Secure" in cookie_header
    assert "SameSite=Strict" in cookie_header
```
