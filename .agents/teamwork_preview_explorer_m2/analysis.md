# Milestone 2 Security Analysis: Server Config & Information Leakage Prevention

This report provides a concrete analysis and implementation strategy for the security controls required in Milestone 2: RGT-452, RGT-442, and RGT-437.

---

## 1. RGT-452: Config: Disable production debug modes and component version disclosures

### Direct Observations & Findings
1. **Python FastAPI Server (`python/server/app.py`):**
   - The FastAPI instance is created inside `build_app` (lines 156-160) without explicitly setting the `debug` parameter. By default, FastAPI's `debug` is `False`.
   - FastAPI dynamically generates and serves interactive Swagger documentation under `/docs` and ReDoc under `/redoc` with the application version `"0.2.0"` exposed (lines 158, 210-217). In production environments, this Swagger metadata exposes endpoint footprints and package versions.
   - Uvicorn runs in `python/cli.py` (line 397) using:
     ```python
     uvicorn.run(app, host=args.host, port=args.port, log_level="info")
     ```
     By default, Uvicorn injects a `Server: uvicorn` header into every HTTP response. ASGI/HTTP middleware is executed *inside* the application layer, meaning Uvicorn appends the `Server` header *after* the application middleware chain completes. Therefore, stripping `Server` in FastAPI middleware is ineffective against Uvicorn.
2. **Go Server (`go/cmd/server/main.go` & `go/internal/server`):**
   - Go's standard library `http.Server` does not automatically append server details, but the `/healthz` API endpoint (defined in `go/internal/server/handlers/handlers.go` line 273) leaks the server version:
     ```go
     "version": "0.3.0"
     ```
   - No explicit headers like `Server` or `X-Powered-By` are appended, but there is no mechanism blocking them if reverse proxies or libraries inject them.

### Proposed Code Changes & Implementation Strategy

#### Python / FastAPI & Uvicorn Configuration
1. **Disable Debug Mode & Hide API Docs in Production:**
   Update `python/server/app.py` to check the environment. If `APP_ENV` is set to `production`, disable debug mode, Swagger, and ReDoc:
   ```python
   import os

   is_prod = os.getenv("APP_ENV") == "production"

   app = FastAPI(
       title="rgt-vault",
       version="0.2.0" if not is_prod else "",
       description="Local HTTP surface for the rgt-vault secrets manager.",
       debug=os.getenv("RGT_VAULT_DEBUG", "0") == "1",
       docs_url=None if is_prod else "/docs",
       redoc_url=None if is_prod else "/redoc",
       openapi_url=None if is_prod else "/openapi.json",
   )
   ```
2. **Strip Server Header in Uvicorn Runner:**
   Update `python/cli.py` to invoke Uvicorn with `server_header=False`:
   ```python
   uvicorn.run(app, host=args.host, port=args.port, log_level="info", server_header=False)
   ```
3. **Ensure Middleware strips other disclosures:**
   Update `secure_http_headers_middleware` in `python/server/app.py` to pop the headers:
   ```python
   response.headers.pop("server", None)
   response.headers.pop("x-powered-by", None)
   ```

#### Go / Chi & Standard Server Configuration
1. **Middleware Header Stripping:**
   Create or update a security middleware in `go/internal/server/middleware.go` to explicitly strip headers:
   ```go
   func (mw *Middleware) SecurityHeadersMiddleware(next http.Handler) http.Handler {
       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
           w.Header().Del("Server")
           w.Header().Del("X-Powered-By")
           next.ServeHTTP(w, r)
       })
   }
   ```
2. **Sanitize Version Disclosure in Go Health Check:**
   Modify `HealthCheck` in `go/internal/server/handlers/handlers.go` to check the environment:
   ```go
   func (h *Handlers) HealthCheck(w http.ResponseWriter, r *http.Request) {
       version := "0.3.0"
       if os.Getenv("APP_ENV") == "production" {
           version = "" // Suppressed in production
       }
       writeJSON(w, http.StatusOK, map[string]interface{}{
           "status":    "ok",
           "vault_id":  h.Store.VaultID(),
           "key_epoch": h.Store.KeyEpoch(),
           "version":   version,
       })
   }
   ```

---

## 2. RGT-442: Information Leakage: Scan and strip sensitive developer comments from HTML templates

### Direct Observations & Findings
- Run a recursive find check across the repository (excluding `.venv/`):
  `find . -name "*.html" -o -name "*.js" -o -name "*.tmpl" -o -name "*.tpl"`
- **Result:** There are **no HTML templates, JavaScript views, or layout templates** in either the Python or Go codebases. The application operates strictly as a headless JSON API.
- However, to prevent developer comments from leaking in the future if frontend capabilities are added, we must define static checks and automated build/compilation processes.

### Proposed Preventive Strategy & Build-Time Checks

1. **Static Analysis Pre-commit & CI Check:**
   Implement a Python script (`scripts/check_template_comments.py`) that runs in the CI/CD pipeline. The script scans all `.html`, `.js`, `.tmpl`, or `.tpl` files for comments containing sensitive strings or general developer notes:
   ```python
   #!/usr/bin/env python3
   import re
   import sys
   from pathlib import Path

   SENSITIVE_PATTERNS = [
       re.compile(r"TODO|FIXME|BUG", re.IGNORECASE),
       re.compile(r"password|credential|token|secret|key", re.IGNORECASE),
       re.compile(r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"),  # Private IPs
   ]
   HTML_COMMENT_RE = re.compile(r"<!--[\s\S]*?-->")
   JS_COMMENT_RE = re.compile(r"\/\/.*|\/\*[\s\S]*?\*\/")

   def check_file(path: Path) -> bool:
       content = path.read_text(errors="ignore")
       has_leak = False

       # Extract comments
       comments = []
       if path.suffix in (".html", ".tmpl", ".tpl"):
           comments.extend(HTML_COMMENT_RE.findall(content))
       if path.suffix == ".js":
           comments.extend(JS_COMMENT_RE.findall(content))

       for comment in comments:
           for pattern in SENSITIVE_PATTERNS:
               if pattern.search(comment):
                   print(f"[LEAK] Sensitive comment found in {path}: {comment.strip()}")
                   has_leak = True
       return has_leak

   def main():
       has_errors = False
       for p in Path(".").rglob("*"):
           if p.suffix in (".html", ".js", ".tmpl", ".tpl") and ".venv" not in p.parts:
               if check_file(p):
                   has_errors = True
       if has_errors:
           sys.exit(1)
       print("All template comment scans passed.")

   if __name__ == "__main__":
       main()
   ```

2. **Build-Time Minimization & Stripping:**
   - **For Python templates (e.g., Jinja2):** Enable Jinja2 whitespace and block trimming. Use `jinja2-htmlmin` or custom filters to strip all `<!-- ... -->` and JS comments from output before rendering.
   - **For Go templates (`html/template`):** Incorporate a template parser wrapper that minifies the generated HTML at build or execution time using a library like `github.com/tdewolff/minify`, which automatically removes HTML/JS comments.

---

## 3. RGT-437: Config: Disable browser caching for crossdomain.xml and clientaccesspolicy.xml

### Direct Observations & Findings
- The files `/crossdomain.xml` (Adobe Flash) and `/clientaccesspolicy.xml` (Microsoft Silverlight) do not exist anywhere in the codebase.
- Standard requests to these files would default to 404 (Not Found). However, caching mechanisms on CDNs, reverse proxies, or client browsers might cache these default error responses or accidental static files.
- To block these legacy vectors completely and prevent any caching of policy responses, we should serve dedicated empty files with explicit cache-disabling headers.

### Proposed Code Changes & Implementation Strategy

#### Python / FastAPI Implementation
Add explicit route handlers inside `python/server/app.py`:
```python
from fastapi.responses import Response

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
```

#### Go / Chi Implementation
1. **Register routes in `go/internal/server/router.go`:**
   ```go
   r.Get("/crossdomain.xml", h.BlockXMLPolicy)
   r.Get("/clientaccesspolicy.xml", h.BlockXMLPolicy)
   ```
2. **Implement handler in `go/internal/server/handlers/handlers.go`:**
   ```go
   func (h *Handlers) BlockXMLPolicy(w http.ResponseWriter, r *http.Request) {
       w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
       w.Header().Set("Pragma", "no-cache")
       w.Header().Set("Expires", "0")
       w.Header().Set("Content-Type", "application/xml")
       w.Header().Set("X-Content-Type-Options", "nosniff")
       w.WriteHeader(http.StatusNotFound)
       w.Write([]byte(`<?xml version="1.0"?><error>Policies are disabled</error>`))
   }
   ```

---

## 4. Best Practices
- **Never Rely on Client-Side Hygiene:** Stripping headers like `Server` and `X-Powered-By` prevents scanning bots from fingerprinting technologies, raising the barrier to entry for script kiddies.
- **Automated Verification:** Standardize all build pipelines to enforce static analysis scanning of developer comments rather than relying on code review alone.
- **Cache-Control Directives:** For sensitive API endpoints, dynamic configuration files, and cross-domain controls, apply all four standard headers to ensure legacy and modern browsers, proxy layers, and gateways enforce caching disablement:
  - `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`
  - `Pragma: no-cache`
  - `Expires: 0`
  - `Surrogate-Control: no-store` (for reverse proxies/CDNs)

---

## 5. Programmatic Verification in Tests

We can verify all three controls in Python and Go tests.

### Python Verification Tests (append to `tests/test_server_hardening.py`)
```python
def test_server_header_and_debug_disclosure_stripped(server):
    """Verify component version disclosures and server headers are stripped (RGT-452)."""
    app, token = server
    c = _authed(app, token)
    
    # 1. Verify headers are not disclosed
    r = c.get("/healthz")
    assert "Server" not in r.headers
    assert "X-Powered-By" not in r.headers
    
    # 2. Verify debug mode is false on the app instance
    assert app.debug is False


def test_crossdomain_and_clientaccesspolicy_cache_disabled(server):
    """Verify crossdomain/clientaccesspolicy files return 404 and disable caching (RGT-437)."""
    app, token = server
    c = _authed(app, token)
    
    for path in ["/crossdomain.xml", "/clientaccesspolicy.xml"]:
        r = c.get(path)
        assert r.status_code == 404
        assert r.headers["Cache-Control"] == "no-store, no-cache, must-revalidate, max-age=0"
        assert r.headers["Pragma"] == "no-cache"
        assert r.headers["Expires"] == "0"
```

### Go Verification Tests (append to `go/internal/server/server_test.go`)
```go
func TestServerHeaderAndDebugStripped(t *testing.T) {
	ts, _ := setupTestServer(t)
	defer ts.Close()

	resp, _ := doJSON(t, "GET", ts.URL+"/healthz", "", nil)

	// Verify server metadata headers are stripped (RGT-452)
	if serverHeader := resp.Header.Get("Server"); serverHeader != "" {
		t.Errorf("Expected Server header to be empty, got %q", serverHeader)
	}
	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		t.Errorf("Expected X-Powered-By header to be empty, got %q", poweredBy)
	}
}

func TestXMLPoliciesCacheDisabled(t *testing.T) {
	ts, _ := setupTestServer(t)
	defer ts.Close()

	paths := []string{"/crossdomain.xml", "/clientaccesspolicy.xml"}
	for _, path := range paths {
		resp, _ := doJSON(t, "GET", ts.URL+path, "", nil)

		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected 404 for %s, got %d", path, resp.StatusCode)
		}

		// Verify Cache-Control directives (RGT-437)
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store, no-cache, must-revalidate, max-age=0" {
			t.Errorf("Expected strict Cache-Control for %s, got %q", path, cc)
		}
		if pragma := resp.Header.Get("Pragma"); pragma != "no-cache" {
			t.Errorf("Expected Pragma: no-cache, got %q", pragma)
		}
		if expires := resp.Header.Get("Expires"); expires != "0" {
			t.Errorf("Expected Expires: 0, got %q", expires)
		}
	}
}
```
