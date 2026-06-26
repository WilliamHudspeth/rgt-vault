# Handoff Report — Milestone 2 Security Controls Analysis

## 1. Observation
- **FastAPI Setup:** Inside `/home/will/rgt-vault/python/server/app.py` lines 156-160, the FastAPI application is initialized:
  ```python
  app = FastAPI(
      title="rgt-vault",
      version="0.2.0",
      description="Local HTTP surface for the rgt-vault secrets manager.",
  )
  ```
  And in `/home/will/rgt-vault/python/cli.py` line 397, Uvicorn runs without stripping server headers:
  ```python
  uvicorn.run(app, host=args.host, port=args.port, log_level="info")
  ```
- **Go Server Health Check:** Inside `/home/will/rgt-vault/go/internal/server/handlers/handlers.go` line 273:
  ```go
  func (h *Handlers) HealthCheck(w http.ResponseWriter, r *http.Request) {
      writeJSON(w, http.StatusOK, map[string]interface{}{
          "status":    "ok",
          "vault_id":  h.Store.VaultID(),
          "key_epoch": h.Store.KeyEpoch(),
          "version":   "0.3.0",
      })
  }
  ```
- **Template Presence:** Executing a recursive file search inside `/home/will/rgt-vault` (excluding `.venv/`) returned no user-defined `.html`, `.js`, `.tmpl`, or `.tpl` files:
  `find . -name "*.html" -o -name "*.js" -o -name "*.tmpl" -o -name "*.tpl"`
- **XML Cross-domain Policy Files:** A grep search across the codebase for `crossdomain.xml` and `clientaccesspolicy.xml` returned no occurrences inside the Go or Python codebase.

## 2. Logic Chain
1. **RGT-452 (Information Disclosure & Debugging):**
   - By omitting `debug=False` in the `FastAPI(...)` call, it relies on Starlette's defaults. Explicitly locking `debug=False` or reading from `RGT_VAULT_DEBUG` ensures it remains disabled in production.
   - Uvicorn injects a default `Server: uvicorn` header at the ASGI socket handler level after the app middleware pipeline finishes. To prevent this, we must pass `server_header=False` to `uvicorn.run(...)` and drop `Server`/`X-Powered-By` in application-level middleware as a secondary filter.
   - Go's health check returns `version: "0.3.0"`, disclosing versioning metadata. Checking the environment at runtime and returning an empty string resolves the leak in production.
2. **RGT-442 (Template Comment Stripping):**
   - Because no HTML/JS templates are currently served by either the Python or Go servers, there is no active exposure.
   - To guard against future regression, we need static pre-commit/CI regex scanners to identify HTML and JS comments before code is merged, along with build-time minifiers to strip comments from the final build artifact.
3. **RGT-437 (Silverlight & Flash Policies Caching):**
   - Standard requests for `/crossdomain.xml` and `/clientaccesspolicy.xml` yield a default 404, which is subject to client/proxy caching.
   - Adding explicit routes that return `404 Not Found` with strict cache-disabling headers (`Cache-Control: no-store...`, `Pragma: no-cache`, `Expires: 0`) ensures browsers and proxies will never cache these endpoints.

## 3. Caveats
- Checked static template assets but did not run dynamic checks on third-party libraries (e.g. Swagger UI assets fetched via CDN).
- Assumed standard environment variable naming (`APP_ENV=production`) is preferred for distinguishing environment settings.

## 4. Conclusion
We have formulated a concrete implementation strategy and verification plan for the required controls:
1. Hardening configuration variables for FastAPI/Uvicorn, hiding dynamic Swagger docs, stripping `Server` header in the runner using `server_header=False`, and sanitizing Go health check outputs.
2. Establishing pre-commit static analysis comment regex checks to prevent future HTML/JS template leaks.
3. Adding explicit XML policy endpoints that block Flash/Silverlight and enforce browser cache-control directives.

## 5. Verification Method
- **Verification Commands:** Run python pytest and go test suites in respective paths to verify the new test functions added in the analysis:
  - Python tests: `pytest tests/test_server_hardening.py`
  - Go tests: `cd go && go test ./internal/server/...`
- **File Inspections:** Inspect the proposed changes in `analysis.md`.
