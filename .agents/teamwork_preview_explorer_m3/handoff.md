# Handoff Report - Milestone 3 Security Controls Strategy & Analysis

## 1. Observation
1. **FastAPI app structure**: The FastAPI application is constructed in `/home/will/rgt-vault/python/server/app.py`. It includes standard Pydantic models for validation (e.g. `SetSecretBody`, `UseBody`) and applies security middleware:
   ```python
   allowed_hosts = ["localhost", "127.0.0.1", "[::1]", "testserver"]
   app.add_middleware(
       TrustedHostMiddleware,
       allowed_hosts=allowed_hosts,
   )
   ```
2. **GraphQL presence**: Grep search for "graphql" inside `/home/will/rgt-vault/` only returned matching strings in `.agents` planning/issue logs, requirements documentation, and standard `.venv` packages (like `fastapi` and `pygments`). No source code files in `python/` implement a GraphQL surface.
3. **Database Layer query constraints**: In `/home/will/rgt-vault/python/storage/sqlite.py`, the `list_secrets` method executes a query without any `LIMIT` or `OFFSET` constraint:
   ```python
   def list_secrets(self, namespace: str, policy_hash: str = "") -> List[Dict[str, Any]]:
       with self._get_conn() as conn:
           cursor = conn.cursor()
           cursor.execute(
               """
               SELECT secret_id, name, version, created_at, updated_at, status, note, require_2fa
               FROM secrets
               WHERE namespace = ? AND status = 'ACTIVE'
           """,
               (namespace,),
           )
   ```
4. **Revocation Authorization Bypasses**: In `/home/will/rgt-vault/python/vault.py`, the `revoke_secret` method executes the revocation without performing any ABAC policy check (compare to `set_secret` which evaluates `self.auth.evaluate`):
   ```python
   def revoke_secret(self, namespace: str, name: str, agent: str = "system") -> None:
       self._hook_consult("revoke", agent, namespace, secret_name=name)
       self.storage.revoke_secret(namespace, name, policy_hash=self.policy_hash)
   ```
5. **Content-Type validation**: `/home/will/rgt-vault/python/server/app.py` enforces application/json content type on write methods:
   ```python
   if request.method in ("POST", "PUT", "PATCH") and request.url.path.startswith("/v1/"):
       # ...
       if "application/json" not in content_type:
           return JSONResponse(...)
   ```
   However, there are no references to `accept` header parsing or negotiation in the server middleware.
6. **Path Traversal/URI Validation**: `/home/will/rgt-vault/python/vault.py` implements simple string validation for parameter fields:
   ```python
   def _validate_string_param(self, param_name: str, value: Any, max_len: int, allow_empty: bool = False):
       if not isinstance(value, str):
           raise ValidationError(f"'{param_name}' must be a string. Got {type(value).__name__}.")
       # ...
   ```
   No normalization or verification of characters like `..` or `\\` is performed.
7. **Test suite status**: The command `.venv/bin/pytest` was executed and completed successfully:
   `262 passed, 8 warnings in 93.53s (0:01:33)`.

---

## 2. Logic Chain
1. **RGT-448 (DoS Prevention)**: Since `list_secrets` returns all records in a namespace without pagination limits, an attacker could populate a namespace with millions of mock secrets and call `/v1/secrets`, causing memory exhaustion (DoS). We must enforce pagination and database query timeout (Observation 3). Furthermore, if a GraphQL surface is added, depth and cost analysis must be applied to the AST before execution to prevent complex recursive queries from starving system threads.
2. **RGT-447 (CSRF Protection)**: The current REST API utilizes bearer tokens via the `Authorization` header, which is safe from CSRF. However, if cookie authentication is introduced in the future, it would be vulnerable to CSRF. Implementing a Double-Submit Cookie pattern in middleware ensures safety by verifying matching tokens in headers and cookies.
3. **RGT-446 (JSON Schema Validation)**: Pydantic handles standard endpoint schemas, but capabilities payloads (`ExecuteCapabilityBody.payload`) are validated loosely. We should enhance `CapabilitySpec` to dynamically compile and validate inputs against full JSON schemas.
4. **RGT-445 (Content Allowlisting)**: While Content-Type is validated for requests, the lack of Accept header checks (Observation 5) allows clients to specify unsupported formats like XML or HTML. Adding Accept validation to the middleware closes this gap (406 responses).
5. **RGT-444 (Multi-Level Authorization)**: Although route-level bearer tokens are validated, `revoke_secret` does not verify ABAC rules (Observation 4). Adding `self.auth.evaluate(agent, namespace, "*", action="revoke")` directly inside the model/vault layer guarantees policy enforcement for deletion operations.
6. **RGT-443 (URI Parsing Consistency)**: The lack of path traversal sanitization (Observation 6) allows characters like `..` and double slashes to reach routers. Adding strict URI normalization in an ASGI middleware prevents path normalization discrepancies between proxy servers and FastAPI.

---

## 3. Caveats
- No GraphQL implementation exists in the current codebase. The GraphQL cost/depth limiting strategy proposed is purely architectural and ready for integration when GraphQL libraries are added.
- The CSRF middleware is proposed under the assumption that cookie authentication might be added. It is bypassed for standard bearer-token requests to preserve existing client compatibility.

---

## 4. Conclusion
We have formulated a robust and detailed implementation plan for the six Milestone 3 security controls. By implementing the proposed middlewares, query limits, ABAC engine check inside `revoke_secret`, and dynamic JSON schema validations, the `rgt-vault` server will fail closed and prevent DoS, CSRF, URL traversal, and unauthorized deletions.

---

## 5. Verification Method
1. **Verification Command**:
   Run `.venv/bin/pytest -m "not fuzz"` (skips slow fuzz tests) to execute the basic test suite.
2. **Files to Inspect**:
   - `/home/will/rgt-vault/.agents/teamwork_preview_explorer_m3/analysis.md` (Detailed design decisions and code snippets)
   - `/home/will/rgt-vault/python/server/app.py` (FastAPI routes and middleware structure)
   - `/home/will/rgt-vault/python/vault.py` (Authorization hooks and capability execution)
3. **Invalidation Conditions**:
   The strategies are invalidated if the project requirements pivot away from FastAPI/Pydantic or if a different Python database engine replaces psycopg2/sqlite3.
