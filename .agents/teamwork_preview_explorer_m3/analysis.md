# Milestone 3 Security Controls Strategy & Analysis Report

## 1. Executive Summary
This report defines the implementation plan, design patterns, and programmatic verification strategy for the six API security controls required under Milestone 3 (API Security & Content Allowlisting) for `rgt-vault`. The target controls are:
- **RGT-448**: Data Layer & GraphQL Query Depth and Cost Limits (DoS Prevention)
- **RGT-447**: CSRF Protection for Cookie-Authenticated Endpoints
- **RGT-446**: End-to-End JSON Schema Validation
- **RGT-445**: REST Content-Type/Accept Allowlisting (406/415)
- **RGT-444**: Route-Level and Model-Level Multi-Level Authorization
- **RGT-443**: URI Parsing Consistency and Sensitive URL Leak Restriction

Through a read-only codebase exploration of the FastAPI server, database storage backends, and ABAC engine, we have identified critical gaps (e.g., lack of pagination limits, missing authorization check on secret revocation, absence of JSON schema validation for capability payloads) and formulated robust, containerized, and test-verified strategies to close them.

---

## 2. Codebase Analysis & Current State
### 2.1. FastAPI Server (`python/server/app.py`)
- **Routing**: Routes are standard FastAPI endpoints. Authentication is centralized in route dependencies: `require_token` (bearer token validation) and `require_operator_token`.
- **Middleware**: Currently enforces DNS rebinding protection via `TrustedHostMiddleware`, strict security headers, and secure cookie attribute formatting (SameSite=Strict, Secure, HttpOnly).
- **Validation**: REST body parameters are typed with standard Pydantic models. However, the `execute_capability` endpoint accepts `payload` as a loose `Dict[str, Any]` which escapes standard Pydantic schema validation.

### 2.2. Database Storage (`python/storage/sqlite.py` & `postgres.py`)
- SQLite storage operates in WAL mode with connection locks for audit logging.
- There are no database-level statement timeouts or query limits enforced. `list_secrets` returns all active records from a namespace in a single query.
- Postgres storage (`PostgresStorageBackendPoC`) is a read-only PoC with a threaded connection pool, but has no insert, update, delete, or pagination logic.

### 2.3. ABAC Policy Engine (`python/auth.py` & `capabilities.py`)
- `ABACPolicyEngine` performs YAML-driven attribute matching.
- Evaluated on secret reads (`use_secret` / `list_secrets`) and writes (`set_secret`), but is completely bypassed during secret revocation (`revoke_secret` endpoint)!

---

## 3. Targeted Security Strategies

### 3.1. RGT-448: Data Layer and GraphQL DoS Prevention
**Objective:** Prevent resource exhaustion/DoS from complex, recursive, or unbounded database and GraphQL queries.

#### 1. REST / Data Layer Controls
- **Query Pagination & Hard Limits**: Update `list_secrets` and `get_audit_log` to enforce strict pagination using query parameters `limit: int = Query(100, ge=1, le=1000)` and `offset: int = Query(0, ge=0)`. Cap execution results in SQL (e.g. `LIMIT ? OFFSET ?`).
- **Statement Timeouts**: Configure query execution timeouts at the database driver level:
  - **SQLite**: Set the `timeout` parameter in the connection string (e.g., `sqlite3.connect(..., timeout=5.0)`).
  - **PostgreSQL**: Configure the pool or connection to abort queries exceeding a budget: `SET statement_timeout = 5000` (5 seconds).
- **JSON Recursion Limit**: Restrict the nesting depth of raw JSON parsing. Implement a custom JSON decoder for incoming FastAPI payloads that raises a ValueError if depth exceeds 5 levels:
  ```python
  def parse_json_with_depth_limit(data: str, max_depth: int = 5) -> Any:
      # Use a recursive hook or custom object_pairs_hook that tracks tree depth
      ...
  ```

#### 2. GraphQL Controls (Architectural Design)
If a GraphQL endpoint is added (e.g., using `Strawberry` or `Ariadne` library), implement the following pre-execution AST validation rules:
- **Query Depth Limiter**: Traverse the AST (Abstract Syntax Tree) representation of incoming queries. Count selection set levels. Raise a validation error if depth exceeds a threshold (e.g., 5).
- **Query Cost Analyzer**: Assign static weights to fields:
  - Scalar fields: 1
  - Association/Relation fields: 5
  - List/Connection fields: 10
  - Limit multiplier: Multiply nested connection cost by the `first` or `limit` argument value.
  Accumulate the cost. Reject queries exceeding a max budget (e.g., 100) before any database execution occurs.

---

### 3.2. RGT-447: Protect Cookie-Authenticated REST Endpoints against CSRF
**Objective:** Protect cookie-based state-changing requests against Cross-Site Request Forgery (CWE-352).

#### 1. CSRF Middleware Architecture
Implement a custom FastAPI middleware using the **Double-Submit Cookie** pattern:
- **Token Generation**: On session establishment or safe GET requests, generate a cryptographically secure random value (`secrets.token_urlsafe(32)`) and set it in a cookie (e.g., `csrf_token`) with flags `SameSite=Strict; Secure; HttpOnly=True`.
- **Validation**:
  - For state-changing methods (`POST`, `PUT`, `PATCH`, `DELETE`), intercept the request.
  - Require the client to provide the matching token in a custom header: `X-CSRF-Token` or `X-XSRF-TOKEN`.
  - Compare the header value with the cookie value. If they are missing or do not match, return `403 Forbidden`.
  - **Bearer Token Bypass**: If the request contains a valid `Authorization: Bearer <token>` header, skip CSRF validation since bearer-token authentication is immune to CSRF.
- **Origin/Referer Check**: Strictly verify that the `Origin` or `Referer` matches the server's configured domain for all state-changing cookie requests.

---

### 3.3. RGT-446: JSON Schema Validation for All API Endpoints
**Objective:** Ensure strict, schema-compliant validation for all inputs before application logic processing.

#### 1. REST Endpoint Validation
- Enforce standard Pydantic models on all FastAPI path routes (already mostly implemented).
- Configure Pydantic models to reject extra parameters: `extra = "forbid"` in `model_config` (Pydantic v2).

#### 2. Capability Payload Schema Validation
- Enhance `CapabilitySpec` to support a full JSON Schema definition (or a Pydantic model) instead of a simple string array.
- In `execute_capability`, validate the incoming loose `payload` dictionary against the schema using Pydantic's `TypeAdapter`:
  ```python
  from pydantic import TypeAdapter, ValidationError as PydanticValidationError
  
  # When registering a capability, accept a Pydantic model class or JSON schema dict
  # Validation:
  try:
      TypeAdapter(spec.params_model).validate_python(payload)
  except PydanticValidationError as e:
      raise ValidationError(f"Payload validation failed: {e}")
  ```

---

### 3.4. RGT-445: REST Content-Type Allowlisting and Rejection
**Objective:** Prevent MIME-sniffing, content bypasses, and ensure consistent serialization (CWE-436).

#### 1. Payload Content-Type Validation (415)
- Enhance the current HTTP middleware to reject any `POST`, `PUT`, or `PATCH` request with an unexpected `Content-Type` header (must be explicitly `application/json` or `application/json; charset=utf-8`). Reject others with `415 Unsupported Media Type`.

#### 2. Response Representation Negotiation (406)
- Validate the `Accept` header. If the client specifies an `Accept` header that does not permit `application/json` (e.g., `Accept: application/xml`), immediately return `406 Not Acceptable` before running downstream handlers:
  ```python
  accept_header = request.headers.get("accept", "")
  if accept_header and not any(mime in accept_header for mime in ("application/json", "*/*", "application/*")):
      return JSONResponse(
          status_code=status.HTTP_406_NOT_ACCEPTABLE,
          content={"error": "NotAcceptable", "detail": "Server only supports application/json responses"}
      )
  ```

---

### 3.5. RGT-444: Multi-Level Authorization (Route & Model Levels)
**Objective:** Enforce authorization checks at both route entry points and database/resource access layers (CWE-285).

#### 1. Route-Level Authorization Gate
- FastAPI route dependencies verify the client's session, credentials, and access roles (e.g. `require_token` and `require_operator_token`).
- Path traversal checking at the routing tier ensures path parameters resolve cleanly.

#### 2. Model-Level Authorization Gate
- **ABAC Engine Evaluation**: Pass the authenticated context (agent identity) down to the model layer. Ensure that the database repository or Vault manager explicitly calls `self.auth.evaluate(agent, namespace, purpose, action)` for all resource operations.
- **Critical Fix (Revocation check)**: Update `revoke_secret` in `vault.py` to evaluate the policy instead of bypassing it.
  ```python
  # Proposed change in vault.py:
  def revoke_secret(self, namespace: str, name: str, agent: str = "system") -> None:
      self._hook_consult("revoke", agent, namespace, secret_name=name)
      
      decision = self.auth.evaluate(agent, namespace, "*", action="revoke")
      if not decision["allowed"]:
          self._log_audit("POLICY_DENIED", name, f"Action: revoke, Agent: {agent}, Namespace: {namespace}")
          raise PolicyDeniedError("Unauthorized to revoke secret.")
          
      self.storage.revoke_secret(namespace, name, policy_hash=self.policy_hash)
  ```
  Ensure `app.py` passes the client agent identity (derived from the token store or parameter) to `vault.revoke_secret`.

---

### 3.6. RGT-443: URI Parsing Consistency and Sensitive Leak Prevention
**Objective:** Ensure consistent URI normalization to prevent path bypasses and SSRF/RFI, and prevent URL credential leakage.

#### 1. Strict URL Normalization Middleware
Add a high-priority ASGI middleware that intercepts all incoming requests and normalizes the path:
- Detect and block path traversal sequences: reject paths containing `..`, `.` (when resolving to traversal), backslashes (`\`), double slashes (`//`), or control characters (`%00`, `\r`, `\n`).
- Immediately return `400 Bad Request` on match:
  ```python
  class StrictURLNormalizationMiddleware:
      async def __call__(self, scope, receive, send):
          if scope["type"] == "http":
              path = scope.get("path", "")
              # Enforce strict parsing
              if ".." in path or "\\" in path or "//" in path or any(c in path for c in ("\r", "\n", "\t", "\x00")):
                  # Send 400 Bad Request directly
                  ...
  ```

#### 2. REST URL Leak Prevention
- Mandate that all sensitive values (tokens, credentials, passcodes) must be submitted via the HTTP Request Body (inside JSON payload) or request headers (e.g. `Authorization`).
- Audit all endpoints to guarantee that no secret parameters are defined as path or query string parameters.

---

## 4. Programmatic Verification in `tests/`
To verify these controls in the test suite, we recommend implementing the following test fixtures and cases inside `tests/test_server.py` and `tests/test_validation.py`:

### 4.1. DoS & Query Limit Verification
```python
def test_audit_log_query_limit_bounds(server):
    app, token = server
    c = _authed(app, token)
    # Assert limit <= 0 or limit > 1000 yields 400 Bad Request
    assert c.get("/v1/audit", params={"limit": 0}).status_code == 400
    assert c.get("/v1/audit", params={"limit": 1001}).status_code == 400
```

### 4.2. CSRF Middleware Verification
```python
def test_csrf_protection_rejects_missing_header_for_cookies(server):
    app, token = server
    c = TestClient(app)
    # Set the cookie directly in client
    c.cookies.set("csrf_token", "test_csrf_token")
    # Mutating request must fail without custom header
    r = c.post("/v1/secrets", json={"name": "API_KEY", "value": "sk-abc", "agent": "tester"})
    assert r.status_code == 403
    # Succeeds when header matches cookie
    c.headers["X-CSRF-Token"] = "test_csrf_token"
    r = c.post("/v1/secrets", json={"name": "API_KEY", "value": "sk-abc", "agent": "tester"})
    # (Assuming we have bypassed bearer token logic or are testing cookie route)
```

### 4.3. Content-Type and Accept Allowlisting Verification
```python
def test_content_type_and_accept_allowlist(server):
    app, token = server
    c = _authed(app, token)
    # POST with XML content-type returns 415
    r = c.post("/v1/secrets", content="<xml></xml>", headers={"Content-Type": "application/xml"})
    assert r.status_code == 415
    
    # GET with XML accept header returns 406
    r = c.get("/v1/secrets", params={"namespace": "default", "agent": "tester"}, headers={"Accept": "application/xml"})
    assert r.status_code == 406
```

### 4.4. Multi-Level Revocation Authorization Verification
```python
def test_revoke_secret_evaluates_abac_policy(server):
    # Setup policy that ALLOWS read/write but DENIES revoke
    # Verify that calling revoke returns 403 PolicyDeniedError
    ...
```

### 4.5. URI Normalization Verification
```python
def test_uri_normalization_blocks_traversal_attempts(server):
    app, token = server
    c = _authed(app, token)
    # Verify path traversals or backslashes return 400 Bad Request
    assert c.post("/v1/secrets/default/..%2F..%2Fsecrets/use", json={...}).status_code == 400
    assert c.get("/v1//secrets").status_code == 400
```
