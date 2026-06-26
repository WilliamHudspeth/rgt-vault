# Project: rgt-vault API, HTTP Headers & Configuration Hardening

## Architecture
- Module/package boundaries, data flow, shared interfaces:
  - `python/server/app.py` is the FastAPI web server.
  - `python/server/auth.py` is the token store and validation logic.
  - `python/server/mcp_server.py` is the Model Context Protocol (MCP) server.
  - Test suite is located in `tests/`.

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | HTTP Headers & CORS Hardening | RGT-454, RGT-453, RGT-438, RGT-436 | None | DONE |
| 2 | Server Config & Information Leakage Prevention | RGT-452, RGT-442, RGT-437 | M1 | PLANNED |
| 3 | API Security & Content Allowlisting | RGT-448, RGT-447, RGT-446, RGT-445, RGT-444, RGT-443 | M2 | PLANNED |
| 4 | Build Hardening & Dependency Governance | RGT-451, RGT-450, RGT-449 | M3 | PLANNED |

## Interface Contracts
### API ↔ Web Client
- HTTPS secure headers configured at FastAPI app level or middleware level.
- CORS policies restricting origins, credentials, and allowed headers.
- Rate-limiting, CSRF, and JSON schema validation for all endpoints.
- Dependency scans and compiler flags applied during build.

## Code Layout
- `python/server/app.py`: FastAPI server configuration, routing, and middleware.
- `python/server/auth.py`: Token verification and authentication logic.
- `tests/test_server_hardening.py`: Server hardening test cases.
