## 2026-06-26T20:46:22Z
You are a teamwork_preview_worker.
Your working directory is /home/will/rgt-vault/.agents/teamwork_preview_worker_m3/.
Your objective is to implement the security controls for Milestone 3 (API Security & Content Allowlisting).

Please read the explorer's report at /home/will/rgt-vault/.agents/teamwork_preview_explorer_m3/analysis.md and handoff.md.

Specifically, you need to:
1. Implement DoS prevention & query limits (RGT-448):
   - Add query pagination limits (limit: int = 100, offset: int = 0) to `list_secrets` in python/vault.py and python/storage/sqlite.py. Enforce LIMIT/OFFSET bounds in SQL query.
   - Restrict audit log limit checks in python/server/app.py.
   - Enforce database statement timeout.
2. Implement CSRF protection (RGT-447):
   - Add Double-Submit Cookie CSRF middleware to the FastAPI app in python/server/app.py. Bypass validation for requests containing a valid Bearer token in the 'Authorization' header.
3. Implement JSON Schema validation for Capability Executions (RGT-446):
   - In python/vault.py or python/server/app.py, validate incoming capability execute payloads dynamically using the registered schemas or type adapters.
4. Implement REST Content-Type allowlisting and Accept header validation (RGT-445):
   - In python/server/app.py middleware, validate the 'Accept' header: return HTTP 406 Not Acceptable if the client accepts only non-JSON formats (like application/xml).
   - Ensure the 'Content-Type' validation is active and robust.
5. Implement multi-level authorization for revocation (RGT-444):
   - Update `revoke_secret` in python/vault.py to evaluate ABAC policy: `self.auth.evaluate(agent, namespace, "*", action="revoke")`. Raise PolicyDeniedError if not allowed.
   - In python/server/app.py, update the `revoke` endpoint to extract client agent identity (e.g. from a query parameter 'agent') and pass it to `vault.revoke_secret`.
6. Implement URI normalization (RGT-443):
   - Add strict ASGI path normalization middleware in python/server/app.py (or a standalone ASGI middleware class) to intercept incoming requests and reject paths containing '..', '\\', '//', or control characters with HTTP 400 Bad Request.
7. Add corresponding test cases to tests/test_server_hardening.py to verify these controls.
8. Run the test suite:
   `PYTHONPATH=. pytest -o addopts="" tests/test_server_hardening.py`
9. Once all tests pass, update the following Multica tickets to 'done' using multica CLI:
   - RGT-448 (UUID: e81e383a-caaf-4da6-a88e-1f1d7e7a6be4)
   - RGT-447 (UUID: f2a5a6a7-3d06-4d59-ba38-2368f83ce8a4)
   - RGT-446 (UUID: f14ff4f6-21aa-4773-97e8-60aaf18c57a2)
   - RGT-445 (UUID: ebe61521-7498-4111-9495-a55b80909383)
   - RGT-444 (UUID: 2a00c1a0-f93a-4530-82f4-65b0fa607bfb)
   - RGT-443 (UUID: c53189cd-6df5-47a1-997f-259d9e18c4c0)

Report the exact commands run and their stdout/stderr in your handoff report.
Write your final handoff report to /home/will/rgt-vault/.agents/teamwork_preview_worker_m3/handoff.md and notify the orchestrator (conversation ID: 43d0761d-4b16-40af-8bf2-ad6fcfce1d66) when complete.

MANDATORY INTEGRITY WARNING:
> DO NOT CHEAT. All implementations must be genuine. DO NOT
> hardcode test results, create dummy/facade implementations, or
> circumvent the intended task. A Forensic Auditor will independently
> verify your work. Integrity violations WILL be detected and your
> work WILL be rejected.
