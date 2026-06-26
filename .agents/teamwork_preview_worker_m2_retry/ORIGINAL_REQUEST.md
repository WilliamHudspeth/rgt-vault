## 2026-06-26T20:40:05Z
You are a teamwork_preview_worker.
Your working directory is /home/will/rgt-vault/.agents/teamwork_preview_worker_m2_retry/.
Your objective is to implement the security controls for Milestone 2 (Server Config & Information Leakage Prevention).

Please read the explorer's report at /home/will/rgt-vault/.agents/teamwork_preview_explorer_m2/analysis.md and handoff.md.

Specifically, you need to:
1. Modify python/server/app.py:
   - Check if APP_ENV is 'production' to disable Swagger/ReDoc and openapi.json.
   - Serve /crossdomain.xml and /clientaccesspolicy.xml with status 404 and strict cache-disabling headers (Cache-Control, Pragma, Expires, X-Content-Type-Options).
   - Ensure the secure_http_headers_middleware pops 'server' and 'x-powered-by' headers.
2. Modify python/cli.py:
   - Call uvicorn.run with server_header=False to prevent Uvicorn from injecting its Server header.
3. If Go server is configured, check if we need to modify go/internal/server/handlers/handlers.go to suppress version in HealthCheck when APP_ENV is production, and serve crossdomain.xml/clientaccesspolicy.xml with 404 and cache-disabling headers. Run 'cd go && go test ./...' to make sure Go tests compile and pass.
4. Implement a static template comment check script at scripts/check_template_comments.py to scan for TODO/FIXME comments in HTML/JS templates, ensuring it is a runnable script.
5. Append new test cases to tests/test_server_hardening.py to verify debug/server header stripping and cache-disabling on xml files (as outlined in analysis.md).
6. Run the pytest command (PYTHONPATH=. pytest tests/test_server_hardening.py) to ensure all tests pass.
7. Once all tests pass, update the following Multica tickets to 'done' using multica CLI:
   - RGT-452 (UUID: ab9fde47-3e0f-4500-a6e1-5f7c2b6b441b)
   - RGT-442 (UUID: 530af09e-2a44-4da2-8725-b41a6db59ff2)
   - RGT-437 (UUID: 09a4c629-a392-422a-a3b5-ede99aab42d8)

Report the exact commands run and their stdout/stderr in your handoff report.
Write your final handoff report to /home/will/rgt-vault/.agents/teamwork_preview_worker_m2_retry/handoff.md and notify the orchestrator (conversation ID: 43d0761d-4b16-40af-8bf2-ad6fcfce1d66) when complete.

MANDATORY INTEGRITY WARNING:
> DO NOT CHEAT. All implementations must be genuine. DO NOT
> hardcode test results, create dummy/facade implementations, or
> circumvent the intended task. A Forensic Auditor will independently
> verify your work. Integrity violations WILL be detected and your
> work WILL be rejected.
