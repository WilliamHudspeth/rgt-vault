## 2026-06-26T16:42:33Z

You are a teamwork_preview_worker.
Your working directory is /home/will/rgt-vault/.agents/teamwork_preview_worker_m1/.
Your objective is to implement the security controls for Milestone 1 (HTTP Headers & CORS Hardening).

Please read the explorer's report at /home/will/rgt-vault/.agents/teamwork_preview_explorer_m1/analysis.md and handoff.md.

Specifically, you need to:
1. Modify python/server/app.py to add:
   - TrustedHostMiddleware for DNS rebinding protection (RGT-436 / RGT-119).
   - CORSMiddleware with a default-deny policy (RGT-436).
   - Custom middleware to inject Strict-Transport-Security, Referrer-Policy, X-Frame-Options, Content-Security-Policy (sandbox for APIs, specific for docs), X-Content-Type-Options, Content-Disposition, and secure cookie flags (Secure, HttpOnly, SameSite=Strict).
   - Content-Type verification for POST/PUT/PATCH endpoints in /v1/ requests (rejecting non-JSON content types with HTTP 415).
2. Modify tests/test_server_hardening.py to add the verification test cases as outlined in analysis.md.
3. Run the pytest command to verify all tests in tests/test_server_hardening.py pass. Make sure you document the test execution command and results in your handoff report.
4. Once tests pass, update the status of the following Multica tickets to 'done' using the `multica issue update` CLI:
   - RGT-454 (UUID: f2877991-f628-490a-bba6-a0e8dcf7648a)
   - RGT-453 (UUID: 55d8922f-eb77-4939-9f78-f68ccc18c98b)
   - RGT-438 (UUID: 5da0b979-306a-426c-bc6e-a0362c46d123)
   - RGT-436 (UUID: 9b0a5646-d60a-4ef0-99bd-b1559dd33c3d)

Scope boundaries: Do not modify any other file. Focus only on python/server/app.py and tests/test_server_hardening.py.
Output requirements: Write a detailed handoff report to `/home/will/rgt-vault/.agents/teamwork_preview_worker_m1/handoff.md` and send a message back to the orchestrator (conversation ID: 43d0761d-4b16-40af-8bf2-ad6fcfce1d66) when complete.

MANDATORY INTEGRITY WARNING:
> DO NOT CHEAT. All implementations must be genuine. DO NOT
> hardcode test results, create dummy/facade implementations, or
> circumvent the intended task. A Forensic Auditor will independently
> verify your work. Integrity violations WILL be detected and your
> work WILL be rejected.
