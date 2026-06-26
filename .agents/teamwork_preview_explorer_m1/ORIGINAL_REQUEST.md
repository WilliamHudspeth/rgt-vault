## 2026-06-26T16:39:32Z
You are a teamwork_preview_explorer.
Your working directory is /home/will/rgt-vault/.agents/teamwork_preview_explorer_m1/.
Your objective is to explore the codebase (specifically python/server/app.py and tests/) and formulate a concrete plan/strategy to implement the following security controls for Milestone 1 (HTTP Headers & CORS Hardening):
- RGT-454: Configure secure HSTS (Strict-Transport-Security), CSP (Content-Security-Policy), Referrer-Policy, and frame embedding controls (X-Frame-Options/frame-ancestors).
- RGT-453: Enforce Content-Type, Content-Disposition, and secure cookie flags (Secure, HttpOnly, SameSite).
- RGT-438: Enforce Content-Disposition and X-Content-Type-Options headers on downloads.
- RGT-436: CORS: Review and harden Cross-Origin Resource Sharing (CORS) headers.

Please investigate how the FastAPI app is set up and suggest:
1. Exact middleware or code additions in python/server/app.py to set secure headers and CORS configuration.
2. Best practices for configuring these headers in our FastAPI server.
3. How to verify these programmatically in tests/test_server_hardening.py.

Save your detailed report as 'analysis.md' in your working directory, and also send a message back to the orchestrator (conversation ID: 43d0761d-4b16-40af-8bf2-ad6fcfce1d66) with a summary.
