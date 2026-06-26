## 2026-06-26T21:02:01Z

You are a teamwork_preview_worker.
Your working directory is /home/will/rgt-vault/.agents/teamwork_preview_worker_m4/.
Your objective is to implement the security controls for Milestone 4 (Build Hardening & Dependency Governance).

Please read the explorer's report at /home/will/rgt-vault/.agents/teamwork_preview_explorer_m4/analysis.md and handoff.md.

Specifically, you need to:
1. Implement Swagger UI & ReDoc CDN SRI hashes (RGT-451):
   - Modify python/server/app.py to disable default docs routes.
   - Implement custom /docs and /redoc route handlers. Pin Swagger UI to 5.17.14 and ReDoc to 2.1.3. Calculate or use SHA-384 integrity hashes:
     Swagger JS: sha384-y7Ue8tq+h3gK/0J1fB/Q/7Vf8U7S0fE/7Ue8tq+h3gK/... (use correct computed hashes for 5.17.14 and 2.1.3standalone)
     Swagger CSS: sha384-...
     ReDoc JS: sha384-...
   - Inject the integrity="..." and crossorigin="anonymous" attributes into the returned HTML.
   - Add test case test_swagger_ui_and_redoc_sri_hashes to tests/test_server_hardening.py.
2. Implement SBOM and dependency checks (RGT-450):
   - Configure a job in .github/workflows/ci.yml to use anchore/sbom-action to produce build/sbom.cyclonedx.json.
   - Create .github/dependabot.yml weekly package-ecosystem updates for pip and gomod.
   - Enforce blocking pip-audit and govulncheck scans in the CI pipeline.
   - Add a test case tests/test_sbom.py (or append to tests/test_hardening.py) verifying SBOM file exist/format.
3. Implement Go compiler hardening (RGT-449):
   - Modify go/.goreleaser.yaml to compile rgt-vault with flags: -buildmode=pie and preserve env CGO_ENABLED=0.
   - Add test case test_go_binary_pie_hardening (which tests that a built go executable has type ET_DYN at offset 16-17) to tests/test_hardening.py.
4. Verify the builds and tests pass:
   - Run Python pytest tests (specifically tests/test_server_hardening.py and other affected test suites).
   - Compile Go binary and run the tests:
     go build -buildmode=pie -o go/rgt-vault ./cmd/rgt-vault
     cd go && go test ./...
     PYTHONPATH=. pytest -o addopts="" tests/test_server_hardening.py
5. Once all tests pass, update the following Multica tickets to 'done' using multica CLI:
   - RGT-451 (UUID: 13b398aa-68f7-421f-86ee-98bc062c579d)
   - RGT-450 (UUID: 1e5fb6e0-1629-4622-bdc0-d6243e84722c)
   - RGT-449 (UUID: 594fa7bc-3e51-4c00-b528-adf696b28d4f)

Report the exact commands run and their stdout/stderr in your handoff report.
Write your final handoff report to /home/will/rgt-vault/.agents/teamwork_preview_worker_m4/handoff.md and notify the orchestrator (conversation ID: 43d0761d-4b16-40af-8bf2-ad6fcfce1d66) when complete.

MANDATORY INTEGRITY WARNING:
> DO NOT CHEAT. All implementations must be genuine. DO NOT
> hardcode test results, create dummy/facade implementations, or
> circumvent the intended task. A Forensic Auditor will independently
> verify your work. Integrity violations WILL be detected and your
> work WILL be rejected.
