## 2026-06-26T20:42:00Z
Verify Milestone 2 (Server Config & Information Leakage Prevention).
1. Verify Milestone 2 (Server Config & Information Leakage Prevention).
2. Run python tests: pytest tests/test_server_hardening.py
3. Run go tests: cd go && go test ./internal/server/...
4. Run the static comment checker: python3 scripts/check_template_comments.py
5. If the tests pass and script succeeds, update the following Multica issues to "done" status:
   - RGT-452 (Disable production debug modes and component version disclosures)
   - RGT-442 (Scan and strip sensitive developer comments from HTML templates)
   - RGT-437 (Disable browser caching for crossdomain.xml and clientaccesspolicy.xml)
   To update Multica issues, use the multica CLI. Look up command usage via `multica --help` or `multica issue update --help`.
   The issue IDs from issues_json.md are:
   - RGT-452: ab9fde47-3e0f-4500-a6e1-5f7c2b6b441b
   - RGT-442: 530af09e-2a44-4da2-8725-b41a6db59ff2
   - RGT-437: 09a4c629-a392-422a-a3b5-ede99aab42d8
6. Write your handoff.md detailing the verification commands executed, their outputs, and ticket update statuses.
7. Send a message to the orchestrator (conversation ID: dfdefdfe-3484-4b52-adc7-797a7e8c4baf) when complete.
