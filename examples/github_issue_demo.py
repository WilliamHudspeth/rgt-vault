"""Concrete demo: an agent files a GitHub issue without ever seeing the token.

    python examples/github_issue_demo.py

The agent asks to create an issue. A human approves it in the Approval
Center (with a TOTP code). The vault leases the GitHub token into a buffer,
makes the API call internally, and hands the agent back only the issue
number — never `ghp_...`.

Runs offline: the outbound call is stubbed so it's deterministic and needs
no real token. The comment in `create_issue` marks exactly where a live run
would POST to api.github.com.
"""

from _demo_lib import Scenario, run

REPO = "WilliamHudspeth/rgt-vault"


def create_issue(token_buf: bytearray) -> str:
    # token_buf is the live GitHub token, only inside the vault boundary.
    # A live run would do, e.g.:
    #     headers = {"Authorization": "token " + token_buf.decode()}
    #     r = httpx.post(f"https://api.github.com/repos/{REPO}/issues",
    #                    headers=headers, json={"title": ..., "body": ...})
    #     return f"Issue created: #{r.json()['number']}"
    # We build the auth header here to show the token IS used, then stub the
    # transport so the demo runs offline. The header (with the secret) never
    # leaves this function.
    auth_header = "token " + token_buf.decode()
    assert auth_header.startswith("token ghp_")  # proves the real token was used
    return f"Issue created: {REPO}#42"


SCENARIO = Scenario(
    service="GitHub",
    agent="research-agent",
    secret_title="GitHub Production Token",
    secret_value="ghp_demo000111222333444555666777888999",
    note="prod PAT, repo automation only",
    capability="create_github_issue",
    purpose="Open a bug report from a failed test run",
    request_fields={"Repository": REPO, "Title": "Flaky test: test_ttl_expiry"},
    use_secret=create_issue,
)


if __name__ == "__main__":
    raise SystemExit(run(SCENARIO))
