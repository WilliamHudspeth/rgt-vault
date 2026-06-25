"""Concrete demo: an agent posts to Slack without ever holding the webhook.

    python examples/slack_demo.py

The agent requests to post a deploy notification. A human approves it (with
TOTP). The vault leases the Slack webhook URL into a buffer, makes the call
internally, and returns only a confirmation — the agent never sees the
webhook secret.

Runs offline (stubbed transport). The comment in `post_message` marks where
a live run would POST to hooks.slack.com.
"""

from _demo_lib import Scenario, run


def post_message(webhook_buf: bytearray) -> str:
    # webhook_buf is the live Slack webhook URL, only inside the vault boundary.
    # A live run would do, e.g.:
    #     r = httpx.post(webhook_buf.decode(), json={"text": "Deploy v0.3.0 ✅"})
    #     return "posted" if r.status_code == 200 else f"failed ({r.status_code})"
    url = webhook_buf.decode()
    assert url.startswith("https://hooks.slack.com/")  # proves the real secret was used
    return "message posted to #deploys"


SCENARIO = Scenario(
    service="Slack",
    agent="release-agent",
    secret_title="Slack Deploy Webhook",
    secret_value="https://hooks.slack.com/services/T000/B000/demoXXXXXXXXXXXXXXXXXXXX",
    note="posts to #deploys channel only",
    capability="slack_post_message",
    purpose="Announce a successful release",
    request_fields={"Channel": "#deploys", "Message": "Deploy v0.3.0 succeeded"},
    use_secret=post_message,
)


if __name__ == "__main__":
    raise SystemExit(run(SCENARIO))
