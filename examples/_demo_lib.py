"""Shared scaffold for the concrete capability demos.

Each scenario tells the same story with a different real-world service:

    Human stores a secret
      -> Agent sees only the title + note (never the value)
      -> Agent requests a capability that needs the secret
      -> Human approves in the Approval Center (with a TOTP code)
      -> The capability runs, using the secret *inside* the vault boundary
      -> Agent gets the result, but never the secret

The demos run offline and deterministically (the outbound call is stubbed),
so an interviewer can clone the repo and run one command in under 30s. Each
demo notes exactly where the real API call would go for a live run.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict

from rgt_vault import totp
from rgt_vault.approval import ApprovalBroker
from rgt_vault.providers.base import MasterSecretProvider
from rgt_vault.vault import VaultManager

NS = "prod"


class _InMemoryProvider(MasterSecretProvider):
    def get_secret(self) -> bytes:
        return b"\x42" * 32

    def rotate_secret(self) -> bytes:
        return b"\x42" * 32


@dataclass
class Scenario:
    """One concrete human <-> agent <-> service story."""

    service: str                       # e.g. "GitHub"
    agent: str                         # e.g. "research-agent"
    secret_title: str                  # e.g. "GitHub Production Token"
    secret_value: str                  # the (fake) secret the human stores
    note: str                          # <= 25-word operator note
    capability: str                    # e.g. "create_github_issue"
    purpose: str                       # e.g. "Open a bug report from a failed test"
    request_fields: Dict[str, str] = field(default_factory=dict)  # shown in the card
    # use_secret receives the leased token buffer and returns the agent-visible
    # result string. It MUST NOT return the secret. This is where a live run
    # would make the real authenticated API call.
    use_secret: Callable[[bytearray], str] = lambda buf: "ok"


def _rule(width: int = 60) -> str:
    return "=" * width


def _print_card(scn: Scenario) -> None:
    print("\n  +--------------- Approval Center ---------------+")
    print(f"   Agent:      {scn.agent}")
    print(f"   Action:     {scn.capability}")
    for k, v in scn.request_fields.items():
        print(f"   {k+':':<11} {v}")
    print(f"   Requires:   {scn.secret_title}")
    print(f"   Purpose:    {scn.purpose}")
    print("   Approve?    [Y] approve (with TOTP)   [N] deny")
    print("  +-----------------------------------------------+")


def run(scn: Scenario) -> int:
    print(_rule())
    print(f" {scn.service} capability demo — human-approved, secret never returned")
    print(_rule())

    totp_secret = totp.generate_secret()
    broker = ApprovalBroker(timeout=10, totp_verifier=totp.ReplayGuardedVerifier(totp_secret))

    with tempfile.TemporaryDirectory() as tmp:
        vault = VaultManager(
            db_path=os.path.join(tmp, "vault.db"),
            policy_yaml=f"rules:\n  - effect: allow\n    agent: {scn.agent}\n  - effect: allow\n    agent: human\n",
            master_provider=_InMemoryProvider(),
            approval_gate=broker,
        )

        # 1. Human stores the secret (note is operator metadata, not the value).
        vault.set_secret(scn.secret_title, scn.secret_value, namespace=NS, agent="human",
                         note=scn.note, require_2fa=True)
        print(f"\n[human]  Stored '{scn.secret_title}'  (note: {scn.note})")

        # 2. The agent can enumerate titles + notes, never values.
        listed = vault.list_secrets(NS, agent=scn.agent)
        visible = [{"title": s["name"], "note": s["note"]} for s in listed]
        print(f"[agent]  Sees only metadata: {visible}")
        assert scn.secret_value not in str(visible), "secret value leaked into the listing!"

        # 3. Agent requests the capability; the request blocks on a human.
        print(f"[agent]  Requests '{scn.capability}' — blocked, waiting for a human...")
        _print_card(scn)

        def operator():
            for _ in range(300):
                pending = broker.list_pending()
                if pending:
                    broker.approve(pending[0].request_id,
                                   totp_code=totp.generate(totp_secret), operator="human")
                    return
                time.sleep(0.01)

        t = threading.Thread(target=operator)
        t.start()

        # 4. Execute: the secret is leased into a buffer, used inside the vault,
        #    and only the result comes back.
        result = vault.execute(scn.agent, NS, scn.purpose, scn.secret_title, scn.use_secret)
        t.join()

        print("\n[human]  Approved with a TOTP code.")
        print(f"[agent]  Result: {result}")
        assert scn.secret_value not in str(result), "secret value leaked into the result!"
        print(f"[agent]  Never saw '{scn.secret_title}' — only the result above.")

    print("\n" + _rule())
    print(" Secret used inside the vault, result returned, value never handed back.")
    print(_rule())
    return 0
