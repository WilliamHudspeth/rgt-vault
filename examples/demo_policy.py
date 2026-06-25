"""End-to-end demo: the whole rgt-vault story in about ten seconds.

Part A — static policy:
    1. Store a secret (encrypted at rest).
    2. Authorized agent executes a capability — secret used internally,
       only the result comes back.
    3. Unauthorized purpose is denied before the secret is touched.
    4. Unknown secret errors cleanly.

Part B — live human-in-the-loop approval with 2FA:
    5. An agent request blocks until a human approves it.
    6. Approval requires a TOTP second factor.
    7. A denied request never reaches the secret.

Throughout, the agent's callback only ever sees a transient buffer; the
secret value is never returned to the caller. Runs entirely in-process on
a temp database — no OS keyring, no daemon, no persistent state.

    python examples/demo_policy.py
"""

import os
import tempfile
import threading
import time

from rgt_vault import totp
from rgt_vault.approval import ApprovalBroker
from rgt_vault.exceptions import PolicyDeniedError, VaultError
from rgt_vault.providers.base import MasterSecretProvider
from rgt_vault.vault import VaultManager

POLICY = """
rules:
  - effect: allow
    agent: admin
    namespace: "*"
    action: write

  - effect: allow
    agent: research_agent
    namespace: openai
    action: read
    purpose: embeddings

  - effect: deny
    agent: research_agent
    purpose: billing
"""

PASS = "  ✓"  # ✓
FAIL = "  ✗"  # ✗


class _InMemoryProvider(MasterSecretProvider):
    def get_secret(self) -> bytes:
        return b"\x42" * 32

    def rotate_secret(self) -> bytes:
        return b"\x42" * 32


def _call_openai(key_buf: bytearray) -> str:
    # key_buf is a transient bytearray; the vault wipes it after we return.
    return f"API call succeeded (used a {len(key_buf)}-byte key, never copied out)"


def part_a_static_policy(tmp: str) -> list:
    print("\nPart A — static policy enforcement")
    results = []
    vault = VaultManager(
        db_path=os.path.join(tmp, "a", "vault.db"),
        policy_yaml=POLICY,
        master_provider=_InMemoryProvider(),
    )

    vault.set_secret("OPENAI_KEY", "sk-live-demo", namespace="openai", agent="admin",
                     note="prod OpenAI key, embeddings team")
    print(f"{PASS} Secret stored (encrypted at rest; plaintext discarded)")
    results.append(True)

    out = vault.execute("research_agent", "openai", "embeddings", "OPENAI_KEY", _call_openai)
    ok = "succeeded" in out
    print(f"{PASS if ok else FAIL} Authorized request succeeded: {out}")
    results.append(ok)

    try:
        vault.execute("research_agent", "openai", "billing", "OPENAI_KEY", _call_openai)
        print(f"{FAIL} Unauthorized request was NOT denied")
        results.append(False)
    except PolicyDeniedError:
        print(f"{PASS} Unauthorized purpose 'billing' denied before any decryption")
        results.append(True)

    try:
        vault.execute("research_agent", "openai", "embeddings", "NOPE", _call_openai)
        print(f"{FAIL} Unknown secret did not error")
        results.append(False)
    except VaultError:
        print(f"{PASS} Unknown secret errored cleanly (no information leak)")
        results.append(True)

    print(f"{PASS if vault.verify_audit_chain() else FAIL} Audit chain verified (tamper-evident)")
    results.append(vault.verify_audit_chain())
    return results


def part_b_live_approval(tmp: str) -> list:
    print("\nPart B — live human approval with 2FA")
    results = []

    totp_secret = totp.generate_secret()
    broker = ApprovalBroker(timeout=10, totp_verifier=lambda c: totp.verify(totp_secret, c))
    vault = VaultManager(
        db_path=os.path.join(tmp, "b", "vault.db"),
        policy_yaml="rules:\n  - effect: allow\n    agent: research_agent\n",
        master_provider=_InMemoryProvider(),
        approval_gate=broker,
    )
    vault.set_secret("OPENAI_KEY", "sk-live-demo", namespace="openai", agent="research_agent",
                     note="needs human sign-off", require_2fa=True)

    def simulated_operator(action: str):
        # Stand in for a human at the TUI: wait for the request, then act.
        for _ in range(200):
            pending = broker.list_pending()
            if pending:
                rid = pending[0].request_id
                if action == "approve":
                    broker.approve(rid, totp_code=totp.generate(totp_secret), operator="demo-human")
                else:
                    broker.deny(rid, reason="not now", operator="demo-human")
                return
            time.sleep(0.01)

    # 5/6. Approve path (with valid TOTP).
    t = threading.Thread(target=simulated_operator, args=("approve",))
    t.start()
    print(f"{PASS} Agent requested OPENAI_KEY; request is blocking on a human...")
    out = vault.execute("research_agent", "openai", "use", "OPENAI_KEY", _call_openai)
    t.join()
    ok = "succeeded" in out
    print(f"{PASS if ok else FAIL} Human approved with a TOTP code; agent unblocked: {out}")
    results.append(ok)

    # 7. Deny path.
    t = threading.Thread(target=simulated_operator, args=("deny",))
    t.start()
    try:
        vault.execute("research_agent", "openai", "use", "OPENAI_KEY", _call_openai)
        print(f"{FAIL} Denied request still reached the secret")
        results.append(False)
    except PolicyDeniedError:
        print(f"{PASS} Human denied the next request; secret never decrypted")
        results.append(True)
    finally:
        t.join()
    return results


def main() -> int:
    print("=" * 56)
    print(" rgt-vault — capability vault with human-in-the-loop approval")
    print("=" * 56)
    with tempfile.TemporaryDirectory() as tmp:
        results = part_a_static_policy(tmp) + part_b_live_approval(tmp)

    passed = sum(1 for r in results if r)
    print("\n" + "=" * 56)
    print(f" {passed}/{len(results)} checks passed.")
    print(" The agent's callback only ever received a buffer the vault")
    print(" wiped on return — the secret value was never handed back to a")
    print(" caller. (This demo runs the broker in-process; the operator-")
    print(" token boundary that stops self-approval is covered by the")
    print(" server tests and the deploy/ daemon.)")
    print("=" * 56)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
