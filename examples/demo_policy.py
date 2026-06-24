"""Policy enforcement demo.

Shows the three outcomes a caller can get from the vault:

  1. Authorized execution  — secret used internally, result returned.
  2. Policy deny           — access blocked before the secret is touched.
  3. Unknown secret        — clean error, no information leak.

Run from the repo root after installing the package:

    python examples/demo_policy.py

Uses an in-memory temp database — no OS keyring, no persistent state.
"""

import os
import tempfile

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


class _InMemoryProvider(MasterSecretProvider):
    def get_secret(self) -> bytes:
        return b"\x42" * 32

    def rotate_secret(self) -> bytes:
        return b"\x42" * 32


def _call_openai(key_buf: bytearray) -> str:
    # key_buf is a mutable bytearray; the vault wipes it after we return.
    print(f"  [vault] Secret delivered to callback (length {len(key_buf)}). "
          "Making API call internally...")
    return "Call successful"


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        vault = VaultManager(
            db_path=os.path.join(tmp, "vault.db"),
            policy_yaml=POLICY,
            master_provider=_InMemoryProvider(),
        )

        # ------------------------------------------------------------------
        # 1. Store a secret (admin agent, allowed by policy)
        # ------------------------------------------------------------------
        print("1. Storing secret as admin...")
        vault.set_secret("OPENAI_KEY", "sk-live-demo-key", namespace="openai", agent="admin")
        print("   Stored. Secret is encrypted at rest; plaintext is gone.\n")

        # ------------------------------------------------------------------
        # 2. Authorized execution
        # ------------------------------------------------------------------
        print("2. research_agent requests embeddings (should ALLOW)...")
        try:
            result = vault.execute(
                agent="research_agent",
                namespace="openai",
                purpose="embeddings",
                secret_name="OPENAI_KEY",
                callback=_call_openai,
            )
            print(f"   ALLOWED — callback returned: {result!r}\n")
        except PolicyDeniedError as e:
            print(f"   UNEXPECTED DENY: {e}\n")

        # ------------------------------------------------------------------
        # 3. Denied execution — billing purpose is explicitly blocked
        # ------------------------------------------------------------------
        print("3. research_agent requests billing access (should DENY)...")
        try:
            vault.execute(
                agent="research_agent",
                namespace="openai",
                purpose="billing",
                secret_name="OPENAI_KEY",
                callback=_call_openai,
            )
            print("   UNEXPECTED ALLOW — policy not enforced!\n")
        except PolicyDeniedError as e:
            print(f"   DENIED (correct): {e}\n")

        # ------------------------------------------------------------------
        # 4. Unknown secret — should error cleanly without leaking anything
        # ------------------------------------------------------------------
        print("4. Requesting a non-existent secret (should error cleanly)...")
        try:
            vault.execute(
                agent="research_agent",
                namespace="openai",
                purpose="embeddings",
                secret_name="NON_EXISTENT",
                callback=_call_openai,
            )
        except VaultError as e:
            print(f"   VaultError (correct): {e}\n")

        # ------------------------------------------------------------------
        # 5. Audit chain integrity
        # ------------------------------------------------------------------
        print(f"5. Audit chain valid: {vault.verify_audit_chain()}")
        print("   Every execution above is recorded and tamper-evident.")


if __name__ == "__main__":
    main()
