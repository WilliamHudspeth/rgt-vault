"""Minimal end-to-end example.

Uses KeyringProvider (cross-platform OS keyring) so it runs out of the box.
For production, seal the master secret with a platform provider (DPAPI/TPM).
"""

import tempfile
import os

from rgt_vault.vault import VaultManager
from rgt_vault.keychain import KeyringProvider


def mock_llm_call(key_buf: bytearray):
    # `key_buf` is a mutable bytearray; the vault wipes it after we return.
    print(f"[Mock] Calling LLM with key (length: {len(key_buf)})... Success!")
    return {"status": "success"}


def main():
    # 1. Define policy: admin may write; research_agent may read openai for
    #    embeddings, but is denied any billing purpose.
    policy = """
    rules:
      - effect: allow
        agent: admin
        namespace: "*"
        action: write
      - effect: allow
        agent: research_agent
        namespace: openai
        action: read
      - effect: deny
        agent: research_agent
        purpose: billing
    """

    # 2. Init vault in a throwaway directory.
    with tempfile.TemporaryDirectory() as tmp:
        vault = VaultManager(
            db_path=os.path.join(tmp, "vault.db"),
            policy_yaml=policy,
            master_provider=KeyringProvider(),
        )

        # 3. Store a secret (as admin).
        print("Setting secret...")
        vault.set_secret("OPENAI_API_KEY", "sk-1234567890abcdef", namespace="openai", agent="admin")

        # 4. Fingerprint (debug aid; never reveals plaintext).
        print(f"Fingerprint: {vault.get_fingerprint('OPENAI_API_KEY', namespace='openai')}")

        # 5. Execute a callback as research_agent (allowed for embeddings).
        print("Executing callback via research_agent (purpose: embeddings)...")
        vault.execute(
            agent="research_agent",
            namespace="openai",
            purpose="embeddings",
            secret_name="OPENAI_API_KEY",
            callback=mock_llm_call,
        )

        # 6. The audit chain should verify.
        print(f"Audit chain valid: {vault.verify_audit_chain()}")


if __name__ == "__main__":
    main()
