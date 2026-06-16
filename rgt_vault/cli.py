import argparse
import sys
from pathlib import Path

from rgt_vault.exceptions import VaultError
from rgt_vault.vault import VaultManager


def main():
    parser = argparse.ArgumentParser(description="Agent Vault CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Set command
    set_parser = subparsers.add_parser("set", help="Store a secret")
    set_parser.add_argument("name", help="Secret name")
    set_parser.add_argument("value", help="Secret value")

    # Simulate command
    sim_parser = subparsers.add_parser("simulate", help="Simulate a policy evaluation")
    sim_parser.add_argument("--policy", required=True, help="Path to policy YAML")
    sim_parser.add_argument("--agent", required=True, help="Agent identity")
    sim_parser.add_argument("--namespace", required=True, help="Namespace")
    sim_parser.add_argument("--purpose", required=True, help="Purpose")
    sim_parser.add_argument("--action", default="read", choices=["read", "write"], help="Action (default: read)")

    # Fingerprint command
    fp_parser = subparsers.add_parser("fingerprint", help="Get secret fingerprint")
    fp_parser.add_argument("name", help="Secret name")

    args = parser.parse_args()

    try:
        if args.command == "set":
            vault = VaultManager()
            vault.set_secret(args.name, args.value)
            print(f"Secret '{args.name}' stored successfully.")
            
        elif args.command == "simulate":
            policy_text = Path(args.policy).read_text()
            # Policy simulation does not touch secrets, so evaluate the engine
            # directly without requiring a master-secret provider.
            from rgt_vault.auth import ABACPolicyEngine
            engine = ABACPolicyEngine(policy_text)
            decision = engine.evaluate(args.agent, args.namespace, args.purpose, action=args.action)
            print("ALLOWED" if decision["allowed"] else "DENIED")
            print(f"Reason: {decision['reason']}")
                
        elif args.command == "fingerprint":
            vault = VaultManager()
            fp = vault.get_fingerprint(args.name)
            print(f"{args.name}\nFingerprint: {fp}")

    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
