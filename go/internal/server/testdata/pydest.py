"""RGT-523 cross-check: the Python line opens a Go-written vault whose audit
log holds DESTINATION_REFUSED rows, with a policy file that carries the new
top-level "destinations:" key and a rule-level "allowed_hosts:" key.

usage: pydest.py VAULT_DIR MASTER_FILE POLICY_FILE
"""
import json
import os
import sys

from rgt_vault.providers.base import MasterSecretProvider
from rgt_vault.vault import VaultManager


class FileMaster(MasterSecretProvider):
    def __init__(self, path):
        self.path = path

    def get_secret(self):
        with open(self.path, "rb") as f:
            return f.read()


def main(vault_dir, master, policy_file):
    with open(policy_file) as f:
        policy = f.read()
    vm = VaultManager(
        db_path=os.path.join(vault_dir, "vault.db"),
        policy_yaml=policy,
        master_provider=FileMaster(master),
    )
    rows = vm.get_audit_log(limit=1000)
    out = {
        "chain": vm.verify_audit_chain(),
        "rules": len(vm.auth.rules),
        "allowed": vm.auth.evaluate("coder", "github", "ci", "read")["allowed"],
        "destination_rows": sum(1 for r in rows if r["action"] == "DESTINATION_REFUSED"),
    }
    print(json.dumps(out))


if __name__ == "__main__":
    main(*sys.argv[1:4])
