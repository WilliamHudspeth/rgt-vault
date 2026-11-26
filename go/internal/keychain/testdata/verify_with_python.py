"""Check that Go-written keychain.json files load in the Python reference.

Usage (from the repo root, with the project venv):

    .venv/bin/python -I go/internal/keychain/testdata/verify_with_python.py \
        go/internal/keychain/testdata/go/*

Each argument is a directory holding keychain.json and manifest.json
(master_hex, vault_id, epoch, dek_hex). For each one this asserts that:
  * HardenedDEKManager.load_dek returns the manifest DEK;
  * the file bytes equal json.dumps(json.load(file), indent=2), i.e. Go wrote
    exactly what Python's json.dump(indent=2) would have written;
  * a wrong epoch raises the "Rollback attack detected" ValueError.
Exits non-zero on the first failure. TestPythonLoadsGoFixtures runs it.
"""

import json
import os
import sys

from rgt_vault.keychain import HardenedDEKManager, MasterSecret


def check(d: str) -> None:
    with open(os.path.join(d, "manifest.json")) as f:
        m = json.load(f)
    path = os.path.join(d, "keychain.json")
    with open(path, "rb") as f:
        raw = f.read()
    assert raw == json.dumps(json.loads(raw), indent=2).encode(), f"{d}: bytes differ from json.dump(indent=2)"

    master = MasterSecret(bytes.fromhex(m["master_hex"]))
    dek = HardenedDEKManager(path).load_dek(master, m["vault_id"], m["epoch"])
    assert dek == bytes.fromhex(m["dek_hex"]), f"{d}: DEK mismatch"

    try:
        HardenedDEKManager(path).load_dek(master, m["vault_id"], m["epoch"] + 1)
    except ValueError as e:
        assert "Rollback attack detected" in str(e), e
    else:
        raise AssertionError(f"{d}: rollback not detected")
    print(f"OK {d} (epoch {m['epoch']}, DEK matches)")


def main(argv: list) -> int:
    if not argv:
        print(__doc__)
        return 2
    for d in argv:
        check(d)
    print(f"python verified {len(argv)} Go-written keychain(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
