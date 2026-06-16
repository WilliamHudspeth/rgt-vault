"""Micro-benchmarks for the vault's security-critical operations.

Run: python benchmarks/bench.py
Numbers are machine-dependent (Argon2id is intentionally expensive). Publish
your own; do not treat the committed sample numbers as guarantees.
"""
import os
import sys
import time
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rgt_vault.vault import VaultManager  # noqa: E402


class _BytesProvider:
    def __init__(self):
        self._s = b"\x05" * 32

    def get_secret(self):
        return self._s

    def rotate_secret(self):
        self._s = os.urandom(32)
        return self._s


def _t(label, fn, repeat=1):
    # warmup
    fn()
    start = time.perf_counter()
    for _ in range(repeat):
        fn()
    elapsed = (time.perf_counter() - start) / repeat
    print(f"{label:<34} {elapsed * 1000:8.2f} ms")
    return elapsed


ALLOW = "rules:\n  - effect: allow\n"


def main():
    with tempfile.TemporaryDirectory() as tmp:
        provider = _BytesProvider()
        db = os.path.join(tmp, "vault.db")

        # Unlock = construct VaultManager (Argon2id + DEK unwrap). Build once so
        # keychain.json exists, then measure the load path.
        VaultManager(db_path=db, policy_yaml=ALLOW, master_provider=provider)
        _t("Unlock vault (Argon2id + unwrap)",
           lambda: VaultManager(db_path=db, policy_yaml=ALLOW, master_provider=provider),
           repeat=5)

        # High rate limit so the benchmark loop isn't throttled.
        vault = VaultManager(db_path=db, policy_yaml=ALLOW, master_provider=provider,
                             rate_limit=10_000_000)
        _t("Set secret (encrypt + insert)",
           lambda: vault.set_secret("k", "v" * 64, agent="a"),
           repeat=50)

        vault.set_secret("read_me", "secret-value", agent="a")
        _t("Lease + decrypt secret",
           lambda: vault.execute("a", "default", "p", "read_me", lambda b: bytes(b)),
           repeat=200)

        _t("Rotate master key (re-wrap KEK)", vault.rotate_master_key, repeat=5)

        # Populate for DEK rotation timing.
        n = 1000
        for i in range(n):
            vault.set_secret(f"bulk{i}", "x" * 64, agent="a")
        start = time.perf_counter()
        vault.rotate_dek()
        print(f"{'Rotate DEK (' + str(n) + ' secrets)':<34} {(time.perf_counter() - start) * 1000:8.2f} ms")


if __name__ == "__main__":
    main()
