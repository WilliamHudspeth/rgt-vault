"""Generate keychain.json compat fixtures with the real Python HardenedDEKManager.

Run from the repo root with the project venv:

    .venv/bin/python go/internal/keychain/testdata/gen_fixtures.py

Writes go/internal/keychain/testdata/py/<case>/{keychain.json,manifest.json}
plus selftest.json. Fixtures are static: once checked in they outlive python/.
The DEK and salt are random (os.urandom inside HardenedDEKManager); the
manifest records the DEK the Python code returned so Go can assert equality.
"""

import json
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from rgt_vault.keychain import (
    AES256GCMWrapper,
    HardenedDEKManager,
    KeyDerivationOrchestrator,
    MasterSecret,
)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "py")

SMALL = dict(memory_cost=1024, time_cost=1, parallelism=1)

CASES = [
    # name, master, vault_id, epoch, params, rewrap_to_epoch
    ("small", bytes(range(32)), "0b9f4c1e-7d2a-4e8b-9c3f-1a2b3c4d5e6f", 1, SMALL, None),
    ("small_par4", b"\xa5" * 32, "vault-par4", 2, dict(memory_cost=2048, time_cost=2, parallelism=4), None),
    # A master of non-32 length (macOS keychain provider returns utf-8 bytes).
    ("small_textmaster", b"correct horse battery staple", "text-master-vault", 1, SMALL, None),
    # initialize at epoch 1 then rewrap (rotate_master_key path) to epoch 3.
    ("small_rewrapped", bytes(range(100, 132)), "rewrap-vault", 1, SMALL, 3),
    ("default", bytes(range(200, 232)), "4f1d2c3b-aaaa-bbbb-cccc-0123456789ab", 1, {}, None),
]


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    for name, master_bytes, vault_id, epoch, params, rewrap_epoch in CASES:
        d = os.path.join(OUT, name)
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "keychain.json")
        if os.path.exists(path):
            os.remove(path)
        master = MasterSecret(master_bytes)
        mgr = HardenedDEKManager(path)
        dek = mgr.initialize_dek(master, vault_id, epoch, **params)
        final_epoch = epoch
        if rewrap_epoch is not None:
            mgr.rewrap_dek(master, vault_id, rewrap_epoch, **params)
            final_epoch = rewrap_epoch
        # Sanity: Python can load what it wrote.
        assert HardenedDEKManager(path).load_dek(master, vault_id, final_epoch) == dek
        # A secret encrypted with the DEK the way vault.py does it
        # (crypto.encrypt: nonce||ct||tag, AAD vault_id:ns:name).
        nonce = bytes(12)
        aad = f"{vault_id}:default:api_key".encode()
        ct = nonce + AESGCM(dek).encrypt(nonce, b"sk-test-plaintext", aad)
        manifest = {
            "master_hex": master_bytes.hex(),
            "vault_id": vault_id,
            "epoch": final_epoch,
            "dek_hex": dek.hex(),
            "secret_aad": aad.decode(),
            "secret_ciphertext_hex": ct.hex(),
            "secret_plaintext": "sk-test-plaintext",
        }
        with open(os.path.join(d, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")

    # run_crypto_selftest known-answer (the Python self-test has no KAT; we
    # record the deterministic ciphertext so Go's SelfTest can pin it).
    orch = KeyDerivationOrchestrator(memory_cost=1024, time_cost=1, parallelism=1)
    kmat = orch.derive_wrapping_key_and_nonce(MasterSecret(b"selftest_master"), b"selftest_salt" * 4, b"test_context")
    ct = AES256GCMWrapper().wrap(b"test_dek", kmat.key, kmat.nonce, b"test_aad")
    with open(os.path.join(OUT, "selftest.json"), "w") as f:
        json.dump({"key_hex": kmat.key.hex(), "nonce_hex": kmat.nonce.hex(), "ciphertext_hex": ct.hex()}, f, indent=2)
        f.write("\n")
    print("wrote fixtures to", OUT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
