#!/usr/bin/env python3
"""Verify the tokens signed by Go (testdata/go_signed.json) with the real Python.

    .venv/bin/python go/internal/captoken/testdata/verify_go_tokens.py

Exits non-zero if any Go-signed token fails Python verification.
"""

import json
import os
import sys

from rgt_vault.hook import HookRequest, TwoFactorHook
from rgt_vault.token import HMACTokenVerifier

HERE = os.path.dirname(os.path.abspath(__file__))
data = json.load(open(os.path.join(HERE, "go_signed.json"), encoding="utf-8"))
key = bytes.fromhex(data["key_hex"])
ver = HMACTokenVerifier(key)
failed = 0

for c in data["v2"]:
    try:
        t = ver.verify(c["token"])
        assert t.agent_id == c["agent_id"], "agent_id"
        assert t.capability == c["capability"], "capability"
        assert t.capability_version == c["capability_version"], "capability_version"
        assert t.context_bindings == (c["context_bindings"] or {}), "bindings"
        print("OK  v2", c["name"], t.token_id)
    except Exception as e:  # noqa: BLE001
        failed += 1
        print("FAIL v2", c["name"], type(e).__name__, e)

for c in data["v1"]:
    # Python's TwoFactorHook accepts the token iff the HMAC uses the shared secret.
    req = HookRequest(operation="read", agent=c["agent"], namespace=c["namespace"], capability_token=c["token"])
    resp = TwoFactorHook(key).consult(req)
    if resp.decision.value == "allow":
        print("OK  v1", c["name"], resp.reason)
    else:
        failed += 1
        print("FAIL v1", c["name"], resp.reason)

sys.exit(1 if failed else 0)
