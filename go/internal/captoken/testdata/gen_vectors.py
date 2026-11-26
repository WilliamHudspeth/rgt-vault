#!/usr/bin/env python3
"""Generate Python-signed capability-token vectors for the Go captoken tests.

Run from the repo root with the project venv (the repo's real Python is the
reference implementation):

    .venv/bin/python go/internal/captoken/testdata/gen_vectors.py

Writes go/internal/captoken/testdata/vectors.json. The key below is a public
test key. All tokens use a far-future exp (2100-01-01) so they stay valid.
"""

import base64
import hashlib
import hmac
import json
import os
import time
from unittest import mock

from rgt_vault import hook as hookmod
from rgt_vault import token as tokmod
from rgt_vault.hook import HookRequest, TwoFactorHook

HERE = os.path.dirname(os.path.abspath(__file__))
KEY = bytes(range(32))  # public test key 00 01 .. 1f
FAR_FUTURE = 4102444800  # 2100-01-01T00:00:00Z
TTL = 3600
SIGN_NOW = FAR_FUTURE - TTL  # fixed "now" when signing so exp == FAR_FUTURE


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def env(payload: bytes, sig: bytes) -> str:
    return b64u(payload) + "." + b64u(sig)


def mac(payload: bytes, key: bytes = KEY) -> bytes:
    return hmac.new(key, payload, hashlib.sha256).digest()


def signed(payload: bytes) -> str:
    return env(payload, mac(payload))


def pj(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def outcome(verifier, token):
    try:
        t = verifier.verify(token)
    except tokmod.TokenError as e:
        return {"error": type(e).__name__}
    except Exception as e:  # not a TokenError (python bug-ish): record it
        return {"error": "UNCAUGHT:" + type(e).__name__}
    return {
        "ok": True,
        "agent_id": t.agent_id,
        "capability": t.capability,
        "capability_version": t.capability_version,
        "context_bindings": t.context_bindings,
        "expires_at": t.expires_at,
        "token_id": t.token_id,
    }


def main():
    verifier = tokmod.HMACTokenVerifier(KEY)
    out = {
        "key_hex": KEY.hex(),
        "sign_now": SIGN_NOW,
        "far_future": FAR_FUTURE,
        "ttl": TTL,
    }

    # ---- positive: signed by Python's HMACTokenVerifier.sign -------------
    sign_cases = [
        ("basic", "research-agent", "github.read_repo", 1, {"repo": "org/research"}),
        ("no-bindings", "a", "secrets.echo", 1, None),
        ("version-7", "agent-7", "x.y", 7, {}),
        ("html-chars", "a<b>&c", "cap.<>&'\"", 2, {"q": "<script>alert(1)</script>&x=y"}),
        ("unicode", "héllo ☃", "café.read", 1, {"name": "日本語", "e": "\U0001f600 emoji"}),
        ("controls-and-del", "a\x00b\x1fc\x7fd", "c\n\r\t\b\f\\\"", 1, {"k": "\x01\x02\x7f  ﻿"}),
        ("key-order", "z", "z.z", 1, {"b": 1, "a": 2, "é": 3, "Z": 4, "\U0001f600": 5, "￿": 6, "": 7}),
        (
            "number-zoo",
            "n",
            "n.n",
            1,
            {
                "int": 42,
                "neg": -17,
                "zero": 0,
                "big": 2**63,
                "bigger": 2**70,
                "f1": 1.0,
                "f2": 0.1,
                "f3": 1e-05,
                "f4": 1e16,
                "f5": 1.5e300,
                "f6": 123456.789,
                "f7": -0.0,
                "f8": 1e15,
                "f9": 0.0001,
                "f10": 5e-324,
                "f11": 1.7976931348623157e308,
                "f12": 100.0,
                "f13": 1234567890123456.0,
            },
        ),
        (
            "nested",
            "n",
            "n.n",
            3,
            {"t": True, "f": False, "n": None, "l": [1, "two", [3.5, None], {"x": {"y": []}}], "o": {"b": {}, "a": [True]}},
        ),
    ]
    out["signed"] = []
    for name, agent, cap, ver, binds in sign_cases:
        with mock.patch.object(tokmod.time, "time", return_value=float(SIGN_NOW)):
            tok = verifier.sign(agent, cap, ver, binds, ttl_seconds=TTL)
        payload = base64.urlsafe_b64decode(tok.split(".")[0] + "==")
        res = outcome(verifier, tok)
        assert res.get("ok"), (name, res)
        out["signed"].append(
            {
                "name": name,
                "agent_id": agent,
                "capability": cap,
                "capability_version": ver,
                "context_bindings": binds,
                "ttl": TTL,
                "token": tok,
                "payload": payload.decode("ascii"),
                "token_id": res["token_id"],
            }
        )

    # ---- adversarial/edge tokens: Python's verdict recorded -----------------
    def base(**over):
        d = {"v": 2, "agent_id": "a", "capability": "c", "capability_version": 1, "context_bindings": {}, "exp": FAR_FUTURE}
        d.update(over)
        return d

    def drop(d, k):
        d = dict(d)
        d.pop(k)
        return d

    raw = []  # (name, token, go_strict)  go_strict: Go intentionally stricter
    raw.append(("expired", signed(pj(base(exp=1))), False))
    raw.append(("exp-zero-never-expires", signed(pj(base(exp=0))), False))
    raw.append(("exp-negative-never-expires", signed(pj(base(exp=-5))), False))
    raw.append(("exp-float-integral", signed(pj(base(exp=float(FAR_FUTURE)))), False))
    raw.append(("version-3", signed(pj(base(v=3))), False))
    raw.append(("version-missing", signed(pj(drop(base(), "v"))), False))
    raw.append(("missing-agent", signed(pj(drop(base(), "agent_id"))), False))
    raw.append(("missing-capability", signed(pj(drop(base(), "capability"))), False))
    raw.append(("missing-capability-version", signed(pj(drop(base(), "capability_version"))), False))
    raw.append(("missing-exp", signed(pj(drop(base(), "exp"))), False))
    raw.append(("bindings-missing-key-ok", signed(pj(drop(base(), "context_bindings"))), False))
    raw.append(("bindings-null", signed(pj(base(context_bindings=None))), False))
    raw.append(("bindings-false", signed(pj(base(context_bindings=False))), False))
    raw.append(("bindings-zero", signed(pj(base(context_bindings=0))), False))
    raw.append(("bindings-empty-string", signed(pj(base(context_bindings=""))), False))
    raw.append(("bindings-empty-list", signed(pj(base(context_bindings=[]))), False))
    raw.append(("bindings-nonempty-list", signed(pj(base(context_bindings=[1]))), False))
    raw.append(("bindings-true", signed(pj(base(context_bindings=True))), False))
    raw.append(("bindings-string", signed(pj(base(context_bindings="x"))), False))
    raw.append(("payload-array", signed(b"[1,2]"), False))
    raw.append(("payload-not-json", signed(b"not json"), False))
    raw.append(("payload-trailing-data", signed(pj(base()) + b" {}"), False))
    raw.append(("payload-invalid-utf8", signed(b'{"v":2,"agent_id":"\xff"}'), False))
    raw.append(("payload-leading-whitespace", signed(b"  " + pj(base())), False))
    raw.append(("payload-non-canonical-key-order", signed(json.dumps(base()).encode()), False))
    raw.append(("payload-duplicate-key-last-wins", signed(b'{"v":2,"agent_id":"x","agent_id":"a","capability":"c","capability_version":1,"exp":%d}' % FAR_FUTURE), False))
    good = signed(pj(base()))
    p, s = good.split(".")
    raw.append(("bad-signature", p + "." + b64u(mac(b"other")), False))
    raw.append(("wrong-key", env(pj(base()), mac(pj(base()), bytes(32))), False))
    raw.append(("tampered-payload", b64u(pj(base(agent_id="evil"))) + "." + s, False))
    raw.append(("no-dot", p, False))
    raw.append(("three-parts", good + ".x", False))
    raw.append(("empty-token", "", False))
    raw.append(("empty-sig", p + ".", False))
    raw.append(("empty-payload", "." + s, False))
    raw.append(("only-dot", ".", False))
    raw.append(("bad-base64", "!!!!." + s, False))
    # Python is lenient about base64 padding / alphabet; Go rejects. Recorded
    # so the test documents the deliberate divergence.
    raw.append(("padded-base64", p + "=" * (-len(p) % 4) + "." + s, True))
    raw.append(("newline-in-base64", p[:5] + "\n" + p[5:] + "." + s, False))
    raw.append(("v-as-string", signed(pj(base(v="2"))), True))
    raw.append(("capability-version-as-string", signed(pj(base(capability_version="1"))), True))
    raw.append(("agent-id-as-number", signed(pj(base(agent_id=5))), True))
    raw.append(("exp-as-string", signed(pj(base(exp=str(FAR_FUTURE)))), True))
    raw.append(("exp-float-fraction", signed(pj(base(exp=FAR_FUTURE + 0.5))), True))
    out["edge"] = []
    for name, tok, strict in raw:
        res = outcome(verifier, tok)
        out["edge"].append({"name": name, "token": tok, "python": res, "go_strict_reject": strict})

    # ---- check_context verdicts ------------------------------------------
    ctx_cases = [
        ({"repo": "org/r"}, {"repo": "org/r"}),
        ({"repo": "org/r"}, {"repo": "org/r", "extra": 1}),
        ({"repo": "org/r"}, {"repo": "other"}),
        ({"repo": "org/r"}, {}),
        ({}, {"anything": 1}),
        ({"n": 1}, {"n": 1.0}),
        ({"n": 1.0}, {"n": 1}),
        ({"n": 1}, {"n": 2}),
        ({"l": [1, 2]}, {"l": [1, 2]}),
        ({"l": [1, 2]}, {"l": [2, 1]}),
        ({"o": {"a": 1}}, {"o": {"a": 1}}),
        ({"o": {"a": 1}}, {"o": {"a": 1, "b": 2}}),
        ({"s": "x"}, {"s": 1}),
        ({"z": None}, {"z": None}),
        ({"z": None}, {}),
        ({"b": True}, {"b": True}),
        ({"b": True}, {"b": False}),
    ]
    out["context"] = []
    for binds, reqctx in ctx_cases:
        t = tokmod.CapabilityV2Token("a", "cap", 1, binds, FAR_FUTURE, "x")
        try:
            t.check_context(reqctx)
            ok = True
        except tokmod.TokenBindingError:
            ok = False
        out["context"].append({"bindings": binds, "request": reqctx, "python_ok": ok})
    # Python treats True == 1; Go deliberately does not (fail closed).
    t = tokmod.CapabilityV2Token("a", "cap", 1, {"n": 1}, FAR_FUTURE, "x")
    t.check_context({"n": True})  # accepted by Python
    out["context_bool_equals_number_python_ok"] = True

    # ---- v1 tokens (python/hook.py) ---------------------------------------
    hook = TwoFactorHook(KEY)
    out["v1"] = []
    v1_cases = [
        ("basic", "agent-1", "ns", ["write", "read"], 1700000000, FAR_FUTURE, "0123456789abcdef0123456789abcdef"),
        ("wildcards", "agent-2", "*", ["*"], 1700000000, FAR_FUTURE, "ffffffffffffffffffffffffffffffff"),
        ("unicode", "héllo<&>", "nés\U0001f600", ["réad"], 1700000000, FAR_FUTURE, "aa" * 16),
        ("expired", "agent-1", "ns", ["read"], 1700000000, 1700000060, "bb" * 16),
        ("not-yet-valid", "agent-1", "ns", ["read"], FAR_FUTURE - 10, FAR_FUTURE, "cc" * 16),
        ("empty-caps", "agent-1", "ns", [], 1700000000, FAR_FUTURE, "dd" * 16),
    ]
    for name, agent, ns, caps, iat, exp, tid in v1_cases:
        tk = hookmod.CapabilityToken(agent=agent, namespace=ns, capabilities=caps, issued_at=iat, expires_at=exp, token_id=tid)
        placeholder = tk.to_compact()  # what Python really emits: HMAC with an EMPTY key
        with mock.patch.object(hookmod, "_sign", lambda payload, _k: mac(payload)):
            good_tok = tk.to_compact()  # same code path, signed with the shared secret
        entry = {
            "name": name,
            "agent": agent,
            "namespace": ns,
            "capabilities": caps,
            "issued_at": iat,
            "expires_at": exp,
            "token_id": tid,
            "to_compact_empty_key": placeholder,
            "to_compact_signed": good_tok,
            "hook": {},
        }
        for label, t_ in (("signed", good_tok), ("empty_key", placeholder)):
            for op, req_ns, req_agent in (("read", ns, agent), ("write", ns, agent), ("delete", ns, agent), ("read", "other-ns", agent), ("read", ns, "intruder")):
                req = HookRequest(operation=op, agent=req_agent, namespace=req_ns, capability_token=t_)
                resp = TwoFactorHook(KEY).consult(req)  # fresh hook: empty replay cache
                entry["hook"][f"{label}|{op}|{req_ns}|{req_agent}"] = {"decision": resp.decision.value, "reason": resp.reason}
        out["v1"].append(entry)

    # dispatch peek: which verifier would TwoFactorHook.consult pick?
    out["format_peek"] = []
    v2tok = out["signed"][0]["token"]
    v1tok = out["v1"][0]["to_compact_signed"]
    for name, tok in [("v2", v2tok), ("v1", v1tok), ("garbage-payload", "e30.x"), ("not-base64", "***.x"), ("v-as-2-float", signed(pj(base(v=2.0))))]:
        parts = tok.split(".", 1)
        try:
            peek = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)).decode("utf-8"))
        except Exception:
            peek = {}
        fmt = 2 if isinstance(peek, dict) and int(peek.get("v", 0)) == 2 else 1
        out["format_peek"].append({"name": name, "token": tok, "format": fmt})

    with open(os.path.join(HERE, "vectors.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")
    print("wrote vectors.json:", len(out["signed"]), "signed,", len(out["edge"]), "edge,", len(out["v1"]), "v1")


if __name__ == "__main__":
    main()
