#!/usr/bin/env python3
"""Generate TOTP vectors from the repo's real python/totp.py for the Go tests.

    .venv/bin/python go/internal/totp/testdata/gen_vectors.py

Writes go/internal/totp/testdata/vectors.json (secrets here are public test
values, never real ones).
"""

import json
import os

from rgt_vault import totp

HERE = os.path.dirname(os.path.abspath(__file__))

SECRETS = [
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",  # RFC "12345678901234567890"
    "JBSWY3DPEHPK3PXP",  # padded-length 16 chars
    "mfrg gzdf mzti",  # lowercase + spaces (authenticator-app style)
    "  ONSWG4TFOQ  ",  # surrounding whitespace, short: pads to 8
    "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43UOV3HO6DZPI",  # 42 chars
    "ONSWG4TFOQ======",  # explicit, correct padding
]
TIMES = [59, 1111111109, 1234567890, 1700000000, 1700000029, 1700000030, 2000000000, 4102444800]


def attempt(fn):
    try:
        return {"ok": fn()}
    except Exception as e:  # noqa: BLE001
        return {"error": type(e).__name__}


def main():
    out = {}
    out["generate"] = []
    for secret in SECRETS:
        for algo in ("SHA1", "SHA256", "SHA512"):
            for digits in (6, 7, 8):
                for period in (30, 60):
                    for ts in TIMES:
                        out["generate"].append(
                            {
                                "secret": secret,
                                "algorithm": algo,
                                "digits": digits,
                                "period": period,
                                "time": ts,
                                "code": totp.generate(secret, timestamp=ts, digits=digits, period=period, algorithm=algo),
                            }
                        )

    # verify: skew handling and junk codes
    base_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    ts = 1700000000
    out["verify"] = []
    cases = []
    for step_off in (-3, -2, -1, 0, 1, 2, 3):
        code = totp.generate(base_secret, timestamp=ts + 30 * step_off)
        for window in (0, 1, 2):
            cases.append((base_secret, code, ts, window, "SHA1", 6, 30))
    good = totp.generate(base_secret, timestamp=ts)
    for junk in ["", " ", "12345", "1234567", "abcdef", "12 3456", " " + good + " ", good + "\n", "-" + good[1:], "+" + good[1:], good[:-1] + "x", "0" * 6, "٣" * 6, "²" * 6]:
        cases.append((base_secret, junk, ts, 1, "SHA1", 6, 30))
    cases.append(("!!!notbase32!!!", good, ts, 1, "SHA1", 6, 30))
    cases.append(("", good, ts, 1, "SHA1", 6, 30))
    cases.append(("A", good, ts, 1, "SHA1", 6, 30))
    for algo, digits, period in (("SHA256", 8, 30), ("SHA512", 7, 60)):
        c = totp.generate(base_secret, timestamp=ts, digits=digits, period=period, algorithm=algo)
        cases.append((base_secret, c, ts, 1, algo, digits, period))
        cases.append((base_secret, c, ts + period, 1, algo, digits, period))
        cases.append((base_secret, c, ts + 2 * period, 1, algo, digits, period))
    for secret, code, t, window, algo, digits, period in cases:
        res = attempt(
            lambda s=secret, c=code, ts_=t, w=window, a=algo, d=digits, p=period: totp.verify(
                s, c, timestamp=ts_, window=w, algorithm=a, digits=d, period=p
            )
        )
        out["verify"].append({"secret": secret, "code": code, "time": t, "window": window, "algorithm": algo, "digits": digits, "period": period, "python": res})

    # replay-guarded verifier: sequences of (offset_seconds, which code) at fixed times
    out["replay"] = []
    seqs = {
        "basic-reuse": [(0, 0), (0, 0)],
        "next-step-after-use": [(0, 0), (30, 30)],
        "older-step-after-newer": [(30, 30), (0, 0)],
        "skew-minus-then-current": [(0, -30), (0, 0)],
        "skew-plus-then-current": [(0, 30), (0, 0)],
        "skew-plus-then-minus": [(0, 30), (0, -30)],
        "wrong-code-does-not-consume": [(0, "000000"), (0, 0), (0, 0)],
        "far-step": [(0, 300), (0, 0)],
        "two-steps-apart": [(0, 0), (60, 60), (60, 60)],
    }
    for name, seq in seqs.items():
        g = totp.ReplayGuardedVerifier(base_secret)
        steps = []
        for now_off, which in seq:
            now = ts + now_off
            code = which if isinstance(which, str) else totp.generate(base_secret, timestamp=ts + which)
            steps.append({"now": now, "code": code, "python": g(code, timestamp=now)})
        out["replay"].append({"name": name, "secret": base_secret, "steps": steps})

    # provisioning URIs
    out["uri"] = []
    uri_cases = [
        ("JBSWY3DPEHPK3PXP", "alice", {}),
        ("JBSWY3DPEHPK3PXP", "alice@example.com", {"issuer": "ACME Co"}),
        ("JBSWY3DPEHPK3PXP", "böb/slash:colon?q=1&x#frag %", {"issuer": "rgt vault/prod+1"}),
        ("JBSWY3DPEHPK3PXP", "日本語 \U0001f600", {"issuer": "été"}),
        ("JBSWY3DPEHPK3PXP", "a~b_c-d.e", {"digits": 8, "period": 60, "algorithm": "SHA256"}),
        ("JBSWY3DPEHPK3PXP", "", {"issuer": ""}),
    ]
    for secret, account, kw in uri_cases:
        out["uri"].append({"secret": secret, "account": account, "kwargs": kw, "uri": totp.provisioning_uri(secret, account, **kw)})

    # base32 decode acceptance (via generate so the key is exercised)
    out["secret_decode"] = []
    for s in ["JBSWY3DPEHPK3PXP", "jbswy3dpehpk3pxp", "JBSW Y3DP EHPK 3PXP", "JBSWY3DPEHPK3PX", "JBSWY3D", "JBSWY3DPEHPK3PXP======", "JBSWY3DPEHPK3PXP\nJBSWY3DP", "JBSWY3DP\t", "JBSWY3DP\tJBSWY3DP", "AAAAAAAA", "A", "1", "JBSWY3DPEHPK3PX1", "", "   "]:
        out["secret_decode"].append({"secret": s, "python": attempt(lambda s=s: totp.generate(s, timestamp=1700000000))})

    with open(os.path.join(HERE, "vectors.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")
    print("wrote", {k: len(v) for k, v in out.items()})


if __name__ == "__main__":
    main()
