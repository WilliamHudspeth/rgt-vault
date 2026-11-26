#!/usr/bin/env python3
"""Generate validation_vectors.json from the REAL python/input_validation.py.

Run from the repo root with the project venv (python/ is symlinked as the
``rgt_vault`` package):

    python3 -m venv .venv && .venv/bin/pip install -e '.[server,dev]'
    .venv/bin/python go/internal/validation/testdata/gen_vectors.py

Output: go/internal/validation/testdata/validation_vectors.json (deterministic).
Each case records Python's accept/reject verdict and exact message. Cases with
"known_divergence" are ones where the Go port is deliberately stricter; the Go
test asserts the Go behaviour for those and documents why.
"""

from __future__ import annotations

import json
import platform
import re
import sys
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[3]))  # repo root: rgt_vault -> python/

from rgt_vault import input_validation as iv  # noqa: E402
from rgt_vault.exceptions import ValidationError  # noqa: E402


def run(fn, *args, **kwargs):
    try:
        return {"ok": True, "result": fn(*args, **kwargs)}
    except ValidationError as e:
        return {"ok": False, "error": str(e)}


NAME_CASES = [
    "ok", "my secret", "a.b-c_d", "A1", "x" * 256, "x" * 257, "x" * 255 + " ", "-", ".", "..", " a ",
    "", " ", "   ", "\t", "\n", "\r\n", "\x1c", "\x1f", "\x85", " ", " ", "　",
    "a/b", "a\\b", "a;b", "a|b", "a$b", "$HOME", "`x`", "a'b", 'a"b', "a%20b", "a:b", "a=b", "a@b",
    "é", "日本", "😀", "a\x00b", "a\x7fb", "аbc",  # cyrillic a
    "tab\there", "a\nb", "\nname", "ünï",
    "abc\n", "abc\n\n", "name \n",  # python's `$` accepts one trailing newline
]
NS_CASES = [
    "ok", "prod", "a.b-c_d", "x" * 128, "x" * 129, "has space", "a/b", "a@b", "", " ", "\t", "é",
    "ns\n", "n\ns", "-", "A_1.2-3", " ", "a b", "日本", "x" * 127 + "é",
]
AGENT_CASES = [
    "agent-1", "alice@example.com", "a.b_c-d", "x" * 128, "x" * 129, "has space", "a/b", "", " ", "\t",
    "é", "agent\n", "a\nb", "@", "@@", "a@b@c", "\x1c", "a+b", "svc:1", "日本",
]


def int_cases():
    vals = [
        ("int", 5), ("int", 0), ("int", -1), ("int", 2**31), ("int", 2**63 - 1), ("int", -(2**63)),
        ("int", 2**63), ("int", -(2**63) - 1), ("int", 10**30),
        ("bool", True), ("bool", False), ("float", 5.0), ("float", 0.5), ("float", float("nan")),
        ("str", "5"), ("none", None), ("list", []), ("dict", {}),
    ]
    bounds = [(None, None), (0, None), (None, 10), (1, 100), (-5, 5), (0, 2**63 - 1)]
    out = []
    for kind, v in vals:
        for lo, hi in bounds:
            r = run(iv.validate_int_bound, "limit", v, min_val=lo, max_val=hi)
            enc = repr(v) if kind == "float" else (str(v) if kind == "int" else (v if kind in ("str",) else None))
            if kind == "bool":
                enc = bool(v)
            out.append({"type": kind, "value": enc if kind != "int" else str(v), "min": lo, "max": hi, **r})
    return out


FREE_CASES = [
    # (value, max_len or None for default)
    ("plain text", None), ("Résumé", None), ("é", None), ("x́", None), ("a​b", None),
    ("a‍b", None), ("tab\there", None), ("two\nlines", None), ("\x00", None), ("\x7f", None),
    ("😀", None), ("ok \U0001f600", None), ("thumbs\U0001f44d\U0001f3fd", None), ("❤️", None),
    ("a b", None), ("a b", None), ("a b", None), ("", None), ("͸", None),
    ("﻿", None), ("한", None), ("Å", None), ("ﬁ", None), ("日本語", None),
    ("", None), ("   ", None), ("a/b/c", None), ("price: $5 + 3 = 8 (approx)", None),
    ("x" * 512, None), ("x" * 513, None), ("é" * 512, None), ("é" * 512, None), ("é" * 513, None),
    ("abcde", 5), ("abcdef", 5), ("abcdé", 5), ("ab́cd", 4), ("", 0), ("a", 0),
    ("क्ष", None),  # Devanagari conjunct: contains Mn/Mc marks -> rejected
    ("é", None), ("Å", None), ("Ⅰ", None),  # Roman numeral one (Nl)
    ("½", None), (" ", None), ("‎", None), ("­", None), ("‘quoted’", None),
    ("€100", None), ("∑", None), ("©", None), ("ʰ", None),
]


def free_cases():
    out = []
    for v, ml in FREE_CASES:
        r = run(iv.validate_free_text, v) if ml is None else run(iv.validate_free_text, v, ml)
        out.append({"value": v, "max_len": ml, **r})
    return out


def normalize_cases():
    out = []
    for v in ["é", "Å", "ﬁ", "plain", "x́", "\t"]:
        out.append({"value": v, **run(iv.normalize_unicode, v)})
    return out


REGEX_CASES = [
    (r"^[a-z]+$", "abc"), (r"^[a-z]+$", "abc1"), (r"[a-z]+", "abc1"), (r"[a-z]+", "1abc"), (r"(\d+)-(\d+)", "12-34x"),
    (r"(a)?b", "b"), (r"(a)?b", "ab"), (r"", "anything"), (r"x*", "yyy"), (r"é+", "ééa"),
]


def regex_cases():
    out = []
    for pat, text in REGEX_CASES:
        m = iv.safe_regex_match(re.compile(pat), text)
        out.append(
            {
                "pattern": pat,
                "text": text,
                "match": None if m is None else [m.group(0)] + [g for g in m.groups()],
            }
        )
    return out


def main() -> None:
    data = {
        "_generated_by": "go/internal/validation/testdata/gen_vectors.py (real python/input_validation.py)",
        "_python": platform.python_version(),
        "_unicodedata": unicodedata.unidata_version,
        "name": [{"value": v, **run(iv.validate_name, v)} for v in NAME_CASES],
        "namespace": [{"value": v, **run(iv.validate_namespace, v)} for v in NS_CASES],
        "agent": [{"value": v, **run(iv.validate_agent, v)} for v in AGENT_CASES],
        "int_bound": int_cases(),
        "free_text": free_cases(),
        "normalize": normalize_cases(),
        "regex": regex_cases(),
    }
    out = HERE / "validation_vectors.json"
    out.write_text(json.dumps(data, indent=1, ensure_ascii=True) + "\n")
    n = sum(len(data[k]) for k in ("name", "namespace", "agent", "int_bound", "free_text", "normalize", "regex"))
    print(f"wrote {out}: {n} cases (unicodedata {unicodedata.unidata_version})")


if __name__ == "__main__":
    main()
