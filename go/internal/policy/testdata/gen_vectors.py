#!/usr/bin/env python3
"""Generate policy_vectors.json from the REAL Python implementation.

Run from the repo root with the project venv (python/ is symlinked as the
``rgt_vault`` package, so the code under test is python/auth.py):

    python3 -m venv .venv && .venv/bin/pip install -e '.[server,dev]'
    .venv/bin/python go/internal/policy/testdata/gen_vectors.py

Output: go/internal/policy/testdata/policy_vectors.json (deterministic).
Python is the reference implementation; the Go tests only read the JSON.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import platform
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[3]))  # repo root: rgt_vault -> python/

from rgt_vault.auth import ABACPolicyEngine  # noqa: E402

POLICIES = {
    "list_basic": """\
- effect: allow
  agent: "agent-*"
  namespace: "prod/*"
  purpose: "deploy*"
  action: read
- effect: deny
  agent: "agent-evil"
  namespace: "*"
- effect: allow
  agent: alice
  namespace: dev
  purpose: "*"
  action: "*"
  ttl: 60
""",
    "rules_map_case": """\
rules:
  - effect: ALLOW
    agent: "svc-?"
    action: "read"
  - effect: Deny
    namespace: "secret"
  - effect: allow
    namespace: "pub*"
    purpose: "Report"
""",
    "slash_purpose": """\
- effect: allow
  agent: "*"
  namespace: "*"
  purpose: "ci/*"
  action: read
- effect: allow
  agent: "*"
  namespace: "*"
  purpose: "deploy/[a-c]*"
  action: read
- effect: allow
  agent: "*"
  namespace: "*"
  purpose: "*/prod"
  action: write
- effect: allow
  agent: "bot"
  namespace: "*"
  purpose: "a?b"
  action: "*"
- effect: deny
  agent: "*"
  namespace: "*"
  purpose: "ci/secret*"
  action: "*"
""",
    "deny_after_allow": """\
- effect: allow
  agent: "*"
  namespace: "*"
- effect: deny
  agent: "intern"
  namespace: "finance*"
""",
    "deny_before_allow": """\
- effect: deny
  agent: "intern"
  namespace: "finance*"
- effect: allow
  agent: "*"
  namespace: "*"
""",
    "charclass": """\
- effect: allow
  agent: "[a-c]*"
  namespace: "*"
  action: read
- effect: allow
  agent: "[!a-c]x"
  namespace: "*"
  action: read
- effect: allow
  agent: "*"
  namespace: "n[]]"
  action: write
- effect: allow
  agent: "*"
  namespace: "[!]]z"
  action: write
- effect: allow
  agent: "*"
  namespace: "[a-]1"
  action: delete
- effect: deny
  agent: "*"
  namespace: "[-a]2"
  action: delete
""",
    "unicode_case": """\
- effect: allow
  agent: "Zoë*"
  namespace: "données"
  purpose: "Résumé*"
  action: read
- effect: allow
  agent: "Admin"
  namespace: "*"
  action: "*"
""",
    "no_rules_key": "foo: bar\nbaz: 1\n",
    "empty": "",
    "whitespace_only": "  \n\t\n",
    "comment_only": "# nothing here\n",
    "scalar_doc": "hello\n",
    "empty_list": "[]\n",
    "effects": """\
- effect: permit
  agent: "*"
- effect: "allow "
  agent: "*"
- agent: "*"
- effect: allow
  agent: "ok"
  namespace: "*"
""",
    "ttl_policy": """\
- effect: allow
  agent: "*"
  action: read
  ttl: 120
- effect: allow
  agent: bob
  action: "*"
  ttl: 30
- effect: allow
  agent: bob
  action: read
  ttl: "45"
- effect: allow
  agent: carol
  action: read
  ttl: 0
- effect: allow
  agent: dave
  action: read
  ttl: -5
- effect: allow
  agent: erin
  action: read
  ttl: 2.9
- effect: allow
  agent: frank
  action: read
  ttl: abc
- effect: allow
  agent: gina
  action: read
  ttl: true
- effect: allow
  agent: hank
  action: read
  ttl: ~
- effect: allow
  agent: ivy
  action: read
  ttl: " 7 "
- effect: allow
  agent: jo
  action: read
  ttl: "1_000"
- effect: allow
  agent: kim
  action: read
  ttl: "1__0"
- effect: allow
  agent: lee
  action: read
  ttl: "+12"
- effect: allow
  agent: max
  action: read
  ttl: 99999999999999999999
- effect: allow
  action: "*"
  ttl: 500
- effect: allow
  agent: nina
  ttl: 777
- effect: allow
  agent: "*"
  action: write
""",
    "ttl_order": """\
- effect: allow
  agent: "*"
  action: "*"
  ttl: 1000
- effect: allow
  agent: zed
  action: "*"
  ttl: 200
- effect: allow
  agent: "*"
  action: read
  ttl: 300
- effect: allow
  agent: zed
  action: read
  ttl: 400
""",
    "duplicate_keys": "- effect: allow\n  agent: a\n  agent: b\n",
    "anchors": """\
base: &base
  effect: allow
  namespace: shared
rules:
  - <<: *base
    agent: svc
  - *base
""",
    "json_dump": """\
- effect: allow
  agent: "ünï/*"
  namespace: "a\\"b"
  note: [1, 2.5, 1.0e-7, 1.0e+22, true, null, "x"]
  ttl: 10
""",
    "merge_multi_keys": """\
a: &a {effect: allow}
b: &b {effect: deny}
rules:
  - <<: *a
    <<: *b
""",
    "merge_list": """\
a: &a {effect: allow, agent: first}
b: &b {effect: allow, agent: second}
rules:
  - <<: [*a, *b]
""",
    "merge_explicit_wins": """\
base: &base {effect: allow, agent: "*", namespace: shared}
rules:
  - <<: *base
    effect: deny
    namespace: locked
""",
    "merge_top_level": """\
base: &base
  rules:
    - {effect: allow, agent: alice}
<<: *base
""",
    "json_floats": """\
- effect: allow
  agent: "*"
  floats: [0.0, -0.0, 100.0, 1.5, 0.0001, 1.0e-5, 1.0e+16, 1.0e+15, 9999999999999998.0, 123456789012345678.0,
           1.5e+300, 5.0e-324, 0.1, 2.5e-10, 3.14159, -42.125, .inf, -.inf, .nan, 1234567.0]
  ints: [0, -1, 9223372036854775807, 18446744073709551615]
  strings: ["tab\\there", "nl\\nx", "cr\\ry", "bs\\\\x", "q\\"x", "\\x01\\x1f", "del\\x7f", "\\U0001F600", "é日", "\\b\\f"]
  nested: {a: [1, {b: null}], c: false}
  empty_list: []
  empty_map: {}
""",
}

# Policies Python loads but whose evaluation raises (Go rejects at load).
RAISING_POLICIES = {
    "rule_not_mapping": "- just a string\n",
    "rules_not_list": "rules: 5\n",
    "rules_null": "rules:\n",
    "agent_not_string": "- effect: allow\n  agent: 5\n",
    "agent_null": "- effect: allow\n  agent: ~\n",
}

# Policies that Python's __init__ itself rejects.
LOAD_ERRORS = {
    "bad_yaml": "- effect: allow\n  agent: [unclosed\n",
    "tab_indent": "rules:\n\t- effect: allow\n",
    "two_documents": "- effect: allow\n---\n- effect: deny\n",
    "custom_tag_rule": "- !custom {effect: allow}\n",
    "custom_tag_value": "- {effect: allow, agent: !custom '*'}\n",
    "python_tag": "x: !!python/object:os.system {}\nrules: []\n",
    "merge_scalar_top": "<<: 5\nrules: []\n",
    "merge_null_rule": "- {effect: allow, <<: ~}\n",
    "merge_list_of_scalars": "- {effect: allow, <<: [1]}\n",
}

# (agent, namespace, purpose, action)
CASES = {
    "list_basic": [
        ("agent-1", "prod/db", "deploy-app", "read"),
        ("agent-1", "prod/db", "deploy/app", "read"),
        ("agent-1", "prod/db/x/y", "deploy", "read"),
        ("agent-1", "prod", "deploy", "read"),
        ("agent-1", "prod/db", "deploy", "write"),
        ("agent-evil", "prod/db", "deploy", "read"),
        ("agent-evil", "anything", "x", "write"),
        ("alice", "dev", "whatever/with/slashes", "delete"),
        ("alice", "dev2", "x", "read"),
        ("Alice", "dev", "x", "read"),
        ("agent-1", "PROD/db", "deploy", "read"),
        ("", "", "", ""),
    ],
    "rules_map_case": [
        ("svc-1", "any", "p", "read"),
        ("svc-12", "any", "p", "read"),
        ("svc-1", "secret", "p", "read"),
        ("other", "public", "Report", "read"),
        ("other", "pub/lic", "Report", "write"),
        ("other", "public", "report", "read"),
    ],
    "slash_purpose": [
        ("x", "n", "ci/build", "read"),
        ("x", "n", "ci/", "read"),
        ("x", "n", "ci/a/b/c", "read"),
        ("x", "n", "ci/secret", "read"),
        ("x", "n", "ci/secret/more", "read"),
        ("x", "n", "ci", "read"),
        ("x", "n", "deploy/apple", "read"),
        ("x", "n", "deploy/zebra", "read"),
        ("x", "n", "a/b/prod", "write"),
        ("x", "n", "/prod", "write"),
        ("x", "n", "prod", "write"),
        ("bot", "n", "a/b", "delete"),
        ("bot", "n", "a\nb", "delete"),
        ("bot", "n", "ab", "delete"),
        ("x", "n", "ci/line1\nline2", "read"),
    ],
    "deny_after_allow": [
        ("intern", "finance", "x", "read"),
        ("intern", "finance/q3", "x", "read"),
        ("intern", "hr", "x", "read"),
        ("boss", "finance", "x", "read"),
    ],
    "deny_before_allow": [
        ("intern", "finance", "x", "read"),
        ("intern", "hr", "x", "read"),
    ],
    "charclass": [
        ("alpha", "x", "p", "read"),
        ("beta", "x", "p", "read"),
        ("delta", "x", "p", "read"),
        ("dx", "x", "p", "read"),
        ("ax", "x", "p", "read"),
        ("zz", "n]", "p", "write"),
        ("zz", "n", "p", "write"),
        ("zz", "wz", "p", "write"),
        ("zz", "]z", "p", "write"),
        ("zz", "a1", "p", "delete"),
        ("zz", "-1", "p", "delete"),
        ("zz", "b1", "p", "delete"),
        ("zz", "a2", "p", "delete"),
        ("zz", "-2", "p", "delete"),
    ],
    "unicode_case": [
        ("Zoë", "données", "Résumé 2024", "read"),
        ("Zoë", "données", "Résumé", "read"),
        ("Zoë", "données", "Résumé", "read"),
        ("zoë", "données", "Résumé", "read"),
        ("Admin", "日本語", "x", "anything"),
        ("admin", "日本語", "x", "anything"),
    ],
    "no_rules_key": [("a", "b", "c", "read")],
    "empty": [("a", "b", "c", "read")],
    "whitespace_only": [("a", "b", "c", "read")],
    "comment_only": [("a", "b", "c", "read")],
    "scalar_doc": [("a", "b", "c", "read")],
    "empty_list": [("a", "b", "c", "read")],
    "effects": [
        ("anyone", "ns", "p", "read"),
        ("ok", "ns", "p", "read"),
    ],
    "duplicate_keys": [("a", "n", "p", "read"), ("b", "n", "p", "read")],
    "merge_multi_keys": [("alice", "ns", "p", "read")],
    "merge_list": [("first", "ns", "p", "read"), ("second", "ns", "p", "read"), ("x", "ns", "p", "read")],
    "merge_explicit_wins": [("anyone", "shared", "p", "read"), ("anyone", "locked", "p", "read")],
    "merge_top_level": [("alice", "ns", "p", "read"), ("bob", "ns", "p", "read")],
    "anchors": [("svc", "shared", "p", "read"), ("svc", "other", "p", "read"), ("x", "shared", "p", "read")],
    "json_dump": [("ünï/a", 'a"b', "p", "read"), ("ünï/a", 'a"b', "p", "read")],
    "json_floats": [("anyone", "ns", "p", "read")],
}

LEASE_CASES = {
    "ttl_policy": [
        ("zoe", "read"),
        ("zoe", "write"),
        ("zoe", "other"),
        ("bob", "read"),
        ("bob", "write"),
        ("carol", "read"),
        ("dave", "read"),
        ("erin", "read"),
        ("frank", "read"),
        ("gina", "read"),
        ("hank", "read"),
        ("ivy", "read"),
        ("jo", "read"),
        ("kim", "read"),
        ("lee", "read"),
        ("max", "read"),
        ("nina", "read"),
        ("nina", "write"),
        ("nobody", "delete"),
        ("*", "read"),
    ],
    "ttl_order": [
        ("zed", "read"),
        ("zed", "write"),
        ("other", "read"),
        ("other", "write"),
    ],
    "list_basic": [("alice", "read"), ("alice", "x"), ("agent-1", "read")],
    "empty": [("a", "read")],
}


def policy_error(yaml_text: str):
    try:
        return ABACPolicyEngine(yaml_text), None
    except Exception as e:  # noqa: BLE001 - recording every failure kind
        return None, type(e).__name__


def explain_text(decision: dict) -> str:
    # Verbatim formula of VaultManager.explain (python/vault.py).
    res = "ALLOWED" if decision["allowed"] else "DENIED"
    rule = decision.get("matched_rule")
    rule_str = json.dumps(rule) if rule else "None"
    return f"Access: {res}\nReason: {decision['reason']}\nMatched Rule: {rule_str}"


def gen_cases() -> list:
    out = []
    for name, cases in CASES.items():
        eng, err = policy_error(POLICIES[name])
        assert eng is not None, (name, err)
        for agent, ns, purpose, action in cases:
            d = eng.evaluate(agent, ns, purpose, action)
            out.append(
                {
                    "policy": name,
                    "agent": agent,
                    "namespace": ns,
                    "purpose": purpose,
                    "action": action,
                    "allowed": d["allowed"],
                    "reason": d["reason"],
                    "matched_rule_json": json.dumps(d["matched_rule"]) if d["matched_rule"] is not None else None,
                    "explain": explain_text(d),
                }
            )
    return out


def gen_raising() -> list:
    out = []
    for name, text in RAISING_POLICIES.items():
        eng, err = policy_error(text)
        assert eng is not None, (name, err)
        try:
            eng.evaluate("a", "n", "p", "read")
            raised = None
        except Exception as e:  # noqa: BLE001
            raised = type(e).__name__
        assert raised is not None, name
        out.append({"policy": name, "yaml": text, "python_raises": raised})
    return out


def gen_load_errors() -> list:
    out = []
    for name, text in LOAD_ERRORS.items():
        eng, err = policy_error(text)
        assert eng is None, name
        out.append({"policy": name, "yaml": text, "python_error": err})
    return out


def gen_lease() -> list:
    out = []
    for name, cases in LEASE_CASES.items():
        eng, _ = policy_error(POLICIES[name])
        for agent, cap in cases:
            try:
                ttl = eng.get_lease_ttl(agent, cap)
                err = None
            except Exception as e:  # noqa: BLE001
                ttl, err = None, type(e).__name__
            out.append({"policy": name, "agent": agent, "capability": cap, "ttl": ttl, "python_error": err})
    return out


def gen_hashes() -> list:
    out = []
    for name, text in POLICIES.items():
        h = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16] if text else ""
        out.append({"policy": name, "hash": h})
    return out


# ----- fnmatch corpus -------------------------------------------------------

EDGE_FNMATCH = [
    ("a/b/c", "*"),
    ("a/b/c", "a*c"),
    ("a/b/c", "a?b?c"),
    ("a/b", "a[/]b"),
    ("a/b", "a[!/]b"),
    ("", ""),
    ("", "*"),
    ("", "?"),
    ("a", ""),
    ("abc", "a*"),
    ("abc", "*c"),
    ("abc", "*b*"),
    ("ABC", "abc"),
    ("abc", "ABC"),
    ("a\nb", "a?b"),
    ("a\nb", "a*b"),
    ("\n", "*"),
    ("\n", "?"),
    ("]", "[]]"),
    ("a", "[]]"),
    ("]", "[!]]"),
    ("a", "[!]]"),
    ("!", "[!]"),
    ("a", "[!]"),
    ("[", "[[]"),
    ("[", "["),
    ("[a", "[a"),
    ("a", "[a"),
    ("a", "[]"),
    ("a", "[!"),
    ("-", "[a-]"),
    ("a", "[a-]"),
    ("-", "[-a]"),
    ("b", "[a-c]"),
    ("d", "[a-c]"),
    ("b", "[c-a]"),
    ("c", "[c-a]"),
    ("a", "[c-a]"),
    ("-", "[a-c-e]"),
    ("d", "[a-c-e]"),
    ("e", "[a-c-e]"),
    ("b", "[a-c-e]"),
    ("\\", "[\\]"),
    ("\\", "[a\\]"),
    ("a", "[\\a]"),
    ("^", "[^a]"),
    ("a", "[^a]"),
    ("b", "[^a]"),
    ("^", "[!^]"),
    ("&", "[&]"),
    ("~", "[~]"),
    ("|", "[|]"),
    ("&", "[a&&b]"),
    ("a", "[a&&b]"),
    ("b", "[a||b]"),
    ("a", "[[:alpha:]]"),
    (":", "[[:alpha:]]"),
    ("]", "[[:alpha:]]"),
    ("a]", "[[:alpha:]]"),
    ("b", "[a--b]"),
    ("a", "[a--b]"),
    ("-", "[a--b]"),
    ("c", "[--a]"),
    ("-", "[--a]"),
    ("a", "[--a]"),
    ("é", "[à-ü]"),
    ("e", "[à-ü]"),
    ("é", "?"),
    ("é", "[!a]"),
    ("日", "?"),
    ("日本", "??"),
    ("😀", "?"),
    ("a.b", "a.b"),
    ("axb", "a.b"),
    ("a+b", "a+b"),
    ("(a)", "(a)"),
    ("a|b", "a|b"),
    ("$", "$"),
    ("a$", "a$"),
    ("^a", "^a"),
    ("{a}", "{a}"),
    ("a\\b", "a\\b"),
    ("a\\", "a\\"),
    ("ab", "a\\b"),
    ("abcabc", "*abc"),
    ("abcabcx", "*abc"),
    ("aaa", "a*a*a"),
    ("aa", "a*a*a"),
    ("xaxbx", "*a*b*"),
    ("ab", "a**b"),
    ("ab", "***"),
    ("", "***"),
    ("a", "*?"),
    ("", "*?"),
    ("ab", "?*?"),
    ("a", "?*?"),
    ("a-b", "a[-]b"),
    ("a-b", "a[!-]b"),
    ("axb", "a[!-]b"),
    ("a]b", "a[]]b"),
    ("a[b", "a[[]b"),
    ("abc", "[a-c][a-c][a-c]"),
    ("abd", "[a-c][a-c][a-c]"),
    ("a", "[a-a]"),
    ("b", "[a-a]"),
]

ALPHABET_V = list("ab/-]![^\\&~|é \n.") + ["日", "AB"]
ALPHABET_P = [
    "a",
    "b",
    "/",
    "*",
    "*",
    "?",
    "?",
    "[",
    "]",
    "!",
    "-",
    "^",
    "\\",
    "&",
    "~",
    "|",
    "é",
    " ",
    "\n",
    ".",
    "[a-c]",
    "[!a-c]",
    "[]",
    "日",
]


def fn_result(value: str, pattern: str):
    try:
        return bool(fnmatch.fnmatchcase(value, pattern)), None
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


def gen_fnmatch(n_random: int = 2500) -> list:
    rng = random.Random(20261126)
    pairs = list(EDGE_FNMATCH)
    seen = set(pairs)
    attempts = 0
    while len(pairs) < len(EDGE_FNMATCH) + n_random and attempts < n_random * 20:
        attempts += 1
        pat = "".join(rng.choice(ALPHABET_P) for _ in range(rng.randint(0, 7)))
        # Bias values to be matchable: sometimes derive from the pattern.
        if rng.random() < 0.5:
            val = "".join(rng.choice(ALPHABET_V) for _ in range(rng.randint(0, 6)))
        else:
            val = "".join(rng.choice(ALPHABET_V) if c in "*?[" else c for c in pat)
        if (val, pat) in seen:
            continue
        seen.add((val, pat))
        pairs.append((val, pat))
    out = []
    for val, pat in pairs:
        m, err = fn_result(val, pat)
        out.append({"value": val, "pattern": pat, "match": m, "python_error": err})
    return out


def main() -> None:
    data = {
        "_generated_by": "go/internal/policy/testdata/gen_vectors.py (real python/auth.py + stdlib fnmatch)",
        "_python": platform.python_version(),
        "policies": {**POLICIES},
        "cases": gen_cases(),
        "lease_ttl": gen_lease(),
        "hashes": gen_hashes(),
        "load_errors": gen_load_errors(),
        "raising": gen_raising(),
        "fnmatch": gen_fnmatch(),
    }
    out = HERE / "policy_vectors.json"
    out.write_text(json.dumps(data, indent=1, ensure_ascii=True) + "\n")
    n_err = sum(1 for c in data["fnmatch"] if c["python_error"])
    print(
        f"wrote {out}: {len(data['cases'])} ABAC cases, {len(data['lease_ttl'])} lease cases, "
        f"{len(data['fnmatch'])} fnmatch pairs ({n_err} raise)"
    )


if __name__ == "__main__":
    main()
