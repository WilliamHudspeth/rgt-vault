"""Tests for the rgt-vault CLI.

The CLI's ``--provider keyring`` default is **mocked** in every test: the real
``KeyringProvider`` writes a new entry to the OS Secret Service / Credential
Manager on first call, which would pollute the developer's keyring and break
hermetic CI runs. We use a stub provider that mimics the production behavior
without side effects, then drive the CLI by patching its ``KeyringProvider``
import to the stub.
"""
import io
import os
import sys

import pytest


class _StubKeyringProvider:
    """In-memory replacement for ``KeyringProvider`` (no OS keyring writes).

    Uses a class-level ``_SECRET`` so that state persists across instances,
    matching the real ``KeyringProvider`` (and the real OS keyring) where a
    rotation changes what ``get_secret`` returns on every subsequent call.
    """

    _INITIAL = os.environ.get("RGT_STUB_INITIAL", "B").encode() * 32
    _ROTATED = os.environ.get("RGT_STUB_ROTATED", "C").encode() * 32
    _SECRET = _INITIAL

    def get_secret(self):
        from rgt_vault.keychain import MasterSecret
        return MasterSecret(self._SECRET)

    def rotate_secret(self):
        from rgt_vault.keychain import MasterSecret
        type(self)._SECRET = self._ROTATED
        return MasterSecret(self._SECRET)


@pytest.fixture
def policy_file(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(
        "rules:\n"
        "  - effect: allow\n"
        "    agent: cli\n"
        "    namespace: default\n"
        "    action: '*'\n"
    )
    return p


def _run_cli_inproc(monkeypatch, args, stdin_payload: bytes = b""):
    """In-process CLI runner: capture stdout/stderr, patch KeyringProvider.

    Redirects stdout/stderr to two local lists (one for each stream) and
    restores at the end. Independent of pytest's capture mode. ``stdin_payload``
    is exposed via ``sys.stdin`` for the duration of the call (used by
    the P1-1 audit fix where ``set`` reads the secret value from stdin).
    """
    from rgt_vault import cli
    monkeypatch.setattr(cli, "KeyringProvider", _StubKeyringProvider)
    monkeypatch.setattr("sys.argv", ["rgt-vault", *args])
    out, err = [], []

    class _Stream:
        def __init__(self, sink):
            self._sink = sink
        def write(self, s):
            self._sink.append(s)
        def flush(self):
            pass

    real_stdout, real_stderr, real_stdin = sys.stdout, sys.stderr, sys.stdin
    sys.stdout = _Stream(out)
    sys.stderr = _Stream(err)
    # StringIO so ``sys.stdin.read()`` returns ``str`` (matches production
    # text-mode stdin). The vault CLI normalizes bytes-vs-str internally.
    sys.stdin = io.StringIO(
        stdin_payload.decode("utf-8") if isinstance(stdin_payload, bytes) else stdin_payload
    )
    try:
        rc = cli.main()
    except SystemExit as e:
        rc = e.code
    finally:
        sys.stdout = real_stdout
        sys.stderr = real_stderr
        sys.stdin = real_stdin
    return rc, "".join(out), "".join(err)


# ------------------------------------------------------------------
# Help / argument parsing
# ------------------------------------------------------------------

def test_help_lists_all_subcommands(monkeypatch, capsys):
    from rgt_vault import cli
    monkeypatch.setattr(cli, "KeyringProvider", _StubKeyringProvider)
    monkeypatch.setattr("sys.argv", ["rgt-vault", "--help"])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 0
    out = capsys.readouterr().out
    for sub in ("set", "get", "list", "revoke", "simulate", "fingerprint", "rotate", "verify-audit", "audit"):
        assert sub in out


# ------------------------------------------------------------------
# simulate (pure logic, no vault needed)
# ------------------------------------------------------------------

def test_simulate_allow(monkeypatch, tmp_path):
    policy = tmp_path / "p.yaml"
    policy.write_text("rules:\n  - effect: allow\n    agent: alice\n    namespace: dev\n    action: read\n")
    rc, out, _ = _run_cli_inproc(monkeypatch, [
        "simulate", "--policy", str(policy),
        "--agent", "alice", "--namespace", "dev", "--purpose", "p", "--action", "read",
    ])
    assert rc == 0
    assert "ALLOWED" in out
    assert "Allow rule matched" in out


def test_simulate_default_deny(monkeypatch, tmp_path):
    policy = tmp_path / "p.yaml"
    policy.write_text("rules:\n  - effect: allow\n    agent: alice\n    namespace: dev\n    action: read\n")
    rc, out, _ = _run_cli_inproc(monkeypatch, [
        "simulate", "--policy", str(policy),
        "--agent", "mallory", "--namespace", "dev", "--purpose", "p", "--action", "read",
    ])
    assert rc == 0
    assert "DENIED" in out
    assert "default deny" in out


def test_simulate_deny_beats_allow(monkeypatch, tmp_path):
    policy = tmp_path / "p.yaml"
    policy.write_text(
        "rules:\n"
        "  - effect: allow\n    agent: a\n    namespace: prod\n    action: read\n"
        "  - effect: deny\n    namespace: prod\n"
    )
    rc, out, _ = _run_cli_inproc(monkeypatch, [
        "simulate", "--policy", str(policy),
        "--agent", "a", "--namespace", "prod", "--purpose", "p", "--action", "read",
    ])
    assert rc == 0
    assert "DENIED" in out
    assert "Explicit deny" in out


# ------------------------------------------------------------------
# set + get + list + revoke (uses real keychain.json, mocked keyring)
# ------------------------------------------------------------------

def test_set_and_get_roundtrip(monkeypatch, tmp_path, policy_file):
    db = tmp_path / "v.db"
    # set (P1-1 audit fix: value via stdin, not argv)
    rc, out, _ = _run_cli_inproc(
        monkeypatch,
        [
            "--db", str(db), "--policy", str(policy_file),
            "set", "MY_KEY", "-",
            "--namespace", "default", "--agent", "cli", "--purpose", "test",
        ],
        stdin_payload=b"super-secret\n",
    )
    assert rc == 0
    assert "MY_KEY" in out
    assert db.exists()
    # The keychain.json lives next to the DB.
    assert (tmp_path / "keychain.json").exists()
    # get
    rc, out, _ = _run_cli_inproc(monkeypatch, [
        "--db", str(db), "--policy", str(policy_file),
        "get", "MY_KEY",
        "--namespace", "default", "--agent", "cli", "--purpose", "test",
    ])
    assert rc == 0
    assert "super-secret" in out


def test_list_empty_namespace(monkeypatch, tmp_path, policy_file):
    db = tmp_path / "v.db"
    rc, out, _ = _run_cli_inproc(monkeypatch, [
        "--db", str(db), "--policy", str(policy_file),
        "list", "--namespace", "default", "--agent", "cli", "--purpose", "",
    ])
    assert rc == 0
    assert "no active secrets" in out


def test_list_after_set(monkeypatch, tmp_path, policy_file):
    db = tmp_path / "v.db"
    for name in ("A", "B", "C"):
        _run_cli_inproc(
            monkeypatch,
            [
                "--db", str(db), "--policy", str(policy_file),
                "set", name, "-",
                "--namespace", "default", "--agent", "cli", "--purpose", "",
            ],
            stdin_payload=b"v\n",
        )
    rc, out, _ = _run_cli_inproc(monkeypatch, [
        "--db", str(db), "--policy", str(policy_file),
        "list", "--namespace", "default", "--agent", "cli", "--purpose", "",
    ])
    assert rc == 0
    for name in ("A", "B", "C"):
        assert name in out


def test_revoke_hides_secret(monkeypatch, tmp_path, policy_file):
    db = tmp_path / "v.db"
    _run_cli_inproc(
        monkeypatch,
        [
            "--db", str(db), "--policy", str(policy_file),
            "set", "K", "-",
            "--namespace", "default", "--agent", "cli", "--purpose", "",
        ],
        stdin_payload=b"v\n",
    )
    rc, out, _ = _run_cli_inproc(monkeypatch, [
        "--db", str(db), "--policy", str(policy_file),
        "revoke", "K", "--namespace", "default",
    ])
    assert rc == 0
    assert "revoked" in out
    # list should now be empty
    rc, out, _ = _run_cli_inproc(monkeypatch, [
        "--db", str(db), "--policy", str(policy_file),
        "list", "--namespace", "default", "--agent", "cli", "--purpose", "",
    ])
    assert "no active secrets" in out


def test_set_with_policy_deny(monkeypatch, tmp_path):
    deny_policy = tmp_path / "p.yaml"
    deny_policy.write_text("rules:\n  - effect: deny\n    agent: cli\n")
    db = tmp_path / "v.db"
    rc, _, err = _run_cli_inproc(
        monkeypatch,
        [
            "--db", str(db), "--policy", str(deny_policy),
            "set", "K", "-",
            "--namespace", "default", "--agent", "cli", "--purpose", "",
        ],
        stdin_payload=b"v\n",
    )
    assert rc == 1
    assert "denied" in err.lower()


# ------------------------------------------------------------------
# fingerprint
# ------------------------------------------------------------------

def test_fingerprint_after_set(monkeypatch, tmp_path, policy_file):
    db = tmp_path / "v.db"
    _run_cli_inproc(
        monkeypatch,
        [
            "--db", str(db), "--policy", str(policy_file),
            "set", "K", "-",
            "--namespace", "default", "--agent", "cli", "--purpose", "",
        ],
        stdin_payload=b"v\n",
    )
    rc, out, _ = _run_cli_inproc(monkeypatch, [
        "--db", str(db), "--policy", str(policy_file),
        "fingerprint", "K", "--namespace", "default",
    ])
    assert rc == 0
    assert "Fingerprint:" in out
    # 8-hex-char fingerprint
    fp_line = [line for line in out.splitlines() if "Fingerprint" in line][0]
    assert len(fp_line.split()[-1]) == 8


# ------------------------------------------------------------------
# rotate
# ------------------------------------------------------------------

def test_rotate_master_key(monkeypatch, tmp_path, policy_file):
    db = tmp_path / "v.db"
    _run_cli_inproc(
        monkeypatch,
        [
            "--db", str(db), "--policy", str(policy_file),
            "set", "K", "-",
            "--namespace", "default", "--agent", "cli", "--purpose", "",
        ],
        stdin_payload=b"v\n",
    )
    rc, out, _ = _run_cli_inproc(monkeypatch, [
        "--db", str(db), "--policy", str(policy_file),
        "rotate", "master",
    ])
    assert rc == 0
    assert "Master key rotated" in out
    # secret should still be readable
    rc, out, err = _run_cli_inproc(monkeypatch, [
        "--db", str(db), "--policy", str(policy_file),
        "get", "K", "--namespace", "default", "--agent", "cli", "--purpose", "test",
    ])
    assert rc == 0, f"get failed: rc={rc} out={out!r} err={err!r}"
    assert "v" in out


# ------------------------------------------------------------------
# verify-audit
# ------------------------------------------------------------------

def test_verify_audit_ok(monkeypatch, tmp_path, policy_file):
    db = tmp_path / "v.db"
    _run_cli_inproc(
        monkeypatch,
        [
            "--db", str(db), "--policy", str(policy_file),
            "set", "K", "-",
            "--namespace", "default", "--agent", "cli", "--purpose", "",
        ],
        stdin_payload=b"v\n",
    )
    rc, out, _ = _run_cli_inproc(monkeypatch, [
        "--db", str(db), "--policy", str(policy_file),
        "verify-audit",
    ])
    assert rc == 0
    assert "OK" in out


# ------------------------------------------------------------------
# audit (tail)
# ------------------------------------------------------------------

def test_audit_shows_set_action(monkeypatch, tmp_path, policy_file):
    db = tmp_path / "v.db"
    _run_cli_inproc(
        monkeypatch,
        [
            "--db", str(db), "--policy", str(policy_file),
            "set", "K", "-",
            "--namespace", "default", "--agent", "cli", "--purpose", "",
        ],
        stdin_payload=b"v\n",
    )
    rc, out, _ = _run_cli_inproc(monkeypatch, [
        "--db", str(db), "--policy", str(policy_file),
        "audit", "--limit", "5",
    ])
    assert rc == 0
    assert "SET_SECRET" in out


# ------------------------------------------------------------------
# Error handling
# ------------------------------------------------------------------

def test_unknown_subcommand(monkeypatch):
    rc, _, err = _run_cli_inproc(monkeypatch, ["bogus"])
    assert rc != 0
    assert "usage" in err.lower() or "invalid choice" in err.lower()


def test_get_nonexistent_secret(monkeypatch, tmp_path, policy_file):
    db = tmp_path / "v.db"
    rc, _, err = _run_cli_inproc(monkeypatch, [
        "--db", str(db), "--policy", str(policy_file),
        "get", "NOPE",
        "--namespace", "default", "--agent", "cli", "--purpose", "x",
    ])
    assert rc == 1
    assert "not found" in err.lower()


def test_unknown_provider(monkeypatch, tmp_path, policy_file):
    db = tmp_path / "v.db"
    # argparse rejects an unknown --provider choice with rc=2 (and the message
    # is printed to stderr by argparse, not by us).
    rc, _, err = _run_cli_inproc(monkeypatch, [
        "--db", str(db), "--policy", str(policy_file), "--provider", "banana",
        "audit",
    ])
    assert rc == 2
    assert "invalid choice" in err.lower() or "banana" in err.lower()


# ------------------------------------------------------------------
# P1-1: CLI plaintext from stdin / --value-file (not argv)
# ------------------------------------------------------------------

def test_set_from_stdin(monkeypatch, tmp_path, policy_file):
    """The plaintext value must be passed via stdin (or --value-file), not
    argv, so it doesn't appear in /proc/<pid>/cmdline."""
    db = tmp_path / "v.db"
    rc, out, _ = _run_cli_inproc(
        monkeypatch,
        [
            "--db", str(db), "--policy", str(policy_file),
            "set", "STDIN_KEY", "-",
            "--namespace", "default", "--agent", "cli", "--purpose", "test",
        ],
        stdin_payload=b"from-stdin-secret\n",
    )
    assert rc == 0
    rc, out, _ = _run_cli_inproc(monkeypatch, [
        "--db", str(db), "--policy", str(policy_file),
        "get", "STDIN_KEY",
        "--namespace", "default", "--agent", "cli", "--purpose", "test",
    ])
    assert rc == 0
    assert "from-stdin-secret" in out


def test_set_from_value_file(monkeypatch, tmp_path, policy_file):
    """--value-file reads the plaintext from disk; safer for automation."""
    db = tmp_path / "v.db"
    vf = tmp_path / "secret.txt"
    vf.write_text("from-file-secret")
    rc, out, _ = _run_cli_inproc(
        monkeypatch,
        [
            "--db", str(db), "--policy", str(policy_file),
            "set", "FILE_KEY", "--value-file", str(vf),
            "--namespace", "default", "--agent", "cli", "--purpose", "test",
        ],
    )
    assert rc == 0
    rc, out, _ = _run_cli_inproc(monkeypatch, [
        "--db", str(db), "--policy", str(policy_file),
        "get", "FILE_KEY",
        "--namespace", "default", "--agent", "cli", "--purpose", "test",
    ])
    assert rc == 0
    assert "from-file-secret" in out


def test_set_rejects_both_value_sources(monkeypatch, tmp_path, policy_file):
    """Passing both '-' and --value-file is a usage error."""
    db = tmp_path / "v.db"
    vf = tmp_path / "secret.txt"
    vf.write_text("x")
    rc, _, err = _run_cli_inproc(monkeypatch, [
        "--db", str(db), "--policy", str(policy_file),
        "set", "K", "-", "--value-file", str(vf),
        "--namespace", "default", "--agent", "cli",
    ])
    assert rc != 0


# ------------------------------------------------------------------
# P1-5: cmd_get emits zeroization-bypass warning to stderr
# ------------------------------------------------------------------

def test_get_warns_about_stdout(monkeypatch, tmp_path, policy_file):
    """cmd_get must print a warning to stderr so users don't accidentally
    treat 'get' as the safe path."""
    db = tmp_path / "v.db"
    _run_cli_inproc(
        monkeypatch,
        [
            "--db", str(db), "--policy", str(policy_file),
            "set", "K", "-",
            "--namespace", "default", "--agent", "cli", "--purpose", "",
        ],
        stdin_payload=b"v\n",
    )
    rc, out, err = _run_cli_inproc(monkeypatch, [
        "--db", str(db), "--policy", str(policy_file),
        "get", "K",
        "--namespace", "default", "--agent", "cli", "--purpose", "test",
    ])
    assert rc == 0
    assert "WARNING" in err
    assert "zeroization" in err.lower()
