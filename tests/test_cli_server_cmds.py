"""CLI tests for init / enroll-2fa / tui / serve (RGT-261 coverage gate).

Everything that would touch the OS keyring, bind a port or open a terminal UI
is replaced with an in-memory stub.
"""

import sys
import types

import pytest

from rgt_vault import cli


class _MemProvider:
    def get_secret(self):
        return b"\x02" * 32

    def rotate_secret(self):  # pragma: no cover - not used
        return b"\x03" * 32


@pytest.fixture(autouse=True)
def _stub_keyring(monkeypatch):
    monkeypatch.setattr(cli, "KeyringProvider", _MemProvider)


def _parse(*argv):
    return cli._build_parser().parse_args(list(argv))


# --------------------------------------------------------------------------- #
# init
# --------------------------------------------------------------------------- #


def test_init_mints_token_once_and_never_reprints(tmp_path, capsys):
    path = tmp_path / "server.token"
    assert cli.cmd_init(_parse("init", "--token-file", str(path))) == 0
    first = capsys.readouterr().out
    token = path.read_text().strip()
    assert token and token in first

    assert cli.cmd_init(_parse("init", "--token-file", str(path))) == 0
    second = capsys.readouterr().out
    assert "already exists" in second
    assert token not in second


def test_init_refuses_empty_token_file(tmp_path):
    from rgt_vault.exceptions import ServerAuthError

    path = tmp_path / "server.token"
    path.write_text("")
    with pytest.raises(ServerAuthError, match="empty"):
        cli.cmd_init(_parse("init", "--token-file", str(path)))


# --------------------------------------------------------------------------- #
# enroll-2fa
# --------------------------------------------------------------------------- #


def test_enroll_2fa_writes_secret_and_refuses_overwrite_without_force(tmp_path, capsys):
    out = tmp_path / "sub" / "totp.secret"
    assert cli.cmd_enroll_2fa(_parse("enroll-2fa", "--out", str(out), "--account", "me")) == 0
    printed = capsys.readouterr().out
    secret = out.read_text().strip()
    assert secret and "otpauth://" in printed and "rgt-vault" in printed

    assert cli.cmd_enroll_2fa(_parse("enroll-2fa", "--out", str(out))) == 1
    assert "already exists" in capsys.readouterr().err
    assert out.read_text().strip() == secret

    assert cli.cmd_enroll_2fa(_parse("enroll-2fa", "--out", str(out), "--force")) == 0
    assert out.read_text().strip() != secret


def test_load_totp_verifier(tmp_path):
    from rgt_vault import totp

    assert cli._load_totp_verifier(None) is None
    f = tmp_path / "s"
    secret = totp.generate_secret()
    f.write_text(secret + "\n")
    verifier = cli._load_totp_verifier(str(f))
    assert verifier(totp.generate(secret)) is True


# --------------------------------------------------------------------------- #
# tui
# --------------------------------------------------------------------------- #


def _fake_tui_module(monkeypatch, run):
    mod = types.ModuleType("rgt_vault.tui")
    mod.run_tui = run  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "rgt_vault.tui", mod)


def test_tui_uses_explicit_token(monkeypatch):
    seen = {}

    def run(url, token, namespace="default"):
        seen.update(url=url, token=token, namespace=namespace)
        return 0

    _fake_tui_module(monkeypatch, run)
    args = _parse("tui", "--url", "http://127.0.0.1:9", "--token", "abc", "--namespace", "ns")
    assert cli.cmd_tui(args) == 0
    assert seen == {"url": "http://127.0.0.1:9", "token": "abc", "namespace": "ns"}


def test_tui_reads_token_file_or_complains(monkeypatch, tmp_path, capsys):
    seen = {}

    def run(url, token, namespace="default"):
        seen["token"] = token
        return 0

    _fake_tui_module(monkeypatch, run)
    missing = tmp_path / "nope"
    assert cli.cmd_tui(_parse("tui", "--token-file", str(missing))) == 1
    assert "No token provided" in capsys.readouterr().err

    present = tmp_path / "tok"
    present.write_text("file-token\n")
    assert cli.cmd_tui(_parse("tui", "--token-file", str(present))) == 0
    assert seen["token"] == "file-token"


def test_tui_runtime_error_is_reported(monkeypatch, capsys):
    def run(url, token, namespace="default"):
        raise RuntimeError("needs the tui extra")

    _fake_tui_module(monkeypatch, run)
    assert cli.cmd_tui(_parse("tui", "--token", "t")) == 1
    assert "needs the tui extra" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# serve
# --------------------------------------------------------------------------- #


@pytest.fixture
def uvicorn_calls(monkeypatch):
    uvicorn = pytest.importorskip("uvicorn")
    calls = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append((app, kw)))
    return calls


def _serve_args(tmp_path, *extra):
    return _parse(
        "--db",
        str(tmp_path / "vault.db"),
        "serve",
        "--token-file",
        str(tmp_path / "agent.token"),
        *extra,
    )


def test_serve_defaults_to_loopback_without_warnings(tmp_path, uvicorn_calls, capsys):
    assert cli.cmd_serve(_serve_args(tmp_path)) == 0
    cap = capsys.readouterr()
    assert "http://127.0.0.1:8765" in cap.out
    assert "WARNING" not in cap.err
    ((app, kw),) = uvicorn_calls
    assert kw["host"] == "127.0.0.1" and kw["port"] == 8765 and kw["server_header"] is False
    assert app.title


def test_serve_warns_on_non_loopback_private_network_and_shared_token(tmp_path, uvicorn_calls, capsys):
    from rgt_vault import totp

    totp_file = tmp_path / "totp"
    totp_file.write_text(totp.generate_secret())
    args = _serve_args(
        tmp_path,
        "--host",
        "0.0.0.0",
        "--allow-private-network",
        "--require-approval",
        "--totp-secret-file",
        str(totp_file),
    )
    assert cli.cmd_serve(args) == 0
    err = capsys.readouterr().err
    assert "exposes the vault beyond loopback" in err
    assert "--allow-private-network" in err
    assert "self-approve" in err
    assert uvicorn_calls


def test_serve_with_operator_token_file_separates_scope(tmp_path, uvicorn_calls, capsys):
    op = tmp_path / "operator.token"
    args = _serve_args(tmp_path, "--require-approval", "--operator-token-file", str(op))
    assert cli.cmd_serve(args) == 0
    cap = capsys.readouterr()
    assert "operator token (approve/deny scope)" in cap.out
    assert "self-approve" not in cap.err
    assert op.read_text().strip()


def test_serve_without_uvicorn_reports_extra(monkeypatch, tmp_path, capsys):
    monkeypatch.setitem(sys.modules, "uvicorn", None)  # makes `import uvicorn` raise ModuleNotFoundError
    assert cli.cmd_serve(_serve_args(tmp_path)) == 1
    assert "[server] extra" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# main(): error mapping
# --------------------------------------------------------------------------- #


def test_main_maps_errors_to_exit_code_1(monkeypatch, capsys):
    from rgt_vault.exceptions import VaultError

    real_parser = cli._build_parser()

    def run_with(exc):
        ns = real_parser.parse_args(["init"])
        ns.func = lambda a: (_ for _ in ()).throw(exc)
        monkeypatch.setattr(cli, "_build_parser", lambda: types.SimpleNamespace(parse_args=lambda: ns))
        return cli.main()

    assert run_with(VaultError("vault problem")) == 1
    assert "Error: vault problem" in capsys.readouterr().err
    assert run_with(FileNotFoundError("missing.txt")) == 1
    assert "missing.txt" in capsys.readouterr().err
    assert run_with(ValueError("kaboom")) == 1
    err = capsys.readouterr().err
    assert "Unexpected error: ValueError: kaboom" in err
    assert "Traceback" not in err

    monkeypatch.setenv("RGT_VAULT_DEBUG", "1")
    assert run_with(ValueError("kaboom")) == 1
    assert "Traceback" in capsys.readouterr().err
