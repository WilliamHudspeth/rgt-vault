"""Command-line interface for rgt-vault.

Most subcommands build a ``VaultManager`` against the platform-default
provider, which on Linux/macOS/Windows reaches for TPM/Keychain/DPAPI and may
require extra setup. The ``--provider keyring`` flag selects the cross-platform
Secret Service provider for local development. ``simulate`` deliberately does
not need a master-secret provider because policy evaluation is pure logic.
"""

import argparse
import sys
from pathlib import Path

from rgt_vault.exceptions import VaultError
from rgt_vault.keychain import KeyringProvider
from rgt_vault.providers import create_platform_provider
from rgt_vault.providers.base import MasterSecretProvider
from rgt_vault.vault import VaultManager


def _build_provider(name: str) -> MasterSecretProvider:
    if name == "keyring":
        # Cross-platform Secret Service / Credential Manager / Keychain.
        # Convenient for local development; production should use --provider
        # platform with a sealed DPAPI/TPM/Keychain backend.
        return KeyringProvider()
    if name == "platform":
        return create_platform_provider()
    raise VaultError(f"Unknown provider '{name}'. Use 'keyring' or 'platform'.")


def _build_vault(args: argparse.Namespace, *, approval_gate=None) -> VaultManager:
    return VaultManager(
        db_path=args.db,
        policy_yaml=Path(args.policy).read_text() if args.policy else "",
        master_provider=_build_provider(args.provider),
        approval_gate=approval_gate,
    )


def cmd_set(args: argparse.Namespace) -> int:
    # P1-1 audit fix: never accept the plaintext secret via argv. argv is
    # visible to other local users via /proc/<pid>/cmdline and may be
    # captured by process supervisors / shell history. The value must come
    # from stdin (one line, trailing newline stripped) or from a file
    # referenced by --value-file.
    if bool(args.value) == bool(args.value_file):
        # argparse shouldn't allow this state because of the mutually-
        # exclusive group, but be explicit.
        print(
            "Error: provide exactly one of an inline VALUE (from stdin "
            "via 'echo SECRET | rgt-vault set NAME -') or --value-file PATH.",
            file=sys.stderr,
        )
        return 2

    if args.value_file:
        with open(args.value_file, "rb") as f:
            raw = f.read()
    else:
        # Read from stdin in binary mode when available. In tests ``sys.stdin``
        # may be a ``StringIO`` without a ``.buffer`` attribute; fall back to
        # text mode and encode.
        if hasattr(sys.stdin, "buffer"):
            raw = sys.stdin.buffer.read()
        else:
            raw = sys.stdin.read().encode("utf-8", errors="replace")

    # Strip a single trailing newline / carriage return pair (the common case
    # when piping from echo/printf). Internal newlines are kept intact.
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if raw.endswith(b"\r"):
        raw = raw[:-1]

    value = bytearray(raw)
    try:
        vault = _build_vault(args)
        vault.set_secret(
            args.name,
            value,
            namespace=args.namespace,
            agent=args.agent,
            purpose=args.purpose,
        )
        print(f"Secret '{args.namespace}/{args.name}' stored successfully.")
        return 0
    finally:
        from rgt_vault.crypto import zeroize_bytearray

        zeroize_bytearray(value)


def cmd_get(args: argparse.Namespace) -> int:
    """Lease a secret, print its UTF-8 value to stdout, and zeroize the buffer.

    Exits non-zero on policy denial or not-found.

    **WARNING (P1-5 audit fix):** writing the plaintext to stdout defeats
    the leased-buffer zeroization guarantee -- the Python string lives in
    interpreter memory until garbage-collected, and may also be captured
    by your shell history, process accounting, or a paging terminal.
    Prefer the ``execute`` subcommand for programmatic use.

    A one-line warning is printed to stderr to make the trade-off visible
    in scripts.
    """
    print(
        "WARNING: 'get' writes plaintext to stdout and bypasses the "
        "zeroization guarantee; prefer 'execute' for production use.",
        file=sys.stderr,
    )
    vault = _build_vault(args)

    def _print(buf: bytearray) -> None:
        sys.stdout.write(buf.decode("utf-8"))
        sys.stdout.write("\n")

    vault.execute(args.agent, args.namespace, args.purpose, args.name, _print)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    vault = _build_vault(args)
    secrets = vault.list_secrets(args.namespace, agent=args.agent, purpose=args.purpose)
    if not secrets:
        print(f"(no active secrets in {args.namespace})")
        return 0
    for s in secrets:
        print(f"{s['name']}\tv{s['latest_version']}\t{s['status']}\t{s['updated_at']}")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    vault = _build_vault(args)
    vault.revoke_secret(args.namespace, args.name, agent=args.agent)
    print(f"Secret '{args.namespace}/{args.name}' revoked.")
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    # Policy simulation does not touch secrets, so evaluate the engine
    # directly without requiring a master-secret provider.
    from rgt_vault.auth import ABACPolicyEngine

    policy_text = Path(args.policy).read_text()
    engine = ABACPolicyEngine(policy_text)
    decision = engine.evaluate(args.agent, args.namespace, args.purpose, action=args.action)
    print("ALLOWED" if decision["allowed"] else "DENIED")
    print(f"Reason: {decision['reason']}")
    return 0


def cmd_fingerprint(args: argparse.Namespace) -> int:
    vault = _build_vault(args)
    fp = vault.get_fingerprint(args.name, namespace=args.namespace)
    print(f"{args.namespace}/{args.name}\tFingerprint: {fp}")
    return 0


def cmd_rotate(args: argparse.Namespace) -> int:
    vault = _build_vault(args)
    if args.target == "master":
        vault.rotate_master_key()
        print(f"Master key rotated. New key epoch: {vault.key_epoch}")
    elif args.target == "dek":
        vault.rotate_dek()
        print(f"DEK rotated. New key epoch: {vault.key_epoch}")
    return 0


def cmd_verify_audit(args: argparse.Namespace) -> int:
    vault = _build_vault(args)
    ok = vault.verify_audit_chain()
    print("OK" if ok else "TAMPERED")
    return 0 if ok else 2


def cmd_audit(args: argparse.Namespace) -> int:
    vault = _build_vault(args)
    for entry in vault.get_audit_log(limit=args.limit):
        ts = entry.get("timestamp", "")
        action = entry.get("action", "")
        name = entry.get("secret_name") or "-"
        details = entry.get("details", "")
        print(f"{ts}\t{action}\t{name}\t{details}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """RGT-55: print a one-screen summary of the vault's current state.

    Outputs (in order, one per line):
      - vault_id, key_epoch
      - secret counts by namespace (from storage.metadata + storage.secrets)
      - total audit row count + the most recent action/timestamp
      - audit chain verification result (OK / TAMPERED)

    Pure read; no writes, no token required. Useful for ops dashboards
    and CI smoke tests. Exit code: 0 if the chain verifies, 2 if
    TAMPERED, 1 on any other error.
    """
    vault = _build_vault(args)
    print(f"vault_id:     {vault.vault_id}")
    print(f"key_epoch:    {vault.key_epoch}")

    # Secret counts by namespace. We do a single connection pass instead
    # of calling list_secrets per namespace (which would be policy-gated
    # and might return empty even when secrets exist for other agents).
    with vault.storage._get_conn() as conn:
        rows = conn.execute(
            "SELECT namespace, COUNT(*) FROM secrets WHERE status = 'ACTIVE' GROUP BY namespace ORDER BY namespace"
        ).fetchall()
    total = sum(n for _ns, n in rows)
    print(f"active secrets: {total}")
    for ns, n in rows:
        print(f"  {ns}: {n}")

    # Audit log: total count + the most recent row.
    total_audit = vault.storage.audit_log_count()
    print(f"audit rows:   {total_audit}")
    with vault.storage._get_conn() as conn:
        last = conn.execute("SELECT action, timestamp, secret_name FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
    if last is not None:
        last_action, last_ts, last_name = last
        print(f"last action:  {last_ts}  {last_action}  {last_name or '-'}")

    ok = vault.verify_audit_chain()
    print(f"audit chain:  {'OK' if ok else 'TAMPERED'}")
    return 0 if ok else 2


def cmd_init(args: argparse.Namespace) -> int:
    """Generate (or report) the server bearer-token file.

    Idempotent: if the token file already exists and is non-empty, the
    existing token is NOT printed. Delete the file to mint a new one.
    P1-3/P1-4 audit fix: never echo an existing token to stdout.
    """
    from rgt_vault.server.auth import DEFAULT_TOKEN_PATH, TokenStore, load_or_create_token

    path = Path(args.token_file) if args.token_file else None
    store_path = path if path else DEFAULT_TOKEN_PATH
    store = TokenStore(store_path)

    if store.exists():
        existing = store.read()
        if existing:
            print(f"Token file: {store_path}")
            print("Token file already exists; not re-printing. Delete the file to mint a new one.")
            print("To see the token id (sha256 prefix) used in audit logs, run:")
            print(
                '  python -c "import hashlib; '
                f"print(hashlib.sha256(open(r'{store_path}').read().strip().encode()).hexdigest()[:8])\""
            )
            return 0

    # File does not exist or was empty -- (re)create it.
    new_path, new_token = load_or_create_token(path)
    print(f"Token file: {new_path}")
    print(f"Bearer token: {new_token}")
    print("Send it as a header:  Authorization: Bearer <token>")
    return 0


def _load_totp_verifier(secret_file):
    """Return a replay-guarded TOTP verifier from a base32 secret file, or None."""
    if not secret_file:
        return None
    from rgt_vault import totp

    secret = Path(secret_file).expanduser().read_text().strip()
    return totp.ReplayGuardedVerifier(secret)


def cmd_enroll_2fa(args: argparse.Namespace) -> int:
    """Generate a TOTP secret for approval 2FA, save it, and print the URI."""
    from rgt_vault import totp

    out = Path(args.out).expanduser()
    if out.exists() and not args.force:
        print(f"{out} already exists. Use --force to overwrite.", file=sys.stderr)
        return 1
    secret = totp.generate_secret()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(secret)
    try:
        out.chmod(0o600)
    except OSError:
        pass
    print(f"TOTP secret written to: {out}")
    print("Add it to your authenticator app via this URI (or type the secret):")
    print("  " + totp.provisioning_uri(secret, args.account, issuer="rgt-vault"))
    print(f"  secret: {secret}")
    print("\nStart the daemon with:  rgt-vault serve --require-approval --totp-secret-file " + str(out))
    return 0


def cmd_tui(args: argparse.Namespace) -> int:
    """Launch the operator TUI against a running daemon."""
    try:
        from rgt_vault.tui import run_tui
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    token = args.token
    if not token:
        from rgt_vault.server.auth import DEFAULT_TOKEN_PATH, TokenStore

        store = TokenStore(Path(args.token_file) if args.token_file else DEFAULT_TOKEN_PATH)
        if not store.exists():
            print("No token provided and no token file found. Run 'rgt-vault init' first.", file=sys.stderr)
            return 1
        token = store.read()

    try:
        return run_tui(args.url, token, namespace=args.namespace)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_serve(args: argparse.Namespace) -> int:
    """Run the local HTTP server (loopback-only by default)."""
    try:
        import uvicorn
    except ModuleNotFoundError:
        print(
            "Error: the server requires the [server] extra. Install it with: pip install 'rgt-vault[server]'",
            file=sys.stderr,
        )
        return 1

    from rgt_vault.approval import ApprovalBroker
    from rgt_vault.server.actions import ActionRegistry, register_builtin_actions
    from rgt_vault.server.app import build_app
    from rgt_vault.server.auth import TokenStore, load_or_create_token

    broker = None
    if getattr(args, "require_approval", False):
        verifier = _load_totp_verifier(getattr(args, "totp_secret_file", None))
        broker = ApprovalBroker(timeout=args.approval_timeout, totp_verifier=verifier)

    vault = _build_vault(args, approval_gate=broker)
    token_path, _token = load_or_create_token(Path(args.token_file) if args.token_file else None)
    store = TokenStore(token_path)

    # Optional separate operator-token scope: when set, approving/denying
    # agent requests requires THIS token, not the agent token. This is the
    # split that makes "the agent cannot self-approve" true.
    operator_store = None
    operator_file = getattr(args, "operator_token_file", None)
    if operator_file:
        op_path, _op_token = load_or_create_token(Path(operator_file))
        operator_store = TokenStore(op_path)
    elif broker is not None:
        # require-approval without a separate operator token means the
        # approve/deny endpoints accept the SAME token agents use to call
        # /use — so an agent holding it could approve its own request. Warn
        # loudly; production should pass --operator-token-file.
        print(
            "WARNING: --require-approval is on but no --operator-token-file was given. "
            "The approve/deny endpoints will accept the agent token, so an agent could "
            "self-approve. Pass --operator-token-file to separate the operator scope.",
            file=sys.stderr,
        )

    registry = ActionRegistry()
    register_builtin_actions(registry)
    app = build_app(
        vault,
        store,
        registry,
        operator_token_store=operator_store,
        broker=broker,
        allow_private_network=args.allow_private_network,
    )

    print(f"rgt-vault server: http://{args.host}:{args.port}  (agent token: {token_path})")
    if operator_store is not None:
        print(f"operator token (approve/deny scope): {operator_file}")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"WARNING: binding to {args.host} exposes the vault beyond loopback. "
            "Put a TLS-terminating reverse proxy in front and restrict access.",
            file=sys.stderr,
        )
    if args.allow_private_network:
        print(
            "WARNING: --allow-private-network enables the built-in HTTP "
            "actions to call loopback / link-local / RFC1918 addresses. "
            "Any caller with a valid bearer token can use this to probe "
            "internal services (SSRF). Only enable on trusted networks.",
            file=sys.stderr,
        )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info", server_header=False)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Agent Vault CLI")
    parser.add_argument("--db", default="~/.secure-vault/vault.db", help="Path to vault.db")
    parser.add_argument(
        "--policy",
        default=None,
        help="Path to policy YAML (recommended; defaults to no policy = default-deny)",
    )
    parser.add_argument(
        "--provider",
        default="keyring",
        choices=["keyring", "platform"],
        help="Master-secret provider (default: keyring for dev convenience)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # set
    p_set = subparsers.add_parser(
        "set", help="Store a secret (read the value from stdin or --value-file; never from argv)"
    )
    p_set.add_argument("name", help="Secret name")
    value_group = p_set.add_mutually_exclusive_group(required=True)
    value_group.add_argument(
        "-",
        dest="value",
        action="store_true",
        help="Read the secret value from stdin (default for piping).",
    )
    value_group.add_argument(
        "--value-file",
        dest="value_file",
        default=None,
        help="Read the secret value from a file (recommended for automation).",
    )
    p_set.add_argument("--namespace", default="default")
    p_set.add_argument("--agent", default="cli")
    p_set.add_argument("--purpose", default="")
    p_set.set_defaults(func=cmd_set)

    # get (lease + print)
    p_get = subparsers.add_parser("get", help="Lease a secret and print its value")
    p_get.add_argument("name", help="Secret name")
    p_get.add_argument("--namespace", default="default")
    p_get.add_argument("--agent", default="cli")
    p_get.add_argument("--purpose", required=True)
    p_get.set_defaults(func=cmd_get)

    # list
    p_list = subparsers.add_parser("list", help="List active secrets in a namespace")
    p_list.add_argument("--namespace", required=True)
    p_list.add_argument("--agent", default="cli")
    p_list.add_argument("--purpose", default="")
    p_list.set_defaults(func=cmd_list)

    # revoke
    p_revoke = subparsers.add_parser("revoke", help="Revoke the active version of a secret")
    p_revoke.add_argument("name", help="Secret name")
    p_revoke.add_argument("--namespace", default="default")
    p_revoke.add_argument("--agent", default="cli")
    p_revoke.set_defaults(func=cmd_revoke)

    # simulate
    p_sim = subparsers.add_parser("simulate", help="Simulate a policy evaluation")
    p_sim.add_argument("--policy", required=True, help="Path to policy YAML")
    p_sim.add_argument("--agent", required=True)
    p_sim.add_argument("--namespace", required=True)
    p_sim.add_argument("--purpose", required=True)
    p_sim.add_argument("--action", default="read", choices=["read", "write"])
    p_sim.set_defaults(func=cmd_simulate)

    # fingerprint
    p_fp = subparsers.add_parser("fingerprint", help="Get a secret's ciphertext fingerprint")
    p_fp.add_argument("name", help="Secret name")
    p_fp.add_argument("--namespace", default="default")
    p_fp.set_defaults(func=cmd_fingerprint)

    # rotate
    p_rot = subparsers.add_parser("rotate", help="Rotate master key or DEK")
    p_rot.add_argument("target", choices=["master", "dek"], help="What to rotate")
    p_rot.set_defaults(func=cmd_rotate)

    # verify-audit
    p_va = subparsers.add_parser("verify-audit", help="Verify the audit log hash chain")
    p_va.set_defaults(func=cmd_verify_audit)

    # audit (tail)
    p_au = subparsers.add_parser("audit", help="Tail the audit log")
    p_au.add_argument("--limit", type=int, default=20)
    p_au.set_defaults(func=cmd_audit)

    # status (RGT-55: one-screen summary)
    p_st = subparsers.add_parser("status", help="Print vault status (id, epoch, secret counts, audit chain)")
    p_st.set_defaults(func=cmd_status)

    # init (generate the server bearer-token file)
    p_init = subparsers.add_parser("init", help="Generate the server bearer-token file")
    p_init.add_argument(
        "--token-file", default=None, help="Token file path (default: ~/.config/rgt-vault/server.token)"
    )
    p_init.set_defaults(func=cmd_init)

    # serve (local HTTP server)
    p_serve = subparsers.add_parser("serve", help="Run the local HTTP server (requires [server] extra)")
    p_serve.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1, loopback only)")
    p_serve.add_argument("--port", type=int, default=8765, help="Bind port (default: 8765)")
    p_serve.add_argument(
        "--token-file", default=None, help="Token file path (default: ~/.config/rgt-vault/server.token)"
    )
    p_serve.add_argument(
        "--allow-private-network",
        action="store_true",
        help="Permit built-in HTTP actions to call loopback / private addresses. "
        "Default: off. Only enable on trusted networks.",
    )
    p_serve.add_argument(
        "--require-approval",
        action="store_true",
        help="Gate every secret lease on live operator approval via the TUI.",
    )
    p_serve.add_argument(
        "--totp-secret-file",
        default=None,
        help="Base32 TOTP secret file (from 'enroll-2fa') used to verify 2FA approvals.",
    )
    p_serve.add_argument(
        "--approval-timeout",
        type=float,
        default=120.0,
        help="Seconds an agent request waits for approval before auto-deny (default: 120).",
    )
    p_serve.add_argument(
        "--operator-token-file",
        default=None,
        help="Separate token for the approve/deny (operator) scope. When set, the "
        "agent token cannot approve its own requests.",
    )
    p_serve.set_defaults(func=cmd_serve)

    # enroll-2fa (generate a TOTP secret for approval 2FA)
    p_2fa = subparsers.add_parser("enroll-2fa", help="Generate a TOTP secret for approval 2FA")
    p_2fa.add_argument("--out", default="~/.config/rgt-vault/totp.secret", help="Where to write the base32 secret")
    p_2fa.add_argument("--account", default="operator", help="Account label for the authenticator app")
    p_2fa.add_argument("--force", action="store_true", help="Overwrite an existing secret file")
    p_2fa.set_defaults(func=cmd_enroll_2fa)

    # tui (operator console)
    p_tui = subparsers.add_parser("tui", help="Launch the operator TUI (requires [tui] extra)")
    p_tui.add_argument("--url", default="http://127.0.0.1:8765", help="Daemon base URL (default: http://127.0.0.1:8765)")
    p_tui.add_argument("--token", default=None, help="Operator bearer token (default: read from --token-file)")
    p_tui.add_argument(
        "--token-file", default=None, help="Token file path (default: ~/.config/rgt-vault/server.token)"
    )
    p_tui.add_argument("--namespace", default="default", help="Namespace to store secrets under (default: default)")
    p_tui.set_defaults(func=cmd_tui)

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except VaultError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # last-resort guard so the CLI never tracebacks
        # Print exception type + message so the user has something to debug
        # with. We deliberately do NOT print a full traceback by default --
        # users can run with `RGT_VAULT_DEBUG=1` to get one.
        import os
        import traceback

        msg = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
        print(f"Unexpected error: {msg}", file=sys.stderr)
        if os.environ.get("RGT_VAULT_DEBUG"):
            traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
