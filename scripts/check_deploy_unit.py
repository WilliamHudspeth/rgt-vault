#!/usr/bin/env python3
"""Static lint for deploy/rgt-vault.service (RGT-262).

Deterministic and dependency-free (stdlib only), so it never flakes on runner
images. It asserts the sandboxing directives the threat model relies on, and
that the daemon is bound to loopback. With ``--write-verify-copy PATH`` it also
writes a copy whose ``ExecStart=`` points at ``/bin/true`` so that
``systemd-analyze verify`` can check unit syntax on a host that does not have
``/opt/rgt-vault`` installed.

Usage:
    python scripts/check_deploy_unit.py [UNIT] [--write-verify-copy PATH]
"""

from __future__ import annotations

import argparse
import configparser
import sys
from pathlib import Path
from typing import List, Optional

DEFAULT_UNIT = Path(__file__).resolve().parent.parent / "deploy" / "rgt-vault.service"

# directive -> accepted values (lower-cased). These are the hardening switches
# documented in the unit file's "defense in depth" block.
REQUIRED_SERVICE_FLAGS = {
    "NoNewPrivileges": {"true", "yes", "1"},
    "ProtectSystem": {"strict", "full", "true", "yes"},
    "ProtectHome": {"true", "yes", "read-only", "tmpfs"},
    "PrivateTmp": {"true", "yes"},
    "PrivateDevices": {"true", "yes"},
    "ProtectKernelModules": {"true", "yes"},
    "ProtectKernelTunables": {"true", "yes"},
    "ProtectControlGroups": {"true", "yes"},
    "RestrictNamespaces": {"true", "yes"},
    "RestrictRealtime": {"true", "yes"},
    "LockPersonality": {"true", "yes"},
    "MemoryDenyWriteExecute": {"true", "yes"},
}


def _join_continuations(text: str) -> str:
    """systemd lets a trailing backslash continue a directive; flatten it."""
    return text.replace("\\\r\n", " ").replace("\\\n", " ")


def _parse(text: str) -> configparser.ConfigParser:
    cp = configparser.ConfigParser(strict=False, interpolation=None)
    cp.optionxform = str  # type: ignore[assignment,method-assign]  # unit keys are case-sensitive
    cp.read_string(_join_continuations(text))
    return cp


def check_unit_text(text: str) -> List[str]:
    """Return a list of human-readable problems (empty list == OK)."""
    problems: List[str] = []
    try:
        cp = _parse(text)
    except configparser.Error as exc:
        return [f"unit does not parse: {exc}"]

    for section in ("Unit", "Service", "Install"):
        if not cp.has_section(section):
            problems.append(f"missing [{section}] section")
    if problems:
        return problems

    svc = cp["Service"]
    for key, allowed in REQUIRED_SERVICE_FLAGS.items():
        value = svc.get(key, "").strip().lower()
        if value not in allowed:
            problems.append(f"[Service] {key} must be one of {sorted(allowed)}, got {value or 'unset'!r}")

    for key in ("User", "Group"):
        value = svc.get(key, "").strip()
        if not value or value == "root":
            problems.append(f"[Service] {key} must be a dedicated non-root account, got {value or 'unset'!r}")

    if not svc.get("ReadWritePaths", "").strip():
        problems.append("[Service] ReadWritePaths must list the vault state dir (ProtectSystem=strict)")

    exec_start = svc.get("ExecStart", "").strip()
    if not exec_start:
        problems.append("[Service] ExecStart is missing")
    else:
        if "0.0.0.0" in exec_start or "::" in exec_start:
            problems.append("[Service] ExecStart must not bind a wildcard address")
        if "--host 127.0.0.1" not in exec_start and "--host=127.0.0.1" not in exec_start:
            problems.append("[Service] ExecStart must bind --host 127.0.0.1 (loopback only)")

    if not cp["Install"].get("WantedBy", "").strip():
        problems.append("[Install] WantedBy is missing")
    return problems


def verify_copy(text: str) -> str:
    """Unit text with ExecStart replaced so ``systemd-analyze verify`` can run anywhere."""
    out = []
    for line in _join_continuations(text).splitlines():
        out.append("ExecStart=/bin/true" if line.startswith("ExecStart=") else line)
    return "\n".join(out) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    ap.add_argument("unit", nargs="?", type=Path, default=DEFAULT_UNIT)
    ap.add_argument("--write-verify-copy", type=Path, default=None, metavar="PATH")
    args = ap.parse_args(argv)

    text = args.unit.read_text(encoding="utf-8")
    problems = check_unit_text(text)
    for p in problems:
        print(f"FAIL {args.unit}: {p}", file=sys.stderr)
    if args.write_verify_copy is not None:
        args.write_verify_copy.write_text(verify_copy(text), encoding="utf-8")
    if problems:
        return 1
    print(f"OK {args.unit}: sandboxing directives present, loopback bind")
    return 0


if __name__ == "__main__":
    sys.exit(main())
