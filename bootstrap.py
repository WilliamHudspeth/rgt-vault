#!/usr/bin/env python3
"""bootstrap.py — one-command setup for rgt-vault.

Run from the repo root on any platform:

    python bootstrap.py

Creates a virtual environment, installs all dependencies, initialises
the vault if needed, and prints the commands to get started.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

MIN_PYTHON = (3, 9)
VENV = Path(".venv")


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), check=check)


def main() -> None:
    # ------------------------------------------------------------------ #
    # 1. Python version gate                                               #
    # ------------------------------------------------------------------ #
    if sys.version_info < MIN_PYTHON:
        print(f"ERROR: Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ required "
              f"(you have {sys.version.split()[0]}).")
        sys.exit(1)

    print(f"Python {sys.version.split()[0]} OK")

    # ------------------------------------------------------------------ #
    # 2. Virtual environment                                               #
    # ------------------------------------------------------------------ #
    if not VENV.exists():
        print("\nCreating virtual environment (.venv)...")
        run(sys.executable, "-m", "venv", str(VENV))
    else:
        print("\nVirtual environment already exists — skipping creation.")

    # Resolve venv Python (works on Windows and POSIX)
    if sys.platform == "win32":
        venv_python = VENV / "Scripts" / "python.exe"
    else:
        venv_python = VENV / "bin" / "python"

    if not venv_python.exists():
        print(f"ERROR: Expected venv Python at {venv_python} — delete .venv and retry.")
        sys.exit(1)

    # ------------------------------------------------------------------ #
    # 3. Install                                                           #
    # ------------------------------------------------------------------ #
    print("\nInstalling rgt-vault and dependencies...")
    # Use `python -m pip` (not pip.exe) — avoids Windows Smart App Control
    # blocking the pip binary in new virtual environments.
    extras = "server,mcp,tui,dev"
    if sys.platform == "win32":
        extras += ",windows"
    run(str(venv_python), "-m", "pip", "install", "--quiet", "--upgrade", "pip")
    run(str(venv_python), "-m", "pip", "install", "--quiet", "-e", f".[{extras}]")
    print("Installation complete.")

    # ------------------------------------------------------------------ #
    # 4. Initialise vault                                                  #
    # ------------------------------------------------------------------ #
    print("\nInitialising vault...")
    result = subprocess.run(
        [str(venv_python), "-m", "rgt_vault.cli", "init"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        print("Vault initialised.")
    else:
        # Already initialised is fine; any other error is surfaced below.
        msg = (result.stderr or result.stdout).strip()
        if "already" in msg.lower() or "exists" in msg.lower():
            print("Vault already initialised.")
        else:
            print(f"Init returned code {result.returncode}: {msg}")

    # ------------------------------------------------------------------ #
    # 5. Status check                                                      #
    # ------------------------------------------------------------------ #
    print()
    run(str(venv_python), "-m", "rgt_vault.cli", "status", check=False)

    # ------------------------------------------------------------------ #
    # 6. Next-steps cheatsheet                                             #
    # ------------------------------------------------------------------ #
    if sys.platform == "win32":
        activate = r".venv\Scripts\activate"
        python   = r".venv\Scripts\python"
    else:
        activate = "source .venv/bin/activate"
        python   = ".venv/bin/python"

    print(f"""
================================================
 Setup complete. Quick-start:
================================================

  Activate:
    {activate}

  See the whole story in 10 seconds (store -> approve -> deny -> audit):
    {python} examples/demo_policy.py

  --- Operator workflow (human approves agent secret use) ---

  1. Enroll a 2FA secret for approvals (scan the printed QR/URI):
    {python} -m rgt_vault.cli enroll-2fa

  2. Start the daemon with live approval:
    {python} -m rgt_vault.cli serve --require-approval \\
        --totp-secret-file ~/.config/rgt-vault/totp.secret

  3. In another terminal, open the operator console:
    {python} -m rgt_vault.cli tui

  Now agent secret requests pop up in the TUI for you to approve
  (with TOTP) or deny. The agent only ever sees titles, never values.

  Start the MCP server (for AI agents / Claude Desktop):
    {python} python/server/mcp_server.py

  Run tests (fast — parallel, skips slow fuzz suite):
    {python} -m pytest -m "not fuzz"

  Run full test suite including fuzz/Hypothesis tests:
    {python} -m pytest

  Simulate a policy decision:
    {python} -m rgt_vault.cli simulate --agent my-agent \\
        --namespace test --action read
================================================
""")


if __name__ == "__main__":
    main()
