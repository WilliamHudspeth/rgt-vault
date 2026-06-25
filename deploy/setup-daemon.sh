#!/usr/bin/env bash
#
# setup-daemon.sh — install rgt-vault as a locked-down systemd daemon.
#
# This is what turns the "soft" same-host boundary into a real one: the
# vault runs as its own service account (rgtvault) that the LLM/agent user
# cannot read. Agents get only the loopback HTTP API and a scoped AGENT
# token; the human/TUI holds a separate OPERATOR token to approve requests.
#
# Run as root on Linux:   sudo bash deploy/setup-daemon.sh
#
set -euo pipefail

VAULT_USER="rgtvault"
STATE_DIR="/var/lib/rgt-vault"
APP_DIR="/opt/rgt-vault"
UNIT_SRC="$(dirname "$0")/rgt-vault.service"
UNIT_DST="/etc/systemd/system/rgt-vault.service"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "Please run as root (sudo)." >&2
    exit 1
fi

echo "==> Creating service account '${VAULT_USER}' (no login shell)"
if ! id "${VAULT_USER}" &>/dev/null; then
    useradd --system --home-dir "${STATE_DIR}" --shell /usr/sbin/nologin "${VAULT_USER}"
fi

echo "==> Preparing state dir ${STATE_DIR} (0700, owned by ${VAULT_USER})"
install -d -o "${VAULT_USER}" -g "${VAULT_USER}" -m 0700 "${STATE_DIR}"

echo "==> Installing app source into ${APP_DIR}"
install -d -o root -g root -m 0755 "${APP_DIR}"
# Copy only tracked source — never the dev .venv, .git, caches, or any local
# vault state that might sit in the working tree (which would land in a
# world-readable /opt). Prefer 'git archive'; fall back to a filtered copy.
if git -C "${REPO_ROOT}" rev-parse --git-dir >/dev/null 2>&1; then
    git -C "${REPO_ROOT}" archive --format=tar HEAD | tar -x -C "${APP_DIR}"
else
    tar -C "${REPO_ROOT}" \
        --exclude=.git --exclude=.venv --exclude=.pytest_cache \
        --exclude=.hypothesis --exclude='*.token' --exclude='*.secret' \
        -cf - python pyproject.toml MANIFEST.in requirements.txt README.md | tar -x -C "${APP_DIR}"
fi
python3 -m venv "${APP_DIR}/.venv"
"${APP_DIR}/.venv/bin/python" -m pip install --quiet --upgrade pip
"${APP_DIR}/.venv/bin/python" -m pip install --quiet -e "${APP_DIR}[server,tui]"

echo "==> Generating tokens and the 2FA secret (as ${VAULT_USER})"
run_as_vault() { runuser -u "${VAULT_USER}" -- "$@"; }
PY="${APP_DIR}/.venv/bin/python"

# Agent token: scoped credential the LLM uses to list/use secrets.
run_as_vault "${PY}" -m rgt_vault.cli init --token-file "${STATE_DIR}/agent.token" >/dev/null
# Operator token: only this can approve/deny. Keep it off the agent's host.
run_as_vault "${PY}" -m rgt_vault.cli init --token-file "${STATE_DIR}/operator.token" >/dev/null
# TOTP secret for 2FA-flagged approvals. Prints the enrollment URI once.
run_as_vault "${PY}" -m rgt_vault.cli enroll-2fa \
    --out "${STATE_DIR}/totp.secret" --account operator --force

chmod 0600 "${STATE_DIR}"/agent.token "${STATE_DIR}"/operator.token "${STATE_DIR}"/totp.secret

echo "==> Installing systemd unit"
cp "${UNIT_SRC}" "${UNIT_DST}"
systemctl daemon-reload
systemctl enable --now rgt-vault.service

cat <<EOF

Done. The daemon is running as '${VAULT_USER}' on http://127.0.0.1:8765.

  Agent (give this to the LLM):     ${STATE_DIR}/agent.token
  Operator (keep for the human):    ${STATE_DIR}/operator.token

The agent token can list/use secrets; only the operator token can approve.
Open the operator console from the human's account (the app is installed
only in ${APP_DIR}/.venv, so use its full path or pip-install rgt-vault[tui]
into your own environment):

  ${APP_DIR}/.venv/bin/python -m rgt_vault.cli tui \\
      --url http://127.0.0.1:8765 \\
      --token "\$(sudo cat ${STATE_DIR}/operator.token)"

Check status:   systemctl status rgt-vault
Tail logs:      journalctl -u rgt-vault -f
EOF
