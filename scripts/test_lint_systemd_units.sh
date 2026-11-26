#!/usr/bin/env bash
# Negative tests for lint_systemd_units.sh: each mutation of the real unit must be rejected.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
unit="$here/../deploy/rgt-vault.service"
lint="$here/lint_systemd_units.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export SKIP_SYSTEMD_ANALYZE=1
bad=0

expect_fail() { # name sed-expr
    sed -E "$2" "$unit" > "$tmp/t.service"
    if "$lint" "$tmp/t.service" >/dev/null 2>&1; then
        echo "FAIL: mutation '$1' was accepted" >&2
        bad=$((bad + 1))
    else
        echo "ok: '$1' rejected"
    fi
}

"$lint" "$unit" >/dev/null || { echo "FAIL: pristine unit rejected" >&2; bad=$((bad + 1)); }
expect_fail "no NoNewPrivileges" 's/^NoNewPrivileges=.*/NoNewPrivileges=false/'
expect_fail "ProtectSystem off" 's/^ProtectSystem=.*/ProtectSystem=no/'
expect_fail "runs as root" 's/^User=.*/User=root/'
expect_fail "missing Group" '/^Group=/d'
expect_fail "wildcard bind" 's/--host 127\.0\.0\.1/--host 0.0.0.0/'
expect_fail "no ReadWritePaths" '/^ReadWritePaths=/d'
expect_fail "packet sockets" 's/^RestrictAddressFamilies=.*/RestrictAddressFamilies=AF_INET AF_PACKET/'
expect_fail "no Install" '/^WantedBy=/d'
[ "$bad" -eq 0 ] && echo "all lint tests passed"
exit "$bad"
