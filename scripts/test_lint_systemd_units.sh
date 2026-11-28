#!/usr/bin/env bash
# Negative tests for lint_systemd_units.sh: each mutation of the real unit must
# be rejected, and for the expected reason (a crash does not count).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
unit="$here/../deploy/rgt-vault.service"
lint="$here/lint_systemd_units.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export SKIP_SYSTEMD_ANALYZE=1
bad=0

# expect_fail NAME EXPECTED_STDERR_SUBSTRING SED_EXPR
expect_fail() {
    local err
    sed -E "$3" "$unit" > "$tmp/t.service"
    if err="$("$lint" "$tmp/t.service" 2>&1 >/dev/null)"; then
        echo "FAIL: mutation '$1' was accepted" >&2
        bad=$((bad + 1))
    elif [[ "$err" != *"$2"* ]]; then
        echo "FAIL: mutation '$1' rejected for the wrong reason: $err" >&2
        bad=$((bad + 1))
    else
        echo "ok: '$1' rejected"
    fi
}

"$lint" "$unit" >/dev/null || { echo "FAIL: pristine unit rejected" >&2; bad=$((bad + 1)); }
expect_fail "NoNewPrivileges off" "NoNewPrivileges" 's/^NoNewPrivileges=.*/NoNewPrivileges=false/'
expect_fail "NoNewPrivileges padded and overridden" "NoNewPrivileges" 's/^NoNewPrivileges=.*/NoNewPrivileges=true\n  NoNewPrivileges = false/'
expect_fail "ProtectSystem off" "ProtectSystem" 's/^ProtectSystem=.*/ProtectSystem=no/'
expect_fail "runs as root" "User must" 's/^User=.*/User=root/'
expect_fail "missing Group" "Group must" '/^Group=/d'
expect_fail "wildcard bind" "wildcard" 's/--host 127\.0\.0\.1/--host 127.0.0.1 --host 0.0.0.0/'
expect_fail "IPv6 wildcard bind" "wildcard" 's/--host 127\.0\.0\.1/--host ::/'
expect_fail "no ReadWritePaths" "ReadWritePaths" '/^ReadWritePaths=/d'
expect_fail "packet sockets" "AF_PACKET" 's/^RestrictAddressFamilies=.*/RestrictAddressFamilies=AF_INET AF_PACKET/'
expect_fail "packet sockets via extra line" "AF_PACKET" 's/^(RestrictAddressFamilies=.*)/RestrictAddressFamilies=AF_PACKET\n\1/'
expect_fail "deny-list address families" "allow-list" 's/^RestrictAddressFamilies=.*/RestrictAddressFamilies=~AF_UNIX/'
expect_fail "ExecStart privilege prefix" "privilege prefix" 's#^ExecStart=#ExecStart=+#'
expect_fail "no WantedBy" "WantedBy" '/^WantedBy=/d'
expect_fail "no Install section" "[Install]" '/^\[Install\]/d'

# The Go unit must run in production mode (RGT-427).
gounit="$here/../deploy/rgt-vault-go.service"
"$lint" "$gounit" >/dev/null || { echo "FAIL: pristine Go unit rejected" >&2; bad=$((bad + 1)); }
for expr in '/^Environment=APP_ENV=production/d' 's/^Environment=APP_ENV=production/Environment=APP_ENV=development/' 's/^Environment=APP_ENV=production/Environment=APP_ENV=production\nEnvironment=/'; do
    sed -E "$expr" "$gounit" > "$tmp/g.service"
    if err="$("$lint" "$tmp/g.service" 2>&1 >/dev/null)"; then
        echo "FAIL: Go unit mutation '$expr' was accepted" >&2
        bad=$((bad + 1))
    elif [[ "$err" != *"APP_ENV=production"* ]]; then
        echo "FAIL: Go unit mutation '$expr' rejected for the wrong reason: $err" >&2
        bad=$((bad + 1))
    else
        echo "ok: Go unit mutation rejected"
    fi
done
[ "$bad" -eq 0 ] && echo "all lint tests passed"
exit "$bad"
