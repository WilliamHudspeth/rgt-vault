#!/usr/bin/env bash
# Lint the systemd unit files under deploy/ (RGT-262, ASVS 1.14.4).
#
# Usage: scripts/lint_systemd_units.sh [UNIT.service ...]
#   With no arguments every deploy/*.service is linted, so a newly added unit
#   (for example deploy/rgt-vault-go.service) is covered automatically and the
#   script also works while only some of them exist on the branch.
#
# Two layers:
#   1. A static sandbox check in plain bash/awk. It needs no systemd, so it
#      gives the same answer on every runner and is the only blocking layer
#      for the hardening directives.
#   2. systemd-analyze, when installed: `verify` on a copy whose ExecStart
#      points at /bin/true (the real binary is not installed on a CI runner),
#      then `security --offline` as an informational score. `verify` failures
#      block; `security` never does, because its scoring changes between
#      systemd versions. Both are skipped with a notice when unavailable.
#
# Environment: SKIP_SYSTEMD_ANALYZE=1 disables layer 2.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
failures=0

fail() { echo "FAIL $1: $2" >&2; failures=$((failures + 1)); }

# Print the unit with backslash continuations joined, comments and blank lines removed.
normalize() {
    awk '
        { sub(/\r$/, "") }
        !cont && /^[[:space:]]*([#;]|$)/ { next }
        { line = cont ? line " " $0 : $0 }
        line ~ /\\$/ { sub(/\\$/, "", line); cont = 1; next }
        { cont = 0; print line; line = "" }
    ' "$1"
}

# Last value assigned to KEY in SECTION ("" when absent). Later assignments win
# in systemd for single-valued directives, and an empty assignment resets.
value() {
    local section="$1" key="$2" file="$3"
    normalize "$file" | awk -v sec="[$section]" -v key="$key" '
        /^\[/ { cur = $0; next }
        cur == sec {
            i = index($0, "=")
            if (i && substr($0, 1, i - 1) == key) { v = substr($0, i + 1); sub(/^[[:space:]]+/, "", v); sub(/[[:space:]]+$/, "", v); val = v }
        }
        END { print val }
    '
}

has_section() { normalize "$2" | grep -qx "\[$1\]"; }

# require FILE SECTION KEY ACCEPTED_REGEX
require_value() {
    local file="$1" section="$2" key="$3" accepted="$4" got
    got="$(value "$section" "$key" "$file" | tr '[:upper:]' '[:lower:]')"
    if ! [[ "$got" =~ ^($accepted)$ ]]; then
        fail "$file" "[$section] $key must match ($accepted), got '${got:-unset}'"
    fi
}

static_check() {
    local f="$1" s v
    for s in Unit Service Install; do
        has_section "$s" "$f" || fail "$f" "missing [$s] section"
    done

    local flag
    for flag in NoNewPrivileges PrivateTmp PrivateDevices ProtectKernelModules \
                ProtectKernelTunables ProtectControlGroups RestrictNamespaces \
                RestrictRealtime LockPersonality MemoryDenyWriteExecute; do
        require_value "$f" Service "$flag" 'true|yes|1|on'
    done
    require_value "$f" Service ProtectSystem 'strict|full|true|yes'
    require_value "$f" Service ProtectHome 'true|yes|read-only|tmpfs'

    for s in User Group; do
        v="$(value Service "$s" "$f")"
        if [ -z "$v" ] || [ "$v" = root ] || [ "$v" = 0 ]; then
            fail "$f" "[Service] $s must be a dedicated non-root account, got '${v:-unset}'"
        fi
    done

    [ -n "$(value Service ReadWritePaths "$f")" ] ||
        fail "$f" "[Service] ReadWritePaths must list the vault state dir (ProtectSystem is read-only otherwise)"

    v="$(value Service ExecStart "$f")"
    if [ -z "$v" ]; then
        fail "$f" "[Service] ExecStart is missing"
    else
        if [[ "$v" == *0.0.0.0* || "$v" == *"::"* ]]; then
            fail "$f" "[Service] ExecStart must not bind a wildcard address"
        fi
        if ! [[ "$v" =~ --host(=|[[:space:]]+)127\.0\.0\.1([[:space:]]|$) ]]; then
            fail "$f" "[Service] ExecStart must bind --host 127.0.0.1 (loopback only)"
        fi
    fi

    [ -n "$(value Install WantedBy "$f")" ] || fail "$f" "[Install] WantedBy is missing"

    # AF_PACKET/AF_NETLINK would widen the attack surface of a loopback API.
    v="$(value Service RestrictAddressFamilies "$f")"
    if [ -z "$v" ]; then
        fail "$f" "[Service] RestrictAddressFamilies must be set"
    elif [[ "$v" == *AF_PACKET* || "$v" == *AF_NETLINK* ]]; then
        fail "$f" "[Service] RestrictAddressFamilies must not allow AF_PACKET or AF_NETLINK"
    fi
}

analyze_check() {
    local f="$1" tmp copy
    if [ "${SKIP_SYSTEMD_ANALYZE:-0}" = 1 ] || ! command -v systemd-analyze >/dev/null 2>&1; then
        echo "NOTE $f: systemd-analyze unavailable or disabled; static checks only"
        return 0
    fi
    tmp="$(mktemp -d)"
    copy="$tmp/$(basename "$f")"
    # Replace the (possibly multi-line) ExecStart with /bin/true so verify does
    # not depend on /opt/rgt-vault being installed.
    awk '
        cont { cont = ($0 ~ /\\$/); next }
        /^ExecStart=/ { print "ExecStart=/bin/true"; cont = ($0 ~ /\\$/); next }
        { print }
    ' "$f" > "$copy"

    local out
    if ! out="$(systemd-analyze verify "$copy" 2>&1)"; then
        fail "$f" "systemd-analyze verify failed:
$out"
    elif printf '%s\n' "$out" | grep -Eiq 'unknown (key|section)|unknown lvalue|invalid|bad '; then
        fail "$f" "systemd-analyze verify reported problems:
$out"
    else
        echo "OK   $f: systemd-analyze verify"
    fi

    # Informational only: never gates (scoring differs between systemd releases).
    if systemd-analyze security --help 2>&1 | grep -q -- '--offline'; then
        systemd-analyze security --offline=true --no-pager "$copy" 2>&1 | tail -n 1 |
            sed "s|^|INFO $f: |" || true
    fi
    rm -rf "$tmp"
}

if [ "$#" -gt 0 ]; then
    units=("$@")
else
    units=()
    for f in "$root"/deploy/*.service; do
        [ -e "$f" ] && units+=("$f")
    done
fi

if [ "${#units[@]}" -eq 0 ]; then
    echo "FAIL no unit files found under deploy/" >&2
    exit 1
fi

for f in "${units[@]}"; do
    before=$failures
    static_check "$f"
    [ "$failures" -eq "$before" ] && echo "OK   $f: sandbox directives present, loopback bind"
    analyze_check "$f"
done

if [ "$failures" -gt 0 ]; then
    echo "$failures problem(s) found" >&2
    exit 1
fi
echo "all ${#units[@]} unit file(s) passed"
