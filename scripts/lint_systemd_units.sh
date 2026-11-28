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

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Print the unit normalized: CR removed, whitespace trimmed (also around the
# first "="), comment and blank lines dropped (comments inside a backslash
# continuation are ignored, as in systemd.syntax(7)), continuations joined.
normalize() {
    awk '
        { sub(/\r$/, ""); sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, "") }
        /^[#;]/ { next }
        !cont && $0 == "" { next }
        { line = cont ? line " " $0 : $0 }
        line ~ /\\$/ { sub(/[[:space:]]*\\$/, "", line); cont = 1; next }
        { cont = 0
          if (line !~ /^\[/) { i = index(line, "="); if (i) { k = substr(line, 1, i - 1); v = substr(line, i + 1); sub(/[[:space:]]+$/, "", k); sub(/^[[:space:]]+/, "", v); line = k "=" v } }
          print line; line = "" }
        END { if (cont) print line }
    ' "$1"
}

# All assignments of KEY in SECTION, one per line, honouring an empty
# assignment as a reset (systemd drops everything assigned before it).
values() {
    local section="$1" key="$2" file="$3"
    normalize "$file" | awk -v sec="[$section]" -v key="$key" '
        /^\[/ { cur = $0; next }
        cur == sec {
            i = index($0, "=")
            if (i && substr($0, 1, i - 1) == key) {
                v = substr($0, i + 1)
                if (v == "") { n = 0 } else { vals[++n] = v }
            }
        }
        END { for (j = 1; j <= n; j++) print vals[j] }
    '
}

# Effective value of a single-valued directive: the last assignment ("" when absent).
value() { values "$@" | tail -n 1; }

has_section() {
    local sections
    sections="$(normalize "$2")"
    [[ $'\n'"$sections"$'\n' == *$'\n'"[$1]"$'\n'* ]]
}

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
    require_value "$f" Service ProtectSystem 'strict|full|true|yes|1|on'
    require_value "$f" Service ProtectHome 'true|yes|1|on|read-only|tmpfs'

    for s in User Group; do
        v="$(value Service "$s" "$f")"
        if [ -z "$v" ] || [ "$v" = root ] || [ "$v" = 0 ]; then
            fail "$f" "[Service] $s must be a dedicated non-root account, got '${v:-unset}'"
        fi
    done

    [ -n "$(value Service ReadWritePaths "$f")" ] ||
        fail "$f" "[Service] ReadWritePaths must list the vault state dir (ProtectSystem is read-only otherwise)"

    local execs
    execs="$(values Service ExecStart "$f")"
    if [ -z "$execs" ]; then
        fail "$f" "[Service] ExecStart is missing"
    else
        while IFS= read -r v; do
            if [[ "$v" == [+!]* ]]; then
                fail "$f" "[Service] ExecStart must not use a privilege prefix (+ or !): $v"
            fi
            if [[ "$v" =~ --host(=|[[:space:]]+)(0\.0\.0\.0|\[?::\]?)([[:space:]]|$) ]]; then
                fail "$f" "[Service] ExecStart must not bind a wildcard address"
            fi
            if ! [[ "$v" =~ (^|[[:space:]])--host(=|[[:space:]]+)127\.0\.0\.1([[:space:]]|$) ]]; then
                fail "$f" "[Service] ExecStart must bind --host 127.0.0.1 (loopback only)"
            fi
            if [ "$(grep -o -- '--host' <<<"$v" | wc -l)" -ne 1 ]; then
                fail "$f" "[Service] ExecStart must pass --host exactly once"
            fi
        done <<<"$execs"
    fi

    # The Go daemon runs in production mode (RGT-427): a unit that starts
    # `rgt-vault serve` must set APP_ENV=production.
    if grep -qE '(^|[/[:space:]])rgt-vault[[:space:]]+serve([[:space:]]|$)' <<<"$execs"; then
        if ! values Service Environment "$f" | grep -qE '(^|[[:space:]"])APP_ENV=production("|[[:space:]]|$)'; then
            fail "$f" "[Service] a unit running 'rgt-vault serve' must set Environment=APP_ENV=production"
        fi
    fi

    [ -n "$(value Install WantedBy "$f")" ] || fail "$f" "[Install] WantedBy is missing"

    # RestrictAddressFamilies is cumulative: check every assignment. Require an
    # allow-list (no leading "~") that excludes raw packet / netlink sockets.
    v="$(values Service RestrictAddressFamilies "$f" | tr '\n' ' ')"
    if [ -z "${v// /}" ]; then
        fail "$f" "[Service] RestrictAddressFamilies must be set"
    elif [[ "$v" == *"~"* ]]; then
        fail "$f" "[Service] RestrictAddressFamilies must be an allow-list, not a '~' deny-list"
    elif [[ "$v" == *AF_PACKET* || "$v" == *AF_NETLINK* ]]; then
        fail "$f" "[Service] RestrictAddressFamilies must not allow AF_PACKET or AF_NETLINK"
    fi
}

analyze_check() {
    local f="$1" copy out relevant last
    if [ "${SKIP_SYSTEMD_ANALYZE:-0}" = 1 ] || ! command -v systemd-analyze >/dev/null 2>&1; then
        echo "NOTE $f: systemd-analyze unavailable or disabled; static checks only"
        return 0
    fi
    copy="$tmp/$(basename "$f")"
    # The real binaries are not installed on a CI runner: keep one ExecStart=
    # (/bin/true) and drop the other Exec* commands before verifying.
    normalize "$f" | awk '
        /^Exec(Start|StartPre|StartPost|Stop|StopPost|Reload|Condition)=/ { next }
        { print }
        $0 == "[Service]" { print "ExecStart=/bin/true" }
    ' > "$copy"

    if ! out="$(systemd-analyze verify "$copy" 2>&1)"; then
        fail "$f" "systemd-analyze verify failed:
$out"
        return 0
    fi
    # verify also loads unrelated units of the runner image; only messages
    # about this unit count (they are prefixed with its path).
    relevant="$(grep -F -- "$copy" <<<"$out" || true)"
    if [ -n "$relevant" ]; then
        fail "$f" "systemd-analyze verify reported problems:
$relevant"
    else
        echo "OK   $f: systemd-analyze verify"
    fi

    # Informational only: never gates (scoring differs between systemd releases).
    if out="$(systemd-analyze security --offline=true --no-pager "$copy" 2>&1)"; then
        last="$(tail -n 1 <<<"$out")"
        printf 'INFO %s: %s\n' "$f" "$last"
    fi
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
    if [ ! -r "$f" ]; then
        fail "$f" "cannot read unit file"
        continue
    fi
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
