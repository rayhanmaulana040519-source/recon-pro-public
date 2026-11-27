#!/usr/bin/env bash
# Keep adb-over-TCP devices connected.
#
# The adb server owns the transport, so this loop has to run as the user that
# owns that server. keepalive_ctl.sh writes the systemd unit that way; run it
# by hand only for debugging.
set -uo pipefail

INTERVAL=${ADB_KEEPALIVE_INTERVAL:-5}
TARGETS=${ADB_KEEPALIVE_SERIALS:-}

log() {
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

discover() {
    {
        [[ -n "$TARGETS" ]] && printf '%s\n' "$TARGETS" | tr ' ' '\n'
        adb devices 2>/dev/null | awk '$1 ~ /:[0-9]+$/ {print $1}'
    } | awk 'NF && !seen[$0]++'
}

state_of() {
    awk -v s="$1" '$1 == s {print $2; found = 1} END {if (!found) print "absent"}' <<<"$2"
}

log "keepalive start (interval ${INTERVAL}s, targets ${TARGETS:-auto})"

prev=""
while :; do
    table=$(adb devices 2>/dev/null)
    line=""
    for serial in $(discover); do
        state=$(state_of "$serial" "$table")
        if [[ "$state" != "device" ]]; then
            adb disconnect "$serial" >/dev/null 2>&1
            adb connect "$serial" >/dev/null 2>&1
            state=$(state_of "$serial" "$(adb devices 2>/dev/null)")
        fi
        line="${line}${serial}=${state} "
    done
    line=${line% }
    if [[ "$line" != "$prev" ]]; then
        log "devices: ${line:-none}"
        prev=$line
    fi
    sleep "$INTERVAL"
done
