#!/usr/bin/env bash
# Keep adb-over-TCP devices connected.
#
# The adb server owns the transport, so this loop has to run as the user that
# owns that server. keepalive_ctl.sh writes the unit that way; run it by hand
# only for debugging.
#
# Knobs: ADB_KEEPALIVE_SERIALS ("host:port" list), ADB_KEEPALIVE_INTERVAL
# (seconds between checks while healthy, default 5), ADB_KEEPALIVE_FAST_INTERVAL
# (while a device is down, default 1), ADB_KEEPALIVE_RESTART_AFTER (failed
# rounds before the adb server itself is restarted, default 6),
# ADB_KEEPALIVE_HEARTBEAT (seconds between "still ok" lines, default 300).
set -uo pipefail

INTERVAL=${ADB_KEEPALIVE_INTERVAL:-5}
FAST_INTERVAL=${ADB_KEEPALIVE_FAST_INTERVAL:-1}
RESTART_AFTER=${ADB_KEEPALIVE_RESTART_AFTER:-6}
HEARTBEAT=${ADB_KEEPALIVE_HEARTBEAT:-300}
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

log "keepalive start (interval ${INTERVAL}s, fast ${FAST_INTERVAL}s, targets ${TARGETS:-auto})"

prev=""
down_streak=0
last_heartbeat=$(date +%s)

while :; do
    table=$(adb devices 2>/dev/null)
    if ! grep -q 'List of devices attached' <<<"$table"; then
        # The client above normally starts a server; this covers a wedged one
        # that answered with nothing at all.
        adb start-server >/dev/null 2>&1
        table=$(adb devices 2>/dev/null)
    fi

    line=""
    down=0
    for serial in $(discover); do
        state=$(state_of "$serial" "$table")
        if [[ "$state" != "device" ]]; then
            adb disconnect "$serial" >/dev/null 2>&1
            adb connect "$serial" >/dev/null 2>&1
            state=$(state_of "$serial" "$(adb devices 2>/dev/null)")
        fi
        [[ "$state" == "device" ]] || down=1
        line="${line}${serial}=${state} "
    done
    line=${line% }

    if [[ "$line" != "$prev" ]]; then
        log "devices: ${line:-none}"
        prev=$line
    fi

    if (( down )); then
        down_streak=$((down_streak + 1))
        if (( down_streak >= RESTART_AFTER )); then
            log "adb server belum sehat setelah ${down_streak} putaran; restart server"
            adb kill-server >/dev/null 2>&1
            adb start-server >/dev/null 2>&1
            down_streak=0
        fi
        sleep "$FAST_INTERVAL"
    else
        down_streak=0
        now=$(date +%s)
        if (( now - last_heartbeat >= HEARTBEAT )); then
            log "ok: ${line:-none}"
            last_heartbeat=$now
        fi
        sleep "$INTERVAL"
    fi
done
