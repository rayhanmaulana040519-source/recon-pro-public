#!/usr/bin/env bash
# Install (or remove) the adb-keepalive service.
#
# Safe to call on every recon.sh --update: it explains itself in one line and
# exits 0 unless this host is root, has adb installed, and already owns an adb
# server for a network device. Override the owner or targets with
# ADB_KEEPALIVE_USER and ADB_KEEPALIVE_SERIALS.
#
#   sudo bash vps_shell/keepalive_ctl.sh
#   sudo bash vps_shell/keepalive_ctl.sh --uninstall
set -euo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
RECON_HOME=${RECON_PRO_HOME:-${HOME:-.}/recon_pro}
STATE_DIR="${RECON_HOME%/}/state"
CONFIG_FILE="${STATE_DIR}/recon_pro.conf"
BIN_FILE="${STATE_DIR}/adb-keepalive.sh"
PID_FILE="${STATE_DIR}/adb-keepalive.pid"
LOG_FILE="${STATE_DIR}/adb-keepalive.log"
UNIT_FILE=/etc/systemd/system/adb-keepalive.service

if [[ "${1:-}" == "--uninstall" ]]; then
    (( EUID == 0 )) || { printf 'Jalankan sebagai root: sudo bash %s --uninstall\n' "${BASH_SOURCE[0]}" >&2; exit 1; }
    systemctl disable --now adb-keepalive.service >/dev/null 2>&1 || true
    systemctl stop adb-keepalive.service >/dev/null 2>&1 || true
    systemctl reset-failed adb-keepalive.service >/dev/null 2>&1 || true
    if [[ -s "$PID_FILE" ]]; then
        old=$(cat -- "$PID_FILE")
        [[ "$old" =~ ^[0-9]+$ ]] && kill "$old" 2>/dev/null || true
        rm -f -- "$PID_FILE"
    fi
    rm -f -- "$UNIT_FILE" "$BIN_FILE"
    systemctl daemon-reload >/dev/null 2>&1 || true
    printf 'adb-keepalive dihentikan dan dihapus.\n'
    exit 0
fi

skip() {
    printf 'adb-keepalive: dilewati (%s)\n' "$*"
    exit 0
}

# Only a root host with systemd and adb can hold this service.
(( EUID == 0 )) || skip "bukan root"
command -v systemctl >/dev/null 2>&1 || skip "systemctl tidak ada"
[[ -f "${SCRIPT_DIR}/adb_keepalive.sh" ]] || skip "adb_keepalive.sh tidak ada"
if grep -qiE '^[[:space:]]*ADB_KEEPALIVE[[:space:]]*=[[:space:]]*0' "$CONFIG_FILE" 2>/dev/null; then
    skip "ADB_KEEPALIVE=0 di config"
fi

# adb is often installed outside the PATH systemd gives this service.
if ! command -v adb >/dev/null 2>&1; then
    for candidate in \
        "${HOME}/Android/Sdk/platform-tools/adb" \
        "${HOME}/platform-tools/adb" \
        "${HOME}/android-sdk/platform-tools/adb" \
        /opt/android-sdk/platform-tools/adb \
        /usr/lib/android-sdk/platform-tools/adb \
        /usr/local/platform-tools/adb; do
        if [[ -x "$candidate" ]]; then
            PATH="$(dirname "$candidate")${PATH:+:${PATH}}"
            export PATH
            break
        fi
    done
fi
command -v adb >/dev/null 2>&1 || skip "adb tidak ada di PATH (${PATH})"

# One-line context for the "no adb server" case: it is usually a container or a
# server started by another tool.
ADB_KEEPALIVE_HINT=${ADB_KEEPALIVE_HINT:-"adb=$(command -v adb 2>/dev/null || echo none); proses=$(
    ps -eo args= 2>/dev/null | grep -c '[a]db' || true); port5037=$(
    (command -v ss >/dev/null 2>&1 && ss -ltnp 2>/dev/null | grep ':5037' | head -1 | tr -s ' ' || true) | paste -sd' ' -); docker=$(
    (command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}:{{.Image}}' 2>/dev/null | head -3 || true) | paste -sd',' -)"}

# The adb server is per user, so the keepalive must run as the account that
# already owns it; a second server under another user would keep nothing alive.
owner=${ADB_KEEPALIVE_USER:-}
if [[ -z "$owner" ]]; then
    server_pid=$(ss -ltnp 2>/dev/null | grep ':5037 ' | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2 || true)
    if [[ -n "$server_pid" ]]; then
        owner=$(ps -o user= -p "$server_pid" 2>/dev/null | tr -d ' ')
    fi
fi
if [[ -z "$owner" ]]; then
    # The server rewrites its own title to "[adb] -L ... fork-server", but some
    # builds keep the plain command line, so both forms are accepted.
    owner=$(ps -eo user=,args= 2>/dev/null | awk '
        /fork-server/ && ($0 ~ /\[adb\]/ || $0 ~ /(^|[\/ ])adb /) {print $1; exit}')
fi
[[ -n "$owner" ]] || skip "tidak menemukan adb server yang jalan (${ADB_KEEPALIVE_HINT:-})"
home=$(getent passwd "$owner" 2>/dev/null | cut -d: -f6)
[[ -n "$home" && -d "$home" ]] || skip "home untuk user ${owner} tidak ada"

serials=${ADB_KEEPALIVE_SERIALS:-}
if [[ -z "$serials" ]]; then
    serials=$(runuser -u "$owner" -- env HOME="$home" adb devices 2>/dev/null \
        | awk '$2 == "device" && $1 ~ /:[0-9]+$/ {print $1}' | paste -sd' ' - || true)
fi
[[ -n "$serials" ]] || skip "tidak ada device adb ip:port yang connected"

interval=${ADB_KEEPALIVE_INTERVAL:-5}
install -m 755 "${SCRIPT_DIR}/adb_keepalive.sh" "$BIN_FILE"

# 1. A real unit survives reboots, when /etc is writable for this caller.
if [[ -w /etc/systemd/system ]]; then
    cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Keep adb devices connected
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=${owner}
Environment=HOME=${home}
Environment=PATH=${PATH}
Environment=ADB_KEEPALIVE_SERIALS=${serials}
Environment=ADB_KEEPALIVE_INTERVAL=${interval}
ExecStart=${BIN_FILE}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$UNIT_FILE"
    systemctl daemon-reload
    systemctl enable adb-keepalive.service >/dev/null 2>&1 || true
    systemctl restart adb-keepalive.service
    printf 'adb-keepalive: %s (unit persisten, user %s, target %s)\n' \
        "$(systemctl is-active adb-keepalive.service 2>/dev/null || true)" "$owner" "$serials"
    exit 0
fi

# 2. The caller is sandboxed (Recon Pro's MCP unit mounts /etc and /usr
#    read-only). Ask systemd for a transient unit of the same name instead.
if command -v systemd-run >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    if systemctl is-active --quiet adb-keepalive.service; then
        printf 'adb-keepalive: %s (unit transient, user %s, target %s)\n' \
            "active" "$owner" "$serials"
        exit 0
    fi
    systemctl reset-failed adb-keepalive.service >/dev/null 2>&1 || true
    if systemd-run --unit=adb-keepalive --collect \
        --description="Keep adb devices connected" \
        --property=User="$owner" \
        --property=Restart=always \
        --property=RestartSec=5 \
        --property=Environment="HOME=$home" \
        --property=Environment="PATH=$PATH" \
        --property=Environment="ADB_KEEPALIVE_SERIALS=$serials" \
        --property=Environment="ADB_KEEPALIVE_INTERVAL=$interval" \
        /bin/bash "$BIN_FILE" >/dev/null 2>&1; then
        printf 'adb-keepalive: %s (unit transient, user %s, target %s)\n' \
            "$(systemctl is-active adb-keepalive.service 2>/dev/null || true)" "$owner" "$serials"
        exit 0
    fi
fi

# 3. Last resort: a detached process, re-created on the next update.
if [[ -s "$PID_FILE" ]]; then
    old=$(cat -- "$PID_FILE")
    [[ "$old" =~ ^[0-9]+$ ]] && kill "$old" 2>/dev/null || true
    rm -f -- "$PID_FILE"
fi
setsid nohup runuser -u "$owner" -- env HOME="$home" PATH="$PATH" \
    ADB_KEEPALIVE_SERIALS="$serials" ADB_KEEPALIVE_INTERVAL="$interval" \
    /bin/bash "$BIN_FILE" </dev/null >>"$LOG_FILE" 2>&1 &
printf '%s\n' "$!" > "$PID_FILE"
printf 'adb-keepalive: proses detached (user %s, target %s, log %s)\n' "$owner" "$serials" "$LOG_FILE"
