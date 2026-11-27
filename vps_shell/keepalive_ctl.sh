#!/usr/bin/env bash
# Install (or remove) the adb-keepalive systemd service.
#
# Safe to call on every recon.sh --update: it stays silent and exits 0 unless
# this host is root, has adb installed, and actually owns an adb server for a
# network device. Override the owner or targets with ADB_KEEPALIVE_USER and
# ADB_KEEPALIVE_SERIALS.
#
#   sudo bash vps_shell/keepalive_ctl.sh
#   sudo bash vps_shell/keepalive_ctl.sh --uninstall
set -euo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
UNIT_FILE=/etc/systemd/system/adb-keepalive.service
BIN_FILE=/usr/local/bin/adb-keepalive.sh
RECON_HOME=${RECON_PRO_HOME:-${HOME:-.}/recon_pro}
CONFIG_FILE="${RECON_HOME%/}/state/recon_pro.conf"

if [[ "${1:-}" == "--uninstall" ]]; then
    if (( EUID != 0 )); then
        printf 'Jalankan sebagai root: sudo bash %s --uninstall\n' "${BASH_SOURCE[0]}" >&2
        exit 1
    fi
    systemctl disable --now adb-keepalive.service >/dev/null 2>&1 || true
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

# The adb server is per user, so the keepalive must run as the account that
# already owns it; a second server under another user would keep nothing alive.
owner=${ADB_KEEPALIVE_USER:-}
if [[ -z "$owner" ]]; then
    owner=$(ps -eo user=,args= 2>/dev/null | awk '/\[adb\].*fork-server/ {print $1; exit}')
fi
[[ -n "$owner" ]] || skip "tidak menemukan adb server yang jalan (docker/container?)"
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

cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Keep adb devices connected
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=${owner}
Environment=HOME=${home}
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
printf 'adb-keepalive: %s (user %s, target %s)\n' \
    "$(systemctl is-active adb-keepalive.service 2>/dev/null || true)" "$owner" "$serials"
