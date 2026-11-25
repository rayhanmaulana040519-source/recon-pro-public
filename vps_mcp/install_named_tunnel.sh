#!/usr/bin/env bash
# Install the Recon Pro MCP updater and a Cloudflare named-tunnel connector as
# persistent systemd services. Run with sudo from the repository checkout.
set -euo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PROJECT_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd -P)

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

if (( EUID != 0 )); then
    fail "Jalankan sebagai root: sudo bash vps_mcp/install_named_tunnel.sh"
fi

[[ -f "${PROJECT_DIR}/recon.sh" && -f "${SCRIPT_DIR}/server.py" ]] || fail "Checkout Recon Pro tidak lengkap."
command -v systemctl >/dev/null 2>&1 || fail "systemd/systemctl tidak tersedia pada host ini."
command -v runuser >/dev/null 2>&1 || fail "Perintah runuser tidak tersedia."
command -v cloudflared >/dev/null 2>&1 || fail "cloudflared belum terpasang. Pasang dari dokumentasi resmi Cloudflare terlebih dahulu."
command -v git >/dev/null 2>&1 || fail "Git belum terpasang."

# Run the updater as the checkout owner so it uses that account's Git access.
SERVICE_USER=$(stat -c '%U' "${PROJECT_DIR}/.git" 2>/dev/null || stat -c '%U' "$PROJECT_DIR")
[[ -n "$SERVICE_USER" ]] || fail "Tidak dapat menemukan pemilik checkout Git."
SERVICE_GROUP=$(id -gn "$SERVICE_USER")
SERVICE_HOME=$(getent passwd "$SERVICE_USER" | cut -d: -f6)
[[ -n "$SERVICE_HOME" && -d "$SERVICE_HOME" ]] || fail "Home untuk akun ${SERVICE_USER} tidak ditemukan."

# Keep systemd unit values simple and unambiguous.
for path_value in "$PROJECT_DIR" "$SCRIPT_DIR" "$SERVICE_HOME"; do
    [[ "$path_value" =~ ^[A-Za-z0-9_./-]+$ ]] || fail "Path mengandung karakter yang tidak didukung systemd: ${path_value}"
done

RECON_HOME=${RECON_PRO_HOME:-${SERVICE_HOME}/recon_pro}
[[ "$RECON_HOME" = /* ]] || fail "RECON_PRO_HOME harus berupa path absolut."
[[ "$RECON_HOME" =~ ^[A-Za-z0-9_./-]+$ ]] || fail "RECON_PRO_HOME mengandung karakter yang tidak didukung systemd."
if [[ ! -e "$RECON_HOME" ]]; then
    install -d -m 750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$RECON_HOME"
fi
[[ -d "$RECON_HOME" ]] || fail "RECON_PRO_HOME bukan direktori."
RECON_HOME=$(cd -- "$RECON_HOME" && pwd -P)
[[ "$RECON_HOME" =~ ^[A-Za-z0-9_./-]+$ ]] || fail "Path hasil resolve RECON_PRO_HOME tidak didukung systemd."
STATE_DIR="${RECON_HOME}/state"
KEY_FILE="${STATE_DIR}/mcp_api_key"
ENV_FILE="${STATE_DIR}/mcp.env"
HOST_FILE="${STATE_DIR}/mcp_hostname"
VENV="${SCRIPT_DIR}/.venv"
UNIT_FILE=/etc/systemd/system/recon-pro-mcp.service

run_as_service_user() {
    runuser -u "$SERVICE_USER" -- env HOME="$SERVICE_HOME" "$@"
}

run_as_service_user git -C "$PROJECT_DIR" rev-parse --show-toplevel >/dev/null 2>&1 || fail "Akun ${SERVICE_USER} tidak dapat membaca checkout Git."
run_as_service_user test -x "$RECON_HOME" 2>/dev/null || fail "Akun ${SERVICE_USER} tidak dapat mengakses RECON_PRO_HOME: ${RECON_HOME}."

PYTHON_BIN=""
for candidate in python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
        PYTHON_BIN=$(command -v "$candidate")
        break
    fi
done
[[ -n "$PYTHON_BIN" ]] || fail "Python 3.11+ diperlukan."

if [[ -s "$HOST_FILE" ]]; then
    SAVED_HOST=$(cat -- "$HOST_FILE")
else
    SAVED_HOST=""
fi
if [[ -t 0 ]]; then
    read -r -p "Hostname publik dari route Cloudflare (contoh mcp.domainkamu.id)${SAVED_HOST:+ [${SAVED_HOST}]}: " PUBLIC_HOST
else
    fail "Perlu terminal interaktif untuk memasukkan hostname dan token tunnel dengan aman."
fi
PUBLIC_HOST=${PUBLIC_HOST:-$SAVED_HOST}
PUBLIC_HOST=${PUBLIC_HOST,,}
[[ -n "$PUBLIC_HOST" ]] || fail "Hostname publik wajib diisi."
"$PYTHON_BIN" - "$PUBLIC_HOST" <<'PY' || fail "Format hostname tidak valid."
import re
import sys
host = sys.argv[1]
labels = host.split(".")
if len(host) > 253 or len(labels) < 2 or any(
    not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
    for label in labels
):
    raise SystemExit(1)
PY

if systemctl cat cloudflared.service >/dev/null 2>&1; then
    if ! systemctl is-active --quiet cloudflared.service; then
        fail "cloudflared.service sudah ada tetapi tidak aktif. Periksa dengan: systemctl status cloudflared --no-pager. Tidak akan menimpa konfigurasi tunnel yang ada."
    fi
    INSTALL_CLOUDFLARED=0
    printf 'cloudflared.service sudah aktif; akan memakai connector yang ada. Pastikan route hostname ini memakai tunnel tersebut.\n'
else
    INSTALL_CLOUDFLARED=1
    printf 'Ambil Tunnel Token dari Cloudflare Zero Trust > Networks > Tunnels > tunnel kamu > Install connector.\n'
    printf 'Token hanya dimasukkan ke prompt terminal VPS ini, jangan kirim ke chat.\n'
    read -r -s -p 'Cloudflare Tunnel Token: ' TUNNEL_TOKEN
    printf '\n'
    [[ -n "$TUNNEL_TOKEN" ]] || fail "Tunnel token tidak boleh kosong."
fi

if [[ -s "$KEY_FILE" ]]; then
    API_KEY=$(cat -- "$KEY_FILE")
else
    API_KEY=$("$PYTHON_BIN" -c 'import secrets; print(secrets.token_urlsafe(48))')
fi
[[ "$API_KEY" =~ ^[A-Za-z0-9_-]{40,}$ ]] || fail "Kunci MCP lokal tidak valid. Rotasi/hapus state/mcp_api_key lalu jalankan ulang."

# The named-tunnel listener and this MCP service must not compete with Quick Tunnel.
if "$PYTHON_BIN" - <<'PY' >/dev/null 2>&1
import socket
with socket.create_connection(("127.0.0.1", 8766), timeout=0.4):
    pass
PY
then
    fail "Port 8766 sudah dipakai. Hentikan service MCP/Quick Tunnel lama sebelum melanjutkan; script tidak akan menghentikan proses lain."
fi

install -d -m 700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$STATE_DIR"
if [[ -d "$VENV" ]]; then
    chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "$VENV"
fi
if [[ ! -x "${VENV}/bin/python" ]]; then
    run_as_service_user "$PYTHON_BIN" -m venv "$VENV"
fi
run_as_service_user "${VENV}/bin/python" -m pip install --disable-pip-version-check -r "${SCRIPT_DIR}/requirements.txt"

KEY_TMP=$(mktemp "${STATE_DIR}/.mcp_api_key.XXXXXX")
printf '%s\n' "$API_KEY" > "$KEY_TMP"
chmod 600 "$KEY_TMP"
chown "${SERVICE_USER}:${SERVICE_GROUP}" "$KEY_TMP"
mv -f -- "$KEY_TMP" "$KEY_FILE"

ENV_TMP=$(mktemp "${STATE_DIR}/.mcp_env.XXXXXX")
printf 'RECON_MCP_API_KEY=%s\n' "$API_KEY" > "$ENV_TMP"
chmod 600 "$ENV_TMP"
chown "${SERVICE_USER}:${SERVICE_GROUP}" "$ENV_TMP"
mv -f -- "$ENV_TMP" "$ENV_FILE"

HOST_TMP=$(mktemp "${STATE_DIR}/.mcp_hostname.XXXXXX")
printf '%s\n' "$PUBLIC_HOST" > "$HOST_TMP"
chmod 600 "$HOST_TMP"
chown "${SERVICE_USER}:${SERVICE_GROUP}" "$HOST_TMP"
mv -f -- "$HOST_TMP" "$HOST_FILE"
printf 'https://%s/mcp\n' "$PUBLIC_HOST" > "${STATE_DIR}/mcp_url"
chmod 600 "${STATE_DIR}/mcp_url"
chown "${SERVICE_USER}:${SERVICE_GROUP}" "${STATE_DIR}/mcp_url"

cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Recon Pro VPS MCP updater
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${SCRIPT_DIR}
Environment=RECON_PRO_ROOT=${PROJECT_DIR}
Environment=RECON_PRO_HOME=${RECON_HOME}
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV}/bin/uvicorn server:app --host 127.0.0.1 --port 8766 --no-access-log
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
chmod 644 "$UNIT_FILE"

if (( INSTALL_CLOUDFLARED )); then
    if ! cloudflared service install "$TUNNEL_TOKEN"; then
        unset TUNNEL_TOKEN
        fail "Cloudflare connector gagal dipasang. Periksa token dan status cloudflared; MCP tetap belum diekspos."
    fi
    unset TUNNEL_TOKEN
fi

systemctl daemon-reload
systemctl enable --now cloudflared.service
systemctl enable --now recon-pro-mcp.service

printf '\nSetup selesai. Hostname MCP: https://%s/mcp\n' "$PUBLIC_HOST"
printf 'Pastikan Published application route di Cloudflare mengarah ke http://127.0.0.1:8766. Jangan buka port 8766 di firewall.\n'
printf 'Status: systemctl status cloudflared recon-pro-mcp --no-pager\n'
printf 'API key tersimpan lokal di: %s\n' "$KEY_FILE"
printf 'Masukkan URL dan key langsung ke FreeMilk > Integrations; jangan kirim key lewat chat.\n'
if [[ "$SERVICE_USER" == root ]]; then
    printf 'PERINGATAN: updater berjalan sebagai root karena root memiliki checkout. Untuk keamanan lebih baik, pindahkan checkout ke akun Linux non-root sebelum memakai koneksi permanen.\n'
fi
