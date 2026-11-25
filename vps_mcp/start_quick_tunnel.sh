#!/usr/bin/env bash
# Start the narrow MCP updater on loopback and expose it using a temporary
# Cloudflare Quick Tunnel. The API key remains in RECON_PRO_HOME/state.
set -euo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
RECON_HOME=$(cd -- "${RECON_PRO_HOME:-${HOME:-.}/recon_pro}" && pwd -P 2>/dev/null || {
    mkdir -p -- "${RECON_PRO_HOME:-${HOME:-.}/recon_pro}"
    cd -- "${RECON_PRO_HOME:-${HOME:-.}/recon_pro}" && pwd -P
})
STATE_DIR="${RECON_HOME}/state"
KEY_FILE="${STATE_DIR}/mcp_api_key"
URL_FILE="${STATE_DIR}/mcp_url"
MCP_PID_FILE="${STATE_DIR}/mcp.pid"
TUNNEL_PID_FILE="${STATE_DIR}/cloudflared.pid"
MCP_LOG="${STATE_DIR}/mcp.log"
TUNNEL_LOG="${STATE_DIR}/cloudflared.log"
VENV="${SCRIPT_DIR}/.venv"

mkdir -p -- "$STATE_DIR"
chmod 700 "$STATE_DIR" 2>/dev/null || true

if ! command -v cloudflared >/dev/null 2>&1; then
    printf 'cloudflared belum terpasang. Pasang dari dokumentasi resmi: https://developers.cloudflare.com/tunnel/downloads/\n' >&2
    exit 1
fi

PYTHON_BIN=""
for candidate in python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
        PYTHON_BIN=$(command -v "$candidate")
        break
    fi
done
if [[ -z "$PYTHON_BIN" ]]; then
    printf 'Python 3.11+ diperlukan untuk SDK MCP.\n' >&2
    exit 1
fi

if [[ -s "$MCP_PID_FILE" && -s "$TUNNEL_PID_FILE" ]]; then
    mcp_pid=$(cat -- "$MCP_PID_FILE")
    tunnel_pid=$(cat -- "$TUNNEL_PID_FILE")
    if [[ "$mcp_pid" =~ ^[0-9]+$ && "$tunnel_pid" =~ ^[0-9]+$ ]] && kill -0 "$mcp_pid" 2>/dev/null && kill -0 "$tunnel_pid" 2>/dev/null; then
        if [[ -s "$URL_FILE" ]]; then
            printf 'MCP dan tunnel sudah berjalan. Endpoint: %s/mcp\n' "$(cat -- "$URL_FILE")"
            exit 0
        fi
    fi
fi

if [[ ! -x "${VENV}/bin/python" ]]; then
    "$PYTHON_BIN" -m venv "$VENV"
fi
"${VENV}/bin/python" -m pip install --disable-pip-version-check -r "${SCRIPT_DIR}/requirements.txt"

if [[ ! -s "$KEY_FILE" ]]; then
    (set -o noclobber; "$PYTHON_BIN" -c 'import secrets; print(secrets.token_urlsafe(48))' > "$KEY_FILE") 2>/dev/null || true
fi
if [[ ! -s "$KEY_FILE" ]]; then
    printf 'Gagal membuat kunci MCP lokal.\n' >&2
    exit 1
fi
chmod 600 "$KEY_FILE" 2>/dev/null || true
API_KEY=$(cat -- "$KEY_FILE")
if (( ${#API_KEY} < 40 )); then
    printf 'Kunci MCP di %s terlalu pendek; hapus lalu jalankan ulang.\n' "$KEY_FILE" >&2
    exit 1
fi

if "$PYTHON_BIN" - "$MCP_PID_FILE" <<'PY'
import socket, sys
try:
    with socket.create_connection(("127.0.0.1", 8766), timeout=0.4):
        raise SystemExit(0)
except OSError:
    raise SystemExit(1)
PY
then
    printf 'Port 8766 sudah dipakai. Tidak akan mengganti proses yang ada.\n' >&2
    exit 1
fi

rm -f -- "$URL_FILE"
: > "$MCP_LOG"
: > "$TUNNEL_LOG"
(
    cd -- "$SCRIPT_DIR"
    export RECON_PRO_ROOT="$PROJECT_DIR"
    export RECON_PRO_HOME="$RECON_HOME"
    export RECON_MCP_API_KEY="$API_KEY"
    export GIT_TERMINAL_PROMPT=0
    export GCM_INTERACTIVE=Never
    nohup "$VENV/bin/uvicorn" server:app --host 127.0.0.1 --port 8766 --no-access-log \
        </dev/null >>"$MCP_LOG" 2>&1 &
    printf '%s\n' "$!" > "$MCP_PID_FILE"
)

ready=0
for _ in {1..30}; do
    if "$PYTHON_BIN" - <<'PY' >/dev/null 2>&1
import socket
with socket.create_connection(("127.0.0.1", 8766), timeout=0.4):
    pass
PY
    then
        ready=1
        break
    fi
    if ! kill -0 "$(cat -- "$MCP_PID_FILE")" 2>/dev/null; then
        break
    fi
    sleep 1
done
if (( ! ready )); then
    printf 'MCP server gagal start. Log terakhir:\n' >&2
    tail -n 30 "$MCP_LOG" >&2 2>/dev/null || true
    if [[ -s "$MCP_PID_FILE" ]]; then
        pid=$(cat -- "$MCP_PID_FILE")
        [[ "$pid" =~ ^[0-9]+$ ]] && kill "$pid" 2>/dev/null || true
        rm -f -- "$MCP_PID_FILE"
    fi
    exit 1
fi

nohup cloudflared tunnel --url http://127.0.0.1:8766 </dev/null >>"$TUNNEL_LOG" 2>&1 &
printf '%s\n' "$!" > "$TUNNEL_PID_FILE"

PUBLIC_URL=""
for _ in {1..30}; do
    PUBLIC_URL=$(grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' "$TUNNEL_LOG" 2>/dev/null | tail -n 1 || true)
    if [[ -n "$PUBLIC_URL" ]]; then
        break
    fi
    if ! kill -0 "$(cat -- "$TUNNEL_PID_FILE")" 2>/dev/null; then
        break
    fi
    sleep 1
done

if [[ -z "$PUBLIC_URL" ]]; then
    printf 'Quick Tunnel belum memberikan URL. Log terakhir:\n' >&2
    tail -n 30 "$TUNNEL_LOG" >&2 2>/dev/null || true
    for pid_file in "$TUNNEL_PID_FILE" "$MCP_PID_FILE"; do
        if [[ -s "$pid_file" ]]; then
            pid=$(cat -- "$pid_file")
            [[ "$pid" =~ ^[0-9]+$ ]] && kill "$pid" 2>/dev/null || true
            rm -f -- "$pid_file"
        fi
    done
    exit 1
fi

printf '%s\n' "$PUBLIC_URL" > "$URL_FILE"
chmod 600 "$URL_FILE" 2>/dev/null || true
printf '\nMCP endpoint: %s/mcp\n' "$PUBLIC_URL"
printf 'API key tersimpan lokal di: %s\n' "$KEY_FILE"
printf 'Masukkan key tersebut langsung ke konfigurasi integrasi FreeMilk; jangan kirim lewat chat.\n'
printf 'Untuk berhenti: bash %s/stop_quick_tunnel.sh\n' "$SCRIPT_DIR"
printf 'URL Quick Tunnel berubah setiap kali tunnel dibuat ulang.\n'
