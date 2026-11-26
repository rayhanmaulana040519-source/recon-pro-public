#!/usr/bin/env bash
# Start the local dashboard with a persistent, private access token.
set -euo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
RECON_HOME="${RECON_PRO_HOME:-${HOME:-.}/recon_pro}"
STATE_DIR="${RECON_HOME%/}/state"
TOKEN_FILE="${STATE_DIR}/web_token"

PYTHON_BIN="$(command -v python3 || command -v python || true)"
if [[ -z "$PYTHON_BIN" ]]; then
    if [[ -n "${TERMUX_VERSION:-}" || "${PREFIX:-}" == *com.termux* ]]; then
        printf 'ERROR: Python belum terpasang. Jalankan: pkg install python\n' >&2
    else
        printf 'ERROR: Python 3 belum terpasang. Jalankan bash setup.sh, lalu coba lagi.\n' >&2
    fi
    exit 1
fi

mkdir -p -- "$STATE_DIR"

if [[ -n "${RECON_WEB_TOKEN:-}" ]]; then
    TOKEN="$RECON_WEB_TOKEN"
else
    if [[ ! -s "$TOKEN_FILE" ]]; then
        NEW_TOKEN=$("$PYTHON_BIN" -c 'import secrets; print(secrets.token_urlsafe(32))') || {
            printf 'ERROR: tidak dapat membuat token dashboard.\n' >&2
            exit 1
        }
        # noclobber avoids replacing a token if two launch attempts race.
        (set -o noclobber; printf '%s\n' "$NEW_TOKEN" > "$TOKEN_FILE") 2>/dev/null || true
    fi
    TOKEN=$(cat -- "$TOKEN_FILE" 2>/dev/null || true)
fi

if (( ${#TOKEN} < 32 )); then
    printf 'ERROR: token RECON_WEB_TOKEN harus minimal 32 karakter. Hapus %s atau buat token baru, lalu coba lagi.\n' "$TOKEN_FILE" >&2
    exit 2
fi

if [[ -f "$TOKEN_FILE" ]]; then
    chmod 600 "$TOKEN_FILE" 2>/dev/null || true
fi

export RECON_PRO_HOME="$RECON_HOME"
export RECON_WEB_TOKEN="$TOKEN"
PORT="${RECON_WEB_PORT:-8765}"

# Certificates made by `recon.sh --ssl` are picked up automatically.
TLS_DIR="${STATE_DIR}/tls"
if [[ -z "${RECON_WEB_TLS_CERT:-}" && -f "${TLS_DIR}/cert.pem" && -f "${TLS_DIR}/key.pem" ]]; then
    export RECON_WEB_TLS_CERT="${TLS_DIR}/cert.pem"
    export RECON_WEB_TLS_KEY="${TLS_DIR}/key.pem"
fi
SCHEME="http"
[[ -n "${RECON_WEB_TLS_CERT:-}" ]] && SCHEME="https"

printf '\nRecon Pro dashboard siap dijalankan.\n'
printf 'Buka  : %s://127.0.0.1:%s\n' "$SCHEME" "$PORT"
printf 'Token : %s\n' "$TOKEN"
printf 'Data  : %s\n' "$RECON_HOME"
if [[ "$SCHEME" == "https" ]]; then
    printf 'TLS   : sertifikat %s (self-signed akan memunculkan peringatan browser)\n' "$RECON_WEB_TLS_CERT"
fi
printf 'Hentikan server dengan Ctrl-C. Jangan bagikan token ini.\n\n'
exec "$PYTHON_BIN" "${PROJECT_DIR}/web_ui/server.py"
