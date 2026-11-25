#!/usr/bin/env bash
set -euo pipefail

RECON_HOME=$(cd -- "${RECON_PRO_HOME:-${HOME:-.}/recon_pro}" && pwd -P 2>/dev/null || printf '%s' "${RECON_PRO_HOME:-${HOME:-.}/recon_pro}")
STATE_DIR="${RECON_HOME}/state"

stop_from_file() {
    local name="$1" expected="$2" pid_file="${STATE_DIR}/$1.pid" pid cmdline
    [[ -s "$pid_file" ]] || return 0
    pid=$(cat -- "$pid_file")
    if [[ ! "$pid" =~ ^[0-9]+$ ]] || ! kill -0 "$pid" 2>/dev/null; then
        rm -f -- "$pid_file"
        return 0
    fi
    cmdline=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)
    if [[ "$cmdline" != *"$expected"* ]]; then
        printf 'Tidak menghentikan PID %s: prosesnya tidak cocok dengan %s.\n' "$pid" "$name" >&2
        return 1
    fi
    kill -TERM "$pid" 2>/dev/null || true
    for _ in {1..10}; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.5
    done
    kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || true
    rm -f -- "$pid_file"
}

stop_from_file mcp 'uvicorn server:app'
stop_from_file cloudflared 'cloudflared tunnel --url http://127.0.0.1:8766'
rm -f -- "${STATE_DIR}/mcp_url"
printf 'MCP updater dan Quick Tunnel dihentikan. API key lokal tetap tersimpan.\n'
