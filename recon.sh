#!/usr/bin/env bash
# =============================================================================
# recon — satu pintu untuk semuanya (scan aktif + toolkit pasif)
# =============================================================================
#
#   bash recon.sh example.com         scan penuh + toolkit pasif, satu perintah
#   bash recon.sh example.com -y      sama, tanpa konfirmasi (otomasi/cron)
#   bash recon.sh --passive example.com   hanya toolkit pasif (OSINT)
#   bash recon.sh --no-passive example.com  scan penuh saja
#   bash recon.sh --report [domain]   detail bug dari kedua laporan
#   bash recon.sh --log [domain]      log scan, ringkasan stage, error
#   bash recon.sh --tools             tool + toolkit Python yang terpasang
#   bash recon.sh --setup             pasang/rapikan semua kebutuhan
#   bash recon.sh                     menu interaktif
#
# Hanya untuk domain yang tercantum in-scope di program bug bounty.
# =============================================================================

if (( ${BASH_VERSINFO[0]:-0} < 4 )); then
    for _candidate in /opt/homebrew/bin/bash /usr/local/bin/bash; do
        if [[ -x "$_candidate" ]]; then
            exec "$_candidate" "$0" "$@"
        fi
    done
    printf 'ERROR: butuh bash 4 atau lebih baru. macOS: brew install bash\n' >&2
    exit 1
fi

set -uo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
BASH_BIN="${BASH:-bash}"
RECON_HOME="${RECON_PRO_HOME:-${HOME:-.}/recon_pro}"
RUNS_DIR="${RECON_HOME%/}/runs"
REPORTS_DIR="${RECON_HOME%/}/reports"
STATE_DIR="${RECON_HOME%/}/state"
CONFIG_FILE="${STATE_DIR}/recon_pro.conf"

TOOLKIT_DIR="${SCRIPT_DIR}/bugbounty-toolkit"
TOOLKIT_SCOPE="${TOOLKIT_DIR}/data/extra_scope.txt"
PASSIVE_REPORT=""

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RED='\033[0;31m'
BOLD='\033[1m'; NC='\033[0m'

info() { printf '%b[*]%b %s\n' "$CYAN" "$NC" "$1"; }
ok()   { printf '%b[+]%b %s\n' "$GREEN" "$NC" "$1"; }
warn() { printf '%b[!]%b %s\n' "$YELLOW" "$NC" "$1"; }
fail() { printf '%b[x]%b %s\n' "$RED" "$NC" "$1"; }

usage() {
    cat <<'TXT'
recon — satu pintu untuk semuanya (scan aktif + toolkit pasif)

  bash recon.sh <domain>              scan penuh + toolkit pasif
  bash recon.sh <domain> -y           tanpa konfirmasi (otomasi/cron)
  bash recon.sh --passive <domain>    hanya toolkit pasif (OSINT)
  bash recon.sh --no-passive <domain> scan penuh saja
  bash recon.sh --report [domain]     detail bug dari kedua laporan
  bash recon.sh --log [domain]        log scan, ringkasan stage, error
  bash recon.sh --tools               tool + toolkit Python terpasang
  bash recon.sh --telegram            atur token, chat ID & user bot, lalu tes
  bash recon.sh --notify-test         kirim ulang pesan tes ke Telegram
  bash recon.sh --stop-bot            hentikan bot yang sedang jalan
  bash recon.sh --bot-status          tampilkan status lock & proses bot
  bash recon.sh --setup               pasang semua kebutuhan
  bash recon.sh --no-setup <domain>   lewati pemasangan otomatis
  bash recon.sh                       menu interaktif

Hanya jalankan pada domain yang tercantum in-scope di program bug bounty.
TXT
}

# ------------------------------------------------------------------ helpers ---
latest_domain() {
    local value
    value=$(ls -1t "$REPORTS_DIR" 2>/dev/null | head -n 1)
    printf '%s' "${value:-}"
}

report_path() {
    local domain="$1" path
    path="${REPORTS_DIR}/${domain}/latest-report.md"
    if [[ ! -f "$path" ]]; then
        path="${RUNS_DIR}/${domain}/latest/final/report.md"
    fi
    if [[ ! -f "$path" ]]; then
        printf ''
        return 1
    fi
    printf '%s' "$path"
}

findings_count() {
    local domain="$1" ledger count
    ledger="${RUNS_DIR}/${domain}/latest/final/findings.tsv"
    if [[ -s "$ledger" ]]; then
        count=$(awk 'END { print NR }' "$ledger" 2>/dev/null)
        printf '%s temuan terkonfirmasi (final/findings.tsv)' "${count:-0}"
    else
        printf 'belum ada data temuan'
    fi
}

# print_section <file> <heading-without-##>
print_section() {
    local file="$1" heading="$2"
    awk -v h="## $heading" '
        $0 == h { inside = 1; next }
        inside && substr($0, 1, 3) == "## " { exit }
        inside { print }
    ' "$file" 2>/dev/null
}

# ----------------------------------------------------------- python toolkit ---
toolkit_python() {
    if [[ -x "$TOOLKIT_DIR/.venv/bin/python" ]]; then
        printf '%s' "$TOOLKIT_DIR/.venv/bin/python"
        return 0
    fi
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "$(command -v python3)"
        return 0
    fi
    return 1
}

toolkit_ready() {
    [[ -x "$TOOLKIT_DIR/.venv/bin/python" && -f "$TOOLKIT_DIR/main.py" ]]
}

passive_report_path() {
    local domain="$1" path
    path=$(ls -1t "$TOOLKIT_DIR/reports/${domain}-"*.md 2>/dev/null | head -n 1)
    printf '%s' "${path:-}"
}

# The toolkit has its own strict scope. recon.sh records the confirmed domain in
# a side file instead of rewriting config.yaml, so its comments stay intact.
ensure_toolkit_scope() {
    local domain="$1"
    [[ -d "$TOOLKIT_DIR" ]] || return 1
    mkdir -p -- "$(dirname -- "$TOOLKIT_SCOPE")" 2>/dev/null || true
    if [[ ! -f "$TOOLKIT_SCOPE" ]]; then
        printf '# Domain yang ditambahkan otomatis oleh recon.sh (mode pasif).\n' > "$TOOLKIT_SCOPE"
        chmod 600 "$TOOLKIT_SCOPE" 2>/dev/null || true
    fi
    grep -qxF -- "$domain" "$TOOLKIT_SCOPE" 2>/dev/null && return 0
    printf '%s\n' "$domain" >> "$TOOLKIT_SCOPE"
    return 0
}

# run_passive <domain> — OSINT + header analysis; sets PASSIVE_REPORT
run_passive() {
    local domain="$1" py

    PASSIVE_REPORT=""
    if [[ ! -d "$TOOLKIT_DIR" ]]; then
        warn "Folder bugbounty-toolkit tidak ada; mode pasif dilewati."
        return 0
    fi
    if [[ ! -f "$TOOLKIT_DIR/main.py" ]]; then
        warn "main.py toolkit tidak ada; mode pasif dilewati."
        return 0
    fi
    if ! py=$(toolkit_python); then
        warn "python3 tidak ada; mode pasif dilewati. Jalankan: bash setup.sh --python-only"
        return 0
    fi
    if ! toolkit_ready; then
        warn "virtualenv toolkit belum siap; jalankan: bash setup.sh --python-only"
    fi

    ensure_toolkit_scope "$domain"

    info "Mode pasif (crt.sh, DNS, RDAP, header, teknologi) untuk ${domain} ..."
    if ! ( cd -- "$TOOLKIT_DIR" && "$py" main.py "$domain" ); then
        warn "Toolkit pasif selesai dengan error; lihat ${TOOLKIT_DIR}/logs/toolkit.log"
    fi

    PASSIVE_REPORT=$(passive_report_path "$domain")
    if [[ -n "$PASSIVE_REPORT" ]]; then
        ok "Laporan pasif: ${PASSIVE_REPORT}"
    fi
    return 0
}

# show_report_detail [domain] — apa bugnya, dampaknya, dan cara ceknya
show_report_detail() {
    local domain="${1:-}" path body passive
    domain="${domain:-$(latest_domain)}"

    if [[ -z "$domain" ]]; then
        fail "Belum ada laporan. Jalankan: bash recon.sh example.com"
        return 1
    fi
    path=$(report_path "$domain" || true)
    if [[ -z "$path" ]]; then
        local only_passive
        only_passive=$(passive_report_path "$domain")
        if [[ -z "$only_passive" ]]; then
            fail "Belum ada laporan untuk ${domain}. Jalankan: bash recon.sh ${domain}"
            return 1
        fi
        printf '%b=== DETAIL LAPORAN PASIF: %s ===%b\n' "${BOLD}${CYAN}" "$domain" "$NC"
        printf 'File      : %s\n' "$only_passive"
        printf '\n--- BUG / TEMUAN (pasif) ---\n'
        printf '%s\n' "$(print_section "$only_passive" "Findings")"
        return 0
    fi

    printf '%b=== DETAIL LAPORAN: %s ===%b\n' "${BOLD}${CYAN}" "$domain" "$NC"
    printf 'File      : %s\n' "$path"
    printf 'Ringkasan : %s\n' "$(findings_count "$domain")"

    printf '\n--- RINGKASAN EKSEKUTIF ---\n'
    print_section "$path" "Executive summary"

    printf '\n--- BUG YANG KETEMU (detail) ---\n'
    body=$(print_section "$path" "Findings")
    if [[ -z "$body" ]] || ! grep -q '^### F-' <<< "$body"; then
        printf '_Tidak ada finding terkonfirmasi pada run aktif. Observasi lengkap: %s/reports/%s/latest-bugs_found.txt_\n' \
            "$RECON_HOME" "$domain"
    else
        printf '%s\n' "$body"
    fi

    passive=$(passive_report_path "$domain")
    if [[ -n "$passive" ]]; then
        printf '\n--- LAPORAN PASIF (OSINT + header) ---\n'
        printf 'File      : %s\n' "$passive"
        printf '%s\n' "$(print_section "$passive" "Findings")"
    fi

    printf '\n--- SELANJUTNYA ---\n'
    printf 'Perubahan vs run sebelumnya: bagian "Changes detected" di file di atas.\n'
    printf 'Laporan lengkap: %s\n' "$path"
    return 0
}

# show_log [domain]
show_log() {
    local domain="${1:-}" run_dir log_file err_file shown
    domain="${domain:-$(latest_domain)}"

    if [[ -z "$domain" ]]; then
        fail "Belum ada run. Jalankan: bash recon.sh example.com"
        return 1
    fi
    run_dir="${RUNS_DIR}/${domain}/latest"
    if [[ ! -d "$run_dir" ]]; then
        fail "Belum ada workspace untuk ${domain}."
        return 1
    fi

    printf '%b=== LOG: %s ===%b\n' "${BOLD}${CYAN}" "$domain" "$NC"
    printf 'Workspace : %s\n' "$run_dir"

    printf '\n--- RINGKASAN STAGE ---\n'
    if [[ -s "$run_dir/logs/stages.tsv" ]]; then
        awk -F'\t' '{ printf "%-12s %-10s %s\n", $1, $2, $3 }' "$run_dir/logs/stages.tsv"
    else
        printf '_belum ada stage yang tercatat_\n'
    fi

    log_file="$run_dir/logs/pipeline.log"
    printf '\n--- 80 BARIS TERAKHIR PIPELINE ---\n'
    if [[ -s "$log_file" ]]; then
        tail -n 80 "$log_file"
    else
        printf '_pipeline.log kosong atau tidak ada_\n'
    fi

    printf '\n--- ERROR PER STAGE ---\n'
    shown=0
    for err_file in "$run_dir"/logs/*.err; do
        [[ -s "$err_file" ]] || continue
        printf '\n[%s]\n' "$(basename -- "$err_file")"
        tail -n 6 "$err_file"
        shown=$((shown + 1))
        if (( shown >= 12 )); then
            printf '\n... error lain tidak ditampilkan\n'
            break
        fi
    done
    (( shown == 0 )) && printf '_tidak ada error: semua stage yang jalan bersih_\n'

    printf '\nLog toolkit pasif: %s/logs/toolkit.log\n' "$TOOLKIT_DIR"
    printf 'Semua file log aktif: %s/logs/  (pipeline.log, stages.tsv, <stage>.err)\n' "$run_dir"
    return 0
}

# ------------------------------------------------------------------- tools ----
TOOL_CANDIDATES="curl jq subfinder assetfinder amass findomain chaos dnsx httpx tlsx nuclei dalfox whatweb katana waybackurls gau x8 ffuf gf naabu nmap python3"

tool_version() {
    local tool="$1" flag out

    for flag in -version --version -V version -version-short; do
        if command -v timeout >/dev/null 2>&1; then
            out=$(timeout 8 "$tool" "$flag" 2>&1 | head -n 4)
        else
            out=$("$tool" "$flag" 2>&1 | head -n 4)
        fi
        out=$(printf '%s\n' "$out" | tr -d '\r' | grep -Eo '[0-9]+(\.[0-9]+)+' | head -n 1)
        if [[ -n "$out" ]]; then
            printf '%s' "$out"
            return 0
        fi
    done
    printf 'terpasang'
}

show_tools() {
    local tool version found=0 missing=0 py

    printf '%b=== TOOL TERPASANG ===%b\n' "${BOLD}${CYAN}" "$NC"
    printf '%-14s %-11s %s\n' "TOOL" "STATUS" "VERSI"
    printf '%-14s %-11s %s\n' "----" "------" "-----"

    for tool in $TOOL_CANDIDATES; do
        if command -v "$tool" >/dev/null 2>&1; then
            version=$(tool_version "$tool")
            printf '%-14s %-11s %s\n' "$tool" "ok" "$version"
            found=$((found + 1))
        else
            printf '%-14s %-11s %s\n' "$tool" "missing" "-"
            missing=$((missing + 1))
        fi
    done

    printf '\nTerpasang: %s · Missing: %s\n' "$found" "$missing"
    if (( missing > 0 )); then
        printf 'Lengkapi dengan: bash setup.sh   (atau bash setup.sh --minimal untuk tool inti)\n'
    fi

    printf '\n%bToolkit pasif (Python):%b\n' "$BOLD" "$NC"
    if [[ ! -d "$TOOLKIT_DIR" ]]; then
        printf '  %-16s %-11s %s\n' "bugbounty-toolkit" "missing" "folder tidak ditemukan"
    elif toolkit_ready && py=$(toolkit_python); then
        printf '  %-16s %-11s %s\n' "toolkit venv" "ok" "$("$py" -V 2>&1)"
        printf '  %-16s %-11s %s\n' "config" "ok" "${TOOLKIT_DIR}/config/config.yaml"
    else
        printf '  %-16s %-11s %s\n' "toolkit venv" "missing" "bash setup.sh --python-only"
    fi
    printf '\n%bTelegram:%b\n' "$BOLD" "$NC"
    local tg_token tg_chat
    tg_token=$(conf_value TELEGRAM_TOKEN || true)
    tg_chat=$(conf_value TELEGRAM_CHAT || true)
    if [[ -n "$tg_token" && -n "$tg_chat" ]]; then
        printf '  %-16s %-11s %s\n' "notifier" "ok" "chat ${tg_chat}"
    else
        printf '  %-16s %-11s %s\n' "notifier" "off" "bash recon.sh --telegram"
    fi

    printf '\nCek detail (folder, proxy, wordlist, config): bash recon_pro.sh -c\n'
    return 0
}

# ---------------------------------------------------------------- telegram ----
# Reads one value from the pipeline config (KEY|value per line).
conf_value() {
    local key="$1"
    [[ -f "$CONFIG_FILE" ]] || return 1
    awk -F'|' -v k="$key" '$1 == k { sub(/^[^|]*\|/, ""); print; exit }' "$CONFIG_FILE"
}

# Writes one KEY|value pair, keeping every other line untouched.
conf_set() {
    local key="$1" value="$2" tmp
    [[ -f "$CONFIG_FILE" ]] || : > "$CONFIG_FILE"
    mkdir -p -- "$(dirname -- "$CONFIG_FILE")" 2>/dev/null || true
    tmp=$(mktemp "${CONFIG_FILE}.XXXXXX") || return 1
    awk -v k="$key" -v v="$value" '
        BEGIN { seen = 0 }
        index($0, k "|") == 1 { if (!seen) { print k "|" v; seen = 1 } ; next }
        { print }
        END { if (!seen) print k "|" v }
    ' "$CONFIG_FILE" > "$tmp" && mv -f -- "$tmp" "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE" 2>/dev/null || true
    return 0
}

# Sends one test message. The token travels through curl's stdin config, never
# through argv, so it does not show up in the process list.
telegram_test() {
    local token="${1:-}" chat="${2:-}" message

    token="${token:-$(conf_value TELEGRAM_TOKEN || true)}"
    chat="${chat:-$(conf_value TELEGRAM_CHAT || true)}"

    if [[ -z "$token" || -z "$chat" ]]; then
        fail "Token/chat belum diisi. Jalankan: bash recon.sh --telegram"
        return 1
    fi
    if ! command -v curl >/dev/null 2>&1; then
        fail "curl tidak terpasang."
        return 1
    fi

    message="recon: notifikasi Telegram aktif ($(date '+%Y-%m-%d %H:%M'))"
    if curl --silent --show-error --max-time 20 --config - >/dev/null 2>&1 <<EOF
url = "https://api.telegram.org/bot${token}/sendMessage"
request = "POST"
data-urlencode = "chat_id=${chat}"
data-urlencode = "text=${message}"
EOF
    then
        ok "Pesan uji terkirim ke chat ${chat}."
        return 0
    fi
    fail "Telegram menolak pesan itu. Periksa token (BotFather) dan chat ID (@userinfobot)."
    return 1
}

# Interactive, quote-safe replacement for editing the config with sed.
set_telegram() {
    local token="" chat="" users="" current_token current_chat

    current_token=$(conf_value TELEGRAM_TOKEN || true)
    current_chat=$(conf_value TELEGRAM_CHAT || true)

    printf 'Token bot Telegram dari @BotFather (input tidak terlihat): '
    read -rs token || token=""
    printf '\n'

    if [[ -z "$token" ]]; then
        if [[ -n "$current_token" ]]; then
            printf 'Token tidak diubah.\n'
            token="$current_token"
        else
            fail "Token kosong; dibatalkan."
            return 1
        fi
    elif [[ ! "$token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]; then
        fail "Format token tidak valid (contoh: 123456789:AAF...). Dibatalkan."
        return 1
    fi

    printf 'Chat ID numerik%s (ambil dari @userinfobot): ' "${current_chat:+ [$current_chat]}"
    read -r chat || chat=""
    chat="${chat// /}"
    if [[ -z "$chat" ]]; then
        chat="$current_chat"
    fi
    if [[ ! "$chat" =~ ^-?[0-9]+$ ]]; then
        fail "Chat ID harus angka. Kirim /start ke bot, lalu cek @userinfobot."
        return 1
    fi

    conf_set TELEGRAM_TOKEN "$token" || { fail "Gagal menulis config."; return 1; }
    conf_set TELEGRAM_CHAT "$chat" || { fail "Gagal menulis config."; return 1; }

    # Optional: the numeric IDs allowed to drive the bot, stored in the same file
    # so the bot needs no environment variables at all.
    printf 'User ID Telegram yang boleh memakai bot (pisahkan koma, Enter = lewati): '
    read -r users || users=""
    users="${users// /}"
    if [[ -n "$users" ]]; then
        if [[ ! "$users" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
            fail "User ID harus angka, dipisah koma tanpa spasi."
            return 1
        fi
        conf_set TELEGRAM_ALLOWED_USERS "$users" || warn "Gagal menyimpan daftar user ID."
    fi

    ok "Tersimpan di ${CONFIG_FILE} (izin 600)."
    telegram_test "$token" "$chat" || true
    return 0
}

# Stops the running bot by the PID it writes into its lock file. More reliable
# than pkill/pgrep, whose pattern matching is easy to get wrong.
stop_bot() {
    local lock="${RECON_HOME%/}/state/bot/bot.lock"
    local pid cmd

    pid=$(tr -dc '0-9' < "$lock" 2>/dev/null)
    if [[ -z "$pid" ]]; then
        bot_status
        fail "Lock tidak memuat PID. Kalau tidak ada bot yang jalan, hapus: rm -f ${lock}"
        return 1
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
        fail "PID ${pid} tidak hidup (lock basi). Jalankan bot, atau hapus: rm -f ${lock}"
        return 1
    fi

    cmd=$(ps -p "$pid" -o args= 2>/dev/null)
    if [[ "$cmd" != *recon_pro_bot.py* ]]; then
        fail "PID ${pid} bukan bot Recon Pro: ${cmd:-<tidak diketahui>}"
        fail "Lock basi. Hapus: rm -f ${lock}"
        return 1
    fi

    kill -TERM "$pid" 2>/dev/null || true
    local attempt
    for attempt in 1 2 3 4 5; do
        sleep 1
        if ! kill -0 "$pid" 2>/dev/null; then
            ok "Bot dihentikan (PID ${pid})."
            return 0
        fi
    done

    kill -KILL "$pid" 2>/dev/null && ok "Bot dihentikan paksa (PID ${pid})."
    return 0
}

# Shows what the bot lock looks like right now, so a stuck start is explainable.
bot_status() {
    local lock="${RECON_HOME%/}/state/bot/bot.lock"
    local pid cmd holder

    printf '%b=== BOT STATUS ===%b\n' "${BOLD}" "$NC"
    printf 'Lock file : %s%s\n' "$lock" "$( [[ -f "$lock" ]] && printf '' || printf '  (belum ada)' )"

    pid=$(tr -dc '0-9' < "$lock" 2>/dev/null)
    if [[ -n "$pid" ]]; then
        printf 'PID di lock: %s\n' "$pid"
        if kill -0 "$pid" 2>/dev/null; then
            cmd=$(ps -p "$pid" -o args= 2>/dev/null)
            printf 'Proses    : %s\n' "${cmd:-<tidak terbaca>}"
        else
            printf 'Proses    : tidak hidup (lock basi)\n'
        fi
    else
        printf 'PID di lock: (kosong)\n'
    fi

    if command -v fuser >/dev/null 2>&1 && [[ -f "$lock" ]]; then
        holder=$(fuser "$lock" 2>/dev/null | tr -s ' ' | sed 's/^ //')
        printf 'Pemegang  : %s\n' "${holder:-tidak ada proses memegang lock}"
    fi

    holder=$(ps -eo pid,args 2>/dev/null | awk '/[r]econ_pro_bot\.py/ { print $1 }' | tr '\n' ' ')
    printf 'Proses bot: %s\n' "${holder:-tidak ada}"
    return 0
}

# ---------------------------------------------------------------- arg parsing --
DOMAIN=""
ACTION=""
ASSUME=0
NO_SETUP=0
NO_PASSIVE=0

while (( $# )); do
    case "$1" in
        -h|--help)    usage; exit 0 ;;
        -y|--yes)     ASSUME=1 ;;
        --setup)      ACTION="setup" ;;
        --passive)    ACTION="passive" ;;
        --no-passive) NO_PASSIVE=1 ;;
        --tools|--check|-c) ACTION="tools" ;;
        --telegram)   ACTION="telegram" ;;
        --notify-test) ACTION="notify" ;;
        --stop-bot)   ACTION="stopbot" ;;
        --bot-status) ACTION="botstatus" ;;
        --no-setup)   NO_SETUP=1 ;;
        --report)
            ACTION="report"
            if [[ -n "${2:-}" && "${2:-}" != -* ]]; then
                DOMAIN="$2"
                shift
            fi
            ;;
        --log)
            ACTION="log"
            if [[ -n "${2:-}" && "${2:-}" != -* ]]; then
                DOMAIN="$2"
                shift
            fi
            ;;
        -*)
            fail "Opsi tidak dikenal: $1"
            usage
            exit 2
            ;;
        *)
            if [[ -n "$DOMAIN" ]]; then
                fail "Satu domain per run."
                exit 2
            fi
            DOMAIN="$1"
            ;;
    esac
    shift
done

case "$ACTION" in
    setup)
        exec "$BASH_BIN" "$SCRIPT_DIR/setup.sh"
        ;;
    tools)
        show_tools
        exit 0
        ;;
    report)
        show_report_detail "$DOMAIN"
        exit $?
        ;;
    log)
        show_log "$DOMAIN"
        exit $?
        ;;
    telegram)
        set_telegram
        exit $?
        ;;
    notify)
        telegram_test
        exit $?
        ;;
    stopbot)
        stop_bot
        exit $?
        ;;
    botstatus)
        bot_status
        exit 0
        ;;
esac

if [[ -z "$DOMAIN" ]]; then
    exec "$BASH_BIN" "$SCRIPT_DIR/recon_pro.sh"
fi

case "$DOMAIN" in
    *://*|*/*|*" "*|.*)
        fail "Tulis apex domain saja, contoh: example.com"
        exit 2
        ;;
    *.*) ;;
    *)
        fail "Tulis apex domain saja, contoh: example.com"
        exit 2
        ;;
esac

# ------------------------------------------------------------ auto-lengkapi ---
maybe_setup() {
    local missing=0 py_missing=0 tool

    [[ -f "$CONFIG_FILE" ]] || missing=1
    for tool in curl jq subfinder dnsx httpx nuclei; do
        command -v "$tool" >/dev/null 2>&1 || missing=1
    done
    toolkit_ready || py_missing=1
    (( missing || py_missing )) || return 0

    if (( NO_SETUP )); then
        warn "Sebagian tool belum ada; lanjut dengan yang tersedia (--no-setup)."
        return 0
    fi

    if (( missing )); then
        info "Melengkapi tool yang belum ada (setup.sh, bisa beberapa menit) ..."
        if ! "$BASH_BIN" "$SCRIPT_DIR/setup.sh"; then
            warn "setup.sh melaporkan masalah; scan tetap dilanjutkan dengan tool yang ada."
        fi
        if command -v go >/dev/null 2>&1; then
            export PATH="$(go env GOPATH 2>/dev/null)/bin:/usr/local/go/bin:$PATH"
        fi
        return 0
    fi

    # Tool Go sudah lengkap tetapi venv toolkit belum ada: cukup siapkan Python.
    info "Menyiapkan toolkit Python pasif (setup.sh --python-only) ..."
    if ! "$BASH_BIN" "$SCRIPT_DIR/setup.sh" --python-only; then
        warn "Penyiapan toolkit melaporkan masalah; mode pasif mungkin dilewati."
    fi
    return 0
}

if [[ "$ACTION" == "passive" ]]; then
    if [[ ! -f "$TOOLKIT_DIR/main.py" ]]; then
        fail "Toolkit pasif tidak ditemukan di ${TOOLKIT_DIR}."
        exit 1
    fi
    if ! toolkit_ready && (( ! NO_SETUP )); then
        info "Menyiapkan toolkit Python (setup.sh --python-only) ..."
        "$BASH_BIN" "$SCRIPT_DIR/setup.sh" --python-only || warn "Penyiapan toolkit melaporkan masalah."
    fi
    if ! toolkit_python >/dev/null; then
        fail "python3 tidak ada. Pasang dulu, lalu: bash setup.sh --python-only"
        exit 1
    fi
else
    maybe_setup
    for tool in curl jq; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            fail "$tool wajib ada. Jalankan: bash setup.sh"
            exit 1
        fi
    done
fi

if (( ! ASSUME )); then
    printf 'Jalankan untuk %b%s%b? Ketik %by%b kalau domain ini resmi in-scope dan kamu berwenang: ' \
        "$CYAN" "$DOMAIN" "$NC" "$GREEN" "$NC"
    answer=""
    read -r answer || answer=""
    case "${answer,,}" in
        y|ya|yes) ;;
        *)
            printf 'Dibatalkan.\n'
            exit 1
            ;;
    esac
fi

# ---------------------------------------------------------------- pasif saja ---
if [[ "$ACTION" == "passive" ]]; then
    printf '\n%b=== TOOLKIT PASIF: %s ===%b\n' "${BOLD}${CYAN}" "$DOMAIN" "$NC"
    run_passive "$DOMAIN"
    if [[ -n "$PASSIVE_REPORT" ]]; then
        printf '\nLaporan pasif : %s\n' "$PASSIVE_REPORT"
        printf 'Detail bug    : bash recon.sh --report %s\n' "$DOMAIN"
    else
        warn "Laporan pasif tidak terbentuk; lihat ${TOOLKIT_DIR}/logs/toolkit.log"
    fi
    exit 0
fi

# ---------------------------------------------------------------------- scan ---
info "Mulai scan penuh: ${DOMAIN}"
"$BASH_BIN" "$SCRIPT_DIR/recon_pro.sh" --yes "$DOMAIN"
rc=$?

if (( rc != 0 )); then
    warn "Scan selesai dengan exit code ${rc}."
    warn "Lihat log: bash recon.sh --log ${DOMAIN}"
else
    ok "Scan selesai."
fi

# Toolkit pasif dijalankan setelah scan aktif: tidak butuh tool Go, hanya Python.
if (( ! NO_PASSIVE )); then
    printf '\n%b=== TOOLKIT PASIF: %s ===%b\n' "${BOLD}${CYAN}" "$DOMAIN" "$NC"
    run_passive "$DOMAIN"
fi

printf '\n%b=== HASIL ===%b\n' "${BOLD}${CYAN}" "$NC"
path=$(report_path "$DOMAIN" || true)
if [[ -n "$path" ]]; then
    printf 'Laporan aktif : %s\n' "$path"
    printf 'Ringkasan bug : %s\n' "$(findings_count "$DOMAIN")"
else
    warn "Laporan aktif belum terbentuk; cek log: bash recon.sh --log ${DOMAIN}"
fi
if [[ -n "$PASSIVE_REPORT" ]]; then
    printf 'Laporan pasif : %s\n' "$PASSIVE_REPORT"
elif (( ! NO_PASSIVE )); then
    printf 'Laporan pasif : (tidak dibuat; cek %s/logs/toolkit.log)\n' "$TOOLKIT_DIR"
fi

printf '\n%bDetail bug:%b  bash recon.sh --report %s\n' "$BOLD" "$NC" "$DOMAIN"
printf '%bLog:%b         bash recon.sh --log %s\n' "$BOLD" "$NC" "$DOMAIN"

exit "$rc"
