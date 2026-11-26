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
#   bash recon.sh --web               jalankan dashboard lokal (token dibuat otomatis)
#   bash recon.sh --setup [opsi]      pasang/rapikan semua kebutuhan
#   bash recon.sh --fix-tools         lengkapi tool yang belum ada (arsenal + Python)
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
LOG_FILE="${STATE_DIR%/}/recon.log"

TOOLKIT_DIR="${SCRIPT_DIR}/bugbounty-toolkit"
TOOLKIT_SCOPE="${TOOLKIT_DIR}/data/extra_scope.txt"
PASSIVE_REPORT=""

# API keys for the passive collectors live in one protected file, so cron and
# the dashboard's subprocess see them without a shell profile. It is parsed,
# never sourced: a stray line in a data file must not run commands.
API_KEYS_FILE="${STATE_DIR}/api_keys.env"
if [[ -f "$API_KEYS_FILE" ]]; then
    while IFS='=' read -r _key _value; do
        [[ -z "${_key:-}" || "$_key" == \#* || ! "$_key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && continue
        export "$_key=$_value"
    done <"$API_KEYS_FILE" 2>/dev/null || true
fi

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
  bash recon.sh --fast <domain>       profil cepat: cap kecil, timeout pendek
  bash recon.sh --deep <domain>       profil dalam: cap besar, autocalibrate
  bash recon.sh --max <domain>        profil maksimal (patuhi rate program)
  bash recon.sh --timings [domain]    durasi per stage, urut paling lama
  bash recon.sh --report [domain]     detail bug dari kedua laporan
  bash recon.sh --log [domain]        log scan, ringkasan stage, error
  bash recon.sh --failures [domain]   hanya tool/stage yang gagal atau skip
  bash recon.sh --tools               tool + toolkit Python terpasang
  bash recon.sh --web                 jalankan dashboard lokal (token dibuat otomatis)
  bash recon.sh --web-restart         stop + jalankan dashboard di background
  bash recon.sh --web-stop            hentikan dashboard yang jalan
  bash recon.sh --web-token           tampilkan URL + token dashboard
  bash recon.sh --telegram            atur token, chat ID & user bot, lalu tes
  bash recon.sh --notify-test         kirim ulang pesan tes ke Telegram
  bash recon.sh --stop-bot            hentikan bot yang sedang jalan
  bash recon.sh --bot-status          tampilkan status lock & proses bot
  bash recon.sh --proxy-check         uji semua proxy, tulis <file>.good
  bash recon.sh --proxy-clean         uji lalu ganti file dengan yang hidup
  bash recon.sh --self-test           cek sintaks semua skrip (setelah pull)
  bash recon.sh --update              git pull + cek sintaks + saran restart bot
  bash recon.sh --status              ringkasan: target, tool, proxy, bot, laporan
  bash recon.sh --install-service     pasang bot sebagai service systemd (root)
  bash recon.sh --setup [opsi]        pasang semua kebutuhan (opsi diteruskan ke setup.sh)
  bash recon.sh --fix-tools           pasang tool yang belum ada (arsenal + Python)
  bash recon.sh --clean [folder]      lihat file sampah (arsip unduhan, output lama)
  bash recon.sh --clean --apply       hapus file sampah yang terdaftar tadi
  bash recon.sh --disk                apa yang benar-benar memenuhi disk
  bash recon.sh --doctor              kesehatan sistem: update, tool, key, TLS, dashboard
  bash recon.sh --ssl [host]          buat sertifikat TLS untuk dashboard (HTTPS)
  bash recon.sh --api-key [NAMA]      simpan API key collector (default PDCP_API_KEY)
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

# The venv can exist while its packages are missing (an earlier pip step may
# have failed), and then every DNS stage silently degrades. Check the imports
# where the toolkit actually runs, not on the system interpreter.
toolkit_deps_ready() {
    local py
    py=$(toolkit_python) || return 1
    "$py" -c 'import requests, yaml, dns.resolver' >/dev/null 2>&1
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

    info "Mode pasif (CT logs, Wayback, Common Crawl, OTX, Anubis, RapidDNS, DNS, AXFR, TLS, robots) untuk ${domain} ..."
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
        awk -F'\t' '{ t = ($4 == "" ? "-" : $4 "s"); printf "%-12s %-10s %-7s %s\n", $1, $2, t, $3 }' "$run_dir/logs/stages.tsv"
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

# show_timings [domain]
# Ranks the stages of the newest run by duration, so a slow scan is tuned from
# data instead of a guess.
show_timings() {
    local domain="${1:-}" run_dir total
    domain="${domain:-$(latest_domain)}"

    if [[ -z "$domain" ]]; then
        fail "Belum ada run. Jalankan: bash recon.sh example.com"
        return 1
    fi
    run_dir="${RUNS_DIR}/${domain}/latest"
    if [[ ! -s "$run_dir/logs/stages.tsv" ]]; then
        fail "Belum ada catatan stage untuk ${domain}. Run lama tidak menyimpan durasi; jalankan scan baru."
        return 1
    fi

    printf '%b=== DURASI STAGE: %s ===%b\n' "${BOLD}${CYAN}" "$domain" "$NC"
    printf 'Workspace : %s\n\n' "$run_dir"
    printf '%-10s %-9s %-8s %s\n' "STAGE" "STATUS" "WAKTU" "CATATAN"
    printf '%-10s %-9s %-8s %s\n' "-----" "------" "-----" "-------"
    sort -t$'\t' -k4,4nr "$run_dir/logs/stages.tsv" |
        awk -F'\t' '{ t = ($4 == "" ? "-" : $4 "s"); printf "%-10s %-9s %-8s %s\n", $1, $2, t, $3 }'
    total=$(awk -F'\t' '{ if ($4 ~ /^[0-9]+$/) s += $4 } END { printf "%d", s }' "$run_dir/logs/stages.tsv")
    printf '\nTotal waktu stage tercatat: %ss\n' "${total:-0}"
    printf 'Perkecil cap stage teratas di %s, atau jalankan: bash recon.sh --fast %s\n' \
        "$CONFIG_FILE" "$domain"
    return 0
}

# ------------------------------------------------------------------- tools ----
TOOL_CANDIDATES="curl jq subfinder assetfinder amass findomain chaos dnsx httpx tlsx nuclei dalfox whatweb katana waybackurls gau x8 ffuf gf naabu nmap python3 skipfish gobuster feroxbuster dirsearch wpscan commix arjun"

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

# ------------------------------------------------------------- disk usage ---
# Shows what is really using the disk. It never deletes anything; the hints at
# the end are the usual safe reclaims.
show_disk() {
    if ! command -v df >/dev/null 2>&1; then
        fail "df tidak tersedia."
        return 1
    fi

    printf '%bDisk filesystem (root):%b\n' "${BOLD}${CYAN}" "$NC"
    df -h / 2>/dev/null | sed -n '1,2p'

    printf '\n%bFolder terbesar (bisa butuh beberapa detik):%b\n' "${BOLD}${CYAN}" "$NC"
    local d size
    for d in /var /var/log /var/lib/docker /var/cache/apt /opt /root /home /tmp /usr "${RECON_HOME}"; do
        [[ -d "$d" ]] || continue
        size=$(timeout 20 du -sh "$d" 2>/dev/null | cut -f1)
        [[ -n "$size" ]] && printf '  %-8s %s\n' "$size" "$d"
    done | sort -h -r

    printf '\n%bFile > 200 MB:%b\n' "${BOLD}${CYAN}" "$NC"
    timeout 25 find /var /opt /root /home /usr /tmp -xdev -type f -size +200M -print0 2>/dev/null \
        | while IFS= read -r -d '' f; do
            printf '  %-8s %s\n' "$(du -h "$f" 2>/dev/null | cut -f1)" "$f"
        done | sort -h -r | head -n 15

    printf '\n%bSaran (aman, tidak otomatis):%b\n' "${BOLD}${CYAN}" "$NC"
    printf '  apt-get clean                    # cache paket apt\n'
    printf '  journalctl --vacuum-time=7d      # journal systemd\n'
    if command -v docker >/dev/null 2>&1; then
        printf '  docker system prune -af          # image/container tak dipakai\n'
    fi
    printf '  bash recon.sh --clean --apply    # arsip unduhan dan output lama\n'
    return 0
}

# ------------------------------------------------------------------ cleanup ---
# Lists the files that are clearly leftovers — downloaded tool archives, old
# nmap output, interrupted-tool state — one directory deep, never recursing and
# never touching a directory. Nothing is deleted without --apply, and even then
# it asks for the word "hapus" first.
show_clean() {
    local dir="${1:-${HOME:-/root}}" apply="${2:-0}" f size count=0 confirm
    if [[ ! -d "$dir" ]]; then
        fail "Folder tidak ada: ${dir}"
        return 1
    fi

    info "Memeriksa ${dir} (hanya file, satu level, folder tidak disentuh) ..."
    printf '\n%-10s %s\n' "UKURAN" "FILE"
    printf '%-10s %s\n' "------" "----"

    local -a files=()
    while IFS= read -r -d '' f; do
        files+=("$f")
    done < <(find "$dir" -maxdepth 1 -type f \
        \( -name '*.zip*' -o -name '*.tar.gz*' -o -name '*.tgz*' \
           -o -name '*.deb' -o -name 'nmap-*' -o -name '*.restore' \) \
        -print0 2>/dev/null)

    if (( ${#files[@]} == 0 )); then
        ok "Tidak ada file sampah yang dikenali di ${dir}."
        return 0
    fi

    for f in "${files[@]}"; do
        size=$(du -h "$f" 2>/dev/null | cut -f1)
        printf '%-10s %s\n' "${size:-?}" "$(basename "$f")"
        count=$((count + 1))
    done

    printf '\nTotal: %d file\n' "$count"
    printf 'Pola yang dianggap sampah: *.zip*, *.tar.gz*, *.tgz*, *.deb, nmap-*, *.restore\n'
    printf 'Folder, laporan, konfigurasi, dan hasil scan tidak pernah ikut dihapus.\n'

    if (( ! apply )); then
        printf '\nBelum ada yang dihapus. Untuk menghapus daftar di atas:\n'
        printf '  bash recon.sh --clean %s --apply\n' "$dir"
        return 0
    fi

    printf '\nHapus %d file di atas? Ketik hapus untuk melanjutkan: ' "$count"
    confirm=""
    read -r confirm || confirm=""
    if [[ "$confirm" != "hapus" ]]; then
        printf 'Dibatalkan.\n'
        return 0
    fi
    for f in "${files[@]}"; do
        if rm -f "$f"; then
            printf '  hapus %s\n' "$(basename "$f")"
        else
            warn "gagal menghapus $(basename "$f")"
        fi
    done
    ok "Selesai."
    return 0
}

# -------------------------------------------------------------------- TLS ----
# Makes a certificate the dashboard can use. A self-signed one is enough for
# direct access by IP; a real domain should get a real certificate (Cloudflare
# Tunnel or certbot), otherwise every browser will warn.
run_ssl() {
    local host="${1:-}" dir="${RECON_HOME%/}/state/tls" port ip4 ip6 san
    mkdir -p "$dir" "$STATE_DIR" 2>/dev/null || true
    if ! command -v openssl >/dev/null 2>&1; then
        fail "openssl tidak terpasang."
        return 1
    fi
    [[ -n "$host" ]] || host="localhost"
    port="${RECON_WEB_PORT:-8765}"

    # Both stacks: a VPS may answer with IPv6 first, and a certificate should
    # cover whichever address the browser is actually pointed at.
    ip4=$(curl -4 -fsS --max-time 5 https://ifconfig.me/ip 2>/dev/null || true)
    ip6=$(curl -6 -fsS --max-time 5 https://ifconfig.me/ip 2>/dev/null || true)
    [[ "$ip4" =~ ^[0-9a-fA-F.:]+$ ]] || ip4=""
    [[ "$ip6" =~ ^[0-9a-fA-F:]+$ ]] || ip6=""

    san="DNS:${host}"
    local extra
    for extra in "DNS:localhost" "IP:127.0.0.1" "IP:::1" \
                 "${ip4:+IP:${ip4}}" "${ip6:+IP:${ip6}}"; do
        [[ -n "$extra" ]] || continue
        case ",${san}," in
            *",${extra},"*) continue ;;
        esac
        san="${san},${extra}"
    done

    info "Membuat sertifikat TLS self-signed untuk ${host} (SAN: ${san}) ..."
    if openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${dir}/key.pem" \
        -out "${dir}/cert.pem" \
        -days 825 -subj "/CN=${host}" \
        -addext "subjectAltName=${san}" >>"$LOG_FILE" 2>&1 \
        || openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${dir}/key.pem" \
        -out "${dir}/cert.pem" \
        -days 825 -subj "/CN=${host}" >>"$LOG_FILE" 2>&1; then
        chmod 600 "${dir}/key.pem" 2>/dev/null || true
        ok "Sertifikat siap: ${dir}/cert.pem"
        printf '  Buka   : https://%s:%s\n' "${ip4:-localhost}" "$port"
        printf '  Catatan: self-signed, browser akan memperingatkan sekali.\n'
        printf '  Tanpa peringatan: pakai domain + Cloudflare Tunnel (lihat vps_mcp/README.md),\n'
        printf '  atau certbot: sudo apt-get install -y certbot && sudo certbot certonly --standalone -d <domain>\n'
        printf '  lalu salin fullchain.pem ke %s/cert.pem dan privkey.pem ke %s/key.pem\n' "$dir" "$dir"
        printf '  Restart dashboard supaya TLS dipakai: bash recon.sh --web\n'
        return 0
    fi
    fail "Gagal membuat sertifikat (lihat ${LOG_FILE})."
    return 1
}

# ---------------------------------------------------------------- api keys ---
# The passive collectors read their keys from the environment; this keeps one
# protected file so cron, the dashboard subprocess and manual runs all agree.
set_api_key() {
    local name="${1:-PDCP_API_KEY}" value tmp
    case "$name" in
        PDCP_API_KEY|OTX_API_KEY|CERTSPOTTER_API_KEY) ;;
        *)
            warn "Nama tidak dikenal: ${name}"
            printf '  Yang dipakai toolkit: PDCP_API_KEY (Chaos), OTX_API_KEY, CERTSPOTTER_API_KEY\n'
            return 1
            ;;
    esac
    mkdir -p "$(dirname "$API_KEYS_FILE")" 2>/dev/null || true
    printf 'Tempel %s (input disembunyikan): ' "$name"
    read -rs value || value=""
    printf '\n'
    if [[ -z "$value" ]]; then
        fail "Kosong; tidak ada yang disimpan."
        return 1
    fi
    tmp=$(mktemp "${API_KEYS_FILE}.XXXXXX") || return 1
    [[ -f "$API_KEYS_FILE" ]] && grep -v "^${name}=" "$API_KEYS_FILE" >"$tmp" 2>/dev/null
    printf '%s=%s\n' "$name" "$value" >>"$tmp"
    mv -f "$tmp" "$API_KEYS_FILE"
    chmod 600 "$API_KEYS_FILE" 2>/dev/null || true
    ok "${name} disimpan di ${API_KEYS_FILE} (mode 600)"
    printf '  Dipakai oleh collector Chaos dan binary `chaos` (env var yang sama).\n'
    printf '  Scan berikutnya langsung memakainya; tidak perlu restart apa pun.\n'
    return 0
}

# -------------------------------------------------------------------- web ----
# Restarting used to mean finding the process by hand and starting it again in
# a terminal that had to stay open. These helpers stop whatever runs the
# dashboard and start it detached, logging to state/web.log.
web_pids() {
    pgrep -f "web_ui/server.py" 2>/dev/null || true
}

web_stop() {
    local s=1 pids
    pids=$(web_pids)
    if [[ -z "$pids" ]]; then
        info "Dashboard tidak sedang jalan."
        return 0
    fi
    info "Menghentikan dashboard ..."
    # shellcheck disable=SC2086
    kill -TERM $pids 2>/dev/null || true
    for (( s = 0; s < 8; s++ )); do
        sleep 0.5
        [[ -z "$(web_pids)" ]] && break
    done
    pids=$(web_pids)
    if [[ -n "$pids" ]]; then
        # shellcheck disable=SC2086
        kill -KILL $pids 2>/dev/null || true
    fi
    ok "Dashboard dihentikan."
    return 0
}

web_start() {
    local scheme="http" port="${RECON_WEB_PORT:-8765}" i
    [[ -f "${RECON_HOME%/}/state/tls/cert.pem" ]] && scheme="https"
    mkdir -p "$STATE_DIR" 2>/dev/null || true
    info "Menjalankan dashboard di background (log: ${STATE_DIR}/web.log) ..."
    nohup bash "${SCRIPT_DIR}/web_ui/start.sh" >>"${STATE_DIR}/web.log" 2>&1 &
    disown 2>/dev/null || true
    for i in $(seq 1 40); do
        if curl -k -s -o /dev/null --max-time 3 "${scheme}://127.0.0.1:${port}/" 2>/dev/null; then
            ok "Dashboard siap: ${scheme}://127.0.0.1:${port}"
            [[ -s "${STATE_DIR}/web_token" ]] && printf '  Token : %s\n' "$(cat "${STATE_DIR}/web_token")"
            printf '  Hentikan: bash recon.sh --web-stop\n'
            return 0
        fi
        sleep 0.5
    done
    warn "Dashboard belum menjawab; lihat ${STATE_DIR}/web.log"
    return 1
}

web_restart() {
    web_stop
    web_start
}

# Prints the URL and the access token without touching the server. Useful when a
# browser lost its session: the HTTPS address is a different origin from the old
# HTTP one, so the saved token does not carry over.
show_web_token() {
    local scheme="http" port="${RECON_WEB_PORT:-8765}" token_file="${STATE_DIR}/web_token"
    [[ -f "${RECON_HOME%/}/state/tls/cert.pem" ]] && scheme="https"
    if [[ ! -s "$token_file" ]]; then
        fail "Token belum dibuat. Jalankan dulu: bash recon.sh --web-restart"
        return 1
    fi
    printf 'URL   : %s://127.0.0.1:%s\n' "$scheme" "$port"
    printf 'Token : %s\n' "$(cat "$token_file")"
    if [[ -z "$(web_pids)" ]]; then
        printf 'Status: dashboard tidak jalan — bash recon.sh --web-restart\n'
    else
        printf 'Status: jalan (PID %s)\n' "$(web_pids | tr '\n' ' ' | sed 's/ $//')"
    fi
    printf 'Catatan: token ini setara password dashboard; jangan dibagikan.\n'
    printf 'Kalau browser masih meminta login setelah ganti http -> https, itu wajar:\n'
    printf 'localStorage terpisah per origin, jadi masuk sekali lagi dengan token di atas.\n'
    return 0
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
        printf 'Lengkapi semuanya : bash recon.sh --fix-tools\n'
        printf 'Tool inti saja    : bash setup.sh --minimal\n'
    fi

    printf '\n%bToolkit pasif (Python):%b\n' "$BOLD" "$NC"
    if [[ ! -d "$TOOLKIT_DIR" ]]; then
        printf '  %-16s %-11s %s\n' "bugbounty-toolkit" "missing" "folder tidak ditemukan"
    elif toolkit_ready && py=$(toolkit_python); then
        printf '  %-16s %-11s %s\n' "toolkit venv" "ok" "$("$py" -V 2>&1)"
        if toolkit_deps_ready; then
            printf '  %-16s %-11s %s\n' "dependensi" "ok" "requests · PyYAML · dnspython"
        else
            printf '  %-16s %-11s %s\n' "dependensi" "missing" "bash setup.sh --python-only"
        fi
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

# Tests every proxy in PROXY_FILE and keeps the ones that answer.
# APPLY_GOOD=1 replaces the file with the working entries instead of writing
# <file>.good next to it.
proxy_check() {
    local file tmp goodtmp total good proxy batch p ip

    APPLY_GOOD=${APPLY_GOOD:-0}

    file=$(conf_value PROXY_FILE || true)
    [[ -n "$file" ]] || file="state/proxies.txt"
    [[ "$file" = /* ]] || file="${RECON_HOME%/}/${file}"

    if [[ ! -f "$file" ]]; then
        fail "File proxy tidak ada: ${file} (jalankan bash setup.sh atau buat sendiri)."
        return 1
    fi

    tmp=$(mktemp) || return 1
    goodtmp=$(mktemp) || { rm -f "$tmp"; return 1; }

    # Strip comments/blank lines and give a bare host:port an http:// scheme,
    # the same normalisation load_proxies() applies.
    awk '
        /^[[:space:]]*(#|$)/ { next }
        {
            gsub(/[[:space:]]/, "")
            p = $0
            if (p !~ /:\/\//) p = "http://" p
            print p
        }
    ' "$file" > "$tmp"

    total=$(awk 'END { print NR }' "$tmp")
    total=${total:-0}
    if (( total == 0 )); then
        fail "Tidak ada proxy di ${file}."
        rm -f "$tmp" "$goodtmp"
        return 1
    fi

    info "Menguji ${total} proxy (10 sekaligus, timeout 8s) ..."
    batch=()
    while IFS= read -r proxy; do
        [[ -n "$proxy" ]] || continue
        batch+=("$proxy")
        if (( ${#batch[@]} >= 10 )); then
            for p in "${batch[@]}"; do
                (
                    ip=$(curl --silent --max-time 8 --proxy "$p" https://api.ipify.org 2>/dev/null)
                    [[ -n "$ip" ]] && printf '%s\n' "$p" >> "$goodtmp"
                ) &
            done
            wait
            batch=()
        fi
    done < "$tmp"

    if (( ${#batch[@]} > 0 )); then
        for p in "${batch[@]}"; do
            (
                ip=$(curl --silent --max-time 8 --proxy "$p" https://api.ipify.org 2>/dev/null)
                [[ -n "$ip" ]] && printf '%s\n' "$p" >> "$goodtmp"
            ) &
        done
        wait
    fi

    sort -u -o "$goodtmp" "$goodtmp" 2>/dev/null || true
    good=$(awk 'END { print NR }' "$goodtmp")
    good=${good:-0}

    if (( APPLY_GOOD )); then
        cp -f "$goodtmp" "$file"
        ok "${good}/${total} proxy hidup. File diganti dengan yang hidup: ${file}"
    else
        cp -f "$goodtmp" "${file}.good"
        ok "${good}/${total} proxy hidup. Daftar: ${file}.good"
        printf 'Pakai yang hidup: bash recon.sh --proxy-clean (ganti file) atau arahkan PROXY_FILE ke %s.good\n' "$file"
    fi

    rm -f "$tmp" "$goodtmp"
    return 0
}

# Shows only what did not work: tools that are not installed, stages that failed
# or were skipped, and the stderr each stage wrote. Complements --log, which is
# the full picture.
show_failures() {
    local domain="${1:-}" run_dir err_file shown=0 missing=0 failed=0 skipped=0

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

    printf '%b=== YANG GAGAL / SKIP: %s ===%b\n' "${BOLD}${CYAN}" "$domain" "$NC"

    printf '\n--- TOOL TIDAK TERPASANG ---\n'
    if [[ -s "$run_dir/final/tool_inventory.txt" ]]; then
        missing=$(grep -c '^MISSING' "$run_dir/final/tool_inventory.txt" 2>/dev/null)
        missing=${missing:-0}
        if (( missing > 0 )); then
            grep '^MISSING' "$run_dir/final/tool_inventory.txt" | sed 's/ (related stage is skipped)//'
        else
            printf '_semua tool yang dipakai pipeline terpasang_\n'
        fi
    else
        printf '_tool_inventory.txt tidak ada (run terlalu lama/terputus)_\n'
    fi

    printf '\n--- STAGE GAGAL ---\n'
    if [[ -s "$run_dir/logs/stages.tsv" ]]; then
        failed=$(awk -F'\t' '$2 == "failed" || $2 == "degraded"' "$run_dir/logs/stages.tsv" 2>/dev/null | wc -l | tr -d '[:space:]')
        if (( ${failed:-0} > 0 )); then
            awk -F'\t' '$2 == "failed" || $2 == "degraded" { printf "%-12s %-10s %s\n", $1, $2, $3 }' "$run_dir/logs/stages.tsv"
        else
            printf '_tidak ada stage yang gagal_\n'
        fi

        printf '\n--- STAGE DISKIP (normal, bukan error) ---\n'
        skipped=$(awk -F'\t' '$2 == "skipped"' "$run_dir/logs/stages.tsv" 2>/dev/null | wc -l | tr -d '[:space:]')
        if (( ${skipped:-0} > 0 )); then
            awk -F'\t' '$2 == "skipped" { printf "%-12s %s\n", $1, $3 }' "$run_dir/logs/stages.tsv"
        else
            printf '_tidak ada stage yang diskip_\n'
        fi
    else
        printf '_stages.tsv tidak ada_\n'
    fi

    printf '\n--- DETAIL ERROR PER STAGE ---\n'
    for err_file in "$run_dir"/logs/*.err; do
        [[ -s "$err_file" ]] || continue
        printf '\n[%s]\n' "$(basename -- "$err_file")"
        grep -E '^exit=' "$err_file" 2>/dev/null | tail -n 2 | sed 's/^/  /'
        tail -n 8 "$err_file" | sed 's/^/  /'
        shown=$((shown + 1))
        if (( shown >= 15 )); then
            printf '\n... sisanya lihat %s/logs/\n' "$run_dir"
            break
        fi
    done
    (( shown == 0 )) && printf '_tidak ada stderr dari tool mana pun_\n'

    printf '\nLog lengkap : bash recon.sh --log %s\n' "$domain"
    printf 'Pasang yang kurang: bash recon.sh --fix-tools\n'
    return 0
}

# Cheap syntax check of every script, so a bad pull is caught before a run.
self_test() {
    local rc=0 script err

    for script in recon_pro.sh recon.sh setup.sh; do
        [[ -f "$SCRIPT_DIR/$script" ]] || continue
        if ! bash -n "$SCRIPT_DIR/$script" 2>/tmp/.recon_syn; then
            err=$(head -n 2 /tmp/.recon_syn | tr '\n' ' ')
            fail "$script: $err"
            rc=1
        fi
    done

    if [[ -f "$SCRIPT_DIR/recon_pro_bot.py" ]] && command -v python3 >/dev/null 2>&1; then
        if ! python3 -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' \
            "$SCRIPT_DIR/recon_pro_bot.py" 2>/tmp/.recon_syn; then
            err=$(tail -n 2 /tmp/.recon_syn | tr '\n' ' ')
            fail "recon_pro_bot.py: $err"
            rc=1
        fi
    fi

    rm -f /tmp/.recon_syn
    (( rc == 0 )) && ok "sintaks semua skrip ok"
    return "$rc"
}

# Updates the checkout, then re-checks every script.
update_repo() {
    local before after pid

    if [[ ! -d "$SCRIPT_DIR/.git" ]]; then
        fail "Bukan repo git: ${SCRIPT_DIR}"
        return 1
    fi
    if ! command -v git >/dev/null 2>&1; then
        fail "git tidak terpasang."
        return 1
    fi

    before=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || true)
    info "git pull di ${SCRIPT_DIR} ..."
    if ! git -C "$SCRIPT_DIR" pull --ff-only; then
        fail "git pull gagal (commit lokal / perubahan file?). Selesaikan dulu, lalu ulangi."
        return 1
    fi
    after=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || true)

    if [[ "$before" == "$after" ]]; then
        ok "Sudah versi terbaru (${after})."
    else
        ok "Update: ${before:-?} -> ${after:-?}"
    fi

    self_test

    pid=$(tr -dc '0-9' < "$RECON_HOME/state/bot/bot.lock" 2>/dev/null)
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        warn "Bot masih jalan dengan kode lama (PID ${pid}). Restart: bash recon.sh --stop-bot && python3 recon_pro_bot.py"
    fi
    return 0
}

# ----------------------------------------------------------------- doctor ----
# One screen of health: system, storage, updates, tools, keys, TLS, dashboard.
# Read-only; nothing here changes the machine.
doctor_line() {
    local color="$NC"
    case "$3" in
        ok) color="$GREEN" ;;
        warn|fail) color="$YELLOW"; DOCTOR_WARN=$((DOCTOR_WARN + 1)) ;;
    esac
    printf '  %b%-14s%b %s\n' "$color" "$1" "$NC" "$2"
}

show_doctor() {
    local os_name load mem_total mem_avail swap_total swap_free disk_use port
    local upd_total upd_sec missing_tools py key_names keys_have cert cert_end cert_days
    local scheme code pid domain
    DOCTOR_WARN=0
    port="${RECON_WEB_PORT:-8765}"

    printf '%b=== DOCTOR ===%b\n' "${BOLD}${CYAN}" "$NC"

    if [[ -r /etc/os-release ]]; then
        os_name=$(. /etc/os-release >/dev/null 2>&1; printf '%s' "${PRETTY_NAME:-${NAME:-linux}}")
    else
        os_name=$(uname -sr)
    fi
    load=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null)
    doctor_line "Sistem" "${os_name:-?} · load ${load:-?}" info
    if [[ -r /proc/meminfo ]]; then
        mem_total=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
        mem_avail=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
        swap_total=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)
        swap_free=$(awk '/^SwapFree:/ {print $2}' /proc/meminfo)
        if [[ -n "$mem_total" && -n "$mem_avail" ]] && (( mem_total > 0 )); then
            local used_mb avail_mb swap_mb
            used_mb=$(( (mem_total - mem_avail) / 1024 ))
            avail_mb=$(( mem_avail / 1024 ))
            swap_mb=$(( (swap_total - swap_free) / 1024 ))
            if (( avail_mb < 200 )); then
                doctor_line "RAM" "${used_mb}MB dipakai · ${avail_mb}MB tersedia · swap ${swap_mb}MB" warn
            else
                doctor_line "RAM" "${used_mb}MB dipakai · ${avail_mb}MB tersedia · swap ${swap_mb}MB" ok
            fi
        fi
    fi

    disk_use=$(df -P / 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
    if [[ -n "$disk_use" ]]; then
        if (( disk_use >= 85 )); then
            doctor_line "Disk" "${disk_use}% terpakai — bash recon.sh --disk" warn
        else
            doctor_line "Disk" "${disk_use}% terpakai" ok
        fi
    fi

    if command -v apt-get >/dev/null 2>&1; then
        upd_total=$(timeout 40 apt list --upgradable 2>/dev/null | tail -n +2 | grep -c . || true)
        upd_sec=$(timeout 40 apt list --upgradable 2>/dev/null | grep -c 'security' || true)
        if [[ -n "$upd_sec" ]] && (( upd_sec > 0 )); then
            doctor_line "Update apt" "${upd_total:-0} paket, ${upd_sec} security — sudo apt-get upgrade" warn
        else
            doctor_line "Update apt" "${upd_total:-0} paket tertunda" ok
        fi
    fi

    missing_tools=""
    for py in curl jq python3 subfinder httpx nuclei dnsx tlsx katana waybackurls gau dalfox ffuf nmap; do
        command -v "$py" >/dev/null 2>&1 || missing_tools="${missing_tools} ${py}"
    done
    if [[ -n "$missing_tools" ]]; then
        doctor_line "Tool inti" "belum ada:${missing_tools}" warn
    else
        doctor_line "Tool inti" "lengkap" ok
    fi

    if toolkit_deps_ready; then
        doctor_line "Toolkit pasif" "venv + requests/PyYAML/dnspython ok" ok
    elif toolkit_ready; then
        doctor_line "Toolkit pasif" "dependensi kurang — bash setup.sh --python-only" warn
    else
        doctor_line "Toolkit pasif" "belum siap — bash setup.sh --python-only" warn
    fi

    key_names=""
    keys_have=0
    local name
    for name in PDCP_API_KEY OTX_API_KEY CERTSPOTTER_API_KEY; do
        if declare -p "$name" >/dev/null 2>&1; then
            keys_have=$((keys_have + 1))
            key_names="${key_names} ${name}"
        fi
    done
    if (( keys_have > 0 )); then
        doctor_line "API key" "${keys_have} terpasang:${key_names}" ok
    else
        doctor_line "API key" "belum ada — bash recon.sh --api-key" info
    fi

    cert="${RECON_HOME%/}/state/tls/cert.pem"
    scheme="http"
    if [[ -f "$cert" ]]; then
        scheme="https"
        cert_end=$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null | cut -d= -f2)
        cert_days=""
        if [[ -n "$cert_end" ]]; then
            local end_epoch
            end_epoch=$(date -d "$cert_end" +%s 2>/dev/null || true)
            [[ -n "$end_epoch" ]] && cert_days=$(( (end_epoch - $(date +%s)) / 86400 ))
        fi
        if [[ -n "$cert_days" ]] && (( cert_days < 14 )); then
            doctor_line "TLS" "sertifikat habis dalam ${cert_days} hari — bash recon.sh --ssl" warn
        else
            doctor_line "TLS" "aktif${cert_days:+, ${cert_days} hari lagi}" ok
        fi
    else
        doctor_line "TLS" "belum ada sertifikat — bash recon.sh --ssl (opsional)" info
    fi

    code=$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 5 "${scheme}://127.0.0.1:${port}/" 2>/dev/null || true)
    if [[ "$code" == "200" ]]; then
        doctor_line "Dashboard" "${scheme}://127.0.0.1:${port} menjawab 200" ok
    elif [[ -n "$code" && "$code" != "000" ]]; then
        doctor_line "Dashboard" "${scheme}://127.0.0.1:${port} menjawab ${code}" info
    else
        doctor_line "Dashboard" "tidak menjawab — bash recon.sh --web" info
    fi

    pid=$(tr -dc '0-9' < "$RECON_HOME/state/bot/bot.lock" 2>/dev/null)
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        doctor_line "Bot Telegram" "jalan (PID ${pid})" ok
    else
        doctor_line "Bot Telegram" "tidak jalan" info
    fi

    domain=$(latest_domain)
    if [[ -n "$domain" && -d "$RUNS_DIR/$domain" ]]; then
        doctor_line "Scan terakhir" "${domain} · $(ls -1t "$RUNS_DIR/$domain" 2>/dev/null | head -n 1)" ok
    else
        doctor_line "Scan terakhir" "belum ada run" info
    fi

    printf '\n'
    if (( DOCTOR_WARN > 0 )); then
        warn "${DOCTOR_WARN} hal perlu perhatian."
    else
        ok "Semua pemeriksaan lolos."
    fi
    return 0
}

# One-screen overview of the whole install.
show_status() {
    local domain have=0 miss=0 t pf count=0 pid findings=0
    local -a missing_tools=()

    domain=$(latest_domain)

    printf '%b=== STATUS ===%b\n' "${BOLD}${CYAN}" "$NC"
    printf 'Folder kode  : %s\n' "$SCRIPT_DIR"
    printf 'Folder data  : %s\n' "$RECON_HOME"
    printf 'Target akhir : %s\n' "${domain:-<belum ada>}"

    for t in curl jq subfinder httpx dnsx nuclei tlsx naabu katana waybackurls gau dalfox ffuf nmap x8; do
        if command -v "$t" >/dev/null 2>&1; then
            have=$((have + 1))
        else
            miss=$((miss + 1))
            missing_tools+=("$t")
        fi
    done
    printf 'Tool         : %s ok, %s missing%s\n' "$have" "$miss" \
        "$( (( miss )) && printf ' (%s)' "${missing_tools[*]}" )"

    if toolkit_ready; then
        printf 'Toolkit pasif: ok (%s)\n' "$TOOLKIT_DIR/.venv"
    else
        printf 'Toolkit pasif: belum siap (bash setup.sh --python-only)\n'
    fi

    pf=$(conf_value PROXY_FILE || true)
    [[ -n "$pf" ]] || pf="state/proxies.txt"
    [[ "$pf" = /* ]] || pf="${RECON_HOME%/}/${pf}"
    if [[ -f "$pf" ]]; then
        count=$(grep -cvE '^[[:space:]]*(#|$)' "$pf" 2>/dev/null)
        printf 'Proxy        : %s entr(y) (%s)\n' "${count:-0}" "$pf"
    else
        printf 'Proxy        : belum ada file (%s)\n' "$pf"
    fi

    pid=$(tr -dc '0-9' < "$RECON_HOME/state/bot/bot.lock" 2>/dev/null)
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        printf 'Bot          : jalan (PID %s)\n' "$pid"
    else
        printf 'Bot          : tidak jalan\n'
    fi

    if [[ -n "$domain" && -d "$RUNS_DIR/$domain/latest" ]]; then
        if [[ -s "$RUNS_DIR/$domain/latest/final/findings.tsv" ]]; then
            findings=$(awk 'END { print NR }' "$RUNS_DIR/$domain/latest/final/findings.tsv")
        fi
        printf 'Run terakhir : %s (%s temuan)\n' "$domain" "${findings:-0}"
    fi

    printf 'Laporan aktif: %s\n' "$(report_path "$domain" 2>/dev/null || printf '-')"
    printf 'Laporan pasif: %s\n' "$(passive_report_path "$domain" 2>/dev/null || printf '-')"
    return 0
}

# Installs the bot as a systemd service so it survives SSH logout and reboots.
install_service() {
    local unit="/etc/systemd/system/recon-pro-bot.service"
    local py="python3"

    if (( EUID != 0 )); then
        fail "Perlu root: sudo bash recon.sh --install-service"
        return 1
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        fail "systemd tidak tersedia di mesin ini."
        return 1
    fi
    command -v python3 >/dev/null 2>&1 && py=$(command -v python3)

    if ! "$py" -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' \
        "$SCRIPT_DIR/recon_pro_bot.py" 2>/dev/null; then
        fail "recon_pro_bot.py belum lolos cek sintaks; jalankan --self-test dulu."
        return 1
    fi

    cat > "$unit" <<EOF
[Unit]
Description=Recon Pro Telegram bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${py} ${SCRIPT_DIR}/recon_pro_bot.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

    if ! systemctl daemon-reload || ! systemctl enable --now recon-pro-bot; then
        fail "Gagal mengaktifkan service. Cek: systemctl status recon-pro-bot"
        return 1
    fi

    ok "Service terpasang: ${unit}"
    printf 'Cek   : systemctl status recon-pro-bot\n'
    printf 'Log   : journalctl -u recon-pro-bot -f\n'
    printf 'Stop  : systemctl disable --now recon-pro-bot\n'
    return 0
}

# ---------------------------------------------------------------- arg parsing --
DOMAIN=""
ACTION=""
ASSUME=0
NO_SETUP=0
NO_PASSIVE=0
CLEAN_APPLY=0
CLEAN_DIR="${HOME:-/root}"
HOST_NAME=""
KEY_NAME="PDCP_API_KEY"
PROFILE=""

while (( $# )); do
    case "$1" in
        -h|--help)    usage; exit 0 ;;
        -y|--yes)     ASSUME=1 ;;
        --setup)      ACTION="setup" ;;
        --fix-tools|--install-missing) ACTION="fixtools" ;;
        --clean)
            ACTION="clean"
            CLEAN_DIR="${HOME:-/root}"
            if [[ -n "${2:-}" && "${2:-}" != -* ]]; then
                CLEAN_DIR="$2"
                shift
            fi
            ;;
        --apply)      CLEAN_APPLY=1 ;;
        --disk|--storage) ACTION="disk" ;;
        --doctor|--health) ACTION="doctor" ;;
        --ssl|--tls)
            ACTION="ssl"
            if [[ -n "${2:-}" && "${2:-}" != -* ]]; then
                HOST_NAME="$2"
                shift
            fi
            ;;
        --api-key|--set-key)
            ACTION="apikey"
            if [[ -n "${2:-}" && "${2:-}" != -* ]]; then
                KEY_NAME="$2"
                shift
            fi
            ;;
        --passive)    ACTION="passive" ;;
        --no-passive) NO_PASSIVE=1 ;;
        --fast)       PROFILE="fast" ;;
        --deep)       PROFILE="deep" ;;
        --max)        PROFILE="max" ;;
        --tools|--check|-c) ACTION="tools" ;;
        --web|--dashboard) ACTION="web" ;;
        --web-restart) ACTION="webrestart" ;;
        --web-stop)   ACTION="webstop" ;;
        --web-token)  ACTION="webtoken" ;;
        --telegram)   ACTION="telegram" ;;
        --notify-test) ACTION="notify" ;;
        --stop-bot)   ACTION="stopbot" ;;
        --bot-status) ACTION="botstatus" ;;
        --proxy-check) ACTION="proxycheck" ;;
        --proxy-clean) ACTION="proxyclean" ;;
        --self-test)  ACTION="selftest" ;;
        --update)     ACTION="update" ;;
        --status)     ACTION="status" ;;
        --install-service) ACTION="service" ;;
        --no-setup)   NO_SETUP=1 ;;
        --report)
            ACTION="report"
            if [[ -n "${2:-}" && "${2:-}" != -* ]]; then
                DOMAIN="$2"
                shift
            fi
            ;;
        --timings)
            ACTION="timings"
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
        --failures|--failed)
            ACTION="failures"
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
        exec "$BASH_BIN" "$SCRIPT_DIR/setup.sh" "$@"
        ;;
    fixtools)
        exec "$BASH_BIN" "$SCRIPT_DIR/setup.sh" --with-arsenal
        ;;
    tools)
        show_tools
        exit 0
        ;;
    clean)
        show_clean "$CLEAN_DIR" "$CLEAN_APPLY"
        exit $?
        ;;
    disk)
        show_disk
        exit $?
        ;;
    doctor)
        show_doctor
        exit $?
        ;;
    ssl)
        run_ssl "$HOST_NAME"
        exit $?
        ;;
    apikey)
        set_api_key "$KEY_NAME"
        exit $?
        ;;
    web)
        exec "$BASH_BIN" "$SCRIPT_DIR/web_ui/start.sh"
        ;;
    webstop)
        web_stop
        exit $?
        ;;
    webrestart)
        web_restart
        exit $?
        ;;
    webtoken)
        show_web_token
        exit $?
        ;;
    report)
        show_report_detail "$DOMAIN"
        exit $?
        ;;
    log)
        show_log "$DOMAIN"
        exit $?
        ;;
    timings)
        show_timings "$DOMAIN"
        exit $?
        ;;
    failures)
        show_failures "$DOMAIN"
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
    proxycheck)
        APPLY_GOOD=0
        proxy_check
        exit $?
        ;;
    proxyclean)
        APPLY_GOOD=1
        proxy_check
        exit $?
        ;;
    selftest)
        self_test
        exit $?
        ;;
    update)
        update_repo
        exit $?
        ;;
    status)
        show_status
        exit 0
        ;;
    service)
        install_service
        exit $?
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
    toolkit_deps_ready || py_missing=1
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
    if ! toolkit_deps_ready && (( ! NO_SETUP )); then
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
if [[ -n "$PROFILE" ]]; then
    export RECON_PRO_PROFILE="$PROFILE"
    info "Profil: ${PROFILE} (mengalahkan angka di ${CONFIG_FILE} untuk run ini)"
fi
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
