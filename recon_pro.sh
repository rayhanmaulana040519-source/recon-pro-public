#!/usr/bin/env bash
# ============================================
# RECON PRO — authorized bug bounty workflow
# ============================================
#
# Requirements: bash 4+, curl. jq is strongly recommended (JSON parsing and the
# fast header audit). Every external scanner is optional: a missing tool skips
# its stage, and the final report records what actually ran.
#
# Two kinds of stage run here. Collection stages gather candidates (subdomains,
# URLs, parameters, ports) and can only ever produce observations. Confirmation
# stages prove or discard a candidate with a second, independent signal: a
# takeover fingerprint in the body, an Origin header that comes back reflected,
# a file whose content matches the format it claims, a redirect that leaves the
# host, a schema that answers introspection. Those land in final/findings.tsv,
# ranked by score, and are what the report puts first.

set -uo pipefail
umask 077

# This script uses bash 4 expansions (${var,,}, ${var^^}); bash 3.2 (still the
# default /bin/bash on macOS) aborts mid-session with "bad substitution".
if (( ${BASH_VERSINFO[0]:-0} < 4 )); then
    printf 'ERROR: bash 4.0 or newer is required (running %s).\n' "${BASH_VERSION:-unknown}" >&2
    printf 'macOS: brew install bash, then run /opt/homebrew/bin/bash %s\n' "$0" >&2
    exit 1
fi

VERSION="4.0"
AUTHOR="rey"
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# ------------------------------------------------------------------- folders --
#
# Everything this tool writes lives inside one root folder, so the home
# directory never fills up with run folders and "where are my results?" always
# has the same answer:
#
#   <root>/runs/<domain>/recon_<domain>_<timestamp>/   one scan workspace
#   <root>/runs/<domain>/latest                        link to the newest run
#   <root>/reports/<domain>/                           copies of the newest report
#   <root>/state/                                      config, exclusions, bot state
#
# Set RECON_PRO_HOME to move the root (or the OUTPUT_BASE setting for the runs
# folder alone); a relative path resolves against the root, never against the
# directory the script happened to be started from.
RECON_HOME="${RECON_PRO_HOME:-${HOME:-.}/recon_pro}"
RUNS_DIR="${RECON_HOME%/}/runs"
REPORTS_DIR="${RECON_HOME%/}/reports"
STATE_DIR="${RECON_HOME%/}/state"

CONFIG_FILE="${STATE_DIR}/recon_pro.conf"
EXCLUDE_FILE="${STATE_DIR}/exclusions.txt"

# Where earlier versions kept their files. They are moved into the tree on the
# first start, so an existing config, exclusion list, scope list and bot state
# keep working without being re-created.
LEGACY_CONFIG_FILE="${HOME:-.}/.recon_pro.conf"
LEGACY_EXCLUDE_FILE="${HOME:-.}/.recon_pro_exclusions.txt"
LEGACY_SCOPE_FILE="${HOME:-.}/.recon_pro_scope.txt"
LEGACY_STATE_DIR="${HOME:-.}/.recon_pro_bot"

DOMAIN=""
OUTPUT_DIR=""
# Runs are written below this directory, so the workspace is always at the same
# predictable place no matter which directory the script was started from.
OUTPUT_BASE="$RUNS_DIR"
THREADS=20
RATE_LIMIT=50
STAGE_TIMEOUT=1800
WEB_PORTS=""
WORDLIST="/usr/share/wordlists/dirb/common.txt"
PARAM_WORDLIST="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
X8_MAX_URLS=40
ARCHIVE_MAX_URLS=150
DALFOX_MAX_URLS=150
FUZZ_MAX_HOSTS=3
NMAP_MAX_HOSTS=10
NUCLEI_INTERACTSH=0
# Retention for the runs folder of one domain: 0 keeps every run, n keeps the
# newest n and deletes older ones after a finished run.
KEEP_RUNS=0

# Rotating proxy for the traffic this pipeline sends, so the target sees the exit
# node instead of your own IP. PROXY_FILE holds one proxy per line
# ("http://user:pass@host:3128", "socks5://host:1080"). Rotation is per stage and
# per request.
#
# DNS (dnsx) and nmap are not HTTP clients and cannot go through an HTTP/SOCKS
# proxy: the resolver and the raw TCP connect still see the source IP. The
# scanners that do support a proxy flag are detected at runtime, never assumed.
PROXY_FILE="${STATE_DIR}/proxies.txt"
PROXY_ROTATE=1
PROXY_REQUIRED=0

PROXIES=()
PROXY_INDEX=0
PROXY_CURRENT=""
P_ARGS=()
declare -A PROXY_FLAG_CACHE=()

# Set by diff_against_previous so the report can describe changes safely.
DIFF_PREVIOUS=""
DIFF_NEW_HOSTS=0
DIFF_GONE_HOSTS=0
DIFF_NEW_FINDINGS=0

# Confirmation stages. Each one only adds evidence to the report; turning one
# off removes its section and nothing else.
MODULE_CORS=1
MODULE_EXPOSURES=1
MODULE_JS=1
MODULE_TAKEOVER=1
MODULE_GRAPHQL=1
MODULE_OPENREDIR=1
NUCLEI_AUTOCALIBRATE=1
NUCLEI_DAST=0
NUCLEI_HEADLESS=0
CORS_MAX_URLS=50
EXPOSURE_MAX_HOSTS=10
JS_MAX_FILES=40
GRAPHQL_MAX_HOSTS=10
OPENAPI_MAX_HOSTS=10
OPENAPI_MAX_ENDPOINTS=100
JS_MAX_SOURCE_MAPS=10
JS_MAX_ENDPOINTS=500
MODULE_TESTSSL=0
TESTSSL_MAX_HOSTS=10
OPENREDIR_MAX_URLS=40
TAKEOVER_MAX_HOSTS=200

# Telegram alerts. The end-of-run message always says whether anything was
# found and lists every high/critical finding; the instant alert is the short
# ping sent the moment such a finding is recorded.
TELEGRAM_INSTANT=1
TELEGRAM_INSTANT_MIN_SCORE=90
TELEGRAM_INSTANT_MAX=10

# Optional: paste your bot token and chat ID between the quotes to have this
# copy always know where to send alerts, without touching the config file.
# Leave both empty if you ever share or upload this script — anyone who reads
# the file can post to that chat with the token.
TELEGRAM_BOT_TOKEN_DEFAULT=""
TELEGRAM_CHAT_ID_DEFAULT=""

TELEGRAM_TOKEN="${TELEGRAM_BOT_TOKEN:-${TELEGRAM_BOT_TOKEN_DEFAULT}}"
TELEGRAM_CHAT="${TELEGRAM_CHAT_ID:-${TELEGRAM_CHAT_ID_DEFAULT}}"
# Numeric Telegram user IDs allowed to drive recon_pro_bot.py. The scan script
# never uses it, but it is preserved here so saving settings cannot drop it.
TELEGRAM_ALLOWED_USERS=""
ASSUME_YES=0
CHECK_ONLY=0
# Stages run one after another. STAGE_MARK holds $SECONDS from the previous
# stage_status call, so the next one can report how long it actually took.
STAGE_MARK=0

# ---------------------------------------------------------------- utilities --

log() {
    local level="$1" msg="$2" timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    if [[ -n "$OUTPUT_DIR" && -d "${OUTPUT_DIR}/logs" ]]; then
        printf '[%s] [%s] %s\n' "$timestamp" "$level" "$msg" >> "${OUTPUT_DIR}/logs/pipeline.log" 2>/dev/null || true
    fi
    case "$level" in
        ERROR) printf '%b[!] %s%b\n' "$RED" "$msg" "$NC" ;;
        WARN)  printf '%b[!] %s%b\n' "$YELLOW" "$msg" "$NC" ;;
        INFO)  printf '%b[*] %s%b\n' "$CYAN" "$msg" "$NC" ;;
        OK)    printf '%b[+] %s%b\n' "$GREEN" "$msg" "$NC" ;;
    esac
}

check_tool() {
    command -v "$1" >/dev/null 2>&1
}

# A plain horizontal rule for the console output and the written report.
rule() {
    printf -- '-%.0s' $(seq 1 78)
    printf '\n'
}

have_jq() {
    check_tool jq
}

is_uint_between() {
    local value="$1" min="$2" max="$3"
    # A bounded length keeps the arithmetic from wrapping around on absurd input
    # (every setting we validate fits in six digits).
    [[ "$value" =~ ^[0-9]{1,6}$ ]] || return 1
    (( 10#$value >= min && 10#$value <= max ))
}

valid_domain() {
    local domain="$1" label
    local -a labels
    [[ ${#domain} -le 253 && "$domain" == *.* ]] || return 1
    IFS='.' read -r -a labels <<< "$domain"
    (( ${#labels[@]} >= 2 )) || return 1
    for label in "${labels[@]}"; do
        [[ "$label" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || return 1
    done
    # Bare IPv4 targets pass the label test but have no subdomain surface.
    [[ "${labels[${#labels[@]}-1]}" =~ ^[0-9]+$ ]] && return 1
    return 0
}

count_lines() {
    local file="$1" count
    if [[ ! -s "$file" ]]; then
        printf '0'
        return 0
    fi
    # awk counts a last line with no trailing newline; wc -l does not.
    count=$(awk 'END { print NR }' "$file" 2>/dev/null | tr -d '[:space:]')
    printf '%s' "${count:-0}"
}

# Returns the configured wordlist when it exists, otherwise the first fallback
# that does, so a fresh box does not silently skip the ffuf and x8 stages.
pick_wordlist() {
    local configured="$1" candidate
    shift
    if [[ -n "$configured" && -f "$configured" ]]; then
        printf '%s' "$configured"
        return 0
    fi
    for candidate in "$@"; do
        if [[ -f "$candidate" ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    printf '%s' "$configured"
}

resolve_wordlists() {
    local directory_list parameter_list
    directory_list=$(pick_wordlist "$WORDLIST" \
        /usr/share/wordlists/dirb/common.txt \
        /usr/share/seclists/Discovery/Web-Content/common.txt \
        /opt/seclists/Discovery/Web-Content/common.txt \
        /usr/share/wordlists/dirb/big.txt)
    parameter_list=$(pick_wordlist "$PARAM_WORDLIST" \
        /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
        /opt/seclists/Discovery/Web-Content/burp-parameter-names.txt)

    if [[ "$directory_list" != "$WORDLIST" ]]; then
        log INFO "Directory wordlist falls back to ${directory_list}"
    fi
    if [[ "$parameter_list" != "$PARAM_WORDLIST" ]]; then
        log INFO "Parameter wordlist falls back to ${parameter_list}"
    fi
    WORDLIST="$directory_list"
    PARAM_WORDLIST="$parameter_list"
}

# ------------------------------------------------- http and findings toolkit --
#
# Primitives shared by the confirmation stages: a URL's host, a severity score,
# a body and header fetcher, origin extraction, query rewriting, and the findings
# ledger every module appends to.

host_of() {
    local host="$1"
    host="${host#*://}"
    host="${host%%[/?#]*}"
    host="${host##*@}"
    host="${host%%:*}"
    printf '%s' "${host,,}"
}

severity_score() {
    case "${1,,}" in
        critical) printf '95' ;;
        high)     printf '80' ;;
        medium)   printf '55' ;;
        low)      printf '30' ;;
        info)     printf '10' ;;
        *)        printf '20' ;;
    esac
}

# validate_finding <score> <confidence> <tool> <host> <title> [evidence]
#
# confidence is one of: confirmed (behaviour was observed), likely (strong
# signal, one step from proof), unverified (needs a human).
add_finding() {
    [[ -n "$OUTPUT_DIR" ]] || return 0
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$1" "$2" "$3" "$4" "$5" "${6:-}" \
        >> "${OUTPUT_DIR}/final/findings.all.tsv" 2>/dev/null || true
    # A high/critical finding is also announced immediately, not only at the end.
    if (( TELEGRAM_INSTANT )) && (( ${1:-0} >= TELEGRAM_INSTANT_MIN_SCORE )); then
        telegram_alert "$@"
    fi
}

# One row per (tool, host, title), highest score first.
finalize_findings() {
    local all="${OUTPUT_DIR}/final/findings.all.tsv"
    local out="${OUTPUT_DIR}/final/findings.tsv"
    : > "$out"
    [[ -s "$all" ]] || return 0
    awk -F'\t' '!seen[$3 FS $4 FS $5]++' "$all" \
        | sort -t $'\t' -k1,1nr -k3,3 > "$out"
}

fetch_body() {
    local url="$1" out="$2" limit="${3:-10}"
    check_tool curl || return 1
    curl_any --silent --show-error --location --compressed --max-time "$limit" \
        --max-filesize 2097152 \
        --user-agent "Mozilla/5.0 (compatible; recon-pro/${VERSION})" \
        --output "$out" "$url" 2>/dev/null
}

fetch_headers() {
    local url="$1" out="$2" limit="${3:-10}"
    check_tool curl || return 1
    curl_any --silent --show-error --max-time "$limit" --max-redirs 0 \
        --user-agent "Mozilla/5.0 (compatible; recon-pro/${VERSION})" \
        --dump-header "$out" --output /dev/null "$url" 2>/dev/null
}

# case-insensitive single header lookup from a dumped header file
header_value() {
    local file="$1" name="$2"
    awk -v want="$name" '
        {
            line = $0
            sub(/\r$/, "", line)
            pos = index(line, ":")
            if (pos == 0) next
            if (tolower(substr(line, 1, pos - 1)) != want) next
            val = substr(line, pos + 1)
            sub(/^[ \t]+/, "", val)
            print val
            exit
        }
    ' "$file" 2>/dev/null
}

# unique_origins <input-url-file> <output> [cap]
# scheme://host[:port], apex first, deduped, optionally capped.
unique_origins() {
    local input="$1" out="$2" cap="${3:-0}"
    [[ -f "$input" ]] || : > "$input"
    awk -v d="$DOMAIN" '
        {
            origin = $1
            if (match(origin, /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\/?#]+/)) {
                origin = substr(origin, 1, RLENGTH)
            } else {
                sub(/[\/?#].*$/, "", origin)
                origin = "https://" origin
            }
            author = origin
            sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "", author)
            sub(/^.*@/, "", author)
            sub(/:[0-9]+$/, "", author)
            author = tolower(author)
            if (author in seen) next
            seen[author] = 1
            printf "%s %s\n", (author == d ? "0" : "1"), origin
        }
    ' "$input" | sort -k1,1 -k2,2 | cut -d' ' -f2 \
        | { if (( cap > 0 )); then head -n "$cap"; else cat; fi; } > "$out"
}

# build_param_candidates: dedup key = endpoint + sorted parameter NAMES, so
# ?id=1 and ?id=2 collapse into one candidate while ?id=1 and ?id=1&q=2 stay
# distinct.
build_param_candidates() {
    local src="${OUTPUT_DIR}/urls/all.txt"
    local out="${OUTPUT_DIR}/urls/params.txt"
    [[ -f "$src" ]] || : > "$src"
    awk '
        # Analytics parameters say nothing about the application, and a URL
        # that carries only tracking is not worth a scan slot, so they are
        # dropped before the dedup key is built. Static assets have no
        # parameters to test either.
        function noise(name,   n) {
            n = tolower(name)
            if (n ~ /^utm_/) return 1
            if (n == "gclid" || n == "fbclid" || n == "msclkid" || n == "yclid" || n == "dclid") return 1
            if (n == "mc_cid" || n == "mc_eid" || n == "_ga" || n == "_gl") return 1
            if (n == "ref" || n == "referrer" || n == "srsltid" || n == "igshid" || n == "mkt_tok") return 1
            if (n == "gbraid" || n == "wbraid") return 1
            return 0
        }
        {
            url = $0
            pos = index(url, "?")
            if (pos == 0) next
            endpoint = substr(url, 1, pos - 1)
            if (tolower(endpoint) ~ /\.(png|jpe?g|gif|svg|ico|css|js|woff2?|ttf|eot|otf|map|mp4|webm|mp3|avi|webp|avif|bmp|tiff?)$/) next
            query = substr(url, pos + 1)
            sub(/#.*$/, "", query)
            if (index(query, "=") == 0) next
            n = split(query, pairs, "&")
            delete names
            count = 0
            for (i = 1; i <= n; i++) {
                eq = index(pairs[i], "=")
                name = (eq > 0) ? substr(pairs[i], 1, eq - 1) : pairs[i]
                if (name == "" || noise(name)) continue
                names[++count] = name
            }
            if (count == 0) next
            for (i = 2; i <= count; i++) {
                t = names[i]
                j = i - 1
                while (j >= 1 && names[j] > t) { names[j + 1] = names[j]; j-- }
                names[j + 1] = t
            }
            key = endpoint "?"
            for (i = 1; i <= count; i++) key = key names[i] "&"
            if (key in seen) next
            seen[key] = 1
            print url
        }
    ' "$src" > "${out}.tmp"
    mv -f -- "${out}.tmp" "$out"
}

# parameter names of a single URL, one per line
param_names() {
    awk '
        {
            pos = index($0, "?")
            if (pos == 0) next
            query = substr($0, pos + 1)
            sub(/#.*$/, "", query)
            n = split(query, pairs, "&")
            for (i = 1; i <= n; i++) {
                eq = index(pairs[i], "=")
                name = (eq > 0) ? substr(pairs[i], 1, eq - 1) : pairs[i]
                if (name != "") print name
            }
        }
    ' <<< "$1"
}

# replace_param_value <url> <name> <value>
replace_param_value() {
    awk -v want="$2" -v repl="$3" -v url="$1" '
        BEGIN {
            pos = index(url, "?")
            if (pos == 0) { print url; exit }
            base = substr(url, 1, pos)
            query = substr(url, pos + 1)
            n = split(query, pairs, "&")
            out = ""
            for (i = 1; i <= n; i++) {
                eq = index(pairs[i], "=")
                name = (eq > 0) ? substr(pairs[i], 1, eq - 1) : pairs[i]
                if (tolower(name) == tolower(want)) pairs[i] = name "=" repl
                out = out (i > 1 ? "&" : "") pairs[i]
            }
            print base out
        }
    '
}

ask_toggle() {
    local prompt="$1" current="$2" value
    read -r -p "${prompt} [${current}, 1=on 0=off]: " value || value=""
    case "$value" in
        0|1) printf '%s' "$value" ;;
        *)   printf '%s' "$current" ;;
    esac
}

describe_status() {
    case "$1" in
        0) printf 'ok' ;;
        124) printf 'timed out after %ss' "$STAGE_TIMEOUT" ;;
        126) printf 'not executable' ;;
        127) printf 'not found' ;;
        *) printf 'exit %s' "$1" ;;
    esac
}

# Record one stage for the final report: name, state (ok/skipped/failed), note.
# Field 4 is the elapsed time since the previous stage (seconds) and field 5 is
# the local finish time, so a slow run can be tuned with numbers instead of
# guesswork. Older rows keep their 3 fields and are read as "no duration".
stage_status() {
    [[ -n "$OUTPUT_DIR" && -d "${OUTPUT_DIR}/logs" ]] || return 0
    local now duration finish
    now=${SECONDS:-0}
    duration=$(( now - STAGE_MARK ))
    (( duration < 0 )) && duration=0
    STAGE_MARK=$now
    finish=$(date '+%H:%M:%S' 2>/dev/null || printf '')
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "${3:-}" "$duration" "$finish" \
        >> "${OUTPUT_DIR}/logs/stages.tsv" 2>/dev/null || true
}

# Run profiles. recon.sh --fast/--deep/--max exports RECON_PRO_PROFILE, which
# overrides the tuned defaults for that run only; the saved config is untouched.
# --max raises concurrency, so keep it inside the rate the bounty program allows.
apply_profile() {
    local profile="${RECON_PRO_PROFILE:-}"
    profile="${profile,,}"
    case "$profile" in
        ''|normal) return 0 ;;
        fast)
            THREADS=40; RATE_LIMIT=100; STAGE_TIMEOUT=600
            X8_MAX_URLS=20; ARCHIVE_MAX_URLS=50; DALFOX_MAX_URLS=50; FUZZ_MAX_HOSTS=2; NMAP_MAX_HOSTS=5
            CORS_MAX_URLS=20; EXPOSURE_MAX_HOSTS=5; JS_MAX_FILES=20
            GRAPHQL_MAX_HOSTS=5; OPENREDIR_MAX_URLS=20; TAKEOVER_MAX_HOSTS=50
            NUCLEI_AUTOCALIBRATE=0
            ;;
        deep)
            THREADS=40; RATE_LIMIT=80; STAGE_TIMEOUT=3600
            X8_MAX_URLS=80; ARCHIVE_MAX_URLS=300; DALFOX_MAX_URLS=300; FUZZ_MAX_HOSTS=10; NMAP_MAX_HOSTS=25
            CORS_MAX_URLS=120; EXPOSURE_MAX_HOSTS=25; JS_MAX_FILES=100
            GRAPHQL_MAX_HOSTS=25; OPENREDIR_MAX_URLS=100; TAKEOVER_MAX_HOSTS=500
            NUCLEI_AUTOCALIBRATE=1
            ;;
        max)
            THREADS=80; RATE_LIMIT=150; STAGE_TIMEOUT=7200
            X8_MAX_URLS=150; ARCHIVE_MAX_URLS=500; DALFOX_MAX_URLS=600; FUZZ_MAX_HOSTS=25; NMAP_MAX_HOSTS=50
            CORS_MAX_URLS=250; EXPOSURE_MAX_HOSTS=50; JS_MAX_FILES=250
            GRAPHQL_MAX_HOSTS=50; OPENREDIR_MAX_URLS=250; TAKEOVER_MAX_HOSTS=1000
            NUCLEI_AUTOCALIBRATE=1
            ;;
        *)
            log WARN "Profil tidak dikenal: ${profile}. Memakai pengaturan config."
            return 0
            ;;
    esac
    log INFO "Profil run: ${profile} · threads ${THREADS} · rate ${RATE_LIMIT}/s · timeout stage ${STAGE_TIMEOUT}s."
    log INFO "Pastikan angka itu masih di dalam batas laju yang diizinkan program bounty."
    return 0
}

# Hides proxy credentials in a command line before it is written to a log or a
# report: "http://user:pass@host" becomes "http://***@host".
redact_cmd() {
    printf '%s' "$*" | sed -E 's#(://)[^/@[:space:]]+@#\1***@#g'
}

# run_tool <stage> [--stdout FILE] [--ok CODES] <command...>
#
# Runs a scanner under STAGE_TIMEOUT. stdout is appended to the --stdout file
# when given, stderr always goes to logs/<stage>.err together with the exit
# status, so a wrong flag is visible instead of looking like "no findings".
# --ok lists the exit codes that are not worth a warning (default "0").
run_tool() {
    local stage="$1" status=0
    shift
    local stdout_target="" ok_codes="0"
    while (( $# )); do
        case "$1" in
            --stdout) stdout_target="$2"; shift 2 ;;
            --ok) ok_codes="$2"; shift 2 ;;
            *) break ;;
        esac
    done
    local -a cmd=("$@")
    local err="${OUTPUT_DIR}/logs/${stage}.err"
    if (( ${#cmd[@]} == 0 )); then
        log ERROR "run_tool: no command given for stage ${stage}."
        return 2
    fi
    : >> "$err"

    if check_tool timeout && is_uint_between "$STAGE_TIMEOUT" 1 86400; then
        if [[ -n "$stdout_target" ]]; then
            timeout "$STAGE_TIMEOUT" "${cmd[@]}" >> "$stdout_target" 2>> "$err"
        else
            timeout "$STAGE_TIMEOUT" "${cmd[@]}" 2>> "$err"
        fi
    else
        if [[ -n "$stdout_target" ]]; then
            "${cmd[@]}" >> "$stdout_target" 2>> "$err"
        else
            "${cmd[@]}" 2>> "$err"
        fi
    fi
    status=$?
    printf 'exit=%s :: %s\n' "$status" "$(redact_cmd "${cmd[*]}")" >> "$err"

    if [[ ",${ok_codes}," != *",${status},"* ]]; then
        log WARN "$(basename -- "${cmd[0]}"): $(describe_status "$status") — see logs/${stage}.err"
    fi
    return "$status"
}

# -------------------------------------------------------------------- proxy --
#
# Every request this pipeline sends can leave through a rotating proxy, so the
# authorized target sees the exit node rather than your own address. Only
# proxies are rotated here: scope checks, rate limits and the authorization gate
# all still apply, and a proxy is never a way around a program's rules.
#
# A scanner only receives a proxy flag when its installed build advertises one,
# so an older or different build is never broken by an unknown flag.
# dnsx and nmap are deliberately not proxied: they are not HTTP clients.

proxies_loaded() {
    (( ${#PROXIES[@]} > 0 ))
}

# Reads PROXY_FILE into PROXIES. Returns 1 when PROXY_REQUIRED is set and the
# pool is empty, so a run that was asked to hide its IP cannot silently leak it.
load_proxies() {
    local line proxy added=0
    local -a loaded=()
    PROXY_INDEX=0
    PROXY_CURRENT=""
    PROXIES=()

    if [[ ! -f "$PROXY_FILE" ]]; then
        if (( PROXY_REQUIRED )); then
            log ERROR "PROXY_REQUIRED is on but ${PROXY_FILE} does not exist. Nothing will be scanned."
            return 1
        fi
        log WARN "No proxy list (${PROXY_FILE}); traffic uses this host's own IP."
        return 0
    fi

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="${line//[[:space:]]/}"
        [[ -n "$line" ]] || continue
        # A bare host:port gets http:// so curl and every scanner understand it.
        if [[ "$line" != *"://"* ]]; then
            line="http://${line}"
        fi
        case "${line,,}" in
            http://*|https://*|socks5://*|socks5h://*|socks4://*) ;;
            *)
                log WARN "Ignoring proxy with an unsupported scheme: ${line%%/*}://..."
                continue
                ;;
        esac
        proxy="${line#*://}"
        proxy="${proxy%%/*}"
        if [[ ! "$proxy" =~ :[0-9]{1,5}$ ]]; then
            log WARN "Ignoring proxy without host:port: ${line#*@}"
            continue
        fi
        loaded+=("$line")
        added=$((added + 1))
    done < "$PROXY_FILE"

    if (( added > 0 )); then
        # Dedupe while keeping the file order, so rotation follows the list.
        mapfile -t PROXIES < <(printf '%s\n' "${loaded[@]}" | awk '!seen[$0]++')
    fi

    if ! proxies_loaded; then
        if (( PROXY_REQUIRED )); then
            log ERROR "PROXY_REQUIRED is on but no usable proxy was found in ${PROXY_FILE}. Nothing will be scanned."
            return 1
        fi
        log WARN "No usable proxy in ${PROXY_FILE}; traffic uses this host's own IP."
        return 0
    fi

    log OK "Proxy pool: $((${#PROXIES[@]})) entr(y) from ${PROXY_FILE}, rotation $([ "$PROXY_ROTATE" == "1" ] && printf 'on' || printf 'off')."
    return 0
}

# Sets PROXY_CURRENT to the next proxy in the pool. Never called in a subshell,
# because the rotation index has to advance between calls.
pick_proxy() {
    local count
    PROXY_CURRENT=""
    proxies_loaded || return 0
    count=${#PROXIES[@]}

    if (( PROXY_ROTATE )); then
        PROXY_CURRENT="${PROXIES[$((PROXY_INDEX % count))]}"
        PROXY_INDEX=$(((PROXY_INDEX + 1) % count))
    else
        PROXY_CURRENT="${PROXIES[0]}"
    fi
    return 0
}

# curl with the next proxy when a pool exists, plain curl otherwise.
curl_any() {
    pick_proxy
    if [[ -n "$PROXY_CURRENT" ]]; then
        curl --proxy "$PROXY_CURRENT" "$@"
    else
        curl "$@"
    fi
}

# proxy_flag_name <tool> — prints the proxy flag the installed build advertises.
# The flag must appear as its own token in the tool's help output, so a version
# that renamed or dropped it makes the stage run without a proxy instead of
# failing on an unknown option.
proxy_flag_name() {
    local tool="$1" candidate help
    local -a candidates=()

    case "$tool" in
        httpx)                          candidates=("-proxy" "-http-proxy") ;;
        subfinder|nuclei|katana|tlsx|naabu) candidates=("-proxy") ;;
        dalfox|whatweb|x8)              candidates=("--proxy") ;;
        amass|findomain)                candidates=("--proxy" "-proxy") ;;
        ffuf)                           candidates=("-x") ;;
        *) return 1 ;;
    esac

    # Read the help once into a variable. Piping it straight into "grep -q"
    # closes the pipe early, and with "set -o pipefail" the SIGPIPE makes the
    # whole pipeline look like a failure — which silently disabled the proxy for
    # every tool with a long help text.
    help=$("$tool" -h 2>&1 || true)

    for candidate in "${candidates[@]}"; do
        if grep -qE "(^|[[:space:],=])${candidate}([[:space:],=]|$)" <<< "$help"; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

# Sets P_ARGS to the proxy arguments for one tool (empty when unsupported).
proxy_args_for() {
    local tool="$1" flag
    P_ARGS=()
    proxies_loaded || return 0
    check_tool "$tool" || return 0

    if [[ -z "${PROXY_FLAG_CACHE[$tool]+set}" ]]; then
        flag=$(proxy_flag_name "$tool" || true)
        PROXY_FLAG_CACHE[$tool]="$flag"
        [[ -n "$flag" ]] || log WARN "${tool} does not advertise a proxy flag in this build; it runs without the proxy."
    fi
    flag="${PROXY_FLAG_CACHE[$tool]}"

    [[ -n "$flag" ]] || return 0
    pick_proxy
    [[ -n "$PROXY_CURRENT" ]] || return 0

    P_ARGS=("$flag" "$PROXY_CURRENT")
    return 0
}

# ------------------------------------------------------------------- config --

# A relative path from the config resolves against the tool's own root, so a
# stale OUTPUT_BASE=runs2 cannot scatter folders into whatever directory the
# script happened to be started from.
resolve_under_root() {
    local value="$1"
    value="${value/#\~/${HOME:-.}}"
    if [[ "$value" != /* ]]; then
        value="${RECON_HOME%/}/${value}"
    fi
    printf '%s' "$value"
}

load_config() {
    [[ -f "$CONFIG_FILE" ]] || return 0
    chmod 600 "$CONFIG_FILE" 2>/dev/null || true

    local line key value
    while IFS= read -r line || [[ -n "$line" ]]; do
        case "$line" in
            ''|'#'*) continue ;;
            *'|'*) key="${line%%|*}"; value="${line#*|}" ;;
            *'='*) key="${line%%=*}"; value="${line#*=}"; value="${value#\"}"; value="${value%\"}" ;;
            *) continue ;;
        esac
        case "$key" in
            THREADS)
                is_uint_between "${value:-}" 1 200 && THREADS=$((10#$value)) || true
                ;;
            RATE_LIMIT)
                is_uint_between "${value:-}" 1 1000 && RATE_LIMIT=$((10#$value)) || true
                ;;
            STAGE_TIMEOUT)
                is_uint_between "${value:-}" 60 86400 && STAGE_TIMEOUT=$((10#$value)) || true
                ;;
            X8_MAX_URLS)
                is_uint_between "${value:-}" 1 5000 && X8_MAX_URLS=$((10#$value)) || true
                ;;
            ARCHIVE_MAX_URLS)
                is_uint_between "${value:-}" 1 5000 && ARCHIVE_MAX_URLS=$((10#$value)) || true
                ;;
            DALFOX_MAX_URLS)
                is_uint_between "${value:-}" 1 10000 && DALFOX_MAX_URLS=$((10#$value)) || true
                ;;
            FUZZ_MAX_HOSTS)
                is_uint_between "${value:-}" 1 500 && FUZZ_MAX_HOSTS=$((10#$value)) || true
                ;;
            NMAP_MAX_HOSTS)
                is_uint_between "${value:-}" 1 200 && NMAP_MAX_HOSTS=$((10#$value)) || true
                ;;
            NUCLEI_INTERACTSH)
                if [[ "${value:-}" == "1" ]]; then NUCLEI_INTERACTSH=1; else NUCLEI_INTERACTSH=0; fi
                ;;
            MODULE_CORS)
                if [[ "${value:-}" == "1" ]]; then MODULE_CORS=1; else MODULE_CORS=0; fi
                ;;
            MODULE_EXPOSURES)
                if [[ "${value:-}" == "1" ]]; then MODULE_EXPOSURES=1; else MODULE_EXPOSURES=0; fi
                ;;
            MODULE_JS)
                if [[ "${value:-}" == "1" ]]; then MODULE_JS=1; else MODULE_JS=0; fi
                ;;
            MODULE_TAKEOVER)
                if [[ "${value:-}" == "1" ]]; then MODULE_TAKEOVER=1; else MODULE_TAKEOVER=0; fi
                ;;
            MODULE_GRAPHQL)
                if [[ "${value:-}" == "1" ]]; then MODULE_GRAPHQL=1; else MODULE_GRAPHQL=0; fi
                ;;
            MODULE_OPENREDIR)
                if [[ "${value:-}" == "1" ]]; then MODULE_OPENREDIR=1; else MODULE_OPENREDIR=0; fi
                ;;
            NUCLEI_AUTOCALIBRATE)
                if [[ "${value:-}" == "1" ]]; then NUCLEI_AUTOCALIBRATE=1; else NUCLEI_AUTOCALIBRATE=0; fi
                ;;
            NUCLEI_DAST)
                if [[ "${value:-}" == "1" ]]; then NUCLEI_DAST=1; else NUCLEI_DAST=0; fi
                ;;
            NUCLEI_HEADLESS)
                if [[ "${value:-}" == "1" ]]; then NUCLEI_HEADLESS=1; else NUCLEI_HEADLESS=0; fi
                ;;
            CORS_MAX_URLS)
                is_uint_between "${value:-}" 1 2000 && CORS_MAX_URLS=$((10#$value)) || true
                ;;
            EXPOSURE_MAX_HOSTS)
                is_uint_between "${value:-}" 1 200 && EXPOSURE_MAX_HOSTS=$((10#$value)) || true
                ;;
            JS_MAX_FILES)
                is_uint_between "${value:-}" 1 500 && JS_MAX_FILES=$((10#$value)) || true
                ;;
            GRAPHQL_MAX_HOSTS)
                is_uint_between "${value:-}" 1 200 && GRAPHQL_MAX_HOSTS=$((10#$value)) || true
                ;;
            OPENREDIR_MAX_URLS)
                is_uint_between "${value:-}" 1 2000 && OPENREDIR_MAX_URLS=$((10#$value)) || true
                ;;
            TAKEOVER_MAX_HOSTS)
                is_uint_between "${value:-}" 1 5000 && TAKEOVER_MAX_HOSTS=$((10#$value)) || true
                ;;
            TELEGRAM_INSTANT)
                if [[ "${value:-}" == "1" ]]; then TELEGRAM_INSTANT=1; else TELEGRAM_INSTANT=0; fi
                ;;
            TELEGRAM_INSTANT_MIN_SCORE)
                is_uint_between "${value:-}" 10 100 && TELEGRAM_INSTANT_MIN_SCORE=$((10#$value)) || true
                ;;
            TELEGRAM_INSTANT_MAX)
                is_uint_between "${value:-}" 0 200 && TELEGRAM_INSTANT_MAX=$((10#$value)) || true
                ;;
            WEB_PORTS)      WEB_PORTS="${value:-}" ;;
            OUTPUT_BASE)
                [[ -n "${value:-}" ]] && OUTPUT_BASE=$(resolve_under_root "$value") || true
                ;;
            KEEP_RUNS)
                is_uint_between "${value:-}" 0 500 && KEEP_RUNS=$((10#$value)) || true
                ;;
            PROXY_FILE)     [[ -n "${value:-}" ]] && PROXY_FILE=$(resolve_under_root "$value") || true ;;
            PROXY_ROTATE)
                if [[ "${value:-}" == "1" ]]; then PROXY_ROTATE=1; else PROXY_ROTATE=0; fi
                ;;
            PROXY_REQUIRED)
                if [[ "${value:-}" == "1" ]]; then PROXY_REQUIRED=1; else PROXY_REQUIRED=0; fi
                ;;
            WORDLIST)       [[ -n "${value:-}" ]] && WORDLIST="$value" || true ;;
            PARAM_WORDLIST) [[ -n "${value:-}" ]] && PARAM_WORDLIST="$value" || true ;;
            TELEGRAM_TOKEN)
                [[ "${value:-}" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] && TELEGRAM_TOKEN="$value" || true
                ;;
            TELEGRAM_CHAT)
                [[ "${value:-}" =~ ^-?[0-9]+$ ]] && TELEGRAM_CHAT="$value" || true
                ;;
            TELEGRAM_ALLOWED_USERS)
                [[ "${value:-}" =~ ^[0-9]+(,[0-9]+)*$ ]] && TELEGRAM_ALLOWED_USERS="$value" || true
                ;;
        esac
    done < "$CONFIG_FILE"
}

save_config() {
    local temp_file
    temp_file=$(mktemp "${STATE_DIR}/recon_pro.conf.XXXXXX") || {
        log ERROR "Could not create a temporary config file."
        return 1
    }
    {
        printf 'THREADS|%s\n' "$THREADS"
        printf 'RATE_LIMIT|%s\n' "$RATE_LIMIT"
        printf 'STAGE_TIMEOUT|%s\n' "$STAGE_TIMEOUT"
        printf 'WEB_PORTS|%s\n' "$WEB_PORTS"
        printf 'OUTPUT_BASE|%s\n' "$OUTPUT_BASE"
        printf 'WORDLIST|%s\n' "$WORDLIST"
        printf 'PARAM_WORDLIST|%s\n' "$PARAM_WORDLIST"
        printf 'X8_MAX_URLS|%s\n' "$X8_MAX_URLS"
        printf 'ARCHIVE_MAX_URLS|%s\n' "$ARCHIVE_MAX_URLS"
        printf 'DALFOX_MAX_URLS|%s\n' "$DALFOX_MAX_URLS"
        printf 'FUZZ_MAX_HOSTS|%s\n' "$FUZZ_MAX_HOSTS"
        printf 'NMAP_MAX_HOSTS|%s\n' "$NMAP_MAX_HOSTS"
        printf 'NUCLEI_INTERACTSH|%s\n' "$NUCLEI_INTERACTSH"
        printf 'MODULE_CORS|%s\n' "$MODULE_CORS"
        printf 'MODULE_EXPOSURES|%s\n' "$MODULE_EXPOSURES"
        printf 'MODULE_JS|%s\n' "$MODULE_JS"
        printf 'MODULE_TAKEOVER|%s\n' "$MODULE_TAKEOVER"
        printf 'MODULE_GRAPHQL|%s\n' "$MODULE_GRAPHQL"
        printf 'MODULE_OPENREDIR|%s\n' "$MODULE_OPENREDIR"
        printf 'NUCLEI_AUTOCALIBRATE|%s\n' "$NUCLEI_AUTOCALIBRATE"
        printf 'NUCLEI_DAST|%s\n' "$NUCLEI_DAST"
        printf 'NUCLEI_HEADLESS|%s\n' "$NUCLEI_HEADLESS"
        printf 'CORS_MAX_URLS|%s\n' "$CORS_MAX_URLS"
        printf 'EXPOSURE_MAX_HOSTS|%s\n' "$EXPOSURE_MAX_HOSTS"
        printf 'JS_MAX_FILES|%s\n' "$JS_MAX_FILES"
        printf 'GRAPHQL_MAX_HOSTS|%s\n' "$GRAPHQL_MAX_HOSTS"
        printf 'OPENREDIR_MAX_URLS|%s\n' "$OPENREDIR_MAX_URLS"
        printf 'TAKEOVER_MAX_HOSTS|%s\n' "$TAKEOVER_MAX_HOSTS"
        printf 'KEEP_RUNS|%s\n' "$KEEP_RUNS"
        printf 'PROXY_FILE|%s\n' "$PROXY_FILE"
        printf 'PROXY_ROTATE|%s\n' "$PROXY_ROTATE"
        printf 'PROXY_REQUIRED|%s\n' "$PROXY_REQUIRED"
        printf 'TELEGRAM_INSTANT|%s\n' "$TELEGRAM_INSTANT"
        printf 'TELEGRAM_INSTANT_MIN_SCORE|%s\n' "$TELEGRAM_INSTANT_MIN_SCORE"
        printf 'TELEGRAM_INSTANT_MAX|%s\n' "$TELEGRAM_INSTANT_MAX"
        printf 'TELEGRAM_TOKEN|%s\n' "$TELEGRAM_TOKEN"
        printf 'TELEGRAM_CHAT|%s\n' "$TELEGRAM_CHAT"
        printf 'TELEGRAM_ALLOWED_USERS|%s\n' "$TELEGRAM_ALLOWED_USERS"
    } > "$temp_file"
    chmod 600 "$temp_file"
    if ! mv -f -- "$temp_file" "$CONFIG_FILE"; then
        rm -f -- "$temp_file"
        log ERROR "Could not save config."
        return 1
    fi
    log OK "Config saved with owner-only permissions."
}

# -------------------------------------------------------------------- scope --
#
# A single in-scope test is shared by hosts, URLs and TLS targets: a host is in
# scope when it equals the apex or ends with ".<apex>", and out of scope when it
# matches an exclusion entry or any of that entry's subdomains.

init_scope_exclusions() {
    if [[ ! -f "$EXCLUDE_FILE" ]]; then
        printf '%s\n' '# Optional out-of-scope hostnames; each entry also excludes its subdomains.' > "$EXCLUDE_FILE"
        chmod 600 "$EXCLUDE_FILE"
    fi
}

# scope_filter <host|url|target> <input> <output>
#   host   : normalize every line to a bare hostname
#   url    : keep HTTP(S) URLs whose host is in scope
#   target : keep HTTPS endpoints as host:port (for TLS checks)
scope_filter() {
    local mode="$1" input="$2" output="$3"
    [[ -f "$input" ]] || : > "$input"
    local -a inputs=("$input")
    [[ -f "$EXCLUDE_FILE" ]] && inputs=("$EXCLUDE_FILE" "$input")

    awk -v d="$DOMAIN" -v e="$EXCLUDE_FILE" -v mode="$mode" '
        function in_scope(host) {
            return host == d || (length(host) > length(d) && substr(host, length(host) - length(d), length(d) + 1) == "." d)
        }
        function excluded(host,   i, entry) {
            for (i = 1; i <= excluded_count; i++) {
                entry = excluded_hosts[i]
                if (host == entry || (length(host) > length(entry) && substr(host, length(host) - length(entry), length(entry) + 1) == "." entry)) return 1
            }
            return 0
        }
        # Splits a host, URL or host:port into the globals H (host) and P (port).
        function split_host(line,   auth) {
            H = line
            P = "443"
            sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "", H)
            sub(/[\/?#].*$/, "", H)
            sub(/^.*@/, "", H)
            if (match(H, /:[0-9]+$/)) {
                P = substr(H, RSTART + 1)
                H = substr(H, 1, RSTART - 1)
            }
            H = tolower(H)
            sub(/^\*\./, "", H)
            sub(/\.$/, "", H)
        }
        FILENAME == e {
            entry = tolower($0)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", entry)
            if (entry == "" || entry ~ /^#/) next
            sub(/^\*\./, "", entry)
            sub(/\.$/, "", entry)
            if (entry != "") excluded_hosts[++excluded_count] = entry
            next
        }
        {
            line = $1
            if (line == "") next
            if (mode == "url") {
                if (tolower(line) !~ /^https?:\/\//) next
                split_host(line)
                if (in_scope(H) && !excluded(H)) print line
                next
            }
            if (mode == "target") {
                if (tolower(line) !~ /^https:\/\//) next
                split_host(line)
                if (in_scope(H) && !excluded(H)) print H ":" P
                next
            }
            split_host(line)
            if (in_scope(H) && !excluded(H)) print H
        }
    ' "${inputs[@]}" | sort -u > "$output"
}

# ---------------------------------------------------------------- workspace --

# The tool's own folder tree, created once, with the files of the earlier layout
# moved in so an existing config, exclusion list, scope list and bot state keep
# working. Everything this script writes stays inside this tree.
init_project_dirs() {
    local dir
    for dir in "$RECON_HOME" "$RUNS_DIR" "$REPORTS_DIR" "$STATE_DIR"; do
        mkdir -p -- "$dir" 2>/dev/null || true
        chmod 700 "$dir" 2>/dev/null || true
    done

    if [[ -f "$LEGACY_CONFIG_FILE" && ! -f "$CONFIG_FILE" ]]; then
        mv -f -- "$LEGACY_CONFIG_FILE" "$CONFIG_FILE" 2>/dev/null \
            && log INFO "Moved the old config into ${CONFIG_FILE}"
    fi
    if [[ -f "$LEGACY_EXCLUDE_FILE" && ! -f "$EXCLUDE_FILE" ]]; then
        mv -f -- "$LEGACY_EXCLUDE_FILE" "$EXCLUDE_FILE" 2>/dev/null \
            && log INFO "Moved the old exclusion list into ${EXCLUDE_FILE}"
    fi
    if [[ -f "$LEGACY_SCOPE_FILE" && ! -f "${STATE_DIR}/scope.txt" ]]; then
        mv -f -- "$LEGACY_SCOPE_FILE" "${STATE_DIR}/scope.txt" 2>/dev/null \
            && log INFO "Moved the Telegram scope list into ${STATE_DIR}/scope.txt"
    fi
    if [[ -d "$LEGACY_STATE_DIR" && ! -e "${STATE_DIR}/bot" ]]; then
        mv -- "$LEGACY_STATE_DIR" "${STATE_DIR}/bot" 2>/dev/null || true
    fi

    [[ -f "$CONFIG_FILE" ]] && chmod 600 "$CONFIG_FILE" 2>/dev/null

    # A commented template makes the proxy list discoverable without inventing
    # a proxy: an empty file simply means "use this host's IP".
    if [[ ! -f "$PROXY_FILE" ]]; then
        mkdir -p -- "$(dirname -- "$PROXY_FILE")" 2>/dev/null || true
        {
            printf '%s\n' '# Optional rotating proxy pool, one proxy per line.'
            printf '%s\n' '# Accepted: http://host:3128  http://user:pass@host:3128'
            printf '%s\n' '#           socks5://host:1080  socks5h://host:1080  socks4://host:1080'
            printf '%s\n' '# Used for curl requests and for every scanner that supports a proxy flag.'
            printf '%s\n' '# dnsx and nmap are not proxied (no HTTP client); see README.md.'
        } > "$PROXY_FILE" 2>/dev/null || true
        chmod 600 "$PROXY_FILE" 2>/dev/null || true
    fi

    return 0
}

init_workspace() {
    local base suffix=1 domain_dir
    base="recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
    domain_dir="${OUTPUT_BASE%/}/${DOMAIN}"

    # The workspace is an absolute path, so the path printed here, written to the
    # log and used in the report can always be copied straight into the shell,
    # whichever directory the script was started from. Runs are grouped under
    # their domain, so one target's history stays together and the runs folder
    # itself only ever holds one folder per target.
    mkdir -p -- "$domain_dir" 2>/dev/null || true
    OUTPUT_DIR="${domain_dir}/${base}"
    # Two runs in the same second would otherwise share a directory and
    # overwrite the previous run's log and report.
    while [[ -e "$OUTPUT_DIR" ]]; do
        OUTPUT_DIR="${domain_dir}/${base}_${suffix}"
        suffix=$((suffix + 1))
    done
    mkdir -p -- "$OUTPUT_DIR"/{subs,alive,urls,nuclei,xss,x8,fuzz,nmap,ports,tls,web,final,logs,js,gf,takeover}
    : > "${OUTPUT_DIR}/logs/pipeline.log"
    : > "${OUTPUT_DIR}/logs/stages.tsv"
    : > "${OUTPUT_DIR}/final/findings.all.tsv"
    date +%s > "${OUTPUT_DIR}/logs/start.epoch" 2>/dev/null || true
    {
        printf 'Target: %s\n' "$DOMAIN"
        printf 'Started (UTC): %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S')"
        printf 'Tool version: %s\n' "$VERSION"
        printf 'Threads: %s\n' "$THREADS"
        printf 'Rate limit: %s requests/sec\n' "$RATE_LIMIT"
        printf 'Stage timeout: %ss\n' "$STAGE_TIMEOUT"
        printf 'Scope exclusions: %s\n' "$EXCLUDE_FILE"
        printf 'Directory wordlist: %s\n' "$WORDLIST"
        printf 'Parameter wordlist: %s\n' "$PARAM_WORDLIST"
        printf 'Recon folder: %s\n' "$RECON_HOME"
        printf 'Retention: %s\n' \
            "$( (( KEEP_RUNS > 0 )) && printf 'keep newest %s run(s)' "$KEEP_RUNS" || printf 'keep every run' )"
        printf 'Proxy: %s (%s entries, rotation %s)\n' \
            "$PROXY_FILE" "$((${#PROXIES[@]}))" \
            "$( (( PROXY_ROTATE )) && printf 'on' || printf 'off' )"
        printf 'Proxy scope: HTTP requests and proxy-capable scanners; dnsx and nmap stay direct.\n'
    } > "${OUTPUT_DIR}/final/scan_info.txt"
    log INFO "Workspace: $OUTPUT_DIR"
    link_latest_run
}

# Points runs/<domain>/latest at the newest workspace, so the short, stable path
# always opens the current result without copying or moving anything.
link_latest_run() {
    local link="${OUTPUT_BASE%/}/${DOMAIN}/latest" target
    [[ -n "$OUTPUT_DIR" && -n "$DOMAIN" ]] || return 0
    target=$(basename -- "$OUTPUT_DIR")

    # A real directory is never removed to make room for the link.
    if [[ -d "$link" && ! -L "$link" ]]; then
        return 0
    fi
    rm -f -- "$link" 2>/dev/null || return 0
    ln -s "$target" "$link" 2>/dev/null || true
    return 0
}

# Keeps a short path to the newest result: reports/<domain>/ holds copies of the
# run's report files. Copies, not links, so a report stays readable after
# retention removes an old workspace.
publish_reports() {
    local dir="${REPORTS_DIR}/${DOMAIN}" src
    [[ -n "$OUTPUT_DIR" && -n "$DOMAIN" ]] || return 0
    mkdir -p -- "$dir" 2>/dev/null || return 0

    for src in bugs_found.txt telegram_report.txt summary.txt findings.tsv report.md; do
        [[ -s "${OUTPUT_DIR}/final/${src}" ]] || continue
        cp -f -- "${OUTPUT_DIR}/final/${src}" "${dir}/latest-${src}" 2>/dev/null || true
    done
    printf '%s\n' "$OUTPUT_DIR" > "${dir}/latest-workspace.txt" 2>/dev/null || true
    return 0
}

# Optional retention: with KEEP_RUNS=n only the newest n runs of a domain stay.
# Off by default (0), so nothing is ever deleted unless it is asked for.
prune_old_runs() {
    local domain_dir="${OUTPUT_BASE%/}/${DOMAIN}" victim removed=0
    [[ -n "$DOMAIN" && -d "$domain_dir" ]] || return 0
    is_uint_between "$KEEP_RUNS" 0 500 || return 0
    (( KEEP_RUNS > 0 )) || return 0

    while IFS= read -r victim; do
        [[ -n "$victim" ]] || continue
        [[ "${victim%/}" == "${OUTPUT_DIR%/}" ]] && continue
        rm -rf -- "$victim" 2>/dev/null && removed=$((removed + 1))
    done < <(find "$domain_dir" -maxdepth 1 -type d -name 'recon_*' -print 2>/dev/null \
        | sort -r | tail -n "+$((KEEP_RUNS + 1))")

    if (( removed > 0 )); then
        log INFO "Retention (KEEP_RUNS=${KEEP_RUNS}): removed ${removed} older run(s) from ${domain_dir}."
    fi
    return 0
}

module_tool_inventory() {
    local report="$OUTPUT_DIR/final/tool_inventory.txt"
    local tool
    : > "$report"
    for tool in subfinder assetfinder amass findomain chaos alterx dnsx httpx tlsx testssl.sh nuclei dalfox \
        whatweb katana waybackurls gau x8 ffuf gf naabu nmap curl jq timeout; do
        if check_tool "$tool"; then
            printf 'AVAILABLE %s\n' "$tool" >> "$report"
        else
            printf 'MISSING   %s (related stage is skipped)\n' "$tool" >> "$report"
        fi
    done
    log INFO "Tool availability saved: $report"
}

# Records the tools whose stage cannot run, so an empty report is explained.
check_required_tools() {
    local missing=()
    check_tool curl || missing+=("curl")
    have_jq || missing+=("jq")
    if (( ${#missing[@]} )); then
        log WARN "Recommended tool(s) missing: ${missing[*]}. Coverage and output parsing are degraded."
    fi
}

# Offline pre-flight: what is installed and what a stage will skip. No network.
check_env() {
    local tool
    local -a required=(curl jq)
    local -a scanners=(subfinder assetfinder amass findomain chaos alterx dnsx httpx tlsx testssl.sh nuclei \
        dalfox whatweb katana waybackurls gau x8 ffuf gf naabu nmap)
    local -a absent=()

    printf '%b\n' "${BOLD}Environment check${NC}  ${CYAN}(recon_pro ${VERSION} by ${AUTHOR})${NC}"
    printf '  bash         %s\n' "$BASH_VERSION"
    printf '  recon folder %s\n' "$RECON_HOME"
    printf '  runs         %s\n' "$OUTPUT_BASE"
    printf '  reports      %s\n' "$REPORTS_DIR"
    printf '  state        %s\n' "$STATE_DIR"
    printf '  retention    %s%s\n' \
        "$( (( KEEP_RUNS > 0 )) && printf 'keep newest %s run(s)' "$KEEP_RUNS" || printf 'keep every run' )" \
        "$( (( KEEP_RUNS > 0 )) && printf '' || printf '  <-- set KEEP_RUNS in settings to reclaim space')"
    printf '  proxies      %s (%s entr(y), rotation %s%s)\n' "$PROXY_FILE" \
        "$((${#PROXIES[@]}))" \
        "$( (( PROXY_ROTATE )) && printf 'on' || printf 'off')" \
        "$( (( PROXY_REQUIRED )) && printf ', required' || printf '' )"
    printf '  config       %s%s\n' "$CONFIG_FILE" \
        "$([[ -f "$CONFIG_FILE" ]] && printf ' (present)' || printf ' (not created yet)')"
    printf '  exclusions   %s\n' "$EXCLUDE_FILE"
    printf '  telegram     %s\n' \
        "$([[ -n "$TELEGRAM_TOKEN" && -n "$TELEGRAM_CHAT" ]] && printf 'ON' || printf 'OFF (no token or chat ID)')"
    printf '  wordlist     %s%s\n' "$WORDLIST" \
        "$([[ -f "$WORDLIST" ]] && printf '' || printf '  <-- MISSING: ffuf stage will be skipped')"
    printf '  param list   %s%s\n' "$PARAM_WORDLIST" \
        "$([[ -f "$PARAM_WORDLIST" ]] && printf '' || printf '  <-- MISSING: x8 stage will be skipped')"

    printf '\n%b\n' "${BOLD}Required${NC}"
    for tool in "${required[@]}"; do
        if check_tool "$tool"; then
            printf '  %-12s ok\n' "$tool"
        else
            printf '  %-12s %bMISSING%b\n' "$tool" "$RED" "$NC"
            absent+=("$tool")
        fi
    done

    printf '\n%b\n' "${BOLD}Scanners (optional; a missing one only skips its stage)${NC}"
    for tool in "${scanners[@]}"; do
        if check_tool "$tool"; then
            printf '  %-12s ok\n' "$tool"
        else
            printf '  %-12s %bmissing%b\n' "$tool" "$YELLOW" "$NC"
            absent+=("$tool")
        fi
    done
    check_tool timeout || printf '  %-12s %bmissing%b (no per-stage timeout)\n' "timeout" "$YELLOW" "$NC"

    if (( ${#absent[@]} )); then
        printf '\n%b\n' "${YELLOW}A missing scanner only skips its stage. Install them one module at a${NC}"
        printf '%b\n' "${YELLOW}time so one failure cannot stop the rest (go install <module>@latest):${NC}"
        printf '  %s\n' \
            'github.com/projectdiscovery/subfinder/v2/cmd/subfinder' \
            'github.com/projectdiscovery/dnsx/cmd/dnsx' \
            'github.com/projectdiscovery/httpx/cmd/httpx' \
            'github.com/projectdiscovery/tlsx/cmd/tlsx' \
            'github.com/projectdiscovery/naabu/v2/cmd/naabu' \
            'github.com/projectdiscovery/nuclei/v3/cmd/nuclei' \
            'github.com/projectdiscovery/katana/cmd/katana' \
            'github.com/tomnomnom/waybackurls' \
            'github.com/tomnomnom/assetfinder' \
            'github.com/lc/gau/v2/cmd/gau' \
            'github.com/hahwul/dalfox/v2'
        printf '%b\n' "${YELLOW}AlterX is pinned for Go compatibility: go install github.com/projectdiscovery/alterx/cmd/alterx@v0.0.6${NC}"
        printf '%b\n' "${YELLOW}apt install nmap ffuf jq libpcap-dev; x8 is Rust: cargo install x8${NC}"
        printf '%b\n' "${YELLOW}gf (optional, improves parameter routing): github.com/tomnomnom/gf${NC}"
    else
        printf '\n%b\n' "${GREEN}All tools present.${NC}"
    fi
    printf '\n%b\n' "${CYAN}Nothing was scanned; this check makes no network requests.${NC}"
    return 0
}

# ---------------------------------------------------------------- telegram ---

# Quote a value for a curl config file. Order matters: backslashes first, then
# quotes, then newlines last, so a multi-line message becomes a literal \n
# instead of breaking the config file onto another line.
curl_escape() {
    local value="$1"
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\r'/}
    value=${value//$'\n'/\\n}
    printf '%s' "$value"
}

notify() {
    local message="$1" token chat response reason
    if [[ -z "$TELEGRAM_TOKEN" || -z "$TELEGRAM_CHAT" ]]; then
        log WARN "Telegram message skipped: token/chat is not configured. Run bash recon.sh --telegram."
        return 1
    fi
    check_tool curl || return 1
    token=$(curl_escape "$TELEGRAM_TOKEN")
    chat=$(curl_escape "$TELEGRAM_CHAT")
    message=$(curl_escape "$message")

    # Credentials and message travel through curl's stdin config, never argv.
    if ! response=$(curl --silent --show-error --max-time 20 --config - <<EOF
url = "https://api.telegram.org/bot${token}/sendMessage"
request = "POST"
data-urlencode = "chat_id=${chat}"
data-urlencode = "text=${message}"
EOF
); then
        log WARN "Telegram request failed before the API returned a response."
        return 1
    fi
    if grep -Eq '"ok"[[:space:]]*:[[:space:]]*true([,}]|$)' <<< "$response"; then
        log INFO "Telegram message sent."
        return 0
    fi
    reason=$(printf '%s' "$response" | sed -n 's/.*"description":"\([^"]*\)".*/\1/p')
    log WARN "Telegram rejected the message${reason:+: ${reason}}."
    return 1
}

notify_document() {
    local title="$1" file="$2" token chat file_arg caption response reason
    if [[ -z "$TELEGRAM_TOKEN" || -z "$TELEGRAM_CHAT" ]]; then
        log WARN "Telegram report skipped: token/chat is not configured. Run bash recon.sh --telegram."
        return 1
    fi
    if [[ ! -s "$file" ]]; then
        log WARN "Telegram report file is missing or empty: $file"
        return 1
    fi
    check_tool curl || return 1
    token=$(curl_escape "$TELEGRAM_TOKEN")
    chat=$(curl_escape "$TELEGRAM_CHAT")
    file_arg=$(curl_escape "$file")
    caption=$(curl_escape "$title")

    # Upload the full Markdown report as a document; secrets stay out of argv.
    if ! response=$(curl --silent --show-error --max-time 60 --config - <<EOF
url = "https://api.telegram.org/bot${token}/sendDocument"
request = "POST"
form = "chat_id=${chat}"
form = "document=@${file_arg};type=text/markdown"
form = "caption=${caption}"
EOF
); then
        log WARN "Telegram report upload failed before the API returned a response."
        return 1
    fi
    if grep -Eq '"ok"[[:space:]]*:[[:space:]]*true([,}]|$)' <<< "$response"; then
        log INFO "Full report sent to Telegram: $file"
        return 0
    fi
    reason=$(printf '%s' "$response" | sed -n 's/.*"description":"\([^"]*\)".*/\1/p')
    log WARN "Telegram rejected the report upload${reason:+: ${reason}}."
    return 1
}

# Telegram rejects anything over 4096 characters, so a long body is cut on line
# boundaries into numbered parts rather than silently failing.
notify_long() {
    local title="$1" file="$2" limit=3000 line chunk="" part=0

    [[ -n "$OUTPUT_DIR" && -s "$file" ]] || return 0

    while IFS= read -r line || [[ -n "$line" ]]; do
        (( ${#line} > 380 )) && line="${line:0:380}..."
        if (( ${#chunk} + ${#line} + 1 > limit )) && [[ -n "$chunk" ]]; then
            part=$((part + 1))
            notify "${title} (part ${part})
${chunk}"
            chunk=""
        fi
        chunk+="${line}"$'\n'
    done < "$file"

    if [[ -n "$chunk" ]]; then
        part=$((part + 1))
        notify "${title} (part ${part})
${chunk}"
    fi
}

# Short alert the moment a high/critical finding is recorded. Deduped by
# tool+host+title and capped, so a noisy template cannot flood the chat.
telegram_alert() {
    local score="$1" confidence="$2" tool="$3" host="$4" title="$5"
    local evidence="${6:-}"
    local dir marker key count level

    [[ -n "$OUTPUT_DIR" && -n "$TELEGRAM_TOKEN" && -n "$TELEGRAM_CHAT" ]] || return 0
    (( TELEGRAM_INSTANT )) || return 0
    (( score >= TELEGRAM_INSTANT_MIN_SCORE )) || return 0
    check_tool curl || return 0

    dir="${OUTPUT_DIR}/logs"
    marker="${dir}/telegram_alerts.sent"
    count=0
    [[ -s "$marker" ]] && count=$(wc -l < "$marker" | tr -d '[:space:]')
    count=${count:-0}
    (( count >= TELEGRAM_INSTANT_MAX )) && return 0

    key="${tool}|${host}|${title}"
    if [[ -s "$marker" ]] && grep -qxF -- "$key" "$marker" 2>/dev/null; then
        return 0
    fi
    printf '%s\n' "$key" >> "$marker" 2>/dev/null || true

    if (( score >= 90 )); then level="CRITICAL"; else level="HIGH"; fi

    notify "BUG ${level} (${score}) — ${DOMAIN}

${title}

tool: ${tool} | host: ${host} | ${confidence}
evidence: ${evidence:-n/a}
workspace: ${OUTPUT_DIR}"
}

# --------------------------------------------------------------- guardrails --

require_domain() {
    if [[ -z "$DOMAIN" ]]; then
        log ERROR "Set a valid domain first."
        return 1
    fi
}

require_workspace() {
    if [[ -z "$OUTPUT_DIR" ]]; then
        log ERROR "No workspace yet; run option 2 or 3 first."
        return 1
    fi
}

require_authorization() {
    local confirmation
    require_domain || return 1
    printf '%b\n' "${YELLOW}Only test ${DOMAIN} assets explicitly in scope. Exclusions: ${EXCLUDE_FILE}${NC}"
    if (( ASSUME_YES )); then
        log INFO "Authorization assumed (-y)."
        return 0
    fi
    if [[ ! -t 0 ]]; then
        log ERROR "No interactive terminal: pass -y to confirm authorization non-interactively."
        return 1
    fi
    read -r -p "Type AUTHORIZED to confirm permission for active testing: " confirmation || return 1
    if [[ "${confirmation^^}" != "AUTHORIZED" ]]; then
        log WARN "Authorization not confirmed; operation cancelled."
        return 1
    fi
    return 0
}


# ------------------------------------------------------------------ modules --

# A wildcard DNS record answers for names that do not exist, which is the single
# biggest source of phantom subdomains in passive enumeration. dnsx's
# -auto-wildcard drops the names that only answer through it; this finds the
# record itself, so the report can say whether the host list was exposed to one.
detect_wildcard_dns() {
    local probe="$OUTPUT_DIR/subs/wildcard_probe.tmp"
    local raw="$OUTPUT_DIR/subs/wildcard_raw.tmp"
    local out="$OUTPUT_DIR/subs/wildcard.txt"
    local i
    : > "$out"
    : > "$probe"
    if ! check_tool dnsx || [[ -z "$DOMAIN" ]]; then
        return 0
    fi

    for i in 1 2 3; do
        printf 'recon-probe-%s-%s.%s\n' "$i" "${RANDOM}${RANDOM}" "$DOMAIN" >> "$probe"
    done
    run_tool dnsx-wildcard --stdout "$raw" dnsx -l "$probe" -a -resp -silent \
        -threads 3 -retry 1 -timeout 5

    awk '{
        line = $0
        gsub(/[\[\],]/, " ", line)
        n = split(line, parts, " ")
        for (i = 1; i <= n; i++) {
            if (parts[i] ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print parts[i]
        }
    }' "$raw" 2>/dev/null | sort -u > "$out"
    rm -f -- "$probe" "$raw"

    if [[ -s "$out" ]]; then
        log WARN "Wildcard DNS on ${DOMAIN} ($(count_lines "$out") address(es)); unresolved names were filtered with dnsx -auto-wildcard."
        stage_status "wildcard" "found" "$(count_lines "$out") wildcard address(es)"
    else
        log OK "No wildcard DNS record; every resolved name is a real record."
        stage_status "wildcard" "ok" "none"
    fi
    return 0
}

module_subdomains() {
    log INFO "Passive subdomain enumeration + bounded permutation generation + DNS validation"
    local raw="$OUTPUT_DIR/subs/all.raw.tmp"
    local passive="$OUTPUT_DIR/subs/all.passive.txt"
    local dns_candidates="$OUTPUT_DIR/subs/all.candidates.txt"
    local resolved="$OUTPUT_DIR/subs/dnsx_resolved.txt"
    local dns_scoped="$OUTPUT_DIR/subs/dnsx_scoped.tmp"
    local out="$OUTPUT_DIR/subs/all.txt"
    local san_raw="$OUTPUT_DIR/subs/san.raw.tmp"
    local tlsx_target="$OUTPUT_DIR/subs/tlsx_target.tmp"
    local alterx_raw="$OUTPUT_DIR/subs/alterx.raw.tmp"
    local alterx_candidates="$OUTPUT_DIR/subs/alterx_candidates.txt"
    local alterx_resolved="$OUTPUT_DIR/subs/alterx_resolved.txt"
    local dnsx_status=0 alterx_rc=0 attempt
    local alterx_status="skipped" alterx_note="alterx missing"
    local alterx_generated=0 alterx_dns_resolved=0
    : > "$raw"
    : > "$resolved"
    : > "$dns_scoped"
    : > "$san_raw"
    : > "$alterx_raw"
    : > "$alterx_candidates"
    : > "$alterx_resolved"
    printf '%s\n' "$DOMAIN" >> "$raw"

    # An apex that does not answer an A lookup cannot be scanned; saying so at
    # the start is more accurate than a run that ends with an empty report.
    if check_tool dnsx; then
        printf '%s\n' "$DOMAIN" | dnsx -silent -a -retry 2 -timeout 5 2>/dev/null > "${raw}.apex"
        if [[ ! -s "${raw}.apex" ]]; then
            log WARN "The apex ${DOMAIN} did not answer an A lookup; later stages may come back empty."
        fi
        rm -f -- "${raw}.apex"
    fi

    if check_tool subfinder; then
        proxy_args_for subfinder
        run_tool subfinder --stdout "$raw" subfinder -d "$DOMAIN" -all -silent \
            "${P_ARGS[@]+"${P_ARGS[@]}"}"
    fi
    if check_tool assetfinder; then run_tool assetfinder --stdout "$raw" assetfinder --subs-only "$DOMAIN"; fi
    if check_tool amass; then run_tool amass --stdout "$raw" amass enum -passive -d "$DOMAIN"; fi
    if check_tool findomain; then run_tool findomain --stdout "$raw" findomain -t "$DOMAIN" -q; fi
    if check_tool chaos; then
        if [[ -n "${PDCP_API_KEY:-}" ]]; then
            run_tool chaos --stdout "$raw" chaos -d "$DOMAIN" -silent
        else
            log WARN "chaos dilewati: PDCP_API_KEY belum diset (ambil dari ProjectDiscovery Cloud)."
            stage_status "chaos" "skipped" "no PDCP_API_KEY"
        fi
    fi

    # Certificate transparency and the free passive-DNS APIs. Every source is
    # additive: a rate limit or an outage costs that one source, never the list.
    if check_tool curl && have_jq; then
        for attempt in 1 2 3; do
            if curl_any --silent --show-error --max-time 60 "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null \
                | jq -r '.[].name_value?' 2>/dev/null >> "$raw"; then
                break
            fi
            log WARN "crt.sh request failed (attempt ${attempt}/3); retrying."
            sleep $((attempt * 2))
        done

        for attempt in 1 2 3; do
            if curl_any --silent --show-error --max-time 45 \
                "https://api.certspotter.com/v1/issuances?domain=${DOMAIN}&include_subdomains=true&expand=dns_names" 2>/dev/null \
                | jq -r '.[].dns_names[]?' 2>/dev/null >> "$raw"; then
                break
            fi
            log WARN "CertSpotter request failed (attempt ${attempt}/3); retrying."
            sleep $((attempt * 2))
        done

        curl_any --silent --show-error --max-time 45 \
            "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}" 2>/dev/null \
            | awk -F, 'NF >= 2 && $1 ~ /\./ { print $1 }' >> "$raw" || true

        curl_any --silent --show-error --max-time 45 \
            "https://jldc.me/anubis/subdomains/${DOMAIN}" 2>/dev/null \
            | jq -r '.[]?' 2>/dev/null >> "$raw" || true
    fi

    # A certificate can name a host that no passive provider lists, so the SANs
    # of the apex certificate join the candidate list and are DNS-validated with
    # everything else instead of only being reported after the fact.
    if check_tool tlsx && have_jq; then
        printf '%s\n' "$DOMAIN" > "$tlsx_target"
        proxy_args_for tlsx
        run_tool tlsx-san --stdout "$san_raw" tlsx -list "$tlsx_target" -san -cn -silent -json \
            "${P_ARGS[@]+"${P_ARGS[@]}"}"
        jq -r '(.subject_an[]?, .subject_cn?) | select(type == "string")' "$san_raw" 2>/dev/null >> "$raw"
        stage_status "tlsx-sans" "ok" "$(count_lines "$san_raw") certificate entries"
    fi
    rm -f -- "$san_raw" "$tlsx_target"

    scope_filter host "$raw" "$passive"
    rm -f -- "$raw"
    stage_status "passive-subs" "ok" "$(count_lines "$passive") scoped passive names"

    # AlterX is only a bounded name generator: every output is scope-filtered
    # again and is sent through the same DNS/wildcard validation as other sources.
    if check_tool alterx; then
        if [[ -s "$passive" ]]; then
            run_tool alterx --stdout "$alterx_raw" alterx -list "$passive" -silent -limit 2000
            alterx_rc=$?
            scope_filter host "$alterx_raw" "$alterx_candidates"
            alterx_generated=$(count_lines "$alterx_candidates")
            if (( alterx_rc == 0 )); then
                alterx_status="ok"
                alterx_note="${alterx_generated} scoped candidates (cap 2000)"
            else
                alterx_status="degraded"
                alterx_note="${alterx_generated} scoped candidates; $(describe_status "$alterx_rc")"
            fi
        else
            alterx_note="no passive names to permute"
        fi
    fi
    stage_status "alterx" "$alterx_status" "$alterx_note"

    { cat "$passive"; cat "$alterx_candidates"; } | sort -u > "$dns_candidates"

    if ! check_tool dnsx; then
        cp -- "$dns_candidates" "$out"
        log WARN "dnsx unavailable; passive and permutation names are not DNS-validated."
        stage_status "dns" "skipped" "dnsx missing"
    elif [[ ! -s "$dns_candidates" ]]; then
        : > "$out"
        log WARN "No in-scope names were found."
        stage_status "dns" "skipped" "no in-scope names"
    else
        run_tool dnsx --stdout "$resolved" dnsx -list "$dns_candidates" -silent -auto-wildcard \
            -threads "$THREADS" -rate-limit "$RATE_LIMIT" -retry 2 -timeout 5s
        dnsx_status=$?
        if [[ ! -s "$resolved" ]] && (( dnsx_status != 0 )); then
            log WARN "dnsx failed ($(describe_status "$dnsx_status")); retrying without -auto-wildcard."
            run_tool dnsx --stdout "$resolved" dnsx -list "$dns_candidates" -silent \
                -threads "$THREADS" -rate-limit "$RATE_LIMIT" -retry 2 -timeout 5s
            dnsx_status=$?
        fi
        if [[ -s "$resolved" ]]; then
            scope_filter host "$resolved" "$dns_scoped"
            cp -- "$dns_scoped" "$out"
            stage_status "dns" "ok" "$(count_lines "$dns_scoped") DNS-validated names"
        else
            # A broken resolver must not wipe the host list and silently skip
            # every later stage, which used to look exactly like "no subdomains".
            cp -- "$dns_candidates" "$out"
            log WARN "dnsx produced no validated names ($(describe_status "$dnsx_status")); continuing with unvalidated candidates."
            stage_status "dns" "degraded" "unvalidated passive and permutation names"
        fi
    fi

    if [[ -s "$alterx_candidates" && -s "$dns_scoped" ]]; then
        grep -Fxf "$alterx_candidates" "$dns_scoped" > "$alterx_resolved" || true
    fi
    alterx_dns_resolved=$(count_lines "$alterx_resolved")
    if ! check_tool dnsx; then
        stage_status "alterx-dns" "skipped" "${alterx_dns_resolved} DNS-validated AlterX candidates; dnsx missing"
    elif [[ ! -s "$alterx_candidates" ]]; then
        stage_status "alterx-dns" "skipped" "0 AlterX candidates to validate"
    elif [[ -s "$resolved" ]]; then
        stage_status "alterx-dns" "ok" "${alterx_dns_resolved}/${alterx_generated} AlterX candidates DNS-validated"
    else
        stage_status "alterx-dns" "degraded" "${alterx_dns_resolved}/${alterx_generated} AlterX candidates DNS-validated"
    fi

    detect_wildcard_dns
    log OK "Scoped names: $(count_lines "$out") (passive: $(count_lines "$passive"), AlterX in-scope generated: ${alterx_generated}, AlterX DNS-validated: ${alterx_dns_resolved}, DNS-validated total: $(count_lines "$dns_scoped"))"
}

module_alive() {
    log INFO "Probing in-scope hosts (httpx)"
    local json="$OUTPUT_DIR/alive/httpx.jsonl"
    local raw="$OUTPUT_DIR/alive/raw.txt"
    local urls="$OUTPUT_DIR/alive/urls.txt"
    local candidates="$OUTPUT_DIR/alive/candidates.tmp"
    : > "$json"
    : > "$raw"
    : > "$urls"
    : > "$candidates"

    if ! check_tool httpx; then
        log WARN "httpx not found; skipping HTTP probing."
        stage_status "alive" "skipped" "httpx missing"
        return 0
    fi
    if [[ ! -s "$OUTPUT_DIR/subs/all.txt" ]]; then
        log WARN "No in-scope hosts to probe."
        stage_status "alive" "skipped" "no hosts"
        return 0
    fi

    local -a probe=(-l "$OUTPUT_DIR/subs/all.txt" -silent -threads "$THREADS" -rate-limit "$RATE_LIMIT" \
        -timeout 10 -retries 2 -status-code -title -tech-detect -web-server -location -cname)
    [[ -n "$WEB_PORTS" ]] && probe+=(-ports "$WEB_PORTS")

    proxy_args_for httpx
    if have_jq; then
        # -irh keeps the response headers, which the header audit reuses; the
        # probe deliberately does not follow redirects, so an in-scope host that
        # redirects off-scope is still reported under its own URL.
        run_tool httpx --stdout "$json" httpx "${probe[@]}" -json -include-response-header \
            "${P_ARGS[@]+"${P_ARGS[@]}"}"
        if [[ ! -s "$json" ]]; then
            log WARN "httpx produced no JSON (older build without -include-response-header?); retrying without headers."
            run_tool httpx --stdout "$json" httpx "${probe[@]}" -json \
                "${P_ARGS[@]+"${P_ARGS[@]}"}"
        fi
        jq -r 'select(.url != null) | .url' "$json" 2>/dev/null > "$candidates"
    else
        log WARN "jq not found: httpx output is parsed as text and the header audit falls back to curl."
        run_tool httpx --stdout "$raw" httpx "${probe[@]}" \
            "${P_ARGS[@]+"${P_ARGS[@]}"}"
        awk '{print $1}' "$raw" 2>/dev/null > "$candidates"
    fi

    scope_filter url "$candidates" "$urls"
    rm -f -- "$candidates"
    if [[ -s "$urls" ]]; then
        stage_status "alive" "ok" "$(count_lines "$urls") live URLs"
    else
        stage_status "alive" "failed" "no live URLs"
    fi
    log OK "Alive URLs: $(count_lines "$urls")"
}

# Header audit on an httpx JSONL export: url + lowercased header block per line.
# httpx stores response headers under .header, sometimes with the raw
# "_:<header>" keys, so both spellings are normalised here.
audit_headers_json() {
    local json="$1" report="$2" flat="$OUTPUT_DIR/web/headers.tsv"
    # Only 2xx and 3xx responses are audited: the header set of a 401, 403, 404
    # or 5xx page is not the application's, and auditing it reported every
    # header as missing on hosts that simply refused the request.
    jq -r 'select(.url? != null) |
        select((.status_code // 200) >= 200 and (.status_code // 200) < 400) |
        [
            .url,
            ((.header // {}) | to_entries[] |
                (if (.key | startswith("_:")) then (.key[2:]) else .key end) as $k |
                "\($k | ascii_downcase | gsub("_"; "-")): \(.value | if type == "array" then join(" | ") else tostring end)")
        ] | @tsv' \
        "$json" 2>/dev/null > "$flat"
    [[ -s "$flat" ]] || return 1
    # Rows that carry only a URL mean httpx sent no headers; auditing them would
    # report every header as missing, so let the caller fall back to curl.
    awk -F'\t' 'NF > 1 { found = 1 } END { exit !found }' "$flat" || return 1

    awk -F'\t' '
        function say(msg) { printf "[INFO] %s — %s\n", url, msg }
        {
            url = $1
            if (url == "") next
            delete h
            for (i = 2; i <= NF; i++) {
                pos = index($i, ": ")
                if (pos == 0) continue
                key = substr($i, 1, pos - 1)
                if (!(key in h)) h[key] = tolower(substr($i, pos + 2))
            }
            if (url ~ /^https:\/\// && !("strict-transport-security" in h)) say("missing Strict-Transport-Security")
            if (!("content-security-policy" in h)) say("missing Content-Security-Policy")
            if (!("x-content-type-options" in h)) say("missing X-Content-Type-Options")
            if (!("x-frame-options" in h) && h["content-security-policy"] !~ /frame-ancestors/) say("no clickjacking protection detected")
            if (!("referrer-policy" in h)) say("missing Referrer-Policy")
            if (!("permissions-policy" in h)) say("missing Permissions-Policy")
            if (h["server"] != "") say("server banner disclosed: " h["server"])
            if (h["x-powered-by"] != "") say("X-Powered-By disclosed: " h["x-powered-by"])
            # httpx joins repeated Set-Cookie headers with " | ", so each cookie
            # is judged on its own instead of on the joined string.
            if ("set-cookie" in h) {
                njar = split(h["set-cookie"], jar, / \| /)
                for (c = 1; c <= njar; c++) {
                    if (jar[c] == "") continue
                    lc = tolower(jar[c])
                    cname = jar[c]
                    sub(/=.*$/, "", cname)
                    if (lc !~ /secure/)   say("cookie " cname " without Secure attribute")
                    if (lc !~ /httponly/) say("cookie " cname " without HttpOnly attribute")
                    if (lc !~ /samesite/) say("cookie " cname " without SameSite attribute")
                }
            }
        }
    ' "$flat" >> "$report"
    return 0
}

# Header audit for one dumped response header file (curl fallback path).
audit_header_file() {
    local url="$1" file="$2" value
    if [[ "$url" == https://* ]] && ! grep -qi '^strict-transport-security:' "$file"; then
        printf '[INFO] %s — missing Strict-Transport-Security\n' "$url"
    fi
    grep -qi '^content-security-policy:' "$file" || printf '[INFO] %s — missing Content-Security-Policy\n' "$url"
    grep -qi '^x-content-type-options:' "$file" || printf '[INFO] %s — missing X-Content-Type-Options\n' "$url"
    if ! grep -qi '^x-frame-options:' "$file" && ! grep -qi '^content-security-policy:.*frame-ancestors' "$file"; then
        printf '[INFO] %s — no clickjacking protection detected\n' "$url"
    fi
    grep -qi '^referrer-policy:' "$file" || printf '[INFO] %s — missing Referrer-Policy\n' "$url"
    grep -qi '^permissions-policy:' "$file" || printf '[INFO] %s — missing Permissions-Policy\n' "$url"
    value=$(grep -i '^server:' "$file" | head -1 | cut -d' ' -f2- | tr -d '\r')
    if [[ -n "$value" ]]; then printf '[INFO] %s — server banner disclosed: %s\n' "$url" "$value"; fi
    value=$(grep -i '^x-powered-by:' "$file" | head -1 | cut -d' ' -f2- | tr -d '\r')
    if [[ -n "$value" ]]; then printf '[INFO] %s — X-Powered-By disclosed: %s\n' "$url" "$value"; fi
    if grep -qi '^set-cookie:' "$file"; then
        grep -qi '^set-cookie:.*secure' "$file" || printf '[INFO] %s — cookie without Secure attribute\n' "$url"
        grep -qi '^set-cookie:.*httponly' "$file" || printf '[INFO] %s — cookie without HttpOnly attribute\n' "$url"
        grep -qi '^set-cookie:.*samesite' "$file" || printf '[INFO] %s — cookie without SameSite attribute\n' "$url"
    fi
}

module_whatweb() {
    log INFO "Low-aggression technology fingerprinting (WhatWeb)"
    local report="$OUTPUT_DIR/web/whatweb.json"
    local scoped="$OUTPUT_DIR/web/whatweb_targets.txt"
    local targets="$OUTPUT_DIR/web/whatweb_targets.capped.txt"
    local rc=0
    : > "$report"

    if ! check_tool whatweb; then
        log WARN "whatweb not found; skipping technology fingerprinting."
        stage_status "whatweb" "skipped" "whatweb missing"
        return 0
    fi
    if [[ ! -s "$OUTPUT_DIR/alive/urls.txt" ]]; then
        log WARN "No live URLs for WhatWeb."
        stage_status "whatweb" "skipped" "no live URLs"
        return 0
    fi

    scope_filter url "$OUTPUT_DIR/alive/urls.txt" "$scoped"
    head -n 100 "$scoped" > "$targets"
    if [[ ! -s "$targets" ]]; then
        log WARN "No in-scope URLs for WhatWeb."
        stage_status "whatweb" "skipped" "no in-scope URLs"
        return 0
    fi

    # Aggression 1 is WhatWeb's single-request fingerprint mode. Redirects are
    # disabled to prevent following a target off the configured program scope.
    proxy_args_for whatweb
    run_tool whatweb whatweb --input-file="$targets" --aggression=1 --max-threads 1 \
        --open-timeout 10 --read-timeout 10 --wait 1 --follow-redirect=never \
        --color=never --quiet --log-json="$report" \
        "${P_ARGS[@]+"${P_ARGS[@]}"}"
    rc=$?
    if (( rc == 0 )); then
        stage_status "whatweb" "ok" "$(count_lines "$targets") scoped URLs fingerprinted"
        log OK "WhatWeb results: $report"
    else
        stage_status "whatweb" "failed" "$(describe_status "$rc")"
        log WARN "WhatWeb did not complete; see logs/whatweb.err."
    fi
}

module_headers() {
    log INFO "Auditing HTTP security headers"
    local report="$OUTPUT_DIR/web/header_audit.txt"
    local headers_file url delay status
    : > "$report"

    if [[ ! -s "$OUTPUT_DIR/alive/urls.txt" ]]; then
        log WARN "No alive URLs; skipping header audit."
        stage_status "headers" "skipped" "no live URLs"
        return 0
    fi

    # Preferred path: reuse the headers httpx already collected (no extra traffic).
    if have_jq && [[ -s "$OUTPUT_DIR/alive/httpx.jsonl" ]]; then
        if audit_headers_json "$OUTPUT_DIR/alive/httpx.jsonl" "$report"; then
            log OK "Header audit saved: $report (from httpx responses: $(count_lines "$report") notes)"
            stage_status "headers" "ok" "$(count_lines "$report") notes"
            return 0
        fi
        log WARN "httpx JSON carried no headers; falling back to per-URL curl."
    fi

    if ! check_tool curl; then
        log WARN "curl not found; skipping header audit."
        stage_status "headers" "skipped" "curl missing"
        return 0
    fi

    delay=$(awk -v rate="$RATE_LIMIT" 'BEGIN { if (rate > 0) printf "%.3f", 1 / rate; else print "0.1" }')
    while IFS= read -r url; do
        [[ -n "$url" ]] || continue
        headers_file=$(mktemp "$OUTPUT_DIR/web/headers.XXXXXX") || continue
        curl_any --silent --show-error --max-time 10 --max-filesize 1048576 --max-redirs 0 \
            --dump-header "$headers_file" --output /dev/null "$url" 2>/dev/null || true
        status=$(awk '/^HTTP\// { print $2; exit }' "$headers_file" 2>/dev/null)
        if [[ "$status" =~ ^[0-9]+$ ]] && (( status >= 200 && status < 400 )); then
            audit_header_file "$url" "$headers_file" >> "$report"
        fi
        rm -f -- "$headers_file"
        sleep "$delay"
    done < "$OUTPUT_DIR/alive/urls.txt"

    log OK "Header audit saved: $report ($(count_lines "$report") notes)"
    stage_status "headers" "ok" "$(count_lines "$report") notes"
}

module_tlsx() {
    log INFO "TLS certificate inventory and misconfiguration checks"
    local targets="$OUTPUT_DIR/tls/targets.txt"
    local inventory="$OUTPUT_DIR/tls/inventory.jsonl"
    local issues="$OUTPUT_DIR/tls/misconfigurations.txt"
    local san_raw="$OUTPUT_DIR/tls/san.raw.tmp"
    local sans="$OUTPUT_DIR/tls/in_scope_sans.txt"
    : > "$inventory"
    : > "$issues"
    : > "$san_raw"
    : > "$sans"

    scope_filter target "$OUTPUT_DIR/alive/urls.txt" "$targets"

    if ! check_tool tlsx || [[ ! -s "$targets" ]]; then
        log WARN "tlsx unavailable or no in-scope HTTPS endpoints; skipping TLS checks."
        stage_status "tls" "skipped" "tlsx missing or no HTTPS endpoints"
        return 0
    fi

    proxy_args_for tlsx
    run_tool tlsx --stdout "$inventory" tlsx -list "$targets" -json -silent -san -cn \
        -tls-version -cipher -concurrency "$THREADS" -timeout 5 -retry 1 \
        "${P_ARGS[@]+"${P_ARGS[@]}"}"
    run_tool tlsx --stdout "$issues" tlsx -list "$targets" -silent \
        -expired -self-signed -mismatched -revoked -untrusted -concurrency "$THREADS" -timeout 5 -retry 1 \
        "${P_ARGS[@]+"${P_ARGS[@]}"}"

    if have_jq && [[ -s "$inventory" ]]; then
        jq -r '(.subject_an[]?, .subject_cn?) | select(type == "string")' "$inventory" 2>/dev/null > "$san_raw"
    fi
    scope_filter host "$san_raw" "$sans"

    log OK "TLS inventory: $(count_lines "$inventory") endpoints, $(count_lines "$issues") misconfigurations, $(count_lines "$sans") in-scope SANs"
    stage_status "tls" "ok" "$(count_lines "$issues") issues / $(count_lines "$sans") SANs"
}

# Optional testssl pass: select only protocol, cipher-category and server-default
# checks; never run its broad default/vulnerability suite. One IP and at most ten
# in-scope HTTPS endpoints are tested sequentially.
module_testssl() {
    local summary="$OUTPUT_DIR/tls/testssl_summary.txt"
    local scoped="$OUTPUT_DIR/tls/testssl_targets.scoped.txt"
    local capped="$OUTPUT_DIR/tls/testssl_targets.txt"
    local target output json status delay count=0 completed=0 failed=0
    : > "$summary"

    if (( ! MODULE_TESTSSL )); then
        stage_status "testssl" "skipped" "opt-in disabled (pass --testssl to enable)"
        return 0
    fi
    if ! check_tool testssl.sh; then
        log WARN "testssl.sh missing; run bash setup.sh to install pinned v3.2.5."
        stage_status "testssl" "skipped" "testssl.sh missing"
        return 0
    fi

    scope_filter target "$OUTPUT_DIR/alive/urls.txt" "$scoped"
    head -n "$TESTSSL_MAX_HOSTS" "$scoped" > "$capped"
    if [[ ! -s "$capped" ]]; then
        stage_status "testssl" "skipped" "no in-scope HTTPS endpoints"
        return 0
    fi

    delay=$(awk -v rate="$RATE_LIMIT" 'BEGIN { if (rate > 0) printf "%.3f", 1 / rate; else print "0.1" }')
    while IFS= read -r target; do
        [[ -n "$target" ]] || continue
        count=$((count + 1))
        output="$OUTPUT_DIR/tls/testssl_$(printf '%02d' "$count").txt"
        json="$OUTPUT_DIR/tls/testssl_$(printf '%02d' "$count").json"
        : > "$output"
        if run_tool "testssl-${count}" --stdout "$output" testssl.sh \
            --ip=one --nodns=min --connect-timeout 10 --openssl-timeout 20 \
            --ids-friendly --disable-rating -p -s -S -q --color 0 \
            --jsonfile "$json" "$target"; then
            status="ok"
            completed=$((completed + 1))
        else
            status="failed"
            failed=$((failed + 1))
        fi
        printf '%s\t%s\t%s\t%s\n' "$target" "$status" "$output" "$json" >> "$summary"
        sleep "$delay"
    done < "$capped"

    if (( failed == 0 )); then
        stage_status "testssl" "ok" "${completed}/${count} HTTPS hosts (cap ${TESTSSL_MAX_HOSTS}); selected TLS checks only"
    else
        stage_status "testssl" "degraded" "${completed}/${count} HTTPS hosts completed; see logs/testssl-*.err"
    fi
    log OK "Optional testssl results saved in $summary"
}

# A host that only a certificate names never went through the HTTP probe, so it
# was silently left out of URL collection, nuclei and dalfox. Such hosts are
# probed here and merged into the host and URL lists, which widens coverage
# without guessing at names.
module_san_hosts() {
    log INFO "Probing hosts named only by certificates"
    local sans="$OUTPUT_DIR/tls/in_scope_sans.txt"
    local known="$OUTPUT_DIR/subs/all.txt"
    local extra="$OUTPUT_DIR/subs/from_tls.txt"
    local json="$OUTPUT_DIR/tls/extra_probe.jsonl"
    local candidates="$OUTPUT_DIR/tls/extra_candidates.tmp"
    local scoped="$OUTPUT_DIR/urls/from_tls.txt"
    local live_count=0
    : > "$extra"
    : > "$json"
    : > "$candidates"

    if [[ ! -s "$sans" ]]; then
        stage_status "san-hosts" "skipped" "no in-scope certificate names"
        return 0
    fi
    [[ -s "$known" ]] || : > "$known"

    if [[ -s "$known" ]]; then
        grep -vxF -f "$known" "$sans" > "$extra" 2>/dev/null || true
    else
        cp -f -- "$sans" "$extra" 2>/dev/null || true
    fi
    sort -u -o "$extra" "$extra"

    if [[ ! -s "$extra" ]]; then
        log OK "No host was named only by a certificate."
        stage_status "san-hosts" "ok" "0 new hosts"
        return 0
    fi

    # Merged into the host list first: the port, takeover and nmap stages read
    # subs/all.txt and would otherwise never see these names.
    cat "$extra" >> "$known"
    sort -u -o "$known" "$known"

    if ! check_tool httpx; then
        log WARN "httpx missing; certificate-only hosts stay unprobed."
        stage_status "san-hosts" "degraded" "httpx missing"
        return 0
    fi

    local -a probe=(-l "$extra" -silent -threads "$THREADS" -rate-limit "$RATE_LIMIT" \
        -timeout 10 -retries 2 -status-code -title -tech-detect -web-server -location -cname)
    [[ -n "$WEB_PORTS" ]] && probe+=(-ports "$WEB_PORTS")

    proxy_args_for httpx
    if have_jq; then
        run_tool httpx-san --stdout "$json" httpx "${probe[@]}" -json -include-response-header \
            "${P_ARGS[@]+"${P_ARGS[@]}"}"
        jq -r 'select(.url != null) | .url' "$json" 2>/dev/null > "$candidates"
    else
        run_tool httpx-san --stdout "$candidates" httpx "${probe[@]}" \
            "${P_ARGS[@]+"${P_ARGS[@]}"}"
        awk '{ print $1 }' "$candidates" 2>/dev/null > "${candidates}.urls"
        sort -u -o "${candidates}.urls" "${candidates}.urls"
        mv -f -- "${candidates}.urls" "$candidates"
    fi

    scope_filter url "$candidates" "$scoped"
    live_count=$(count_lines "$scoped")
    if [[ -s "$scoped" ]]; then
        cat "$scoped" >> "$OUTPUT_DIR/alive/urls.txt"
        sort -u -o "$OUTPUT_DIR/alive/urls.txt" "$OUTPUT_DIR/alive/urls.txt"
        if [[ -s "$json" ]]; then
            cat "$json" >> "$OUTPUT_DIR/alive/httpx.jsonl" 2>/dev/null || true
        fi
        cat "$scoped" >> "$OUTPUT_DIR/urls/all.txt" 2>/dev/null || true
        sort -u -o "$OUTPUT_DIR/urls/all.txt" "$OUTPUT_DIR/urls/all.txt" 2>/dev/null || true
    fi
    rm -f -- "$candidates"

    log OK "Certificate-only hosts: $(count_lines "$extra") checked, ${live_count} live"
    stage_status "san-hosts" "ok" "$(count_lines "$extra") hosts / ${live_count} live URLs"
}

# Historical URLs from the newest passive toolkit snapshot (Wayback + Common
# Crawl). Archives still list endpoints that today's crawl no longer shows, and
# a good share of them still answer. Prints one URL per line, capped by
# ARCHIVE_MAX_URLS; prints nothing when no snapshot exists for the domain.
toolkit_archived_urls() {
    local domain="$1"
    local dir="${SCRIPT_DIR}/bugbounty-toolkit/data/history/${domain}"
    [[ -d "$dir" ]] || return 1
    local snapshot
    snapshot=$(ls -1t "$dir"/*.json 2>/dev/null | head -n 1)
    [[ -n "$snapshot" ]] || return 1
    jq -r '.archived_urls // [] | .[]' "$snapshot" 2>/dev/null \
        | head -n "${ARCHIVE_MAX_URLS:-150}" || true
}

module_urls() {
    log INFO "Collecting URLs"
    local raw="$OUTPUT_DIR/urls/all.raw.tmp"
    local out="$OUTPUT_DIR/urls/all.txt"
    local hosts="$OUTPUT_DIR/subs/all.txt"
    local alive="$OUTPUT_DIR/alive/urls.txt"
    : > "$raw"
    : > "$OUTPUT_DIR/urls/params.txt"

    if ! check_tool waybackurls && ! check_tool gau && ! check_tool katana; then
        log WARN "No URL collector (waybackurls, gau, katana) installed; only archived URLs will be used."
    fi

    # waybackurls and gau have no proxy flag; they honour the standard
    # HTTP(S)_PROXY variables, so the proxy is passed through the environment
    # when a pool is configured.
    if [[ -s "$hosts" ]] && check_tool waybackurls; then
        if proxies_loaded; then
            pick_proxy
            run_tool waybackurls --stdout "$raw" env \
                "HTTPS_PROXY=${PROXY_CURRENT}" "HTTP_PROXY=${PROXY_CURRENT}" \
                waybackurls < "$hosts"
        else
            run_tool waybackurls --stdout "$raw" waybackurls < "$hosts"
        fi
    fi
    if [[ -s "$hosts" ]] && check_tool gau; then
        if proxies_loaded; then
            pick_proxy
            run_tool gau --stdout "$raw" env \
                "HTTPS_PROXY=${PROXY_CURRENT}" "HTTP_PROXY=${PROXY_CURRENT}" \
                gau --threads "$THREADS" < "$hosts"
        else
            run_tool gau --stdout "$raw" gau --threads "$THREADS" < "$hosts"
        fi
    fi
    if [[ -s "$alive" ]] && check_tool katana; then
        proxy_args_for katana
        run_tool katana --stdout "$raw" katana -list "$alive" -silent -d 3 -jc \
            -c "$THREADS" -rl "$RATE_LIMIT" \
            "${P_ARGS[@]+"${P_ARGS[@]}"}"
    fi

    scope_filter url "$raw" "$out"
    rm -f -- "$raw"

    # Live URLs found through a certificate name are as valid as harvested ones;
    # scope_filter above rewrote the list, so they are put back here.
    if [[ -s "$OUTPUT_DIR/urls/from_tls.txt" ]]; then
        cat "$OUTPUT_DIR/urls/from_tls.txt" >> "$out"
        sort -u -o "$out" "$out"
    fi

    # Archived endpoints from the passive toolkit extend the pool the parameter
    # stage feeds on; they pass the same scope rules as everything else, so an
    # archive URL cannot widen the target list.
    local arch_raw="${OUTPUT_DIR}/urls/archived.raw.tmp"
    local arch_scoped="${OUTPUT_DIR}/urls/archived.txt"
    if toolkit_archived_urls "$DOMAIN" >"$arch_raw" && [[ -s "$arch_raw" ]]; then
        scope_filter url "$arch_raw" "$arch_scoped"
        if [[ -s "$arch_scoped" ]]; then
            cat "$arch_scoped" >> "$out"
            sort -u -o "$out" "$out"
            log OK "Archived URLs from the passive toolkit: $(count_lines "$arch_scoped")"
        fi
    fi
    rm -f -- "$arch_raw"

    build_param_candidates

    log OK "In-scope URLs: $(count_lines "$out") ($(count_lines "$OUTPUT_DIR/urls/params.txt") parameterised)"
    stage_status "urls" "ok" "$(count_lines "$out") URLs"
}

# Probe conventional JSON and YAML OpenAPI locations, but harvest only GET
# operations. Documented query parameters feed existing checks; write methods and
# request-body examples are never replayed.
module_openapi() {
    log INFO "OpenAPI route discovery (bounded, GET-only)"
    local bases="$OUTPUT_DIR/urls/openapi_bases.txt"
    local specs="$OUTPUT_DIR/urls/openapi_specs.txt"
    local raw="$OUTPUT_DIR/urls/openapi_endpoints.raw.tmp"
    local endpoints="$OUTPUT_DIR/urls/openapi_endpoints.txt"
    local base spec_path spec_url body headers extracted status size delay route query
    local route_count=0 spec_count=0 yaml_python="" python_candidate=""
    local -a spec_paths=(
        /openapi.json /openapi.yaml
        /swagger.json /swagger.yaml
        /swagger/v1/swagger.json /swagger/v1/swagger.yaml
        /v3/api-docs /v3/api-docs.yaml
        /api-docs /api-docs.yaml
        /api/openapi.json /api/openapi.yaml
    )
    : > "$specs"
    : > "$raw"
    : > "$endpoints"

    if ! check_tool curl || ! have_jq; then
        log WARN "curl or jq missing; skipping OpenAPI discovery."
        stage_status "openapi" "skipped" "curl or jq missing"
        return 0
    fi
    if [[ ! -s "$OUTPUT_DIR/alive/urls.txt" ]]; then
        stage_status "openapi" "skipped" "no live URLs"
        return 0
    fi

    for python_candidate in "${SCRIPT_DIR}/bugbounty-toolkit/.venv/bin/python" "$(command -v python3 2>/dev/null || true)"; do
        [[ -x "$python_candidate" ]] || continue
        if "$python_candidate" -c 'import yaml' >/dev/null 2>&1; then
            yaml_python="$python_candidate"
            break
        fi
    done
    if [[ -z "$yaml_python" ]]; then
        log WARN "Python/PyYAML unavailable; YAML OpenAPI documents are skipped (JSON remains enabled)."
    fi

    unique_origins "$OUTPUT_DIR/alive/urls.txt" "$bases" "$OPENAPI_MAX_HOSTS"
    delay=$(awk -v rate="$RATE_LIMIT" 'BEGIN { if (rate > 0) printf "%.3f", 1 / rate; else print "0.1" }')

    while IFS= read -r base; do
        [[ -n "$base" ]] || continue
        for spec_path in "${spec_paths[@]}"; do
            case "${spec_path,,}" in
                *.yaml|*.yml) [[ -n "$yaml_python" ]] || continue ;;
            esac
            spec_url="${base%/}${spec_path}"
            body=$(mktemp "$OUTPUT_DIR/urls/openapi.XXXXXX") || continue
            headers=$(mktemp "$OUTPUT_DIR/urls/openapi_headers.XXXXXX") || {
                rm -f -- "$body"
                continue
            }
            # Enforce the 2 MiB ceiling even for chunked responses with no length.
            curl_any --silent --show-error --max-time 10 --max-redirs 0 --max-filesize 2097152 \
                --user-agent "Mozilla/5.0 (compatible; recon-pro/${VERSION})" \
                --dump-header "$headers" --output - "$spec_url" 2>/dev/null \
                | head -c 2097153 > "$body" || true
            sleep "$delay"
            status=$(awk 'index($1, "HTTP/") == 1 { code = $2 } END { print code }' "$headers" 2>/dev/null)
            size=$(wc -c < "$body" 2>/dev/null | tr -d '[:space:]')
            rm -f -- "$headers"
            case "${spec_path,,}" in
                *.yaml|*.yml)
                    if [[ "$status" != "200" ]] || (( ${size:-0} > 2097152 )); then
                        rm -f -- "$body"
                        continue
                    fi
                    extracted=$(mktemp "$OUTPUT_DIR/urls/openapi_routes.XXXXXX") || {
                        rm -f -- "$body"
                        continue
                    }
                    if ! "$yaml_python" "${SCRIPT_DIR}/bugbounty-toolkit/openapi_routes.py" \
                        "$body" "$((OPENAPI_MAX_ENDPOINTS - route_count))" > "$extracted" 2>/dev/null; then
                        rm -f -- "$body" "$extracted"
                        continue
                    fi
                    printf '%s\n' "$spec_url" >> "$specs"
                    spec_count=$((spec_count + 1))
                    while IFS=$'\t' read -r route query; do
                        (( route_count >= OPENAPI_MAX_ENDPOINTS )) && break
                        [[ "$route" == /* && "$route" != //* ]] || continue
                        printf '%s%s%s\n' "${base%/}" "$route" "${query:+?${query}}" >> "$raw"
                        route_count=$((route_count + 1))
                    done < "$extracted"
                    rm -f -- "$body" "$extracted"
                    break
                    ;;
            esac
            if [[ "$status" != "200" ]] || (( ${size:-0} > 2097152 )) || ! jq -e \
                '(.paths | type) == "object" and ((.openapi // "" | startswith("3.")) or .swagger == "2.0")' \
                "$body" >/dev/null 2>&1; then
                rm -f -- "$body"
                continue
            fi

            printf '%s\n' "$spec_url" >> "$specs"
            spec_count=$((spec_count + 1))
            while IFS=$'\t' read -r route query; do
                (( route_count >= OPENAPI_MAX_ENDPOINTS )) && break
                [[ "$route" == /* && "$route" != //* ]] || continue
                route=$(sed -E 's/\{[^}]+\}/1/g' <<< "$route")
                printf '%s%s%s\n' "${base%/}" "$route" "${query:+?${query}}" >> "$raw"
                route_count=$((route_count + 1))
            done < <(jq -r '
                .paths // {} | to_entries[]? |
                select(.value.get? != null) |
                .key as $path |
                ((.value.parameters // []) + (.value.get.parameters // [])) as $params |
                ([$params[]? | select(.in == "query" and (.name | type == "string")) | (.name | @uri) + "=1"] | unique | join("&")) as $query |
                [$path, $query] | @tsv
            ' "$body" 2>/dev/null)
            rm -f -- "$body"
            break
        done
        (( route_count >= OPENAPI_MAX_ENDPOINTS )) && break
    done < "$bases"

    scope_filter url "$raw" "$endpoints"
    if [[ -s "$endpoints" ]]; then
        cat "$endpoints" >> "$OUTPUT_DIR/urls/all.txt"
        sort -u -o "$OUTPUT_DIR/urls/all.txt" "$OUTPUT_DIR/urls/all.txt"
        build_param_candidates
    fi

    if (( spec_count > 0 )); then
        log OK "OpenAPI: ${spec_count} valid spec(s), $(count_lines "$endpoints") scoped GET endpoint(s)"
        stage_status "openapi" "ok" "${spec_count} spec(s) / $(count_lines "$endpoints") GET endpoints (cap ${OPENAPI_MAX_ENDPOINTS})"
    else
        log INFO "No valid public OpenAPI/Swagger JSON or YAML spec found on the capped host set."
        stage_status "openapi" "skipped" "no valid JSON/YAML specification found"
    fi
    rm -f -- "$raw"
}

module_x8() {
    log INFO "Hidden parameter discovery (x8)"
    local out="$OUTPUT_DIR/x8/parameters.json"
    local targets="$OUTPUT_DIR/x8/targets.txt"
    local delay_ms
    : > "$out"

    if ! check_tool x8 || [[ ! -f "$PARAM_WORDLIST" ]]; then
        log WARN "x8 or its parameter wordlist is unavailable; skipping parameter discovery."
        stage_status "x8" "skipped" "x8 or wordlist missing"
        return 0
    fi
    if [[ ! -s "$OUTPUT_DIR/urls/params.txt" ]]; then
        log WARN "No in-scope parameter URLs for x8."
        stage_status "x8" "skipped" "no parameterised URLs"
        return 0
    fi

    head -n "$X8_MAX_URLS" "$OUTPUT_DIR/urls/params.txt" > "$targets"
    delay_ms=$(((1000 + RATE_LIMIT - 1) / RATE_LIMIT))
    proxy_args_for x8
    run_tool x8 x8 -u "$targets" -w "$PARAM_WORDLIST" -W 1 -c 1 \
        --delay "$delay_ms" --verify --strict --remove-empty -O json -o "$out" \
        "${P_ARGS[@]+"${P_ARGS[@]}"}"

    log OK "x8 candidates: $(count_lines "$out") line(s) in $out"
    stage_status "x8" "ok" "$(count_lines "$targets") URLs tested"
}

module_nuclei() {
    log INFO "Nuclei automated technology-aware scan"
    local out="$OUTPUT_DIR/nuclei/results.txt"
    local jsonl="$OUTPUT_DIR/nuclei/results.jsonl"
    local targets="$OUTPUT_DIR/nuclei/targets.txt"
    local targets_raw="$OUTPUT_DIR/nuclei/targets.raw.tmp"
    local rc=0
    : > "$out"
    : > "$jsonl"
    : > "$targets"
    : > "$targets_raw"

    if ! check_tool nuclei; then
        log WARN "nuclei not found; skipping template scan."
        stage_status "nuclei" "skipped" "nuclei missing"
        return 0
    fi
    [[ -s "$OUTPUT_DIR/alive/urls.txt" ]] && cat "$OUTPUT_DIR/alive/urls.txt" >> "$targets_raw"
    [[ -s "$OUTPUT_DIR/urls/openapi_endpoints.txt" ]] && cat "$OUTPUT_DIR/urls/openapi_endpoints.txt" >> "$targets_raw"
    [[ -s "$OUTPUT_DIR/js/endpoints_in_scope.txt" ]] && cat "$OUTPUT_DIR/js/endpoints_in_scope.txt" >> "$targets_raw"
    if [[ -s "$targets_raw" ]]; then
        sort -u "$targets_raw" > "$targets"
        scope_filter url "$targets" "$targets_raw"
        mv -f -- "$targets_raw" "$targets"
    fi
    if [[ ! -s "$targets" ]]; then
        log WARN "No in-scope URLs for nuclei."
        stage_status "nuclei" "skipped" "no in-scope URLs"
        return 0
    fi

    local -a opts=(-list "$targets" -silent
        -severity low,medium,high,critical -exclude-tags dos,fuzz,intrusive
        -rate-limit "$RATE_LIMIT" -concurrency "$THREADS" -timeout 10 -retries 1
        -duc -nc)
    if (( ! NUCLEI_INTERACTSH )); then
        opts+=(-no-interactsh)
    fi
    # -as/-automatic-scan picks templates from the technology the host actually
    # runs (wappalyzer to tag mapping), so the template set stays relevant
    # instead of firing every tag at every host.
    if (( NUCLEI_AUTOCALIBRATE )); then
        opts+=(-automatic-scan)
    fi
    if (( NUCLEI_DAST )); then
        opts+=(-dast)
    fi
    if (( NUCLEI_HEADLESS )); then
        opts+=(-headless)
    fi

    proxy_args_for nuclei
    run_tool nuclei nuclei "${opts[@]}" -o "$out" -jsonl-export "$jsonl" \
        "${P_ARGS[@]+"${P_ARGS[@]}"}"
    rc=$?
    if (( rc != 0 )) && [[ ! -s "$out" ]]; then
        # Older nuclei builds have no -jsonl-export and would lose every result.
        log WARN "nuclei failed ($(describe_status "$rc")); retrying with text output only."
        run_tool nuclei nuclei "${opts[@]}" -o "$out" \
            "${P_ARGS[@]+"${P_ARGS[@]}"}"
    fi

    # One ledger row per nuclei match, scored by severity.
    if [[ -s "$jsonl" ]] && have_jq; then
        jq -r 'select(.info.severity != null)
            | [(.info.severity | ascii_downcase), .host,
               (."template-id" // "unknown"),
               (.info.name // ""),
               (."matched-at" // .host // "")]
            | @tsv' "$jsonl" 2>/dev/null | sort -u \
            | while IFS=$'\t' read -r sev nhost tid tname matched; do
                [[ -n "$sev" ]] || continue
                add_finding "$(severity_score "$sev")" confirmed nuclei \
                    "$nhost" "nuclei ${tid}${tname:+ — ${tname}}" "$matched"
            done
    fi

    log OK "Nuclei results: $out"
    stage_status "nuclei" "ok" "$(count_lines "$out") result lines"
}

# dalfox_run <mode> <targets> <out> <delay-ms>
# Runs one dalfox invocation with the mode the installed build understands.
# Proxy arguments are already in P_ARGS.
dalfox_run() {
    local mode="$1" targets="$2" out="$3" delay_ms="$4"

    if [[ "$mode" == "scan" ]]; then
        run_tool dalfox --ok "0,1" dalfox scan -i file "$targets" -S --only-poc v \
            --delay "$delay_ms" -o "$out" \
            "${P_ARGS[@]+"${P_ARGS[@]}"}"
    else
        run_tool dalfox --ok "0,1" dalfox file "$targets" -S --only-poc v \
            --delay "$delay_ms" -o "$out" \
            "${P_ARGS[@]+"${P_ARGS[@]}"}"
    fi
}

module_xss() {
    log INFO "XSS checks (dalfox)"
    local out="$OUTPUT_DIR/xss/dalfox.txt"
    local targets="$OUTPUT_DIR/xss/targets.txt"
    local delay_ms
    : > "$out"

    if ! check_tool dalfox; then
        log WARN "dalfox not found; skipping XSS checks."
        stage_status "xss" "skipped" "dalfox missing"
        return 0
    fi
    if [[ ! -s "$OUTPUT_DIR/urls/params.txt" ]]; then
        log WARN "No parameterised URLs for dalfox."
        stage_status "xss" "skipped" "no parameterised URLs"
        return 0
    fi

    head -n "$DALFOX_MAX_URLS" "$OUTPUT_DIR/urls/params.txt" > "$targets"
    delay_ms=$(((1000 + RATE_LIMIT - 1) / RATE_LIMIT))

    # dalfox builds differ: some take "scan -i file", others only "file".
    # Ask the installed build which sub-commands it lists instead of guessing,
    # and retry the other style once if it rejects this one.
    local rc=0 mode="file" dalfox_help errf="${OUTPUT_DIR}/logs/dalfox.err" alt
    dalfox_help=$(dalfox --help 2>&1 || true)
    if grep -qE '^[[:space:]]+scan[[:space:]]' <<< "$dalfox_help"; then
        mode="scan"
    fi

    : > "$errf"
    proxy_args_for dalfox
    dalfox_run "$mode" "$targets" "$out" "$delay_ms"
    rc=$?

    if grep -qiE 'unknown command|unknown flag|invalid flag' "$errf" 2>/dev/null; then
        alt="file"
        [[ "$mode" == "file" ]] && alt="scan"
        log WARN "dalfox menolak mode ${mode}; mencoba ${alt} ..."
        dalfox_run "$alt" "$targets" "$out" "$delay_ms"
        rc=$?
    fi

    if (( rc > 1 )); then
        log WARN "dalfox did not complete ($(describe_status "$rc")); see logs/dalfox.err"
        stage_status "xss" "failed" "dalfox $(describe_status "$rc")"
        return 0
    fi

    # Every confirmed PoC becomes a ledger row, so it ranks with the rest.
    if [[ -s "$out" ]]; then
        grep -oE 'https?://[^ ]*' "$out" 2>/dev/null | sort -u | head -n 20 \
            | while IFS= read -r poc; do
                [[ -n "$poc" ]] || continue
                add_finding 85 confirmed dalfox "$(host_of "$poc")" \
                    "XSS confirmed by dalfox" "$poc"
            done
    fi

    log OK "dalfox output: $(count_lines "$out") line(s)"
    stage_status "xss" "ok" "$(count_lines "$targets") URLs tested"
}

module_fuzz() {
    log INFO "Directory discovery (ffuf)"
    local report="$OUTPUT_DIR/fuzz/dirs.txt"
    local bases="$OUTPUT_DIR/fuzz/bases.txt"
    local base raw index=0 rows total=0
    : > "$report"
    : > "$bases"

    if ! check_tool ffuf || [[ ! -f "$WORDLIST" ]]; then
        log WARN "ffuf or the configured wordlist is unavailable."
        stage_status "fuzz" "skipped" "ffuf or wordlist missing"
        return 0
    fi
    if [[ ! -s "$OUTPUT_DIR/alive/urls.txt" ]]; then
        log WARN "No live URLs for directory discovery."
        stage_status "fuzz" "skipped" "no live URLs"
        return 0
    fi

    # One origin per host, apex first, capped by FUZZ_MAX_HOSTS. An origin, not
    # the probed URL: fuzzing from https://host/login would otherwise probe
    # /login/FUZZ instead of the site root.
    unique_origins "$OUTPUT_DIR/alive/urls.txt" "$bases" "$FUZZ_MAX_HOSTS"

    while IFS= read -r base; do
        [[ -n "$base" ]] || continue
        index=$((index + 1))
        raw="$OUTPUT_DIR/fuzz/run_${index}.md"
        : > "$raw"
        printf '\n### %s\n' "${base%/}" >> "$report"
        proxy_args_for ffuf
        run_tool "ffuf" ffuf -u "${base%/}/FUZZ" -w "$WORDLIST" -mc 200,301,302,401,403 \
            -ac -t "$THREADS" -rate "$RATE_LIMIT" -of md -o "$raw" -s \
            "${P_ARGS[@]+"${P_ARGS[@]}"}"
        if [[ -s "$raw" ]]; then
            cat "$raw" >> "$report"
            rows=$(count_table_rows "$raw")
            total=$((total + rows))
        else
            printf '_no matching paths_\n' >> "$report"
        fi
    done < "$bases"

    log OK "Directory discovery: ${total} path(s) across ${index} host(s) — $report"
    stage_status "fuzz" "ok" "${total} paths on ${index} hosts"
}

module_naabu() {
    log INFO "Naabu top-100 TCP port discovery (CDN-aware)"
    local out="$OUTPUT_DIR/ports/naabu.txt"
    local hosts="$OUTPUT_DIR/subs/all.txt"
    : > "$out"

    if ! check_tool naabu || [[ ! -s "$hosts" ]]; then
        log WARN "naabu unavailable or no in-scope DNS names; skipping port discovery."
        stage_status "ports" "skipped" "naabu missing or no hosts"
        return 0
    fi

    local rc=0

    proxy_args_for naabu
    run_tool naabu naabu -list "$hosts" -top-ports 100 -rate "$RATE_LIMIT" -c "$THREADS" \
        -exclude-cdn -retries 1 -timeout 1s -sV -sV-fast -sV-workers "$THREADS" -sV-timeout 3s \
        -silent -o "$out" \
        "${P_ARGS[@]+"${P_ARGS[@]}"}"
    rc=$?

    # The -sV* flags are recent: an older naabu rejects the whole command, which
    # would lose every open port. A plain port scan always works, so fall back.
    if (( rc != 0 && rc != 124 )) && [[ ! -s "$out" ]]; then
        log WARN "naabu with service detection failed ($(describe_status "$rc")); retrying a plain port scan."
        run_tool naabu naabu -list "$hosts" -top-ports 100 -rate "$RATE_LIMIT" -c "$THREADS" \
            -exclude-cdn -retries 1 -timeout 1s -silent -o "$out" \
            "${P_ARGS[@]+"${P_ARGS[@]}"}"
    fi

    if [[ ! -s "$out" ]]; then
        log WARN "naabu produced no output; see logs/naabu.err."
    fi
    log OK "Open endpoints: $(count_lines "$out") — $out"
    stage_status "ports" "ok" "$(count_lines "$out") open endpoint(s)"
}

module_nmap() {
    log INFO "Nmap service scan"
    local out="$OUTPUT_DIR/nmap/scan.txt"
    local ranked="$OUTPUT_DIR/nmap/ranked.tmp"
    local hosts="$OUTPUT_DIR/nmap/hosts.tmp"
    local inscope="$OUTPUT_DIR/nmap/inscope.tmp"
    local targets="$OUTPUT_DIR/nmap/targets.txt"
    : > "$out"
    : > "$ranked"
    : > "$targets"

    # Rank first, filter second: 0 = a host that already answered on a port
    # (naabu), 1 = a live web host (httpx), 2 = the apex. Ranking before
    # scope_filter means its sort -u cannot flatten the priority, and the three
    # sources are merged instead of replaced, so a naabu list of bare IPs can no
    # longer leave nmap with nothing to scan while live hosts exist.
    if [[ -s "$OUTPUT_DIR/ports/naabu.txt" ]]; then
        awk -F: '{ print "0 " $1 }' "$OUTPUT_DIR/ports/naabu.txt" >> "$ranked"
    fi

    if [[ -s "$OUTPUT_DIR/alive/urls.txt" ]]; then
        awk '{
            url = $1
            sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "", url)
            sub(/[\/?#].*$/, "", url)
            sub(/:[0-9]+$/, "", url)
            printf "1 %s\n", url
        }' "$OUTPUT_DIR/alive/urls.txt" >> "$ranked"
    fi

    printf '2 %s\n' "$DOMAIN" >> "$ranked"

    awk '{ print $2 }' "$ranked" | sort -u > "$hosts"
    scope_filter host "$hosts" "$inscope"

    awk '
        NR == FNR { keep[$1] = 1; next }
        ($2 in keep) { print $1, $2 }
    ' "$inscope" "$ranked" \
        | sort -k1,1n -k2,2 -u \
        | awk '!seen[$2]++ { print $2 }' \
        | head -n "$NMAP_MAX_HOSTS" > "$targets"

    rm -f -- "$ranked" "$hosts" "$inscope"

    if ! check_tool nmap; then
        log WARN "nmap not found; skipping."
        stage_status "nmap" "skipped" "nmap missing"
        return 0
    fi
    if [[ ! -s "$targets" ]]; then
        log WARN "No in-scope nmap targets."
        stage_status "nmap" "skipped" "no in-scope targets"
        return 0
    fi

    run_tool nmap nmap -sV -sC -T3 --top-ports 1000 -Pn --max-retries 1 --host-timeout 10m \
        -iL "$targets" -oN "$out"

    log OK "Nmap report: $out ($(count_lines "$targets") host(s))"
    stage_status "nmap" "ok" "$(count_lines "$targets") host(s) scanned"
}


# ------------------------------------------------------- confirmation stages --
#
# Everything below turns a candidate into evidence. Each section records what it
# proved and how, so the report separates confirmed findings from observations.

# Service fingerprints of providers that answer with "this resource is not
# claimed". A host whose CNAME points here is a takeover candidate; the body must
# also carry the fingerprint before it is called confirmed.
declare -A TAKEOVER_FINGERPRINT=(
    ["github.io"]="There isn't a GitHub Pages site here"
    ["herokuapp.com"]="No such app"
    ["s3.amazonaws.com"]="NoSuchBucket"
    ["bitbucket.io"]="Repository not found"
    ["azurewebsites.net"]="Error 404 - Web app not found"
    ["cloudapp.azure.com"]="Error 404 - Web app not found"
    ["surge.sh"]="project not found"
    ["netlify.app"]="Not Found - Request ID"
    ["readme.io"]="Project doesnt exist... yet!"
    ["zendesk.com"]="Oops, this help center no longer exists"
    ["pantheonsite.io"]="The gods are wise, but do not know of the site which you seek"
    ["myshopify.com"]="Sorry, this shop is currently unavailable"
    ["ghost.io"]="The thing you were looking for is no longer here"
    ["tumblr.com"]="Whatever you were looking for doesn't currently exist at this address"
    ["fastly.net"]="Fastly error: unknown domain"
    ["helpscoutdocs.com"]="No settings were found for this company"
    ["statuspage.io"]="This page is not yet available"
)

module_takeover() {
    log INFO "Subdomain takeover check (dangling CNAME + service fingerprint)"
    local dir="$OUTPUT_DIR/takeover"
    local out="$dir/takeover.txt"
    local map="$dir/cnames.tsv"
    local raw="$dir/cnames.jsonl"
    local host target zone fingerprint body count=0 zone_candidate

    mkdir -p -- "$dir"
    : > "$out"
    : > "$map"
    : > "$raw"

    if (( ! MODULE_TAKEOVER )); then
        stage_status "takeover" "skipped" "disabled in settings"
        return 0
    fi
    if ! check_tool dnsx || ! have_jq; then
        log WARN "dnsx or jq missing; skipping the takeover check."
        stage_status "takeover" "skipped" "dnsx or jq missing"
        return 0
    fi
    if [[ ! -s "$OUTPUT_DIR/subs/all.txt" ]]; then
        log WARN "No hosts to check for takeovers."
        stage_status "takeover" "skipped" "no hosts"
        return 0
    fi

    run_tool dnsx --stdout "$raw" dnsx -l "$OUTPUT_DIR/subs/all.txt" -cname -silent -json
    if [[ -s "$raw" ]]; then
        jq -r '
            select(.cname != null) | .host as $h
            | (.cname | if type == "array" then .[] else . end)
            | select(. != null and . != "")
            | "\($h)\t\(.)"
        ' "$raw" 2>/dev/null | sort -u > "$map"
    fi

    if [[ ! -s "$map" ]]; then
        log INFO "No CNAME records to evaluate for takeover."
        stage_status "takeover" "skipped" "no CNAME records"
        return 0
    fi

    while IFS=$'\t' read -r host target; do
        [[ -n "$host" && -n "$target" ]] || continue
        zone=""
        for zone_candidate in "${!TAKEOVER_FINGERPRINT[@]}"; do
            if [[ "$target" == "$zone_candidate" || "$target" == *".${zone_candidate}" ]]; then
                zone="$zone_candidate"
                break
            fi
        done
        [[ -n "$zone" ]] || continue

        count=$((count + 1))
        (( count > TAKEOVER_MAX_HOSTS )) && break

        fingerprint="${TAKEOVER_FINGERPRINT[$zone]}"
        body=$(mktemp "$dir/body.XXXXXX") || continue
        : > "$body"
        fetch_body "https://${host}" "$body" 12 || true
        if ! grep -qaF -- "$fingerprint" "$body"; then
            : > "$body"
            fetch_body "http://${host}" "$body" 12 || true
        fi

        if grep -qaF -- "$fingerprint" "$body"; then
            printf '[HIGH] %s — dangling CNAME to %s (%s): the service reports the resource as unclaimed\n' \
                "$host" "$target" "$zone" >> "$out"
            add_finding 90 confirmed takeover "$host" \
                "Subdomain takeover candidate (${zone})" "${host} -> ${target}"
        else
            printf '[INFO] %s — CNAME to %s (%s); fingerprint not matched, verify by hand\n' \
                "$host" "$target" "$zone" >> "$out"
            add_finding 25 unverified takeover "$host" \
                "CNAME to unclaimed service ${zone}" "${host} -> ${target}"
        fi
        rm -f -- "$body"
    done < "$map"

    log OK "Takeover candidates: $(count_lines "$out") — $out"
    stage_status "takeover" "ok" "$(count_lines "$map") CNAMEs evaluated"
}

module_cors() {
    log INFO "CORS misconfiguration check"
    local out="$OUTPUT_DIR/web/cors.txt"
    local headers probe delay url acao acac host test_origin
    : > "$out"

    if (( ! MODULE_CORS )); then
        stage_status "cors" "skipped" "disabled in settings"
        return 0
    fi
    if ! check_tool curl; then
        log WARN "curl not found; skipping the CORS check."
        stage_status "cors" "skipped" "curl missing"
        return 0
    fi
    if [[ ! -s "$OUTPUT_DIR/alive/urls.txt" ]]; then
        log WARN "No alive URLs for the CORS check."
        stage_status "cors" "skipped" "no live URLs"
        return 0
    fi

    probe="https://recon-probe.invalid"
    delay=$(awk -v rate="$RATE_LIMIT" 'BEGIN { if (rate > 0) printf "%.3f", 1 / rate; else print "0.1" }')
    headers=$(mktemp "$OUTPUT_DIR/web/cors.XXXXXX") || return 0

    while IFS= read -r url; do
        [[ -n "$url" ]] || continue
        host=$(host_of "$url")

        for test_origin in "$probe" "null"; do
            : > "$headers"
            curl_any --silent --show-error --max-time 10 --max-redirs 0 \
                --user-agent "Mozilla/5.0 (compatible; recon-pro/${VERSION})" \
                --header "Origin: ${test_origin}" --dump-header "$headers" \
                --output /dev/null "$url" 2>/dev/null || true

            acao=$(header_value "$headers" "access-control-allow-origin")
            acac=$(header_value "$headers" "access-control-allow-credentials")
            [[ -n "$acao" ]] || continue

            if [[ "$acao" == "$test_origin" && "${acac,,}" == "true" ]]; then
                printf '[HIGH] %s — reflects Origin: %s with credentials\n' "$url" "$test_origin" >> "$out"
                add_finding 85 confirmed cors "$host" \
                    "CORS reflects arbitrary origin with credentials" "${url} (Origin: ${test_origin})"
            elif [[ "$acao" == "$test_origin" ]]; then
                printf '[MEDIUM] %s — reflects Origin: %s without credentials\n' "$url" "$test_origin" >> "$out"
                add_finding 55 likely cors "$host" \
                    "CORS reflects arbitrary origin" "${url} (Origin: ${test_origin})"
            elif [[ "$acao" == "*" && "${acac,,}" == "true" ]]; then
                printf '[LOW] %s — wildcard origin combined with credentials\n' "$url" >> "$out"
                add_finding 30 likely cors "$host" \
                    "CORS wildcard origin with credentials" "$url"
            fi
            sleep "$delay"
        done
    done < <(head -n "$CORS_MAX_URLS" "$OUTPUT_DIR/alive/urls.txt")

    rm -f -- "$headers"
    log OK "CORS notes: $(count_lines "$out")"
    stage_status "cors" "ok" "$(count_lines "$out") note(s)"
}

module_exposures() {
    log INFO "Sensitive file and endpoint checks (content-confirmed)"
    local out="$OUTPUT_DIR/web/exposures.txt"
    local bases="$OUTPUT_DIR/web/exposure_bases.txt"
    local body base path pattern severity title strict url found=0

    : > "$out"
    if (( ! MODULE_EXPOSURES )); then
        stage_status "exposures" "skipped" "disabled in settings"
        return 0
    fi
    if ! check_tool curl; then
        log WARN "curl not found; skipping the exposure checks."
        stage_status "exposures" "skipped" "curl missing"
        return 0
    fi
    if [[ ! -s "$OUTPUT_DIR/alive/urls.txt" ]]; then
        log WARN "No alive URLs for the exposure checks."
        stage_status "exposures" "skipped" "no live URLs"
        return 0
    fi

    unique_origins "$OUTPUT_DIR/alive/urls.txt" "$bases" "$EXPOSURE_MAX_HOSTS"

    while IFS='|' read -r path pattern severity title strict; do
        [[ -n "$path" ]] || continue
        while IFS= read -r base; do
            [[ -n "$base" ]] || continue
            url="${base%/}${path}"
            body=$(mktemp "$OUTPUT_DIR/web/exposure.XXXXXX") || continue
            : > "$body"
            fetch_body "$url" "$body" 10 || true

            if [[ -s "$body" ]]; then
                # A single-page app answers 200 for everything; its HTML shell must
                # never be mistaken for a leaked file.
                if [[ "$strict" == "strict" ]] && grep -qi '<html' "$body"; then
                    rm -f -- "$body"
                    continue
                fi
                if grep -qaE -- "$pattern" "$body"; then
                    printf '[%s] %s — %s\n' "${severity^^}" "$url" "$title" >> "$out"
                    add_finding "$(severity_score "$severity")" confirmed exposure \
                        "$(host_of "$url")" "$title" "$url"
                    found=$((found + 1))
                fi
            fi
            rm -f -- "$body"
        done < "$bases"
    done <<'EXPOSURES'
/.git/config|repositoryformatversion|high|Git repository exposed|strict
/.git/HEAD|^ref: refs/|high|Git repository exposed|strict
/.env|^[A-Za-z_][A-Za-z0-9_]*=.+|critical|Environment file exposed|strict
/.aws/credentials|aws_access_key_id|critical|AWS credentials file exposed|strict
/.svn/entries|[0-9]+$|low|SVN metadata exposed|loose
/.DS_Store|Bud1|low|DS_Store metadata exposed|loose
/server-status|Apache Server Status|medium|Apache server-status exposed|strict
/actuator/env|propertySources|high|Spring Actuator env exposed|strict
/actuator/health|"status"|low|Spring Actuator health exposed|loose
/actuator/beans|"beans"|medium|Spring Actuator beans exposed|strict
/phpinfo.php|PHP Version|medium|phpinfo exposed|strict
/web.config|<configuration|medium|ASP.NET configuration exposed|strict
/robots.txt|^User-agent:|info|robots.txt present|loose
/.well-known/security.txt|^Contact:|info|security.txt present|loose
/sitemap.xml|<urlset|info|sitemap.xml present|loose
/crossdomain.xml|cross-domain-policy|low|crossdomain.xml present|loose
EXPOSURES

    log OK "Sensitive paths confirmed: ${found} — $out"
    stage_status "exposures" "ok" "${found} confirmed path(s)"
}

# Secrets commonly left in front-end bundles. Scores drive the report ordering;
# JWT is deliberately low because bundles legitimately carry public tokens.
JS_SECRET_NAMES=(
    "AWS access key ID"
    "AWS secret access key"
    "Google API key"
    "Google OAuth client secret"
    "Stripe live secret key"
    "Stripe restricted key"
    "GitHub token"
    "Slack token"
    "SendGrid API key"
    "Twilio API key"
    "Private key block"
    "JSON Web Token"
    "GitHub fine-grained token"
    "npm token"
    "PyPI token"
    "Bearer token"
)
JS_SECRET_SCORES=(85 85 80 80 90 85 85 80 80 75 90 40 85 80 80 75)
JS_SECRET_PATTERNS=(
    'A(KIA|IDA|ROA|SIA)[0-9A-Z]{16}'
    '[Aa][Ww][Ss].{0,20}[Ss][Ee][Cc][Rr][Ee][Tt].{0,20}[Kk][Ee][Yy][^A-Za-z0-9]{1,10}[A-Za-z0-9/+=]{40}'
    'AIza[0-9A-Za-z_-]{35}'
    'GOCSPX-[0-9A-Za-z_-]{28}'
    'sk_live_[0-9A-Za-z]{24,}'
    'rk_live_[0-9A-Za-z]{24,}'
    'gh[pousr]_[A-Za-z0-9]{36,}'
    'xox[baprs]-[0-9A-Za-z-]{10,}'
    'SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}'
    'SK[0-9a-f]{32}'
    '-----BEGIN [A-Z ]*PRIVATE KEY-----'
    'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
    'github_pat_[A-Za-z0-9_]{22,}'
    'npm_[A-Za-z0-9]{36}'
    'pypi-[A-Za-z0-9_-]{50,}'
    'Bearer[[:space:]]+[A-Za-z0-9._~+/=-]{20,}'
)

js_is_placeholder() {
    local v="${1,,}"
    case "$v" in
        *example*|*sample*|*dummy*|*placeholder*|*changeme*|*your_*|*_here*|*xxxx*|*000000*|*123456*|*lorem*|*redacted*)
            return 0 ;;
    esac
    [[ "$v" =~ ^[x0]+$ ]] && return 0
    return 1
}

js_mask() {
    local v="$1" len=${#1}
    if (( len <= 12 )); then
        printf '%s...' "${v:0:4}"
    else
        printf '%s...%s' "${v:0:6}" "${v: -4}"
    fi
}

js_scan_secrets() {
    local url="$1" host="$2" file="$3" out="$4"
    local i name score pattern match masked found
    for i in "${!JS_SECRET_NAMES[@]}"; do
        name="${JS_SECRET_NAMES[$i]}"
        score="${JS_SECRET_SCORES[$i]}"
        pattern="${JS_SECRET_PATTERNS[$i]}"
        found=0
        while IFS= read -r match; do
            [[ -n "$match" ]] || continue
            js_is_placeholder "$match" && continue
            masked=$(js_mask "$match")
            printf '[%s] %s — %s: %s\n' "$score" "$url" "$name" "$masked" >> "$out"
            add_finding "$score" likely js "$host" \
                "Secret in JavaScript: ${name}" "${url} (${masked})"
            found=$((found + 1))
            (( found >= 5 )) && break
        done < <(grep -aoE -- "$pattern" "$file" 2>/dev/null | sort -u | head -n 5)
    done
}

# Normalize an HTTP(S) URL to its origin. Userinfo and malformed authorities are
# rejected so a source-map directive cannot smuggle credentials or another host.
url_origin() {
    local url="$1" scheme authority host port="" port_number
    [[ "$url" =~ ^(https?)://([^/?#]+) ]] || return 1
    scheme="${BASH_REMATCH[1],,}"
    authority="${BASH_REMATCH[2],,}"
    [[ "$authority" != *@* ]] || return 1

    if [[ "$authority" =~ ^([^:]+):([0-9]{1,5})$ ]]; then
        host="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
        port_number=$((10#$port))
        (( port_number >= 1 && port_number <= 65535 )) || return 1
    else
        host="$authority"
        [[ "$host" != *:* ]] || return 1
    fi
    [[ "$host" =~ ^[a-z0-9.-]+$ ]] || return 1

    if [[ ( "$scheme" == "https" && "${port:-443}" == "443" ) || \
          ( "$scheme" == "http" && "${port:-80}" == "80" ) ]]; then
        printf '%s://%s' "$scheme" "$host"
    elif [[ -n "$port" ]]; then
        printf '%s://%s:%s' "$scheme" "$host" "$port_number"
    else
        printf '%s://%s' "$scheme" "$host"
    fi
}

# Resolve a sourceMappingURL reference and require an exact scheme/host/port
# match with the JavaScript file. Redirects are separately disabled at fetch time.
js_source_map_url() {
    local script_url="$1" reference="$2" origin scheme authority path directory resolved script_origin resolved_origin
    reference="${reference%%#*}"
    [[ -n "$reference" && ${#reference} -le 2048 ]] || return 1
    case "${reference,,}" in data:*|javascript:*) return 1 ;; esac

    if [[ "${reference,,}" =~ ^https?:// ]]; then
        resolved="$reference"
    elif [[ "$reference" == //* ]]; then
        scheme="${script_url%%://*}"
        resolved="${scheme}:${reference}"
    else
        origin=$(url_origin "$script_url") || return 1
        if [[ "$reference" == /* ]]; then
            resolved="${origin}${reference}"
        else
            authority="${script_url#*://}"
            authority="${authority%%[/?#]*}"
            path="${script_url#*://}"
            path="${path#"$authority"}"
            path="${path%%\?*}"
            path="${path%%\#*}"
            [[ -n "$path" ]] || path="/"
            directory="${path%/*}"
            [[ "$directory" != "$path" ]] || directory="/"
            resolved="${origin}${directory%/}/${reference}"
        fi
    fi

    script_origin=$(url_origin "$script_url") || return 1
    resolved_origin=$(url_origin "$resolved") || return 1
    [[ "$script_origin" == "$resolved_origin" ]] || return 1
    printf '%s' "$resolved"
}

# Mine a bounded number of endpoint-looking strings from a JS or source-content
# file. Scope is checked separately before any discovered URL reaches a scanner.
js_extract_endpoints() {
    local file="$1" base="$2" out="$3" cap="$4" scheme="${2%%://*}"
    (( cap > 0 )) || return 0
    {
        grep -aoE 'https?://[A-Za-z0-9._-]+(:[0-9]+)?/[A-Za-z0-9_./?=&%~-]*' "$file" || true
        grep -aoE '"/[A-Za-z0-9_./?=&%~-]{3,120}"' "$file" | tr -d '"' || true
        grep -aoE "'/[A-Za-z0-9_./?=&%~-]{3,120}'" "$file" | tr -d "'" || true
    } | awk -v base="$base" -v scheme="$scheme" '
        /^https?:\/\// { print; next }
        /^\/\// { print scheme ":" $0; next }
        /^\// { print base $0 }
    ' | sort -u | head -n "$cap" >> "$out" || true
}

module_js() {
    log INFO "JavaScript analysis (endpoints, source maps and secrets)"
    local dir="$OUTPUT_DIR/js"
    local list="$dir/urls.txt"
    local secrets="$dir/secrets.txt"
    local source_maps="$dir/source_maps.txt"
    local raw="$dir/endpoints_raw.txt"
    local scoped="$dir/endpoints_in_scope.txt"
    local map_candidate="$dir/source_map_candidate.tmp"
    local map_scoped="$dir/source_map_scoped.tmp"
    local url file host base script_headers script_status map_ref map_url map_body map_headers map_content map_status map_size source_count
    local count=0 map_count=0 raw_count=0 remaining=0 delay

    mkdir -p -- "$dir"
    : > "$list"
    : > "$secrets"
    : > "$source_maps"
    : > "$raw"
    : > "$scoped"
    : > "$map_candidate"
    : > "$map_scoped"

    if (( ! MODULE_JS )); then
        stage_status "js" "skipped" "disabled in settings"
        return 0
    fi
    if ! check_tool curl; then
        log WARN "curl not found; skipping JavaScript analysis."
        stage_status "js" "skipped" "curl missing"
        return 0
    fi
    if [[ ! -s "$OUTPUT_DIR/urls/all.txt" ]]; then
        log WARN "No URLs to extract JavaScript from; run URL collection first."
        stage_status "js" "skipped" "no URLs"
        return 0
    fi

    awk 'tolower($0) ~ /\.js(\?|$)/' "$OUTPUT_DIR/urls/all.txt" \
        | sort -u | head -n "$JS_MAX_FILES" > "$list"

    if [[ ! -s "$list" ]]; then
        log INFO "No JavaScript files in the collected URLs."
        stage_status "js" "skipped" "no JavaScript files"
        return 0
    fi

    delay=$(awk -v rate="$RATE_LIMIT" 'BEGIN { if (rate > 0) printf "%.3f", 1 / rate; else print "0.1" }')
    while IFS= read -r url; do
        count=$((count + 1))
        file="$dir/file_${count}.js"
        script_headers=$(mktemp "$dir/js_headers.XXXXXX") || continue
        # Stop at 1 MiB + one sentinel byte, and never follow a cross-scope redirect.
        curl_any --silent --show-error --max-time 15 --max-redirs 0 \
            --user-agent "Mozilla/5.0 (compatible; recon-pro/${VERSION})" \
            --dump-header "$script_headers" --output - "$url" 2>/dev/null \
            | head -c 1048577 > "$file" || true
        sleep "$delay"
        script_status=$(awk 'index($1, "HTTP/") == 1 { code = $2 } END { print code }' "$script_headers" 2>/dev/null)
        rm -f -- "$script_headers"
        [[ "$script_status" == "200" && -s "$file" ]] || continue

        # Keep the artefact as evidence but bound every parser and regex pass.
        head -c 1048576 "$file" > "${file}.cut" 2>/dev/null || true
        mv -f -- "${file}.cut" "$file" 2>/dev/null || true

        host=$(host_of "$url")
        base=$(url_origin "$url" 2>/dev/null) || continue

        js_scan_secrets "$url" "$host" "$file" "$secrets"
        raw_count=$(count_lines "$raw")
        remaining=$((JS_MAX_ENDPOINTS - raw_count))
        js_extract_endpoints "$file" "$base" "$raw" "$remaining"

        # Read the last source-map directive only; data URLs and cross-origin
        # references are rejected by js_source_map_url before being stored.
        map_ref=$(grep -aoE 'sourceMappingURL=[^[:space:]]+' "$file" 2>/dev/null \
            | tail -n 1 | sed -E 's/^sourceMappingURL=//; s/\*\/$//')
        if [[ -n "$map_ref" ]]; then
            map_url=$(js_source_map_url "$url" "$map_ref" 2>/dev/null || true)
            [[ -n "$map_url" ]] && printf '%s\n' "$map_url" >> "$map_candidate"
        fi
    done < "$list"

    # Scope-filter a second time before fetching; exact-origin validation above
    # prevents a sibling host or redirect from broadening map access.
    if have_jq; then
        scope_filter url "$map_candidate" "$map_scoped"
    else
        log WARN "jq missing; source-map JSON inspection is skipped."
    fi
    while IFS= read -r map_url; do
        [[ -n "$map_url" ]] || continue
        map_count=$((map_count + 1))
        (( map_count > JS_MAX_SOURCE_MAPS )) && break

        map_body=$(mktemp "$dir/source_map.XXXXXX") || continue
        map_headers=$(mktemp "$dir/source_map_headers.XXXXXX") || {
            rm -f -- "$map_body"
            continue
        }
        curl_any --silent --show-error --max-time 15 --max-redirs 0 \
            --max-filesize 2097152 \
            --user-agent "Mozilla/5.0 (compatible; recon-pro/${VERSION})" \
            --dump-header "$map_headers" --output - "$map_url" 2>/dev/null \
            | head -c 2097153 > "$map_body" || true
        sleep "$delay"
        map_status=$(awk 'index($1, "HTTP/") == 1 { code = $2 } END { print code }' "$map_headers" 2>/dev/null)
        map_size=$(wc -c < "$map_body" 2>/dev/null | tr -d '[:space:]')
        rm -f -- "$map_headers"
        if [[ "$map_status" != "200" ]] || (( ${map_size:-0} > 2097152 )) || \
           ! jq -e 'type == "object" and .version == 3 and (.sources | type == "array")' \
                "$map_body" >/dev/null 2>&1; then
            printf '[SKIP] %s — HTTP %s or invalid/oversized source map\n' \
                "$map_url" "${map_status:-000}" >> "$source_maps"
            rm -f -- "$map_body"
            continue
        fi

        source_count=$(jq '[.sourcesContent[]? | select(type == "string")] | length' \
            "$map_body" 2>/dev/null || printf '0')
        printf '[OK] %s — valid source map; embedded sources: %s\n' \
            "$map_url" "${source_count:-0}" >> "$source_maps"

        if [[ "${source_count:-0}" =~ ^[0-9]+$ ]] && (( source_count > 0 )); then
            map_content=$(mktemp "$dir/source_content.XXXXXX") || {
                rm -f -- "$map_body"
                continue
            }
            jq -r '.sourcesContent[]? | select(type == "string")' "$map_body" \
                > "$map_content" 2>/dev/null || :
            if [[ -s "$map_content" ]]; then
                head -c 2097152 "$map_content" > "${map_content}.cut" 2>/dev/null || true
                mv -f -- "${map_content}.cut" "$map_content" 2>/dev/null || true
                host=$(host_of "$map_url")
                base=$(url_origin "$map_url" 2>/dev/null) || base=""
                js_scan_secrets "$map_url" "$host" "$map_content" "$secrets"
                raw_count=$(count_lines "$raw")
                remaining=$((JS_MAX_ENDPOINTS - raw_count))
                js_extract_endpoints "$map_content" "$base" "$raw" "$remaining"
            fi
            rm -f -- "$map_content"
        fi
        rm -f -- "$map_body"
    done < <(head -n "$JS_MAX_SOURCE_MAPS" "$map_scoped")

    scope_filter url "$raw" "$scoped"

    # New in-scope endpoints join the corpus so the parameter, XSS and directory
    # stages test what the application actually calls.
    if [[ -s "$scoped" ]]; then
        cat "$scoped" >> "$OUTPUT_DIR/urls/all.txt"
        sort -u -o "$OUTPUT_DIR/urls/all.txt" "$OUTPUT_DIR/urls/all.txt"
        build_param_candidates
    fi

    log OK "JavaScript: $(count_lines "$list") file(s), ${map_count} source-map request(s), $(count_lines "$secrets") secret(s), $(count_lines "$scoped") new in-scope endpoint(s)"
    stage_status "js" "ok" "$(count_lines "$secrets") secret(s) / ${map_count} source-map request(s) / $(count_lines "$scoped") endpoint(s)"
}

# Classify parameterised URLs by the vulnerability class their parameter names
# suggest, so the heavy scanners focus where they pay off.
gf_builtin_category() {
    local pattern="$1" out="$2"
    awk -v pat="$pattern" '
        {
            url = $0
            pos = index(url, "?")
            if (pos == 0) next
            query = substr(url, pos + 1)
            n = split(query, pairs, "&")
            for (i = 1; i <= n; i++) {
                eq = index(pairs[i], "=")
                name = (eq > 0) ? substr(pairs[i], 1, eq - 1) : pairs[i]
                name = tolower(name)
                if (name ~ pat) { print url; next }
            }
        }
    ' "$OUTPUT_DIR/urls/params.txt" | sort -u > "$out"
}

# Parameter-name regex used when gf is absent, and also when gf runs but has no
# pattern file for a class (the public Gf-Patterns set, for instance, ships no
# xss pattern).
gf_fallback_pattern() {
    case "$1" in
        ssrf)
            printf '%s' '(^|_)(url|uri|dest|redirect|next|target|site|domain|callback|return|rurl|to|out|view|show|file|document|folder|root|page|open|link|src|source|host|port|fetch|load|proxy|service|feed|data|reference|web|location|u)($|_)'
            ;;
        redirect)
            printf '%s' '(^|_)(url|uri|next|redirect|return|dest|destination|redir|target|rurl|continue|go|forward|link|out|to|ref|referer|callback|fallback|checkout_url|return_to|returnurl|success|failure|cancel)($|_)'
            ;;
        sqli)
            printf '%s' '(^|_)(id|select|report|role|update|query|filter|search|keyword|order|sort|column|field|table|where|view|mode|limit|offset|page|num|number|cat|category|item|product|pid|uid|userid)($|_)'
            ;;
        lfi)
            printf '%s' '(^|_)(file|path|page|include|require|doc|document|folder|root|dir|load|read|template|php_path|style|view|cat|name|download|filepath|filename)($|_)'
            ;;
        xss)
            printf '%s' '(^|_)(q|s|search|query|keyword|message|comment|name|title|desc|description|text|content|body|html|lang|country|city|address|subject|label|tag|error|msg)($|_)'
            ;;
        ssti)
            printf '%s' '(^|_)(template|format|name|message|content|title|text|lang|page|view)($|_)'
            ;;
        idor)
            printf '%s' '(^|_)(id|user|userid|uid|account|number|order|doc|document|key|email|group|profile)($|_)'
            ;;
        rce)
            printf '%s' '(^|_)(upload|execute|exec|cmd|command|shell|daemon|cli|download)($|_)'
            ;;
        *)
            printf '%s' '(^|_)(id|url|file|page)($|_)'
            ;;
    esac
}

module_gf() {
    log INFO "Classifying parameterised URLs by vulnerability class"
    local dir="$OUTPUT_DIR/gf"
    local cat note="" summary=""
    local -a cats=(ssrf sqli lfi redirect xss ssti idor rce)
    mkdir -p -- "$dir"

    if [[ ! -s "$OUTPUT_DIR/urls/params.txt" ]]; then
        log WARN "No parameterised URLs to classify."
        stage_status "gf" "skipped" "no parameterised URLs"
        return 0
    fi

    if check_tool gf; then
        for cat in "${cats[@]}"; do
            gf "$cat" < "$OUTPUT_DIR/urls/params.txt" > "$dir/${cat}.txt" 2>/dev/null || true
            # A pattern file the installed set does not ship leaves the list
            # empty; the built-in classifier fills it instead of the stage
            # silently reporting nothing for that class.
            if [[ ! -s "$dir/${cat}.txt" ]]; then
                gf_builtin_category "$(gf_fallback_pattern "$cat")" "$dir/${cat}.txt"
                note+="${cat}:built-in "
            fi
        done
        log OK "gf patterns applied."
    else
        log WARN "gf not installed; using the built-in parameter classifiers."
        for cat in "${cats[@]}"; do
            gf_builtin_category "$(gf_fallback_pattern "$cat")" "$dir/${cat}.txt"
        done
        note="all built-in"
    fi

    : > "$dir/summary.txt"
    for cat in "${cats[@]}"; do
        [[ -f "$dir/${cat}.txt" ]] || continue
        printf '%-8s %s\n' "$cat" "$(count_lines "$dir/${cat}.txt")" >> "$dir/summary.txt"
        summary+="${cat}:$(count_lines "$dir/${cat}.txt") "
    done

    log OK "Parameter classes — ${summary}"
    stage_status "gf" "ok" "${summary}${note:+[${note}]}"
}

module_open_redirect() {
    log INFO "Open redirect confirmation"
    local out="$OUTPUT_DIR/web/open_redirect.txt"
    local candidates="$OUTPUT_DIR/gf/redirect.txt"
    local probe="https://recon-probe.invalid/"
    local url name rewritten headers location count=0 delay

    : > "$out"

    if (( ! MODULE_OPENREDIR )); then
        stage_status "redirect" "skipped" "disabled in settings"
        return 0
    fi
    if ! check_tool curl; then
        log WARN "curl not found; skipping open redirect checks."
        stage_status "redirect" "skipped" "curl missing"
        return 0
    fi
    if [[ ! -s "$candidates" ]]; then
        log INFO "No redirect candidates to confirm."
        stage_status "redirect" "skipped" "no redirect candidates"
        return 0
    fi

    headers=$(mktemp "$OUTPUT_DIR/web/redir.XXXXXX") || return 0
    delay=$(awk -v rate="$RATE_LIMIT" 'BEGIN { if (rate > 0) printf "%.3f", 1 / rate; else print "0.1" }')

    while IFS= read -r url; do
        [[ -n "$url" ]] || continue
        count=$((count + 1))
        (( count > OPENREDIR_MAX_URLS )) && break

        while IFS= read -r name; do
            [[ -n "$name" ]] || continue
            rewritten=$(replace_param_value "$url" "$name" "$probe")
            : > "$headers"
            fetch_headers "$rewritten" "$headers" 10 || true
            location=$(header_value "$headers" "location")
            if [[ "$location" == *"recon-probe.invalid"* ]]; then
                printf '[HIGH] %s — parameter "%s" redirects to an external host\n' "$url" "$name" >> "$out"
                add_finding 80 confirmed redirect "$(host_of "$url")" \
                    "Open redirect via ${name}" "$url"
                break
            fi
            sleep "$delay"
        done < <(param_names "$url" | head -n 3)
    done < <(head -n "$OPENREDIR_MAX_URLS" "$candidates")

    rm -f -- "$headers"
    log OK "Open redirects confirmed: $(count_lines "$out")"
    stage_status "redirect" "ok" "$(count_lines "$out") confirmed of $(count_lines "$candidates") candidate(s)"
}

module_graphql() {
    log INFO "GraphQL endpoint discovery"
    local out="$OUTPUT_DIR/web/graphql.txt"
    local bases="$OUTPUT_DIR/web/graphql_bases.txt"
    local base path url body
    : > "$out"

    if (( ! MODULE_GRAPHQL )); then
        stage_status "graphql" "skipped" "disabled in settings"
        return 0
    fi
    if ! check_tool curl; then
        log WARN "curl not found; skipping GraphQL discovery."
        stage_status "graphql" "skipped" "curl missing"
        return 0
    fi
    if [[ ! -s "$OUTPUT_DIR/alive/urls.txt" ]]; then
        log WARN "No alive URLs for GraphQL discovery."
        stage_status "graphql" "skipped" "no live URLs"
        return 0
    fi

    unique_origins "$OUTPUT_DIR/alive/urls.txt" "$bases" "$GRAPHQL_MAX_HOSTS"

    while IFS= read -r base; do
        [[ -n "$base" ]] || continue
        for path in /graphql /api/graphql /v1/graphql /query; do
            url="${base%/}${path}"
            body=$(mktemp "$OUTPUT_DIR/web/graphql.XXXXXX") || continue
            curl_any --silent --show-error --max-time 10 -X POST \
                --header 'Content-Type: application/json' \
                --data '{"query":"{__schema{types{name}}}"}' \
                --output "$body" "$url" 2>/dev/null || true

            if grep -qa '__schema' "$body" && grep -qa '"types"' "$body"; then
                printf '[MEDIUM] %s — GraphQL introspection enabled\n' "$url" >> "$out"
                add_finding 55 confirmed graphql "$(host_of "$url")" \
                    "GraphQL introspection enabled" "$url"
                rm -f -- "$body"
                break
            elif grep -qa 'GraphQL' "$body"; then
                printf '[INFO] %s — GraphQL endpoint responded (verify by hand)\n' "$url" >> "$out"
                add_finding 25 unverified graphql "$(host_of "$url")" \
                    "GraphQL endpoint present" "$url"
                rm -f -- "$body"
                break
            fi
            rm -f -- "$body"
        done
    done < "$bases"

    log OK "GraphQL notes: $(count_lines "$out")"
    stage_status "graphql" "ok" "$(count_lines "$out") note(s)"
}


# ------------------------------------------------------------------- report --

count_table_rows() {
    local file="$1" rows
    if [[ ! -s "$file" ]]; then
        printf '0'
        return 0
    fi
    # Result rows only: skip the markdown separator and the column header ffuf
    # writes at the top of every table.
    rows=$(awk '/^\|/ && $0 !~ /---/ && tolower($0) !~ /^\| *url /' "$file" | wc -l | tr -d '[:space:]')
    printf '%s' "${rows:-0}"
}

report_section() {
    local body="$1" title="$2" file="$3" limit="${4:-0}"
    {
        printf '\n'
        printf '%s\n' "$title"
        rule
        if [[ -s "$file" ]]; then
            if (( limit > 0 )); then
                head -n "$limit" "$file"
            else
                cat "$file"
            fi
        else
            printf '_none_\n'
        fi
    } >> "$body"
}

# ------------------------------------------------------- finding knowledge --
#
# Every finding in the report explains itself: what was found, why it matters,
# what the impact is, how to verify it by hand, and what to fix. The knowledge
# base is keyed on tool + title, so nuclei template ids and the built-in stages
# both land on a written explanation instead of a bare data row.

severity_label() {
    case "${1:-0}" in
        9[0-9]|100) printf 'Critical' ;;
        8[0-9])     printf 'High' ;;
        5[5-9]|6[0-9]|7[0-9]) printf 'Medium' ;;
        3[0-9]|4[0-9]|5[0-4]) printf 'Low' ;;
        *)          printf 'Info' ;;
    esac
}

# explain_finding <tool> <title> — sets EXPL_WHAT, EXPL_WHY, EXPL_IMPACT,
# EXPL_CHECK (a safe, manual command or action) and EXPL_FIX.
explain_finding() {
    local tool="${1,,}" t="${2,,}"

    EXPL_WHAT="$2"
    EXPL_WHY="A collection or confirmation stage of this pipeline reported this for the target."
    EXPL_IMPACT="Treat it as unverified until you reproduce it by hand."
    EXPL_CHECK="Re-request the evidence URL yourself and compare the response with what the stage recorded."
    EXPL_FIX="Confirm the behaviour, then document it before reporting it upstream."

    case "${tool}:${t}" in
        takeover:*|nuclei:*takeover*)
            EXPL_WHAT="A subdomain's DNS record points at a service that is no longer provisioned (a dangling CNAME)."
            EXPL_WHY="Somebody else can register that service name at the provider and serve their own content from your subdomain."
            EXPL_IMPACT="Full control of content on a host inside the bug-bounty scope: phishing under the brand, cookie or token theft on sibling domains, and bypass of domain allowlists."
            EXPL_CHECK="dig CNAME <host> +short — if the CNAME points at a provider that answers with its 'not found' or 'no such app' page, the record is claimable."
            EXPL_FIX="Remove the dangling record or re-create the service; keep a CNAME inventory and re-check records after every decommission."
            ;;
        cors:*)
            EXPL_WHAT="The endpoint answers a foreign Origin header, and in the worse case also allows credentials."
            EXPL_WHY="A browser will let any site read the response, which removes the same-origin protection for that endpoint."
            EXPL_IMPACT="Authenticated data exposure: a malicious page can read private API responses for a signed-in user when credentials are allowed."
            EXPL_CHECK="curl -si -H 'Origin: https://recon-probe.invalid' <url> and look for Access-Control-Allow-Origin echoing that origin plus Access-Control-Allow-Credentials: true."
            EXPL_FIX="Validate Origin against an explicit allowlist and never combine a reflected origin with credentials."
            ;;
        exposure:*|exposures:*|nuclei:*exposure*|nuclei:*exposed*)
            EXPL_WHAT="A path that should not be public returned content matching the format it claims to be."
            EXPL_WHY="The file was confirmed by its content, not just its name or status code, so it is very likely a real artefact rather than a soft 404."
            EXPL_IMPACT="Credentials, repository history or configuration secrets can give an attacker a foothold that needs no vulnerability at all."
            EXPL_CHECK="Fetch the exact evidence URL once and inspect the first lines; do not download more than you need to confirm the file."
            EXPL_FIX="Delete the file from the web root, block dotfiles and backups at the edge, and rotate any secret it contained."
            ;;
        redirect:*|nuclei:*redirect*)
            EXPL_WHAT="A parameter controls the destination of a redirect that leaves the host."
            EXPL_WHY="Users and security filters trust the domain in the link, so an off-site destination is a phishing and token-leak primitive."
            EXPL_IMPACT="Credential phishing behind a trusted brand link, and theft of OAuth or reset tokens that pass through the redirect."
            EXPL_CHECK="Replace only the one parameter with https://recon-probe.invalid/ and read the Location header of the response."
            EXPL_FIX="Only allow relative paths or an explicit allowlist of destinations, and never trust the raw parameter."
            ;;
        graphql:*)
            EXPL_WHAT="A GraphQL endpoint answered an introspection query (or at least responded to a GraphQL request)."
            EXPL_WHY="Introspection exposes the full schema, which maps every query, mutation and field to test."
            EXPL_IMPACT="Easier discovery of sensitive mutations and fields; combined with weak authorisation it can expose private objects."
            EXPL_CHECK="Send a single {__schema{types{name}}} query and check whether the schema is returned without authentication."
            EXPL_FIX="Disable introspection in production and enforce object-level authorisation on every field."
            ;;
        dalfox:*|xss:*|nuclei:*xss*)
            EXPL_WHAT="A payload was reflected unescaped into the response by a parameter."
            EXPL_WHY="Reflection is the precondition for cross-site scripting, which runs attacker code in a victim's session."
            EXPL_IMPACT="Session and token theft, actions performed as the victim, and defacement of the affected page."
            EXPL_CHECK="Send the same parameter with a harmless marker such as reconprobe123 and check whether it appears unencoded in the response."
            EXPL_FIX="Encode output for the context it lands in, and add a strict Content-Security-Policy as defence in depth."
            ;;
        js:*|secret:*)
            EXPL_WHAT="A JavaScript file contained something that looks like a credential, key or internal endpoint."
            EXPL_WHY="Secrets shipped to the browser are readable by everyone who loads the page."
            EXPL_IMPACT="Depending on the key: API access, cloud resource access, or a map of internal services that should not be public."
            EXPL_CHECK="Open the reported file, search for the masked value, and confirm whether it is a live credential or a public identifier."
            EXPL_FIX="Move secrets server-side, rotate anything real, and keep internal endpoints out of client bundles."
            ;;
        nuclei:*cve*)
            EXPL_WHAT="A nuclei template for a known CVE matched the target."
            EXPL_WHY="Template matches are evidence the described component and version responded as the template expects, but a template can still match a patched host."
            EXPL_IMPACT="Varies per CVE; read the template's description before judging, and treat remote code execution or authentication bypass as the highest tier."
            EXPL_CHECK="Read the template that matched (nuclei -tl -id <template-id>) and repeat its request once by hand to confirm."
            EXPL_FIX="Patch the component to the fixed version; the template name usually names the affected software."
            ;;
        nuclei:*sql*)
            EXPL_WHAT="A template detected SQL injection behaviour in a parameter."
            EXPL_WHY="Unsanitised input reaching the database query allows reading or changing data the application did not intend."
            EXPL_IMPACT="Data disclosure of the whole database, authentication bypass, and in some setups code execution via the database engine."
            EXPL_CHECK="Reproduce the template's single request manually and compare the response against a benign value for the same parameter."
            EXPL_FIX="Use parameterised queries everywhere, and least-privilege database accounts."
            ;;
        nuclei:*lfi*|nuclei:*traversal*|nuclei:*path-*)
            EXPL_WHAT="A template detected local file inclusion or path traversal."
            EXPL_WHY="A file path parameter is reaching the filesystem without confinement."
            EXPL_IMPACT="Disclosure of files readable by the service: configuration, credentials, and source that then enables deeper attacks."
            EXPL_CHECK="Repeat the single request from the template by hand and check whether the body contains the marker file content it expects."
            EXPL_FIX="Resolve the path, confine it to an allowlisted base directory, and never build paths from raw input."
            ;;
        nuclei:*rce*|nuclei:*command*)
            EXPL_WHAT="A template for remote code or command execution matched."
            EXPL_WHY="This class of finding is the most severe outcome of a web assessment and needs immediate manual confirmation."
            EXPL_IMPACT="Full control of the affected server: data theft, lateral movement, and persistent access."
            EXPL_CHECK="Do not run the template payload blindly. Read the template, repeat only the minimal harmless probe it describes, and stop as soon as the behaviour is proven."
            EXPL_FIX="Patch the component and treat the host as potentially compromised until reviewed."
            ;;
        nuclei:*ssrf*)
            EXPL_WHAT="A template detected that the server fetched a URL supplied by the request."
            EXPL_WHY="Server-side requests can reach internal services that are not exposed to the internet."
            EXPL_IMPACT="Access to cloud metadata credentials and internal-only APIs, sometimes leading to full account takeover."
            EXPL_CHECK="Re-run the template's request once and confirm whether the response contains the data the template expects from the internal target."
            EXPL_FIX="Allowlist outbound destinations, block link-local and metadata ranges, and never fetch raw user input."
            ;;
        nuclei:*default-login*|nuclei:*default*credential*)
            EXPL_WHAT="A login form accepted a well-known default credential pair."
            EXPL_WHY="Default credentials are the fastest path from internet exposure to full administrative access."
            EXPL_IMPACT="Administrative control of the component, and often of the host behind it."
            EXPL_CHECK="Log in once with the reported pair in a browser session, then log out; do not change anything."
            EXPL_FIX="Change the credential immediately, disable the default account, and require strong authentication."
            ;;
        nuclei:*tls*|nuclei:*ssl*|nuclei:*cert*)
            EXPL_WHAT="A TLS or certificate condition was detected on the endpoint."
            EXPL_WHY="Certificate and protocol problems affect every user of the host and are trivially observable by anyone on the path."
            EXPL_IMPACT="Browser warnings that train users to click through, or interception of traffic when the protocol is weak."
            EXPL_CHECK="openssl s_client -connect <host>:443 -servername <host> and read the certificate dates, issuer and chain."
            EXPL_FIX="Renew or replace the certificate, disable obsolete protocol versions, and automate expiry monitoring."
            ;;
        nuclei:*panel*|nuclei:*admin*|nuclei:*login*)
            EXPL_WHAT="An administrative or login interface answered on the target."
            EXPL_WHY="Administrative surfaces widen the attack surface and are frequently exposed by accident."
            EXPL_IMPACT="Depends on authentication and network placement; usually an information leak only, but a serious amplifier if credentials are weak."
            EXPL_CHECK="Open the reported URL in a browser, note whether it requires authentication, and do not attempt to log in."
            EXPL_FIX="Restrict administrative interfaces to trusted networks and enforce strong authentication."
            ;;
        nuclei:*misconfig*|nuclei:*config*|nuclei:*disclosure*)
            EXPL_WHAT="A configuration or information-disclosure issue was detected by a template."
            EXPL_WHY="Misconfiguration usually means data or behaviour that was never meant to be public."
            EXPL_IMPACT="Varies: from version and technology disclosure to exposed debug data or permissive settings."
            EXPL_CHECK="Repeat the template's request once and read the response field it matched."
            EXPL_FIX="Apply the hardening the template describes and confirm the response no longer contains the matched data."
            ;;
        nuclei:*)
            EXPL_WHAT="A nuclei template matched this host."
            EXPL_WHY="A match means the response contained the pattern the template looks for, which is strong evidence but not a substitute for reading the template."
            EXPL_IMPACT="Read the template description before judging severity; it names the component, the condition and the expected evidence."
            EXPL_CHECK="Inspect the template with: nuclei -tl -id <template-id>, then repeat its single request by hand."
            EXPL_FIX="Apply the fix described in the template's description and re-run the same template."
            ;;
        *)
            ;;
    esac
}

# previous_run_dir — newest other workspace for this domain, if any.
previous_run_dir() {
    local parent="${OUTPUT_BASE%/}/${DOMAIN}" current="${OUTPUT_DIR%/}" victim
    [[ -d "$parent" ]] || return 0
    while IFS= read -r victim; do
        [[ -n "$victim" ]] || continue
        [[ "${victim%/}" == "$current" ]] && continue
        printf '%s' "${victim%/}"
        return 0
    done < <(find "$parent" -maxdepth 1 -type d -name 'recon_*' -print 2>/dev/null | sort -r)
    return 0
}

# diff_against_previous <previous-workspace> — writes final/diff_new_hosts.txt,
# final/diff_gone_hosts.txt and final/diff_new_findings.txt, and sets
# DIFF_PREVIOUS, DIFF_NEW_HOSTS, DIFF_GONE_HOSTS, DIFF_NEW_FINDINGS.
diff_against_previous() {
    local prev="${1%/}"
    local cur_hosts="$OUTPUT_DIR/subs/all.txt" prev_hosts="$prev/subs/all.txt"
    local cur_findings="$OUTPUT_DIR/final/findings.tsv" prev_findings="$prev/final/findings.tsv"

    DIFF_PREVIOUS=""
    DIFF_NEW_HOSTS=0
    DIFF_GONE_HOSTS=0
    DIFF_NEW_FINDINGS=0
    : > "$OUTPUT_DIR/final/diff_new_hosts.txt"
    : > "$OUTPUT_DIR/final/diff_gone_hosts.txt"
    : > "$OUTPUT_DIR/final/diff_new_findings.txt"
    [[ -n "$prev" && -d "$prev" ]] || return 0
    DIFF_PREVIOUS="$prev"

    if [[ -s "$prev_hosts" && -s "$cur_hosts" ]]; then
        comm -13 <(sort -u "$prev_hosts") <(sort -u "$cur_hosts") \
            > "$OUTPUT_DIR/final/diff_new_hosts.txt" 2>/dev/null || true
        comm -23 <(sort -u "$prev_hosts") <(sort -u "$cur_hosts") \
            > "$OUTPUT_DIR/final/diff_gone_hosts.txt" 2>/dev/null || true
    fi
    DIFF_NEW_HOSTS=$(count_lines "$OUTPUT_DIR/final/diff_new_hosts.txt")
    DIFF_GONE_HOSTS=$(count_lines "$OUTPUT_DIR/final/diff_gone_hosts.txt")

    if [[ -s "$prev_findings" && -s "$cur_findings" ]]; then
        awk -F'\t' '{ print $3 "\t" $5 "\t" $4 }' "$prev_findings" 2>/dev/null | sort -u \
            > "$OUTPUT_DIR/final/.prev_findings.tmp"
        awk -F'\t' '{ print $3 "\t" $5 "\t" $4 }' "$cur_findings" 2>/dev/null | sort -u \
            > "$OUTPUT_DIR/final/.cur_findings.tmp"
        comm -13 "$OUTPUT_DIR/final/.prev_findings.tmp" "$OUTPUT_DIR/final/.cur_findings.tmp" \
            > "$OUTPUT_DIR/final/diff_new_findings.txt" 2>/dev/null || true
        rm -f -- "$OUTPUT_DIR/final/.prev_findings.tmp" "$OUTPUT_DIR/final/.cur_findings.tmp"
    elif [[ -s "$cur_findings" ]]; then
        awk -F'\t' '{ print $3 "\t" $5 "\t" $4 }' "$cur_findings" 2>/dev/null | sort -u \
            > "$OUTPUT_DIR/final/diff_new_findings.txt"
    fi
    DIFF_NEW_FINDINGS=$(count_lines "$OUTPUT_DIR/final/diff_new_findings.txt")
    return 0
}

# build_markdown_report — the human-readable deliverable: final/report.md.
# Every finding carries a written explanation, evidence and a manual check, so
# the document can be read by a triager who never saw the tool output.
build_markdown_report() {
    local md="$OUTPUT_DIR/final/report.md"
    local ledger="$OUTPUT_DIR/final/findings.tsv"
    local confirmed=0 observations=0 critical=0 high=0 medium=0 low=0 info=0
    local duration="" started="" now="" index=0
    local score conf tool host title evidence

    [[ -s "$OUTPUT_DIR/final/finding_count.txt" ]] && confirmed=$(tr -d '[:space:]' < "$OUTPUT_DIR/final/finding_count.txt")
    [[ -s "$OUTPUT_DIR/final/observation_count.txt" ]] && observations=$(tr -d '[:space:]' < "$OUTPUT_DIR/final/observation_count.txt")
    confirmed=${confirmed:-0}
    observations=${observations:-0}

    if [[ -s "$ledger" ]]; then
        critical=$(awk -F'\t' '$1 >= 90' "$ledger" 2>/dev/null | wc -l | tr -d '[:space:]')
        high=$(awk -F'\t' '$1 >= 80 && $1 < 90' "$ledger" 2>/dev/null | wc -l | tr -d '[:space:]')
        medium=$(awk -F'\t' '$1 >= 55 && $1 < 80' "$ledger" 2>/dev/null | wc -l | tr -d '[:space:]')
        low=$(awk -F'\t' '$1 >= 30 && $1 < 55' "$ledger" 2>/dev/null | wc -l | tr -d '[:space:]')
        info=$(awk -F'\t' '$1 < 30' "$ledger" 2>/dev/null | wc -l | tr -d '[:space:]')
    fi
    critical=${critical:-0}; high=${high:-0}; medium=${medium:-0}; low=${low:-0}; info=${info:-0}

    if [[ -s "$OUTPUT_DIR/logs/start.epoch" ]]; then
        started=$(tr -d '[:space:]' < "$OUTPUT_DIR/logs/start.epoch")
        now=$(date +%s)
        if [[ "$started" =~ ^[0-9]+$ ]] && (( now > started )); then
            duration="$(( (now - started) / 60 ))m $(( (now - started) % 60 ))s"
        fi
    fi

    {
        printf '# Recon Pro report — %s\n\n' "$DOMAIN"
        printf '_Authorized security assessment. Only in-scope assets were touched; out-of-scope hosts were excluded before any request was sent._\n\n'

        printf '## Executive summary\n\n'
        if (( confirmed > 0 )); then
            printf 'The scan recorded **%s confirmed finding(s)** and %s observation(s) against `%s`. ' \
                "$confirmed" "$observations" "$DOMAIN"
        else
            printf 'The scan recorded **no confirmed findings** and %s observation(s) against `%s`. ' \
                "$observations" "$DOMAIN"
        fi
        printf 'Confirmed findings are the ones a second, independent signal proved; observations are candidates and hardening notes that need a human eye.\n\n'

        printf '| Severity | Findings |\n| --- | --- |\n'
        printf '| Critical | %s |\n| High | %s |\n| Medium | %s |\n| Low | %s |\n| Info | %s |\n\n' \
            "$critical" "$high" "$medium" "$low" "$info"

        if (( critical + high > 0 )); then
            printf '> **Start here.** %s critical and %s high-severity finding(s) are listed first in the findings section, each with the impact and the exact manual check.\n\n' \
                "$critical" "$high"
        fi

        printf '## Target information\n\n'
        printf '| Field | Value |\n| --- | --- |\n'
        printf '| Apex domain | `%s` |\n' "$DOMAIN"
        printf '| Workspace | `%s` |\n' "$OUTPUT_DIR"
        printf '| Started (UTC) | %s |\n' \
            "$( [[ -n "$started" && "$started" =~ ^[0-9]+$ ]] && date -u -d "@${started}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || printf '%s' "$(date -u '+%Y-%m-%d %H:%M:%S')" )"
        printf '| Duration | %s |\n' "${duration:-unknown}"
        printf '| Threads / rate | %s threads, %s requests/s |\n' "$THREADS" "$RATE_LIMIT"
        printf '| Proxy | %s |\n' \
            "$( proxies_loaded && printf '%s entr(y), rotation %s' "$((${#PROXIES[@]}))" "$( (( PROXY_ROTATE )) && printf on || printf off )" || printf 'none (direct from the scan host)' )"
        printf '| Tool version | recon_pro %s by %s |\n\n' "$VERSION" "$AUTHOR"

        printf '## Scope verification\n\n'
        printf 'A host is in scope only when it equals `%s` or ends with `.%s`, and never when it matches the exclusion list. ' \
            "$DOMAIN" "$DOMAIN"
        printf 'Every collected host, URL and TLS target passed that filter before a request was sent.\n\n'
        printf '| Item | Value |\n| --- | --- |\n'
        printf '| Exclusions file | `%s` |\n' "$EXCLUDE_FILE"
        printf '| In-scope hosts tested | %s |\n' "$(count_lines "$OUTPUT_DIR/subs/all.txt")"
        printf '| In-scope live URLs | %s |\n\n' "$(count_lines "$OUTPUT_DIR/alive/urls.txt")"
        if [[ -s "$EXCLUDE_FILE" ]] && grep -qvE '^[[:space:]]*(#|$)' "$EXCLUDE_FILE" 2>/dev/null; then
            printf 'Excluded entries applied during this run:\n\n```\n'
            grep -vE '^[[:space:]]*(#|$)' "$EXCLUDE_FILE" | head -n 40
            printf '```\n\n'
        fi

        printf '## Methodology\n\n'
        printf 'Passive collection first (subdomain sources, certificate transparency, certificate SANs), then DNS validation, HTTP probing, and confirmation stages. ' 
        printf 'A finding is written as `confirmed` only when a second signal proved it; everything else stays an observation.\n\n'
        if [[ -s "$OUTPUT_DIR/logs/stages.tsv" ]]; then
            printf '| Stage | Result | Time | Detail |\n| --- | --- | --- | --- |\n'
            awk -F'\t' '{ t = ($4 == "" ? "-" : $4 "s"); printf "| %s | %s | %s | %s |\n", $1, $2, t, $3 }' "$OUTPUT_DIR/logs/stages.tsv"
            printf '\n'
        fi

        printf '## Findings\n\n'
        if [[ -s "$ledger" ]]; then
            while IFS=$'\t' read -r score conf tool host title evidence; do
                [[ -n "$score" ]] || continue
                index=$((index + 1))
                explain_finding "$tool" "$title"
                printf '### F-%02d · %s — %s\n\n' "$index" "$(severity_label "$score")" "$title"
                printf '| Field | Value |\n| --- | --- |\n'
                printf '| Severity | **%s** (score %s) |\n' "$(severity_label "$score")" "$score"
                printf '| Confidence | %s |\n' "$conf"
                printf '| Host | `%s` |\n' "$host"
                printf '| Detected by | %s |\n' "$tool"
                printf '| Evidence | `%s` |\n\n' "${evidence:-n/a}"
                printf '**What it is.** %s\n\n' "$EXPL_WHAT"
                printf '**Why it matters.** %s\n\n' "$EXPL_WHY"
                printf '**Impact.** %s\n\n' "$EXPL_IMPACT"
                printf '**How to verify it yourself.**\n\n```bash\n%s\n```\n\n' "$EXPL_CHECK"
                printf '**Recommended fix.** %s\n\n' "$EXPL_FIX"
                printf '---\n\n'
            done < "$ledger"
        else
            printf '_No confirmed finding. Observations are listed in the appendix and in `final/bugs_found.txt`._\n\n'
        fi

        printf '## Changes detected\n\n'
        if [[ -n "$DIFF_PREVIOUS" ]]; then
            printf 'Compared with the previous run: `%s`\n\n' "$DIFF_PREVIOUS"
            printf '| Change | Count |\n| --- | --- |\n'
            printf '| New hosts | %s |\n| Hosts no longer resolving | %s |\n| New findings | %s |\n\n' \
                "$DIFF_NEW_HOSTS" "$DIFF_GONE_HOSTS" "$DIFF_NEW_FINDINGS"
            if [[ -s "$OUTPUT_DIR/final/diff_new_hosts.txt" ]]; then
                printf 'New hosts:\n\n```\n'; head -n 40 "$OUTPUT_DIR/final/diff_new_hosts.txt"; printf '```\n\n'
            fi
            if [[ -s "$OUTPUT_DIR/final/diff_new_findings.txt" ]]; then
                printf 'New findings:\n\n```\n'; head -n 20 "$OUTPUT_DIR/final/diff_new_findings.txt"; printf '```\n\n'
            fi
        else
            printf '_First recorded run for this domain, so there is nothing to compare with yet._\n\n'
        fi

        printf '## Risk assessment\n\n'
        if (( critical > 0 )); then
            printf '**Overall risk: critical.** A critical finding is present; treat the affected host as compromised until disproved and fix it before anything else.\n\n'
        elif (( high > 0 )); then
            printf '**Overall risk: high.** At least one high-severity finding is confirmed; report it first and fix it in the next maintenance window.\n\n'
        elif (( medium > 0 )); then
            printf '**Overall risk: medium.** Confirmed findings degrade defence in depth but need a specific precondition to be abused.\n\n'
        elif (( low + info > 0 )); then
            printf '**Overall risk: low.** Findings are information leaks or hardening gaps; fix them with the next release.\n\n'
        else
            printf '**Overall risk: informational.** No confirmed weakness was observed in this pass; keep monitoring for changes.\n\n'
        fi
        printf 'The assessment covers what these collectors and confirmation stages can see. A clean result means "nothing proved here", not "nothing exists".\n\n'

        printf '## Recommendations\n\n'
        printf '1. Fix every critical and high finding first; each one lists its manual check and its fix above.\n'
        printf '2. Re-run this pipeline after the fixes to confirm the finding disappeared and compare with this report.\n'
        printf '3. Keep the exclusions file and the program scope current before each run.\n'
        printf '4. Report only what you can reproduce by hand, with the evidence line from the finding.\n'
        if (( $(count_lines "$OUTPUT_DIR/web/header_audit.txt") > 0 )); then
            printf '5. Add the missing security headers listed in the appendix as a low-effort hardening pass.\n'
        fi
        printf '\n'

        printf '## Appendix\n\n'
        printf '| File | Purpose |\n| --- | --- |\n'
        for file in \
            "subs/all.txt:in-scope hosts" \
            "subs/wildcard.txt:wildcard DNS addresses" \
            "alive/urls.txt:live URLs" \
            "urls/params.txt:parameterised candidates" \
            "tls/in_scope_sans.txt:certificate names" \
            "tls/testssl_summary.txt:optional bounded testssl.sh TLS checks" \
            "web/header_audit.txt:header observations" \
            "web/cors.txt:CORS notes" \
            "web/exposures.txt:exposed paths" \
            "web/open_redirect.txt:redirects" \
            "web/graphql.txt:GraphQL notes" \
            "urls/openapi_specs.txt:public API specifications" \
            "urls/openapi_endpoints.txt:GET routes documented by OpenAPI" \
            "js/source_maps.txt:bounded same-origin source-map results" \
            "js/secrets.txt:JavaScript and embedded source-map secrets (masked)" \
            "nuclei/results.txt:nuclei matches" \
            "ports/naabu.txt:open ports" \
            "final/summary.txt:counts" \
            "final/telegram_report.txt:chat summary"; do
            printf '| `%s` | %s |\n' "${file%%:*}" "${file#*:}"
        done
        printf '\n## Metadata\n\n'
        printf '- Tool: recon_pro %s by %s\n' "$VERSION" "$AUTHOR"
        printf '- Generated (UTC): %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S')"
        printf '- Workspace: `%s`\n' "$OUTPUT_DIR"
        printf '- Report: `final/report.md` (this file) and `final/bugs_found.txt` (console report)\n'
        printf '\n_Authorized targets only. Everything here is the result of permitted reconnaissance and confirmation against the scope above._\n'
    } > "$md" 2>/dev/null || return 0

    log OK "Markdown report saved: $md"
    return 0
}

module_report() {
    log INFO "Generating report"
    local report="$OUTPUT_DIR/final/bugs_found.txt"
    local body="$OUTPUT_DIR/final/report_body.tmp"
    local jsonl="$OUTPUT_DIR/nuclei/results.jsonl"
    local nuclei_text="$OUTPUT_DIR/nuclei/results.txt"
    local nuclei_count=0 xss_count=0 tls_count=0 san_count=0 port_count=0 x8_count=0
    local header_count=0 dir_count=0 findings=0 observations=0
    : > "$body"
    finalize_findings
    diff_against_previous "$(previous_run_dir)"

    if [[ -s "$jsonl" ]] && have_jq && jq -s 'length' "$jsonl" >/dev/null 2>&1; then
        nuclei_count=$(jq -s 'length' "$jsonl")
        printf '\nNUCLEI FINDINGS\n%s\n' "$(rule)" >> "$body"
        jq -r '"[" + ((.info.severity // "unknown") | ascii_upcase) + "] " + (."template-id" // "unknown") + " " + (."matched-at" // .host // "")' \
            "$jsonl" >> "$body"
        printf '\n%s\n' 'Nuclei severity summary:' >> "$body"
        jq -rs '
            map((.info.severity // "unknown") | ascii_downcase) as $all
            | ["critical","high","medium","low"][] as $sev
            | "\($sev | ascii_upcase): \([ $all[] | select(. == $sev) ] | length)"
        ' "$jsonl" 2>/dev/null >> "$body"
    else
        nuclei_count=$(grep -Eic '\[(critical|high|medium|low)' "$nuclei_text" 2>/dev/null)
        nuclei_count=${nuclei_count:-0}
        report_section "$body" "NUCLEI FINDINGS" "$nuclei_text"
    fi

    xss_count=$(count_lines "$OUTPUT_DIR/xss/dalfox.txt")
    report_section "$body" "XSS MATCHES (review manually)" "$OUTPUT_DIR/xss/dalfox.txt"

    tls_count=$(count_lines "$OUTPUT_DIR/tls/misconfigurations.txt")
    report_section "$body" "TLS CERTIFICATE CHECKS (validate findings)" "$OUTPUT_DIR/tls/misconfigurations.txt"
    report_section "$body" "OPTIONAL TESTSSL.SH TLS CHECKS (selected checks; review manually)" "$OUTPUT_DIR/tls/testssl_summary.txt"

    san_count=$(count_lines "$OUTPUT_DIR/tls/in_scope_sans.txt")
    report_section "$body" "IN-SCOPE TLS SAN CANDIDATES (review before testing)" "$OUTPUT_DIR/tls/in_scope_sans.txt"

    port_count=$(count_lines "$OUTPUT_DIR/ports/naabu.txt")
    report_section "$body" "OPEN PORTS (validate service and scope)" "$OUTPUT_DIR/ports/naabu.txt"

    x8_count=$(count_lines "$OUTPUT_DIR/x8/parameters.json")
    report_section "$body" "HIDDEN PARAMETER CANDIDATES (review manually)" "$OUTPUT_DIR/x8/parameters.json"

    header_count=$(count_lines "$OUTPUT_DIR/web/header_audit.txt")
    report_section "$body" "SECURITY HEADER OBSERVATIONS (not confirmed vulnerabilities)" "$OUTPUT_DIR/web/header_audit.txt"
    report_section "$body" "TECHNOLOGY FINGERPRINTS (WhatWeb, low-aggression)" "$OUTPUT_DIR/web/whatweb.json" 80

    dir_count=$(count_table_rows "$OUTPUT_DIR/fuzz/dirs.txt")
    report_section "$body" "DIRECTORY DISCOVERY" "$OUTPUT_DIR/fuzz/dirs.txt"

    report_section "$body" "SUBDOMAIN TAKEOVER" "$OUTPUT_DIR/takeover/takeover.txt"
    report_section "$body" "CORS MISCONFIGURATION" "$OUTPUT_DIR/web/cors.txt"
    report_section "$body" "SENSITIVE FILES AND ENDPOINTS (content-confirmed)" "$OUTPUT_DIR/web/exposures.txt"
    report_section "$body" "OPEN REDIRECTS (confirmed)" "$OUTPUT_DIR/web/open_redirect.txt"
    report_section "$body" "GRAPHQL" "$OUTPUT_DIR/web/graphql.txt"
    report_section "$body" "PUBLIC OPENAPI / SWAGGER SPECIFICATIONS" "$OUTPUT_DIR/urls/openapi_specs.txt"
    report_section "$body" "GET ROUTES FROM OPENAPI (first 100)" "$OUTPUT_DIR/urls/openapi_endpoints.txt" 100
    report_section "$body" "SOURCE MAP DISCOVERY (same-origin, bounded)" "$OUTPUT_DIR/js/source_maps.txt"
    report_section "$body" "SECRETS AND TOKENS IN JAVASCRIPT (masked)" "$OUTPUT_DIR/js/secrets.txt"
    report_section "$body" "NEW ENDPOINTS FROM JAVASCRIPT (in scope, first 40)" "$OUTPUT_DIR/js/endpoints_in_scope.txt" 40
    report_section "$body" "PARAMETER CLASSES (gf / built-in)" "$OUTPUT_DIR/gf/summary.txt"

    report_section "$body" "POTENTIAL PARAMETER URLS (first 15)" "$OUTPUT_DIR/urls/params.txt" 15
    report_section "$body" "NMAP SERVICE SCAN (first 60 lines)" "$OUTPUT_DIR/nmap/scan.txt" 60

    local confirmed_count=0
    confirmed_count=$(awk -F'\t' '$2 == "confirmed"' "$OUTPUT_DIR/final/findings.tsv" 2>/dev/null | wc -l | tr -d '[:space:]')
    confirmed_count=${confirmed_count:-0}

    # The ledger already holds one row per nuclei and dalfox finding, so the
    # confirmed total is the honest count; the per-tool numbers stay as detail.
    findings=$confirmed_count
    observations=$((tls_count + san_count + port_count + x8_count + header_count + dir_count))

    local high_count=0 duration="" started="" now=""
    high_count=$(awk -F'\t' '$1 >= 80' "$OUTPUT_DIR/final/findings.tsv" 2>/dev/null | wc -l | tr -d '[:space:]')
    high_count=${high_count:-0}

    if [[ -s "$OUTPUT_DIR/logs/start.epoch" ]]; then
        started=$(tr -d '[:space:]' < "$OUTPUT_DIR/logs/start.epoch")
        now=$(date +%s)
        if [[ "$started" =~ ^[0-9]+$ ]] && (( now > started )); then
            if (( (now - started) >= 60 )); then
                duration="$(( (now - started) / 60 ))m"
            else
                duration="$(( now - started ))s"
            fi
        fi
    fi

    {
        printf '%s\n' '================================================================================'
        printf '     RECON PRO %s                          by %s\n' "$VERSION" "$AUTHOR"
        printf '%s\n\n' '================================================================================'

        printf 'Target        : %s\n' "$DOMAIN"
        if [[ -n "$started" && "$started" =~ ^[0-9]+$ ]]; then
            printf 'Started (UTC) : %s\n' \
                "$(date -u -d "@${started}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || printf '?')"
        fi
        printf 'Finished (UTC): %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S')"
        [[ -n "$duration" ]] && printf 'Duration      : %s\n' "$duration"
        printf 'Workspace     : %s\n' "$OUTPUT_DIR"
        printf 'Threads       : %s  |  Rate: %s/s  |  Stage timeout: %ss\n\n' \
            "$THREADS" "$RATE_LIMIT" "$STAGE_TIMEOUT"

        printf 'CONFIRMED FINDINGS (%s)\n%s\n' "$findings" "$(rule)"
        if [[ -s "$OUTPUT_DIR/final/findings.tsv" ]]; then
            printf '%-5s %-11s %-9s %-26s %s\n' SCORE CONFIDENCE TOOL HOST TITLE
            awk -F'\t' '{
                printf "%-5s %-11s %-9s %-26s %s\n", $1, $2, $3, $4, $5
            }' "$OUTPUT_DIR/final/findings.tsv"
        else
            printf 'none — no confirmed finding from any stage.\n'
        fi
        printf '\n'

        if (( high_count > 0 )); then
            printf 'EVIDENCE (high and critical)\n%s\n' "$(rule)"
            awk -F'\t' '$1 >= 80 {
                level = ($1 >= 90 ? "CRITICAL" : "HIGH")
                printf "%d) [%s %s] %s — %s\n", ++i, level, $1, $5, $4
                printf "   tool: %s | %s\n", $3, $2
                printf "   evidence: %s\n", ($6 == "" ? "n/a" : $6)
            }' "$OUTPUT_DIR/final/findings.tsv"
            printf '\n'
        fi

        printf 'OBSERVATIONS (%s)\n%s\n' "$observations" "$(rule)"
        printf 'TLS %s | ports %s | params(x8) %s | headers %s | dirs %s | SANs %s\n\n' \
            "$tls_count" "$port_count" "$x8_count" "$header_count" "$dir_count" "$san_count"

        if [[ -s "$OUTPUT_DIR/final/scan_info.txt" ]]; then
            printf 'SCAN CONTEXT\n%s\n' "$(rule)"
            cat "$OUTPUT_DIR/final/scan_info.txt"
            printf '\n'
        fi
        if [[ -s "$OUTPUT_DIR/final/tool_inventory.txt" ]]; then
            printf 'TOOL AVAILABILITY\n%s\n' "$(rule)"
            cat "$OUTPUT_DIR/final/tool_inventory.txt"
            printf '\n'
        fi
        if [[ -s "$OUTPUT_DIR/logs/stages.tsv" ]]; then
            printf 'STAGE SUMMARY\n%s\n' "$(rule)"
            awk -F'\t' '{ t = ($4 == "" ? "-" : $4 "s"); printf "%-10s %-9s %-7s %s\n", $1, $2, t, $3 }' "$OUTPUT_DIR/logs/stages.tsv"
            printf '\n'
        fi

        printf 'Empty sections for a stage that ran: read logs/<stage>.err — a wrong tool flag fails silently otherwise.\n\n'
        printf '%s\n' "$(rule)"
        printf 'recon_pro %s by %s · generated %s\n' "$VERSION" "$AUTHOR" "$(date -u '+%Y-%m-%d %H:%M:%S')"
    } > "$report"
    cat "$body" >> "$report"
    rm -f -- "$body"

    printf '%s\n' "$findings" > "$OUTPUT_DIR/final/finding_count.txt"
    printf '%s\n' "$observations" > "$OUTPUT_DIR/final/observation_count.txt"
    {
        printf 'Confirmed findings: %s\n' "$confirmed_count"
        printf '  nuclei %s | dalfox %s\n' "$nuclei_count" "$xss_count"
        printf 'Observations: %s (TLS %s, ports %s, params %s, headers %s, dirs %s, SANs %s)\n' \
            "$observations" "$tls_count" "$port_count" "$x8_count" "$header_count" "$dir_count" "$san_count"
    } > "$OUTPUT_DIR/final/summary.txt"

    build_telegram_report
    build_markdown_report
    publish_reports

    if (( findings > 0 )); then
        log OK "Confirmed findings: $findings (observations: $observations)"
    else
        log WARN "No confirmed findings; $observations observation(s) to review."
    fi
}

# Human-readable Telegram message: whether anything was found, what it was, and
# the detail of every high/critical finding. Written to final/telegram_report.txt
# so the same text can be inspected or re-sent later.
build_telegram_report() {
    local out="${OUTPUT_DIR}/final/telegram_report.txt"
    local ledger="${OUTPUT_DIR}/final/findings.tsv"
    local counts="${OUTPUT_DIR}/final/finding_count.txt"
    local observations_file="${OUTPUT_DIR}/final/observation_count.txt"
    local confirmed=0 observations=0 high=0 duration="" start="" now=""

    [[ -s "$counts" ]] && confirmed=$(tr -d '[:space:]' < "$counts")
    [[ -s "$observations_file" ]] && observations=$(tr -d '[:space:]' < "$observations_file")
    confirmed=${confirmed:-0}
    observations=${observations:-0}

    if [[ -s "${OUTPUT_DIR}/logs/start.epoch" ]]; then
        start=$(tr -d '[:space:]' < "${OUTPUT_DIR}/logs/start.epoch")
        now=$(date +%s)
        if [[ "$start" =~ ^[0-9]+$ ]] && (( now > start )); then
            duration="$(( (now - start) / 60 ))m"
        fi
    fi

    high=0
    [[ -s "$ledger" ]] && high=$(awk -F'\t' '$1 >= 80' "$ledger" | wc -l | tr -d '[:space:]')
    high=${high:-0}

    {
        if (( confirmed > 0 )); then
            printf 'ADA TEMUAN — %s\n' "$DOMAIN"
        else
            printf 'TIDAK ADA TEMUAN — %s\n' "$DOMAIN"
        fi
        printf 'Workspace: %s\n' "$OUTPUT_DIR"
        printf 'Selesai (UTC): %s%s\n\n' \
            "$(date -u '+%Y-%m-%d %H:%M:%S')" "${duration:+ | durasi ${duration}}"
        printf 'Confirmed: %s | Observasi: %s\n' "$confirmed" "$observations"

        if [[ -s "$ledger" ]]; then
            awk -F'\t' '{
                c[$3]++
            } END {
                for (t in c) printf "  %-10s %s\n", t, c[t]
            }' "$ledger"
        fi

        printf '\n'

        if (( high > 0 )); then
            printf 'HIGH / CRITICAL (%s)\n' "$high"
            awk -F'\t' '$1 >= 80 {
                level = ($1 >= 90 ? "CRITICAL" : "HIGH")
                printf "%d) [%s %s] %s — %s\n   tool: %s | %s\n   evidence: %s\n",
                    ++i, level, $1, $5, $4, $3, $2, ($6 == "" ? "n/a" : $6)
            }' "$ledger"
        else
            printf 'Tidak ada temuan HIGH / CRITICAL.\n'
        fi

        printf '\nLaporan lengkap: %s/final/bugs_found.txt\n' "$OUTPUT_DIR"
        printf 'Penjelasan per bug (dampak + cara cek): %s/final/report.md\n' "$OUTPUT_DIR"
        printf 'recon_pro %s by %s\n' "$VERSION" "$AUTHOR"
    } > "$out" 2>/dev/null || return 0

    log INFO "Telegram message saved: $out"
}

notify_summary() {
    [[ -n "$OUTPUT_DIR" ]] || return 0
    local file="$OUTPUT_DIR/final/telegram_report.txt"
    [[ -s "$file" ]] || file="$OUTPUT_DIR/final/summary.txt"
    if [[ ! -s "$file" ]]; then
        log WARN "Telegram summary was not sent: no report file was generated."
        return 0
    fi
    if [[ -z "$TELEGRAM_TOKEN" || -z "$TELEGRAM_CHAT" ]]; then
        log WARN "Telegram report was not sent: configure it with bash recon.sh --telegram."
        return 0
    fi
    notify_long "Recon ${DOMAIN}" "$file"
    if [[ -s "$OUTPUT_DIR/final/bugs_found.txt" ]]; then
        notify_document "Recon ${DOMAIN} — full findings and observations" "$OUTPUT_DIR/final/bugs_found.txt"
    else
        log WARN "Full findings report is missing; only the Telegram summary was sent."
    fi
    if [[ -s "$OUTPUT_DIR/final/report.md" ]]; then
        notify_document "Recon ${DOMAIN} — explained Markdown report" "$OUTPUT_DIR/final/report.md"
    else
        log WARN "Explained Markdown report is missing; only the Telegram summary was sent."
    fi
}

show_report() {
    local report="$OUTPUT_DIR/final/bugs_found.txt"
    local findings=0 observations=0
    local score conf tool host title evidence shown=0
    [[ -s "$OUTPUT_DIR/final/finding_count.txt" ]] && findings=$(tr -d '[:space:]' < "$OUTPUT_DIR/final/finding_count.txt")
    [[ -s "$OUTPUT_DIR/final/observation_count.txt" ]] && observations=$(tr -d '[:space:]' < "$OUTPUT_DIR/final/observation_count.txt")
    findings=${findings:-0}
    observations=${observations:-0}

    printf '\n%b\n' "${GREEN}${BOLD}========== FINAL REPORT ==========${NC}"
    printf '%b\n' "${CYAN}recon_pro ${VERSION} by ${AUTHOR}${NC}"
    if [[ -s "$report" ]]; then
        cat "$report"
    else
        printf '%b\n' "${YELLOW}[-] No report yet; run option 6 after a scan.${NC}"
        return 0
    fi
    printf '\n'
    if (( findings > 0 )); then
        printf '%b\n' "${GREEN}${BOLD}[+] ${findings} confirmed finding(s) in final/findings.tsv${NC}"
    else
        printf '%b\n' "${YELLOW}[-] No confirmed findings; ${observations} observation(s) to review${NC}"
    fi
    # The written explanation is what makes a finding usable: what it is, what it
    # costs, and the exact manual step that proves it.
    if [[ -s "$OUTPUT_DIR/final/findings.tsv" ]]; then
        printf '\n%b\n' "${BOLD}${CYAN}FINDING DETAIL — what / impact / how to check${NC}"
        while IFS=$'\t' read -r score conf tool host title evidence; do
            [[ -n "$score" ]] || continue
            (( shown < 10 )) || { printf '%b\n' "${YELLOW}... more findings in final/report.md${NC}"; break; }
            shown=$((shown + 1))
            explain_finding "$tool" "$title"
            printf '\n%b%d) [%s %s] %s%b — %s\n' "${BOLD}" "$shown" "$(severity_label "$score")" "$score" "$title" "$NC" "$host"
            printf '   evidence  : %s\n' "${evidence:-n/a}"
            printf '   apa itu   : %s\n' "$EXPL_WHAT"
            printf '   dampak    : %s\n' "$EXPL_IMPACT"
            printf '   cara cek  : %s\n' "$EXPL_CHECK"
            printf '   perbaikan : %s\n' "$EXPL_FIX"
        done < "$OUTPUT_DIR/final/findings.tsv"
    fi

    printf '\n%b\n' "${CYAN}Workspace: ${OUTPUT_DIR}${NC}"
    printf '%b\n' "${CYAN}Markdown : ${OUTPUT_DIR}/final/report.md${NC}"
    printf '%b\n' "${RED}${BOLD}[!] Authorized targets only.${NC}"
}

# -------------------------------------------------------------- orchestration --

run_discovery() {
    module_tool_inventory
    check_required_tools
    module_subdomains
    module_alive
}

run_scans() {
    module_tlsx
    module_testssl
    module_san_hosts
    module_headers
    module_whatweb
    module_urls
    module_openapi
    module_js
    module_gf
    module_open_redirect
    module_cors
    module_exposures
    module_graphql
    module_x8
    module_nuclei
    module_xss
    module_fuzz
    module_naabu
    module_takeover
    module_nmap
}

run_full() {
    init_workspace
    run_discovery
    run_scans
    module_report
    show_report
    notify_summary
    prune_old_runs
}

# ------------------------------------------------------------------------ UI --

banner() {
    if [[ -t 1 ]] && check_tool clear; then clear; fi
    printf '%b' "${CYAN}${BOLD}"
    echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
    echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
    echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
    echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
    echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
    echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
    printf '%b\n' "         ${MAGENTA}PRO ${VERSION}${NC} ${CYAN}+ Telegram${NC}   ${YELLOW}by ${AUTHOR}${NC}"
    printf '%b\n\n' "  ${CYAN}Authorized Bug Bounty Pipeline${NC}"
}

usage() {
    cat <<EOF
RECON PRO ${VERSION} — authorized bug bounty workflow (by ${AUTHOR})

Usage: $(basename -- "$0") [options] [domain]

  domain         Apex domain (e.g. example.com); runs the full pipeline
  -y, --yes      Skip the AUTHORIZED confirmation (non-interactive runs)
  --testssl      Opt in to bounded testssl.sh TLS checks (max 10 HTTPS hosts)
  -c, --check    Show installed tools and wordlist paths, then exit
  -h, --help     Show this help

Without a domain the interactive menu is shown.
Everything is written inside ${RECON_HOME}:
  runs/<domain>/recon_<timestamp>/   one scan workspace (latest/ links to it)
  reports/<domain>/                  newest report at a short, stable path
  state/                             config, exclusions, bot state
Set RECON_PRO_HOME (or the OUTPUT_BASE setting) to move it. KEEP_RUNS=n keeps
only the newest n runs per domain; the default 0 keeps every run.

Config:        ${CONFIG_FILE}
Exclusions:    ${EXCLUDE_FILE} (one hostname per line; subdomains included)

Telegram alerts come from (in order of precedence): the config file above,
the TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID environment variables, then the
optional TELEGRAM_*_DEFAULT values near the top of this script.
EOF
}

set_domain_from() {
    local normalized="${1,,}"
    normalized="${normalized%.}"
    if ! valid_domain "$normalized"; then
        log ERROR "Invalid domain: ${1} (use a hostname like example.com, no scheme or wildcard)."
        return 1
    fi
    if [[ "$normalized" != "$DOMAIN" ]]; then OUTPUT_DIR=""; fi
    DOMAIN="$normalized"
    log OK "Target set to ${DOMAIN}"
}

set_domain() {
    local input
    read -r -p "Target domain: " input || return 1
    set_domain_from "$input" || true
}

settings() {
    local value
    banner
    read -r -p "Threads [${THREADS}, 1-200]: " value || value=""
    if [[ -n "$value" ]]; then
        if is_uint_between "$value" 1 200; then THREADS=$((10#$value)); else log WARN "Threads must be 1-200."; fi
    fi
    read -r -p "Rate limit [${RATE_LIMIT}, requests/sec, 1-1000]: " value || value=""
    if [[ -n "$value" ]]; then
        if is_uint_between "$value" 1 1000; then RATE_LIMIT=$((10#$value)); else log WARN "Rate limit must be 1-1000."; fi
    fi
    read -r -p "Per-stage timeout [${STAGE_TIMEOUT}s, 60-86400]: " value || value=""
    if [[ -n "$value" ]]; then
        if is_uint_between "$value" 60 86400; then STAGE_TIMEOUT=$((10#$value)); else log WARN "Timeout must be 60-86400."; fi
    fi
    read -r -p "Extra HTTP ports for httpx [${WEB_PORTS:-none}, e.g. 8080,8443]: " value || value=""
    if [[ -n "$value" ]]; then
        if [[ "$value" =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]]; then WEB_PORTS="$value"; else log WARN "Ports must look like 8080,8443."; fi
    fi
    read -r -p "x8 target cap [${X8_MAX_URLS}]: " value || value=""
    is_uint_between "${value:-}" 1 5000 && X8_MAX_URLS=$((10#$value)) || true
    read -r -p "dalfox target cap [${DALFOX_MAX_URLS}]: " value || value=""
    is_uint_between "${value:-}" 1 10000 && DALFOX_MAX_URLS=$((10#$value)) || true
    read -r -p "ffuf host cap [${FUZZ_MAX_HOSTS}]: " value || value=""
    is_uint_between "${value:-}" 1 500 && FUZZ_MAX_HOSTS=$((10#$value)) || true
    read -r -p "nmap host cap [${NMAP_MAX_HOSTS}]: " value || value=""
    is_uint_between "${value:-}" 1 200 && NMAP_MAX_HOSTS=$((10#$value)) || true
    read -r -p "Directory wordlist [${WORDLIST}]: " value || value=""
    [[ -n "$value" ]] && WORDLIST="$value"
    read -r -p "Parameter wordlist for x8 [${PARAM_WORDLIST}]: " value || value=""
    [[ -n "$value" ]] && PARAM_WORDLIST="$value"
    read -r -p "Runs folder [${OUTPUT_BASE}]: " value || value=""
    if [[ -n "$value" ]]; then
        value=$(resolve_under_root "$value")
        if mkdir -p -- "$value" 2>/dev/null; then
            OUTPUT_BASE="$value"
        else
            log WARN "Cannot create ${value}; keeping ${OUTPUT_BASE}."
        fi
    fi
    read -r -p "Keep newest N runs per domain [${KEEP_RUNS}, 0 = keep every run]: " value || value=""
    is_uint_between "${value:-}" 0 500 && KEEP_RUNS=$((10#$value)) || true
    read -r -p "Proxy list file [${PROXY_FILE}]: " value || value=""
    if [[ -n "$value" ]]; then
        PROXY_FILE=$(resolve_under_root "$value")
        mkdir -p -- "$(dirname -- "$PROXY_FILE")" 2>/dev/null || true
    fi
    PROXY_ROTATE=$(ask_toggle "Rotate proxies per stage and per request" "$PROXY_ROTATE")
    PROXY_REQUIRED=$(ask_toggle "Refuse to scan when no proxy is configured" "$PROXY_REQUIRED")
    read -r -p "Enable nuclei interactsh callbacks (out-of-band checks leave your host) [y/N]: " value || value=""
    if [[ "${value,,}" == "y" ]]; then NUCLEI_INTERACTSH=1; else NUCLEI_INTERACTSH=0; fi

    read -r -s -p "Telegram bot token [Enter keeps current; - disables]: " value || value=""
    echo
    if [[ "$value" == "-" ]]; then
        TELEGRAM_TOKEN=""
    elif [[ -n "$value" ]]; then
        if [[ "$value" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]; then TELEGRAM_TOKEN="$value"; else log WARN "Token format is invalid; keeping the previous token."; fi
    fi
    read -r -p "Telegram chat ID [Enter keeps current; - disables]: " value || value=""
    if [[ "$value" == "-" ]]; then
        TELEGRAM_CHAT=""
    elif [[ -n "$value" ]]; then
        if [[ "$value" =~ ^-?[0-9]+$ ]]; then TELEGRAM_CHAT="$value"; else log WARN "Chat ID must be numeric; keeping the previous value."; fi
    fi
    save_config
}

# Confirmation stages and the nuclei behaviour that decides how much noise the
# report contains. Defaults favour accuracy over volume.
settings_advanced() {
    local value
    banner
    printf '%b\n' "${CYAN}Advanced scans (press Enter to keep the current value)${NC}"

    MODULE_TAKEOVER=$(ask_toggle "Subdomain takeover (dangling CNAME + fingerprint)" "$MODULE_TAKEOVER")
    MODULE_CORS=$(ask_toggle "CORS misconfiguration" "$MODULE_CORS")
    MODULE_EXPOSURES=$(ask_toggle "Sensitive files and endpoints" "$MODULE_EXPOSURES")
    MODULE_JS=$(ask_toggle "JavaScript secrets and endpoint mining" "$MODULE_JS")
    MODULE_GRAPHQL=$(ask_toggle "GraphQL discovery" "$MODULE_GRAPHQL")
    MODULE_OPENREDIR=$(ask_toggle "Open redirect confirmation" "$MODULE_OPENREDIR")
    NUCLEI_AUTOCALIBRATE=$(ask_toggle "nuclei technology-aware template selection (-as)" "$NUCLEI_AUTOCALIBRATE")
    NUCLEI_DAST=$(ask_toggle "nuclei DAST/fuzzing templates (noisy)" "$NUCLEI_DAST")
    NUCLEI_HEADLESS=$(ask_toggle "nuclei headless templates (needs Chrome)" "$NUCLEI_HEADLESS")

    read -r -p "CORS URL cap [${CORS_MAX_URLS}]: " value || value=""
    is_uint_between "${value:-}" 1 2000 && CORS_MAX_URLS=$((10#$value)) || true
    read -r -p "Sensitive-file host cap [${EXPOSURE_MAX_HOSTS}]: " value || value=""
    is_uint_between "${value:-}" 1 200 && EXPOSURE_MAX_HOSTS=$((10#$value)) || true
    read -r -p "JavaScript file cap [${JS_MAX_FILES}]: " value || value=""
    is_uint_between "${value:-}" 1 500 && JS_MAX_FILES=$((10#$value)) || true
    read -r -p "Open redirect URL cap [${OPENREDIR_MAX_URLS}]: " value || value=""
    is_uint_between "${value:-}" 1 2000 && OPENREDIR_MAX_URLS=$((10#$value)) || true
    read -r -p "Takeover host cap [${TAKEOVER_MAX_HOSTS}]: " value || value=""
    is_uint_between "${value:-}" 1 5000 && TAKEOVER_MAX_HOSTS=$((10#$value)) || true

    TELEGRAM_INSTANT=$(ask_toggle "Instant Telegram alert per high/critical finding" "$TELEGRAM_INSTANT")
    read -r -p "Instant alert minimum score [${TELEGRAM_INSTANT_MIN_SCORE}, 10-100]: " value || value=""
    is_uint_between "${value:-}" 10 100 && TELEGRAM_INSTANT_MIN_SCORE=$((10#$value)) || true
    read -r -p "Instant alert cap per run [${TELEGRAM_INSTANT_MAX}, 0 = unlimited]: " value || value=""
    is_uint_between "${value:-}" 0 200 && TELEGRAM_INSTANT_MAX=$((10#$value)) || true

    save_config
}

menu() {
    local choice pause
    while true; do
        banner
        printf '%b\n' "${YELLOW}Target: ${BOLD}${DOMAIN:-not set}${NC}"
        printf '%b\n' "${YELLOW}Threads: ${THREADS} | Rate: ${RATE_LIMIT}/s | Timeout: ${STAGE_TIMEOUT}s | Telegram: $( if [[ -n "$TELEGRAM_TOKEN" && -n "$TELEGRAM_CHAT" ]]; then echo ON; else echo OFF; fi )${NC}"
        printf '%b\n' "${YELLOW}Runs: ${OUTPUT_BASE} | Reports: ${REPORTS_DIR}${NC}"
        printf '%b\n' "${YELLOW}Proxy: $( if proxies_loaded; then printf '%s entr(y), rotation %s' "$((${#PROXIES[@]}))" "$( (( PROXY_ROTATE )) && printf on || printf off)"; else printf 'none (this host IP)'; fi )${NC}"
        printf '%b\n\n' "Scope exclusions: ${EXCLUDE_FILE}"
        echo "1) Set domain"
        echo "2) Full automated pipeline (DNS, TLS, ports, web checks)"
        echo "3) Subdomains + DNS validation + alive probe"
        echo "4) Collect in-scope URLs and parameters"
        echo "5) Run the active scans on the current workspace"
        echo "6) Generate and show report"
        echo "7) Settings"
        echo "8) Advanced scans (confirmation stages and nuclei options)"
        echo "9) Test the proxy list (one request per proxy)"
        echo "0) Exit"
        echo
        read -r -p "Select: " choice || break
        pause=1
        case "$choice" in
            1) pause=0; set_domain || true ;;
            2) require_authorization && run_full ;;
            3) require_authorization && { init_workspace; run_discovery; } ;;
            4) require_workspace && require_authorization && module_urls ;;
            5) require_workspace && require_authorization && run_scans ;;
            6) require_workspace && { module_report; show_report; notify_summary; } ;;
            7) pause=0; settings || true ;;
            8) pause=0; settings_advanced || true ;;
            9) pause=0; test_proxies || true ;;
            0) printf '%b\n' "${MAGENTA}Bye.${NC}"; return 0 ;;
            *) pause=0; log WARN "Choose a listed option."; sleep 1 ;;
        esac
        if (( pause )); then
            read -r -p "Press Enter to return to menu..." _ || true
        fi
    done
}

main() {
    while (( $# )); do
        case "$1" in
            -y|--yes) ASSUME_YES=1 ;;
            --testssl) MODULE_TESTSSL=1 ;;
            -c|--check) CHECK_ONLY=1 ;;
            -h|--help) usage; return 0 ;;
            -*) log ERROR "Unknown option: ${1}"; usage; return 2 ;;
            *)
                if [[ -n "$DOMAIN" ]]; then
                    log ERROR "Only one domain can be given."
                    return 2
                fi
                set_domain_from "$1" || return 2
                ;;
        esac
        shift
    done

    if (( CHECK_ONLY )); then
        check_env
        return 0
    fi

    if (( PROXY_REQUIRED )) && ! proxies_loaded; then
        log ERROR "PROXY_REQUIRED=1 but ${PROXY_FILE} holds no usable proxy. Refusing to scan without one."
        return 1
    fi

    if [[ -n "$DOMAIN" ]]; then
        if require_authorization; then
            run_full
        fi
        return 0
    fi
    menu
}

# Opt-in: sends one harmless request to a neutral endpoint through every proxy in
# the pool, so a dead entry is found before a scan spends its budget on it.
test_proxies() {
    local proxy ip
    if ! proxies_loaded; then
        log WARN "No proxy in ${PROXY_FILE} to test."
        return 0
    fi
    if ! check_tool curl; then
        log ERROR "curl is required to test proxies."
        return 1
    fi

    log INFO "Testing $((${#PROXIES[@]})) proxy entr(y); this makes one request per proxy."
    for proxy in "${PROXIES[@]}"; do
        ip=$(curl --silent --max-time 10 --proxy "$proxy" https://api.ipify.org 2>/dev/null)
        if [[ -n "$ip" ]]; then
            printf '%b[+] %s -> exit IP %s%b\n' "$GREEN" "$proxy" "$ip" "$NC"
        else
            printf '%b[!] %s -> no answer%b\n' "$RED" "$proxy" "$NC"
        fi
    done
    return 0
}

init_project_dirs

load_config
apply_profile
load_proxies || true
# Bot-launched scans always send Telegram alerts back to the approved private
# chat that issued the command, rather than a stale chat ID saved in config.
if [[ "${RECON_PRO_BOT_WORKER:-0}" == "1" ]]; then
    TELEGRAM_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
    TELEGRAM_CHAT="${TELEGRAM_CHAT_ID:-}"
fi
init_scope_exclusions
resolve_wordlists

if [[ -n "$TELEGRAM_BOT_TOKEN_DEFAULT" || -n "$TELEGRAM_CHAT_ID_DEFAULT" ]]; then
    log WARN "Telegram credentials are embedded in this script file; anyone who reads it can use them."
fi

main "$@"
exit $?
