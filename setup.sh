#!/usr/bin/env bash
# =============================================================================
# recon_pro setup — satu perintah untuk memasang semua yang dibutuhkan
# =============================================================================
#
#   bash setup.sh            pasang yang belum ada, lalu cek hasilnya
#   bash setup.sh --minimal  hanya curl, jq, subfinder, dnsx, httpx, nuclei
#   bash setup.sh --no-packages   lewati apt/brew (hanya tool Go)
#   bash setup.sh --no-go    lewati pemasangan tool Go
#   bash setup.sh --with-x8  sekalian pasang x8 lewat cargo (lama)
#
# Aman dijalankan berulang: setiap langkah memeriksa dulu, jadi yang sudah ada
# tidak dipasang ulang. Skrip ini tidak pernah memindai apa pun; langkah
# terakhirnya hanya pemeriksaan offline.
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
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RECON_HOME="${RECON_PRO_HOME:-${HOME:-.}/recon_pro}"
STATE_DIR="${RECON_HOME%/}/state"
CONFIG_FILE="${STATE_DIR}/recon_pro.conf"
LOG_FILE="${STATE_DIR}/setup.log"
GO_VERSION="${RECON_PRO_GO_VERSION:-1.23.4}"

MINIMAL=0
DO_PACKAGES=1
DO_GO=1
DO_X8=0
DO_TEMPLATES=1
DO_PYTHON=1
DO_WEB_AUDIT=0
DO_ARSENAL=0

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'

info() { printf '%b[*]%b %s\n' "$CYAN" "$NC" "$1"; }
ok()   { printf '%b[+]%b %s\n' "$GREEN" "$NC" "$1"; }
warn() { printf '%b[!]%b %s\n' "$YELLOW" "$NC" "$1"; }
fail() { printf '%b[x]%b %s\n' "$RED" "$NC" "$1"; }

usage() {
    cat <<'TXT'
recon_pro setup — pasang semua yang dibutuhkan lalu cek hasilnya

  bash setup.sh                 pasang yang belum ada, lalu cek offline
  bash setup.sh --minimal       hanya curl, jq, subfinder, dnsx, httpx, nuclei
  bash setup.sh --no-packages   lewati apt/brew (hanya tool Go)
  bash setup.sh --no-go         lewati pemasangan tool Go
  bash setup.sh --no-templates  lewati unduh template nuclei
  bash setup.sh --with-x8       sekalian pasang x8 lewat cargo (lama)
  bash setup.sh --with-web-audit pasang sqlmap, wafw00f, whatweb, nikto
  bash setup.sh --web-audit-only hanya pasang paket audit web opsional
  bash setup.sh --with-arsenal   tambah skipfish, gobuster, dirsearch, feroxbuster,
                                 arjun, wpscan, commix (butuh pipx/gem/cargo)
  bash setup.sh --arsenal-only   hanya paket arsenal, tanpa tool pipeline lain
  bash setup.sh --no-python     lewati toolkit Python pasif
  bash setup.sh --python-only   hanya siapkan toolkit Python

Aman dijalankan berulang. Skrip ini tidak memindai apa pun.
TXT
}

while (( $# )); do
    case "$1" in
        --minimal)     MINIMAL=1 ;;
        --no-packages) DO_PACKAGES=0 ;;
        --no-go)       DO_GO=0 ;;
        --with-x8)     DO_X8=1 ;;
        --with-web-audit) DO_WEB_AUDIT=1 ;;
        --with-arsenal)   DO_ARSENAL=1 ;;
        --arsenal-only)
            DO_ARSENAL=1
            DO_PACKAGES=0
            DO_GO=0
            DO_TEMPLATES=0
            DO_X8=0
            DO_PYTHON=0
            ;;
        --web-audit-only)
            DO_WEB_AUDIT=1
            DO_PACKAGES=0
            DO_GO=0
            DO_TEMPLATES=0
            DO_X8=0
            DO_PYTHON=0
            ;;
        --no-templates) DO_TEMPLATES=0 ;;
        --no-python)   DO_PYTHON=0 ;;
        --python-only)
            DO_PYTHON=1
            DO_PACKAGES=0
            DO_GO=0
            DO_TEMPLATES=0
            DO_X8=0
            ;;
        -h|--help)     usage; exit 0 ;;
        *) fail "Opsi tidak dikenal: $1"; usage; exit 2 ;;
    esac
    shift
done

mkdir -p -- "$STATE_DIR" 2>/dev/null || true
: > "$LOG_FILE" 2>/dev/null || true

# --------------------------------------------------------------- os helpers --
OS="other"
DISTRO=""

detect_os() {
    case "$(uname -s)" in
        Darwin) OS="mac" ;;
        Linux)
            OS="linux"
            if [[ -r /etc/os-release ]]; then
                # shellcheck disable=SC1091
                . /etc/os-release
                DISTRO="${ID:-}"
            fi
            ;;
        *) OS="other" ;;
    esac
}

run_root() {
    if (( EUID == 0 )); then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        return 1
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# pipx drops binaries into ~/.local/bin, which is not on PATH for a non-login
# shell. Without this every later check — and the dashboard inventory — would
# report an installed tool as missing.
case ":$PATH:" in
    *":${HOME}/.local/bin:"*) ;;
    *) PATH="${HOME}/.local/bin:${PATH}" ;;
esac
export PATH

# ------------------------------------------------------------- system tools --
install_packages() {
    if (( ! DO_PACKAGES )); then
        warn "Melewati paket sistem (--no-packages)."
        return 0
    fi

    case "$OS" in
        mac)
            if ! have brew; then
                warn "Homebrew tidak ada. Pasang dari https://brew.sh lalu jalankan ulang."
                return 1
            fi
            info "Memasang paket lewat Homebrew (bisa beberapa menit) ..."
            local pkg
            for pkg in curl jq nmap ffuf python3; do
                if have "$pkg"; then continue; fi
                brew install "$pkg" >>"$LOG_FILE" 2>&1 && ok "$pkg" || warn "$pkg gagal dipasang"
            done
            ;;
        linux)
            case "$DISTRO" in
                ubuntu|debian|linuxmint|pop|elementary|kali)
                    info "Memasang paket lewat apt (bisa beberapa menit) ..."
                    run_root env DEBIAN_FRONTEND=noninteractive apt-get update -y >>"$LOG_FILE" 2>&1 || warn "apt-get update gagal"
                    run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
                        curl jq git nmap python3 python3-venv ca-certificates >>"$LOG_FILE" 2>&1 \
                        && ok "curl jq git nmap python3" || warn "sebagian paket apt gagal"
                    # ffuf dan wordlist kecil dipasang terpisah: tidak ada di semua rilis.
                    run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y ffuf >>"$LOG_FILE" 2>&1 || true
                    run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y dirb >>"$LOG_FILE" 2>&1 || true
                    ;;
                fedora|rhel|centos|rocky|almalinux)
                    info "Memasang paket lewat dnf ..."
                    run_root dnf install -y curl jq git nmap python3 >>"$LOG_FILE" 2>&1 \
                        && ok "curl jq git nmap python3" || warn "sebagian paket dnf gagal"
                    ;;
                arch|manjaro|endeavouros)
                    info "Memasang paket lewat pacman ..."
                    run_root pacman -Sy --noconfirm curl jq git nmap ffuf python >>"$LOG_FILE" 2>&1 \
                        && ok "curl jq git nmap ffuf python" || warn "sebagian paket pacman gagal"
                    ;;
                *)
                    warn "Distribusi ${DISTRO:-unknown} belum dikenali; pasang manual: curl jq git nmap ffuf"
                    ;;
            esac
            ;;
        *)
            warn "Sistem operasi tidak dikenali; paket sistem harus dipasang manual."
            ;;
    esac
    return 0
}

# ---------------------------------------------------------------------- go ----
go_version_ok() {
    have go || return 1
    local version major minor
    version=$(go version 2>/dev/null | awk '{print $3}')
    version="${version#go}"
    major="${version%%.*}"
    minor="${version#*.}"
    minor="${minor%%.*}"
    [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
    (( major > 1 || (major == 1 && minor >= 21) ))
}

install_go() {
    if go_version_ok; then
        ok "Go $(go version | awk '{print $3}')"
        return 0
    fi

    if [[ "$OS" != "linux" ]]; then
        warn "Go belum ada atau terlalu tua. Pasang dari https://go.dev/dl lalu jalankan ulang."
        return 1
    fi

    local arch tmp
    case "$(uname -m)" in
        x86_64|amd64)  arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) warn "Arsitektur $(uname -m) tidak didukung untuk unduhan Go otomatis."; return 1 ;;
    esac

    tmp=$(mktemp -d) || return 1
    info "Mengunduh Go ${GO_VERSION} (${arch}) ..."
    if ! curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" -o "$tmp/go.tar.gz" >>"$LOG_FILE" 2>&1; then
        warn "Unduhan Go gagal. Pasang manual dari https://go.dev/dl"
        rm -rf -- "$tmp"
        return 1
    fi
    run_root rm -rf /usr/local/go >>"$LOG_FILE" 2>&1 || true
    if ! run_root tar -C /usr/local -xzf "$tmp/go.tar.gz" >>"$LOG_FILE" 2>&1; then
        warn "Ekstraksi Go gagal (butuh sudo ke /usr/local)."
        rm -rf -- "$tmp"
        return 1
    fi
    rm -rf -- "$tmp"
    export PATH="/usr/local/go/bin:$PATH"
    ok "Go $(go version | awk '{print $3}') terpasang di /usr/local/go"
    return 0
}

ensure_shell_path() {
    local line="$1" rc="${HOME:-.}/.bashrc"
    [[ -f "$rc" ]] || : > "$rc"
    grep -qF -- "$line" "$rc" 2>/dev/null || printf '\n%s\n' "$line" >> "$rc"
}

install_go_tools() {
    if (( ! DO_GO )); then
        warn "Melewati tool Go (--no-go)."
        return 0
    fi
    install_go || { warn "Tool Go dilewati karena Go tidak tersedia."; return 0; }

    local gobin
    gobin="$(go env GOPATH 2>/dev/null)/bin"
    export PATH="/usr/local/go/bin:${gobin}:$PATH"
    ensure_shell_path "export PATH=\"/usr/local/go/bin:${gobin}:\$PATH\""

    local -a modules=()
    if (( MINIMAL )); then
        modules=(
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
            "github.com/projectdiscovery/dnsx/cmd/dnsx"
            "github.com/projectdiscovery/httpx/cmd/httpx"
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
        )
    else
        modules=(
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
            "github.com/projectdiscovery/dnsx/cmd/dnsx"
            "github.com/projectdiscovery/httpx/cmd/httpx"
            "github.com/projectdiscovery/tlsx/cmd/tlsx"
            "github.com/projectdiscovery/naabu/v2/cmd/naabu"
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
            "github.com/projectdiscovery/katana/cmd/katana"
            "github.com/tomnomnom/waybackurls"
            "github.com/tomnomnom/assetfinder"
            "github.com/lc/gau/v2/cmd/gau"
            "github.com/hahwul/dalfox/v2"
            "github.com/ffuf/ffuf/v2"
            "github.com/tomnomnom/gf"
        )
    fi

    local module name
    for module in "${modules[@]}"; do
        name="${module##*/}"
        if have "$name"; then
            ok "$name"
            continue
        fi
        info "Memasang $name ..."
        if go install "${module}@latest" >>"$LOG_FILE" 2>&1; then
            ok "$name"
        else
            warn "$name gagal dipasang (detail: ${LOG_FILE})"
        fi
    done
    return 0
}

install_web_audit_tools() {
    if (( ! DO_WEB_AUDIT )); then
        return 0
    fi

    local pkg
    local -a packages=(sqlmap wafw00f whatweb nikto)
    case "$OS:$DISTRO" in
        linux:ubuntu|linux:debian|linux:linuxmint|linux:pop|linux:elementary|linux:kali)
            info "Memasang tool audit web resmi lewat apt ..."
            run_root env DEBIAN_FRONTEND=noninteractive apt-get update -y >>"$LOG_FILE" 2>&1 || warn "apt-get update gagal; mencoba paket yang tersedia."
            for pkg in "${packages[@]}"; do
                if have "$pkg"; then
                    ok "$pkg"
                elif run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >>"$LOG_FILE" 2>&1; then
                    ok "$pkg"
                else
                    warn "$pkg gagal dipasang; lihat ${LOG_FILE}"
                fi
            done
            ;;
        linux:arch|linux:manjaro|linux:endeavouros)
            for pkg in "${packages[@]}"; do
                if have "$pkg"; then
                    ok "$pkg"
                elif run_root pacman -S --needed --noconfirm "$pkg" >>"$LOG_FILE" 2>&1; then
                    ok "$pkg"
                else
                    warn "$pkg gagal dipasang; lihat ${LOG_FILE}"
                fi
            done
            ;;
        mac:*)
            if ! have brew; then
                warn "Homebrew tidak ada; paket audit web dilewati."
                return 0
            fi
            for pkg in "${packages[@]}"; do
                if have "$pkg"; then
                    ok "$pkg"
                elif brew install "$pkg" >>"$LOG_FILE" 2>&1; then
                    ok "$pkg"
                else
                    warn "$pkg gagal dipasang; lihat ${LOG_FILE}"
                fi
            done
            ;;
        *)
            warn "Paket audit web otomatis belum didukung untuk ${OS}/${DISTRO:-unknown}; pasang dari repositori resmi distro."
            ;;
    esac
    return 0
}

apt_package_present() {
    if command -v dpkg >/dev/null 2>&1; then
        dpkg -s "$1" >/dev/null 2>&1
    else
        return 1
    fi
}

install_apt_package() {
    local pkg="$1"
    if have "$pkg" || apt_package_present "$pkg"; then
        return 0
    fi
    case "$OS:$DISTRO" in
        linux:ubuntu|linux:debian|linux:linuxmint|linux:pop|linux:elementary|linux:kali)
            run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >>"$LOG_FILE" 2>&1
            ;;
        linux:arch|linux:manjaro|linux:endeavouros)
            run_root pacman -S --needed --noconfirm "$pkg" >>"$LOG_FILE" 2>&1
            ;;
        mac:*)
            if have brew; then
                brew install "$pkg" >>"$LOG_FILE" 2>&1
            else
                return 1
            fi
            ;;
        *)
            return 1
            ;;
    esac
}

install_skipfish() {
    if have skipfish; then
        ok "skipfish"
        return 0
    fi
    if install_apt_package skipfish && have skipfish; then
        ok "skipfish"
        return 0
    fi
    # Ubuntu dropped the package; Debian/Kali still ship it. Build the official
    # 2.10b source in that case (needs openssl, zlib, idn and pcre headers).
    if ! have git || ! have make || ! have cc; then
        info "Memasang prasyarat build skipfish ..."
        install_apt_package git || true
        install_apt_package build-essential || true
    fi
    # Header names differ across releases: libidn11-dev on older Debian/Ubuntu,
    # libidn12-dev or the virtual libidn-dev on newer ones, and pcre may only be
    # available as the libpcre3-dev compatibility build. A name that does not
    # exist is skipped silently, so trying all of them is cheap.
    local pkg
    for pkg in pkg-config libssl-dev zlib1g-dev \
               libpcre3-dev libpcre-dev libidn11-dev libidn12-dev libidn-dev; do
        install_apt_package "$pkg" || true
    done
    if ! have git || ! have make; then
        warn "skipfish dilewati: git/make belum tersedia"
        return 0
    fi
    local src="/opt/skipfish" build_log="${STATE_DIR}/skipfish-build.log"
    if [[ ! -d "${src}/.git" ]]; then
        info "Mengunduh sumber skipfish ..."
        if ! run_root git clone --depth 1 https://github.com/spinkham/skipfish "$src" >>"$LOG_FILE" 2>&1; then
            warn "skipfish: unduhan sumber gagal; lihat ${LOG_FILE}"
            return 0
        fi
    fi
    info "Membangun skipfish dari sumber (2.10b) ..."
    if run_root make -C "$src" >"$build_log" 2>&1; then
        run_root ln -sf "${src}/skipfish" /usr/local/bin/skipfish >>"$LOG_FILE" 2>&1 || true
        run_root mkdir -p /usr/local/share/skipfish >>"$LOG_FILE" 2>&1 || true
        if [[ -d "${src}/dictionaries" ]]; then
            run_root ln -sfn "${src}/dictionaries" /usr/local/share/skipfish/dictionaries >>"$LOG_FILE" 2>&1 || true
        fi
        if have skipfish; then
            ok "skipfish (build 2.10b)"
            return 0
        fi
    fi
    warn "skipfish gagal dikompilasi; ringkasan:"
    if grep -qi 'error:' "$build_log" 2>/dev/null; then
        grep -i 'error:' "$build_log" 2>/dev/null | head -n 4 | while IFS= read -r line; do printf '    %s\n' "$line"; done
    else
        tail -n 6 "$build_log" 2>/dev/null | while IFS= read -r line; do printf '    %s\n' "$line"; done
    fi
    printf '    Log build: %s\n' "$build_log"
    return 0
}

install_pipx_tool() {
    local tool="$1"
    if have "$tool"; then
        ok "$tool"
        return 0
    fi
    if ! have pipx; then
        info "Memasang pipx (prasyarat $tool) ..."
        install_apt_package pipx || true
    fi
    if ! have pipx; then
        warn "$tool dilewati: pipx belum tersedia (pasang: sudo apt-get install -y pipx)"
        return 0
    fi
    info "Memasang $tool lewat pipx ..."
    if ! pipx install "$tool" >>"$LOG_FILE" 2>&1; then
        warn "$tool gagal dipasang lewat pipx; lihat ${LOG_FILE}"
        return 0
    fi
    # Link the console script into /usr/local/bin so every shell, cron job and
    # the dashboard see it without sourcing .bashrc first.
    local bin_dir
    bin_dir=$(pipx environment --value PIPX_BIN_DIR 2>/dev/null || true)
    if [[ -z "$bin_dir" ]]; then
        bin_dir="${HOME}/.local/bin"
    fi
    if [[ -x "${bin_dir}/${tool}" ]]; then
        run_root ln -sf "${bin_dir}/${tool}" "/usr/local/bin/${tool}" >>"$LOG_FILE" 2>&1 || true
    fi
    PATH="/usr/local/bin:${bin_dir}:${PATH}"
    export PATH
    if have "$tool"; then
        ok "$tool"
    else
        warn "$tool terpasang di ${bin_dir} tetapi belum ada di PATH"
    fi
    return 0
}

install_cargo_bin() {
    local tool="$1"
    if have "$tool"; then
        ok "$tool"
        return 0
    fi
    if ! have cargo; then
        warn "$tool dilewati: cargo (Rust) belum ada (pasang: sudo apt-get install -y cargo)"
        return 0
    fi
    info "Memasang $tool lewat cargo (bisa lama) ..."
    if cargo install "$tool" >>"$LOG_FILE" 2>&1; then
        ok "$tool"
    else
        warn "$tool gagal dipasang lewat cargo; lihat ${LOG_FILE}"
    fi
    return 0
}

install_feroxbuster() {
    if have feroxbuster; then
        ok "feroxbuster"
        return 0
    fi
    local asset=""
    case "$(uname -m)" in
        x86_64|amd64) asset="x86_64-linux-feroxbuster.zip" ;;
        aarch64|arm64) asset="aarch64-linux-feroxbuster.zip" ;;
    esac
    if [[ -n "$asset" ]] && have curl; then
        info "Mengunduh feroxbuster (binary resmi rilis terbaru) ..."
        if curl -fsSL --retry 2 -o /tmp/feroxbuster.zip \
            "https://github.com/epi052/feroxbuster/releases/latest/download/${asset}" >>"$LOG_FILE" 2>&1; then
            install_apt_package unzip || true
            if have unzip && run_root unzip -o -q /tmp/feroxbuster.zip -d /usr/local/bin >>"$LOG_FILE" 2>&1; then
                run_root chmod 755 /usr/local/bin/feroxbuster >>"$LOG_FILE" 2>&1 || true
                if have feroxbuster; then
                    rm -f /tmp/feroxbuster.zip
                    ok "feroxbuster"
                    return 0
                fi
            fi
        fi
        rm -f /tmp/feroxbuster.zip
        warn "Unduhan feroxbuster tidak berhasil; mencoba cargo."
    fi
    install_cargo_bin feroxbuster
    return 0
}

install_wpscan() {
    if have wpscan; then
        ok "wpscan"
        return 0
    fi
    if ! have gem; then
        info "Memasang Ruby (prasyarat wpscan) ..."
        install_apt_package ruby || true
        install_apt_package ruby-dev || true
    fi
    if ! have gem; then
        warn "wpscan dilewati: Ruby gem belum tersedia (pasang: sudo apt-get install -y ruby ruby-dev build-essential)"
        return 0
    fi
    # wpscan needs to compile native extensions (nokogiri, ethon, ffi); without
    # these headers `gem install` fails on a minimal VPS.
    local dep gem_log="${STATE_DIR}/wpscan-gem.log"
    for dep in build-essential pkg-config libcurl4-openssl-dev libxml2-dev libxslt1-dev zlib1g-dev libsqlite3-dev libffi-dev libyaml-dev; do
        install_apt_package "$dep" || true
    done
    # nokogiri ships a pre-compiled gem per platform; installing it first keeps
    # a 1-2 GB VPS from being killed while it compiles its C extensions.
    local nokogiri_platform=""
    case "$(uname -m)" in
        x86_64|amd64) nokogiri_platform="x86_64-linux" ;;
        aarch64|arm64) nokogiri_platform="arm64-linux" ;;
    esac
    if [[ -n "$nokogiri_platform" ]]; then
        info "Memasang nokogiri pre-compiled (tanpa kompilasi) ..."
        run_root gem install --no-document --platform "$nokogiri_platform" nokogiri >>"$gem_log" 2>&1 \
            || warn "nokogiri pre-compiled tidak tersedia; gem wpscan akan mencoba kompilasi sendiri"
    fi
    info "Memasang wpscan lewat gem (Ruby, bisa beberapa menit) ..."
    if run_root gem install --no-document wpscan >"$gem_log" 2>&1 && have wpscan; then
        ok "wpscan"
        return 0
    fi
    warn "wpscan gagal dipasang; ringkasan error:"
    tail -n 6 "$gem_log" 2>/dev/null | while IFS= read -r line; do printf '    %s\n' "$line"; done
    printf '    Log lengkap: %s\n' "$gem_log"
    return 0
}

install_commix() {
    if have commix; then
        ok "commix"
        return 0
    fi
    if ! have git; then
        info "Memasang git (prasyarat commix) ..."
        install_apt_package git || true
    fi
    if ! have git; then
        warn "commix dilewati: git belum tersedia"
        return 0
    fi
    if [[ -d /opt/commix/.git ]]; then
        run_root ln -sf /opt/commix/commix.py /usr/local/bin/commix >>"$LOG_FILE" 2>&1 || true
        if have commix; then
            ok "commix"
            return 0
        fi
    fi
    info "Memasang commix dari repositori resminya ..."
    if run_root git clone --depth 1 https://github.com/commixproject/commix /opt/commix >>"$LOG_FILE" 2>&1; then
        run_root ln -sf /opt/commix/commix.py /usr/local/bin/commix >>"$LOG_FILE" 2>&1 || true
        if have commix; then
            ok "commix"
        else
            warn "commix terpasang tetapi tidak ada di PATH"
        fi
    else
        warn "commix gagal dipasang; lihat ${LOG_FILE}"
    fi
    return 0
}

install_arsenal_tools() {
    if (( ! DO_ARSENAL )); then
        return 0
    fi

    local pkg bin ready=0 missing=""
    local -a apt_packages=(gobuster dirsearch)
    local -a arsenal_bins=(skipfish gobuster dirsearch feroxbuster arjun wpscan commix)
    case "$OS:$DISTRO" in
        linux:ubuntu|linux:debian|linux:linuxmint|linux:pop|linux:elementary|linux:kali)
            info "Memasang paket arsenal lewat apt (yang tersedia) ..."
            run_root env DEBIAN_FRONTEND=noninteractive apt-get update -y >>"$LOG_FILE" 2>&1 || warn "apt-get update gagal; mencoba paket yang tersedia."
            for pkg in "${apt_packages[@]}"; do
                if have "$pkg"; then
                    ok "$pkg"
                elif run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >>"$LOG_FILE" 2>&1; then
                    ok "$pkg"
                else
                    warn "$pkg tidak tersedia lewat apt (opsional, dilewati)"
                fi
            done
            ;;
        *)
            warn "Paket arsenal lewat apt hanya untuk Debian/Ubuntu; sisanya dicoba lewat pipx/gem/cargo."
            ;;
    esac

    install_skipfish
    install_pipx_tool arjun
    install_pipx_tool dirsearch
    install_wpscan
    install_feroxbuster
    install_commix

    for bin in "${arsenal_bins[@]}"; do
        if have "$bin"; then
            ready=$((ready + 1))
        else
            missing="${missing} ${bin}"
        fi
    done
    info "Arsenal terpasang: ${ready}/${#arsenal_bins[@]}"
    if [[ -n "$missing" ]]; then
        warn "Belum terpasang:${missing} — detail pemasangan ada di ${LOG_FILE}"
    fi
    return 0
}

install_optional_extras() {
    install_web_audit_tools
    install_arsenal_tools
    if (( ! DO_X8 )); then
        return 0
    fi
    if ! have cargo; then
        warn "cargo (Rust) tidak ada; x8 dilewati."
        return 0
    fi
    if have x8; then
        ok "x8"
        return 0
    fi
    info "Memasang x8 lewat cargo (bisa 5-10 menit) ..."
    cargo install x8 >>"$LOG_FILE" 2>&1 && ok "x8" || warn "x8 gagal dipasang"
    return 0
}

update_nuclei_templates() {
    if (( ! DO_TEMPLATES )); then
        warn "Melewati unduh template nuclei (--no-templates)."
        return 0
    fi
    if ! have nuclei; then
        return 0
    fi
    info "Memperbarui template nuclei (unduhan besar, sekali saja) ..."
    if nuclei -update-templates >>"$LOG_FILE" 2>&1; then
        ok "template nuclei siap"
    else
        warn "update template gagal; nuclei masih bisa jalan dengan template yang ada"
    fi
    return 0
}

# --------------------------------------------------------------- python env --
setup_python() {
    if (( ! DO_PYTHON )); then
        warn "Melewati toolkit Python (--no-python)."
        return 0
    fi

    local toolkit="${SCRIPT_DIR}/bugbounty-toolkit"

    if [[ ! -d "$toolkit" ]]; then
        warn "Folder bugbounty-toolkit tidak ada; toolkit Python dilewati."
        return 0
    fi
    if ! have python3; then
        warn "python3 tidak ada; toolkit Python dilewati."
        return 0
    fi
    if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
        warn "Python 3.9+ dibutuhkan; versi terpasang: $(python3 -V 2>&1)"
        return 0
    fi

    if [[ ! -x "$toolkit/.venv/bin/python" ]]; then
        info "Membuat virtualenv toolkit Python ..."
        if ! python3 -m venv "$toolkit/.venv" >>"$LOG_FILE" 2>&1; then
            warn "Gagal membuat virtualenv (paket python3-venv terpasang?). Toolkit dilewati."
            return 0
        fi
    fi

    info "Memasang dependensi toolkit (requests, PyYAML, dnspython) ..."
    "$toolkit/.venv/bin/python" -m pip install --quiet --upgrade pip >>"$LOG_FILE" 2>&1 || true
    if ! "$toolkit/.venv/bin/python" -m pip install --quiet -r "$toolkit/requirements.txt" >>"$LOG_FILE" 2>&1; then
        warn "pip install gagal; lihat ${LOG_FILE}"
        return 0
    fi
    ok "dependensi toolkit Python"

    if "$toolkit/.venv/bin/python" -c "import requests, yaml, dns.resolver" >>"$LOG_FILE" 2>&1; then
        ok "toolkit Python siap: ${toolkit}/.venv"
    else
        warn "import dependensi toolkit gagal; lihat ${LOG_FILE}"
    fi
    return 0
}

# ---------------------------------------------------------------- wordlists --
find_wordlist() {
    local candidate
    for candidate in \
        /usr/share/wordlists/dirb/common.txt \
        /usr/share/dirb/wordlists/common.txt \
        /usr/share/seclists/Discovery/Web-Content/common.txt \
        /opt/seclists/Discovery/Web-Content/common.txt \
        /usr/local/share/seclists/Discovery/Web-Content/common.txt
    do
        if [[ -f "$candidate" ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

find_param_wordlist() {
    local candidate
    for candidate in \
        /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
        /opt/seclists/Discovery/Web-Content/burp-parameter-names.txt \
        /usr/local/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
    do
        if [[ -f "$candidate" ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

write_builtin_wordlist() {
    local target="$1"
    mkdir -p -- "$(dirname -- "$target")" 2>/dev/null || true
    cat > "$target" <<'WORDS'
admin
administrator
api
api/v1
api/v2
app
assets
auth
backup
backups
blog
cache
cgi-bin
config
configs
console
css
dashboard
data
db
debug
dev
docs
download
downloads
files
fonts
graphql
health
help
home
img
images
include
includes
index
internal
js
json
logs
login
logout
manage
management
media
metrics
old
panel
private
public
register
reset
robots.txt
sitemap.xml
signin
signup
static
status
storage
swagger
system
temp
test
tmp
upload
uploads
user
users
vendor
web
wp-admin
wp-content
wp-includes
wp-login.php
.git/HEAD
.git/config
.env
env
.DS_Store
.svn/entries
.htaccess
server-status
actuator
actuator/health
actuator/env
graphiql
phpinfo.php
info.php
readme.md
README.md
CHANGELOG.md
package.json
composer.json
Dockerfile
docker-compose.yml
WORDS
    chmod 600 "$target" 2>/dev/null || true
    printf '%s' "$target"
}

write_builtin_param_wordlist() {
    local target="$1"
    mkdir -p -- "$(dirname -- "$target")" 2>/dev/null || true
    cat > "$target" <<'PARAMS'
id
uid
user
userid
user_id
username
name
email
account
account_id
pass
password
passwd
pwd
token
access_token
refresh_token
auth
key
apikey
api_key
secret
session
sessionid
code
otp
redirect
redirect_uri
redirect_url
next
return
returnUrl
url
uri
link
callback
file
filename
filepath
path
dir
folder
page
p
pg
page_id
view
template
theme
lang
language
locale
q
query
search
s
term
keyword
filter
sort
order
orderby
limit
offset
start
count
size
num
number
type
mode
action
cmd
command
exec
run
process
debug
test
admin
role
status
state
format
output
callback_url
target
host
domain
ip
port
PARAMS
    chmod 600 "$target" 2>/dev/null || true
    printf '%s' "$target"
}

# ------------------------------------------------------------------- config --
config_has_key() {
    local key="$1"
    [[ -f "$CONFIG_FILE" ]] || return 1
    awk -F'|' -v k="$key" '$1==k {found=1} END {exit !found}' "$CONFIG_FILE"
}

set_config_default() {
    local key="$1" value="$2"
    [[ -f "$CONFIG_FILE" ]] || : > "$CONFIG_FILE"
    config_has_key "$key" && return 0
    printf '%s|%s\n' "$key" "$value" >> "$CONFIG_FILE"
    return 0
}

write_config() {
    local wordlist="$1" param_wordlist="$2"

    if [[ -f "$CONFIG_FILE" ]]; then
        set_config_default WORDLIST "$wordlist"
        set_config_default PARAM_WORDLIST "$param_wordlist"
        set_config_default PROXY_FILE "state/proxies.txt"
        set_config_default PROXY_ROTATE 1
        set_config_default PROXY_REQUIRED 0
        chmod 600 "$CONFIG_FILE" 2>/dev/null || true
        info "Config sudah ada, hanya melengkapi nilai yang kosong: ${CONFIG_FILE}"
        return 0
    fi

    {
        printf 'THREADS|20\n'
        printf 'RATE_LIMIT|50\n'
        printf 'STAGE_TIMEOUT|1800\n'
        printf 'WEB_PORTS|\n'
        printf 'OUTPUT_BASE|runs\n'
        printf 'WORDLIST|%s\n' "$wordlist"
        printf 'PARAM_WORDLIST|%s\n' "$param_wordlist"
        printf 'X8_MAX_URLS|40\n'
        printf 'DALFOX_MAX_URLS|150\n'
        printf 'FUZZ_MAX_HOSTS|3\n'
        printf 'NMAP_MAX_HOSTS|10\n'
        printf 'NUCLEI_INTERACTSH|0\n'
        printf 'MODULE_CORS|1\n'
        printf 'MODULE_EXPOSURES|1\n'
        printf 'MODULE_JS|1\n'
        printf 'MODULE_TAKEOVER|1\n'
        printf 'MODULE_GRAPHQL|1\n'
        printf 'MODULE_OPENREDIR|1\n'
        printf 'NUCLEI_AUTOCALIBRATE|1\n'
        printf 'NUCLEI_DAST|0\n'
        printf 'NUCLEI_HEADLESS|0\n'
        printf 'CORS_MAX_URLS|50\n'
        printf 'EXPOSURE_MAX_HOSTS|10\n'
        printf 'JS_MAX_FILES|40\n'
        printf 'GRAPHQL_MAX_HOSTS|10\n'
        printf 'OPENREDIR_MAX_URLS|40\n'
        printf 'TAKEOVER_MAX_HOSTS|200\n'
        printf 'KEEP_RUNS|0\n'
        printf 'PROXY_FILE|state/proxies.txt\n'
        printf 'PROXY_ROTATE|1\n'
        printf 'PROXY_REQUIRED|0\n'
        printf 'TELEGRAM_INSTANT|1\n'
        printf 'TELEGRAM_INSTANT_MIN_SCORE|90\n'
        printf 'TELEGRAM_INSTANT_MAX|10\n'
        printf 'TELEGRAM_TOKEN|\n'
        printf 'TELEGRAM_CHAT|\n'
        printf 'TELEGRAM_ALLOWED_USERS|\n'
    } > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE" 2>/dev/null || true
    ok "Config awal dibuat: ${CONFIG_FILE}"
    return 0
}

# Cheap guard against a broken checkout: a syntax error in any script is caught
# here instead of at the first run.
check_syntax() {
    local rc=0 script err

    for script in recon_pro.sh recon.sh setup.sh web_ui/start.sh; do
        [[ -f "$SCRIPT_DIR/$script" ]] || continue
        if ! bash -n "$SCRIPT_DIR/$script" 2>/tmp/.recon_syn; then
            err=$(head -n 2 /tmp/.recon_syn | tr '\n' ' ')
            warn "$script: $err"
            rc=1
        fi
    done

    if have python3; then
        for script in recon_pro_bot.py web_ui/server.py; do
            [[ -f "$SCRIPT_DIR/$script" ]] || continue
            if ! python3 -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' \
                "$SCRIPT_DIR/$script" 2>/tmp/.recon_syn; then
                err=$(tail -n 2 /tmp/.recon_syn | tr '\n' ' ')
                warn "$script: $err"
                rc=1
            fi
        done
    fi

    rm -f /tmp/.recon_syn
    (( rc == 0 )) && ok "sintaks skrip ok"
    return "$rc"
}

# --------------------------------------------------------------------- main --
detect_os
info "Sistem: ${OS}${DISTRO:+ (${DISTRO})}  ·  folder: ${RECON_HOME}"

install_packages
install_go_tools
install_optional_extras
update_nuclei_templates
setup_python

WORDLIST_PATH=$(find_wordlist || true)
if [[ -n "$WORDLIST_PATH" ]]; then
    ok "Wordlist direktori: ${WORDLIST_PATH}"
else
    WORDLIST_PATH=$(write_builtin_wordlist "${STATE_DIR}/wordlist.txt")
    ok "Wordlist bawaan dibuat: ${WORDLIST_PATH}"
fi

PARAM_PATH=$(find_param_wordlist || true)
if [[ -n "$PARAM_PATH" ]]; then
    ok "Wordlist parameter: ${PARAM_PATH}"
else
    PARAM_PATH=$(write_builtin_param_wordlist "${STATE_DIR}/params.txt")
    ok "Wordlist parameter bawaan dibuat: ${PARAM_PATH}"
fi

write_config "$WORDLIST_PATH" "$PARAM_PATH"

info "Pemeriksaan offline (tanpa network) ..."
BASH_BIN="${BASH:-bash}"
check_syntax || warn "Ada file yang belum benar; perbaiki sebelum menjalankan scan."
if ! "$BASH_BIN" "$SCRIPT_DIR/recon_pro.sh" -c; then
    warn "Pemeriksaan melaporkan masalah; baca output di atas."
fi

printf '\n%bSelesai.%b Berikutnya:\n' "$GREEN" "$NC"
printf '  bash recon.sh example.com            scan penuh + toolkit pasif\n'
printf '  bash recon.sh example.com -y         tanpa konfirmasi (otomasi)\n'
printf '  bash recon.sh --passive example.com  hanya toolkit pasif (OSINT)\n'
printf '  bash recon.sh --report example.com   detail bug yang ketemu\n'
printf '  bash recon.sh --log example.com      log dan error per stage\n'
printf '  bash recon.sh --tools                tool + versi\n'
printf '  bash recon.sh --web                  jalankan dashboard lokal (token otomatis)\n'
printf '\nLaporan aktif : %s/reports/<domain>/latest-report.md\n' "$RECON_HOME"
printf 'Laporan pasif : %s/bugbounty-toolkit/reports/\n' "$SCRIPT_DIR"
printf 'Detail pemasangan: %s\n' "$LOG_FILE"
