#!/usr/bin/env python3
"""Local Recon Pro dashboard for an authorized VPS or Termux host.

The standard-library server binds to loopback by default. Set RECON_WEB_TOKEN to
an operator-generated secret before starting it. Scan requests are validated
against the local scope and exclusion files. An optional command runner accepts
Bash commands only with RECON_WEB_ENABLE_SHELL=1 and a loopback bind; it runs
with the dashboard account's privileges and is not an interactive TTY.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RECON_HOME = Path(os.path.expanduser(os.environ.get("RECON_PRO_HOME") or "~/recon_pro")).resolve()
STATE_DIR = RECON_HOME / "state"
SCOPE_FILE = Path(os.path.expanduser(os.environ.get("BUGBOUNTY_SCOPE_FILE", str(STATE_DIR / "scope.txt")))).resolve()
EXCLUDE_FILE = STATE_DIR / "exclusions.txt"
CONFIG_FILE = STATE_DIR / "recon_pro.conf"
RUNS_DIR = RECON_HOME / "runs"
REPORTS_DIR = RECON_HOME / "reports"
TOOLKIT_REPORTS_DIR = ROOT / "bugbounty-toolkit" / "reports"
TOOLKIT_HISTORY_DIR = ROOT / "bugbounty-toolkit" / "data" / "history"
TOOLKIT_VENV = ROOT / "bugbounty-toolkit" / ".venv"
TOKEN = os.environ.get("RECON_WEB_TOKEN", "")
HOST = os.environ.get("RECON_WEB_HOST", "127.0.0.1").strip()
PORT_RAW = os.environ.get("RECON_WEB_PORT", "8765")
SHELL_ENABLED = os.environ.get("RECON_WEB_ENABLE_SHELL") == "1"
DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
PROXY_SCHEMES = {"http", "https", "socks4", "socks5", "socks5h"}
MAX_BODY = 32 * 1024
MAX_REPORT = 1024 * 1024
MAX_ARCHIVE_FILE = 16 * 1024 * 1024
RUN_NAME_TEMPLATE = "recon_{}_"
LOG_FILE_NAMES = ("pipeline.log", "stages.tsv", "start.epoch")
REPORT_FILE_NAMES = (
    "report.md", "bugs_found.txt", "findings.tsv", "findings.all.tsv",
    "telegram_report.txt", "summary.txt", "scan_info.txt", "tool_inventory.txt",
)
LATEST_REPORT_FILE_NAMES = (
    "latest-report.md", "latest-bugs_found.txt", "latest-telegram_report.txt",
    "latest-summary.txt", "latest-findings.tsv",
)

SCAN_LOCK = threading.RLock()
SCAN: dict[str, Any] = {
    "id": None,
    "target": None,
    "mode": None,
    "status": "idle",
    "started_at": None,
    "finished_at": None,
    "return_code": None,
    "output": deque(maxlen=2000),
    "next_seq": 0,
    "process": None,
}
AUTH_LOCK = threading.Lock()
FAILED_LOGINS: dict[str, deque[float]] = {}
OPERATION_LOCK = threading.Lock()
SHELL_LOCK = threading.RLock()
SHELL: dict[str, Any] = {
    "id": None,
    "status": "idle",
    "started_at": None,
    "finished_at": None,
    "return_code": None,
    "output": deque(maxlen=2000),
    "next_seq": 0,
    "process": None,
}


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def _read_text(path: Path, root: Path, limit: int = MAX_REPORT) -> str:
    """Read a regular text file only when its resolved path stays under root."""
    try:
        resolved = path.resolve(strict=True)
        if not _inside(resolved, root) or not resolved.is_file():
            return ""
        if resolved.stat().st_size > limit:
            with resolved.open("r", encoding="utf-8", errors="replace") as handle:
                return handle.read(limit) + "\n[Isi dipotong karena melewati batas tampilan.]"
        return resolved.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _redact(text: str) -> str:
    text = re.sub(r"(?i)((?:https?|socks4|socks5h?)://)[^/@\s]+@", r"\1***@", text)
    text = re.sub(r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)\b((?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|telegram[_-]?token|password|passwd|secret)\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)", r"\1[REDACTED]", text)
    text = re.sub(r"\b[0-9]{6,}:[A-Za-z0-9_-]{20,}\b", "[REDACTED TELEGRAM TOKEN]", text)
    return text


def _normalize_domain(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    domain = value.strip().lower().rstrip(".")
    if not domain or len(domain) > 253 or "://" in domain or "/" in domain or "@" in domain:
        return None
    labels = domain.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return None
    if not all(DOMAIN_LABEL.fullmatch(label) for label in labels):
        return None
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        return domain


def _read_list(path: Path, root: Path) -> list[str]:
    text = _read_text(path, root, 256 * 1024)
    entries = []
    for line in text.splitlines():
        value = line.split("#", 1)[0].strip().lower().rstrip(".")
        if value:
            entries.append(value)
    return entries


def _authorized_domains() -> list[str]:
    if not _inside(SCOPE_FILE, RECON_HOME):
        return []
    return [domain for item in _read_list(SCOPE_FILE, RECON_HOME) if (domain := _normalize_domain(item))]


def _excluded(domain: str) -> bool:
    return any(domain == item or domain.endswith("." + item) for item in _read_list(EXCLUDE_FILE, RECON_HOME))


def _scope_decision(domain: str) -> tuple[bool, str]:
    if domain not in _authorized_domains():
        return False, "Domain harus tercantum persis di daftar scope lokal."
    if _excluded(domain):
        return False, "Domain atau subdomain ini tercantum dalam exclusions.txt."
    return True, "Scope cocok; pengecualian tidak memblokir domain ini."


def _atomic_write(path: Path, content: str, root: Path) -> None:
    if not _inside(path, root):
        raise ValueError("File konfigurasi harus berada di dalam folder data Recon Pro.")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(path.parent), prefix=".recon-web-", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        temporary.replace(path)
        os.chmod(path, 0o600)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink(missing_ok=True)


def _config_values() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in _read_text(CONFIG_FILE, RECON_HOME, 128 * 1024).splitlines():
        if "|" in line:
            key, value = line.split("|", 1)
        elif "=" in line:
            key, value = line.split("=", 1)
            value = value.strip().strip('"')
        else:
            continue
        values[key.strip()] = value.strip()
    return values


def _proxy_file() -> tuple[Path, bool]:
    value = _config_values().get("PROXY_FILE", "state/proxies.txt")
    candidate = Path(os.path.expanduser(value))
    if not candidate.is_absolute():
        candidate = RECON_HOME / candidate
    candidate = candidate.resolve()
    return candidate, _inside(candidate, RECON_HOME)


def _proxy_lines() -> list[str]:
    path, _ = _proxy_file()
    return [line.split("#", 1)[0].strip() for line in _read_text(path, RECON_HOME, 256 * 1024).splitlines() if line.split("#", 1)[0].strip()]


def _validate_proxy(value: str) -> str | None:
    value = value.strip()
    if not value or any(char in value for char in "\r\n\t "):
        return None
    if "://" not in value:
        value = "http://" + value
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme.lower() not in PROXY_SCHEMES or not parsed.hostname or parsed.port is None:
            return None
        if not 1 <= parsed.port <= 65535 or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            return None
    except ValueError:
        return None
    return value


def _masked_proxy(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value if "://" in value else "http://" + value)
        host = parsed.hostname or "?"
        if ":" in host:
            host = "[" + host + "]"
        port = ":" + str(parsed.port) if parsed.port else ""
        auth = "***@" if parsed.username is not None or parsed.password is not None else ""
        return "{}://{}{}{}".format(parsed.scheme, auth, host, port)
    except ValueError:
        return "proxy (format tidak terbaca)"


def _safe_target_path(base: Path, domain: str, *parts: str) -> Path | None:
    if not _normalize_domain(domain) or domain != domain.lower():
        return None
    path = base.joinpath(domain, *parts)
    if not _inside(path, RECON_HOME):
        return None
    return path


def _runs_base() -> Path:
    configured = _config_values().get("OUTPUT_BASE", "runs")
    candidate = Path(os.path.expanduser(configured.strip()))
    if not candidate.is_absolute():
        candidate = RECON_HOME / candidate
    return candidate.resolve()


def _run_entries(domain: str) -> list[dict[str, Any]]:
    if not _normalize_domain(domain) or domain != domain.lower():
        return []
    base = _runs_base()
    domain_dir = base / domain
    try:
        if domain_dir.is_symlink() or not domain_dir.is_dir():
            return []
        resolved_domain = domain_dir.resolve(strict=True)
        if resolved_domain.parent != base:
            return []
        name_pattern = re.compile(r"^{}\d{{8}}_\d{{6}}(?:_\d+)?$".format(re.escape(RUN_NAME_TEMPLATE.format(domain))))
        entries = []
        for path in resolved_domain.iterdir():
            if path.is_symlink() or not name_pattern.fullmatch(path.name) or not path.is_dir():
                continue
            resolved = path.resolve(strict=True)
            if resolved.parent != resolved_domain or not _inside(resolved, base):
                continue
            modified = resolved.stat().st_mtime
            entries.append({
                "id": resolved.name,
                "label": "{} · {}".format(resolved.name, datetime.fromtimestamp(modified, timezone.utc).astimezone().strftime("%d %b %Y %H:%M:%S %Z")),
                "updated": datetime.fromtimestamp(modified, timezone.utc).isoformat(timespec="seconds"),
                "_path": resolved,
                "_modified": modified,
            })
        return sorted(entries, key=lambda item: item["_modified"], reverse=True)
    except OSError:
        return []


def _run_path(domain: str, run_id: str = "") -> Path | None:
    entries = _run_entries(domain)
    if run_id:
        return next((item["_path"] for item in entries if item["id"] == run_id), None)
    return entries[0]["_path"] if entries else None


def _latest_run(domain: str) -> Path | None:
    return _run_path(domain)


def _safe_regular_file(path: Path, root: Path) -> Path | None:
    try:
        resolved_root = root.resolve()
        current = path.absolute()
        while current != resolved_root:
            if current.is_symlink():
                return None
            parent = current.parent
            if parent == current or not _inside(parent, resolved_root):
                return None
            current = parent
        resolved = path.resolve(strict=True)
        if not _inside(resolved, resolved_root) or not resolved.is_file():
            return None
        return resolved
    except OSError:
        return None


def _available_targets() -> list[dict[str, Any]]:
    found: dict[str, float] = {}
    for base in (REPORTS_DIR, _runs_base()):
        try:
            resolved_base = base.resolve()
            for path in resolved_base.iterdir():
                domain = _normalize_domain(path.name)
                if not domain or path.is_symlink() or not path.is_dir():
                    continue
                resolved = path.resolve(strict=True)
                if resolved.parent == resolved_base:
                    found[domain] = max(found.get(domain, 0.0), resolved.stat().st_mtime)
        except OSError:
            continue
    try:
        for path in TOOLKIT_REPORTS_DIR.iterdir():
            match = re.fullmatch(r"([A-Za-z0-9.-]+)-\d{8}T\d{6}Z\.(?:md|json)", path.name, re.IGNORECASE)
            domain = _normalize_domain(match.group(1)) if match else None
            safe_path = _safe_regular_file(path, ROOT) if domain else None
            if domain and safe_path is not None:
                found[domain] = max(found.get(domain, 0.0), safe_path.stat().st_mtime)
    except OSError:
        pass
    return [
        {"domain": domain, "updated": datetime.fromtimestamp(stamp, timezone.utc).isoformat(timespec="seconds")}
        for domain, stamp in sorted(found.items(), key=lambda pair: pair[1], reverse=True)[:30]
    ]


def _latest_target() -> str | None:
    targets = _available_targets()
    return targets[0]["domain"] if targets else None


def _findings_count(domain: str | None) -> int:
    if not domain:
        return 0
    run = _latest_run(domain)
    if run is None:
        return 0
    ledger = _read_text(run / "final" / "findings.tsv", run, 4 * 1024 * 1024)
    return sum(1 for line in ledger.splitlines() if line.strip())


def _which(name: str) -> str | None:
    """Resolve a tool on PATH, then in ~/.local/bin (where pipx installs)."""
    found = shutil.which(name)
    if found:
        return found
    candidate = Path(os.path.expanduser("~/.local/bin")) / name
    try:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    except OSError:
        return None
    return None


def _toolkit_python() -> str:
    """The interpreter the passive toolkit really runs on, or "" when absent."""
    candidate = TOOLKIT_VENV / "bin" / "python"
    try:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    except OSError:
        return ""
    return ""


def _toolkit_module_states(modules: tuple[str, ...]) -> dict[str, bool]:
    """Check toolkit packages inside its venv, not in the dashboard's interpreter.

    The dashboard usually runs on the system Python while the toolkit runs in
    its own venv, so looking them up here reported every package as missing
    even when the toolkit had them.
    """
    interpreter = _toolkit_python()
    if interpreter:
        checker = (
            "import importlib.util,sys;"
            "print(','.join(m for m in sys.argv[1:] if importlib.util.find_spec(m)))"
        )
        try:
            done = subprocess.run(
                [interpreter, "-c", checker, *modules],
                capture_output=True, text=True, timeout=15, check=False,
            )
            if done.returncode == 0:
                found = {part.strip() for part in (done.stdout or "").split(",") if part.strip()}
                return {module: module in found for module in modules}
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
    states: dict[str, bool] = {}
    for module in modules:
        try:
            states[module] = importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
            states[module] = False
    return states


def _tool_inventory() -> list[dict[str, Any]]:
    tools = [
        ("curl", "HTTP client"), ("jq", "JSON utilities"), ("python3", "Passive toolkit / dashboard"),
        ("subfinder", "Subdomain discovery"), ("assetfinder", "Subdomain discovery"),
        ("amass", "Subdomain discovery"), ("findomain", "Subdomain discovery"),
        ("chaos", "Subdomain discovery"), ("dnsx", "DNS validation"),
        ("httpx", "HTTP probing"), ("tlsx", "TLS inventory"),
        ("katana", "URL collection"), ("waybackurls", "URL collection"), ("gau", "URL collection"),
        ("gf", "Pattern filtering"), ("x8", "Parameter discovery"), ("arjun", "Parameter discovery"),
        ("ffuf", "Content discovery"), ("gobuster", "Content discovery"),
        ("feroxbuster", "Content discovery"), ("dirsearch", "Content discovery"),
        ("skipfish", "Authorized crawl and directory mapping"),
        ("nuclei", "Template checks"), ("dalfox", "Parameter checks"),
        ("whatweb", "Technology detection"), ("wafw00f", "WAF identification"),
        ("nikto", "Authorized web server checks"), ("sqlmap", "Authorized SQL injection testing"),
        ("wpscan", "Authorized WordPress checks"), ("commix", "Authorized command injection testing"),
        ("naabu", "Port discovery"), ("nmap", "Port inventory"),
    ]
    result = [{"name": name, "group": group, "installed": _which(name) is not None} for name, group in tools]
    modules = {"yaml": "PyYAML", "requests": "Requests", "dns": "dnspython"}
    states = _toolkit_module_states(tuple(modules))
    result.append({"name": "toolkit venv", "group": "Passive toolkit", "installed": bool(_toolkit_python())})
    for module, label in modules.items():
        result.append({"name": label, "group": "Passive toolkit", "installed": states.get(module, False)})
    return result


# Read-only catalogue shown on the dashboard's Arsenal page. Every command is a
# low-volume starting point for an asset that is explicitly in scope; the
# dashboard never runs them on its own.
ARSENAL_CATALOG: tuple[dict[str, str], ...] = (
    {
        "id": "skipfish", "bin": "skipfish", "name": "Skipfish", "category": "crawl",
        "summary": "Crawler aktif 2.10b dengan dictionary bawaan: memetakan direktori, file, dan form.",
        "install": "bash recon.sh --fix-tools   # apt, lalu build dari sumber dengan header pcre/idn/ssl",
        "usage": "touch /tmp/skipfish-new.wl && skipfish -o /tmp/skipfish-{{TARGET}} -S /usr/local/share/skipfish/dictionaries/complete.wl -W /tmp/skipfish-new.wl -l 20 -r 2000 https://{{TARGET}}/",
    },
    {
        "id": "gobuster", "bin": "gobuster", "name": "Gobuster", "category": "crawl",
        "summary": "Brute-force direktori dan file dengan wordlist, cepat dan hemat memori.",
        "install": "sudo apt-get install -y gobuster",
        "usage": "gobuster dir -u https://{{TARGET}}/ -w /usr/share/wordlists/dirb/common.txt -t 20 --timeout 10s",
    },
    {
        "id": "feroxbuster", "bin": "feroxbuster", "name": "Feroxbuster", "category": "crawl",
        "summary": "Content discovery rekursif berbasis Rust dengan batas waktu per run.",
        "install": "cargo install feroxbuster",
        "usage": "feroxbuster -u https://{{TARGET}}/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 -d 2 --time-limit 10m",
    },
    {
        "id": "dirsearch", "bin": "dirsearch", "name": "dirsearch", "category": "crawl",
        "summary": "Pemetaan path dengan ekstensi umum dan wordlist bawaan.",
        "install": "pipx install dirsearch",
        "usage": "dirsearch -u https://{{TARGET}}/ -t 20 --max-time 10",
    },
    {
        "id": "ffuf", "bin": "ffuf", "name": "ffuf", "category": "crawl",
        "summary": "Fuzzer HTTP serba bisa untuk path, host, dan parameter.",
        "install": "go install github.com/ffuf/ffuf/v2@latest",
        "usage": "ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://{{TARGET}}/FUZZ -mc 200,204,301,302,403 -rate 40 -t 10",
    },
    {
        "id": "nuclei", "bin": "nuclei", "name": "Nuclei", "category": "audit",
        "summary": "Pemeriksaan berbasis template untuk misconfig, exposure, dan CVE.",
        "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "usage": "nuclei -u https://{{TARGET}}/ -as -duc -rl 30 -c 10 -severity low,medium,high,critical",
    },
    {
        "id": "nikto", "bin": "nikto", "name": "Nikto", "category": "audit",
        "summary": "Pemeriksaan konfigurasi web server dan file berbahaya yang umum.",
        "install": "sudo apt-get install -y nikto",
        "usage": "nikto -host https://{{TARGET}}/ -nointeractive -maxtime 300",
    },
    {
        "id": "whatweb", "bin": "whatweb", "name": "WhatWeb", "category": "audit",
        "summary": "Fingerprinting teknologi pada mode satu request per host.",
        "install": "sudo apt-get install -y whatweb",
        "usage": "whatweb --aggression=1 --no-errors https://{{TARGET}}/",
    },
    {
        "id": "wafw00f", "bin": "wafw00f", "name": "WAFW00F", "category": "audit",
        "summary": "Identifikasi WAF dan produk proteksi sebelum menguji lebih jauh.",
        "install": "pipx install wafw00f",
        "usage": "wafw00f https://{{TARGET}}/ -a",
    },
    {
        "id": "sqlmap", "bin": "sqlmap", "name": "SQLMap", "category": "audit",
        "summary": "Uji SQL injection terbatas, tanpa dump, shell, atau perubahan data.",
        "install": "sudo apt-get install -y sqlmap",
        "usage": "sqlmap -u 'https://{{TARGET}}/?id=1' --batch --risk=1 --level=1 --technique=BE --threads=1 --timeout=10 --retries=1",
    },
    {
        "id": "wpscan", "bin": "wpscan", "name": "WPScan", "category": "audit",
        "summary": "Pemeriksaan versi plugin/tema WordPress yang rentan.",
        "install": "sudo gem install wpscan",
        "usage": "wpscan --url https://{{TARGET}}/ --enumerate vp,vt --random-user-agent --request-timeout 15 --no-update",
    },    {
        "id": "commix", "bin": "commix", "name": "Commix", "category": "audit",
        "summary": "Uji command injection non-destruktif pada parameter yang diizinkan.",
        "install": "git clone https://github.com/commixproject/commix /opt/commix && sudo ln -sf /opt/commix/commix.py /usr/local/bin/commix",
        "usage": "commix --url='https://{{TARGET}}/?cmd=1' --batch --level=1 --skip-empty",
    },
    {
        "id": "dalfox", "bin": "dalfox", "name": "Dalfox", "category": "param",
        "summary": "Pemindaian XSS berbasis parameter dengan worker terbatas.",
        "install": "go install github.com/hahwul/dalfox/v2@latest",
        "usage": "dalfox url 'https://{{TARGET}}/?q=1' --worker 5 --delay 200 --skip-bav",
    },
    {
        "id": "arjun", "bin": "arjun", "name": "Arjun", "category": "param",
        "summary": "Penemuan parameter tersembunyi pada endpoint GET/POST.",
        "install": "pipx install arjun",
        "usage": "arjun -u https://{{TARGET}}/ -m GET --stable --quiet",
    },
    {
        "id": "x8", "bin": "x8", "name": "x8", "category": "param",
        "summary": "Ekstraksi parameter dari wordlist dengan jumlah request terkendali.",
        "install": "cargo install x8",
        "usage": "x8 -u https://{{TARGET}}/ -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    },
    {
        "id": "subfinder", "bin": "subfinder", "name": "Subfinder", "category": "recon",
        "summary": "Enumerasi subdomain pasif dari banyak sumber publik.",
        "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "usage": "subfinder -d {{TARGET}} -all -silent",
    },
    {
        "id": "amass", "bin": "amass", "name": "Amass", "category": "recon",
        "summary": "Pemetaan serangan-surface pasif beserta relasi DNS.",
        "install": "go install github.com/owasp-amass/amass/v4/cmd/amass@latest",
        "usage": "amass enum -passive -d {{TARGET}} -timeout 10",
    },
    {
        "id": "chaos", "bin": "chaos", "name": "Chaos", "category": "recon",
        "summary": "Subdomain dari dataset ProjectDiscovery yang sudah dikurasi.",
        "install": "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
        "usage": "chaos -d {{TARGET}} -silent -o /tmp/chaos-{{TARGET}}.txt",
    },
    {
        "id": "dnsx", "bin": "dnsx", "name": "dnsx", "category": "recon",
        "summary": "Validasi hasil subdomain lewat resolver sebelum dipindai.",
        "install": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "usage": "subfinder -d {{TARGET}} -silent | dnsx -silent -a -resp",
    },
    {
        "id": "httpx", "bin": "httpx", "name": "httpx", "category": "recon",
        "summary": "Probing HTTP: status, judul, teknologi, dan ringkasan TLS.",
        "install": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "usage": "httpx -u https://{{TARGET}}/ -title -tech-detect -status-code -tls-grab",
    },
    {
        "id": "katana", "bin": "katana", "name": "Katana", "category": "recon",
        "summary": "Crawler untuk mengumpulkan URL dan endpoint dari aplikasi.",
        "install": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "usage": "katana -u https://{{TARGET}}/ -d 2 -jc -rl 30 -silent",
    },
    {
        "id": "gau", "bin": "gau", "name": "gau", "category": "recon",
        "summary": "URL historis dari arsip publik untuk menemukan endpoint lama.",
        "install": "go install github.com/lc/gau/v2/cmd/gau@latest",
        "usage": "gau {{TARGET}} --threads 5 --subs",
    },
    {
        "id": "tlsx", "bin": "tlsx", "name": "tlsx", "category": "recon",
        "summary": "Inventaris TLS: versi protokol, masa berlaku, dan SAN.",
        "install": "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
        "usage": "tlsx -host {{TARGET}} -silent -tls-version -expired",
    },
    {
        "id": "naabu", "bin": "naabu", "name": "Naabu", "category": "port",
        "summary": "Penemuan port cepat dengan laju terkendali.",
        "install": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "usage": "naabu -host {{TARGET}} -top-ports 100 -rate 300 -silent",
    },
    {
        "id": "nmap", "bin": "nmap", "name": "Nmap", "category": "port",
        "summary": "Inventaris port dan versi layanan tanpa skrip agresif.",
        "install": "sudo apt-get install -y nmap",
        "usage": "nmap -sV -Pn --top-ports 200 -T3 {{TARGET}}",
    },
)


def _arsenal_data() -> dict[str, Any]:
    items = []
    for entry in ARSENAL_CATALOG:
        item = dict(entry)
        item["installed"] = _which(entry["bin"]) is not None
        items.append(item)
    return {
        "items": items,
        "installed": sum(1 for item in items if item["installed"]),
        "total": len(items),
    }


def _scan_snapshot() -> dict[str, Any]:
    with SCAN_LOCK:
        return {
            "id": SCAN["id"],
            "target": SCAN["target"],
            "mode": SCAN["mode"],
            "status": SCAN["status"],
            "started_at": SCAN["started_at"],
            "finished_at": SCAN["finished_at"],
            "return_code": SCAN["return_code"],
        }


def _dashboard_status() -> dict[str, Any]:
    tools = _tool_inventory()
    proxies = _proxy_lines()
    config = _config_values()
    latest = _latest_target()
    with SCAN_LOCK:
        running = SCAN["status"] == "running"
    return {
        "ok": True,
        "server_time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "recon_home": str(RECON_HOME),
        "host_type": "TERMUX / ANDROID" if os.environ.get("TERMUX_VERSION") else "VPS / LINUX" if sys.platform.startswith("linux") else sys.platform.upper(),
        "scan": _scan_snapshot(),
        "latest_target": latest,
        "targets": _available_targets(),
        "findings": _findings_count(latest),
        "tools_installed": sum(1 for tool in tools if tool["installed"]),
        "tools_total": len(tools),
        "proxy_count": len(proxies),
        "proxy_rotate": config.get("PROXY_ROTATE", "1") == "1",
        "proxy_required": config.get("PROXY_REQUIRED", "0") == "1",
        "scan_running": running,
    }


def _scan_worker(scan_id: str, process: subprocess.Popen[str]) -> None:
    buffer = ""
    try:
        assert process.stdout is not None
        while True:
            chunk = process.stdout.readline(4096)
            if not chunk:
                break
            buffer += chunk
            if buffer.endswith("\n"):
                _append_output(scan_id, buffer.rstrip("\r\n"))
                buffer = ""
            elif len(buffer) >= 8000:
                _append_output(scan_id, buffer[:8000] + " [baris dipotong]")
                buffer = buffer[8000:]
        if buffer:
            _append_output(scan_id, buffer.rstrip("\r\n"))
        return_code = process.wait()
    except (OSError, ValueError) as error:
        _append_output(scan_id, "Dashboard: proses berhenti membaca output: {}".format(error))
        return_code = process.poll()
        if return_code is None:
            return_code = 1
    with SCAN_LOCK:
        if SCAN["id"] == scan_id:
            SCAN["return_code"] = return_code
            SCAN["status"] = "completed" if return_code == 0 else "failed"
            SCAN["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            SCAN["process"] = None


def _append_output(scan_id: str, line: str) -> None:
    with SCAN_LOCK:
        if SCAN["id"] != scan_id:
            return
        SCAN["next_seq"] += 1
        SCAN["output"].append({"seq": SCAN["next_seq"], "line": _redact(line[:8000])})


def _start_scan(domain: str, mode: str) -> dict[str, Any]:
    allowed, reason = _scope_decision(domain)
    if not allowed:
        raise ValueError(reason)
    if mode not in ("full", "passive"):
        raise ValueError("Mode scan tidak dikenal.")
    command = ["bash", str(ROOT / "recon.sh"), "--no-setup"]
    if mode == "passive":
        command.append("--passive")
    command.extend(["--yes", domain])
    env = os.environ.copy()
    env.pop("RECON_WEB_TOKEN", None)
    env.setdefault("PYTHONUNBUFFERED", "1")
    with OPERATION_LOCK:
        with SHELL_LOCK:
            if SHELL["status"] == "running":
                raise ValueError("Scan dashboard tidak dapat dimulai saat command shell berjalan.")
        with SCAN_LOCK:
            if SCAN["status"] == "running":
                raise ValueError("Scan lain masih berjalan.")
            process = subprocess.Popen(
                command,
                cwd=str(ROOT),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                start_new_session=True,
            )
            scan_id = secrets.token_hex(12)
            SCAN.update({
                "id": scan_id,
                "target": domain,
                "mode": mode,
                "status": "running",
                "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "finished_at": None,
                "return_code": None,
                "output": deque(maxlen=2000),
                "next_seq": 0,
                "process": process,
            })
            worker = threading.Thread(target=_scan_worker, args=(scan_id, process), daemon=True)
            worker.start()
    return _scan_snapshot()


def _stop_scan() -> dict[str, Any]:
    with SCAN_LOCK:
        process = SCAN.get("process")
        if SCAN["status"] != "running" or process is None:
            raise ValueError("Tidak ada scan yang sedang berjalan.")
        pid = process.pid
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError as error:
        raise ValueError("Sinyal berhenti gagal dikirim: {}".format(error)) from error
    return _scan_snapshot()


def _run_stages(run: Path | None) -> list[dict[str, str]]:
    if run is None:
        return []
    stages = []
    stage_file = _safe_regular_file(run / "logs" / "stages.tsv", run)
    if stage_file is None:
        return stages
    try:
        lines = stage_file.read_text(encoding="utf-8", errors="replace")[:512 * 1024].splitlines()
    except OSError:
        return stages
    for line in lines:
        fields = line.split("\t")
        if len(fields) < 3:
            continue
        duration = 0
        if len(fields) >= 4 and fields[3].strip().isdigit():
            duration = int(fields[3].strip())
        stages.append({
            "name": fields[0],
            "status": fields[1],
            "note": _redact(fields[2]),
            "duration": duration,
            "finished": fields[4].strip() if len(fields) >= 5 else "",
        })
    return stages


def _passive_report_paths(domain: str) -> list[Path]:
    try:
        paths = [
            path for path in TOOLKIT_REPORTS_DIR.glob(domain + "-*")
            if path.suffix.lower() in (".md", ".json")
            and re.fullmatch(r"[A-Za-z0-9.-]+-[A-Za-z0-9_.-]+\.(?:md|json)", path.name, re.IGNORECASE)
            and _safe_regular_file(path, ROOT) is not None
        ]
        return sorted(paths, key=lambda path: path.stat().st_mtime, reverse=True)
    except OSError:
        return []


PASSIVE_CACHE_LOCK = threading.Lock()
PASSIVE_CACHE: dict[str, tuple[float, int, dict[str, Any]]] = {}


def _passive_summary(domain: str) -> dict[str, Any]:
    """Summarise the newest passive snapshot stored by the bugbounty toolkit.

    The dashboard polls this endpoint for as long as it is open and a snapshot
    can be several megabytes, so the parsed summary is cached until the file
    under ``data/history`` changes on disk.
    """
    try:
        candidates = [
            path for path in (TOOLKIT_HISTORY_DIR / domain).glob("*.json")
            if _safe_regular_file(path, ROOT) is not None
        ]
        latest = max(candidates, key=lambda path: path.stat().st_mtime, default=None)
    except OSError:
        latest = None
    if latest is None:
        raise ValueError("Belum ada snapshot pasif untuk domain ini. Jalankan scan passive dahulu.")

    try:
        stats = latest.stat()
    except OSError as error:
        raise ValueError("Snapshot pasif tidak dapat dibaca: {}".format(error)) from error

    with PASSIVE_CACHE_LOCK:
        cached = PASSIVE_CACHE.get(domain)
    if cached is not None and cached[0] == stats.st_mtime and cached[1] == stats.st_size:
        return cached[2]

    try:
        snapshot = json.loads(latest.read_text(encoding="utf-8", errors="replace")[: 8 * 1024 * 1024])
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Snapshot pasif tidak dapat dibaca: {}".format(error)) from error
    if not isinstance(snapshot, dict):
        raise ValueError("Snapshot pasif tidak valid.")

    sources = snapshot.get("sources", {}) or {}
    js_entries = [entry for entry in snapshot.get("js_intel", []) or [] if isinstance(entry, dict)]
    hosts = [host for host in snapshot.get("hosts", []) or [] if isinstance(host, dict)]
    axfr = snapshot.get("axfr", {}) or {}
    summary = {
        "target": domain,
        "collected_at": str(snapshot.get("collected_at", "") or ""),
        "snapshot_file": latest.name,
        "subdomains": len(snapshot.get("subdomains", []) or []),
        "live_subdomains": len(snapshot.get("live_subdomains", []) or []),
        "archived_urls": len(snapshot.get("archived_urls", []) or []),
        "hosts_probed": len(hosts),
        "certificates": len(snapshot.get("certificates", []) or []),
        "sources": {str(key): int(value or 0) for key, value in sources.items() if isinstance(value, (int, float))},
        "axfr": bool(isinstance(axfr, dict) and axfr.get("records")),
        "axfr_ns": str((axfr or {}).get("ns", "") or ""),
        "dmarc": bool(str(snapshot.get("dmarc", "") or "").strip()),
        "dmarc_checked": bool(snapshot.get("dmarc_checked")),
        "js_scanned": sum(int(entry.get("js_scanned") or 0) for entry in js_entries),
        "js_secrets": sum(len(entry.get("secrets", []) or []) for entry in js_entries),
        "js_source_maps": sum(len(entry.get("source_maps", []) or []) for entry in js_entries),
        "tls_verified": sum(1 for host in hosts if (host.get("tls", {}) or {}).get("version")),
        "tls_failed": sum(1 for host in hosts if (host.get("tls", {}) or {}).get("verification_failed")),
        "robots_paths": sum(len((host.get("robots", {}) or {}).get("paths", []) or []) for host in hosts),
    }
    with PASSIVE_CACHE_LOCK:
        PASSIVE_CACHE[domain] = (stats.st_mtime, stats.st_size, summary)
    return summary


def _latest_report_paths(domain: str) -> dict[str, Path]:
    report_dir = REPORTS_DIR / domain
    return {
        name: report_dir / name
        for name in LATEST_REPORT_FILE_NAMES
        if _safe_regular_file(report_dir / name, RECON_HOME) is not None
    }


def _archive_collections(domain: str, kind: str) -> list[dict[str, str]]:
    if kind not in ("logs", "reports"):
        raise ValueError("Jenis arsip tidak dikenal.")
    runs = _run_entries(domain)
    items = [{key: value for key, value in entry.items() if not key.startswith("_")} for entry in runs]
    if kind == "reports":
        if _passive_report_paths(domain):
            items.append({"id": "passive", "label": "Laporan pasif · semua riwayat", "updated": ""})
        if not runs and _latest_report_paths(domain):
            items.append({"id": "latest", "label": "Salinan laporan terbaru", "updated": ""})
    elif any(_safe_regular_file(ROOT / "bugbounty-toolkit" / "logs" / ("toolkit.log" + ("." + str(index) if index else "")), ROOT) for index in range(4)):
        items.append({"id": "toolkit", "label": "Log toolkit pasif · global/rotasi", "updated": ""})
    return items


def _archive_paths(domain: str, collection: str, kind: str) -> tuple[dict[str, Path], Path]:
    if kind not in ("logs", "reports"):
        raise ValueError("Jenis arsip tidak dikenal.")
    known = {item["id"] for item in _archive_collections(domain, kind)}
    if collection not in known:
        raise ValueError("Run atau koleksi arsip tidak ditemukan.")
    if collection == "passive" and kind == "reports":
        return ({path.name: path for path in _passive_report_paths(domain)}, ROOT)
    if collection == "latest" and kind == "reports":
        return (_latest_report_paths(domain), RECON_HOME)
    if collection == "toolkit" and kind == "logs":
        log_dir = ROOT / "bugbounty-toolkit" / "logs"
        paths = {}
        for index in range(4):
            name = "toolkit.log" + ("." + str(index) if index else "")
            path = log_dir / name
            if _safe_regular_file(path, ROOT) is not None:
                paths[name] = path
        return paths, ROOT
    run = _run_path(domain, collection)
    if run is None:
        raise ValueError("Run tidak ditemukan atau sudah dihapus.")
    if kind == "logs":
        log_dir = run / "logs"
        paths = {name: log_dir / name for name in LOG_FILE_NAMES}
        try:
            for path in log_dir.iterdir():
                if path.name.endswith(".err") and re.fullmatch(r"[A-Za-z0-9_.-]{1,180}\.err", path.name):
                    paths[path.name] = path
        except OSError:
            pass
    else:
        final_dir = run / "final"
        paths = {name: final_dir / name for name in REPORT_FILE_NAMES}
    return ({name: path for name, path in paths.items() if _safe_regular_file(path, run) is not None}, run)


def _archive_files(domain: str, collection: str, kind: str) -> list[dict[str, Any]]:
    paths, root = _archive_paths(domain, collection, kind)
    files = []
    for name, path in paths.items():
        safe_path = _safe_regular_file(path, root)
        if safe_path is None:
            continue
        try:
            modified = safe_path.stat().st_mtime
            size = safe_path.stat().st_size
        except OSError:
            continue
        files.append({
            "id": name,
            "name": name,
            "size": size,
            "updated": datetime.fromtimestamp(modified, timezone.utc).isoformat(timespec="seconds"),
        })
    return sorted(files, key=lambda item: item["name"])


def _archive_file_data(domain: str, collection: str, kind: str, file_id: str) -> dict[str, Any]:
    paths, root = _archive_paths(domain, collection, kind)
    path = paths.get(file_id)
    if path is None:
        raise ValueError("File tidak ditemukan dalam koleksi yang dipilih.")
    safe_path = _safe_regular_file(path, root)
    if safe_path is None:
        raise ValueError("File tidak aman atau sudah tidak tersedia.")
    try:
        with safe_path.open("r", encoding="utf-8", errors="replace") as handle:
            content = handle.read(MAX_ARCHIVE_FILE + 1)
    except OSError as error:
        raise ValueError("File tidak dapat dibaca: {}".format(error)) from error
    truncated = len(content) > MAX_ARCHIVE_FILE
    if truncated:
        content = content[:MAX_ARCHIVE_FILE] + "\n[Isi dipotong setelah batas 16 MiB.]"
    return {
        "name": safe_path.name,
        "content": _redact(content),
        "size": safe_path.stat().st_size,
        "truncated": truncated,
        "redacted": True,
    }


def _logs(domain: str, run_id: str = "") -> dict[str, Any]:
    run = _run_path(domain, run_id)
    if run is None:
        return {"target": domain, "available": False, "stages": [], "text": "Belum ada workspace untuk run yang dipilih."}
    pipeline_path = _safe_regular_file(run / "logs" / "pipeline.log", run)
    pipeline = _read_text(pipeline_path, run, MAX_ARCHIVE_FILE) if pipeline_path is not None else ""
    return {
        "target": domain,
        "run": run.name,
        "available": True,
        "stages": _run_stages(run),
        "text": _redact(pipeline or "Pilih file log untuk melihat detail lengkap."),
    }


def _reports(domain: str) -> dict[str, Any]:
    run = _latest_run(domain)
    reports = []
    if run is not None:
        for name in REPORT_FILE_NAMES:
            path = _safe_regular_file(run / "final" / name, run)
            if path is not None:
                content = _read_text(path, run, MAX_ARCHIVE_FILE)
                if content:
                    reports.append({"id": name, "title": name, "content": _redact(content)})
    for path in _passive_report_paths(domain):
        content = _read_text(path, ROOT, MAX_ARCHIVE_FILE)
        if content:
            reports.append({"id": path.name, "title": path.name, "content": _redact(content)})
    return {"target": domain, "reports": reports}


def _scope_data() -> dict[str, Any]:
    return {
        "domains": _authorized_domains(),
        "exclusions": _read_list(EXCLUDE_FILE, RECON_HOME),
        "editable": _inside(SCOPE_FILE, RECON_HOME),
    }


def _change_scope(action: str, domain: str, confirmed: bool) -> dict[str, Any]:
    if not confirmed:
        raise ValueError("Konfirmasi otorisasi wajib dicentang.")
    if not _inside(SCOPE_FILE, RECON_HOME):
        raise ValueError("Lokasi scope harus berada di dalam folder data Recon Pro.")
    entries = _authorized_domains()
    original_lines = _read_text(SCOPE_FILE, RECON_HOME, 256 * 1024).splitlines()
    if action == "add":
        if domain in entries:
            raise ValueError("Domain sudah ada di daftar scope.")
        original_lines.append(domain)
    elif action == "remove":
        if domain not in entries:
            raise ValueError("Domain tidak ditemukan di daftar scope.")
        original_lines = [
            line for line in original_lines
            if _normalize_domain(line.split("#", 1)[0].strip()) != domain
        ]
    else:
        raise ValueError("Aksi scope tidak dikenal.")
    content = "\n".join(original_lines).rstrip() + ("\n" if original_lines else "")
    _atomic_write(SCOPE_FILE, content, RECON_HOME)
    return _scope_data()


def _save_proxies(raw: Any, confirmed: bool) -> dict[str, Any]:
    if not confirmed:
        raise ValueError("Konfirmasi penggantian daftar proxy wajib dicentang.")
    if not isinstance(raw, str):
        raise ValueError("Daftar proxy harus berupa teks.")
    path, editable = _proxy_file()
    if not editable:
        raise ValueError("File proxy yang dikonfigurasi berada di luar folder data; perubahan web diblokir.")
    entries = []
    errors = []
    for line_number, line in enumerate(raw.splitlines(), 1):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        normalized = _validate_proxy(value)
        if normalized is None:
            errors.append(str(line_number))
        elif normalized not in entries:
            entries.append(normalized)
    if errors:
        raise ValueError("Format proxy tidak valid pada baris: {}. Gunakan scheme://host:port (kredensial opsional).".format(", ".join(errors)))
    if len(entries) > 300:
        raise ValueError("Maksimal 300 proxy per daftar.")
    _atomic_write(path, "".join(entry + "\n" for entry in entries), RECON_HOME)
    return _proxy_data()


def _proxy_data() -> dict[str, Any]:
    path, editable = _proxy_file()
    entries = _proxy_lines()
    return {
        "count": len(entries),
        "items": [_masked_proxy(entry) for entry in entries],
        "editable": editable,
        "file_label": str(path.relative_to(RECON_HOME)) if _inside(path, RECON_HOME) else "path luar folder data (hanya-baca)",
        "rotate": _config_values().get("PROXY_ROTATE", "1") == "1",
        "required": _config_values().get("PROXY_REQUIRED", "0") == "1",
        "editor_value": "\n".join(entries) if editable else "",
    }


def _shell_available() -> bool:
    try:
        loopback = HOST.lower() == "localhost" or ipaddress.ip_address(HOST).is_loopback
    except ValueError:
        loopback = False
    return SHELL_ENABLED and loopback


def _shell_snapshot() -> dict[str, Any]:
    with SHELL_LOCK:
        return {
            "id": SHELL["id"],
            "status": SHELL["status"],
            "started_at": SHELL["started_at"],
            "finished_at": SHELL["finished_at"],
            "return_code": SHELL["return_code"],
        }


def _shell_data(after: int) -> dict[str, Any]:
    with SHELL_LOCK:
        lines = [line for line in SHELL["output"] if line["seq"] > after]
        shell = {
            "id": SHELL["id"],
            "status": SHELL["status"],
            "started_at": SHELL["started_at"],
            "finished_at": SHELL["finished_at"],
            "return_code": SHELL["return_code"],
        }
        return {"shell": shell, "lines": lines, "next_seq": SHELL["next_seq"], "enabled": _shell_available()}


def _append_shell_output(shell_id: str, line: str) -> None:
    line = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", line)
    with SHELL_LOCK:
        if SHELL["id"] != shell_id:
            return
        SHELL["next_seq"] += 1
        SHELL["output"].append({"seq": SHELL["next_seq"], "line": _redact(line[:8000])})


def _shell_worker(shell_id: str, process: subprocess.Popen[str]) -> None:
    buffer = ""
    try:
        assert process.stdout is not None
        while True:
            chunk = process.stdout.readline(4096)
            if not chunk:
                break
            buffer += chunk
            if buffer.endswith("\n"):
                _append_shell_output(shell_id, buffer.rstrip("\r\n"))
                buffer = ""
            elif len(buffer) >= 8000:
                _append_shell_output(shell_id, buffer[:8000] + " [baris dipotong]")
                buffer = buffer[8000:]
        if buffer:
            _append_shell_output(shell_id, buffer.rstrip("\r\n"))
        return_code = process.wait()
    except (OSError, ValueError) as error:
        _append_shell_output(shell_id, "Dashboard: gagal membaca output shell: {}".format(error))
        return_code = process.poll()
        if return_code is None:
            return_code = 1
    with SHELL_LOCK:
        if SHELL["id"] == shell_id:
            SHELL["return_code"] = return_code
            SHELL["status"] = "completed" if return_code == 0 else "failed"
            SHELL["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            SHELL["process"] = None


def _resolve_shell_cwd(value: Any) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Masukkan direktori kerja absolut, misalnya / atau /tmp.")
    raw_path = value.strip()
    if len(raw_path) > 1024 or "\x00" in raw_path:
        raise ValueError("Path direktori terlalu panjang atau tidak valid.")
    path = Path(os.path.expanduser(raw_path))
    if not path.is_absolute():
        raise ValueError("Direktori kerja harus berupa path absolut, misalnya /root atau /tmp.")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ValueError("Direktori kerja tidak ditemukan atau tidak dapat diakses.") from error
    if not resolved.is_dir():
        raise ValueError("Path direktori kerja bukan sebuah folder.")
    return resolved


def _start_shell(command_text: Any, cwd_text: Any, acknowledged: Any) -> dict[str, Any]:
    if not _shell_available():
        raise ValueError("Terminal web nonaktif. Jalankan dashboard dengan RECON_WEB_ENABLE_SHELL=1 dan bind 127.0.0.1.")
    if acknowledged is not True:
        raise ValueError("Konfirmasi risiko shell wajib diberikan.")
    if not isinstance(command_text, str) or not command_text.strip():
        raise ValueError("Masukkan perintah shell.")
    command_text = command_text.strip()
    if len(command_text) > 4096 or "\x00" in command_text:
        raise ValueError("Perintah terlalu panjang atau mengandung karakter yang tidak valid.")
    cwd = _resolve_shell_cwd(cwd_text)
    env = os.environ.copy()
    env.pop("RECON_WEB_TOKEN", None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "Never"
    env.setdefault("PYTHONUNBUFFERED", "1")
    with OPERATION_LOCK:
        with SCAN_LOCK:
            if SCAN["status"] == "running":
                raise ValueError("Command shell tidak dapat dimulai saat scan dashboard aktif.")
        with SHELL_LOCK:
            if SHELL["status"] == "running":
                raise ValueError("Selesaikan atau hentikan command shell yang sedang berjalan dahulu.")
            process = subprocess.Popen(
                ["bash", "-c", command_text],
                cwd=str(cwd),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                start_new_session=True,
            )
            shell_id = secrets.token_hex(12)
            SHELL.update({
                "id": shell_id,
                "status": "running",
                "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "finished_at": None,
                "return_code": None,
                "output": deque(maxlen=2000),
                "next_seq": 0,
                "process": process,
            })
            worker = threading.Thread(target=_shell_worker, args=(shell_id, process), daemon=True)
            worker.start()
    return _shell_snapshot()


def _stop_shell() -> dict[str, Any]:
    with SHELL_LOCK:
        process = SHELL.get("process")
        if SHELL["status"] != "running" or process is None:
            raise ValueError("Tidak ada command shell yang sedang berjalan.")
        pid = process.pid
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError as error:
        raise ValueError("Sinyal berhenti gagal dikirim: {}".format(error)) from error
    return _shell_snapshot()


class DashboardHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ReconProLocal/1.0"
    sys_version = ""

    def log_message(self, _format: str, *args: Any) -> None:
        # Do not write request headers, query values, tokens, or proxy details to a log.
        return

    def _headers(self, content_type: str, length: int) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._headers("application/json; charset=utf-8", len(body))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _check_host(self) -> bool:
        header = self.headers.get("Host", "")
        try:
            request_host = urllib.parse.urlsplit("//" + header).hostname
        except ValueError:
            request_host = None
        if not request_host:
            self._json(400, {"error": "Header Host tidak valid."})
            return False
        allowed = {item.strip().lower() for item in os.environ.get("RECON_WEB_ALLOWED_HOSTS", "localhost,127.0.0.1,::1").split(",") if item.strip()}
        allowed.add(HOST.lower())
        if request_host.lower() not in allowed:
            self._json(421, {"error": "Host tidak diizinkan. Atur RECON_WEB_ALLOWED_HOSTS secara eksplisit."})
            return False
        return True

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        try:
            origin_host = urllib.parse.urlsplit(origin).netloc.lower()
        except ValueError:
            return False
        return bool(origin_host) and origin_host == self.headers.get("Host", "").lower()

    def _body(self) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"error": "Content-Length tidak valid."})
            return None
        if length < 0 or length > MAX_BODY:
            self._json(413, {"error": "Ukuran permintaan melebihi batas."})
            return None
        if length == 0:
            self._json(400, {"error": "Body JSON wajib diisi."})
            return None
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(400, {"error": "Body JSON tidak valid."})
            return None
        if not isinstance(payload, dict):
            self._json(400, {"error": "Body JSON harus berupa object."})
            return None
        return payload

    def _authorized(self) -> bool:
        value = self.headers.get("Authorization", "")
        scheme, _, supplied = value.partition(" ")
        if scheme.lower() == "bearer" and secrets.compare_digest(supplied, TOKEN):
            return True
        self._json(401, {"error": "Sesi tidak valid atau kedaluwarsa. Masuk kembali."})
        return False

    def _login_allowed(self) -> bool:
        address = self.client_address[0]
        now = time.monotonic()
        with AUTH_LOCK:
            attempts = FAILED_LOGINS.setdefault(address, deque())
            while attempts and now - attempts[0] > 300:
                attempts.popleft()
            if len(attempts) >= 8:
                return False
        return True

    def do_GET(self) -> None:
        if not self._check_host():
            return
        path = urllib.parse.urlsplit(self.path).path
        static = {"/": (ROOT / "index.html", "text/html; charset=utf-8"),
                  "/index.html": (ROOT / "index.html", "text/html; charset=utf-8"),
                  "/app.js": (ROOT / "app.js", "text/javascript; charset=utf-8"),
                  "/styles.css": (ROOT / "styles.css", "text/css; charset=utf-8")}
        if path in static:
            file_path, content_type = static[path]
            try:
                body = file_path.read_bytes()
            except OSError:
                self._json(404, {"error": "File UI tidak ditemukan."})
                return
            self.send_response(200)
            self._headers(content_type, len(body))
            self.end_headers()
            self.wfile.write(body)
            return
        if not path.startswith("/api/"):
            self._json(404, {"error": "Endpoint tidak ditemukan."})
            return
        if not self._authorized():
            return
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        try:
            if path == "/api/status":
                payload = _dashboard_status()
            elif path == "/api/tools":
                tools = _tool_inventory()
                payload = {"tools": tools, "installed": sum(1 for tool in tools if tool["installed"]), "total": len(tools)}
            elif path == "/api/arsenal":
                payload = _arsenal_data()
            elif path == "/api/scope":
                payload = _scope_data()
            elif path == "/api/proxies":
                payload = _proxy_data()
            elif path == "/api/scan":
                payload = {"scan": _scan_snapshot()}
            elif path == "/api/scan/output":
                after = int(query.get("after", ["0"])[0])
                with SCAN_LOCK:
                    lines = [line for line in SCAN["output"] if line["seq"] > after]
                    payload = {"scan_id": SCAN["id"], "lines": lines, "next_seq": SCAN["next_seq"]}
            elif path == "/api/shell":
                after = int(query.get("after", ["0"])[0])
                payload = _shell_data(after)
            elif path in ("/api/runs", "/api/files", "/api/file", "/api/download"):
                target = _normalize_domain(query.get("target", [""])[0])
                if not target:
                    raise ValueError("Pilih domain yang valid.")
                kind = query.get("kind", [""])[0]
                if kind not in ("logs", "reports"):
                    raise ValueError("Jenis arsip tidak dikenal.")
                if path == "/api/runs":
                    payload = {"target": target, "kind": kind, "items": _archive_collections(target, kind)}
                else:
                    collection = query.get("collection", [""])[0]
                    if path == "/api/files":
                        payload = {"target": target, "collection": collection, "kind": kind, "files": _archive_files(target, collection, kind)}
                    else:
                        file_id = query.get("file", [""])[0]
                        artifact = _archive_file_data(target, collection, kind, file_id)
                        if path == "/api/file":
                            payload = artifact
                        else:
                            body = artifact["content"].encode("utf-8")
                            filename = re.sub(r"[^A-Za-z0-9._-]", "_", artifact["name"])[:180] or "recon-file.txt"
                            self.send_response(200)
                            self._headers("text/plain; charset=utf-8", len(body))
                            self.send_header("Content-Disposition", "attachment; filename=\"{}\"".format(filename))
                            self.end_headers()
                            self.wfile.write(body)
                            return
            elif path == "/api/logs":
                target = _normalize_domain(query.get("target", [""])[0])
                if not target:
                    raise ValueError("Pilih domain yang valid.")
                payload = _logs(target, query.get("run", [""])[0])
            elif path == "/api/reports":
                target = _normalize_domain(query.get("target", [""])[0])
                if not target:
                    raise ValueError("Pilih domain yang valid.")
                payload = _reports(target)
            elif path == "/api/passive/summary":
                target = _normalize_domain(query.get("target", [""])[0])
                if not target:
                    raise ValueError("Pilih domain yang valid.")
                payload = {"ok": True, "summary": _passive_summary(target)}
            else:
                self._json(404, {"error": "Endpoint tidak ditemukan."})
                return
            self._json(200, payload)
        except (OSError, ValueError) as error:
            self._json(400, {"error": str(error)})

    def do_POST(self) -> None:
        if not self._check_host():
            return
        path = urllib.parse.urlsplit(self.path).path
        if not self._origin_ok():
            self._json(403, {"error": "Origin tidak cocok dengan host dashboard."})
            return
        payload = self._body()
        if payload is None:
            return
        if path == "/api/login":
            if not self._login_allowed():
                self._json(429, {"error": "Terlalu banyak percobaan masuk. Coba lagi setelah beberapa menit."})
                return
            supplied = payload.get("token")
            if isinstance(supplied, str) and secrets.compare_digest(supplied, TOKEN):
                with AUTH_LOCK:
                    FAILED_LOGINS.pop(self.client_address[0], None)
                self._json(200, {"ok": True})
            else:
                with AUTH_LOCK:
                    FAILED_LOGINS.setdefault(self.client_address[0], deque()).append(time.monotonic())
                self._json(401, {"error": "Token tidak cocok."})
            return
        if not self._authorized():
            return
        try:
            if path == "/api/scan":
                domain = _normalize_domain(payload.get("target"))
                if not domain:
                    raise ValueError("Masukkan apex domain yang valid, tanpa URL atau path.")
                if payload.get("authorized") is not True:
                    raise ValueError("Konfirmasi otorisasi wajib dicentang sebelum scan.")
                payload_out = {"scan": _start_scan(domain, str(payload.get("mode", "full")))}
            elif path == "/api/scan/stop":
                payload_out = {"scan": _stop_scan()}
            elif path == "/api/shell/start":
                payload_out = {"shell": _start_shell(payload.get("command"), payload.get("cwd"), payload.get("acknowledged"))}
            elif path == "/api/shell/stop":
                payload_out = {"shell": _stop_shell()}
            elif path == "/api/scope":
                domain = _normalize_domain(payload.get("domain"))
                if not domain:
                    raise ValueError("Masukkan apex domain yang valid.")
                payload_out = _change_scope(str(payload.get("action", "")), domain, payload.get("authorized") is True)
            elif path == "/api/proxies":
                payload_out = _save_proxies(payload.get("proxies"), payload.get("confirm") is True)
            else:
                self._json(404, {"error": "Endpoint tidak ditemukan."})
                return
            self._json(200, payload_out)
        except ValueError as error:
            self._json(400, {"error": str(error)})
        except (OSError, subprocess.SubprocessError) as error:
            self._json(500, {"error": "Operasi gagal: {}".format(error)})


def main() -> int:
    if len(TOKEN) < 32:
        print("ERROR: set RECON_WEB_TOKEN ke secret acak minimal 32 karakter sebelum menjalankan dashboard.", file=sys.stderr)
        print("Contoh: export RECON_WEB_TOKEN=... (buat dengan secrets.token_urlsafe(32)).", file=sys.stderr)
        return 2
    try:
        port = int(PORT_RAW)
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        print("ERROR: RECON_WEB_PORT harus angka 1-65535.", file=sys.stderr)
        return 2
    try:
        is_loopback = HOST.lower() == "localhost" or ipaddress.ip_address(HOST).is_loopback
    except ValueError:
        is_loopback = False
    if SHELL_ENABLED and not is_loopback:
        print("ERROR: terminal web memerlukan RECON_WEB_HOST loopback (127.0.0.1); jangan expose shell ke jaringan.", file=sys.stderr)
        return 2
    if not is_loopback:
        if os.environ.get("RECON_WEB_ALLOW_REMOTE") != "1":
            print("ERROR: bind non-local memerlukan RECON_WEB_ALLOW_REMOTE=1.", file=sys.stderr)
            return 2
        if not os.environ.get("RECON_WEB_ALLOWED_HOSTS", "").strip():
            print("ERROR: set RECON_WEB_ALLOWED_HOSTS untuk bind non-local.", file=sys.stderr)
            return 2
        print("PERINGATAN: bind non-local tanpa TLS hanya aman di balik reverse proxy; atur RECON_WEB_TLS_CERT dan RECON_WEB_TLS_KEY untuk HTTPS langsung.", file=sys.stderr)
    tls_cert = os.path.expanduser(os.environ.get("RECON_WEB_TLS_CERT", "").strip())
    tls_key = os.path.expanduser(os.environ.get("RECON_WEB_TLS_KEY", "").strip())
    use_tls = bool(tls_cert and tls_key)
    if use_tls and not (Path(tls_cert).is_file() and Path(tls_key).is_file()):
        print("ERROR: RECON_WEB_TLS_CERT/KEY diisi tetapi file-nya tidak ada.", file=sys.stderr)
        return 2
    if not (ROOT / "recon.sh").is_file():
        print("ERROR: recon.sh tidak ditemukan di {}.".format(ROOT), file=sys.stderr)
        return 2
    try:
        server = ThreadingHTTPServer((HOST, port), DashboardHandler)
    except OSError as error:
        print("ERROR: tidak dapat membuka {}:{}: {}".format(HOST, port, error), file=sys.stderr)
        return 2
    server.daemon_threads = True
    if use_tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tls_cert, tls_key)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print("Recon Pro dashboard berjalan di https://{}:{}".format(HOST, port))
    else:
        print("Recon Pro dashboard berjalan di http://{}:{}".format(HOST, port))
    print("Hentikan dengan Ctrl-C. Scan hanya berjalan pada mesin ini.")
    if SHELL_ENABLED:
        print("PERINGATAN: terminal web aktif; akses shell hanya lewat loopback dan token dashboard.")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nDashboard dihentikan.")
    finally:
        with SCAN_LOCK:
            process = SCAN.get("process")
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except OSError:
                pass
        with SHELL_LOCK:
            shell_process = SHELL.get("process")
        if shell_process is not None and shell_process.poll() is None:
            try:
                os.killpg(shell_process.pid, signal.SIGTERM)
            except OSError:
                pass
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
