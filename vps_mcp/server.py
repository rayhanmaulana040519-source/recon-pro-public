#!/usr/bin/env python3
"""Narrow remote MCP endpoint for updating the Recon Pro checkout.

Expose this only through a trusted HTTPS tunnel. The endpoint accepts one
fixed update operation and never accepts arbitrary commands or paths.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

EXPECTED_ORIGIN = "https://github.com/rayhanmaulana040519-source/recon-pro.git"
ROOT = Path(os.environ.get("RECON_PRO_ROOT", Path(__file__).resolve().parents[1])).resolve()
API_KEY = os.environ.get("RECON_MCP_API_KEY", "")
MAX_OUTPUT = 12000

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

mcp = MCPServer("Recon Pro VPS updater")


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )


def _active_scan() -> str | None:
    """Refuse updates while this checkout's active or passive scan is running."""
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return "Tidak dapat memeriksa proses Linux; update ditolak demi keamanan."

    scan_paths = {
        (ROOT / "recon_pro.sh").resolve(),
        (ROOT / "bugbounty-toolkit" / "main.py").resolve(),
    }
    for cmdline_path in proc_root.glob("[0-9]*/cmdline"):
        try:
            pid = int(cmdline_path.parent.name)
            if pid == os.getpid():
                continue
            raw_args = cmdline_path.read_bytes().split(b"\0")
            args = [value.decode("utf-8", errors="replace") for value in raw_args if value]
            cwd = (proc_root / str(pid) / "cwd").resolve()
        except (OSError, ValueError):
            continue

        for argument in args:
            candidate = Path(argument)
            if not candidate.is_absolute():
                candidate = cwd / candidate
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            if resolved in scan_paths:
                return "Scan Recon Pro terdeteksi (PID {}). Tunggu sampai scan selesai sebelum update.".format(pid)
    return None


def _validate_checkout() -> str | None:
    if not (ROOT / ".git").exists() or not (ROOT / "recon.sh").is_file():
        return "Folder repo Recon Pro tidak valid: {}".format(ROOT)

    branch = _git("branch", "--show-current")
    if branch.returncode != 0 or branch.stdout.strip() != "main":
        return "Update ditolak: checkout harus berada pada branch main."

    upstream = _git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
    if upstream.returncode != 0 or upstream.stdout.strip() != "origin/main":
        return "Update ditolak: branch main harus melacak origin/main."

    origin = _git("remote", "get-url", "origin")
    if origin.returncode != 0 or origin.stdout.strip() != EXPECTED_ORIGIN:
        return "Update ditolak: URL origin tidak cocok dengan repo Recon Pro yang diizinkan."

    status = _git("status", "--porcelain", "--untracked-files=all")
    if status.returncode != 0:
        return "Tidak dapat memeriksa status git; update dibatalkan."
    if status.stdout.strip():
        return "Update ditolak: working tree repo tidak bersih. Simpan atau tinjau perubahan lokal dahulu."
    return None


def _run_update() -> str:
    if os.name != "posix":
        return "Update hanya didukung pada host Linux/POSIX."
    if os.geteuid() == 0:
        logging.warning("MCP updater berjalan sebagai root; endpoint HTTPS hanya membuka operasi update tetap.")

    problem = _validate_checkout()
    if problem:
        return problem
    problem = _active_scan()
    if problem:
        return problem

    env = os.environ.copy()
    env.pop("RECON_MCP_API_KEY", None)
    env.pop("RECON_WEB_TOKEN", None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GCM_INTERACTIVE"] = "Never"
    before = _git("rev-parse", "--short", "HEAD")
    if before.returncode != 0:
        return "Tidak dapat membaca commit lokal; update dibatalkan."

    try:
        update = subprocess.run(
            ["bash", str(ROOT / "recon.sh"), "--update"],
            cwd=str(ROOT),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=900,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "Update timeout setelah 15 menit. Periksa koneksi GitHub dan log di VPS."
    except OSError as error:
        return "Gagal menjalankan updater: {}".format(error)

    output = update.stdout[-MAX_OUTPUT:].strip()
    if update.returncode != 0:
        return "Update gagal (exit {}).\n{}".format(update.returncode, output or "Tidak ada output.")

    # The repository's updater prints the self-test result but does not propagate
    # every self-test exit code, so verify it explicitly before reporting success.
    try:
        test = subprocess.run(
            ["bash", str(ROOT / "recon.sh"), "--self-test"],
            cwd=str(ROOT),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return "Repo sudah ditarik, tetapi self-test tidak dapat diselesaikan: {}".format(error)

    after = _git("rev-parse", "--short", "HEAD")
    commit = after.stdout.strip() if after.returncode == 0 else "tidak diketahui"
    if test.returncode != 0:
        return "Repo telah diperbarui ke {}, tetapi self-test gagal.\n{}\n{}".format(
            commit, output, test.stdout[-MAX_OUTPUT:].strip()
        )
    return "Update selesai: {} -> {}. Self-test lulus.\n{}".format(
        before.stdout.strip(), commit, output or "Repo sudah versi terbaru."
    )


@mcp.tool()
def update_recon_pro() -> str:
    """Fast-forward the configured Recon Pro main checkout and run its self-test.

    This operation refuses dirty checkouts, other origins/branches, and detected
    scans. It does not restart the dashboard or bot. It accepts no command input.
    """
    return _run_update()


class BearerKeyMiddleware:
    """Require a locally generated bearer key for every MCP HTTP request."""

    def __init__(self, app: Any, key: str) -> None:
        self.app = app
        self.key = key

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("path", "").rstrip("/") != "/mcp":
            await self.app(scope, receive, send)
            return

        headers = {name.lower(): value for name, value in scope.get("headers", [])}
        authorization = headers.get(b"authorization", b"").decode("latin-1")
        scheme, separator, supplied = authorization.partition(" ")
        if separator and scheme.lower() == "bearer" and hmac.compare_digest(supplied, self.key):
            await self.app(scope, receive, send)
            return

        body = json.dumps({"error": "unauthorized"}).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json; charset=utf-8"),
                (b"cache-control", b"no-store"),
                (b"www-authenticate", b'Bearer realm="Recon Pro updater"'),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body})


if len(API_KEY) < 40:
    raise RuntimeError("RECON_MCP_API_KEY wajib berisi secret acak minimal 40 karakter.")

transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
app = BearerKeyMiddleware(
    mcp.streamable_http_app(
        json_response=True,
        stateless_http=True,
        max_request_body_size=256 * 1024,
        transport_security=transport_security,
    ),
    API_KEY,
)
