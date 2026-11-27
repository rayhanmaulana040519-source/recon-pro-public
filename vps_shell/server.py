#!/usr/bin/env python3
"""Remote MCP endpoint that runs shell commands on the VPS.

This is the wide counterpart of ``vps_mcp/server.py``: instead of one fixed
update action it exposes the checkout owner's shell. Expose it only through a
trusted HTTPS tunnel, keep the bearer key local, and stop it when it is not
needed.
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

ROOT = Path(os.environ.get("RECON_PRO_ROOT", Path(__file__).resolve().parents[1])).resolve()
API_KEY = os.environ.get("RECON_SHELL_API_KEY", "")
MAX_OUTPUT = 12000
MAX_READ = 200000

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

mcp = MCPServer("Recon Pro VPS shell")


def _resolve_dir(cwd: str) -> Path:
    target = Path(cwd or "/")
    if not target.is_absolute():
        target = ROOT / target
    try:
        target = target.resolve()
    except OSError:
        return ROOT
    return target if target.is_dir() else ROOT


@mcp.tool()
def run_command(command: str, cwd: str = "/", timeout: int = 120) -> str:
    """Run one bash command on the VPS and return its merged output and exit code.

    ``cwd`` is the working directory (default ``/``), ``timeout`` is the limit
    in seconds. There is no stdin and no interactive TTY, so commands must be
    non-interactive.
    """
    if not command.strip():
        return "Perintah kosong."
    limit = max(1, min(int(timeout or 120), 900))
    workdir = _resolve_dir(cwd)
    try:
        result = subprocess.run(
            ["bash", "-lc", command],
            cwd=str(workdir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=limit,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        partial = (error.output or "")[-MAX_OUTPUT:]
        return "Timeout setelah {} detik di {}.\n{}".format(limit, workdir, partial.strip())
    except OSError as error:
        return "Gagal menjalankan perintah: {}".format(error)

    output = (result.stdout or "").strip()
    if len(output) > MAX_OUTPUT:
        output = "...(dipotong)...\n" + output[-MAX_OUTPUT:]
    return "exit={} cwd={}\n{}".format(result.returncode, workdir, output or "(tanpa output)")


@mcp.tool()
def read_file(path: str, max_bytes: int = 20000) -> str:
    """Read a text file on the VPS, at most ``max_bytes`` bytes from the start."""
    target = Path(path)
    if not target.is_absolute():
        target = ROOT / target
    limit = max(1, min(int(max_bytes or 20000), MAX_READ))
    try:
        with target.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError as error:
        return "Gagal membaca {}: {}".format(target, error)
    text = data[:limit].decode("utf-8", errors="replace")
    if len(data) > limit:
        text += "\n...(terpotong di {} byte)".format(limit)
    return text or "(file kosong)"


@mcp.tool()
def write_file(path: str, content: str, mode: str = "644") -> str:
    """Write ``content`` to ``path`` on the VPS, creating parent folders."""
    target = Path(path)
    if not target.is_absolute():
        target = ROOT / target
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        try:
            os.chmod(target, int(mode, 8))
        except (OSError, ValueError):
            pass
    except OSError as error:
        return "Gagal menulis {}: {}".format(target, error)
    return "Tersimpan: {} ({} byte, mode {})".format(target, len(content.encode("utf-8")), mode)


@mcp.tool()
def list_dir(path: str = "/") -> str:
    """List one directory on the VPS with sizes for regular files."""
    target = Path(path)
    if not target.is_absolute():
        target = ROOT / target
    try:
        entries = sorted(target.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower()))
    except OSError as error:
        return "Gagal membaca folder {}: {}".format(target, error)
    lines = []
    for entry in entries[:400]:
        if entry.is_symlink():
            kind = "link"
        elif entry.is_dir():
            kind = "dir"
        else:
            kind = "file"
        try:
            size = entry.stat().st_size if kind == "file" else 0
        except OSError:
            size = 0
        lines.append("{:5} {:>10} {}".format(kind, size, entry.name))
    return "\n".join(lines) or "(folder kosong)"


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
                (b"www-authenticate", b'Bearer realm="Recon Pro shell"'),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body})


if len(API_KEY) < 40:
    raise RuntimeError("RECON_SHELL_API_KEY wajib berisi secret acak minimal 40 karakter.")

transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
app = BearerKeyMiddleware(
    mcp.streamable_http_app(
        json_response=True,
        stateless_http=True,
        max_request_body_size=2 * 1024 * 1024,
        transport_security=transport_security,
    ),
    API_KEY,
)
