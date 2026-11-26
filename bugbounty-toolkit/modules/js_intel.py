"""Client-side JavaScript intelligence from the page a host already serves.

For every probed host this module reads the root page, follows the script tags
that live on the same origin, and reads what a browser would read anyway:

* exposed source maps (``//# sourceMappingURL=``) that ship the original code,
* hard-coded credentials and API keys inside the JavaScript itself.

Every request is a single read-only GET of a resource the page already loads,
through the shared rate-limited client. Nothing is fuzzed, guessed or sent as a
payload, and no script outside the probed host's own origin is touched.
"""

from __future__ import annotations

import re
from typing import Any, Mapping
from urllib.parse import urljoin, urlsplit

SCRIPT_SRC = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
SOURCE_MAP_COMMENT = re.compile(r"//#\s*sourceMappingURL=\s*(\S+)")

# (label, pattern, default severity). The patterns are deliberately
# conservative: each one matches a format that is a credential by itself, not
# any string that merely contains the word "key".
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "High"),
    ("AWS secret access key", re.compile(r"(?i)aws.{0,30}[\"'][0-9a-zA-Z/+]{40}[\"']"), "High"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Medium"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), "High"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY(?: BLOCK)?-----"), "High"),
    ("Hard-coded bearer token", re.compile(r"(?i)[\"']?Authorization[\"']?\s*[:=]\s*[\"']Bearer [A-Za-z0-9\-._~+/]+=*[\"']"), "Medium"),
]


def _mask(value: str) -> str:
    """Mask a matched credential so the report never carries the secret."""
    value = value.strip()
    if len(value) <= 12:
        return value[:3] + "…"
    return value[:6] + "…" + value[-4:]


class JsIntel:
    """Reads same-origin scripts of probed hosts and mines them for secrets.

    Args:
        http: Shared rate-limited HTTP client.
        logger: Logger for progress and errors.
        config: Parsed ``config.yaml`` mapping.
    """

    def __init__(self, http: Any, logger: Any, config: Mapping[str, Any]) -> None:
        collectors = config.get("collectors", {}) or {}
        self.http = http
        self.logger = logger
        self.max_files = int(collectors.get("max_js_files", 10))
        self.max_hosts = int(collectors.get("js_intel_max_hosts", 10))

    # -- public API -----------------------------------------------------------
    def scan_hosts(self, hosts: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Run the JS pass over probed hosts and return one entry per host.

        Args:
            hosts: The ``hosts`` list of a snapshot; every entry carries
                ``host`` (the probed hostname).

        Returns:
            A list of ``js_intel`` entries; hosts with no scripts are omitted.
        """
        results: list[dict[str, Any]] = []
        for host in hosts[: self.max_hosts]:
            if not isinstance(host, Mapping):
                continue
            name = str(host.get("host", "")).strip().lower()
            if not name:
                continue
            entry = self.scan_host(name, str(host.get("url") or ""))
            if entry:
                results.append(entry)
        if results:
            self.logger.info("js intel: %d host(s) scanned", len(results))
        return results

    def scan_host(self, name: str, probed_url: str = "") -> dict[str, Any] | None:
        """Read the host's page, follow its same-origin scripts, describe them.

        Args:
            name: The probed hostname, already scope-checked by the caller.
            probed_url: The URL the probe reached this host on, when known, so an
                HTTP-only host is read over the scheme that actually answered.

        Returns:
            ``{"host", "js_scanned", "source_maps", "secrets"}`` or ``None``
            when the root page is unreachable or links no same-origin script.
        """
        page = None
        for origin in self._origins(name, probed_url):
            page = self.http.get(origin, allow_redirects=True)
            if page is not None and (page.text or "").strip():
                break
            page = None
        if page is None:
            return None

        host = (urlsplit(str(page.url)).hostname or "").lower() or name
        scripts = self._scripts(str(page.url), page.text or "", host)
        if not scripts:
            return None

        secrets: list[dict[str, str]] = []
        source_maps: list[dict[str, str]] = []
        scanned = 0

        for script_url in scripts[: self.max_files]:
            response = self.http.get(script_url, allow_redirects=True)
            if response is None:
                continue
            scanned += 1
            body = response.text or ""

            # Source maps are declared in the last line of a script, so the
            # search window is the tail of the file.
            map_match = SOURCE_MAP_COMMENT.search(body[-1000:])
            if map_match:
                map_url = urljoin(str(response.url), map_match.group(1).strip())
                if self._same_host(map_url, host) and self._map_is_real(map_url):
                    source_maps.append({"file": script_url, "map": map_url})

            for label, pattern, severity in SECRET_PATTERNS:
                for match in pattern.finditer(body[:500_000]):
                    secrets.append(
                        {
                            "type": label,
                            "severity": severity,
                            "file": script_url,
                            "masked": _mask(match.group(0)),
                        }
                    )
                    break  # one hit per pattern per file keeps the report readable

        if not secrets and not source_maps:
            return None

        self.logger.info("js intel %s: %d script(s), %d secret(s), %d map(s)", name, scanned, len(secrets), len(source_maps))
        return {
            "host": name,
            "js_scanned": scanned,
            "source_maps": source_maps,
            "secrets": secrets,
        }

    # -- helpers --------------------------------------------------------------
    @staticmethod
    def _origins(name: str, probed_url: str) -> list[str]:
        """Candidate page URLs: the probed scheme first, then HTTPS and HTTP."""
        origins: list[str] = []
        if probed_url.startswith(("http://", "https://")):
            origins.append(probed_url)
        for origin in (f"https://{name}", f"http://{name}"):
            if origin not in origins:
                origins.append(origin)
        return origins

    @staticmethod
    def _same_host(url: str, host: str) -> bool:
        """True when ``url`` belongs to the probed host itself."""
        return (urlsplit(url).hostname or "").lower() == host

    def _scripts(self, base_url: str, body: str, host: str) -> list[str]:
        """Extract same-origin script URLs from the page body."""
        scripts: list[str] = []
        for raw in SCRIPT_SRC.findall(body[:200_000]):
            url = urljoin(base_url, raw.strip())
            if url.startswith(("http://", "https://")) and self._same_host(url, host):
                scripts.append(url)
        return sorted(set(scripts))

    def _map_is_real(self, map_url: str) -> bool:
        """Fetch a source map and confirm it really is a map, not a 404 page."""
        response = self.http.get(map_url, allow_redirects=True)
        if response is None:
            return False
        text = (response.text or "").strip()
        return response.status_code == 200 and text.startswith("{") and ('"sources"' in text[:2000] or '"mappings"' in text[:2000])
