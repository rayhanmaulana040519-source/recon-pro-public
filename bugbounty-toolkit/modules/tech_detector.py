"""Technology detection from a single benign GET per host.

Detection is signature based (headers, cookies and a few HTML markers). It never
requests a path the site does not already link to: the probe fetches the origin
root once, with redirects followed and the shared rate limit applied.
"""

from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import urljoin, urlsplit

GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
VERSION_IN_SERVER = re.compile(r"^(?P<product>[A-Za-z][\w.\-]*)/(?P<version>[0-9][\w.\-]*)")
ROBOTS_LINE = re.compile(r"(?im)^\s*Disallow\s*:\s*(\S+)")

# (what to look at, pattern, technology label)
SIGNATURES: list[tuple[str, str, str]] = [
    ("header:server", r"nginx", "nginx"),
    ("header:server", r"apache", "Apache HTTP Server"),
    ("header:server", r"microsoft-iis", "Microsoft IIS"),
    ("header:server", r"litespeed", "LiteSpeed"),
    ("header:server", r"cloudflare", "Cloudflare"),
    ("header:server", r"openresty", "OpenResty"),
    ("header:x-powered-by", r"php", "PHP"),
    ("header:x-powered-by", r"asp\.net", "ASP.NET"),
    ("header:x-powered-by", r"express", "Express"),
    ("header:x-aspnet-version", r".", "ASP.NET"),
    ("header:x-generator", r"drupal", "Drupal"),
    ("header:x-drupal-cache", r".", "Drupal"),
    ("header:x-shopify-stage", r".", "Shopify"),
    ("header:x-github-request-id", r".", "GitHub Pages"),
    ("header:cf-ray", r".", "Cloudflare"),
    ("header:x-akamai-transformed", r".", "Akamai"),
    ("header:x-amz-cf-id", r".", "Amazon CloudFront"),
    ("header:x-vercel-id", r".", "Vercel"),
    ("header:x-served-by", r".", "Fastly"),
    ("header:via", r"nginx", "nginx (proxied)"),
    ("header:set-cookie", r"phpsessid", "PHP session"),
    ("header:set-cookie", r"jsessionid", "Java servlet"),
    ("header:set-cookie", r"asp\.net_sessionid", "ASP.NET session"),
    ("header:set-cookie", r"laravel_session", "Laravel"),
    ("header:set-cookie", r"wordpress_", "WordPress"),
    ("header:set-cookie", r"cf_clearance", "Cloudflare challenge"),
    ("header:content-security-policy", r".", "Content-Security-Policy present"),
    ("body", r"wp-content/", "WordPress"),
    ("body", r"/_next/static/", "Next.js"),
    ("body", r"__nuxt__", "Nuxt"),
    ("body", r"ng-version=", "Angular"),
    ("body", r"data-reactroot", "React"),
    ("body", r"cdn\.shopify\.com", "Shopify"),
    ("body", r"grafana", "Grafana"),
    ("body", r"kibana", "Kibana"),
    ("body", r"jenkins", "Jenkins"),
]


class TechDetector:
    """Probes the root of an origin and labels the technology it can recognise.

    Args:
        http: Shared rate-limited HTTP client.
        logger: Logger for progress and errors.
    """

    def __init__(self, http: Any, logger: Any) -> None:
        self.http = http
        self.logger = logger

    def probe(self, origin: str, config: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
        """Fetch ``origin`` once and describe it.

        Args:
            origin: ``https://dev.example.com`` — scope-checked by the caller.
            config: Optional config for the CORS probe toggle.

        Returns:
            A dict with ``url``, ``status``, ``headers``, ``technologies``,
            ``title`` and optionally ``cors``; ``None`` when unreachable.
        """
        response = self.http.get(origin, allow_redirects=True)
        if response is None:
            return None

        headers = {str(key).lower(): str(value) for key, value in response.headers.items()}
        body = response.text or ""
        technologies = self._detect(headers, body)

        # Keep each Set-Cookie header on its own so the cookie rules can read the
        # actual attributes instead of a comma-joined string.
        raw_cookies: list[str] = []
        try:
            raw_cookies = [str(item) for item in response.raw.headers.getlist("Set-Cookie")]
        except (AttributeError, TypeError):
            single = headers.get("set-cookie", "")
            raw_cookies = [single] if single else []

        result: dict[str, Any] = {
            "url": str(response.url),
            "status": response.status_code,
            "headers": headers,
            "technologies": technologies,
            "title": self._title(body),
            "server": headers.get("server", ""),
            "x_powered_by": headers.get("x-powered-by", ""),
            "cookies": [cookie.strip() for cookie in raw_cookies if cookie.strip()],
        }

        if ((config or {}).get("analysis", {}) or {}).get("cors_probe", False):
            result["cors"] = self._cors_probe(origin)

        collectors = ((config or {}).get("collectors", {}) or {})
        http_cfg = ((config or {}).get("http", {}) or {})
        hostname = (urlsplit(str(response.url)).hostname or "").lower()
        timeout = float(http_cfg.get("timeout", 10) or 10)

        # A single TLS handshake reads the certificate this host actually serves,
        # which is the only way to see expiry and trust problems rather than the
        # certificates that happen to sit in the CT logs. Like DNS, the handshake
        # leaves from this machine and cannot use the HTTP proxy.
        if hostname and bool(collectors.get("tls_probe", True)):
            # Bounded well below the HTTP timeout: a host with no listener on 443
            # must not add fifteen seconds to every pass.
            tls = _tls_probe(hostname, min(timeout, 8.0))
            if tls:
                result["tls"] = tls

        # robots.txt is a file the site publishes for crawlers: one GET of a
        # standard path, never a guess at hidden paths.
        if bool(collectors.get("robots_txt", True)):
            robots = self._robots(str(response.url))
            if robots:
                result["robots"] = robots

        self.logger.info("%s: %s technologies", origin, len(technologies))
        return result

    # -- helpers --------------------------------------------------------------
    @staticmethod
    def _title(body: str) -> str:
        match = TITLE.search(body)
        return re.sub(r"\s+", " ", match.group(1)).strip()[:120] if match else ""

    def _detect(self, headers: Mapping[str, str], body: str) -> list[str]:
        """Match the signature table against headers and a bounded body sample."""
        sample = body[:200_000]
        found: set[str] = set()

        for source, pattern, label in SIGNATURES:
            if source.startswith("header:"):
                value = headers.get(source.split(":", 1)[1], "")
                if value and re.search(pattern, value, re.I):
                    found.add(label)
            elif re.search(pattern, sample, re.I):
                found.add(label)

        generator = GENERATOR.search(sample)
        if generator:
            found.add(generator.group(1).strip()[:60])

        return sorted(found)

    def _cors_probe(self, origin: str) -> dict[str, str]:
        """Send one GET with a foreign Origin header and read the CORS answer."""
        probe = "https://recon-probe.invalid"
        response = self.http.get(origin, headers={"Origin": probe}, allow_redirects=True)
        if response is None:
            return {}
        return {
            "origin_sent": probe,
            "allow_origin": response.headers.get("Access-Control-Allow-Origin", ""),
            "allow_credentials": response.headers.get("Access-Control-Allow-Credentials", ""),
        }

    def _robots(self, base_url: str) -> dict[str, Any]:
        """Read ``/robots.txt`` once and return the paths it disallows.

        ``Disallow`` entries are paths the owner asked crawlers to skip, so they
        point at administration, staging or internal routes. Only the one
        standard file is requested — no path is guessed from it.
        """
        url = urljoin(base_url, "/robots.txt")
        response = self.http.get(url, allow_redirects=True)
        if response is None or response.status_code != 200:
            return {}
        text = (response.text or "")[:20_000]
        if not text.strip() or "<html" in text[:200].lower():
            return {}
        paths: list[str] = []
        for match in ROBOTS_LINE.finditer(text):
            value = match.group(1).strip()
            if value and value != "/" and value not in paths:
                paths.append(value)
        if not paths:
            return {}
        self.logger.info("%s: robots.txt lists %d disallowed path(s)", base_url, len(paths))
        return {"url": url, "paths": paths[:60]}


def _tls_probe(host: str, timeout: float) -> dict[str, Any]:
    """Read the certificate ``host`` serves today, with one TLS handshake.

    A verified handshake is attempted first, so a success means the certificate
    is trusted and matches the hostname — exactly what a browser requires. When
    verification fails, the failure itself is the observation (expired,
    self-signed or issued for another name), which is what the analyzer reports.

    Args:
        host: Hostname to connect to on port 443.
        timeout: Socket timeout in seconds.

    Returns:
        ``{"version", "issuer", "subject", "not_before", "not_after"}`` on
        success, ``{"error", "verification_failed"}`` on failure, ``{}`` when
        nothing could be learned.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                version = tls.version() or ""
                certificate = tls.getpeercert() or {}
    except ssl.SSLCertVerificationError as error:
        return {"error": str(error), "verification_failed": True}
    except (OSError, ssl.SSLError, ValueError) as error:
        return {"error": str(error)}
    if not certificate:
        return {}
    return {
        "version": version,
        "issuer": _cert_name(certificate.get("issuer", ())),
        "subject": _cert_name(certificate.get("subject", ())),
        "not_before": _cert_date(certificate.get("notBefore")),
        "not_after": _cert_date(certificate.get("notAfter")),
    }


def _cert_date(value: Any) -> str:
    """Turn an ``ssl`` certificate date into a plain ISO date."""
    try:
        stamp = ssl.cert_time_to_seconds(str(value))
    except (TypeError, ValueError):
        return str(value or "")
    return datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%d")


def _cert_name(parts: Any) -> str:
    """Flatten the nested tuple ``getpeercert()`` returns into one name."""
    for group in parts or ():
        try:
            for key, value in group:
                if key in ("commonName", "organizationName"):
                    return str(value)
        except (TypeError, ValueError):
            continue
    return ""
