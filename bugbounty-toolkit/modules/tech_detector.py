"""Technology detection from a single benign GET per host.

Detection is signature based (headers, cookies and a few HTML markers). It never
requests a path the site does not already link to: the probe fetches the origin
root once, with redirects followed and the shared rate limit applied.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
VERSION_IN_SERVER = re.compile(r"^(?P<product>[A-Za-z][\w.\-]*)/(?P<version>[0-9][\w.\-]*)")

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

        if (config or {}).get("analysis", {}).get("cors_probe", False):
            result["cors"] = self._cors_probe(origin)

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
