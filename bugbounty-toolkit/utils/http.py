"""Rate-limited HTTP client with optional proxy rotation.

Every outbound request in this toolkit goes through :class:`HttpClient`, so the
rate limit, retry policy, timeout, user agent and proxy rotation live in exactly
one place instead of being repeated in each collector.

The client only performs ordinary GET/HEAD requests on the root of a host. It
cannot fuzz, brute-force or send payloads: that is a deliberate design limit of
this toolkit.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

import requests


class HttpError(RuntimeError):
    """Raised when a request still fails after every retry."""


@dataclass
class ProxyPool:
    """An ordered proxy list with optional round-robin rotation.

    A proxy entry is any URL ``requests`` understands, e.g.
    ``http://user:pass@host:3128`` or ``socks5h://host:1080``.
    """

    entries: list[str] = field(default_factory=list)
    rotate: bool = True
    _index: int = 0

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> "ProxyPool":
        """Build a pool from the ``http.proxies`` section of the config."""
        section = (config.get("http", {}) or {}).get("proxies", {}) or {}
        if not section.get("enabled", False):
            return cls([], False)

        entries: list[str] = []
        for item in section.get("list") or []:
            proxy = str(item).strip()
            if not proxy or proxy.startswith("#"):
                continue
            if "://" not in proxy:
                proxy = "http://" + proxy
            entries.append(proxy)
        return cls(entries, bool(section.get("rotate", True)))

    def __bool__(self) -> bool:
        return bool(self.entries)

    def next(self) -> dict[str, str] | None:
        """Return the proxies mapping for the next request, or ``None``."""
        if not self.entries:
            return None
        if self.rotate:
            proxy = self.entries[self._index % len(self.entries)]
            self._index += 1
        else:
            proxy = self.entries[0]
        return {"http": proxy, "https": proxy}


class RateLimiter:
    """Enforces a minimum interval between requests to the same host."""

    def __init__(self, delay_seconds: float) -> None:
        self.delay = max(0.0, float(delay_seconds))
        self._last_seen: dict[str, float] = {}

    def wait(self, host: str) -> None:
        """Sleep just enough to keep the per-host interval."""
        if self.delay <= 0:
            return
        now = time.monotonic()
        last = self._last_seen.get(host)
        if last is not None:
            remaining = self.delay - (now - last)
            if remaining > 0:
                time.sleep(remaining)
        self._last_seen[host] = time.monotonic()


class HttpClient:
    """Small wrapper around :class:`requests.Session`.

    Responsibilities:
        * per-host rate limiting,
        * bounded retries with a linear backoff,
        * optional proxy rotation,
        * one consistent user agent.

    Every helper returns ``None`` instead of raising when a collector can simply
    skip a source, so one dead API never aborts a whole run.
    """

    def __init__(self, config: Mapping[str, Any], logger: Any) -> None:
        http = config.get("http", {}) or {}
        self.logger = logger
        self.timeout = float(http.get("timeout", 15))
        self.max_retries = max(0, int(http.get("max_retries", 2)))
        self.limiter = RateLimiter(float(http.get("per_host_delay", 1.0)))
        self.proxies = ProxyPool.from_config(config)

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": http.get("user_agent", "PassiveReconToolkit/1.0"),
                "Accept": "*/*",
            }
        )

    # -- lifecycle ------------------------------------------------------------
    def close(self) -> None:
        """Release the underlying connection pool."""
        self.session.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    # -- core -----------------------------------------------------------------
    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """Perform one request with rate limiting, proxies and retries.

        Args:
            method: HTTP method, ``GET`` or ``HEAD`` in this toolkit.
            url: Absolute URL to fetch.
            **kwargs: Passed to :meth:`requests.Session.request`.

        Raises:
            HttpError: when every attempt failed.
        """
        host = (urlsplit(url).hostname or "").lower()
        timeout = kwargs.pop("timeout", self.timeout)
        allow_redirects = kwargs.pop("allow_redirects", True)
        last_error: Exception | None = None

        for attempt in range(self.max_retries + 1):
            self.limiter.wait(host)
            try:
                response = self.session.request(
                    method,
                    url,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                    proxies=self.proxies.next(),
                    **kwargs,
                )
            except requests.RequestException as error:
                last_error = error
                if attempt < self.max_retries:
                    time.sleep(1.5 * (attempt + 1))
                continue

            if response.status_code >= 500 and attempt < self.max_retries:
                last_error = HttpError(f"HTTP {response.status_code} from {url}")
                time.sleep(1.5 * (attempt + 1))
                continue
            return response

        raise HttpError(f"{method} {url} failed after {self.max_retries + 1} attempt(s): {last_error}")

    # -- convenience ----------------------------------------------------------
    def get_text(self, url: str, **kwargs: Any) -> str | None:
        """Fetch a URL and return its body, or ``None`` on failure."""
        try:
            response = self.request("GET", url, **kwargs)
        except HttpError as error:
            self.logger.warning("%s", error)
            return None
        return response.text

    def get_json(self, url: str, **kwargs: Any) -> Any | None:
        """Fetch a URL and return parsed JSON, or ``None`` on failure."""
        try:
            response = self.request("GET", url, **kwargs)
        except HttpError as error:
            self.logger.warning("%s", error)
            return None
        try:
            return response.json()
        except ValueError:
            self.logger.warning("Response from %s was not JSON", url)
            return None

    def get(self, url: str, **kwargs: Any) -> requests.Response | None:
        """Fetch a URL and return the response, or ``None`` on failure."""
        try:
            return self.request("GET", url, **kwargs)
        except HttpError as error:
            self.logger.warning("%s", error)
            return None

    def head(self, url: str, **kwargs: Any) -> requests.Response | None:
        """Send a HEAD request and return the response, or ``None`` on failure."""
        try:
            return self.request("HEAD", url, **kwargs)
        except HttpError as error:
            self.logger.warning("%s", error)
            return None
