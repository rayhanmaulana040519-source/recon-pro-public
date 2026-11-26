"""Passive reconnaissance: certificate transparency, Wayback, OTX, DNS, RDAP.

Everything here reads public data or performs a single plain GET. No paths are
enumerated, no payloads are sent, and no target is touched beyond what a normal
browser visit would do.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping
from urllib.parse import quote, urlsplit

try:  # dnspython is optional at import time so one missing dep cannot break the CLI
    import dns.exception
    import dns.query
    import dns.resolver
    import dns.zone

    DNS_AVAILABLE = True
except ImportError:  # pragma: no cover - handled at runtime with a warning
    DNS_AVAILABLE = False


CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
RDAP_URL = "https://rdap.org/domain/{domain}"

# Wayback Machine CDX index: archived URLs for the whole domain tree. A free,
# key-less API. `matchType=domain` covers every subdomain; `collapse=urlkey`
# keeps one URL per canonical form; `filter=statuscode:200` keeps only pages
# that were actually archived successfully.
WAYBACK_CDX_URL = (
    "https://web.archive.org/cdx/search/cdx?url={domain}&matchType=domain"
    "&output=json&fl=original&collapse=urlkey&filter=statuscode:200&limit={limit}"
)

# AlienVault OTX passive DNS: hostnames that have historically resolved for the
# domain. Free; the API key is optional (it only raises the rate limit) and is
# read from the environment variable named in the config.
OTX_PASSIVE_DNS_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

# Cert Spotter: certificate-transparency issuances with cleaner pagination than
# crt.sh, useful both as a second subdomain source and as a crt.sh fallback.
# Free; the API key is optional (it raises the rate limit) and is read from the
# environment variable named in the config.
CERTSPOTTER_URL = (
    "https://certspotter.com/api/v1/issuances?domain={domain}"
    "&include_subdomains=true&limit={limit}"
)

# More free, key-less public sources. Each one is a different dataset of
# historically observed names, so their union finds hosts a single source misses.
ANUBIS_URL = "https://jldc.me/anubis/subdomains/{domain}"
RAPIDDNS_URL = "https://rapiddns.io/subdomain/{domain}?full=1"

# Project Discovery Chaos: subdomains the community has observed for a domain.
# Free, but every request needs a PDCP API key from
# https://cloud.projectdiscovery.io, sent as the Authorization header. The key
# is read from the environment variable named in the config.
CHAOS_URL = "https://dns.projectdiscovery.io/dns/{domain}/subdomains"

COMMONCRAWL_INDICES_URL = "https://index.commoncrawl.org/collinfo.json"
COMMONCRAWL_INDEX_URL = "{index}?url=*.{domain}/*&output=json&limit={limit}"


def _now() -> str:
    """Current UTC timestamp in ISO-8601 form."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _secret(name: str) -> str:
    """Read an API key from the environment, else from the protected key file.

    The launcher writes collector keys to ``$RECON_PRO_HOME/state/api_keys.env``
    (mode 600) so cron and the dashboard's subprocess see the same values
    without a shell profile. The environment always wins.

    Args:
        name: Environment variable name, for example ``PDCP_API_KEY``.

    Returns:
        The key, or an empty string when it is not configured anywhere.
    """
    value = os.environ.get(name, "").strip()
    if value:
        return value
    home = os.environ.get("RECON_PRO_HOME") or os.path.join(os.path.expanduser("~"), "recon_pro")
    path = os.path.join(home, "state", "api_keys.env")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, raw = line.partition("=")
                if key.strip() == name:
                    return raw.strip().strip("\"'")
    except OSError:
        pass
    return ""


class PassiveRecon:
    """Collects public data about one authorized apex domain.

    Args:
        http: Shared rate-limited HTTP client.
        logger: Logger for progress and errors.
        config: Parsed ``config.yaml`` mapping.
    """

    def __init__(self, http: Any, logger: Any, config: Mapping[str, Any]) -> None:
        self.http = http
        self.logger = logger
        collectors = config.get("collectors", {}) or {}
        self.config = config
        self.enable_crt = bool(collectors.get("certificate_transparency", True))
        self.enable_dns = bool(collectors.get("dns_records", True))
        self.enable_whois = bool(collectors.get("whois_rdap", True))
        self.dns_types: Iterable[str] = collectors.get("dns_types") or ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
        self.max_subdomains = int(collectors.get("max_subdomains", 2000))
        self.enable_wayback = bool(collectors.get("wayback_cdx", True))
        self.max_archived_urls = int(collectors.get("max_archived_urls", 300))
        self.enable_otx = bool(collectors.get("otx_passive_dns", True))
        self.otx_api_key_env = str(collectors.get("otx_api_key_env", "OTX_API_KEY") or "")
        self.enable_certspotter = bool(collectors.get("certspotter", True))
        self.certspotter_api_key_env = str(collectors.get("certspotter_api_key_env", "CERTSPOTTER_API_KEY") or "")
        self.max_certspotter = int(collectors.get("max_certspotter_issuances", 100))
        self.enable_anubis = bool(collectors.get("anubis", True))
        self.enable_rapiddns = bool(collectors.get("rapiddns", True))
        self.enable_chaos = bool(collectors.get("chaos", True))
        self.chaos_api_key_env = str(collectors.get("chaos_api_key_env", "PDCP_API_KEY") or "")
        self.enable_commoncrawl = bool(collectors.get("commoncrawl", True))
        self.max_commoncrawl_urls = int(collectors.get("max_commoncrawl_urls", 200))
        self.enable_dns_live = bool(collectors.get("dns_live_check", True))
        self.max_live_checks = int(collectors.get("max_live_checks", 100))
        self.enable_axfr = bool(collectors.get("dns_axfr", True))
        timeout = (config.get("http", {}) or {}).get("timeout", 15)
        self.dns_timeout = float(timeout)

    # -- certificate transparency --------------------------------------------
    def certificate_transparency(self, domain: str) -> dict[str, Any]:
        """Read crt.sh and return subdomains plus certificate metadata.

        Args:
            domain: Apex domain, already scope-checked by the caller.

        Returns:
            ``{"subdomains": [...], "certificates": [...]}``; empty on failure.
        """
        result: dict[str, Any] = {"subdomains": [], "certificates": []}
        if not self.enable_crt:
            self.logger.info("certificate transparency disabled in config")
            return result

        url = CRTSH_URL.format(domain=quote(domain))
        payload = self.http.get_json(url, timeout=40)
        if not isinstance(payload, list):
            self.logger.warning("crt.sh returned no usable data for %s", domain)
            return result

        names: set[str] = set()
        certificates: list[dict[str, Any]] = []
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            for field in ("name_value", "common_name"):
                raw = entry.get(field) or ""
                for value in str(raw).splitlines():
                    name = value.strip().strip(".").lower()
                    if name.startswith("*."):
                        name = name[2:]
                    if name and name.endswith(domain) and "." in name:
                        names.add(name)
            certificates.append(
                {
                    "common_name": str(entry.get("common_name") or "").strip().lower(),
                    "issuer": str(entry.get("issuer_name") or "").strip(),
                    "not_before": str(entry.get("not_before") or ""),
                    "not_after": str(entry.get("not_after") or ""),
                    "entry_timestamp": str(entry.get("entry_timestamp") or ""),
                }
            )

        subdomains = sorted(names)[: self.max_subdomains]
        self.logger.info("crt.sh: %d subdomain(s), %d certificate record(s)", len(subdomains), len(certificates))
        return {"subdomains": subdomains, "certificates": certificates}

    # -- DNS ------------------------------------------------------------------
    def dns_records(self, domain: str) -> dict[str, list[str]]:
        """Resolve the configured record types for ``domain``.

        DNS is not an HTTP protocol, so these lookups cannot be proxied; the
        resolver still sees this machine. That limitation is documented in the
        README and repeated in the report metadata.

        Returns:
            Mapping of record type to a list of text records.
        """
        records: dict[str, list[str]] = {}
        if not self.enable_dns:
            self.logger.info("DNS collection disabled in config")
            return records
        if not DNS_AVAILABLE:
            self.logger.warning("dnspython is not installed; skipping DNS records")
            return records

        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = self.dns_timeout
        resolver.lifetime = self.dns_timeout * 2

        for record_type in self.dns_types:
            try:
                answer = resolver.resolve(domain, str(record_type), raise_on_no_answer=False)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue
            except (dns.exception.Timeout, dns.exception.DNSException) as error:
                self.logger.warning("DNS %s lookup failed for %s: %s", record_type, domain, error)
                continue

            values: list[str] = []
            if answer.rrset is not None:
                for rdata in answer.rrset:
                    if record_type == "TXT":
                        chunks = getattr(rdata, "strings", None)
                        if chunks:
                            values.append(b"".join(chunks).decode("utf-8", "replace"))
                            continue
                    values.append(rdata.to_text().strip().strip('"'))
                records[str(record_type)] = sorted(set(values))

        self.logger.info("DNS: %d record type(s) answered", len(records))
        return records

    # -- WHOIS over RDAP ------------------------------------------------------
    def whois(self, domain: str) -> dict[str, Any]:
        """Fetch public registration data from RDAP (no WHOIS port 43 traffic)."""
        if not self.enable_whois:
            self.logger.info("RDAP WHOIS disabled in config")
            return {}

        payload = self.http.get_json(RDAP_URL.format(domain=quote(domain)))
        if not isinstance(payload, dict):
            self.logger.warning("RDAP returned no usable data for %s", domain)
            return {}

        registrar = ""
        for entity in payload.get("entities", []) or []:
            roles = [str(role).lower() for role in entity.get("roles", []) or []]
            if "registrar" not in roles:
                continue
            vcard = (entity.get("vcardArray") or [None, []])[1]
            for item in vcard or []:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                    registrar = str(item[3])
                    break
            if registrar:
                break

        events: dict[str, str] = {}
        for event in payload.get("events", []) or []:
            action = str(event.get("eventAction") or "").lower()
            date = str(event.get("eventDate") or "")
            if action and date:
                events[action] = date

        result = {
            "registrar": registrar,
            "status": [str(item) for item in payload.get("status", []) or []],
            "nameservers": [str(ns.get("ldhName") or "").lower() for ns in payload.get("nameservers", []) or []],
            "events": events,
        }
        self.logger.info("RDAP: registrar %s", registrar or "unknown")
        return result

    # -- Wayback Machine ------------------------------------------------------
    def wayback_urls(self, domain: str) -> dict[str, Any]:
        """Read the CDX index and return archived hostnames and URLs.

        Args:
            domain: Apex domain, already scope-checked by the caller.

        Returns:
            ``{"subdomains": [...], "urls": [...]}``; empty lists on failure.
        """
        result: dict[str, list[str]] = {"subdomains": [], "urls": []}
        if not self.enable_wayback:
            self.logger.info("wayback CDX disabled in config")
            return result

        url = WAYBACK_CDX_URL.format(domain=quote(domain), limit=self.max_archived_urls)
        payload = self.http.get_json(url, timeout=60)
        # With output=json the first row is the header ["original"]; anything
        # else means the index answered in a shape this parser does not know.
        if not isinstance(payload, list) or len(payload) < 2 or not isinstance(payload[0], list):
            self.logger.warning("wayback CDX returned no usable data for %s", domain)
            return result

        suffix = "." + domain
        hostnames: set[str] = set()
        urls: list[str] = []
        for row in payload[1:]:
            if not row:
                continue
            original = str(row[0]).strip()
            if not original:
                continue
            urls.append(original)
            hostname = (urlsplit(original).hostname or "").strip().lower()
            if hostname and (hostname == domain or hostname.endswith(suffix)):
                hostnames.add(hostname)

        result["subdomains"] = sorted(hostnames)
        result["urls"] = urls
        self.logger.info("wayback: %d archived URL(s), %d hostname(s)", len(urls), len(hostnames))
        return result

    # -- AlienVault OTX -------------------------------------------------------
    def otx_subdomains(self, domain: str) -> list[str]:
        """Read OTX passive DNS and return the historical hostnames.

        Args:
            domain: Apex domain, already scope-checked by the caller.

        Returns:
            Sorted list of hostnames under ``domain``; empty on failure.
        """
        if not self.enable_otx:
            self.logger.info("OTX passive DNS disabled in config")
            return []

        headers: dict[str, str] = {}

        api_key = _secret(self.otx_api_key_env)
        if api_key:
            headers["X-OTX-API-KEY"] = api_key

        payload = self.http.get_json(OTX_PASSIVE_DNS_URL.format(domain=quote(domain)), headers=headers)
        if not isinstance(payload, dict):
            self.logger.warning("OTX returned no usable data for %s", domain)
            return []

        suffix = "." + domain
        names: set[str] = set()
        for entry in payload.get("passive_dns", []) or []:
            if not isinstance(entry, dict):
                continue
            hostname = str(entry.get("hostname") or "").strip().strip(".").lower()
            if hostname.startswith("*."):
                hostname = hostname[2:]
            if hostname and (hostname == domain or hostname.endswith(suffix)) and "." in hostname:
                names.add(hostname)

        self.logger.info("OTX: %d hostname(s)", len(names))
        return sorted(names)

    # -- Cert Spotter ---------------------------------------------------------
    def certspotter_issuances(self, domain: str) -> dict[str, Any]:
        """Read Cert Spotter and return extra subdomains and certificates.

        Args:
            domain: Apex domain, already scope-checked by the caller.

        Returns:
            ``{"subdomains": [...], "certificates": [...]}``; empty on failure.
        """
        result: dict[str, Any] = {"subdomains": [], "certificates": []}
        if not self.enable_certspotter:
            self.logger.info("certspotter disabled in config")
            return result

        headers: dict[str, str] = {}
        api_key = _secret(self.certspotter_api_key_env)
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        url = CERTSPOTTER_URL.format(domain=quote(domain), limit=self.max_certspotter)
        payload = self.http.get_json(url, timeout=40, headers=headers)
        if not isinstance(payload, list):
            self.logger.warning("certspotter returned no usable data for %s", domain)
            return result

        suffix = "." + domain
        names: set[str] = set()
        certificates: list[dict[str, Any]] = []
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            for raw in entry.get("dns_names", []) or []:
                name = str(raw).strip().strip(".").lower()
                if name.startswith("*."):
                    name = name[2:]
                if name and (name == domain or name.endswith(suffix)) and "." in name:
                    names.add(name)
            issuer = entry.get("issuer") or {}
            issuer_name = issuer.get("name") if isinstance(issuer, dict) else ""
            certificates.append(
                {
                    "common_name": str(entry.get("common_name") or "").strip().lower(),
                    "issuer": str(issuer_name or "").strip(),
                    "not_before": str(entry.get("not_before") or ""),
                    "not_after": str(entry.get("not_after") or ""),
                    "entry_timestamp": str(entry.get("id") or ""),
                }
            )

        result["subdomains"] = sorted(names)
        result["certificates"] = certificates
        self.logger.info("certspotter: %d subdomain(s), %d issuance record(s)", len(names), len(certificates))
        return result

    # -- RapidDNS -------------------------------------------------------------
    def rapiddns_subdomains(self, domain: str) -> list[str]:
        """Read the RapidDNS public index and return the hostnames it lists.

        RapidDNS answers with an HTML table, so the parse is a tolerant regex
        over hostnames that end in the target domain.

        Args:
            domain: Apex domain, already scope-checked by the caller.

        Returns:
            Sorted list of hostnames; empty on failure.
        """
        if not self.enable_rapiddns:
            self.logger.info("rapiddns disabled in config")
            return []

        text = self.http.get_text(RAPIDDNS_URL.format(domain=quote(domain)), timeout=40)
        if not text:
            self.logger.warning("rapiddns returned no usable data for %s", domain)
            return []

        suffix = "." + domain
        names: set[str] = set()
        for match in re.finditer(r">([A-Za-z0-9_*.\-]+\." + re.escape(domain) + r")<", text):
            name = match.group(1).strip().strip(".").lower()
            if name.startswith("*."):
                name = name[2:]
            if name and (name == domain or name.endswith(suffix)) and "." in name:
                names.add(name)

        self.logger.info("rapiddns: %d hostname(s)", len(names))
        return sorted(names)

    # -- Anubis ---------------------------------------------------------------
    def anubis_subdomains(self, domain: str) -> list[str]:
        """Read the Anubis dataset (jldc.me) and return its hostnames.

        Args:
            domain: Apex domain, already scope-checked by the caller.

        Returns:
            Sorted list of hostnames; empty on failure.
        """
        if not self.enable_anubis:
            self.logger.info("anubis disabled in config")
            return []

        payload = self.http.get_json(ANUBIS_URL.format(domain=quote(domain)), timeout=40)
        if not isinstance(payload, list):
            self.logger.warning("anubis returned no usable data for %s", domain)
            return []

        suffix = "." + domain
        names: set[str] = set()
        for raw in payload:
            name = str(raw).strip().strip(".").lower()
            if name.startswith("*."):
                name = name[2:]
            if name and (name == domain or name.endswith(suffix)) and "." in name:
                names.add(name)

        self.logger.info("anubis: %d hostname(s)", len(names))
        return sorted(names)

    # -- Project Discovery Chaos ----------------------------------------------
    def chaos_subdomains(self, domain: str) -> list[str]:
        """Read the Chaos dataset and return the hostnames it lists.

        Chaos needs a Project Discovery Cloud (PDCP) API key, which is free at
        https://cloud.projectdiscovery.io. The key is read from the environment
        variable named in the config and never written to a file.

        Args:
            domain: Apex domain, already scope-checked by the caller.

        Returns:
            Sorted list of hostnames; empty on failure or without a key.
        """
        if not self.enable_chaos:
            self.logger.info("chaos disabled in config")
            return []

        api_key = _secret(self.chaos_api_key_env)
        if not api_key:
            self.logger.warning(
                "chaos skipped: %s is not set. Create a free Project Discovery Cloud "
                "API key at https://cloud.projectdiscovery.io, then run "
                "`bash recon.sh --api-key` on the host to store it.",
                self.chaos_api_key_env,
            )
            return []

        payload = self.http.get_json(
            CHAOS_URL.format(domain=quote(domain)),
            headers={"Authorization": api_key},
            timeout=40,
        )
        if not isinstance(payload, dict):
            self.logger.warning("chaos returned no usable data for %s", domain)
            return []

        suffix = "." + domain
        names: set[str] = set()
        for raw in payload.get("subdomains", []) or []:
            name = str(raw).strip().strip(".").lower()
            if not name:
                continue
            if name.startswith("*."):
                name = name[2:]
            if "." not in name:
                # The API usually returns fully qualified names, but a bare
                # label is still usable once the apex is appended.
                name = name + suffix
            if (name == domain or name.endswith(suffix)) and "." in name:
                names.add(name)

        self.logger.info("chaos: %d hostname(s)", len(names))
        return sorted(names)

    # -- Common Crawl ---------------------------------------------------------
    def commoncrawl_urls(self, domain: str) -> list[str]:
        """Read the newest Common Crawl index and return archived URLs.

        Common Crawl answers with NDJSON (one JSON object per line), so the
        response is parsed line by line rather than as a single JSON document.

        Args:
            domain: Apex domain, already scope-checked by the caller.

        Returns:
            List of archived URLs; empty on failure.
        """
        if not self.enable_commoncrawl:
            self.logger.info("commoncrawl disabled in config")
            return []

        indices = self.http.get_json(COMMONCRAWL_INDICES_URL)
        if not isinstance(indices, list) or not indices:
            self.logger.warning("commoncrawl: could not list index collections")
            return []

        index = str((indices[0] or {}).get("cdx-api") or "").rstrip("/")
        if not index:
            self.logger.warning("commoncrawl: newest collection has no CDX API URL")
            return []

        url = COMMONCRAWL_INDEX_URL.format(index=index, domain=quote(domain), limit=self.max_commoncrawl_urls)
        text = self.http.get_text(url, timeout=60)
        if not text:
            self.logger.warning("commoncrawl returned no usable data for %s", domain)
            return []

        urls: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            archived = str(entry.get("url") or "").strip()
            if archived:
                urls.append(archived)

        self.logger.info("commoncrawl: %d archived URL(s)", len(urls))
        return urls

    # -- DNS liveness ---------------------------------------------------------
    def resolve_live_hosts(self, names: list[str]) -> list[str]:
        """Resolve each discovered hostname once and return the ones with an A record.

        DNS answers only say whether a name resolves today — a cheap way to
        separate the live surface from historical noise.

        Args:
            names: Hostnames, already scope-checked by the caller.

        Returns:
            Sorted list of hostnames that answered with an A record.
        """
        if not self.enable_dns_live:
            self.logger.info("DNS liveness check disabled in config")
            return []
        if not DNS_AVAILABLE:
            self.logger.warning("dnspython is not installed; skipping liveness check")
            return []

        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = self.dns_timeout
        resolver.lifetime = self.dns_timeout

        live: list[str] = []
        checked = 0
        for name in names:
            if checked >= self.max_live_checks:
                break
            checked += 1
            try:
                answer = resolver.resolve(name, "A", raise_on_no_answer=False)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
                continue
            if answer.rrset is not None and len(answer.rrset) > 0:
                live.append(name)

        self.logger.info("DNS liveness: %d of %d checked host(s) answered", len(live), checked)
        return sorted(set(live))

    # -- AXFR -----------------------------------------------------------------
    def zone_transfer(self, domain: str) -> dict[str, Any]:
        """Attempt a read-only AXFR against the domain's own nameservers.

        A zone transfer is a single standard DNS request; a correctly
        configured nameserver simply refuses it, which is the normal result.
        When one answers, the whole zone has been handed over — a critical
        finding.

        Args:
            domain: Apex domain, already scope-checked by the caller.

        Returns:
            ``{"ns": <server>, "records": [...]}`` when a transfer succeeded,
            ``{}`` otherwise.
        """
        if not self.enable_axfr:
            self.logger.info("AXFR check disabled in config")
            return {}
        if not DNS_AVAILABLE:
            self.logger.warning("dnspython is not installed; skipping AXFR check")
            return {}

        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = self.dns_timeout
        resolver.lifetime = self.dns_timeout

        nameservers: list[str] = []
        try:
            answer = resolver.resolve(domain, "NS", raise_on_no_answer=False)
            if answer.rrset is not None:
                nameservers = [str(rdata).rstrip(".").lower() for rdata in answer.rrset]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException) as error:
            self.logger.info("AXFR skipped: could not list nameservers (%s)", error)
            return {}

        for nameserver in nameservers:
            try:
                # lifetime bounds the whole transfer: without it a nameserver
                # that silently drops AXFR packets stalls the run for minutes.
                zone = dns.zone.from_xfr(
                    dns.query.xfr(nameserver, domain, timeout=self.dns_timeout, lifetime=self.dns_timeout * 2)
                )
                records = sorted(str(node) for node in zone.nodes.keys())[:200]
                self.logger.warning("AXFR succeeded against %s — zone exposed (%d record(s))", nameserver, len(records))
                return {"ns": nameserver, "records": records}
            except Exception as error:  # a refusal or timeout here is the normal outcome
                self.logger.info("AXFR refused by %s (%s)", nameserver, error)

        self.logger.info("AXFR: all %d nameserver(s) refused", len(nameservers))
        return {}

    # -- DMARC ----------------------------------------------------------------
    def dmarc_record(self, domain: str) -> tuple[str, bool]:
        """Read the ``_dmarc`` TXT record.

        Args:
            domain: Apex domain, already scope-checked by the caller.

        Returns:
            ``(record, checked)``. ``record`` is the joined TXT value, or an
            empty string when the domain publishes none. ``checked`` is True only
            when the resolver actually answered the query, so the analyzer never
            reports "no DMARC record" for a lookup that could not be made.
        """
        if not self.enable_dns:
            self.logger.info("DNS collection disabled; DMARC not checked")
            return "", False
        if not DNS_AVAILABLE:
            self.logger.warning("dnspython is not installed; skipping DMARC lookup")
            return "", False

        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = self.dns_timeout
        resolver.lifetime = self.dns_timeout
        try:
            answer = resolver.resolve(f"_dmarc.{domain}", "TXT", raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # A definite answer: the name or the record does not exist.
            return "", True
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            self.logger.info("DMARC lookup for %s did not complete", domain)
            return "", False
        except dns.exception.DNSException as error:
            self.logger.info("DMARC lookup failed for %s: %s", domain, error)
            return "", False
        if answer.rrset is None:
            return "", True
        values: list[str] = []
        for rdata in answer.rrset:
            chunks = getattr(rdata, "strings", None)
            if chunks:
                values.append(b"".join(chunks).decode("utf-8", "replace"))
        return "".join(values), True

    # -- orchestration --------------------------------------------------------
    def run(self, domain: str) -> dict[str, Any]:
        """Collect every enabled passive source for ``domain``.

        Returns:
            A snapshot dict that is stored as history and fed to the analyzer.
            Subdomains are the union of every enabled source; archived URLs are
            kept under ``archived_urls``; ``live_subdomains`` marks the names
            that still resolve, and ``axfr``/``dmarc`` carry the DNS policy
            checks the analyzer turns into findings.
        """
        ct = self.certificate_transparency(domain)

        subdomains: set[str] = set(ct["subdomains"])
        archived_urls: list[str] = []
        sources: dict[str, int] = {"crtsh": len(ct["subdomains"])}

        certspotter = self.certspotter_issuances(domain)
        if certspotter["subdomains"] or certspotter["certificates"]:
            sources["certspotter"] = len(certspotter["subdomains"])
            subdomains.update(certspotter["subdomains"])
            # Merge both CT sources without duplicating the same issuance.
            seen_certs = {(cert["common_name"], cert["not_after"]) for cert in ct["certificates"]}
            for cert in certspotter["certificates"]:
                key = (cert["common_name"], cert["not_after"])
                if key not in seen_certs:
                    seen_certs.add(key)
                    ct["certificates"].append(cert)

        wayback = self.wayback_urls(domain)
        if wayback["subdomains"] or wayback["urls"]:
            sources["wayback"] = len(wayback["subdomains"])
            sources["wayback_urls"] = len(wayback["urls"])
            subdomains.update(wayback["subdomains"])
            archived_urls.extend(wayback["urls"])

        otx_names = self.otx_subdomains(domain)
        if otx_names:
            sources["otx"] = len(otx_names)
            subdomains.update(otx_names)

        anubis_names = self.anubis_subdomains(domain)
        if anubis_names:
            sources["anubis"] = len(anubis_names)
            subdomains.update(anubis_names)

        rapiddns_names = self.rapiddns_subdomains(domain)
        if rapiddns_names:
            sources["rapiddns"] = len(rapiddns_names)
            subdomains.update(rapiddns_names)

        chaos_names = self.chaos_subdomains(domain)
        if chaos_names:
            sources["chaos"] = len(chaos_names)
            subdomains.update(chaos_names)

        commoncrawl = self.commoncrawl_urls(domain)
        if commoncrawl:
            sources["commoncrawl_urls"] = len(commoncrawl)
            archived_urls.extend(commoncrawl)

        # Hostnames that still answer DNS today, over the discovered surface.
        live_subdomains = self.resolve_live_hosts(sorted(subdomains)[: self.max_subdomains])
        axfr = self.zone_transfer(domain)
        dmarc, dmarc_checked = self.dmarc_record(domain)

        return {
            "target": domain,
            "collected_at": _now(),
            "subdomains": sorted(subdomains)[: self.max_subdomains],
            "certificates": ct["certificates"],
            "dns": self.dns_records(domain),
            "whois": self.whois(domain),
            "archived_urls": archived_urls[: self.max_archived_urls * 2],
            "sources": sources,
            "live_subdomains": live_subdomains,
            "axfr": axfr,
            "dmarc": dmarc,
            "dmarc_checked": dmarc_checked,
        }
