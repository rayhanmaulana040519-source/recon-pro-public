"""Passive reconnaissance: certificate transparency, DNS and RDAP WHOIS.

Everything here reads public data or performs a single plain GET. No paths are
enumerated, no payloads are sent, and no target is touched beyond what a normal
browser visit would do.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping
from urllib.parse import quote

try:  # dnspython is optional at import time so one missing dep cannot break the CLI
    import dns.exception
    import dns.resolver

    DNS_AVAILABLE = True
except ImportError:  # pragma: no cover - handled at runtime with a warning
    DNS_AVAILABLE = False


CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
RDAP_URL = "https://rdap.org/domain/{domain}"


def _now() -> str:
    """Current UTC timestamp in ISO-8601 form."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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

    # -- orchestration --------------------------------------------------------
    def run(self, domain: str) -> dict[str, Any]:
        """Collect every enabled passive source for ``domain``.

        Returns:
            A snapshot dict that is stored as history and fed to the analyzer.
        """
        ct = self.certificate_transparency(domain)
        return {
            "target": domain,
            "collected_at": _now(),
            "subdomains": ct["subdomains"],
            "certificates": ct["certificates"],
            "dns": self.dns_records(domain),
            "whois": self.whois(domain),
        }
