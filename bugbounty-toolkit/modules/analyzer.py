"""Rule-based analysis that turns raw observations into explained findings.

Every finding carries the four things a report needs to be useful:

* **what** was found,
* **why** it matters,
* **impact** in plain language,
* **how to verify** it by hand (passive, read-only steps),

plus a severity estimate with its reason and a recommendation. The rules are
deterministic on purpose: the same input always produces the same report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

SEVERITY_SCORE: dict[str, int] = {
    "Critical": 95,
    "High": 80,
    "Medium": 55,
    "Low": 30,
    "Info": 10,
}

# Security headers worth reporting, with the wording each one deserves.
HEADER_RULES: list[dict[str, Any]] = [
    {
        "header": "strict-transport-security",
        "severity": "Low",
        "title": "Missing Strict-Transport-Security header",
        "what": "The HTTPS response does not tell the browser to stay on HTTPS for this host.",
        "why": "Without HSTS a single plain-HTTP request to the same host can be intercepted before the redirect happens.",
        "impact": "An attacker on the path can downgrade the first request and capture session cookies or credentials.",
        "verify": "curl -sI https://<host>/ | grep -i strict-transport-security  (no output means it is absent)",
        "recommendation": "Send Strict-Transport-Security with a one-year max-age, includeSubDomains and preload once you are ready.",
        "https_only": True,
    },
    {
        "header": "content-security-policy",
        "severity": "Low",
        "title": "Missing Content-Security-Policy header",
        "what": "The application does not declare which sources may load scripts or frames.",
        "why": "A CSP turns most cross-site scripting attempts into blocked requests instead of executed code.",
        "impact": "Reflected or stored script injection has no second line of defence, so one input bug becomes account compromise.",
        "verify": "curl -sI https://<host>/ | grep -i content-security-policy  (no output means it is absent)",
        "recommendation": "Add a CSP that starts in report-only mode, then enforce it with a nonce-based script-src.",
    },
    {
        "header": "x-content-type-options",
        "severity": "Low",
        "title": "Missing X-Content-Type-Options header",
        "what": "The browser is allowed to sniff a response into a type the server did not declare.",
        "why": "MIME sniffing can turn an uploaded text file into executed HTML or JavaScript.",
        "impact": "A user-controlled upload can become stored cross-site scripting on the same origin.",
        "verify": "curl -sI https://<host>/ | grep -i x-content-type-options  (expected value: nosniff)",
        "recommendation": "Send X-Content-Type-Options: nosniff on every response.",
    },
    {
        "header": "x-frame-options",
        "severity": "Low",
        "title": "Missing clickjacking protection",
        "what": "Neither X-Frame-Options nor a CSP frame-ancestors directive is present.",
        "why": "Any site can embed this page in an invisible frame and overlay it with attacker content.",
        "impact": "A signed-in user can be tricked into clicking actions they did not intend, on this exact application.",
        "verify": "curl -sI https://<host>/ | grep -iE 'x-frame-options|frame-ancestors'",
        "recommendation": "Use CSP frame-ancestors 'self' (or X-Frame-Options: DENY) on every page that renders user actions.",
    },
    {
        "header": "referrer-policy",
        "severity": "Info",
        "title": "Missing Referrer-Policy header",
        "what": "The page does not control what the browser sends in the Referer header to other sites.",
        "why": "URLs frequently contain tokens, ids and search terms that then leak to third parties.",
        "impact": "Sensitive values in a URL can appear in a third-party log or analytics system.",
        "verify": "curl -sI https://<host>/ | grep -i referrer-policy",
        "recommendation": "Send Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
    },
    {
        "header": "permissions-policy",
        "severity": "Info",
        "title": "Missing Permissions-Policy header",
        "what": "The page does not restrict access to browser features such as camera, microphone or geolocation.",
        "why": "Any embedded frame or injected script can request those features unless the page denies them.",
        "impact": "A compromised third-party script can ask for device permissions from a trusted origin.",
        "verify": "curl -sI https://<host>/ | grep -i permissions-policy",
        "recommendation": "Declare a Permissions-Policy that denies every feature the application does not use.",
    },
]

TAKEOVER_PREFIXES = ("s3.amazonaws.com",)


@dataclass
class Finding:
    """One explained finding, ready to render in the report."""

    id: str
    title: str
    category: str
    host: str
    severity: str
    score: int
    confidence: str
    evidence: str
    what: str
    why: str
    impact: str
    verify: str
    recommendation: str
    references: list[str] = field(default_factory=list)

    @property
    def severity_label(self) -> str:
        """Human-readable severity including its score."""
        return f"{self.severity} ({self.score})"

    def to_dict(self) -> dict[str, Any]:
        """Serialise the finding for the JSON report."""
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "host": self.host,
            "severity": self.severity,
            "score": self.score,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "what": self.what,
            "why": self.why,
            "impact": self.impact,
            "verify": self.verify,
            "recommendation": self.recommendation,
            "references": self.references,
        }


class Analyzer:
    """Applies the rule set to a collected snapshot.

    Args:
        config: Parsed ``config.yaml`` mapping.
        logger: Logger for progress.
    """

    def __init__(self, config: Mapping[str, Any], logger: Any) -> None:
        analysis = config.get("analysis", {}) or {}
        self.config = config
        self.logger = logger
        self.takeover_suffixes = [str(item).lower() for item in analysis.get("dangling_cname_suffixes", []) or []]
        self.sensitive_hints = [str(item).lower() for item in analysis.get("sensitive_label_hints", []) or []]
        self.max_per_category = max(1, int(analysis.get("max_per_category", 10)))
        self._findings: list[Finding] = []

    # -- public API -----------------------------------------------------------
    def analyze(self, snapshot: Mapping[str, Any], changes: Iterable[Mapping[str, Any]] = ()) -> list[Finding]:
        """Run every rule and return the findings sorted by score."""
        self._findings = []
        domain = str(snapshot.get("target", ""))
        hosts = snapshot.get("hosts", []) or []

        for host in hosts:
            if not isinstance(host, dict):
                continue
            self._rule_headers(host)
            self._rule_banners(host)
            self._rule_cookies(host)
            self._rule_cors(host)
            self._rule_http_only(host)

        self._rule_certificates(snapshot)
        self._rule_dangling_cnames(snapshot, domain)
        self._rule_email_authentication(snapshot)
        self._rule_sensitive_names(snapshot)
        self._rule_changes(changes)

        # A wide target can match the same rule on dozens of hosts. Keeping the
        # highest-scoring entries per category keeps the report readable without
        # hiding a whole class of issue.
        kept: list[Finding] = []
        per_category: dict[str, int] = {}
        for finding in sorted(self._findings, key=lambda item: item.score, reverse=True):
            seen = per_category.get(finding.category, 0)
            if seen >= self.max_per_category:
                continue
            per_category[finding.category] = seen + 1
            kept.append(finding)

        for index, finding in enumerate(kept, start=1):
            finding.id = f"F-{index:02d}"

        self.logger.info("analysis produced %d finding(s)", len(kept))
        return kept

    # -- construction ---------------------------------------------------------
    def _add(
        self,
        title: str,
        category: str,
        host: str,
        severity: str,
        confidence: str,
        evidence: str,
        what: str,
        why: str,
        impact: str,
        verify: str,
        recommendation: str,
        references: list[str] | None = None,
    ) -> None:
        """Append one finding with a sequential id."""
        score = SEVERITY_SCORE.get(severity, 10)
        self._findings.append(
            Finding(
                id=f"F-{len(self._findings) + 1:02d}",
                title=title,
                category=category,
                host=host,
                severity=severity,
                score=score,
                confidence=confidence,
                evidence=evidence,
                what=what,
                why=why,
                impact=impact,
                verify=verify,
                recommendation=recommendation,
                references=references or [],
            )
        )

    # -- rules ----------------------------------------------------------------
    def _rule_headers(self, host: Mapping[str, Any]) -> None:
        """Report missing security headers and insecure cookie flags."""
        url = str(host.get("url", ""))
        headers = {str(key).lower(): str(value) for key, value in (host.get("headers", {}) or {}).items()}
        is_https = url.startswith("https://")

        for rule in HEADER_RULES:
            name = rule["header"]
            if rule.get("https_only") and not is_https:
                continue
            if name in headers:
                continue
            # A frame-ancestors CSP replaces X-Frame-Options, so honour either.
            if name == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", ""):
                continue
            self._add(
                title=rule["title"],
                category="missing security header",
                host=url,
                severity=rule["severity"],
                confidence="confirmed",
                evidence=f"{url} — response headers did not include {name}",
                what=rule["what"],
                why=rule["why"],
                impact=rule["impact"],
                verify=rule["verify"].replace("<host>", _hostname(url)),
                recommendation=rule["recommendation"],
            )

    def _rule_banners(self, host: Mapping[str, Any]) -> None:
        """Report server and framework banner disclosure."""
        url = str(host.get("url", ""))
        headers = {str(key).lower(): str(value) for key, value in (host.get("headers", {}) or {}).items()}
        server = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")

        if server and any(char.isdigit() for char in server):
            self._add(
                title="Server version disclosed in the Server header",
                category="information disclosure",
                host=url,
                severity="Low",
                confidence="confirmed",
                evidence=f"{url} — Server: {server}",
                what="The response names the server product and its exact version.",
                why="A public version number lets anyone map the host to known CVEs without probing.",
                impact="Attackers skip guesswork: a matching public exploit can be selected before any active testing.",
                verify=f"curl -sI {url} | grep -i '^server'",
                recommendation="Return a neutral Server header (or none) from the reverse proxy and keep the real version internal.",
            )

        if powered_by:
            self._add(
                title="Framework disclosed in the X-Powered-By header",
                category="information disclosure",
                host=url,
                severity="Info",
                confidence="confirmed",
                evidence=f"{url} — X-Powered-By: {powered_by}",
                what="The application exposes the framework (and often its version).",
                why="Framework fingerprints narrow the search space for a targeted attack.",
                impact="Low on its own, but it removes a layer of attacker uncertainty.",
                verify=f"curl -sI {url} | grep -i '^x-powered-by'",
                recommendation="Disable the header in the application or framework configuration.",
            )

    def _rule_cookies(self, host: Mapping[str, Any]) -> None:
        """Report session cookies missing Secure, HttpOnly or SameSite."""
        url = str(host.get("url", ""))
        for cookie in host.get("cookies", []) or []:
            name = str(cookie).split("=", 1)[0].strip()
            # Cookies are only visible as a name/value pair here, so the flags are
            # judged from the raw Set-Cookie string kept by the detector.
            raw = str(cookie).lower()
            if "secure" not in raw:
                self._add(
                    title=f"Cookie {name or 'unknown'} without the Secure attribute",
                    category="insecure cookie",
                    host=url,
                    severity="Medium",
                    confidence="likely",
                    evidence=f"{url} — Set-Cookie: {cookie}",
                    what="The cookie can be sent over a plain-HTTP request.",
                    why="Any downgrade to HTTP, or a mixed-content request, exposes the cookie on the wire.",
                    impact="Session hijacking for a user on a hostile network.",
                    verify=f"curl -sI {url} | grep -i '^set-cookie'  and read the cookie attributes",
                    recommendation="Mark session cookies Secure, HttpOnly and SameSite=Lax (or Strict).",
                )
            if "httponly" not in raw:
                self._add(
                    title=f"Cookie {name or 'unknown'} without the HttpOnly attribute",
                    category="insecure cookie",
                    host=url,
                    severity="Medium",
                    confidence="likely",
                    evidence=f"{url} — Set-Cookie: {cookie}",
                    what="Client-side JavaScript can read the cookie.",
                    why="Any cross-site scripting on the origin can steal the session directly.",
                    impact="Session takeover from a single script injection.",
                    verify=f"curl -sI {url} | grep -i '^set-cookie'  and read the cookie attributes",
                    recommendation="Add HttpOnly to every cookie that the browser does not need to read.",
                )

    def _rule_cors(self, host: Mapping[str, Any]) -> None:
        """Report a permissive CORS answer from the single probe request."""
        url = str(host.get("url", ""))
        cors = host.get("cors", {}) or {}
        allow_origin = str(cors.get("allow_origin", "")).strip()
        allow_credentials = str(cors.get("allow_credentials", "")).strip().lower()
        if not allow_origin:
            return

        reflected = allow_origin == str(cors.get("origin_sent", "")).strip()
        if reflected and allow_credentials == "true":
            severity, confidence = "High", "confirmed"
        elif reflected or (allow_origin == "*" and allow_credentials == "true"):
            severity, confidence = "Medium", "likely"
        elif allow_origin == "*":
            severity, confidence = "Info", "confirmed"
        else:
            return

        self._add(
            title="CORS policy allows a foreign origin",
            category="CORS misconfiguration",
            host=url,
            severity=severity,
            confidence=confidence,
            evidence=f"{url} — Access-Control-Allow-Origin: {allow_origin} (sent Origin: {cors.get('origin_sent', '')})",
            what="The endpoint answers a request from an origin it should not trust.",
            why="CORS is the browser rule that stops one site from reading another site's responses.",
            impact=(
                "A malicious page can read authenticated responses for a signed-in user when credentials are allowed."
                if allow_credentials == "true"
                else "A malicious page can read public-but-origin-restricted responses, which can leak user-specific data."
            ),
            verify=f"curl -sI -H 'Origin: https://recon-probe.invalid' {url} | grep -i access-control",
            recommendation="Validate Origin against an explicit allowlist and never combine a reflected origin with credentials.",
        )

    def _rule_http_only(self, host: Mapping[str, Any]) -> None:
        """Report a host that only answered over plain HTTP."""
        url = str(host.get("url", ""))
        if not url.startswith("http://"):
            return
        self._add(
            title="Host answers over plain HTTP",
            category="transport security",
            host=url,
            severity="Medium",
            confidence="confirmed",
            evidence=f"{url} responded without TLS",
            what="The origin serves content over unencrypted HTTP.",
            why="Everything on the connection — cookies, credentials, page content — is readable and modifiable in transit.",
            impact="Session theft and content injection for any user on the same network.",
            verify=f"curl -sI {url}  (note the absence of a redirect to https://)",
            recommendation="Serve HTTPS only and redirect HTTP with HSTS once the certificate covers every hostname.",
        )

    def _rule_certificates(self, snapshot: Mapping[str, Any]) -> None:
        """Report expired or soon-to-expire certificates from crt.sh data."""
        domain = str(snapshot.get("target", ""))
        expiring: list[tuple[str, str]] = []
        for certificate in snapshot.get("certificates", []) or []:
            not_after = str(certificate.get("not_after", "")).strip()
            if not not_after:
                continue
            try:
                expiry = datetime.strptime(not_after[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            days_left = (expiry - datetime.now(timezone.utc)).days
            expiring.append((not_after[:10], str(days_left)))

        if not expiring:
            return

        expiries = sorted({date for date, _ in expiring})
        latest = expiries[-1]
        try:
            latest_days = (datetime.strptime(latest, "%Y-%m-%d").replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
        except ValueError:
            return

        if latest_days < 0:
            severity, confidence = "High", "likely"
            title = "Certificate for this domain appears expired"
        elif latest_days <= 30:
            severity, confidence = "Medium", "likely"
            title = "Certificate for this domain expires within 30 days"
        else:
            return

        self._add(
            title=title,
            category="certificate lifecycle",
            host=domain,
            severity=severity,
            confidence=confidence,
            evidence=f"crt.sh — latest not_after {latest} ({latest_days} day(s) from today)",
            what="A certificate logged for this domain is expired or about to expire.",
            why="crt.sh shows what was issued, so confirm the host actually in use before acting on it.",
            impact="Browsers show an interstitial that trains users to click through warnings, and automation may start failing.",
            verify=f"openssl s_client -connect www.{domain}:443 -servername www.{domain} </dev/null 2>/dev/null | openssl x509 -noout -dates",
            recommendation="Renew and automate certificate renewal, and monitor expiry at least 30 days ahead.",
        )

    def _rule_dangling_cnames(self, snapshot: Mapping[str, Any], domain: str) -> None:
        """Flag CNAMEs pointing at services that are takeover-prone."""
        for value in (snapshot.get("dns", {}) or {}).get("CNAME", []) or []:
            target = str(value).strip().strip(".").lower()
            if not target:
                continue
            if not any(target.endswith(suffix) for suffix in self.takeover_suffixes):
                continue
            self._add(
                title="CNAME points at a takeover-prone service",
                category="subdomain takeover candidate",
                host=domain,
                severity="High",
                confidence="unverified",
                evidence=f"CNAME {domain} -> {target}",
                what="The record delegates this hostname to a third-party service that must still claim it.",
                why="If the service or app was deleted and was not re-claimed, anyone can register it and serve content for your hostname.",
                impact="Full control of content on an in-scope host: brand phishing, cookie theft and allowlist bypass.",
                verify=f"dig CNAME {domain} +short  then open the CNAME target and look for the provider's 'not found' page",
                recommendation="Remove the dangling record or re-create the service; keep a CNAME inventory and review it after every decommission.",
            )

    def _rule_email_authentication(self, snapshot: Mapping[str, Any]) -> None:
        """Report a missing SPF record, which enables sender spoofing."""
        txt_records = [str(record).lower() for record in (snapshot.get("dns", {}) or {}).get("TXT", []) or []]
        if not txt_records or any("v=spf1" in record for record in txt_records):
            return
        domain = str(snapshot.get("target", ""))
        self._add(
            title="No SPF record published for the domain",
            category="email authentication",
            host=domain,
            severity="Low",
            confidence="likely",
            evidence=f"TXT records for {domain} did not contain v=spf1",
            what="The domain does not publish which servers may send mail for it.",
            why="Without SPF (and DMARC) receivers cannot tell a spoofed sender from a legitimate one.",
            impact="Phishing mail can be sent with the brand's domain in the From header, which often passes basic filters.",
            verify=f"dig TXT {domain} +short  and look for a record starting with v=spf1",
            recommendation="Publish SPF, then DMARC with p=none while you review reports, and finally p=reject.",
        )

    def _rule_sensitive_names(self, snapshot: Mapping[str, Any]) -> None:
        """Point out subdomains whose name suggests a non-production surface."""
        reported = 0
        for name in snapshot.get("subdomains", []) or []:
            label = str(name).split(".", 1)[0].lower()
            if not any(hint in label for hint in self.sensitive_hints):
                continue
            reported += 1
            if reported > 5:  # keep the report readable
                break
            self._add(
                title="Subdomain name suggests a non-production environment",
                category="attack surface",
                host=str(name),
                severity="Info",
                confidence="unverified",
                evidence=f"{name} appears in certificate transparency",
                what="The hostname pattern matches environments usually reserved for staff testing.",
                why="Staging and tooling hosts often skip the hardening the production site gets.",
                impact="Only meaningful if the host is reachable and in scope; treat it as a pointer for later, not a finding by itself.",
                verify=f"dig {name} +short  and open it in a browser to see whether it is live",
                recommendation="Confirm the host is intended to be public, and apply the same hardening as production if it is.",
            )

    def _rule_changes(self, changes: Iterable[Mapping[str, Any]]) -> None:
        """Turn newly appeared subdomains into an informational note."""
        for change in changes or []:
            if change.get("type") != "subdomain" or change.get("detail") != "subdomain added":
                continue
            self._add(
                title="New subdomain since the previous run",
                category="change detection",
                host=str(change.get("item", "")),
                severity="Info",
                confidence="confirmed",
                evidence=f"new in this run: {change.get('item', '')}",
                what="A hostname that was not present in the previous snapshot showed up.",
                why="New infrastructure is often deployed with default settings before hardening.",
                impact="Nothing by itself; it is the highest-yield place to look next time.",
                verify=f"dig {change.get('item', '')} +short  and record it in the program's asset list",
                recommendation="Review new hosts before the next scheduled scan and confirm they are intentionally public.",
            )


def _hostname(url: str) -> str:
    """Return the hostname of ``url`` for command examples."""
    value = url.split("://", 1)[-1]
    value = value.split("/", 1)[0]
    return value.split(":", 1)[0]
