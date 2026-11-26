# Passive reconnaissance report — example.com

**Generated:** 2025-01-16 10:15:00 UTC  ·  **Target:** `example.com`

> Authorized bug-bounty research only. Everything below was collected passively
> or with single, ordinary HTTP GET requests against hosts inside the scope
> defined in `config/config.yaml`.

## Executive summary

This passive assessment of **example.com** produced **8 finding(s)** and recorded **8 change(s)** against the previous snapshot.

| Severity | Count |
| --- | --- |
| Critical | 0 |
| High | 5 |
| Medium | 1 |
| Low | 2 |
| Info | 0 |

> **Start with the critical and high findings.** Each one below names the impact in plain language and the exact read-only step that reproduces it.

## Target information

| Field | Value |
| --- | --- |
| Apex domain | `example.com` |
| Subdomains found | 27 |
| — from crt.sh | 18 |
| — from Cert Spotter | 12 |
| — from Wayback CDX | 9 |
| — from OTX passive DNS | 14 |
| — from Anubis | 11 |
| — from RapidDNS | 7 |
| Archived URLs (Wayback + Common Crawl) | 431 |
| — from Common Crawl | 131 |
| Hosts probed over HTTP | 12 |
| TLS certificates read directly | 11 host(s) |
| robots.txt paths disclosed | 6 |
| Live subdomains (DNS) | 16 |
| JavaScript scanned | 9 file(s), 1 secret(s), 2 source map(s) |
| Registrar (RDAP) | Example Registrar, Inc. |
| Certificate records (CT logs) | 48 |
| DNS record types answered | A, AAAA, CNAME, MX, NS, SOA, TXT |
| Run | 20250116T101500Z |

## Scope verification result

A target is touched only when it equals an in-scope entry or is one of its subdomains, and never when it matches an out-of-scope entry. Every decision is recorded in `data/history/scope_history.jsonl` with its reason.

* Strict mode: **on**
* In scope: `example.com`
* Out of scope: `status.example.com`, `billing.example.com`

## Methodology

Only public data and single, ordinary GET requests were used. No path was enumerated from a wordlist, no payload was sent, and nothing was brute-forced.

1. Certificate transparency (crt.sh and Cert Spotter) for subdomains and certificate dates.
2. Wayback Machine CDX index (web.archive.org) and the newest Common Crawl index for archived URLs.
3. AlienVault OTX, Anubis and RapidDNS passive datasets for historical subdomains.
4. DNS liveness check over the discovered names, an AXFR attempt and DMARC/SPF policy data.
5. Same-origin JavaScript intelligence: exposed source maps and hard-coded credentials.
6. One TLS handshake per probed host for the certificate actually served and its protocol version.
7. The site's own robots.txt, read once for the paths it discloses.
8. Public DNS records (A, AAAA, CNAME, MX, TXT, NS, SOA) via the system resolver.
9. Public registration data through RDAP (no WHOIS port 43 traffic).
10. One HTTP GET per host for headers, technology, cookies and a single CORS probe.
11. Comparison with the previous snapshot and rule-based analysis.

> DNS lookups and the TLS handshake are not proxied and leave from this host; crt.sh, RDAP and HTTP probes use the configured proxy when enabled.

## Findings

### F-01 · High (80) — Nameserver allows a full zone transfer (AXFR)

| Field | Value |
| --- | --- |
| Category | dns misconfiguration |
| Host | `example.com` |
| Confidence | confirmed |
| Evidence | `AXFR against ns1.example.net returned 184 record(s)` |

**What it is.** The nameserver hands out the complete DNS zone, including every internal hostname it knows, to any requester.

**Why it matters.** Zone transfer is meant for secondary nameservers only; public access exposes the entire naming plan.

**Impact.** An attacker receives a map of internal hosts, services and environments without touching any of them.

**How to verify it yourself.**

```bash
dig AXFR example.com @ns1.example.net  (a transfer that streams records confirms it)
```

**Recommended fix.** Restrict transfers to the primary's approved secondaries ('allow-transfer {'secondary-ip'; };') on every nameserver.

---

### F-02 · High (80) — TLS certificate is rejected by a verifying client

| Field | Value |
| --- | --- |
| Category | transport security |
| Host | `https://legacy.example.com` |
| Confidence | confirmed |
| Evidence | `https://legacy.example.com — handshake failed verification: certificate has expired (_ssl.c:1006)` |

**What it is.** A client that validates certificates could not accept the one this host presents.

**Why it matters.** Expired, self-signed or wrong-name certificates are refused before any content is shown.

**Impact.** Browsers show a full-page warning and well-behaved clients refuse the connection entirely, which trains users to click through warnings.

**How to verify it yourself.**

```bash
openssl s_client -connect <host>:443 -servername <host> </dev/null 2>&1 | grep -E 'verify|notAfter'
```

**Recommended fix.** Install a currently valid certificate that covers this exact hostname and automate renewal.

---

### F-03 · High (80) — CNAME points at a takeover-prone service

| Field | Value |
| --- | --- |
| Category | subdomain takeover candidate |
| Host | `example.com` |
| Confidence | unverified |
| Evidence | `CNAME dev.example.com -> example-dev.herokuapp.com` |

**What it is.** The record delegates this hostname to a third-party service that must still claim it.

**Why it matters.** If the service or app was deleted and was not re-claimed, anyone can register it and serve content for your hostname.

**Impact.** Full control of content on an in-scope host: brand phishing, cookie theft and allowlist bypass.

**How to verify it yourself.**

```bash
dig CNAME dev.example.com +short  then open the CNAME target and look for the provider's 'not found' page
```

**Recommended fix.** Remove the dangling record or re-create the service; keep a CNAME inventory and review it after every decommission.

---

### F-04 · High (80) — CORS policy allows a foreign origin

| Field | Value |
| --- | --- |
| Category | CORS misconfiguration |
| Host | `https://api.example.com` |
| Confidence | confirmed |
| Evidence | `https://api.example.com — Access-Control-Allow-Origin: https://recon-probe.invalid (sent Origin: https://recon-probe.invalid)` |

**What it is.** The endpoint answers a request from an origin it should not trust.

**Why it matters.** CORS is the browser rule that stops one site from reading another site's responses.

**Impact.** A malicious page can read authenticated responses for a signed-in user when credentials are allowed.

**How to verify it yourself.**

```bash
curl -sI -H 'Origin: https://recon-probe.invalid' https://api.example.com | grep -i access-control
```

**Recommended fix.** Validate Origin against an explicit allowlist and never combine a reflected origin with credentials.

---

### F-05 · High (80) — Hard-coded AWS access key ID in client JavaScript

| Field | Value |
| --- | --- |
| Category | secret in client code |
| Host | `https://www.example.com` |
| Confidence | possible |
| Evidence | `https://www.example.com/static/js/app.4f2c1a.js — pattern matched (masked): AKIA1B…Q7XZ` |

**What it is.** A JavaScript file served by the host contains a string in the exact format of a live credential.

**Why it matters.** Client-side code ships to every visitor, so anything hard-coded in it is public regardless of who was meant to read it.

**Impact.** If the value is real, it grants whatever the key can do — storage, email, cloud resources or an internal API — without authentication.

**How to verify it yourself.**

```bash
curl -s https://www.example.com/static/js/app.4f2c1a.js | grep -oE '<the matched pattern>'  then test the value against its own service before reporting
```

**Recommended fix.** Move the secret server-side or into a short-lived, least-privilege token, then rotate the exposed value immediately.

---

### F-06 · Medium (55) — Cookie session without the Secure attribute

| Field | Value |
| --- | --- |
| Category | insecure cookie |
| Host | `https://www.example.com` |
| Confidence | likely |
| Evidence | `https://www.example.com — Set-Cookie: session=[…]; Path=/; HttpOnly` |

**What it is.** The cookie can be sent over a plain-HTTP request.

**Why it matters.** Any downgrade to HTTP, or a mixed-content request, exposes the cookie on the wire.

**Impact.** Session hijacking for a user on a hostile network.

**How to verify it yourself.**

```bash
curl -sI https://www.example.com | grep -i '^set-cookie'  and read the cookie attributes
```

**Recommended fix.** Mark session cookies Secure, HttpOnly and SameSite=Lax (or Strict).

---

### F-07 · Low (30) — robots.txt discloses administration or internal paths

| Field | Value |
| --- | --- |
| Category | attack surface |
| Host | `https://www.example.com` |
| Confidence | confirmed |
| Evidence | `https://www.example.com/robots.txt disallows: /admin, /internal/api, /backup` |

**What it is.** The file meant to keep crawlers away lists the paths the owner considers sensitive.

**Why it matters.** robots.txt is public by design, so it also works as a shortlist for anyone looking for admin panels or internal tooling.

**Impact.** It removes the guesswork from finding management interfaces; the real risk depends on what answers there.

**How to verify it yourself.**

```bash
curl -s https://www.example.com/robots.txt  and read the Disallow lines
```

**Recommended fix.** Keep robots.txt free of sensitive paths and protect those paths with authentication and network controls instead.

---

### F-08 · Low (30) — Missing Strict-Transport-Security header

| Field | Value |
| --- | --- |
| Category | missing security header |
| Host | `https://www.example.com` |
| Confidence | confirmed |
| Evidence | `https://www.example.com — response headers did not include strict-transport-security` |

**What it is.** The HTTPS response does not tell the browser to stay on HTTPS for this host.

**Why it matters.** Without HSTS a single plain-HTTP request to the same host can be intercepted before the redirect happens.

**Impact.** An attacker on the path can downgrade the first request and capture session cookies or credentials.

**How to verify it yourself.**

```bash
curl -sI https://www.example.com/ | grep -i strict-transport-security  (no output means it is absent)
```

**Recommended fix.** Send Strict-Transport-Security with a one-year max-age, includeSubDomains and preload once you are ready.

---

## Changes detected

| Type | Item | Detail | Significance |
| --- | --- | --- | --- |
| subdomain | `dev.example.com` | subdomain added | medium |
| subdomain | `api-v2.example.com` | subdomain added | medium |
| live_subdomain | `staging.example.com` | host started resolving | medium |
| archived_url | `https://dev.example.com/api/v1/users?id=1` | archived URL added | low |
| technology | Cloudflare | technology added | low |
| header | `https://www.example.com · server` | header changed: nginx/1.18.0 -> nginx/1.24.0 | medium |
| dns | `TXT v=spf1 include:_spf.example.net ~all` | TXT record added | medium |
| certificate | `certificate` | latest certificate not_after changed: 2025-03-02 -> 2025-06-30 | medium |

## Risk assessment

**Overall risk: high.** At least one high-severity issue is present.

The rating follows the highest confirmed severity, weighted by confidence: a `likely` finding that still needs a manual step is never presented as proven.

## Recommendations

Ordered by severity, the fixes worth doing first:

* **High** — Restrict transfers to the primary's approved secondaries on every nameserver.
* **High** — Install a currently valid certificate that covers this exact hostname and automate renewal.
* **High** — Remove the dangling record or re-create the service; keep a CNAME inventory and review it after every decommission.
* **High** — Validate Origin against an explicit allowlist and never combine a reflected origin with credentials.
* **High** — Move the secret server-side or into a short-lived, least-privilege token, then rotate the exposed value immediately.
* **Medium** — Mark session cookies Secure, HttpOnly and SameSite=Lax (or Strict).
* **Low** — Keep robots.txt free of sensitive paths and protect those paths with authentication and network controls instead.
* **Low** — Send Strict-Transport-Security with a one-year max-age, includeSubDomains and preload once you are ready.

After the fixes, re-run the toolkit and compare the new report with this one: the finding should disappear and the change list should show only intended work.

## Appendix

### Collected subdomains

```
api.example.com
api-v2.example.com
backup.example.com
dev.example.com
docs.example.com
legacy.example.com
mail.example.com
staging.example.com
status.example.com
www.example.com
```

### DNS records

| Type | Value |
| --- | --- |
| A | `93.184.216.34` |
| AAAA | `2606:2800:220:1:248:1893:25c8:1946` |
| CNAME | `example-dev.herokuapp.com` |
| MX | `10 mail.example.com` |
| NS | `a.iana-servers.net` |
| SOA | `a.iana-servers.net. hostmaster.example.com. 2025011601 7200 3600 1209600 3600` |
| TXT | `v=spf1 include:_spf.example.net ~all` |

### Probed hosts

| URL | Status | Technologies |
| --- | --- | --- |
| `https://example.com` | 200 | nginx, Cloudflare |
| `https://api.example.com` | 200 | Express |
| `https://www.example.com` | 200 | nginx, WordPress |
| `https://legacy.example.com` | 200 | Apache HTTP Server, PHP |

## Metadata

* tool: Passive Bug Bounty Toolkit 2.1.0
* author: rey
* run_id: 20250116T101500Z
* generated_at: 2025-01-16 10:15:00 UTC
* config: bugbounty-toolkit/config/config.yaml
* previous_snapshot: bugbounty-toolkit/data/history/example.com/20250109T090000Z.json
* proxy: enabled
* dns_note: DNS lookups and the TLS handshake are not proxied and leave from this host; crt.sh, RDAP and HTTP probes use the configured proxy when enabled.

_Authorized scope only. This toolkit performs passive collection and single read-only requests; it contains no scanner, brute force, fuzzing or exploit code._
