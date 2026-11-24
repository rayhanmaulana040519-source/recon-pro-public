# Passive reconnaissance report — example.com

**Generated:** 2025-01-16 10:15:00 UTC  ·  **Target:** `example.com`

> Authorized bug-bounty research only. Everything below was collected passively
> or with single, ordinary HTTP GET requests against hosts inside the scope
> defined in `config/config.yaml`.

## Executive summary

This passive assessment of **example.com** produced **4 finding(s)** and recorded **6 change(s)** against the previous snapshot.

| Severity | Count |
| --- | --- |
| Critical | 0 |
| High | 2 |
| Medium | 1 |
| Low | 1 |
| Info | 0 |

> **Start with the critical and high findings.** Each one below names the impact in plain language and the exact read-only step that reproduces it.

## Target information

| Field | Value |
| --- | --- |
| Apex domain | `example.com` |
| Subdomains found | 12 |
| Hosts probed over HTTP | 12 |
| Registrar (RDAP) | Example Registrar, Inc. |
| Certificate records (crt.sh) | 31 |
| DNS record types answered | A, CNAME, MX, NS, SOA, TXT |
| Run | 20250116T101500Z |

## Scope verification result

A target is touched only when it equals an in-scope entry or is one of its subdomains, and never when it matches an out-of-scope entry. Every decision is recorded in `data/history/scope_history.jsonl` with its reason.

* Strict mode: **on**
* In scope: `example.com`
* Out of scope: `status.example.com`, `billing.example.com`

## Methodology

Only public data and single, ordinary GET requests were used. No path was enumerated from a wordlist, no payload was sent, and nothing was brute-forced.

1. Certificate transparency (crt.sh) for subdomains and certificate dates.
2. Public DNS records (A, AAAA, CNAME, MX, TXT, NS, SOA) via the system resolver.
3. Public registration data through RDAP (no WHOIS port 43 traffic).
4. One HTTP GET per host for headers, technology, cookies and a single CORS probe.
5. Comparison with the previous snapshot and rule-based analysis.

> DNS lookups are not proxied and leave from this host; crt.sh, RDAP and HTTP probes use the configured proxy when enabled.

## Findings

### F-01 · High (80) — CNAME points at a takeover-prone service

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

### F-02 · High (80) — CORS policy allows a foreign origin

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

### F-03 · Medium (55) — Cookie session without the Secure attribute

| Field | Value |
| --- | --- |
| Category | insecure cookie |
| Host | `https://www.example.com` |
| Confidence | likely |
| Evidence | `https://www.example.com — Set-Cookie: session=8f14e45fceea; Path=/; HttpOnly` |

**What it is.** The cookie can be sent over a plain-HTTP request.

**Why it matters.** Any downgrade to HTTP, or a mixed-content request, exposes the cookie on the wire.

**Impact.** Session hijacking for a user on a hostile network.

**How to verify it yourself.**

```bash
curl -sI https://www.example.com | grep -i '^set-cookie'  and read the cookie attributes
```

**Recommended fix.** Mark session cookies Secure, HttpOnly and SameSite=Lax (or Strict).

---

### F-04 · Low (30) — Missing Strict-Transport-Security header

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
| technology | Cloudflare | technology added | low |
| header | `https://www.example.com · server` | header changed: nginx/1.18.0 -> nginx/1.24.0 | medium |
| dns | `TXT v=spf1 include:_spf.example.net ~all` | TXT record added | medium |
| certificate | `certificate` | latest certificate not_after changed: 2025-03-02 -> 2025-06-30 | medium |

## Risk assessment

**Overall risk: high.** At least one high-severity issue is present.

The rating follows the highest confirmed severity, weighted by confidence: a `likely` finding that still needs a manual step is never presented as proven.

## Recommendations

Ordered by severity, the fixes worth doing first:

* **High** — Remove the dangling record or re-create the service; keep a CNAME inventory and review it after every decommission.
* **High** — Validate Origin against an explicit allowlist and never combine a reflected origin with credentials.
* **Medium** — Mark session cookies Secure, HttpOnly and SameSite=Lax (or Strict).
* **Low** — Send Strict-Transport-Security with a one-year max-age, includeSubDomains and preload once you are ready.

After the fixes, re-run the toolkit and compare the new report with this one: the finding should disappear and the change list should show only intended work.

## Appendix

### Collected subdomains

```
api.example.com
api-v2.example.com
dev.example.com
docs.example.com
mail.example.com
status.example.com
www.example.com
```

### DNS records

| Type | Value |
| --- | --- |
| A | `93.184.216.34` |
| CNAME | `example-dev.herokuapp.com` |
| MX | `10 mail.example.com` |
| NS | `a.iana-servers.net` |
| TXT | `v=spf1 include:_spf.example.net ~all` |

### Probed hosts

| URL | Status | Technologies |
| --- | --- | --- |
| `https://example.com` | 200 | nginx, Cloudflare |
| `https://api.example.com` | 200 | Express |
| `https://www.example.com` | 200 | nginx, WordPress |

## Metadata

* tool: Passive Bug Bounty Toolkit 1.0.0
* author: rey
* run_id: 20250116T101500Z
* generated_at: 2025-01-16 10:15:00 UTC
* config: config/config.yaml
* previous_snapshot: data/history/example.com/20250109T090000Z.json
* proxy: enabled
* dns_note: DNS lookups are not proxied and leave from this host; crt.sh, RDAP and HTTP probes use the configured proxy when enabled.

_Authorized scope only. This toolkit performs passive collection and single read-only requests; it contains no scanner, brute force, fuzzing or exploit code._
