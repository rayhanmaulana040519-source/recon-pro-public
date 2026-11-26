# Passive Bug Bounty Toolkit

A small, auditable Python toolkit that does **passive and OSINT-only** bug-bounty
reconnaissance and writes a report a triager can actually read.

It is built on one rule: **nothing happens before the target passes the scope
check**, and nothing it does is more invasive than a browser visiting the site.

## What it does

| Stage | What it collects | How |
| --- | --- | --- |
| Scope check | allow / deny decision per target, with the reason | `modules/scope_checker.py`, logged to `data/history/scope_history.jsonl` |
| Certificate transparency | subdomains, issuers, `not_before` / `not_after` | crt.sh + Cert Spotter, public APIs |
| Wayback archive | archived URLs, historical hostnames | Wayback Machine CDX (`web.archive.org`), free, no key |
| Common Crawl | archived URLs from the world-scale web archive | newest Common Crawl CDX index, free, no key |
| Passive DNS | historical subdomains | AlienVault OTX, Anubis, RapidDNS — free, no key; Chaos needs a free PDCP key (`PDCP_API_KEY` from <https://cloud.projectdiscovery.io>) |
| DNS policy | liveness of discovered names, AXFR attempt, DMARC/SPF | `dnspython`, read-only standard queries |
| JavaScript intelligence | exposed source maps, hard-coded credentials | same-origin scripts of probed hosts, `modules/js_intel.py` |
| DNS | A, AAAA, CNAME, MX, TXT, NS, SOA | system resolver via `dnspython` |
| Registration data | registrar, status, nameservers, events | RDAP (`rdap.org`), no WHOIS port 43 |
| HTTP header analysis | security headers, server, framework, cookies, CORS answer | one GET per host, root path only |
| TLS inspection | the certificate actually served today (issuer, dates, trust) and the negotiated protocol | one TLS handshake per probed host |
| robots.txt | the paths the site itself disallows for crawlers | one GET of `/robots.txt`, no path guessed |
| Technology detection | server, framework, CDN, CMS from headers/cookies/HTML markers | signature table in `modules/tech_detector.py` |
| History & diff | new/removed subdomains, technology, header, certificate and DNS changes | `modules/history_manager.py` |
| Analysis | explained findings with severity, impact, confidence and a manual check | `modules/analyzer.py` |
| Reporting | Markdown + JSON | `modules/report_generator.py`, `templates/report_template.md` |

## What it deliberately does **not** do

No port scanning, no directory or parameter brute force, no fuzzing, no payloads,
no authentication attempts, no exploitation, no active vulnerability scanning.
Those are separate, noisier activities that belong to a tool your program has
explicitly permitted. This toolkit stays inside passive collection and single
read-only requests.

## Project layout

```
bugbounty-toolkit/
├── config/
│   └── config.yaml            # scope, rate limit, proxies, collectors, report
├── modules/
│   ├── scope_checker.py       # strict allow/deny with an audit trail
│   ├── passive_recon.py       # crt.sh, Cert Spotter, Wayback, Common Crawl, OTX, Anubis, RapidDNS, DNS, RDAP
│   ├── js_intel.py            # same-origin scripts: source maps, hard-coded secrets
│   ├── tech_detector.py       # headers, technology, cookies, CORS probe
│   ├── history_manager.py     # snapshot storage + diff engine
│   ├── analyzer.py            # rule engine that explains each finding
│   ├── report_generator.py    # Markdown from template + JSON
│   └── notifier.py            # console summary + alerts.jsonl
├── utils/
│   ├── logger.py              # console + rotating file logging
│   └── http.py                # rate-limited client with proxy rotation
├── templates/
│   └── report_template.md     # report skeleton with {{TOKENS}}
├── data/history/              # per-target JSON snapshots
├── reports/                   # generated reports + example-report.md
├── logs/
├── main.py
├── requirements.txt
└── README.md
```

## Install

Requires Python 3.9 or newer.

The recommended path is the project-level setup, which creates the virtualenv
and installs the dependencies for you:

```bash
cd ..
bash setup.sh --python-only      # venv + requests, PyYAML, dnspython
bash recon.sh --fix-tools        # semua tool yang belum ada (arsenal + Python)
bash recon.sh --passive example.com
```

Manual install, if you prefer to run the toolkit on its own:

```bash
cd bugbounty-toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

When `recon.sh` runs the toolkit it records the domain in
`data/extra_scope.txt`, so your `config.yaml` (and its comments) never needs to
be edited by hand. `/passive` in the Telegram bot does the same thing.

## Configure

Edit `config/config.yaml` before the first run:

```yaml
scope:
  in_scope:
    - "example.com"          # only programs that explicitly authorize this
  out_of_scope:
    - "status.example.com"
  strict: true
```

Everything else has a working default. The two values worth reviewing:

* `http.per_host_delay` — seconds between two requests to the same host (1.0 by
  default; raise it if the program asks for slower testing).
* `http.proxies` — optional; when enabled, requests are rotated through the list.

## Run

The command works from **any** directory: every path in the config is resolved
against the toolkit folder, so there is no need to `cd` into it first.

```bash
python3 bugbounty-toolkit/main.py                 # list the domains in scope, send nothing
python3 bugbounty-toolkit/main.py example.com     # full passive run for one domain
python3 bugbounty-toolkit/main.py --all           # every domain in scope, one after another
python3 bugbounty-toolkit/main.py --dry-run example.com   # scope decision + plan, no requests
python3 bugbounty-toolkit/main.py --no-http example.com   # CT, archives, DNS and RDAP only
python3 bugbounty-toolkit/main.py -q example.com  # quiet console, log file only
```

From inside the toolkit folder the same commands are just `python3 main.py ...`.

Exit codes: `0` success, `1` unexpected error, `2` at least one target refused by
the scope check.

## Output

```
reports/example.com-20250116T101500Z.md      # human-readable report
reports/example.com-20250116T101500Z.json    # machine-readable twin
reports/alerts.jsonl                         # one JSON line per finding
data/history/example.com/<timestamp>.json    # snapshot for the next diff
logs/toolkit.log                             # full run log (rotating)
```

`reports/example-report.md` in this repository is a finished example of what a
report looks like, including the explanation format for each finding.

## Adding a rule

1. Add a `_rule_<name>(self, snapshot_or_host)` method to
   `modules/analyzer.py`.
2. Call it from `Analyzer.analyze`.
3. Use `self._add(...)` with the five texts (`what`, `why`, `impact`, `verify`,
   `recommendation`) and a severity. Nothing else needs to change: the report,
   the JSON and the console summary pick the finding up automatically.

`verify` must stay read-only: a single `curl`, `dig` or `openssl` command that
reproduces the observation without changing anything on the target.

## Adding a collector

1. Add a method to `modules/passive_recon.py` that returns plain data.
2. Call it from `PassiveRecon.run` and store the result in the snapshot.
3. Add the corresponding rule in `Analyzer` if the data can produce a finding.

Collectors must use the shared `HttpClient` so the rate limit, timeout, retries
and proxy settings apply.

## Proxies and privacy

`http.proxies.enabled: true` rotates every HTTP request through the list. Two
honest limitations:

* **DNS is not proxied.** `dnsx`-style lookups and `dnspython` resolution go to
  the resolver directly, so the resolver still sees which names you asked for.
* **The TLS handshake is not proxied either.** It is a raw socket to port 443 of
  the target, because `requests` cannot pass a proxy into a handshake it did not
  open.
* **RDAP, crt.sh, Cert Spotter, the Wayback CDX index, Common Crawl, OTX, Anubis
  and RapidDNS are third-party services.** They see your IP (or your proxy's IP)
  as any normal visitor would.

A proxy hides your address from the target; it does not make you anonymous.

## Ethics and legality

* Use this only on programs that explicitly list the target in scope, and follow
  the program's rules on rate, timing and prohibited techniques.
* The default is intentionally gentle: one request per host, one second apart.
  Do not lower `per_host_delay` to "finish faster" on a live program.
* Everything the toolkit reports is an observation. Verify by hand before you
  submit anything, and never present an unverified rule match as a vulnerability.
* Do not add rules or collectors that fuzz, brute-force or send payloads. If you
  need that, it is a different tool with a different permission conversation.
* Keep the report and the raw data private to the program you are working with.
