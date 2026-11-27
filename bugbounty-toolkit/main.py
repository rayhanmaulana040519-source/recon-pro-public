#!/usr/bin/env python3
"""Entry point for the passive bug-bounty toolkit.

The pipeline for one target is deliberately linear and easy to audit:

1. scope check (hard stop when the target is not authorized),
2. passive collection (certificate transparency, DNS, RDAP),
3. one benign GET per discovered host (headers, technology, cookies, CORS),
4. save the snapshot and diff it against the previous run,
5. analyse everything into explained findings,
6. write Markdown + JSON reports and print a summary.

No stage fuzzes, brute-forces, guesses paths or sends payloads.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from modules.ai_triage import summarize_findings
from modules.analyzer import Analyzer
from modules.history_manager import HistoryManager
from modules.js_intel import JsIntel
from modules.notifier import Notifier
from modules.passive_recon import PassiveRecon
from modules.report_generator import ReportGenerator
from modules.scope_checker import ScopeChecker, ScopeViolation
from modules.tech_detector import TechDetector
from utils.http import HttpClient
from utils.logger import setup_logger

# Paths are anchored on the toolkit folder, so the command works from any
# directory instead of only from the folder itself.
TOOLKIT_ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = TOOLKIT_ROOT / "config" / "config.yaml"
TOOL_NAME = "Passive Bug Bounty Toolkit"

# Config keys whose value is a path that must resolve against TOOLKIT_ROOT.
PATH_KEYS: dict[str, tuple[str, ...]] = {
    "data": ("history_dir",),
    "report": ("output_dir", "markdown_template"),
    "logging": ("file",),
    "scope": ("history_file", "extra_scope_file"),
    "notify": ("alerts_file",),
}


def load_config(path: Path) -> dict[str, Any]:
    """Load and validate the YAML configuration.

    Every path inside the file is rewritten to an absolute path under the
    toolkit folder, so the toolkit behaves the same from any working directory.

    Args:
        path: Path to ``config.yaml``.

    Returns:
        The parsed configuration mapping.

    Raises:
        SystemExit: when the file is missing or is not a mapping.
    """
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        sys.exit(f"ERROR: config file not found: {path}")
    except (OSError, yaml.YAMLError) as error:
        sys.exit(f"ERROR: could not read {path}: {error}")
    if not isinstance(raw, dict):
        sys.exit(f"ERROR: {path} must contain a YAML mapping")
    return _resolve_paths(raw)


def _resolve_paths(config: dict[str, Any]) -> dict[str, Any]:
    """Rewrite the configured relative paths to absolute ones under the toolkit."""
    for section_name, keys in PATH_KEYS.items():
        section = config.get(section_name)
        if not isinstance(section, dict):
            continue
        for key in keys:
            value = section.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            candidate = Path(os.path.expanduser(value.strip()))
            section[key] = candidate if candidate.is_absolute() else (TOOLKIT_ROOT / candidate)
    return config


def print_scope(checker: ScopeChecker) -> None:
    """List the domains this installation may touch, without sending anything."""
    domains = sorted(set(checker.in_scope))
    if not domains:
        print("Scope kosong. Tambahkan domain ke scope.in_scope di config.yaml.")
        return
    print("Domain dalam scope ({}):".format(len(domains)))
    for domain in domains:
        print("  - {}".format(domain))
    print("")
    print("Jalankan: python3 main.py <domain>   atau   python3 main.py --all")


def collect(
    target: str,
    config: Mapping[str, Any],
    http: HttpClient,
    logger: Any,
) -> dict[str, Any]:
    """Gather the passive snapshot for ``target``.

    Args:
        target: Apex domain, already scope-checked.
        config: Parsed configuration.
        http: Shared HTTP client.
        logger: Logger for progress.

    Returns:
        Snapshot dict with subdomains, certificates, DNS, RDAP data and hosts.
    """
    recon = PassiveRecon(http, logger, config)
    snapshot = recon.run(target)

    collectors = config.get("collectors", {}) or {}
    probe_enabled = bool(collectors.get("http_headers", True))
    max_hosts = int(collectors.get("max_hosts", 25))

    hosts: list[dict[str, Any]] = []
    if probe_enabled:
        detector = TechDetector(http, logger)
        names = [target] + [name for name in snapshot.get("subdomains", []) if name != target]
        for name in names[:max_hosts]:
            # HTTPS first; fall back to HTTP once so an http-only host is visible.
            origin = f"https://{name}"
            info = detector.probe(origin, config)
            if info is None:
                info = detector.probe(f"http://{name}", config)
            if info is not None:
                info["host"] = name
                hosts.append(info)
                logger.info("probed %s (%s)", name, info.get("status"))
    snapshot["hosts"] = hosts

    # The JS pass re-reads the root page of probed hosts and follows only
    # same-origin scripts, so it stays inside the host list just probed.
    if hosts and bool((config.get("collectors", {}) or {}).get("js_intel", True)):
        js_intel = JsIntel(http, logger, config)
        snapshot["js_intel"] = js_intel.scan_hosts(hosts)
    return snapshot


def run_target(
    target: str,
    config: Mapping[str, Any],
    config_path: Path,
    logger: Any,
    dry_run: bool,
    checker: ScopeChecker | None = None,
    request_ai_summary: bool = False,
) -> dict[str, Any]:
    """Run the whole pipeline for one target and return a result summary.

    Args:
        target: Target apex domain given on the command line.
        config: Parsed configuration.
        config_path: Path of the config file, recorded in the report.
        logger: Logger for progress.
        dry_run: When true, stop after the scope decision.
        checker: Reuse an existing scope checker instead of building a new one.
        request_ai_summary: Make one bounded AI request after analysis when true.

    Returns:
        ``{"target": str, "allowed": bool, "findings": [...], "reports": {...}}``.
    """
    project = config.get("project", {}) or {}
    checker = checker or ScopeChecker(config, logger)

    try:
        domain = checker.assert_in_scope(target)
    except ScopeViolation as error:
        logger.error("%s", error)
        return {"target": target, "allowed": False, "findings": [], "reports": {}}

    logger.info("scope accepted for %s", domain)
    if dry_run:
        logger.info(
            "dry run: would collect every passive source for %s (CT logs, Wayback, Common Crawl, "
            "OTX, Anubis, RapidDNS, DNS, RDAP)",
            domain,
        )
        logger.info("dry run: would send one GET per host (max %s hosts)", (config.get("collectors", {}) or {}).get("max_hosts", 25))
        logger.info("dry run: no request was sent and no report was written")
        return {"target": domain, "allowed": True, "findings": [], "reports": {}}

    with HttpClient(config, logger) as http:
        snapshot = collect(domain, config, http, logger)

        history = HistoryManager(Path((config.get("data", {}) or {}).get("history_dir", TOOLKIT_ROOT / "data" / "history")), logger)
        previous = history.load_latest(domain)
        changes = history.diff(previous, snapshot)
        history.save(domain, snapshot)

        analyzer = Analyzer(config, logger)
        findings = analyzer.analyze(snapshot, changes)

        ai_summary = ""
        ai_provider = str((config.get("ai", {}) or {}).get("provider", "ollama"))
        if request_ai_summary:
            try:
                ai_summary, ai_provider = summarize_findings(domain, findings, changes, config, logger)
            except Exception as error:
                ai_summary = f"AI triage unavailable: {error}"
                logger.warning("AI triage failed: %s", error)

        metadata: dict[str, Any] = {
            "tool": f"{project.get('name', TOOL_NAME)} {project.get('version', '1.0.0')}",
            "author": project.get("author", ""),
            "run_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "config": str(config_path),
            "previous_snapshot": (previous or {}).get("_snapshot_file", "none"),
            "proxy": "enabled" if http.proxies else "disabled (direct from this host)",
            "dns_note": "DNS lookups and the TLS handshake are not proxied and leave from this host; crt.sh, RDAP and HTTP probes use the configured proxy when enabled.",
            "methodology": [
                "Certificate transparency (crt.sh and Cert Spotter) for subdomains and certificate dates.",
                "Wayback Machine CDX index (web.archive.org) and the newest Common Crawl index for archived URLs.",
                "AlienVault OTX, Anubis and RapidDNS passive datasets for historical subdomains.",
                "DNS liveness check over the discovered names, an AXFR attempt and DMARC/SPF policy data.",
                "Same-origin JavaScript intelligence: exposed source maps and hard-coded credentials.",
                "One TLS handshake per probed host for the certificate actually served and its protocol version.",
                "The site's own robots.txt, read once for the paths it discloses.",
                "Public DNS records (A, AAAA, CNAME, MX, TXT, NS, SOA) via the system resolver.",
                "Public registration data through RDAP (no WHOIS port 43 traffic).",
                "One HTTP GET per host for headers, technology, cookies and a single CORS probe.",
                "Comparison with the previous snapshot and rule-based analysis.",
            ],
        }

        generator = ReportGenerator(config, logger)
        reports = generator.generate(domain, snapshot, findings, changes, checker.scope_summary(), metadata)
        if request_ai_summary:
            markdown_path = reports.get("markdown")
            if markdown_path is not None:
                ai_path = markdown_path.with_name(f"{markdown_path.stem}-ai.md")
            else:
                ai_path = generator.output_dir / f"{domain}-{metadata['run_id']}-ai.md"
            quoted_summary = "\n".join("> " + line if line else ">" for line in ai_summary.splitlines())
            ai_path.write_text(
                f"# AI-assisted triage — {domain}\n\n"
                f"Provider: {ai_provider}\n\n"
                "> AI-generated assistance only; it does not confirm findings. Verify every item manually.\n\n"
                f"{quoted_summary}\n",
                encoding="utf-8",
            )
            reports["AI triage"] = ai_path
            logger.info("AI triage report written: %s", ai_path)

        notifier = Notifier(config, logger)
        notifier.summary(domain, findings, changes, reports)
        notifier.save_alerts(findings)

    return {"target": domain, "allowed": True, "findings": findings, "reports": reports}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(
        description="Passive, scope-checked bug-bounty reconnaissance with explained reports.",
        epilog="Only use this against programs that explicitly authorize the target.",
    )
    parser.add_argument("targets", nargs="*", help="apex domain(s), e.g. example.com; empty lists the scope")
    parser.add_argument("-c", "--config", default=str(DEFAULT_CONFIG), help=f"config file (default: {DEFAULT_CONFIG})")
    parser.add_argument("--all", action="store_true", help="run every domain listed in the scope")
    parser.add_argument("--list", action="store_true", help="list the in-scope domains and exit")
    parser.add_argument("--dry-run", action="store_true", help="check scope and show the plan without any request")
    parser.add_argument("--no-http", action="store_true", help="skip the per-host HTTP probe (pure DNS/CT/RDAP)")
    parser.add_argument("--ai-summary", action="store_true", help="opt in to one bounded AI triage request for this report")
    parser.add_argument("-q", "--quiet", action="store_true", help="only warnings and errors on the console")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Program entry point. Returns the process exit code."""
    args = parse_args(argv)
    config_path = Path(args.config)
    config = load_config(config_path)

    if args.no_http:
        collectors = config.setdefault("collectors", {})
        collectors["http_headers"] = False
        collectors["js_intel"] = False
        collectors["robots_txt"] = False
    if args.quiet:
        config.setdefault("logging", {})["level"] = "WARNING"
        config.setdefault("notify", {})["console"] = False

    logging_cfg = config.get("logging", {}) or {}
    logger = setup_logger(
        name="bugbounty",
        log_file=logging_cfg.get("file", str(TOOLKIT_ROOT / "logs" / "toolkit.log")),
        level=logging_cfg.get("level", "INFO"),
        max_bytes=int(logging_cfg.get("max_bytes", 2_000_000)),
        backups=int(logging_cfg.get("backups", 3)),
    )

    checker = ScopeChecker(config, logger)
    if args.list:
        print_scope(checker)
        return 0

    targets = [str(item) for item in args.targets]
    if not targets and not args.all:
        print_scope(checker)
        logger.info("no target given: pass a domain, or --all to run every in-scope domain")
        return 0
    if args.all:
        targets = sorted(set(checker.in_scope))
        if not targets:
            logger.error("no in-scope domain is configured; add one to config.yaml")
            return 2
        logger.info("running every in-scope domain: %d target(s)", len(targets))

    logger.info("starting %s with %d target(s)", TOOL_NAME, len(targets))
    exit_code = 0
    for target in targets:
        result = run_target(target, config, config_path, logger, args.dry_run, checker, args.ai_summary)
        if not result["allowed"]:
            exit_code = 2  # at least one target was refused

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
