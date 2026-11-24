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
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from modules.analyzer import Analyzer
from modules.history_manager import HistoryManager
from modules.notifier import Notifier
from modules.passive_recon import PassiveRecon
from modules.report_generator import ReportGenerator
from modules.scope_checker import ScopeChecker, ScopeViolation
from modules.tech_detector import TechDetector
from utils.http import HttpClient
from utils.logger import setup_logger

DEFAULT_CONFIG = "config/config.yaml"
TOOL_NAME = "Passive Bug Bounty Toolkit"


def load_config(path: Path) -> dict[str, Any]:
    """Load and validate the YAML configuration.

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
    return raw


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
    return snapshot


def run_target(
    target: str,
    config: Mapping[str, Any],
    config_path: Path,
    logger: Any,
    dry_run: bool,
) -> dict[str, Any]:
    """Run the whole pipeline for one target and return a result summary.

    Args:
        target: Target apex domain given on the command line.
        config: Parsed configuration.
        config_path: Path of the config file, recorded in the report.
        logger: Logger for progress.
        dry_run: When true, stop after the scope decision.

    Returns:
        ``{"target": str, "allowed": bool, "findings": [...], "reports": {...}}``.
    """
    project = config.get("project", {}) or {}
    checker = ScopeChecker(config, logger)

    try:
        domain = checker.assert_in_scope(target)
    except ScopeViolation as error:
        logger.error("%s", error)
        return {"target": target, "allowed": False, "findings": [], "reports": {}}

    logger.info("scope accepted for %s", domain)
    if dry_run:
        logger.info("dry run: would collect certificate transparency, DNS and RDAP for %s", domain)
        logger.info("dry run: would send one GET per host (max %s hosts)", (config.get("collectors", {}) or {}).get("max_hosts", 25))
        logger.info("dry run: no request was sent and no report was written")
        return {"target": domain, "allowed": True, "findings": [], "reports": {}}

    with HttpClient(config, logger) as http:
        snapshot = collect(domain, config, http, logger)

        history = HistoryManager(Path((config.get("data", {}) or {}).get("history_dir", "data/history")), logger)
        previous = history.load_latest(domain)
        changes = history.diff(previous, snapshot)
        history.save(domain, snapshot)

        analyzer = Analyzer(config, logger)
        findings = analyzer.analyze(snapshot, changes)

        metadata: dict[str, Any] = {
            "tool": f"{project.get('name', TOOL_NAME)} {project.get('version', '1.0.0')}",
            "author": project.get("author", ""),
            "run_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "config": str(config_path),
            "previous_snapshot": (previous or {}).get("_snapshot_file", "none"),
            "proxy": "enabled" if http.proxies else "disabled (direct from this host)",
            "dns_note": "DNS lookups are not proxied and leave from this host; crt.sh, RDAP and HTTP probes use the configured proxy when enabled.",
            "methodology": [
                "Certificate transparency (crt.sh) for subdomains and certificate dates.",
                "Public DNS records (A, AAAA, CNAME, MX, TXT, NS, SOA) via the system resolver.",
                "Public registration data through RDAP (no WHOIS port 43 traffic).",
                "One HTTP GET per host for headers, technology, cookies and a single CORS probe.",
                "Comparison with the previous snapshot and rule-based analysis.",
            ],
        }

        generator = ReportGenerator(config, logger)
        reports = generator.generate(domain, snapshot, findings, changes, checker.scope_summary(), metadata)

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
    parser.add_argument("targets", nargs="+", help="Apex domain(s), e.g. example.com")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG, help=f"config file (default: {DEFAULT_CONFIG})")
    parser.add_argument("--dry-run", action="store_true", help="check scope and show the plan without any request")
    parser.add_argument("--no-http", action="store_true", help="skip the per-host HTTP probe (pure DNS/CT/RDAP)")
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
    if args.quiet:
        config.setdefault("logging", {})["level"] = "WARNING"
        config.setdefault("notify", {})["console"] = False

    logging_cfg = config.get("logging", {}) or {}
    logger = setup_logger(
        name="bugbounty",
        log_file=logging_cfg.get("file", "logs/toolkit.log"),
        level=logging_cfg.get("level", "INFO"),
        max_bytes=int(logging_cfg.get("max_bytes", 2_000_000)),
        backups=int(logging_cfg.get("backups", 3)),
    )

    logger.info("starting %s with %d target(s)", TOOL_NAME, len(args.targets))
    exit_code = 0
    for target in args.targets:
        result = run_target(target, config, config_path, logger, args.dry_run)
        if not result["allowed"]:
            exit_code = 2  # at least one target was refused

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
