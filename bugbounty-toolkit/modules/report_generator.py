"""Markdown and JSON report generation.

The Markdown report is written from ``templates/report_template.md``: the
template holds the fixed structure and this module fills in the generated
sections. Rendering uses plain string replacement so the template can contain any
Markdown (including braces) without escaping rules.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


def _timestamp() -> str:
    """UTC timestamp used in the report header."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _slug() -> str:
    """Filesystem-safe run id."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class ReportGenerator:
    """Builds the Markdown report and the machine-readable JSON twin.

    Args:
        config: Parsed ``config.yaml`` mapping.
        logger: Logger for progress.
    """

    def __init__(self, config: Mapping[str, Any], logger: Any) -> None:
        report_cfg = config.get("report", {}) or {}
        self.config = config
        self.logger = logger
        self.output_dir = Path(report_cfg.get("output_dir", "reports"))
        self.template_path = Path(report_cfg.get("markdown_template", "templates/report_template.md"))
        self.formats = [str(item).lower() for item in report_cfg.get("formats", ["markdown", "json"]) or []]
        self.include_appendix = bool(report_cfg.get("include_appendix", True))

    # -- public API -----------------------------------------------------------
    def generate(
        self,
        target: str,
        snapshot: Mapping[str, Any],
        findings: Sequence[Any],
        changes: Sequence[Mapping[str, Any]],
        scope: Mapping[str, Any],
        metadata: Mapping[str, Any],
    ) -> dict[str, Path]:
        """Render and write every configured format.

        Args:
            target: Apex domain of this run.
            snapshot: Collected data for the template.
            findings: :class:`~modules.analyzer.Finding` objects.
            changes: Change dicts from the history diff.
            scope: Scope summary from the checker.
            metadata: Run metadata (tool version, proxy state, flags).

        Returns:
            Mapping of format name to the written file path.
        """
        written: dict[str, Path] = {}
        self.output_dir.mkdir(parents=True, exist_ok=True)
        run_id = _slug()

        if "markdown" in self.formats:
            try:
                markdown = self.render(target, snapshot, findings, changes, scope, metadata)
            except OSError as error:
                self.logger.error("could not read the report template: %s", error)
            else:
                path = self.output_dir / f"{target}-{run_id}.md"
                path.write_text(markdown, encoding="utf-8")
                written["markdown"] = path
                self.logger.info("markdown report written: %s", path)

        if "json" in self.formats:
            path = self.output_dir / f"{target}-{run_id}.json"
            payload = {
                "target": target,
                "generated_at": _timestamp(),
                "scope": dict(scope),
                "metadata": dict(metadata),
                "summary": self._summary_counts(findings),
                "findings": [finding.to_dict() for finding in findings],
                "changes": list(changes),
                "snapshot": {
                    "subdomains": snapshot.get("subdomains", []),
                    "dns": snapshot.get("dns", {}),
                    "whois": snapshot.get("whois", {}),
                    "hosts": snapshot.get("hosts", []),
                },
            }
            path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            written["json"] = path
            self.logger.info("json report written: %s", path)

        return written

    def render(
        self,
        target: str,
        snapshot: Mapping[str, Any],
        findings: Sequence[Any],
        changes: Sequence[Mapping[str, Any]],
        scope: Mapping[str, Any],
        metadata: Mapping[str, Any],
    ) -> str:
        """Return the Markdown report as a string."""
        template = self.template_path.read_text(encoding="utf-8")
        replacements = {
            "{{TITLE}}": f"Passive reconnaissance report — {target}",
            "{{TARGET}}": target,
            "{{GENERATED_AT}}": _timestamp(),
            "{{SUMMARY}}": self._summary(target, findings, changes),
            "{{TARGET_INFO}}": self._target_info(target, snapshot, metadata),
            "{{SCOPE}}": self._scope_section(scope),
            "{{METHODOLOGY}}": self._methodology(metadata),
            "{{FINDINGS}}": self._findings_section(findings),
            "{{CHANGES}}": self._changes_section(changes, snapshot),
            "{{RISK}}": self._risk_section(findings),
            "{{RECOMMENDATIONS}}": self._recommendations(findings),
            "{{APPENDIX}}": self._appendix(snapshot) if self.include_appendix else "",
            "{{METADATA}}": self._metadata(metadata),
        }

        rendered = template
        for token, value in replacements.items():
            rendered = rendered.replace(token, value)
        return rendered

    # -- sections -------------------------------------------------------------
    @staticmethod
    def _summary_counts(findings: Sequence[Any]) -> dict[str, int]:
        counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def _summary(self, target: str, findings: Sequence[Any], changes: Sequence[Mapping[str, Any]]) -> str:
        counts = self._summary_counts(findings)
        total = len(findings)
        lines = [
            f"This passive assessment of **{target}** produced **{total} finding(s)** "
            f"and recorded **{len(changes)} change(s)** against the previous snapshot.",
            "",
            "| Severity | Count |",
            "| --- | --- |",
        ]
        for severity in ("Critical", "High", "Medium", "Low", "Info"):
            lines.append(f"| {severity} | {counts.get(severity, 0)} |")

        if counts["Critical"] or counts["High"]:
            lines += [
                "",
                "> **Start with the critical and high findings.** Each one below names the impact "
                "in plain language and the exact read-only step that reproduces it.",
            ]
        else:
            lines += [
                "",
                "No critical or high-severity issue was confirmed in this pass. That means "
                "\"nothing proved here\", not \"nothing exists\": the scope of this toolkit is "
                "passive data and header analysis.",
            ]
        return "\n".join(lines)

    @staticmethod
    def _target_info(target: str, snapshot: Mapping[str, Any], metadata: Mapping[str, Any]) -> str:
        whois = snapshot.get("whois", {}) or {}
        dns = snapshot.get("dns", {}) or {}
        sources = snapshot.get("sources", {}) or {}
        js_entries = [entry for entry in snapshot.get("js_intel", []) or [] if isinstance(entry, dict)]
        js_files = sum(int(entry.get("js_scanned") or 0) for entry in js_entries)
        js_secrets = sum(len(entry.get("secrets", []) or []) for entry in js_entries)
        js_maps = sum(len(entry.get("source_maps", []) or []) for entry in js_entries)
        hosts = [host for host in snapshot.get("hosts", []) or [] if isinstance(host, dict)]
        tls_read = sum(1 for host in hosts if (host.get("tls", {}) or {}).get("version"))
        robots_paths = sum(len((host.get("robots", {}) or {}).get("paths", []) or []) for host in hosts)
        lines = [
            "| Field | Value |",
            "| --- | --- |",
            f"| Apex domain | `{target}` |",
            f"| Subdomains found | {len(snapshot.get('subdomains', []) or [])} |",
            f"| — from crt.sh | {sources.get('crtsh', 'n/a')} |",
            f"| — from Cert Spotter | {sources.get('certspotter', 'n/a')} |",
            f"| — from Wayback CDX | {sources.get('wayback', 'n/a')} |",
            f"| — from OTX passive DNS | {sources.get('otx', 'n/a')} |",
            f"| — from Anubis | {sources.get('anubis', 'n/a')} |",
            f"| — from RapidDNS | {sources.get('rapiddns', 'n/a')} |",
            f"| Archived URLs (Wayback + Common Crawl) | {len(snapshot.get('archived_urls', []) or [])} |",
            f"| — from Common Crawl | {sources.get('commoncrawl_urls', 'n/a')} |",
            f"| Hosts probed over HTTP | {len(hosts)} |",
            f"| TLS certificates read directly | {tls_read} host(s) |",
            f"| robots.txt paths disclosed | {robots_paths} |",
            f"| Live subdomains (DNS) | {len(snapshot.get('live_subdomains', []) or [])} |",
            f"| JavaScript scanned | {js_files} file(s), {js_secrets} secret(s), {js_maps} source map(s) |",
            f"| Registrar (RDAP) | {whois.get('registrar') or 'not reported'} |",
            f"| Certificate records (CT logs) | {len(snapshot.get('certificates', []) or [])} |",
            f"| DNS record types answered | {', '.join(sorted(dns)) or 'none'} |",
            f"| Run | {metadata.get('run_id', '')} |",
        ]
        return "\n".join(lines)

    @staticmethod
    def _scope_section(scope: Mapping[str, Any]) -> str:
        in_scope = scope.get("in_scope", []) or []
        out_of_scope = scope.get("out_of_scope", []) or []
        lines = [
            "A target is touched only when it equals an in-scope entry or is one of its "
            "subdomains, and never when it matches an out-of-scope entry. Every decision is "
            "recorded in `data/history/scope_history.jsonl` with its reason.",
            "",
            f"* Strict mode: **{'on' if scope.get('strict') else 'off'}**",
            f"* In scope: {', '.join(f'`{item}`' for item in in_scope) or '_none configured_'}",
            f"* Out of scope: {', '.join(f'`{item}`' for item in out_of_scope) or '_none configured_'}",
        ]
        return "\n".join(lines)

    @staticmethod
    def _methodology(metadata: Mapping[str, Any]) -> str:
        steps = metadata.get("methodology") or []
        lines = [
            "Only public data and single, ordinary GET requests were used. No path was "
            "enumerated from a wordlist, no payload was sent, and nothing was brute-forced.",
            "",
        ]
        lines += [f"{index}. {step}" for index, step in enumerate(steps, start=1)]
        if metadata.get("dns_note"):
            lines += ["", f"> {metadata['dns_note']}"]
        return "\n".join(lines)

    def _findings_section(self, findings: Sequence[Any]) -> str:
        if not findings:
            return "_No finding was produced for this run._"

        blocks: list[str] = []
        for finding in findings:
            references = ""
            if finding.references:
                references = "\n\n**References**\n\n" + "\n".join(f"* {link}" for link in finding.references)
            blocks.append(
                "\n".join(
                    [
                        f"### {finding.id} · {finding.severity_label} — {finding.title}",
                        "",
                        "| Field | Value |",
                        "| --- | --- |",
                        f"| Category | {finding.category} |",
                        f"| Host | `{finding.host}` |",
                        f"| Confidence | {finding.confidence} |",
                        f"| Evidence | `{finding.evidence}` |",
                        "",
                        f"**What it is.** {finding.what}",
                        "",
                        f"**Why it matters.** {finding.why}",
                        "",
                        f"**Impact.** {finding.impact}",
                        "",
                        "**How to verify it yourself.**",
                        "",
                        "```bash",
                        finding.verify,
                        "```",
                        "",
                        f"**Recommended fix.** {finding.recommendation}{references}",
                        "",
                        "---",
                    ]
                )
            )
        return "\n\n".join(blocks)

    @staticmethod
    def _changes_section(changes: Sequence[Mapping[str, Any]], snapshot: Mapping[str, Any]) -> str:
        if not changes:
            return (
                "_No previous snapshot to compare with, or nothing changed in this run. "
                "The next run will list new or removed subdomains, technologies, headers, "
                "certificate dates and DNS records here._"
            )
        lines = ["| Type | Item | Detail | Significance |", "| --- | --- | --- | --- |"]
        for change in changes[:80]:
            lines.append(
                f"| {change.get('type', '')} | `{change.get('item', '')}` | "
                f"{change.get('detail', '')} | {change.get('significance', '')} |"
            )
        if len(changes) > 80:
            lines += ["", f"_… and {len(changes) - 80} more change(s) in the JSON report._"]
        return "\n".join(lines)

    @classmethod
    def _risk_section(cls, findings: Sequence[Any]) -> str:
        counts = cls._summary_counts(findings)
        if counts["Critical"]:
            headline = "**Overall risk: critical.** Fix the critical finding(s) before any other work."
        elif counts["High"]:
            headline = "**Overall risk: high.** At least one high-severity issue is present."
        elif counts["Medium"]:
            headline = "**Overall risk: medium.** Confirmed weaknesses exist but need a precondition to be abused."
        elif counts["Low"] or counts["Info"]:
            headline = "**Overall risk: low.** The findings are hardening gaps and information leaks."
        else:
            headline = "**Overall risk: informational.** Nothing was confirmed in this passive pass."

        lines = [
            headline,
            "",
            "The rating follows the highest confirmed severity, weighted by confidence: a "
            "`likely` finding that still needs a manual step is never presented as proven.",
        ]
        return "\n".join(lines)

    @staticmethod
    def _recommendations(findings: Sequence[Any]) -> str:
        if not findings:
            return (
                "1. Keep the scope file current and re-run this toolkit on a schedule; a clean "
                "passive result is a baseline, not a guarantee.\n"
                "2. Compare each run with the previous one so new infrastructure is reviewed "
                "before it is forgotten."
            )
        lines = ["Ordered by severity, the fixes worth doing first:", ""]
        seen: set[str] = set()
        for finding in findings:
            if finding.recommendation in seen:
                continue
            seen.add(finding.recommendation)
            lines.append(f"* **{finding.severity}** — {finding.recommendation}")
        lines += [
            "",
            "After the fixes, re-run the toolkit and compare the new report with this one: the "
            "finding should disappear and the change list should show only intended work.",
        ]
        return "\n".join(lines)

    @staticmethod
    def _appendix(snapshot: Mapping[str, Any]) -> str:
        lines = ["### Collected subdomains", ""]
        subdomains = snapshot.get("subdomains", []) or []
        if subdomains:
            lines += ["```"] + [str(item) for item in subdomains[:200]] + ["```"]
            if len(subdomains) > 200:
                lines.append(f"_… and {len(subdomains) - 200} more (see the JSON report)._")
        else:
            lines.append("_None found._")

        lines += ["", "### DNS records", "", "| Type | Value |", "| --- | --- |"]
        dns = snapshot.get("dns", {}) or {}
        if dns:
            for record_type in sorted(dns):
                for value in dns[record_type]:
                    lines.append(f"| {record_type} | `{value}` |")
        else:
            lines.append("| — | _none collected_ |")

        hosts = snapshot.get("hosts", []) or []
        if hosts:
            lines += ["", "### Probed hosts", "", "| URL | Status | Technologies |", "| --- | --- | --- |"]
            for host in hosts:
                tech = ", ".join(host.get("technologies", []) or []) or "—"
                lines.append(f"| `{host.get('url', '')}` | {host.get('status', '')} | {tech} |")
        return "\n".join(lines)

    @staticmethod
    def _metadata(metadata: Mapping[str, Any]) -> str:
        lines = [f"* {key}: {value}" for key, value in metadata.items() if key != "methodology"]
        lines.append("")
        lines.append(
            "_Authorized scope only. This toolkit performs passive collection and single read-only "
            "requests; it contains no scanner, brute force, fuzzing or exploit code._"
        )
        return "\n".join(lines)
