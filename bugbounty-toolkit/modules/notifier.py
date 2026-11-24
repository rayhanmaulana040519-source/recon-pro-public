"""Console summary and machine-readable alert export.

The notifier never contacts the network: alerts are printed and appended to a
local JSONL file, so nothing about a target leaves the machine from here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")


class Notifier:
    """Prints a short summary and keeps an alert log.

    Args:
        config: Parsed ``config.yaml`` mapping.
        logger: Logger for progress.
    """

    def __init__(self, config: Mapping[str, Any], logger: Any) -> None:
        notify = config.get("notify", {}) or {}
        self.logger = logger
        self.console = bool(notify.get("console", True))
        self.alerts_file = Path(notify.get("alerts_file", "reports/alerts.jsonl"))

    def summary(
        self,
        target: str,
        findings: Sequence[Any],
        changes: Sequence[Mapping[str, Any]],
        report_paths: Mapping[str, Path],
    ) -> None:
        """Print the end-of-run summary for one target."""
        counts: dict[str, int] = {severity: 0 for severity in SEVERITY_ORDER}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1

        if not self.console:
            return

        print("\n" + "=" * 62)
        print(f"SUMMARY — {target}")
        print("=" * 62)
        print(f"findings: {len(findings)}   changes since last run: {len(changes)}")
        print("severity: " + " | ".join(f"{name} {counts.get(name, 0)}" for name in SEVERITY_ORDER))

        for finding in findings[:5]:
            print(f"  [{finding.severity}] {finding.title} — {finding.host}")
        if len(findings) > 5:
            print(f"  … {len(findings) - 5} more in the report")

        for name, path in report_paths.items():
            print(f"{name}: {path}")
        print("=" * 62 + "\n")

    def save_alerts(self, findings: Sequence[Any]) -> Path | None:
        """Append every finding to the alert log and return the file path."""
        if not findings:
            return None
        try:
            self.alerts_file.parent.mkdir(parents=True, exist_ok=True)
            with self.alerts_file.open("a", encoding="utf-8") as handle:
                for finding in findings:
                    handle.write(json.dumps(finding.to_dict(), ensure_ascii=False) + "\n")
        except OSError as error:
            self.logger.warning("could not write alert log %s: %s", self.alerts_file, error)
            return None
        self.logger.info("alerts appended to %s", self.alerts_file)
        return self.alerts_file
