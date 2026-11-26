"""Snapshot history and the diff engine.

Each run writes ``data/history/<target>/<timestamp>.json``. The newest file that
is not the current snapshot is the comparison baseline, which is how the report
can say what changed since last time instead of repeating a static list.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


def _now_slug() -> str:
    """Filesystem-friendly UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class HistoryManager:
    """Reads and writes per-target JSON snapshots.

    Args:
        directory: Root directory for history files.
        logger: Logger for progress and errors.
    """

    def __init__(self, directory: str | Path, logger: Any) -> None:
        self.directory = Path(directory)
        self.logger = logger
        self.directory.mkdir(parents=True, exist_ok=True)

    def save(self, target: str, snapshot: Mapping[str, Any]) -> Path | None:
        """Persist ``snapshot`` for ``target`` and return the file path."""
        target_dir = self.directory / target
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            path = target_dir / f"{_now_slug()}.json"
            path.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False), encoding="utf-8")
            self.logger.info("history saved: %s", path)
            return path
        except OSError as error:
            self.logger.warning("could not save history for %s: %s", target, error)
            return None

    def load_latest(self, target: str) -> dict[str, Any] | None:
        """Return the newest snapshot for ``target``, or ``None``."""
        target_dir = self.directory / target
        if not target_dir.is_dir():
            return None
        candidates = sorted(target_dir.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        for path in candidates:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                self.logger.warning("could not read %s: %s", path, error)
                continue
            if isinstance(data, dict):
                data["_snapshot_file"] = str(path)
                return data
        return None

    def diff(self, previous: Mapping[str, Any] | None, current: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Compare two snapshots and describe what changed.

        Args:
            previous: Older snapshot, or ``None`` for a first run.
            current: The snapshot collected in this run.

        Returns:
            A list of change dicts with ``type``, ``item``, ``detail`` and
            ``significance`` keys.
        """
        changes: list[dict[str, Any]] = []
        if not previous:
            return changes

        changes += self._diff_set(
            "subdomain",
            "subdomain added",
            "subdomain removed",
            previous.get("subdomains", []) or [],
            current.get("subdomains", []) or [],
            significance="medium",
        )

        prev_tech = self._technologies(previous)
        cur_tech = self._technologies(current)
        changes += self._diff_set("technology", "technology added", "technology removed", prev_tech, cur_tech, significance="low")

        changes += self._diff_headers(previous, current)
        changes += self._diff_certificate(previous, current)
        changes += self._diff_dns(previous, current)
        changes += self._diff_set(
            "archived_url",
            "archived URL added",
            "archived URL removed",
            previous.get("archived_urls", []) or [],
            current.get("archived_urls", []) or [],
            significance="low",
        )
        changes += self._diff_set(
            "live_subdomain",
            "host started resolving",
            "host stopped resolving",
            previous.get("live_subdomains", []) or [],
            current.get("live_subdomains", []) or [],
            significance="medium",
        )
        return changes

    # -- helpers --------------------------------------------------------------
    @staticmethod
    def _technologies(snapshot: Mapping[str, Any]) -> list[str]:
        values: list[str] = []
        for host in snapshot.get("hosts", []) or []:
            values.extend(host.get("technologies", []) or [])
        return sorted(set(values))

    @staticmethod
    def _diff_set(
        kind: str,
        added_label: str,
        removed_label: str,
        previous: list[Any],
        current: list[Any],
        significance: str,
    ) -> list[dict[str, Any]]:
        before = {str(item) for item in previous}
        after = {str(item) for item in current}
        changes: list[dict[str, Any]] = []
        for item in sorted(after - before):
            changes.append({"type": kind, "item": item, "detail": added_label, "significance": significance})
        for item in sorted(before - after):
            changes.append({"type": kind, "item": item, "detail": removed_label, "significance": significance})
        return changes

    def _diff_headers(self, previous: Mapping[str, Any], current: Mapping[str, Any]) -> list[dict[str, Any]]:
        prev_map = {host.get("url", ""): host.get("headers", {}) for host in previous.get("hosts", []) or []}
        cur_map = {host.get("url", ""): host.get("headers", {}) for host in current.get("hosts", []) or []}
        changes: list[dict[str, Any]] = []

        for url in sorted(set(prev_map) & set(cur_map)):
            before = prev_map[url] or {}
            after = cur_map[url] or {}
            for name in sorted(set(before) | set(after)):
                old = before.get(name)
                new = after.get(name)
                if old == new:
                    continue
                changes.append(
                    {
                        "type": "header",
                        "item": f"{url} · {name}",
                        "detail": f"header changed: {old or '(absent)'} -> {new or '(absent)'}",
                        "significance": "medium" if name in {"server", "x-powered-by"} else "low",
                    }
                )
        return changes

    @staticmethod
    def _diff_certificate(previous: Mapping[str, Any], current: Mapping[str, Any]) -> list[dict[str, Any]]:
        def newest(snapshot: Mapping[str, Any]) -> str:
            dates = [str(cert.get("not_after") or "") for cert in snapshot.get("certificates", []) or []]
            return max((date for date in dates if date), default="")

        before, after = newest(previous), newest(current)
        if before and after and before != after:
            return [
                {
                    "type": "certificate",
                    "item": "certificate",
                    "detail": f"latest certificate not_after changed: {before} -> {after}",
                    "significance": "medium",
                }
            ]
        return []

    @staticmethod
    def _diff_dns(previous: Mapping[str, Any], current: Mapping[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        prev_dns = previous.get("dns", {}) or {}
        cur_dns = current.get("dns", {}) or {}

        for record_type in sorted(set(prev_dns) | set(cur_dns)):
            before = {str(item) for item in prev_dns.get(record_type, []) or []}
            after = {str(item) for item in cur_dns.get(record_type, []) or []}
            for value in sorted(after - before):
                changes.append(
                    {
                        "type": "dns",
                        "item": f"{record_type} {value}",
                        "detail": f"{record_type} record added",
                        "significance": "medium",
                    }
                )
            for value in sorted(before - after):
                changes.append(
                    {
                        "type": "dns",
                        "item": f"{record_type} {value}",
                        "detail": f"{record_type} record removed",
                        "significance": "medium",
                    }
                )
        return changes
