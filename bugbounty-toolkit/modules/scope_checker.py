"""Strict scope enforcement.

The scope checker is the first thing every target touches: nothing is collected,
resolved or requested before :meth:`ScopeChecker.assert_in_scope` has accepted
it. Every decision is logged and appended to a JSONL history, so the report can
show why a host was allowed.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")


class ScopeViolation(RuntimeError):
    """Raised when a target is not inside the authorized scope."""


def extract_host(target: str) -> str:
    """Return the lowercase hostname of ``target`` (a URL or a bare hostname).

    Args:
        target: ``https://dev.example.com/path`` or ``dev.example.com``.

    Returns:
        The hostname without scheme, port, credentials or trailing dot, or an
        empty string when nothing usable is present.
    """
    value = str(target).strip()
    if not value:
        return ""
    if SCHEME.match(value):
        host = urlsplit(value).hostname or ""
    else:
        host = value.split("/", 1)[0]
        host = host.split("@")[-1]
        host = host.split(":", 1)[0]
    return host.strip().strip(".").lower()


class ScopeChecker:
    """Validates targets against the in-scope and out-of-scope lists.

    An in-scope entry covers itself and its subdomains. An out-of-scope entry
    always wins, so a broad apex can never widen access to a host the program
    excluded.

    Args:
        config: Parsed ``config.yaml`` mapping.
        logger: Logger used for every decision.
    """

    def __init__(self, config: Mapping[str, Any], logger: Any) -> None:
        scope = config.get("scope", {}) or {}
        self.logger = logger
        self.strict = bool(scope.get("strict", True))
        self.in_scope = [self._normalize(entry) for entry in scope.get("in_scope", [])]
        self.out_of_scope = [self._normalize(entry) for entry in scope.get("out_of_scope", [])]
        self.in_scope = [entry for entry in self.in_scope if entry]
        self.out_of_scope = [entry for entry in self.out_of_scope if entry]

        # recon.sh records the domain you just scanned in a small side file, so a
        # domain never has to be added by editing YAML by hand and the config
        # comments stay intact.
        extra_file = scope.get("extra_scope_file", "data/extra_scope.txt")
        self.extra_scope_path = Path(extra_file)
        self.extra_in_scope = self._read_extra_scope()
        self.in_scope.extend(self.extra_in_scope)

        history = Path(scope.get("history_file", "data/history/scope_history.jsonl"))
        self.history_path = history
        try:
            history.parent.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            self.logger.warning("Cannot create scope history directory %s: %s", history.parent, error)

        if not self.in_scope:
            self.logger.warning("No in-scope entry is configured; every target will be rejected.")

    def _read_extra_scope(self) -> list[str]:
        """Read one domain per line from the side scope file (comments allowed)."""
        try:
            lines = self.extra_scope_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        entries = []
        for line in lines:
            value = line.split("#", 1)[0].strip()
            if not value:
                continue
            normalized = self._normalize(value)
            if normalized:
                entries.append(normalized)
        return entries

    # -- normalisation --------------------------------------------------------
    @staticmethod
    def _normalize(entry: Any) -> str:
        """Lowercase an entry, drop a leading ``*.`` and a trailing dot."""
        value = str(entry).strip().lower()
        if value.startswith("*."):
            value = value[2:]
        return value.strip().strip(".")

    def _matches(self, host: str, entry: str) -> bool:
        """True when ``host`` equals ``entry`` or is one of its subdomains."""
        return host == entry or host.endswith("." + entry)

    def _valid_host(self, host: str) -> bool:
        """True when ``host`` looks like a real domain name, not an IP."""
        if not host or "." not in host or len(host) > 253:
            return False
        labels = host.split(".")
        if len(labels) < 2 or labels[-1].isdigit():
            return False
        return all(LABEL.match(label) for label in labels)

    # -- decisions ------------------------------------------------------------
    def is_in_scope(self, target: str) -> bool:
        """Decide whether ``target`` may be touched, and record the decision."""
        host = extract_host(target)
        if not host:
            self._record(False, target, "empty or unparseable target")
            return False

        if self.strict and not self._valid_host(host):
            self._record(False, host, "not a valid domain name (strict mode)")
            return False

        for entry in self.out_of_scope:
            if self._matches(host, entry):
                self._record(False, host, f"matches out_of_scope entry {entry}")
                return False

        for entry in self.in_scope:
            if self._matches(host, entry):
                self._record(True, host, f"matches in_scope entry {entry}")
                return True

        self._record(False, host, "not covered by any in_scope entry")
        return False

    def assert_in_scope(self, target: str) -> str:
        """Return the host of ``target``, or raise :class:`ScopeViolation`.

        Args:
            target: URL or bare hostname to validate.

        Raises:
            ScopeViolation: when the target is not authorized.
        """
        host = extract_host(target)
        if not self.is_in_scope(host):
            raise ScopeViolation(
                f"{host or target} is not in the authorized scope. "
                "Add it to config.yaml only if the program explicitly authorizes it."
            )
        return host

    def scope_summary(self) -> dict[str, Any]:
        """Return a report-friendly description of the configured scope."""
        return {
            "in_scope": list(self.in_scope),
            "out_of_scope": list(self.out_of_scope),
            "strict": self.strict,
            "extra_scope_file": str(self.extra_scope_path),
        }

    # -- audit trail ----------------------------------------------------------
    def _record(self, allowed: bool, target: str, reason: str) -> None:
        """Log one decision and append it to the JSONL scope history."""
        if allowed:
            self.logger.info("scope ALLOW %s — %s", target, reason)
        else:
            self.logger.warning("scope DENY %s — %s", target, reason)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "decision": status,
            "target": target,
            "reason": reason,
        }
        try:
            with self.history_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as error:
            self.logger.warning("Cannot append scope history: %s", error)
