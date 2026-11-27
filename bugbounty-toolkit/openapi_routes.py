#!/usr/bin/env python3
"""Extract bounded GET routes from a JSON or YAML OpenAPI document.

The caller has already fetched a small in-scope document. This helper never makes
network requests; it emits path/query TSV records for the caller to scope-check.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

MAX_SPEC_BYTES = 2 * 1024 * 1024
MAX_YAML_ALIASES = 100
MAX_YAML_DEPTH = 100
MAX_QUERY_PARAMETERS = 20
MAX_PARAMETER_NAME_LENGTH = 128


def _load_document(path: Path) -> dict[str, object]:
    """Load one bounded OpenAPI document, preferring standard-library JSON."""
    if path.stat().st_size > MAX_SPEC_BYTES:
        raise ValueError("document exceeds 2 MiB")
    content = path.read_bytes()
    if len(content) > MAX_SPEC_BYTES:
        raise ValueError("document exceeds 2 MiB")
    text = content.decode("utf-8-sig")

    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml
        except ImportError as error:
            raise ValueError("PyYAML is not installed") from error

        class BoundedSafeLoader(yaml.SafeLoader):
            def __init__(self, stream: object) -> None:
                self.alias_count = 0
                self.compose_depth = 0
                super().__init__(stream)

            def compose_node(self, parent: object, index: object) -> object:
                if self.check_event(yaml.AliasEvent):
                    self.alias_count += 1
                    if self.alias_count > MAX_YAML_ALIASES:
                        raise yaml.YAMLError("too many YAML aliases")
                self.compose_depth += 1
                try:
                    if self.compose_depth > MAX_YAML_DEPTH:
                        raise yaml.YAMLError("YAML nesting is too deep")
                    return super().compose_node(parent, index)
                finally:
                    self.compose_depth -= 1

        document = yaml.load(text, Loader=BoundedSafeLoader)

    if not isinstance(document, dict):
        raise ValueError("document root must be a mapping")
    version = document.get("openapi")
    if not (isinstance(version, str) and version.startswith("3.")) and document.get("swagger") != "2.0":
        raise ValueError("unsupported OpenAPI/Swagger version")
    if not isinstance(document.get("paths"), dict):
        raise ValueError("document has no paths mapping")
    return document


def _safe_route(path: object) -> Optional[str]:
    if not isinstance(path, str) or len(path) > 512:
        return None
    if not path.startswith("/") or path.startswith("//"):
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        return None
    if any(char in path for char in "\\?#"):
        return None
    return re.sub(r"\{[^{}]+\}", "1", path)


def _query_parameters(path_item: Mapping[str, object], operation: Mapping[str, object]) -> str:
    names: list[str] = []
    seen: set[str] = set()
    for owner in (path_item, operation):
        parameters = owner.get("parameters")
        if not isinstance(parameters, list):
            continue
        for parameter in parameters:
            if not isinstance(parameter, Mapping) or parameter.get("in") != "query":
                continue
            name = parameter.get("name")
            if not isinstance(name, str) or not name or len(name) > MAX_PARAMETER_NAME_LENGTH:
                continue
            if any(ord(char) < 32 or ord(char) == 127 for char in name) or name in seen:
                continue
            seen.add(name)
            names.append(name)
            if len(names) >= MAX_QUERY_PARAMETERS:
                break
        if len(names) >= MAX_QUERY_PARAMETERS:
            break
    return urlencode([(name, "1") for name in names])


def extract_routes(document: Mapping[str, object], limit: int) -> list[tuple[str, str]]:
    paths = document.get("paths")
    if not isinstance(paths, Mapping):
        return []
    routes: list[tuple[str, str]] = []
    for raw_path, raw_item in paths.items():
        if len(routes) >= limit:
            break
        route = _safe_route(raw_path)
        if route is None or not isinstance(raw_item, Mapping):
            continue
        operation = raw_item.get("get")
        if not isinstance(operation, Mapping):
            continue
        routes.append((route, _query_parameters(raw_item, operation)))
    return routes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("document", type=Path)
    parser.add_argument("limit", type=int)
    args = parser.parse_args()
    if args.limit < 0 or args.limit > 100:
        parser.error("limit must be between 0 and 100")
    try:
        document = _load_document(args.document)
        for route, query in extract_routes(document, args.limit):
            print(f"{route}\t{query}")
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        print(f"openapi YAML parse failed: {error}", file=sys.stderr)
        return 2
    except Exception as error:
        # PyYAML parser exceptions vary by version, so malformed documents fail
        # closed without affecting the rest of the scan.
        print(f"openapi YAML parse failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
