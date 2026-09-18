"""Cheap package-ranking hints derived from base exports and source paths."""

from __future__ import annotations

import json
import re
import sqlite3
import urllib.parse
from pathlib import Path
from typing import Any

from ..candidate_discovery.metadata import CveMetadata
from ..io_utils import read_json


GENERIC_SOURCE_COMPONENTS = {"common", "include", "lib", "source", "src", "test", "tests", "tool", "tools"}


def metadata_function_files(metadata: CveMetadata) -> dict[str, str]:
    function_code = metadata.raw.get("function_code") or {}
    by_function = dict(function_code.get("by_function") or {}) if isinstance(function_code, dict) else {}
    return {
        function: str((by_function.get(function) or {}).get("file") or "")
        for function in metadata.functions
    }


def source_component_hints(source_files: Any) -> list[str]:
    output = []
    for source_file in source_files:
        parts = Path(str(source_file)).parts
        if len(parts) < 2:
            continue
        component = re.sub(r"[^a-z0-9]+", "", parts[0].lower())
        if component and component not in GENERIC_SOURCE_COMPONENTS and component not in output:
            output.append(component)
    return output


def package_matches_hint(package: str, hint: str) -> bool:
    normalized_package = re.sub(r"[^a-z0-9]+", "", package.lower())
    normalized_hint = re.sub(r"[^a-z0-9]+", "", Path(hint).name.lower())
    return bool(normalized_package and normalized_hint and normalized_hint in normalized_package)


def package_matches_component(package: str, component: str) -> bool:
    normalized_package = re.sub(r"[^a-z0-9]+", "", package.lower())
    normalized_component = re.sub(r"[^a-z0-9]+", "", component.lower())
    # Generic directories such as lib/ or src/ are too weak to affect package ranking.
    return bool(
        normalized_component
        and normalized_component not in GENERIC_SOURCE_COMPONENTS
        and normalized_component in normalized_package
    )


def load_base_binary_hints(metadata_path: Path, project: str, cve_id: str) -> tuple[list[str], list[str]]:
    dataset_root = metadata_dataset_root(metadata_path)
    hints: set[str] = set()
    sources: list[str] = []
    database_path = dataset_root / f"{project}.sqlite"
    if database_path.is_file():
        try:
            uri = f"file:{urllib.parse.quote(str(database_path))}?mode=ro"
            with sqlite3.connect(uri, uri=True) as connection:
                rows = connection.execute(
                    "SELECT DISTINCT binary_name FROM testset_entries WHERE cve_id = ? AND binary_name != ''",
                    (cve_id,),
                ).fetchall()
            hints.update(str(row[0]) for row in rows if row and row[0])
            if rows:
                sources.append(str(database_path))
        except sqlite3.Error:
            pass
    for export_path in sorted((dataset_root / "exports").glob("groundtruth*.json")):
        try:
            before = len(hints)
            collect_export_binary_hints(read_json(export_path), cve_id, hints)
            if len(hints) > before:
                sources.append(str(export_path))
        except (OSError, json.JSONDecodeError):
            continue
    return sorted(hints), sources


def metadata_dataset_root(metadata_path: Path) -> Path:
    return metadata_path.parent.parent if metadata_path.parent.name in {"export", "exports"} else metadata_path.parent


def collect_export_binary_hints(value: Any, cve_id: str, hints: set[str], *, in_cve: bool = False) -> None:
    if isinstance(value, dict):
        current_cve = str(value.get("cve_id") or value.get("CVE") or value.get("id") or "")
        scoped = in_cve or current_cve.upper() == cve_id.upper()
        if scoped and isinstance(value.get("binary_name"), str) and value["binary_name"]:
            hints.add(value["binary_name"])
        for key, child in value.items():
            collect_export_binary_hints(child, cve_id, hints, in_cve=scoped or str(key).upper() == cve_id.upper())
    elif isinstance(value, list):
        for child in value:
            collect_export_binary_hints(child, cve_id, hints, in_cve=in_cve)
