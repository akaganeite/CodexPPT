from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from utils.io import read_json, write_json


def text_value(value: Any) -> str:
    return str(value).strip() if isinstance(value, (str, int, float)) else ""


def line_numbers(entries: Any) -> list[int]:
    out = []
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        try:
            line = int(entry.get("line", 0))
        except (TypeError, ValueError):
            continue
        if line > 0 and line not in out:
            out.append(line)
    return sorted(out)


def line_range(value: Any) -> list[int]:
    if not isinstance(value, list) or len(value) != 2:
        return []
    try:
        start, end = int(value[0]), int(value[1])
    except (TypeError, ValueError):
        return []
    return [start, end] if start > 0 and end >= start else []


def canonical_commit(repo: Path, commit: str) -> str:
    if not commit:
        return ""
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", f"{commit}^{{commit}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    resolved = proc.stdout.decode("utf-8", errors="replace").strip()
    return resolved if proc.returncode == 0 and resolved else commit


def analysis_location(analysis: dict[str, Any]) -> dict[str, Any] | None:
    function = analysis.get("function") if isinstance(analysis.get("function"), dict) else {}
    metadata = analysis.get("metadata") if isinstance(analysis.get("metadata"), dict) else {}
    metadata_function = metadata.get("function") if isinstance(metadata.get("function"), dict) else {}
    step_b = analysis.get("step_b") if isinstance(analysis.get("step_b"), dict) else {}
    step_function = step_b.get("function") if isinstance(step_b.get("function"), dict) else {}

    name = text_value(function.get("name") or metadata_function.get("name") or step_function.get("name"))
    file_path = text_value(function.get("file") or metadata_function.get("file") or step_function.get("file"))
    if not name and not file_path:
        return None

    pre_patch = analysis.get("pre_patch_source_sink") if isinstance(analysis.get("pre_patch_source_sink"), dict) else {}
    return {
        "function": name,
        "file": file_path.removeprefix("./"),
        "function_line_range": line_range(
            metadata_function.get("line_range") or step_function.get("line_range")
        ),
        "changed_old_lines": line_numbers(pre_patch.get("old_changed_lines")),
        "changed_new_lines": line_numbers(step_b.get("changed_lines")),
    }


def build_patch_source(repo: Path, source_item: Any, fallback_commit: str = "") -> dict[str, Any]:
    source_item = source_item if isinstance(source_item, dict) else {}
    analyses = source_item.get("function_analyses")
    locations = []
    commit = fallback_commit
    for analysis in analyses if isinstance(analyses, list) else []:
        if not isinstance(analysis, dict):
            continue
        function = analysis.get("function") if isinstance(analysis.get("function"), dict) else {}
        commit = commit or text_value(function.get("commit"))
        location = analysis_location(analysis)
        if location and location not in locations:
            locations.append(location)
    return {"commit": canonical_commit(repo, commit), "locations": locations}


def patch_source_ok(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and isinstance(value.get("commit"), str)
        and isinstance(value.get("locations"), list)
    )


def enrich_behavior_data(
    behavior_data: dict[str, Any],
    source_full: dict[str, Any],
    repo: Path,
    commits: dict[str, str],
    cve_ids: list[str],
) -> int:
    source_cves = source_full.get("cves") if isinstance(source_full.get("cves"), dict) else {}
    updated = 0
    for cve_id in cve_ids:
        item = behavior_data.get(cve_id)
        if not isinstance(item, dict):
            continue
        patch_source = build_patch_source(repo, source_cves.get(cve_id), commits.get(cve_id, ""))
        if item.get("patch_source") != patch_source:
            item["patch_source"] = patch_source
            updated += 1
    return updated


def enrich_behavior_file(
    behavior_path: Path,
    source_full_path: Path,
    repo: Path,
    commits: dict[str, str],
    cve_ids: list[str],
) -> int:
    behavior_data = read_json(behavior_path, {})
    source_full = read_json(source_full_path, {})
    if not isinstance(behavior_data, dict) or not isinstance(source_full, dict):
        return 0
    updated = enrich_behavior_data(behavior_data, source_full, repo, commits, cve_ids)
    if updated:
        write_json(behavior_path, behavior_data)
    return updated
