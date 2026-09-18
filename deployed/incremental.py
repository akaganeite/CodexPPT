"""Content-based resume checks and cumulative deployed-state merging."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import fields
from pathlib import Path
from typing import Any, TypeVar

from .candidate_discovery.metadata import CveMetadata
from .io_utils import read_json, write_json
from .models import ArtifactResult, LabeledSourceVersion, PackagePair
from .naming import deployed_export_name
from .testset_selection.ubuntu_publication_artifacts import normalize_arch


EXPORTABLE_STATUSES = {"ok", "inline_only", "dwarf_range_present", "dwarf_available"}
T = TypeVar("T")


def completed_cves(
    output: Path,
    project: str,
    arch: str,
    *,
    required_count_per_label: int | None = None,
) -> set[str]:
    root = output.expanduser().resolve()
    variant = f"ubuntu-{normalize_arch(arch)}"
    exports = root / "exports"
    trace = root / "deployed" / "trace"
    testset = read_optional_json(exports / f"testset.{variant}.json", [])
    groundtruth = read_optional_json(exports / f"groundtruth.{variant}.json", [])
    detailed = read_optional_json(trace / "testset_detailed.json", [])
    if not all(isinstance(value, list) for value in (testset, groundtruth, detailed)):
        return set()

    state = root / "deployed" / "state"
    resolved = read_optional_json(state / "resolved_3v3.json", [])
    artifacts = read_optional_json(state / "artifact_results.json", [])
    if not isinstance(resolved, list) or not isinstance(artifacts, list):
        return set()
    resolved_cves = {
        str(item.get("cve_id") or "")
        for item in resolved
        if isinstance(item, dict) and item.get("cve_id")
    }
    state_names: dict[str, set[str]] = defaultdict(set)
    for item in artifacts:
        if not valid_state_artifact(item):
            continue
        state_names[str(item["cve_id"])].add(deployed_export_name(str(item["stripped_path"])))

    testset_by_cve = rows_by_cve(testset, "CVE")
    truth_by_cve = rows_by_cve(groundtruth, "CVE")
    completed: set[str] = set()
    for detail in detailed:
        if not isinstance(detail, dict):
            continue
        cve_id = str(detail.get("CVE") or "")
        test = testset_by_cve.get(cve_id)
        truth = truth_by_cve.get(cve_id)
        if not cve_id or not test or not truth:
            continue
        vuln = list(detail.get("vuln") or [])
        patch = list(detail.get("patch") or [])
        vuln_versions = {str(item.get("source_version") or "") for item in vuln if isinstance(item, dict)}
        patch_versions = {str(item.get("source_version") or "") for item in patch if isinstance(item, dict)}
        if "" in vuln_versions or "" in patch_versions:
            continue
        if len(vuln_versions) != len(patch_versions) or not 1 <= len(vuln_versions) <= 3:
            continue
        if required_count_per_label is not None and len(vuln_versions) != required_count_per_label:
            continue
        entries = [*vuln, *patch]
        if not entries or not all(valid_artifact_entry(item) for item in entries):
            continue
        detailed_vuln = {str(item.get("name") or "") for item in vuln}
        detailed_patch = {str(item.get("name") or "") for item in patch}
        truth_vuln = set(truth.get("vuln") or [])
        truth_patch = set(truth.get("patch") or [])
        test_binaries = set(test.get("binaries") or [])
        if detailed_vuln != truth_vuln or detailed_patch != truth_patch:
            continue
        if test_binaries != truth_vuln | truth_patch:
            continue
        if cve_id not in resolved_cves or not test_binaries <= state_names[cve_id]:
            continue
        completed.add(cve_id)
    return completed


def valid_artifact_entry(item: Any) -> bool:
    if not isinstance(item, dict) or item.get("status") not in EXPORTABLE_STATUSES:
        return False
    if not str(item.get("build_id") or ""):
        return False
    return Path(str(item.get("path") or "")).is_file() and Path(str(item.get("debug_path") or "")).is_file()


def valid_state_artifact(item: Any) -> bool:
    if not isinstance(item, dict) or item.get("status") not in EXPORTABLE_STATUSES:
        return False
    if not item.get("cve_id") or not item.get("build_id"):
        return False
    return Path(str(item.get("stripped_path") or "")).is_file() and Path(
        str(item.get("debug_path") or "")
    ).is_file()


def load_build_snapshot(output: Path) -> dict[str, Any]:
    root = output.expanduser().resolve()
    active_state = root / "state"
    state = active_state if active_state.is_dir() else root / "deployed" / "state"
    if not state.is_dir():
        return empty_build_snapshot()
    return {
        "metadata": hydrate_rows(CveMetadata, read_optional_json(state / "metadata_rows.json", [])),
        "labels": hydrate_rows(LabeledSourceVersion, read_optional_json(state / "ubuntu_labels.json", [])),
        "pairs": hydrate_rows(PackagePair, read_optional_json(state / "package_pairs.json", [])),
        "artifacts": hydrate_rows(ArtifactResult, read_optional_json(state / "artifact_results.json", [])),
        "selections": list(read_optional_json(state / "selected_3v3.json", [])),
        "resolved_selections": list(read_optional_json(state / "resolved_3v3.json", [])),
        "rankings": dict(read_optional_json(state / "package_rankings.json", {})),
        "search": dict(read_optional_json(state / "package_search.json", {})),
    }


def empty_build_snapshot() -> dict[str, Any]:
    return {
        "metadata": [],
        "labels": [],
        "pairs": [],
        "artifacts": [],
        "selections": [],
        "resolved_selections": [],
        "rankings": {},
        "search": {},
    }


def merge_build_snapshot(
    previous: dict[str, Any],
    *,
    current_cves: set[str],
    metadata: list[CveMetadata],
    labels: list[LabeledSourceVersion],
    pairs: list[PackagePair],
    artifacts: list[ArtifactResult],
    selections: list[dict[str, Any]],
    resolved_selections: list[dict[str, Any]],
    rankings: dict[str, Any],
    search: dict[str, Any],
) -> dict[str, Any]:
    successful_cves = {
        str(item.get("cve_id") or "")
        for item in resolved_selections
        if isinstance(item, dict) and item.get("cve_id")
    }
    merged_search = merge_search_reports(previous.get("search") or {}, search)
    return {
        "metadata": replace_dataclass_cves(previous.get("metadata") or [], metadata, current_cves),
        "labels": replace_dataclass_cves(previous.get("labels") or [], labels, successful_cves),
        "pairs": replace_dataclass_cves(previous.get("pairs") or [], pairs, successful_cves),
        "artifacts": replace_dataclass_cves(previous.get("artifacts") or [], artifacts, successful_cves),
        "selections": replace_dict_cves(previous.get("selections") or [], selections, current_cves),
        "resolved_selections": replace_dict_cves(
            previous.get("resolved_selections") or [], resolved_selections, successful_cves
        ),
        "rankings": {**dict(previous.get("rankings") or {}), **rankings},
        "search": merged_search,
    }


def merge_search_reports(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    reports = {
        str(item.get("cve_id") or ""): item
        for item in previous.get("cves") or []
        if isinstance(item, dict) and item.get("cve_id")
    }
    for item in current.get("cves") or []:
        if not isinstance(item, dict) or not item.get("cve_id"):
            continue
        cve_id = str(item["cve_id"])
        existing = reports.get(cve_id)
        if item.get("status") == "selected" or not existing or existing.get("status") != "selected":
            reports[cve_id] = item
    cve_reports = [reports[cve_id] for cve_id in sorted(reports)]
    resolved = replace_dict_cves(
        list(previous.get("resolved_selections") or []),
        list(current.get("resolved_selections") or []),
        {
            str(item.get("cve_id") or "")
            for item in current.get("resolved_selections") or []
            if isinstance(item, dict)
        },
    )
    policy = {**dict(previous.get("policy") or {}), **dict(current.get("policy") or {})}
    return {
        "schema": current.get("schema") or previous.get("schema") or "ubuntu-adaptive-package-search-v2",
        "policy": policy,
        "cves": cve_reports,
        "resolved_selections": resolved,
        "selected_cves": sum(item.get("status") == "selected" for item in cve_reports),
        "unresolved_cves": sum(item.get("status") != "selected" for item in cve_reports),
    }


def load_selection_snapshot(selection_dir: Path) -> dict[str, Any]:
    exports = selection_dir / "exports"
    return {
        "selected": list(read_optional_json(exports / "selected_3v3.json", [])),
        "excluded": list(read_optional_json(exports / "excluded_cves.json", [])),
        "matrix": list(read_optional_json(exports / "candidate_matrix.json", [])),
        "summary": dict(read_optional_json(exports / "select_3v3_summary.json", {})),
    }


def merge_selection_outputs(
    selection_dir: Path,
    previous: dict[str, Any],
    *,
    current_cves: set[str],
) -> list[dict[str, Any]]:
    exports = selection_dir / "exports"
    current_selected = list(read_optional_json(exports / "selected_3v3.json", []))
    current_excluded = list(read_optional_json(exports / "excluded_cves.json", []))
    current_matrix = list(read_optional_json(exports / "candidate_matrix.json", []))
    current_summary = dict(read_optional_json(exports / "select_3v3_summary.json", {}))
    merged_selected = replace_dict_cves(previous.get("selected") or [], current_selected, current_cves)
    merged_excluded = replace_dict_cves(previous.get("excluded") or [], current_excluded, current_cves)
    merged_matrix = replace_dict_cves(previous.get("matrix") or [], current_matrix, current_cves)
    summary = {
        "schema": current_summary.get("schema") or previous.get("summary", {}).get("schema") or "ubuntu-balanced-candidate-summary-v3",
        "project": current_summary.get("project") or previous.get("summary", {}).get("project") or "",
        "metadata": current_summary.get("metadata") or previous.get("summary", {}).get("metadata") or "",
        "requested_arch": current_summary.get("requested_arch") or previous.get("summary", {}).get("requested_arch") or "",
        "requested_cves": len(merged_selected) + len(merged_excluded),
        "selected_cves": len(merged_selected),
        "excluded_cves": len(merged_excluded),
        "selected": [selection_summary(item) for item in merged_selected],
    }
    write_json(exports / "selected_3v3.json", merged_selected)
    write_json(exports / "excluded_cves.json", merged_excluded)
    write_json(exports / "candidate_matrix.json", merged_matrix)
    write_json(exports / "select_3v3_summary.json", summary)
    return current_selected


def selection_summary(result: dict[str, Any]) -> dict[str, Any]:
    selected = result.get("selected") or {}
    return {
        "cve_id": result.get("cve_id") or "",
        "count_per_label": selected.get("count_per_label", 0),
        "series": selected.get("series", ""),
        "ubuntu_release": selected.get("ubuntu_release", ""),
        "vulnerable_versions": [item.get("source_version", "") for item in selected.get("vulnerable") or []],
        "patch_versions": [item.get("source_version", "") for item in selected.get("patch") or []],
        "selection_score": selected.get("selection_score") or {},
    }


def replace_dataclass_cves(previous: list[T], current: list[T], replace_cves: set[str]) -> list[T]:
    output = [item for item in previous if str(getattr(item, "cve_id", "")) not in replace_cves]
    output.extend(current)
    return output


def replace_dict_cves(
    previous: list[dict[str, Any]], current: list[dict[str, Any]], replace_cves: set[str]
) -> list[dict[str, Any]]:
    output = [item for item in previous if str(item.get("cve_id") or item.get("CVE") or "") not in replace_cves]
    output.extend(current)
    return sorted(output, key=lambda item: str(item.get("cve_id") or item.get("CVE") or ""))


def hydrate_rows(record_type: type[T], rows: Any) -> list[T]:
    if not isinstance(rows, list):
        return []
    names = {field.name for field in fields(record_type)}
    output = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            output.append(record_type(**{key: value for key, value in row.items() if key in names}))
        except TypeError:
            continue
    return output


def rows_by_cve(rows: list[Any], key: str) -> dict[str, dict[str, Any]]:
    return {
        str(item.get(key) or ""): item
        for item in rows
        if isinstance(item, dict) and item.get(key)
    }


def read_optional_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return read_json(path)
    except (OSError, ValueError):
        return default
