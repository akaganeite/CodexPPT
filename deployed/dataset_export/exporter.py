from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from ..candidate_discovery.metadata import CveMetadata
from ..io_utils import write_csv, write_json
from ..models import ArtifactResult, LabeledSourceVersion, PackagePair
from ..naming import deployed_export_name
from ..versions import debian_sort_key


TESTSET_STATUSES = {"ok", "inline_only", "dwarf_range_present", "dwarf_available"}


def export_all(
    *,
    project: str,
    output: Path,
    metadata: list[CveMetadata],
    labels: list[LabeledSourceVersion],
    pairs: list[PackagePair],
    artifacts: list[ArtifactResult],
    params: dict[str, Any],
    max_per_label: int = 3,
) -> None:
    exports = output / "exports"
    metadata_by_cve = {item.cve_id: item for item in metadata}
    labels_json = [item.to_json() for item in labels]
    pairs_json = [item.to_json() for item in pairs]
    write_json(exports / f"{project}_ubuntu_trace.json", labels_json)
    write_csv(
        exports / f"{project}_ubuntu_trace.csv",
        labels_json,
        ["cve_id", "source_package", "source_version", "series", "pocket", "component", "label", "reason", "provenance"],
    )
    write_json(exports / f"{project}_deb_ddeb_links.json", pairs_json)
    write_csv(
        exports / f"{project}_deb_ddeb_links.csv",
        pairs_json,
        [
            "cve_id",
            "label",
            "source_version",
            "series",
            "runtime_package",
            "runtime_version",
            "runtime_url",
            "debug_package",
            "debug_version",
            "debug_url",
            "status",
            "candidate_id",
            "requested_functions",
        ],
    )
    write_json(exports / "artifacts.json", [item.to_json() for item in artifacts])
    write_json(exports / "dwarf_candidates.json", build_dwarf_candidates(artifacts))
    write_json(exports / "function_missing.json", build_function_missing(artifacts))
    testset, groundtruth, detailed, testset_1v1 = write_testset_exports(
        output=output,
        metadata_by_cve=metadata_by_cve,
        artifacts=artifacts,
        max_expand=max_per_label,
    )
    prune_unreferenced_binaries(project, output, groundtruth, artifacts)
    write_json(
        exports / "build_report.json",
        build_report(
            project=project,
            metadata=metadata,
            labels=labels,
            pairs=pairs,
            artifacts=artifacts,
            testset=testset,
            groundtruth=groundtruth,
            testset_1v1=testset_1v1,
            params=params,
        ),
    )


def write_testset_exports(
    *,
    output: Path,
    metadata_by_cve: dict[str, CveMetadata],
    artifacts: list[ArtifactResult],
    max_expand: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    exports = output / "exports"
    detailed = build_testset(artifacts, metadata_by_cve, max_per_label=max_expand)
    detailed_1v1 = build_testset(artifacts, metadata_by_cve, max_per_label=1)
    groundtruth = build_groundtruth(detailed)
    testset = build_base_testset(groundtruth)
    groundtruth_1v1 = build_groundtruth(detailed_1v1)
    testset_1v1 = build_base_testset(groundtruth_1v1)
    write_json(exports / "testset_detailed.json", detailed)
    write_json(exports / "testset_1v1.json", testset_1v1)
    write_json(exports / "groundtruth_1v1.json", groundtruth_1v1)
    write_json(exports / "testset.json", testset)
    write_json(exports / "groundtruth.json", groundtruth)
    return testset, groundtruth, detailed, testset_1v1


def build_testset(
    artifacts: Iterable[ArtifactResult],
    metadata_by_cve: dict[str, CveMetadata],
    *,
    max_per_label: int,
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, dict[str, list[ArtifactResult]]]] = defaultdict(
        lambda: {"vuln": defaultdict(list), "patch": defaultdict(list)}
    )
    for artifact in best_artifact_per_version(artifacts):
        if artifact.status not in TESTSET_STATUSES or artifact.label not in {"vuln", "patch"} or not artifact.stripped_path:
            continue
        grouped[artifact.cve_id][artifact.label][artifact.source_version].append(artifact)
    output = []
    for cve_id in sorted(grouped):
        vulnerable_versions = sorted(grouped[cve_id]["vuln"], key=debian_sort_key, reverse=True)
        patched_versions = sorted(grouped[cve_id]["patch"], key=debian_sort_key)
        selected_count = min(max_per_label, len(vulnerable_versions), len(patched_versions))
        if selected_count < 1:
            continue
        vulnerable_versions = vulnerable_versions[:selected_count]
        patched_versions = patched_versions[:selected_count]
        vulnerable = [item for version in vulnerable_versions for item in grouped[cve_id]["vuln"][version]]
        patched = [item for version in patched_versions for item in grouped[cve_id]["patch"][version]]
        metadata = metadata_by_cve.get(cve_id)
        output.append(
            {
                "CVE": cve_id,
                "functions": metadata.functions if metadata else [],
                "summary": metadata.summary if metadata else "",
                "count_per_label": selected_count,
                "vuln": [artifact_entry(item) for item in vulnerable],
                "patch": [artifact_entry(item) for item in patched],
            }
        )
    return output


def best_artifact_per_version(artifacts: Iterable[ArtifactResult]) -> list[ArtifactResult]:
    by_key: dict[tuple[str, str, str, str], ArtifactResult] = {}
    for artifact in artifacts:
        key = (artifact.cve_id, artifact.label, artifact.source_version, artifact.stripped_path)
        previous = by_key.get(key)
        if previous is None or artifact_score(artifact) > artifact_score(previous):
            by_key[key] = artifact
    return list(by_key.values())


def artifact_score(artifact: ArtifactResult) -> tuple[int, int, int]:
    return (
        1 if artifact.status == "ok" else 0,
        len(artifact.found_functions),
        -len(artifact.missing_functions),
    )


def artifact_entry(item: ArtifactResult) -> dict[str, Any]:
    validation = item.report.get("function_validation", {}) if isinstance(item.report, dict) else {}
    return {
        "path": item.stripped_path,
        "debug_path": item.debug_path,
        "name": deployed_export_name(item.stripped_path) if item.stripped_path else "",
        "source_version": item.source_version,
        "runtime_package": item.runtime_package,
        "runtime_version": item.runtime_version,
        "debug_package": item.debug_package,
        "debug_version": item.debug_version,
        "build_id": item.build_id,
        "status": item.status,
        "availability": validation.get("availability", item.status),
        "function_status": validation.get("function_status", {}),
    }


def build_groundtruth(detailed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "CVE": item["CVE"],
            "functions": item.get("functions") or [],
            "vuln": list(dict.fromkeys(entry["name"] for entry in item.get("vuln") or [] if entry.get("name"))),
            "patch": list(dict.fromkeys(entry["name"] for entry in item.get("patch") or [] if entry.get("name"))),
        }
        for item in detailed
    ]


def build_base_testset(groundtruth: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "CVE": item["CVE"],
            "functions": item.get("functions") or [],
            "binaries": list(dict.fromkeys([*(item.get("vuln") or []), *(item.get("patch") or [])])),
        }
        for item in groundtruth
    ]


def prune_unreferenced_binaries(
    project: str,
    output: Path,
    groundtruth: list[dict[str, Any]],
    artifacts: Iterable[ArtifactResult],
) -> None:
    referenced = {
        binary
        for item in groundtruth
        for binary in [*(item.get("vuln") or []), *(item.get("patch") or [])]
    }
    physical_names = {
        Path(artifact.stripped_path).name
        for artifact in artifacts
        if artifact.stripped_path and deployed_export_name(artifact.stripped_path) in referenced
    }
    stripped_dir = output / "binaries" / "target" / f"{project}_stripped"
    debug_dir = output / "binaries" / "target" / f"{project}_debug"
    for path in stripped_dir.glob("*") if stripped_dir.is_dir() else ():
        if path.is_file() and path.name not in physical_names:
            path.unlink()
    expected_debug = {f"{name}.debug" for name in physical_names}
    for path in debug_dir.glob("*.debug") if debug_dir.is_dir() else ():
        if path.is_file() and path.name not in expected_debug:
            path.unlink()


def build_dwarf_candidates(artifacts: Iterable[ArtifactResult]) -> list[dict[str, Any]]:
    output = []
    for artifact in artifacts:
        if artifact.status not in {"inline_only", "dwarf_range_present", "dwarf_available"}:
            continue
        validation = artifact.report.get("function_validation", {}) if isinstance(artifact.report, dict) else {}
        output.append(
            {
                "CVE": artifact.cve_id,
                "label": artifact.label,
                "source_version": artifact.source_version,
                "runtime_package": artifact.runtime_package,
                "debug_package": artifact.debug_package,
                "target_path": artifact.stripped_path,
                "debug_path": artifact.debug_path,
                "availability": validation.get("availability", artifact.status),
                "functions": artifact.functions,
                "function_status": validation.get("function_status", {}),
                "reason": artifact.reason,
            }
        )
    return output


def build_function_missing(artifacts: Iterable[ArtifactResult]) -> list[dict[str, Any]]:
    return [
        {
            "CVE": item.cve_id,
            "label": item.label,
            "source_version": item.source_version,
            "runtime_package": item.runtime_package,
            "debug_package": item.debug_package,
            "target_path": item.stripped_path,
            "debug_path": item.debug_path,
            "missing_functions": item.missing_functions,
            "reason": item.reason,
        }
        for item in artifacts
        if item.status == "function_missing"
    ]


def build_report(
    *,
    project: str,
    metadata: list[CveMetadata],
    labels: list[LabeledSourceVersion],
    pairs: list[PackagePair],
    artifacts: list[ArtifactResult],
    testset: list[dict[str, Any]],
    groundtruth: list[dict[str, Any]],
    testset_1v1: list[dict[str, Any]],
    params: dict[str, Any],
) -> dict[str, Any]:
    return {
        "project": project,
        "params": params,
        "counts": {
            "metadata_cves": len(metadata),
            "metadata_ok": sum(1 for item in metadata if item.status == "ok"),
            "labels": len(labels),
            "labels_by_status": count_by(labels, "label"),
            "pairs": len(pairs),
            "pairs_by_status": count_by(pairs, "status"),
            "artifacts": len(artifacts),
            "artifacts_by_status": count_by(artifacts, "status"),
            "testset_cves": len(testset),
            "groundtruth_cves": len(groundtruth),
            "testset_1v1_cves": len(testset_1v1),
        },
        "metadata_incomplete": [item.to_json() for item in metadata if item.status != "ok"],
    }


def count_by(items: Iterable[Any], attr: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(getattr(item, attr, ""))
        counts[value] = counts.get(value, 0) + 1
    return counts
