"""Audit final deployed dataset exports and binary layout."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from ..io_utils import read_json, write_json
from ..naming import deployed_export_name


EXPORTABLE_STATUSES = {"ok", "inline_only", "dwarf_range_present", "dwarf_available"}


def validate_dataset(project: str, output: Path, *, variant: str = "") -> dict[str, Any]:
    root = output.expanduser().resolve()
    exports = root / "exports"
    trace = root / "deployed" / "trace"
    state = root / "deployed" / "state"
    testset = read_json(resolve_variant_export(exports, "testset", variant)) or []
    groundtruth = read_json(resolve_variant_export(exports, "groundtruth", variant)) or []
    detailed = read_json(existing_path(exports / "testset_detailed.json", trace / "testset_detailed.json")) or []
    artifacts = read_json(existing_path(exports / "artifacts.json", trace / "artifacts.json")) or []
    search = read_json(existing_path(root / "state" / "package_search.json", state / "package_search.json")) or {}
    resolved_search_cves = int(search.get("selected_cves") or 0)
    unresolved_search_cves = int(search.get("unresolved_cves") or 0)
    stripped_dir = root / "binaries" / "target" / f"{project}_stripped"
    debug_dir = root / "binaries" / "target" / f"{project}_debug"
    errors: list[str] = []
    warnings: list[str] = []

    testset_by_cve = {str(item.get("CVE") or ""): item for item in testset}
    groundtruth_by_cve = {str(item.get("CVE") or ""): item for item in groundtruth}
    detailed_by_cve = {str(item.get("CVE") or ""): item for item in detailed}
    if not testset_by_cve:
        errors.append("dataset contains no exported CVEs")
    if set(testset_by_cve) != set(groundtruth_by_cve) or set(testset_by_cve) != set(detailed_by_cve):
        errors.append("testset, groundtruth, and detailed CVE sets differ")

    for cve_id, truth in groundtruth_by_cve.items():
        test_binaries = set(testset_by_cve.get(cve_id, {}).get("binaries") or [])
        truth_binaries = set([*(truth.get("vuln") or []), *(truth.get("patch") or [])])
        if test_binaries != truth_binaries:
            errors.append(f"{cve_id}: testset binaries differ from groundtruth union")
        detail = detailed_by_cve.get(cve_id) or {}
        vulnerable_versions = {
            str(item.get("source_version") or "") for item in detail.get("vuln") or []
        }
        patch_versions = {
            str(item.get("source_version") or "") for item in detail.get("patch") or []
        }
        if len(vulnerable_versions) != len(patch_versions):
            errors.append(
                f"{cve_id}: unbalanced source versions "
                f"({len(vulnerable_versions)} vuln, {len(patch_versions)} patch)"
            )
        elif not 1 <= len(vulnerable_versions) <= 3:
            errors.append(
                f"{cve_id}: balanced source-version count must be between 1 and 3, "
                f"got {len(vulnerable_versions)}"
            )
    referenced_binaries = {
        binary
        for truth in groundtruth_by_cve.values()
        for binary in [*(truth.get("vuln") or []), *(truth.get("patch") or [])]
    }
    stripped_files = list(stripped_dir.glob("*")) if stripped_dir.is_dir() else []
    debug_files = list(debug_dir.glob("*.debug")) if debug_dir.is_dir() else []
    unreferenced_stripped = sorted(
        path.name for path in stripped_files if deployed_export_name(path.name) not in referenced_binaries
    )
    unreferenced_debug = sorted(
        path.name
        for path in debug_files
        if deployed_export_name(path.name.removesuffix(".debug")) not in referenced_binaries
    )
    if unreferenced_stripped:
        errors.append(f"unreferenced stripped binaries remain: {len(unreferenced_stripped)}")
    if unreferenced_debug:
        errors.append(f"unreferenced debug binaries remain: {len(unreferenced_debug)}")
    accepted_artifacts = [
        item
        for item in artifacts
        if item.get("status") in EXPORTABLE_STATUSES
        and deployed_export_name(str(item.get("stripped_path") or "")) in referenced_binaries
    ]
    artifact_names = {
        deployed_export_name(str(item.get("stripped_path") or ""))
        for item in accepted_artifacts
        if item.get("stripped_path")
    }
    for cve_id, truth in groundtruth_by_cve.items():
        for binary in sorted([*(truth.get("vuln") or []), *(truth.get("patch") or [])]):
            if binary not in artifact_names:
                errors.append(f"{cve_id}: no exportable artifact for binary: {binary}")
    for item in accepted_artifacts:
        if not item.get("build_id"):
            errors.append(
                f"{item.get('cve_id')}:{item.get('source_version')}: exportable artifact has empty Build-ID"
            )
        if not Path(str(item.get("stripped_path") or "")).is_file():
            errors.append(
                f"{item.get('cve_id')}:{item.get('source_version')}: artifact stripped_path does not exist"
            )
        if not Path(str(item.get("debug_path") or "")).is_file():
            errors.append(
                f"{item.get('cve_id')}:{item.get('source_version')}: artifact debug_path does not exist"
            )
    non_exportable = [
        item
        for item in artifacts
        if item.get("status") not in EXPORTABLE_STATUSES
        or deployed_export_name(str(item.get("stripped_path") or "")) not in referenced_binaries
    ]
    if non_exportable:
        warnings.append(f"artifact report contains {len(non_exportable)} non-exportable rows")
    if unresolved_search_cves:
        warnings.append(f"package search left {unresolved_search_cves} unresolved CVEs")

    return {
        "schema": "ubuntu-deployed-dataset-validation-v1",
        "project": project,
        "output": str(root),
        "status": "ok" if not errors else "failed",
        "counts": {
            "testset_cves": len(testset),
            "groundtruth_cves": len(groundtruth),
            "detailed_cves": len(detailed),
            "artifact_rows": len(artifacts),
            "exportable_artifact_rows": len(accepted_artifacts),
            "stripped_files": len(stripped_files),
            "debug_files": len(debug_files),
            "resolved_search_cves": resolved_search_cves,
            "unresolved_search_cves": unresolved_search_cves,
        },
        "errors": errors,
        "warnings": warnings,
    }


def resolve_variant_export(exports: Path, name: str, variant: str) -> Path:
    canonical = exports / f"{name}.json"
    if canonical.is_file():
        return canonical
    if variant:
        candidate = exports / f"{name}.{variant}.json"
        if candidate.is_file():
            return candidate
        raise FileNotFoundError(f"missing {name} export for variant {variant}: {candidate}")
    candidates = sorted(exports.glob(f"{name}.ubuntu-*.json"))
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise FileNotFoundError(f"missing {name} export under {exports}")
    raise ValueError(f"multiple {name} variants found; specify --variant")


def existing_path(*candidates: Path) -> Path:
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit final deployed dataset outputs.")
    parser.add_argument("-p", "--project", required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--variant", default="")
    args = parser.parse_args()
    result = validate_dataset(args.project, args.dataset, variant=args.variant)
    write_json(args.output, result)
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
