"""One-command orchestration for the retained Ubuntu deployed workflow."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .candidate_discovery.metadata import CVE_RE, load_metadata, resolve_metadata_path
from .candidate_discovery.ubuntu_groundtruth import SECURITY_CVE_URL, load_cve_json
from .candidate_discovery.ubuntu_tracker_fallback import fetch_tracker_cve
from .dataset_export.finalize import (
    cleanup_work_caches,
    deployed_variant,
    final_groundtruth_path,
    final_testset_path,
    finalize_run_output,
    rebase_finalized_output,
)
from .dataset_export.validator import validate_dataset
from .incremental import completed_cves, load_selection_snapshot, merge_selection_outputs
from .io_utils import read_json, write_json
from .package_acquisition.command_build import handle_build
from .package_acquisition.deepseek_client import DEFAULT_LLM_CONFIG
from .system_utils import download_file
from .testset_selection.command_select import handle_select, persist_selection_updates
from .testset_selection.ubuntu_3v3 import SAMPLING_STRATA, expand_selection_result


def add_run_command(subparsers) -> None:
    parser = subparsers.add_parser(
        "run",
        help="Run the full Ubuntu deployed workflow from base metadata to final dataset.",
    )
    parser.add_argument("-p", "--project", required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parent / "config.json")
    parser.add_argument("--llm-config", type=Path, default=DEFAULT_LLM_CONFIG)
    parser.add_argument("--cve", action="append", default=[])
    parser.add_argument("--cve-file", type=Path, action="append", default=[])
    parser.add_argument("--cve-json", type=Path, action="append", default=[])
    parser.add_argument("--cve-json-dir", type=Path)
    parser.add_argument("--series", action="append")
    parser.add_argument("--arch", default="x86")
    parser.add_argument("--include-esm", action="store_true")
    parser.add_argument("--max-candidates-per-side", type=int, default=8)
    parser.add_argument("--max-per-label", type=int, choices=(1, 2, 3), default=3)
    parser.add_argument("--max-selection-minutes", type=float, default=20.0)
    parser.add_argument("--source-download-timeout", type=int, default=90)
    parser.add_argument("--source-review-timeout", type=int, default=300)
    parser.add_argument("--selection-jobs", type=int, default=1)
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--refresh-package-ranking", action="store_true")
    parser.add_argument("--max-package-families", type=int, default=3)
    parser.add_argument("--max-version-attempts", type=int, default=4)
    parser.add_argument("--max-source-fallback-rounds", type=int, default=2)
    parser.add_argument("--max-search-minutes", type=float, default=30.0)
    parser.add_argument("--skip-download", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--no-sha256", action="store_true")
    parser.add_argument("--skip-validation", action="store_true")
    parser.set_defaults(func=handle_run)


def add_finalize_command(subparsers) -> None:
    parser = subparsers.add_parser(
        "finalize",
        help="Migrate a verified deployed run to the compact base-shaped output layout.",
    )
    parser.add_argument("-p", "--project", required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--arch", default="x86")
    parser.add_argument("--keep-work-cache", action="store_true")
    parser.set_defaults(func=handle_finalize)


def handle_run(args: argparse.Namespace) -> int:
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    rebased = rebase_finalized_output(output)
    if rebased:
        previous_root, current_root = next(iter(rebased.items()))
        print(
            f"[deployed] rebased retained paths from {previous_root} to {current_root}",
            file=sys.stderr,
            flush=True,
        )
    max_per_label = int(getattr(args, "max_per_label", 3) or 3)
    metadata_path = resolve_metadata_path(args.metadata, args.project)
    cve_ids = resolve_requested_cves(args, metadata_path)
    if not cve_ids:
        print("[deployed] run failed: no CVEs selected", file=sys.stderr)
        return 2

    reusable = set()
    if args.resume and not args.refresh and not getattr(args, "refresh_package_ranking", False):
        reusable = completed_cves(
            output,
            args.project,
            args.arch,
            required_count_per_label=max_per_label,
        ) & set(cve_ids)
    pending_cves = [cve_id for cve_id in cve_ids if cve_id not in reusable]
    if reusable:
        print(
            f"[deployed] resume reused {len(reusable)} completed CVEs; pending {len(pending_cves)}",
            file=sys.stderr,
            flush=True,
        )
    if not pending_cves:
        return finish_existing_resume(output, args.project, args.arch, cve_ids)

    auxiliary = output / "deployed"
    input_root = auxiliary / "input"
    input_dir = (args.cve_json_dir or input_root / "ubuntu-cves").expanduser().resolve()
    json_paths, download_report = prepare_ubuntu_jsons(
        pending_cves,
        explicit_paths=args.cve_json,
        input_dir=input_dir,
        refresh=args.refresh,
        timeout=args.source_download_timeout,
    )
    previous_download_report = read_json(input_root / "ubuntu_cve_jsons.json") if (input_root / "ubuntu_cve_jsons.json").is_file() else []
    cumulative_download_report = merge_cve_reports(previous_download_report, download_report, set(pending_cves))
    unavailable_cves = [item for item in cumulative_download_report if item["status"] != "ok"]
    write_json(input_root / "cves.json", cve_ids)
    write_json(input_root / "ubuntu_cve_jsons.json", cumulative_download_report)
    write_json(input_root / "ubuntu_json_excluded.json", unavailable_cves)
    if unavailable_cves:
        excluded_ids = ",".join(item["cve_id"] for item in unavailable_cves)
        print(
            f"[deployed] excluded {len(unavailable_cves)} CVEs without usable Ubuntu Security JSON: {excluded_ids}",
            file=sys.stderr,
            flush=True,
        )
    if not json_paths:
        if reusable:
            return finish_existing_resume(output, args.project, args.arch, cve_ids)
        print("[deployed] run failed: Ubuntu Security has no JSON for any requested CVE", file=sys.stderr)
        return 2

    selection_dir = auxiliary / "selection"
    previous_selection = load_selection_snapshot(selection_dir)
    select_args = argparse.Namespace(
        project=args.project,
        metadata=args.metadata,
        cve_json=json_paths,
        output=selection_dir,
        config=args.config,
        series=args.series,
        arch=args.arch,
        include_esm=args.include_esm,
        max_candidates_per_side=args.max_candidates_per_side,
        max_per_label=max_per_label,
        max_selection_minutes=args.max_selection_minutes,
        source_download_timeout=args.source_download_timeout,
        source_review_timeout=args.source_review_timeout,
        selection_jobs=getattr(args, "selection_jobs", 1),
        refresh=args.refresh,
    )
    rc = handle_select(select_args)
    if rc != 0:
        return rc

    current_cves = set(pending_cves)
    pending_selections = merge_selection_outputs(selection_dir, previous_selection, current_cves=current_cves)
    pending_selection_file = input_root / "pending_selected_3v3.json"
    write_json(pending_selection_file, pending_selections)
    if not pending_selections:
        if reusable:
            return finish_existing_resume(output, args.project, args.arch, cve_ids)
        print("[deployed] run failed: no pending CVE produced a balanced source selection", file=sys.stderr)
        return 2
    build_args = argparse.Namespace(
        project=args.project,
        metadata=args.metadata,
        selection_file=[pending_selection_file],
        output=output,
        config=args.config,
        llm_config=args.llm_config,
        refresh_package_ranking=args.refresh_package_ranking,
        max_package_families=args.max_package_families,
        max_version_attempts=args.max_version_attempts,
        max_per_label=max_per_label,
        max_search_minutes=args.max_search_minutes,
        skip_download=args.skip_download,
        only_stage="",
        resume=args.resume,
        no_sha256=args.no_sha256,
    )
    rc = handle_build(build_args)
    if rc != 0:
        return rc
    if not args.skip_download:
        rc = run_source_fallbacks(
            args,
            output=output,
            selection_dir=selection_dir,
            pending_selection_file=pending_selection_file,
            selections=pending_selections,
            metadata_path=metadata_path,
            build_args=build_args,
        )
        if rc != 0:
            return rc

    if args.skip_validation:
        manifest = finalize_run_output(output, project=args.project, arch=args.arch, metadata=metadata_path)
        result = summary(
            output,
            cve_ids,
            {},
            arch=args.arch,
            manifest=manifest,
            work_caches_retained=True,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    validation, manifest, removed = finalize_verified_run(
        output,
        project=args.project,
        arch=args.arch,
        metadata=metadata_path,
    )
    result = summary(output, cve_ids, validation, arch=args.arch, manifest=manifest, removed_caches=removed)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if validation.get("status") == "ok" else 1


def run_source_fallbacks(
    args: argparse.Namespace,
    *,
    output: Path,
    selection_dir: Path,
    pending_selection_file: Path,
    selections: list[dict[str, Any]],
    metadata_path: Path,
    build_args: argparse.Namespace,
) -> int:
    max_rounds = max(0, int(getattr(args, "max_source_fallback_rounds", 2) or 0))
    max_per_label = int(getattr(args, "max_per_label", 3) or 3)
    if max_rounds < 1:
        return 0
    metadata_by_cve = {
        item.cve_id: item for item in load_metadata(metadata_path, project=args.project)
    }
    selection_by_cve = {
        str(item.get("cve_id") or ""): item for item in selections if item.get("cve_id")
    }
    for round_index in range(1, max_rounds + 1):
        search_path = output / "state" / "package_search.json"
        if not search_path.is_file():
            return 0
        search = read_json(search_path)
        unresolved_reports = {
            str(item.get("cve_id") or ""): item
            for item in search.get("cves") or []
            if item.get("status") != "selected" and str(item.get("cve_id") or "") in selection_by_cve
        }
        if not unresolved_reports:
            return 0
        updated = []
        retry_selections = []
        for cve_id, report in unresolved_reports.items():
            selection = selection_by_cve[cve_id]
            metadata = metadata_by_cve.get(cve_id)
            if metadata is None:
                continue
            expansion = expand_selection_result(
                selection,
                metadata,
                output=selection_dir,
                preferred_strata=failed_sampling_strata(report),
                max_selection_minutes=args.max_selection_minutes,
                source_download_timeout=args.source_download_timeout,
                source_review_timeout=getattr(args, "source_review_timeout", 300),
                max_per_label=max_per_label,
                refresh=args.refresh,
                log=lambda message: print(f"[deployed] {message}", file=sys.stderr, flush=True),
            )
            if not expansion["reviewed_candidate_ids"]:
                continue
            updated.append(selection)
            if expansion["new_pair_count"] > 0:
                retry_selections.append(selection)
            print(
                f"[deployed] source-fallback round={round_index}/{max_rounds} cve={cve_id} "
                f"reviewed={len(expansion['reviewed_candidate_ids'])} new_pairs={expansion['new_pair_count']} "
                f"reserve={expansion['reserve_candidate_count']}",
                file=sys.stderr,
                flush=True,
            )
        if updated:
            persist_selection_updates(selection_dir, updated)
        if not updated:
            return 0
        if not retry_selections:
            continue
        write_json(pending_selection_file, retry_selections)
        build_args.selection_file = [pending_selection_file]
        build_args.resume = True
        rc = handle_build(build_args)
        if rc != 0:
            return rc
    return 0


def failed_sampling_strata(report: dict[str, Any]) -> list[str]:
    seen = set()
    for attempt in report.get("version_attempts") or []:
        if attempt.get("status") == "selected":
            continue
        selected = attempt.get("selection") or {}
        for row in [*(selected.get("vulnerable") or []), *(selected.get("patch") or [])]:
            stratum = str(row.get("sampling_stratum") or "")
            if stratum in SAMPLING_STRATA:
                seen.add(stratum)
    return [stratum for stratum in SAMPLING_STRATA if stratum in seen] or list(SAMPLING_STRATA)


def finish_existing_resume(output: Path, project: str, arch: str, cve_ids: list[str]) -> int:
    validation = validate_dataset(project, output, variant=deployed_variant(arch))
    audit = output / "deployed" / "audit"
    write_json(audit / "validation.json", validation)
    manifest_path = output / "deployed" / "manifest.json"
    manifest = read_json(manifest_path) if manifest_path.is_file() else {}
    print(json.dumps(summary(output, cve_ids, validation, arch=arch, manifest=manifest), indent=2, ensure_ascii=False))
    return 0 if validation.get("status") == "ok" else 1


def merge_cve_reports(previous: Any, current: list[dict[str, Any]], current_cves: set[str]) -> list[dict[str, Any]]:
    previous_rows = previous if isinstance(previous, list) else []
    rows = [
        item
        for item in previous_rows if isinstance(item, dict)
        and str(item.get("cve_id") or "") not in current_cves
    ]
    rows.extend(current)
    return sorted(rows, key=lambda item: str(item.get("cve_id") or ""))


def handle_finalize(args: argparse.Namespace) -> int:
    output = args.output.expanduser().resolve()
    metadata_path = resolve_metadata_path(args.metadata, args.project)
    validation, manifest, removed = finalize_verified_run(
        output,
        project=args.project,
        arch=args.arch,
        metadata=metadata_path,
        cleanup=not args.keep_work_cache,
    )
    result = summary(
        output,
        [],
        validation,
        arch=args.arch,
        manifest=manifest,
        removed_caches=removed,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if validation.get("status") == "ok" else 1


def finalize_verified_run(
    output: Path,
    *,
    project: str,
    arch: str,
    metadata: Path,
    cleanup: bool = True,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    root = output.expanduser().resolve()
    audit = root / "deployed" / "audit"
    legacy_root = root / "dataset"
    validation_root = legacy_root if legacy_root.is_dir() else root
    preliminary = validate_dataset(project, validation_root, variant=deployed_variant(arch))
    write_json(audit / "pre_finalize_validation.json", preliminary)
    if preliminary.get("status") != "ok":
        return preliminary, {}, []

    manifest = finalize_run_output(root, project=project, arch=arch, metadata=metadata)
    variant = deployed_variant(arch)
    finalized = validate_dataset(project, root, variant=variant)
    write_json(audit / "post_layout_validation.json", finalized)
    if finalized.get("status") != "ok" or not cleanup:
        return finalized, manifest, []

    removed = cleanup_work_caches(root)
    final_validation = validate_dataset(project, root, variant=variant)
    write_json(audit / "validation.json", final_validation)
    return final_validation, manifest, removed


def resolve_requested_cves(args: argparse.Namespace, metadata_path: Path) -> list[str]:
    explicit = cve_ids_from_values(args.cve) + cve_ids_from_files(args.cve_file) + cve_ids_from_paths(args.cve_json)
    if explicit:
        return sorted(dict.fromkeys(explicit))
    base_export_ids = cve_ids_from_base_testset(metadata_path, args.project)
    if base_export_ids:
        return base_export_ids
    return sorted(row.cve_id for row in load_metadata(metadata_path, project=args.project) if row.functions)


def cve_ids_from_base_testset(metadata_path: Path, project: str) -> list[str]:
    _ = project
    dataset_root = metadata_path.parent.parent if metadata_path.parent.name in {"export", "exports"} else metadata_path.parent
    for name in ("testset.json", "groundtruth.json"):
        path = dataset_root / "exports" / name
        if not path.is_file():
            path = dataset_root / "export" / name
        if path.is_file():
            ids = cve_ids_from_payload(read_json(path))
            if ids:
                return sorted(dict.fromkeys(ids))
    return []


def cve_ids_from_files(paths: list[Path]) -> list[str]:
    ids: list[str] = []
    for path in paths:
        ids.extend(cve_ids_from_values(path.expanduser().read_text(encoding="utf-8").splitlines()))
    return ids


def cve_ids_from_paths(paths: list[Path]) -> list[str]:
    ids: list[str] = []
    for path in input_paths(paths):
        before = len(ids)
        try:
            payload = load_cve_json(path)
        except (OSError, json.JSONDecodeError, ValueError):
            payload = {}
        ids.extend(cve_ids_from_payload(payload))
        if len(ids) == before:
            ids.extend(cve_ids_from_values([path.stem]))
    return ids


def cve_ids_from_payload(payload: Any) -> list[str]:
    ids: list[str] = []
    if isinstance(payload, dict):
        for key in ("CVE", "cve_id", "id", "cve"):
            value = payload.get(key)
            if isinstance(value, str):
                ids.extend(cve_ids_from_values([value]))
        for value in payload.values():
            if isinstance(value, (dict, list)):
                ids.extend(cve_ids_from_payload(value))
    elif isinstance(payload, list):
        for item in payload:
            ids.extend(cve_ids_from_payload(item))
    elif isinstance(payload, str):
        ids.extend(cve_ids_from_values([payload]))
    return ids


def cve_ids_from_values(values: list[str]) -> list[str]:
    ids: list[str] = []
    for value in values:
        for match in CVE_RE.finditer(str(value)):
            ids.append(match.group(0).upper())
    return ids


def prepare_ubuntu_jsons(
    cve_ids: list[str],
    *,
    explicit_paths: list[Path],
    input_dir: Path,
    refresh: bool,
    timeout: int,
) -> tuple[list[Path], list[dict[str, Any]]]:
    by_cve = {}
    for path in input_paths(explicit_paths):
        for cve_id in cve_ids_from_paths([path]):
            by_cve[cve_id] = path

    report: list[dict[str, Any]] = []
    paths: list[Path] = []
    ubuntu_json_available: bool | None = None
    for cve_id in cve_ids:
        path = by_cve.get(cve_id) or input_dir / f"{cve_id}.json"
        source = "ubuntu_json"
        if path.exists() and not refresh:
            status, message = "ok", "reused"
        else:
            if ubuntu_json_available is not False:
                url = SECURITY_CVE_URL.format(cve_id=cve_id)
                ok, message = download_file(
                    url,
                    path,
                    verify_sha256=False,
                    timeout=min(5, timeout),
                    attempts=1,
                    bypass_proxy=True,
                )
                status = "ok" if ok else ("not_found" if is_http_not_found(message) else "unavailable")
                ubuntu_json_available = status in {"ok", "not_found"}
            else:
                status, message = "unavailable", "Ubuntu Security JSON circuit open"
        if status == "ok":
            try:
                payload = load_cve_json(path)
                if payload.get("tracker_source"):
                    source = "ubuntu_cve_tracker"
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                status, message = "invalid", str(exc)
                ubuntu_json_available = False
        if status != "ok":
            ok, tracker_message = fetch_tracker_cve(cve_id, path, timeout=min(12, timeout))
            if ok:
                status, message, source = "ok", tracker_message, "ubuntu_cve_tracker"
            else:
                message = f"{message}; tracker fallback failed: {tracker_message}"
        report.append(
            {"cve_id": cve_id, "path": str(path), "status": status, "message": message, "source": source}
        )
        if status == "ok":
            paths.append(path)
    return paths, report


def is_http_not_found(message: str) -> bool:
    return str(message).startswith("HTTP Error 404:")


def input_paths(values: list[Path]) -> list[Path]:
    return [Path(item).expanduser().resolve() for value in values for item in str(value).split(",") if item.strip()]


def summary(
    output: Path,
    cve_ids: list[str],
    validation: dict[str, Any],
    *,
    arch: str,
    manifest: dict[str, Any],
    removed_caches: list[str] | None = None,
    work_caches_retained: bool = False,
) -> dict[str, Any]:
    return {
        "schema": "ubuntu-deployed-run-summary-v1",
        "requested_cves": len(cve_ids),
        "output": str(output),
        "selection": str(output / "deployed" / "selection" / "exports" / "selected_3v3.json"),
        "testset": str(final_testset_path(output, arch)),
        "groundtruth": str(final_groundtruth_path(output, arch)),
        "audit": str(output / "deployed" / "audit" / "validation.json"),
        "manifest": manifest,
        "removed_caches": removed_caches or [],
        "work_caches_retained": work_caches_retained,
        "validation": validation or {},
    }
