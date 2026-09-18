"""CLI handler for balanced Ubuntu candidate-pool selection."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

from ..candidate_discovery.metadata import load_metadata, resolve_metadata_path
from ..candidate_discovery.ubuntu_groundtruth import load_cve_json
from ..config import load_config, parse_csv_args, require_project
from ..io_utils import read_json, write_json
from ..logging_utils import BuildLogger
from .ubuntu_3v3 import select_3v3_for_cve


def add_select_command(subparsers) -> None:
    parser = subparsers.add_parser(
        "select-3v3",
        help="Select a balanced Tier1 candidate pool with up to three versions per label.",
    )
    parser.add_argument("-p", "--project", required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--cve-json", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parents[1] / "config.json")
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
    parser.set_defaults(func=handle_select)


def handle_select(args: argparse.Namespace) -> int:
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    logger = BuildLogger(output / "select_3v3.log")
    project = require_project(load_config(args.config), args.project)
    metadata_path = resolve_metadata_path(args.metadata, args.project)
    metadata_by_cve = {item.cve_id: item for item in load_metadata(metadata_path, project=args.project)}
    paths = input_paths(args.cve_json)

    def select_path(path: Path) -> dict:
        try:
            payload = load_cve_json(path)
            cve_id = str(payload.get("id") or payload.get("cve_id") or "").upper()
            metadata = metadata_by_cve.get(cve_id)
            if metadata is None:
                result = {"cve_id": cve_id, "status": "metadata_missing", "selected": None, "series_attempts": []}
            else:
                result = select_3v3_for_cve(
                    payload,
                    metadata,
                    source_package=project.source_package,
                    output=output,
                    arch=args.arch,
                    series_filter=parse_csv_args(args.series),
                    include_esm=args.include_esm,
                    max_candidates_per_side=args.max_candidates_per_side,
                    max_per_label=args.max_per_label,
                    max_selection_minutes=args.max_selection_minutes,
                    source_download_timeout=args.source_download_timeout,
                    source_review_timeout=args.source_review_timeout,
                    refresh=args.refresh,
                    log=logger.log,
                )
        except Exception as exc:
            result = {"cve_id": path.stem, "status": "failed", "selected": None, "series_attempts": [], "error": str(exc)}
        write_json(output / "exports" / "3v3" / f"{result['cve_id']}.json", result)
        return result

    jobs = max(1, int(getattr(args, "selection_jobs", 1) or 1))
    if jobs == 1:
        results = [select_path(path) for path in paths]
    else:
        with ThreadPoolExecutor(max_workers=jobs, thread_name_prefix="deployed-select") as executor:
            results = list(executor.map(select_path, paths))
    selected = [item for item in results if item.get("selected")]
    excluded = [item for item in results if not item.get("selected")]
    summary = {
        "schema": "ubuntu-balanced-candidate-summary-v3",
        "project": args.project,
        "metadata": str(metadata_path),
        "requested_arch": args.arch,
        "requested_cves": len(results),
        "selected_cves": len(selected),
        "excluded_cves": len(excluded),
        "selected": [selection_summary(item) for item in selected],
    }
    write_json(output / "exports" / "selected_3v3.json", selected)
    write_json(output / "exports" / "excluded_cves.json", excluded)
    write_json(output / "exports" / "candidate_matrix.json", candidate_matrix(results))
    write_json(output / "exports" / "select_3v3_summary.json", summary)
    logger.log(f"select-3v3 done selected={len(selected)} excluded={len(excluded)}")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


def selection_summary(result: dict) -> dict:
    selected = result["selected"]
    return {
        "cve_id": result["cve_id"],
        "count_per_label": selected.get("count_per_label", 0),
        "series": selected["series"],
        "ubuntu_release": selected["ubuntu_release"],
        "vulnerable_versions": [item["source_version"] for item in selected["vulnerable"]],
        "patch_versions": [item["source_version"] for item in selected["patch"]],
        "selection_score": selected["selection_score"],
    }


def candidate_matrix(results: list[dict]) -> list[dict]:
    return [
        {
            "cve_id": result.get("cve_id"),
            "series": attempt.get("series"),
            "ubuntu_release": attempt.get("ubuntu_release"),
            "fixed_source_version": attempt.get("fixed_source_version"),
            "status": attempt.get("status"),
            "reason": attempt.get("reason"),
            "candidates": attempt.get("candidate_matrix") or [],
        }
        for result in results
        for attempt in result.get("series_attempts") or []
    ]


def persist_selection_updates(output: Path, updates: list[dict]) -> list[dict]:
    if not updates:
        return []
    exports = output / "exports"
    update_ids = {str(item.get("cve_id") or "") for item in updates}
    selected_path = exports / "selected_3v3.json"
    excluded_path = exports / "excluded_cves.json"
    matrix_path = exports / "candidate_matrix.json"
    summary_path = exports / "select_3v3_summary.json"
    selected = [
        item
        for item in (read_json(selected_path) if selected_path.is_file() else [])
        if str(item.get("cve_id") or "") not in update_ids
    ]
    selected.extend(item for item in updates if item.get("selected"))
    selected.sort(key=lambda item: str(item.get("cve_id") or ""))
    excluded = [
        item
        for item in (read_json(excluded_path) if excluded_path.is_file() else [])
        if str(item.get("cve_id") or "") not in update_ids
    ]
    excluded.extend(item for item in updates if not item.get("selected"))
    excluded.sort(key=lambda item: str(item.get("cve_id") or ""))
    matrix = [
        item
        for item in (read_json(matrix_path) if matrix_path.is_file() else [])
        if str(item.get("cve_id") or "") not in update_ids
    ]
    matrix.extend(candidate_matrix(updates))
    summary = read_json(summary_path) if summary_path.is_file() else {}
    summary.update(
        {
            "requested_cves": len(selected) + len(excluded),
            "selected_cves": len(selected),
            "excluded_cves": len(excluded),
            "selected": [selection_summary(item) for item in selected],
        }
    )
    for item in updates:
        write_json(exports / "3v3" / f"{item['cve_id']}.json", item)
    write_json(selected_path, selected)
    write_json(excluded_path, excluded)
    write_json(matrix_path, matrix)
    write_json(summary_path, summary)
    return selected


def input_paths(values: list[Path]) -> list[Path]:
    return [Path(item).expanduser().resolve() for value in values for item in str(value).split(",") if item.strip()]
