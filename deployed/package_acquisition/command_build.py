"""CLI handler for ranked sequential deb/ddeb materialization and export."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .artifacts import process_artifacts
from ..candidate_discovery.metadata import load_metadata, resolve_metadata_path
from ..config import load_config, require_project
from ..dataset_export.exporter import export_all
from ..incremental import load_build_snapshot, merge_build_snapshot
from ..io_utils import write_json
from ..logging_utils import BuildLogger
from .package_hints import load_base_binary_hints
from .deepseek_client import DEFAULT_LLM_CONFIG
from .selected_build import (
    ensure_package_rankings,
    labels_from_selections,
    load_selection_results,
    materialize_ranked_selections,
    planned_pairs_from_rankings,
)


STAGES = ("metadata", "label", "pair", "artifact", "export")


def add_build_command(subparsers) -> None:
    parser = subparsers.add_parser(
        "build",
        help="Resolve and build balanced binaries with up to three versions per label.",
    )
    parser.add_argument("-p", "--project", required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--selection-file", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parents[1] / "config.json")
    parser.add_argument("--llm-config", type=Path, default=DEFAULT_LLM_CONFIG)
    parser.add_argument("--refresh-package-ranking", action="store_true")
    parser.add_argument("--max-package-families", type=int, default=3)
    parser.add_argument("--max-version-attempts", type=int, default=4)
    parser.add_argument("--max-per-label", type=int, choices=(1, 2, 3), default=3)
    parser.add_argument("--max-search-minutes", type=float, default=30.0)
    parser.add_argument("--skip-download", action="store_true")
    parser.add_argument("--only-stage", choices=STAGES, default="")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--no-sha256", action="store_true")
    parser.set_defaults(func=handle_build)


def handle_build(args: argparse.Namespace) -> int:
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    max_per_label = int(getattr(args, "max_per_label", 3) or 3)
    logger = BuildLogger(output / "build.log")
    bundle = load_config(args.config)
    project = require_project(bundle, args.project)
    metadata_path = resolve_metadata_path(args.metadata, args.project)
    previous = load_build_snapshot(output) if args.resume else None
    state = output / "state"
    state.mkdir(parents=True, exist_ok=True)
    params = {
        "project": args.project,
        "metadata": str(metadata_path),
        "selection_files": [str(path.expanduser().resolve()) for path in args.selection_file],
        "output": str(output),
        "llm_config": str(args.llm_config.expanduser().resolve()),
        "refresh_package_ranking": args.refresh_package_ranking,
        "max_package_families": args.max_package_families,
        "max_version_attempts": args.max_version_attempts,
        "max_per_label": max_per_label,
        "max_search_minutes": args.max_search_minutes,
        "skip_download": args.skip_download,
        "resume": args.resume,
        "verify_sha256": bundle.defaults.verify_sha256 and not args.no_sha256,
    }
    write_json(state / "build_params.json", params)
    logger.log(f"stage=metadata start project={args.project}")
    all_metadata = load_metadata(metadata_path, project=args.project)
    selections = [item for path in args.selection_file for item in load_selection_results(path)]
    selected_cves = {str(item.get("cve_id") or "") for item in selections}
    metadata = [item for item in all_metadata if item.cve_id in selected_cves]
    metadata_by_cve = {item.cve_id: item for item in metadata}
    missing = sorted(selected_cves - set(metadata_by_cve))
    if missing:
        logger.log(f"build failed metadata_missing={','.join(missing)}")
        return 2
    write_json(state / "metadata_rows.json", [item.to_json() for item in metadata])
    logger.log(f"stage=metadata done rows={len(metadata)}")
    if stop_after(args, "metadata"):
        return 0

    labels = labels_from_selections(selections, metadata_by_cve)
    write_json(state / "ubuntu_labels.json", [item.to_json() for item in labels])
    logger.log(f"stage=label done labels={len(labels)}")
    if stop_after(args, "label"):
        export_all(project=args.project, output=output, metadata=metadata, labels=labels, pairs=[], artifacts=[], params=params, max_per_label=max_per_label)
        return 0

    hints = {cve_id: load_base_binary_hints(metadata_path, args.project, cve_id)[0] for cve_id in selected_cves}
    rankings = ensure_package_rankings(
        selections,
        metadata_by_cve,
        project,
        output=output,
        config_path=args.llm_config,
        base_binary_hints=hints,
        refresh=args.refresh_package_ranking,
        log=logger.log,
    )
    for cve_id, ranking in rankings.items():
        write_json(output / "exports" / "package_rankings" / f"{cve_id}.json", ranking)
    write_json(state / "package_rankings.json", rankings)
    write_json(state / "selected_3v3.json", selections)
    planned_pairs = planned_pairs_from_rankings(selections, rankings)
    write_json(state / "package_pairs_planned.json", [item.to_json() for item in planned_pairs])
    logger.log(f"stage=pair done planned_pairs={len(planned_pairs)}")
    if stop_after(args, "pair"):
        export_all(project=args.project, output=output, metadata=metadata, labels=labels, pairs=planned_pairs, artifacts=[], params=params, max_per_label=max_per_label)
        return 0

    if args.skip_download:
        pairs = planned_pairs
        artifacts = process_artifacts(
            project=project,
            pairs=pairs,
            metadata_by_cve=metadata_by_cve,
            output=output,
            verify_sha256=params["verify_sha256"],
            resume=args.resume,
            skip_download=True,
            log=logger.log,
        )
        search_report = {"schema": "ubuntu-ranked-package-search-v1", "status": "skipped", "tasks": []}
        resolved_selections = []
    else:
        pairs, artifacts, search_report = materialize_ranked_selections(
            selections,
            rankings,
            project,
            output=output,
            verify_sha256=params["verify_sha256"],
            resume=args.resume,
            max_family_attempts=args.max_package_families,
            max_version_attempts=args.max_version_attempts,
            max_per_label=max_per_label,
            max_search_minutes=args.max_search_minutes,
            log=logger.log,
        )
        resolved_selections = list(search_report.get("resolved_selections") or [])
        labels = labels_from_selections(resolved_selections, metadata_by_cve)
        unresolved = [
            item for item in search_report.get("cves") or [] if item.get("status") != "selected"
        ]
        write_json(state / "resolved_3v3.json", resolved_selections)
        write_json(state / "ubuntu_labels.json", [item.to_json() for item in labels])
        write_json(output / "exports" / "excluded_cves.json", unresolved)
        logger.log(
            f"stage=resolve done selected_cves={len(resolved_selections)} unresolved_cves={len(unresolved)}"
        )

    if previous is not None and not args.skip_download:
        cumulative = merge_build_snapshot(
            previous,
            current_cves=selected_cves,
            metadata=metadata,
            labels=labels,
            pairs=pairs,
            artifacts=artifacts,
            selections=selections,
            resolved_selections=resolved_selections,
            rankings=rankings,
            search=search_report,
        )
        metadata = cumulative["metadata"]
        labels = cumulative["labels"]
        pairs = cumulative["pairs"]
        artifacts = cumulative["artifacts"]
        selections = cumulative["selections"]
        resolved_selections = cumulative["resolved_selections"]
        rankings = cumulative["rankings"]
        search_report = cumulative["search"]
        logger.log(
            f"stage=incremental merged_cves={search_report.get('selected_cves', 0)} "
            f"unresolved_cves={search_report.get('unresolved_cves', 0)}"
        )

    write_json(state / "metadata_rows.json", [item.to_json() for item in metadata])
    write_json(state / "ubuntu_labels.json", [item.to_json() for item in labels])
    write_json(state / "selected_3v3.json", selections)
    write_json(state / "resolved_3v3.json", resolved_selections)
    write_json(state / "package_rankings.json", rankings)
    for cve_id, ranking in rankings.items():
        write_json(output / "exports" / "package_rankings" / f"{cve_id}.json", ranking)
    unresolved = [item for item in search_report.get("cves") or [] if item.get("status") != "selected"]
    write_json(output / "exports" / "excluded_cves.json", unresolved)
    write_json(state / "package_pairs.json", [item.to_json() for item in pairs])
    write_json(state / "artifact_results.json", [item.to_json() for item in artifacts])
    write_json(state / "package_search.json", search_report)
    logger.log(f"stage=artifact done artifacts={len(artifacts)} counts={json.dumps(count_by(artifacts, 'status'), sort_keys=True)}")
    if stop_after(args, "artifact"):
        export_all(project=args.project, output=output, metadata=metadata, labels=labels, pairs=pairs, artifacts=artifacts, params=params, max_per_label=max_per_label)
        return 0
    export_all(project=args.project, output=output, metadata=metadata, labels=labels, pairs=pairs, artifacts=artifacts, params=params, max_per_label=max_per_label)
    logger.log(f"stage=export done exports={output / 'exports'}")
    return 0


def stop_after(args: argparse.Namespace, stage: str) -> bool:
    return args.only_stage == stage


def count_by(items: list[Any], attr: str) -> dict[str, int]:
    counts = {}
    for item in items:
        value = str(getattr(item, attr, ""))
        counts[value] = counts.get(value, 0) + 1
    return counts
