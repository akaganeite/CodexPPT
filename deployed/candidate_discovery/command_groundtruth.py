"""CLI handlers for Ubuntu JSON and source-publication groundtruth stages."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ..config import parse_csv_args
from ..io_utils import write_json
from ..logging_utils import BuildLogger
from .ubuntu_groundtruth import build_ubuntu_groundtruth, load_cve_json, load_release_catalog
from .ubuntu_source_groundtruth import build_source_groundtruth_for_cve


def add_groundtruth_commands(subparsers) -> None:
    groundtruth = subparsers.add_parser("groundtruth", help="Parse Ubuntu CVE JSON into release and security-fix rows.")
    groundtruth.add_argument("--cve-json", type=Path, action="append", required=True)
    groundtruth.add_argument("--output", type=Path, required=True)
    groundtruth.add_argument("--series", action="append")
    groundtruth.add_argument("--include-esm", action="store_true")
    groundtruth.add_argument("--release-catalog", type=Path)
    groundtruth.set_defaults(func=handle_groundtruth)

    source = subparsers.add_parser("source-groundtruth", help="Attach exact Launchpad source publications and older candidates.")
    source.add_argument("--cve-json", type=Path, action="append", required=True)
    source.add_argument("--output", type=Path, required=True)
    source.add_argument("--series", action="append")
    source.add_argument("--include-esm", action="store_true")
    source.add_argument("--max-vulnerable", type=int, default=3)
    source.add_argument("--refresh", action="store_true")
    source.set_defaults(func=handle_source_groundtruth)


def handle_groundtruth(args: argparse.Namespace) -> int:
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    paths = input_paths(args.cve_json)
    series = parse_csv_args(args.series)
    status_rows: list[dict[str, Any]] = []
    patch_rows: list[dict[str, Any]] = []
    results = []
    try:
        catalog = load_release_catalog(args.release_catalog)
        for path in paths:
            result = build_ubuntu_groundtruth(
                load_cve_json(path),
                source_path=path,
                series_filter=series,
                include_esm=args.include_esm,
                release_catalog=catalog,
            )
            results.append(result)
            status_rows.extend(result["release_status"])
            patch_rows.extend(result["security_patch_groundtruth"])
            write_json(output / "exports" / "groundtruth" / f"{result['cve_id']}_release_status.json", result["release_status"])
            write_json(output / "exports" / "groundtruth" / f"{result['cve_id']}_patch.json", result["security_patch_groundtruth"])
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[deployed] groundtruth failed: {exc}", file=sys.stderr)
        return 2
    status_rows = dedupe_rows(status_rows)
    patch_rows = dedupe_rows(patch_rows)
    write_json(output / "exports" / "ubuntu_release_status.json", status_rows)
    write_json(output / "exports" / "ubuntu_groundtruth.json", patch_rows)
    summary = {
        "schema": "ubuntu-release-groundtruth-summary-v1",
        "input_files": [str(path) for path in paths],
        "cves": sorted({item["cve_id"] for item in results if item.get("cve_id")}),
        "release_status_rows": len(status_rows),
        "security_patch_rows": len(patch_rows),
        "include_esm": bool(args.include_esm),
    }
    write_json(output / "exports" / "ubuntu_groundtruth_summary.json", summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


def handle_source_groundtruth(args: argparse.Namespace) -> int:
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    logger = BuildLogger(output / "source_groundtruth.log")
    paths = input_paths(args.cve_json)
    rows = []
    results = []
    try:
        for path in paths:
            result = build_source_groundtruth_for_cve(
                load_cve_json(path),
                source_path=path,
                state_dir=output / "state" / "source_history",
                series_filter=parse_csv_args(args.series),
                include_esm=args.include_esm,
                max_vulnerable=args.max_vulnerable,
                refresh=args.refresh,
                log=logger.log,
            )
            results.append(result)
            rows.extend(result["rows"])
            write_json(output / "exports" / "source_groundtruth" / f"{result['cve_id']}.json", result)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        logger.log(f"source-groundtruth failed error={exc}")
        return 2
    rows = dedupe_rows(rows)
    verified = [row for row in rows if row["source_groundtruth_status"] == "verified"]
    summary = {
        "schema": "ubuntu-source-groundtruth-summary-v1",
        "cves": sorted({item["cve_id"] for item in results}),
        "rows": len(rows),
        "verified_rows": len(verified),
        "json_only_rows": len(rows) - len(verified),
        "total_vulnerable_candidates": sum(len(row["vulnerable_candidates"]) for row in verified),
    }
    write_json(output / "exports" / "ubuntu_source_groundtruth.json", verified)
    write_json(output / "exports" / "ubuntu_source_groundtruth_all.json", rows)
    write_json(output / "exports" / "ubuntu_source_groundtruth_summary.json", summary)
    logger.log(f"source-groundtruth done cves={len(summary['cves'])} rows={len(rows)}")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


def input_paths(values: list[Path]) -> list[Path]:
    return [Path(item).expanduser().resolve() for value in values for item in str(value).split(",") if item.strip()]


def dedupe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = {}
    for row in rows:
        key = tuple(row.get(field, "") for field in ("cve_id", "source_package", "ubuntu_series", "status", "fixed_source_version", "pocket"))
        output[key] = row
    return sorted(output.values(), key=lambda row: (row.get("cve_id", ""), row.get("source_package", ""), row.get("ubuntu_series", "")))
