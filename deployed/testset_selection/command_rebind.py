"""CLI for reusing source-reviewed selections on another Ubuntu architecture."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..io_utils import read_json, write_json
from ..logging_utils import BuildLogger
from .architecture_rebind import rebind_reviewed_selections


def add_rebind_command(subparsers) -> None:
    parser = subparsers.add_parser(
        "rebind-arch",
        help="Reuse source-reviewed selections and rebuild package availability for another architecture.",
    )
    parser.add_argument("--selection-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--arch", required=True)
    parser.add_argument("--max-per-label", type=int, choices=(1, 2, 3), default=1)
    parser.add_argument("--cve", action="append", default=[])
    parser.add_argument("--refresh", action="store_true")
    parser.set_defaults(func=handle_rebind)


def handle_rebind(args: argparse.Namespace) -> int:
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = read_json(args.selection_file.expanduser().resolve())
    if not isinstance(source, list):
        raise ValueError("selection file must contain a JSON list")
    requested = {str(item).upper() for item in args.cve if str(item).strip()}
    if requested:
        source = [item for item in source if str(item.get("cve_id") or "").upper() in requested]
    logger = BuildLogger(output / "rebind_arch.log")
    selected, excluded = rebind_reviewed_selections(
        source,
        arch=args.arch,
        cache_dir=output / "state" / "binary_availability",
        max_per_label=args.max_per_label,
        refresh=args.refresh,
        log=logger.log,
    )
    exports = output / "exports"
    write_json(exports / "selected_3v3.json", selected)
    write_json(exports / "excluded_cves.json", excluded)
    summary = {
        "schema": "ubuntu-architecture-rebind-summary-v1",
        "source_selection": str(args.selection_file.expanduser().resolve()),
        "arch": args.arch,
        "max_per_label": args.max_per_label,
        "requested_cves": len(source),
        "selected_cves": len(selected),
        "excluded_cves": len(excluded),
    }
    write_json(exports / "rebind_summary.json", summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0
