from __future__ import annotations

import argparse

from .candidate_discovery.command_groundtruth import add_groundtruth_commands
from .command_run import add_finalize_command, add_run_command
from .package_acquisition.command_build import add_build_command
from .testset_selection.command_select import add_select_command
from .testset_selection.command_rebind import add_rebind_command


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build balanced Ubuntu deployed-binary datasets with up to three versions per label."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_groundtruth_commands(subparsers)
    add_select_command(subparsers)
    add_rebind_command(subparsers)
    add_build_command(subparsers)
    add_run_command(subparsers)
    add_finalize_command(subparsers)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)
