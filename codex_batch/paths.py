from __future__ import annotations

import argparse
from pathlib import Path


def requested_binary_to_actual(name: str, opt: str = "o0") -> str:
    for tool in ("readelf", "objdump", "nm", "curl"):
        suffix = "-" + tool
        if name.endswith(suffix):
            return name[: -len(suffix)] + "-" + opt + suffix
    return name


def resolve_requested_binary(target_dir: Path, name: str, opt: str = "o0") -> str:
    """Resolve a requested testcase name to a file under target_dir.

    Source-built testsets request names such as curl-7.58.0-curl while the
    actual optimized binary is curl-7.58.0-o0-curl. Deployed package binaries
    are already named as concrete package artifacts and should be used as-is.
    """
    opt_name = requested_binary_to_actual(name, opt)
    if (target_dir / opt_name).is_file():
        return opt_name
    if (target_dir / name).is_file():
        return name
    return opt_name


def derive_project_paths(args: argparse.Namespace) -> None:
    """Fill project_json/testset_json/target_dir/output from --project when used."""
    base_dir = args.base_dir.resolve()
    binaries_root = args.binaries_root.resolve()
    runs_dir = base_dir / "runs"
    args.project_dir = None
    if args.project:
        project = args.project
        project_dir = base_dir / project
        args.project_dir = project_dir

        project_json_candidates = [project_dir / f"{project}.json", base_dir / f"{project}.json"]
        testset_candidates = [project_dir / "testset.json", base_dir / "testset.json"]
        target_candidates = [
            binaries_root / f"{project}_gcc",
            project_dir / "targets",
            project_dir / "gcc",
            project_dir,
        ]

        if args.project_json is None:
            args.project_json = next((p for p in project_json_candidates if p.exists()), project_json_candidates[0])
        if args.testset_json is None:
            args.testset_json = next((p for p in testset_candidates if p.exists()), testset_candidates[0])
        if args.target_dir is None:
            args.target_dir = next((p for p in target_candidates if p.exists()), target_candidates[0])
        if args.output is None:
            args.output = runs_dir / f"{project}_{args.opt}_codex_results.json"

    missing = [
        name
        for name in ("project_json", "testset_json", "target_dir", "output")
        if getattr(args, name) is None
    ]
    if missing:
        opts = ", ".join("--" + name.replace("_", "-") for name in missing)
        raise ValueError(f"missing required arguments: {opts}; or provide --project")
