from __future__ import annotations

import argparse
from pathlib import Path


def normalize_opt_for_filename(opt: str) -> str:
    """Return the optimization spelling used in dataset4ppt target filenames."""
    if len(opt) == 2 and opt[0].lower() == "o" and opt[1].isdigit():
        return "O" + opt[1]
    return opt


def requested_binary_to_actual(name: str, compiler: str = "gcc", opt: str = "O0") -> str:
    return f"{name}-{compiler}-{normalize_opt_for_filename(opt)}"


def resolve_requested_binary(
    target_dir: Path,
    name: str,
    compiler: str = "gcc",
    opt: str = "O0",
) -> str:
    """Resolve a requested testcase name to a file under target_dir.

    Dataset testsets and groundtruth use canonical binary names. Target
    collections may store those names directly, deployed package artifacts as
    <canonical>-deployed, or source-built artifacts as
    <canonical>-<compiler>-<opt>, e.g. curl-7.58.0-libcurl-gcc-O0.
    """
    if (target_dir / name).is_file():
        return name
    deployed_name = f"{name}-deployed"
    if (target_dir / deployed_name).is_file():
        return deployed_name
    actual_name = requested_binary_to_actual(name, compiler, opt)
    if (target_dir / actual_name).is_file():
        return actual_name
    return actual_name


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
