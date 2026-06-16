from __future__ import annotations

import argparse
import itertools
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .anonymize import prepare_anonymous_targets, remap_result_to_original
from .evaluation import evaluate_results
from .io import is_relative_to, load_json, write_json
from .paths import derive_project_paths
from .prompt import build_prompt
from .results import error_result, extract_json_object, validate_cve_result
from .run_state import (
    load_existing_results,
    safe_run_id,
    select_cves,
    should_skip,
)
from .runner import run_codex
from .schema import write_result_schema
from .testset import normalize_testset


def resolve_run_paths(args: argparse.Namespace, script_dir: Path) -> dict[str, Path | None]:
    derive_project_paths(args)
    project_json = args.project_json.resolve()
    testset_json = args.testset_json.resolve()
    target_dir = args.target_dir.resolve()
    output = args.output.resolve()
    raw_dir = (args.raw_dir or output.parent / (output.stem + "_codex_runs")).resolve()
    default_cd = args.project_dir if args.project_dir is not None else target_dir
    cd = args.cd.resolve() if args.cd is not None else default_cd.resolve()
    metrics_output = (
        args.metrics_output.resolve()
        if args.metrics_output
        else output.with_suffix(output.suffix + ".metrics.json")
    )

    args.target_dir = target_dir
    args.cd = cd
    args.prompt_template = args.prompt_template.resolve()
    args.safe_objdump_dir = script_dir / "utils"
    args.original_cd = cd
    return {
        "project_json": project_json,
        "testset_json": testset_json,
        "target_dir": target_dir,
        "output": output,
        "raw_dir": raw_dir,
        "groundtruth_json": args.groundtruth_json.resolve() if args.groundtruth_json else None,
        "metrics_output": metrics_output,
    }


def validate_inputs(args: argparse.Namespace, paths: dict[str, Path | None]) -> None:
    target_dir = require_path(paths["target_dir"])
    groundtruth_json = paths["groundtruth_json"]
    if groundtruth_json is not None:
        forbidden_roots = [target_dir, args.cd]
        if any(is_relative_to(groundtruth_json, root) for root in forbidden_roots):
            raise ValueError(
                "groundtruth JSON is inside the codex-visible target/cd directory. "
                "Move it outside the project directory before running."
            )

    if not target_dir.is_dir():
        raise ValueError(f"target directory does not exist or is not a directory: {target_dir}")
    if not args.prompt_template.is_file():
        raise ValueError(f"prompt template does not exist: {args.prompt_template}")


def safe_objdump_helper_for_prompt(cd: Path, script_dir: Path) -> str:
    helper = script_dir / "utils" / "safe_objdump.py"
    return os.path.relpath(helper, cd)


def process_cve(
    cve: str,
    total: int,
    counter: itertools.count,
    metadata: dict[str, Any],
    testset: dict[str, list[str]],
    merged: dict[str, Any],
    lock: threading.Lock,
    paths: dict[str, Path | None],
    args: argparse.Namespace,
    script_dir: Path,
    requested_binaries: list[str] | None = None,
    run_id: str | None = None,
) -> None:
    """Run one task (one CVE, or one CVE/binary pair) end to end.

    Resume/skip is decided before submission (see should_skip), so this always
    runs the task. ``lock`` guards every ``merged`` mutation + ``write_json`` so
    concurrent workers never serialize a dict mid-mutation; everything else
    (codex exec, parsing, remap) stays off the lock so tasks truly overlap.
    """
    output = require_path(paths["output"])
    raw_dir = require_path(paths["raw_dir"])
    target_dir = require_path(paths["target_dir"])
    schema_path = raw_dir / "single_cve_schema.json"

    binaries = requested_binaries or testset[cve]
    run_id = run_id or safe_run_id(cve)

    if cve not in metadata:
        with lock:
            merged.setdefault(cve, {}).update(
                error_result(
                    cve,
                    binaries,
                    "Cannot inspect patch presence without metadata.",
                    f"{cve} not found in project metadata JSON",
                )
            )
            write_json(output, merged)
        return

    anonymous_targets = None
    run_binaries = binaries
    run_target_dir = target_dir
    run_cd = args.original_cd
    run_safe_objdump_dir = args.safe_objdump_dir
    run_safe_objdump_helper = safe_objdump_helper_for_prompt(run_cd, script_dir)
    run_binary_resolution = None
    if not args.no_anonymize_targets:
        anonymous_targets = prepare_anonymous_targets(
            cve,
            binaries,
            target_dir,
            args.opt,
            args.safe_objdump_dir,
        )
        run_binaries = anonymous_targets.requested_binaries
        run_target_dir = anonymous_targets.target_dir
        run_cd = anonymous_targets.cd
        run_safe_objdump_dir = anonymous_targets.safe_objdump_dir
        run_safe_objdump_helper = anonymous_targets.safe_objdump_helper
        run_binary_resolution = anonymous_targets.binary_resolution

    prompt = build_prompt(
        args.prompt_template,
        cve,
        metadata[cve],
        run_binaries,
        run_target_dir,
        args.opt,
        run_safe_objdump_helper,
        run_binary_resolution,
    )

    label = f"{cve} ({len(binaries)} binaries)" if len(binaries) != 1 else f"{cve} {binaries[0]}"
    print(f"[{next(counter)}/{total}] run {label}", flush=True)
    if args.dry_run:
        (raw_dir / f"{run_id}.prompt.txt").write_text(prompt, encoding="utf-8")
        if anonymous_targets is not None:
            write_json(raw_dir / f"{run_id}.anonymized_targets.json", anonymized_mapping_payload(anonymous_targets))
            anonymous_targets.cleanup()
        return

    try:
        if anonymous_targets is not None:
            write_json(raw_dir / f"{run_id}.anonymized_targets.json", anonymized_mapping_payload(anonymous_targets))
        rc, final_text, stderr_text, _ = run_codex(
            prompt,
            run_id,
            args,
            raw_dir,
            schema_path,
            cd=run_cd,
            target_dir=run_target_dir,
            safe_objdump_dir=run_safe_objdump_dir,
        )
        if rc != 0:
            raise RuntimeError(f"codex exec exited {rc}: {stderr_text[-1000:]}")
        parsed = extract_json_object(final_text)
        result = validate_cve_result(cve, run_binaries, parsed)
        if anonymous_targets is not None:
            result = remap_result_to_original(
                result,
                anonymous_targets.anonymous_to_original,
                binaries,
                anonymous_targets.target_dir,
            )
        with lock:
            merged.setdefault(cve, {}).update(result)
            write_json(output, merged)
    except Exception as exc:
        with lock:
            merged.setdefault(cve, {}).update(
                error_result(
                    cve,
                    binaries,
                    "See raw per-CVE files in raw_dir.",
                    f"codex exec failed or returned invalid JSON: {exc}",
                )
            )
            write_json(output, merged)
    finally:
        if anonymous_targets is not None:
            anonymous_targets.cleanup()


def anonymized_mapping_payload(targets: Any) -> dict[str, Any]:
    return {
        "target_dir": str(targets.target_dir),
        "cd": str(targets.cd),
        "anonymous_to_original": targets.anonymous_to_original,
        "original_to_anonymous": targets.original_to_anonymous,
        "original_to_actual": targets.actual_mapping,
        "safe_objdump_helper": targets.safe_objdump_helper,
    }


def write_metrics(paths: dict[str, Path | None], merged: dict[str, Any]) -> None:
    groundtruth_json = paths["groundtruth_json"]
    if groundtruth_json is None:
        return
    metrics_output = require_path(paths["metrics_output"])
    metrics = evaluate_results(merged, load_json(groundtruth_json))
    write_json(metrics_output, metrics)
    m = metrics["metrics"]
    c = metrics["counts"]
    print(f"metrics written to {metrics_output}")
    print(
        "metrics: "
        f"A={m['A']:.4f} P={m['P']:.4f} R={m['R']:.4f} "
        f"F1={m['F1']:.4f} DSR={m['DSR']:.4f} "
        f"(TP={c['TP']} TN={c['TN']} FP={c['FP']} FN={c['FN']} "
        f"inconclusive={c['inconclusive']} error={c['error']} "
        f"TC={c['TC']} not_found_excluded={c['not_found']})"
    )


def run_batch(args: argparse.Namespace, script_dir: Path) -> int:
    paths = resolve_run_paths(args, script_dir)
    validate_inputs(args, paths)

    metadata = load_json(require_path(paths["project_json"]))
    testset = normalize_testset(load_json(require_path(paths["testset_json"])))
    if not isinstance(metadata, dict):
        raise ValueError("project JSON must be an object keyed by CVE")

    selected = select_cves(testset, args.cve, args.limit)
    output = require_path(paths["output"])
    raw_dir = require_path(paths["raw_dir"])
    raw_dir.mkdir(parents=True, exist_ok=True)
    write_result_schema(raw_dir / "single_cve_schema.json")

    merged = load_existing_results(output, args.resume)
    merged_lock = threading.Lock()

    if args.binarywise:
        raw_tasks = [(cve, [binary], safe_run_id(cve, binary)) for cve in selected for binary in testset[cve]]
    else:
        raw_tasks = [(cve, testset[cve], safe_run_id(cve)) for cve in selected]

    pending = [task for task in raw_tasks if not should_skip(args, merged, task[0], task[1])]
    pending_ids = {run_id for _cve, _binaries, run_id in pending}
    for cve, binaries, run_id in raw_tasks:
        if run_id not in pending_ids:
            label = f"{cve} ({len(binaries)} binaries)" if len(binaries) != 1 else f"{cve} {binaries[0]}"
            print(f"skip {label} (already in output)")

    total = len(pending)
    counter = itertools.count(1)
    jobs = max(1, args.jobs)
    with ThreadPoolExecutor(max_workers=jobs) as executor:
        futures = [
            executor.submit(
                process_cve,
                cve,
                total,
                counter,
                metadata,
                testset,
                merged,
                merged_lock,
                paths,
                args,
                script_dir,
                requested_binaries=binaries,
                run_id=run_id,
            )
            for cve, binaries, run_id in pending
        ]
        try:
            for future in as_completed(futures):
                future.result()
        except KeyboardInterrupt:
            executor.shutdown(wait=True, cancel_futures=True)
            raise

    if args.dry_run:
        print(f"dry-run complete; prompts written under {raw_dir}")
    else:
        print(f"merged results written to {output}")
        print(f"raw per-CVE files written under {raw_dir}")
        write_metrics(paths, merged)
    return 0


def require_path(value: Path | None) -> Path:
    if value is None:
        raise ValueError("internal error: expected resolved path")
    return value
