#!/usr/bin/env python3
"""
Run one `codex exec` patch-presence analysis per CVE and merge the results.

Input:
  - project JSON: CVE metadata, e.g. binutils.json
  - testset JSON: CVE -> list of requested binaries
  - target dir: directory containing binaries

Each Codex invocation receives exactly one CVE, its metadata, and the binary
list for that CVE. The script saves raw per-CVE outputs and writes one merged
JSON result.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

from codex_batch.evaluation import evaluate_results
from codex_batch.io import is_relative_to, load_json, write_json
from codex_batch.paths import derive_project_paths
from codex_batch.prompt import build_prompt
from codex_batch.results import (
    cve_has_status,
    error_result,
    extract_json_object,
    validate_cve_result,
    write_schema,
)
from codex_batch.runner import run_codex
from codex_batch.testset import normalize_testset


SCRIPT_DIR = Path(__file__).resolve().parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one codex exec per CVE and merge patch-presence JSON results."
    )
    parser.add_argument(
        "--project",
        help="Project name under --base-dir. Example: --project binutils uses binutils.json and binutils/.",
    )
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=SCRIPT_DIR,
        help="Directory containing <project>.json, testset.json, and <project>/.",
    )
    parser.add_argument(
        "--binaries-root",
        type=Path,
        default=Path.home() / "ClawSpace" / "binaries",
        help=(
            "Root for external binary collections. With --project binutils, "
            "the first default target-dir candidate is <root>/binutils_gcc."
        ),
    )
    parser.add_argument(
        "--opt",
        default="o0",
        choices=["o0", "o1", "o2", "o3"],
        help="Optimization level used in target binary names, e.g. binutils-2.30-o2-objdump.",
    )
    parser.add_argument("--project-json", type=Path)
    parser.add_argument("--testset-json", type=Path)
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--groundtruth-json",
        type=Path,
        help="Groundtruth JSON used only by this wrapper after all codex exec runs finish. Never passed to codex.",
    )
    parser.add_argument(
        "--metrics-output",
        type=Path,
        help="Optional path for evaluation metrics JSON. Defaults to <output>.metrics.json.",
    )
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=None,
        help="Directory for prompts, stdout/stderr, and per-CVE outputs.",
    )
    parser.add_argument(
        "--prompt-template",
        type=Path,
        default=SCRIPT_DIR / "prompts" / "patch_presence.md",
        help="Prompt template file loaded for every CVE.",
    )
    parser.add_argument("--cve", action="append", help="Only run this CVE; repeatable.")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--resume", action="store_true", help="Skip CVEs already in --output.")
    parser.add_argument(
        "--retry-errors",
        action="store_true",
        help="With --resume, rerun CVEs whose existing output contains at least one status=error.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Write prompts but do not call codex.")
    parser.add_argument("--codex-bin", default="codex")
    parser.add_argument("--model", default=None)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument(
        "--sandbox",
        default="workspace-write",
        choices=["read-only", "workspace-write", "danger-full-access"],
    )
    parser.add_argument(
        "--cd",
        type=Path,
        default=None,
        help="Working root passed to codex exec. With --project, defaults to the project directory; otherwise defaults to --target-dir.",
    )
    parser.add_argument(
        "--codex-json-events",
        action="store_true",
        help="Pass --json to codex exec. The final message is still read from --output-last-message.",
    )
    parser.add_argument(
        "--avoid-line-numbers",
        action="store_true",
        help="Prompt Codex to avoid --line-numbers unless line mapping is essential.",
    )
    return parser.parse_args()


def resolve_run_paths(args: argparse.Namespace) -> dict[str, Path | None]:
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
    args.safe_objdump_dir = SCRIPT_DIR / "utils"
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
        # The groundtruth must not be visible to codex exec. The wrapper reads it
        # only after model outputs have been merged.
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


def select_cves(testset: dict[str, list[str]], args: argparse.Namespace) -> list[str]:
    selected = sorted(testset)
    if args.cve:
        wanted = set(args.cve)
        selected = [cve for cve in selected if cve in wanted]
    if args.limit is not None:
        selected = selected[: args.limit]
    return selected


def load_existing_results(output: Path, args: argparse.Namespace) -> dict[str, Any]:
    if not args.resume or not output.exists():
        return {}
    existing = load_json(output)
    if not isinstance(existing, dict):
        raise ValueError("--output exists but is not a JSON object")
    return existing


def safe_objdump_helper_for_prompt(cd: Path) -> str:
    helper = SCRIPT_DIR / "utils" / "safe_objdump.py"
    return os.path.relpath(helper, cd)


def prompt_extra_rules(args: argparse.Namespace) -> list[str]:
    rules: list[str] = []
    if args.avoid_line_numbers:
        rules.append(
            "- Avoid `--line-numbers` by default. Use it only if raw addresses/calls are insufficient; "
            "line-number output repeats long source paths and should not be used for routine confirmation."
        )
    return rules


def process_cve(
    cve: str,
    index: int,
    total: int,
    metadata: dict[str, Any],
    testset: dict[str, list[str]],
    merged: dict[str, Any],
    paths: dict[str, Path | None],
    args: argparse.Namespace,
) -> None:
    output = require_path(paths["output"])
    raw_dir = require_path(paths["raw_dir"])
    target_dir = require_path(paths["target_dir"])
    schema_path = raw_dir / "single_cve_schema.json"

    if args.resume and cve in merged:
        if args.retry_errors and cve_has_status(merged[cve], "error"):
            print(f"[{index}/{total}] retry {cve} (existing status=error)")
        else:
            print(f"[{index}/{total}] skip {cve} (already in output)")
            return

    binaries = testset[cve]
    if cve not in metadata:
        merged[cve] = error_result(
            cve,
            binaries,
            "Cannot inspect patch presence without metadata.",
            f"{cve} not found in project metadata JSON",
        )
        write_json(output, merged)
        return

    prompt = build_prompt(
        args.prompt_template,
        cve,
        metadata[cve],
        binaries,
        target_dir,
        args.opt,
        safe_objdump_helper_for_prompt(args.cd),
        prompt_extra_rules(args),
    )

    print(f"[{index}/{total}] run {cve} ({len(binaries)} binaries)")
    if args.dry_run:
        (raw_dir / f"{cve}.prompt.txt").write_text(prompt, encoding="utf-8")
        return

    try:
        rc, final_text, stderr_text, _ = run_codex(prompt, cve, args, raw_dir, schema_path)
        if rc != 0:
            raise RuntimeError(f"codex exec exited {rc}: {stderr_text[-1000:]}")
        parsed = extract_json_object(final_text)
        merged[cve] = validate_cve_result(cve, binaries, parsed)
    except Exception as exc:
        merged[cve] = error_result(
            cve,
            binaries,
            "See raw per-CVE files in raw_dir.",
            f"codex exec failed or returned invalid JSON: {exc}",
        )
    write_json(output, merged)


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


def require_path(value: Path | None) -> Path:
    if value is None:
        raise ValueError("internal error: expected resolved path")
    return value


def main() -> int:
    args = parse_args()
    paths = resolve_run_paths(args)
    validate_inputs(args, paths)

    metadata = load_json(require_path(paths["project_json"]))
    testset = normalize_testset(load_json(require_path(paths["testset_json"])))
    if not isinstance(metadata, dict):
        raise ValueError("project JSON must be an object keyed by CVE")

    selected = select_cves(testset, args)
    output = require_path(paths["output"])
    raw_dir = require_path(paths["raw_dir"])
    raw_dir.mkdir(parents=True, exist_ok=True)
    write_schema(raw_dir / "single_cve_schema.json")

    merged = load_existing_results(output, args)
    for index, cve in enumerate(selected, 1):
        process_cve(cve, index, len(selected), metadata, testset, merged, paths, args)

    if args.dry_run:
        print(f"dry-run complete; prompts written under {raw_dir}")
    else:
        print(f"merged results written to {output}")
        print(f"raw per-CVE files written under {raw_dir}")
        write_metrics(paths, merged)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        raise SystemExit(130)
