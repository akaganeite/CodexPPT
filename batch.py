"""Batch runner over the curl testset.

Each (CVE, binary) case runs as an isolated subprocess of the single-case loop,
so there is no shared AGENT_CONTEXT state between cases. Groundtruth maps
vuln -> absent, patch -> present, not_affected -> not_affected; predictions are
scored into an accuracy summary and a 4-way confusion matrix.

Run:
    python3 -m claudeagent.batch --out-root <dir> [--limit N] [--cve CVE-...] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from claudeagent.common import ROOT, VERDICTS, expand, jdump, load_json


PACKAGE_PARENT = ROOT.parent  # so `python3 -m claudeagent.agent_loop` resolves
DEFAULT_GROUNDTRUTH = "/home/zhangxb/extdisk/dataset4ppt/curl/exports/groundtruth_with_not_affected.json"
DEFAULT_BINARIES_ROOT = "~/extdisk/dataset4ppt/curl/binaries"
DEFAULT_VARIANT = "target/curl_stripped"
DEFAULT_METADATA = "/home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_project_source_analysis.behavior.json"

# Groundtruth list name -> expected verdict.
LABEL_TO_STATUS = {"vuln": "absent", "patch": "present", "not_affected": "not_affected"}


def load_cases(groundtruth_path: str, cve_filter: str) -> list[dict[str, Any]]:
    data = load_json(groundtruth_path)
    cases: list[dict[str, Any]] = []
    for entry in data:
        cve = entry.get("CVE") or entry.get("cve_id")
        if not cve or (cve_filter and cve != cve_filter):
            continue
        for label, expected in LABEL_TO_STATUS.items():
            for binary in entry.get(label, []) or []:
                cases.append({"cve_id": cve, "binary_name": binary, "expected": expected})
    return cases


def resolve_binary(binaries_root: str, variant: str, binary_name: str) -> Path:
    return expand(binaries_root) / variant / binary_name


def safe_case_dir(out_root: Path, cve_id: str, binary_name: str) -> Path:
    safe = binary_name.replace("/", "_")
    return out_root / cve_id / safe


def run_one_case(case: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    binary_path = resolve_binary(args.binaries_root, args.variant, case["binary_name"])
    case_dir = safe_case_dir(expand(args.out_root), case["cve_id"], case["binary_name"])
    record = {
        "cve_id": case["cve_id"],
        "binary": case["binary_name"],
        "binary_path": str(binary_path),
        "expected": case["expected"],
        "output_dir": str(case_dir),
    }
    if not binary_path.is_file():
        record.update({"predicted": "not_found", "ok": False, "error": "binary file missing", "correct": False})
        return record

    cmd = [
        sys.executable, "-m", "claudeagent.agent_loop",
        "--cve-id", case["cve_id"],
        "--metadata-json", str(expand(args.metadata_json)),
        "--binary", str(binary_path),
        "--output-dir", str(case_dir),
        "--max-turns", str(args.max_turns),
        "--finalization-turns", str(args.finalization_turns),
        "--api-timeout", str(args.api_timeout),
        "--api-max-retries", str(args.api_max_retries),
    ]
    if args.model:
        cmd += ["--model", args.model]
    if args.base_url:
        cmd += ["--base-url", args.base_url]
    if args.no_strict:
        cmd += ["--no-strict"]
    if args.thinking:
        cmd += ["--thinking", "--reasoning-effort", args.reasoning_effort]

    started = time.time()
    try:
        proc = subprocess.run(
            cmd, cwd=str(PACKAGE_PARENT), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=args.case_timeout,
        )
        record["agent_returncode"] = proc.returncode
        if proc.stderr.strip():
            record["stderr_tail"] = proc.stderr.strip()[-600:]
    except subprocess.TimeoutExpired:
        record.update({"predicted": "timeout", "ok": False, "error": f"case timeout after {args.case_timeout}s", "correct": False})
        return record

    final_path = case_dir / "final_result.json"
    if not final_path.is_file():
        record.update({"predicted": "error", "ok": False, "error": "no final_result.json produced", "correct": False})
        return record
    try:
        final = load_json(final_path)
    except Exception as exc:
        record.update({"predicted": "error", "ok": False, "error": f"unreadable final_result: {exc}", "correct": False})
        return record

    predicted = str(final.get("status", "error"))
    record.update({
        "predicted": predicted,
        "confidence": final.get("confidence"),
        "ok": bool(final.get("ok")),
        "correct": predicted == case["expected"],
        "evidence_id_count": len(final.get("evidence_ids", []) or []),
        "harness_metrics": final.get("harness_metrics", {}),
        "wall_seconds": round(time.time() - started, 2),
        "schema_validation_errors": final.get("schema_validation_errors", []),
    })
    return record


def aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    outcomes = list(VERDICTS) + ["not_found", "timeout", "error"]
    confusion = {exp: {pred: 0 for pred in outcomes} for exp in VERDICTS}
    correct = 0
    scored = 0
    repair_totals = {"schema_repair_attempts": 0, "no_evidence_verdicts": 0, "tool_failures": 0, "command_failures": 0}
    for rec in records:
        exp = rec.get("expected")
        pred = rec.get("predicted", "error")
        if exp in confusion:
            confusion[exp][pred if pred in outcomes else "error"] += 1
        scored += 1
        if rec.get("correct"):
            correct += 1
        for key in repair_totals:
            repair_totals[key] += int(rec.get("harness_metrics", {}).get(key, 0) or 0)
    return {
        "total_cases": len(records),
        "scored_cases": scored,
        "correct": correct,
        "accuracy": round(correct / scored, 4) if scored else 0.0,
        "confusion_matrix": confusion,
        "repair_totals": repair_totals,
    }


def run_batch(args: argparse.Namespace) -> int:
    cases = load_cases(args.groundtruth, args.cve)
    if args.limit > 0:
        cases = cases[: args.limit]
    out_root = expand(args.out_root)

    if args.dry_run:
        missing = [c for c in cases if not resolve_binary(args.binaries_root, args.variant, c["binary_name"]).is_file()]
        print("BATCH_DRY_RUN")
        print("groundtruth:", args.groundtruth)
        print("binaries_root:", str(expand(args.binaries_root) / args.variant))
        print("metadata:", args.metadata_json)
        print("total_cases:", len(cases))
        print("by_expected:", {v: sum(1 for c in cases if c["expected"] == v) for v in VERDICTS})
        print("missing_binaries:", len(missing))
        for c in missing[:10]:
            print("  MISSING", c["cve_id"], c["binary_name"])
        return 0

    out_root.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    started = time.time()
    with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as pool:
        futures = {pool.submit(run_one_case, case, args): case for case in cases}
        for done in as_completed(futures):
            rec = done.result()
            records.append(rec)
            mark = "OK " if rec.get("correct") else "XX "
            print(f"{mark}{rec['cve_id']} {rec['binary']}: predicted={rec.get('predicted')} expected={rec['expected']}", file=sys.stderr)

    records.sort(key=lambda r: (r["cve_id"], r["binary"]))
    summary = aggregate(records)
    summary["wall_seconds"] = round(time.time() - started, 2)
    metrics = {"summary": summary, "cases": records}
    (out_root / "batch_metrics.json").write_text(jdump(metrics) + "\n", encoding="utf-8")
    print(jdump(summary))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="claudeagent batch patch-presence detection over the curl testset")
    parser.add_argument("--groundtruth", default=DEFAULT_GROUNDTRUTH)
    parser.add_argument("--binaries-root", default=DEFAULT_BINARIES_ROOT)
    parser.add_argument("--variant", default=DEFAULT_VARIANT, help="subpath under binaries-root, e.g. target/curl_stripped")
    parser.add_argument("--metadata-json", default=DEFAULT_METADATA)
    parser.add_argument("--out-root", required=True)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--cve", default="", help="restrict to a single CVE id")
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--case-timeout", type=int, default=900)
    parser.add_argument("--dry-run", action="store_true")
    # Passthrough to the single-case loop.
    parser.add_argument("--model", default="")
    parser.add_argument("--base-url", default="")
    parser.add_argument("--no-strict", action="store_true")
    parser.add_argument("--thinking", action="store_true")
    parser.add_argument("--reasoning-effort", default="medium")
    parser.add_argument("--max-turns", type=int, default=20)
    parser.add_argument("--finalization-turns", type=int, default=3)
    parser.add_argument("--api-timeout", type=int, default=240)
    parser.add_argument("--api-max-retries", type=int, default=3)
    return parser


def main(argv: list[str] | None = None) -> int:
    return run_batch(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
