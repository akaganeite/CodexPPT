"""Batch runner for direct metadata-to-binary patch-presence investigation."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from claudeagent.common import DETERMINATE_STATUSES, ROOT, VERDICTS, expand, jdump, load_json
from claudeagent.finalize import FINAL_SCHEMA_VERSION, validate_final_result_artifact
from claudeagent.host import import_env_from_interactive_shell
from claudeagent.metadata_input import metadata_sha256, validate_metadata_prompt_input
from claudeagent.model_config import resolve_api_key, resolve_profile


PACKAGE_PARENT = ROOT.parent
DEFAULT_BINARIES_ROOT = "~/extdisk/dataset4ppt/curl/binaries"
DEFAULT_VARIANT = "target/curl_stripped"
DEFAULT_METADATA = "/home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_project_source_analysis.behavior.json"
LABEL_TO_STATUS = {"vuln": "absent", "patch": "present", "not_affected": "not_affected"}
SCORING_STATUSES = {"present", "absent", "not_affected"}
RESUME_MODES = ("auto", "all", "error", "inconclusive")
_COMPLETED_STATUSES = set(VERDICTS)
_COMPILER_OPT_RE = re.compile(r"-.+-O[0-3]$")
DEPLOY_COMPILER = "deploy"
_DEPLOY_SUFFIX = "-deployed"

_USAGE_KEY_MAP = {
    "input_tokens": "prompt_tokens",
    "output_tokens": "completion_tokens",
    "total_tokens": "total_tokens",
    "input_tokens_details.cached_tokens": "prompt_tokens_details.cached_tokens",
    "output_tokens_details.reasoning_tokens": "completion_tokens_details.reasoning_tokens",
}
_USAGE_DROP_KEYS = {"input_tokens_details.cache_write_tokens"}


def rename_usage(totals: dict[str, Any]) -> dict[str, int | float]:
    """Map Responses usage names to the compatible batch-report vocabulary."""
    if not isinstance(totals, dict):
        return {}

    def leaves(value: Any, prefix: str = "") -> list[tuple[str, int | float]]:
        if isinstance(value, dict):
            return [
                pair
                for key, item in value.items()
                for pair in leaves(item, f"{prefix}.{key}" if prefix else str(key))
            ]
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return [(prefix, value)]
        return []

    out: dict[str, int | float] = {}
    for key, value in leaves(totals):
        mapped = _USAGE_KEY_MAP.get(key)
        if mapped and key not in _USAGE_DROP_KEYS:
            out[mapped] = value
    input_tokens = totals.get("input_tokens")
    details = totals.get("input_tokens_details")
    cached = details.get("cached_tokens") if isinstance(details, dict) else None
    if isinstance(input_tokens, (int, float)) and not isinstance(input_tokens, bool):
        cached_value = cached if isinstance(cached, (int, float)) and not isinstance(cached, bool) else 0
        out["prompt_cache_hit_tokens"] = cached_value
        out["prompt_cache_miss_tokens"] = input_tokens - cached_value
    return out


def safe_ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _sum_usage(records: list[dict[str, Any]]) -> dict[str, int | float]:
    totals: dict[str, int | float] = {}
    wall_seconds = 0.0
    for record in records:
        for key, value in (record.get("usage_totals") or {}).items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                totals[key] = totals.get(key, 0) + value
        timing = record.get("timing") or {}
        wall = timing.get("wall_seconds") if isinstance(timing, dict) else None
        if isinstance(wall, (int, float)) and not isinstance(wall, bool):
            wall_seconds += float(wall)
    totals["case_wall_seconds_sum"] = round(wall_seconds, 3)
    return totals


def _mean_usage(totals: dict[str, int | float], count: int) -> dict[str, float]:
    if count <= 0:
        return {key: 0.0 for key in totals}
    return {
        key: round(float(value) / count, 6)
        for key, value in totals.items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    }


def batch_metrics_pptagent(
    records: list[dict[str, Any]],
    batch_wall_seconds: float | None = None,
) -> dict[str, Any]:
    """Produce the same top-level metrics shape used by prior batch reports."""
    scored = [record for record in records if record.get("expected") in SCORING_STATUSES]
    affected = [record for record in scored if record["expected"] != "not_affected"]
    not_affected = [record for record in scored if record["expected"] == "not_affected"]
    tp = sum(record["expected"] == "present" and record.get("predicted") == "present" for record in affected)
    tn = sum(record["expected"] == "absent" and record.get("predicted") == "absent" for record in affected)
    fp = sum(record["expected"] == "absent" and record.get("predicted") == "present" for record in affected)
    fn = sum(record["expected"] == "present" and record.get("predicted") == "absent" for record in affected)
    precision = safe_ratio(tp, tp + fp)
    recall = safe_ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 6) if precision + recall else 0.0
    binary_correct = tp + tn
    binary_decided = tp + tn + fp + fn
    total_correct = sum(record.get("predicted") == record["expected"] for record in scored)
    na_correct = sum(record.get("predicted") == "not_affected" for record in not_affected)
    usage_totals = _sum_usage(scored)
    if batch_wall_seconds is not None:
        usage_totals["batch_wall_seconds"] = round(batch_wall_seconds, 3)
    usage_mean = _mean_usage(usage_totals, len(scored))
    if batch_wall_seconds is not None:
        usage_mean["batch_wall_seconds"] = round(batch_wall_seconds / len(scored), 6) if scored else 0.0
    return {
        "binary_metrics": {
            "DSR": safe_ratio(binary_correct, len(affected)),
            "A": safe_ratio(binary_correct, binary_decided),
            "P": precision,
            "F1": f1,
            "R": recall,
        },
        "not_affected_metrics": {"not_affected_accuracy": safe_ratio(na_correct, len(not_affected))},
        "overall_metrics": {"overall_DSR": safe_ratio(total_correct, len(scored))},
        "classification_counts": {
            "TN": tn,
            "TP": tp,
            "FN": fn,
            "FP": fp,
            "TC": len(affected),
            "not-affected": sum(record.get("predicted") == "not_affected" for record in scored),
            "inconclusive": sum(record.get("predicted") == "inconclusive" for record in scored),
        },
        "inconclusive_status": dict(sorted(Counter(
            str(record.get("inconclusive_reason") or "unspecified")
            for record in scored
            if record.get("predicted") == "inconclusive"
        ).items())),
        "usage_totals": usage_totals,
        "usage_mean": usage_mean,
    }


def _groundtruth_label_index(groundtruth_path: str) -> dict[tuple[str, str], str]:
    data = load_json(groundtruth_path)
    index: dict[tuple[str, str], str] = {}
    if not isinstance(data, list):
        return index
    for entry in data:
        if not isinstance(entry, dict):
            continue
        cve = entry.get("CVE") or entry.get("cve_id")
        if not cve:
            continue
        for label, expected in LABEL_TO_STATUS.items():
            for binary in entry.get(label, []) or []:
                index[(str(cve), str(binary))] = expected
    return index


def load_cases(testset_path: str, groundtruth_path: str, cve_filter: str) -> list[dict[str, Any]]:
    """Use the label-free testset to select cases and groundtruth to score them."""
    testset = load_json(testset_path)
    labels = _groundtruth_label_index(groundtruth_path)
    cases: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    if not isinstance(testset, list):
        return cases
    for entry in testset:
        if not isinstance(entry, dict):
            continue
        cve = entry.get("CVE") or entry.get("cve_id")
        if not cve or (cve_filter and cve != cve_filter):
            continue
        for binary in entry.get("binaries", []) or []:
            key = (str(cve), str(binary))
            if key in seen:
                continue
            seen.add(key)
            cases.append({"cve_id": key[0], "binary_name": key[1], "expected": labels.get(key, "unknown")})
    return cases


def load_metadata_index(metadata_path: str) -> dict[str, dict[str, Any]]:
    raw = load_json(metadata_path)
    indexed: dict[str, dict[str, Any]] = {}
    if isinstance(raw, dict) and isinstance(raw.get("cve_id"), str):
        candidates = [raw]
    elif isinstance(raw, dict):
        candidates = []
        for key, value in raw.items():
            if isinstance(value, dict):
                item = dict(value)
                item.setdefault("cve_id", str(key))
                candidates.append(item)
    elif isinstance(raw, list):
        candidates = [item for item in raw if isinstance(item, dict)]
    else:
        raise ValueError("metadata JSON must be a CVE object, object map, or list")
    for candidate in candidates:
        cve_id = candidate.get("cve_id")
        if isinstance(cve_id, str) and cve_id:
            item = dict(candidate)
            item.setdefault("project", "curl")
            indexed[cve_id] = item
    return indexed


def required_metadata_hashes(
    metadata_by_cve: dict[str, dict[str, Any]],
    cve_ids: set[str] | list[str],
) -> dict[str, str]:
    return {
        cve_id: metadata_sha256(metadata_by_cve[cve_id], cve_id)
        for cve_id in sorted(set(cve_ids))
        if cve_id in metadata_by_cve
    }


def _normalized_opt(opt: str) -> str:
    value = str(opt or "o0").strip().lstrip("-")
    return (value or "o0").upper()


def _suffixed_binary_name(binary_name: str, compiler: str, opt: str) -> str:
    compiler = str(compiler or "gcc").strip() or "gcc"
    if compiler == DEPLOY_COMPILER:
        return binary_name if binary_name.endswith(_DEPLOY_SUFFIX) else f"{binary_name}{_DEPLOY_SUFFIX}"
    if _COMPILER_OPT_RE.search(binary_name):
        return binary_name
    return f"{binary_name}-{compiler}-{_normalized_opt(opt)}"


def resolve_binary(
    binaries_root: str,
    variant: str,
    binary_name: str,
    compiler: str = "gcc",
    opt: str = "o0",
) -> Path:
    variant_dir = expand(binaries_root) / variant
    exact = variant_dir / binary_name
    if exact.is_file():
        return exact
    suffixed = _suffixed_binary_name(binary_name, compiler, opt)
    direct = variant_dir / suffixed
    if direct.is_file():
        return direct
    if suffixed != binary_name:
        tail = suffixed[len(binary_name):]
        matches = sorted(path for path in variant_dir.glob(f"{binary_name}*{tail}") if path.is_file())
        if matches:
            return matches[0]
    return direct


def safe_case_dir(out_root: Path, cve_id: str, binary_name: str) -> Path:
    return out_root / cve_id / binary_name.replace("/", "_")


def _artifact_validation_errors(final: Any) -> list[str]:
    if not isinstance(final, dict):
        return ["final_result.json is not an object"]
    errors: list[str] = []
    if isinstance(final.get("schema_validation_errors"), list) and final["schema_validation_errors"]:
        errors.append("artifact records schema_validation_errors")
    errors.extend(validate_final_result_artifact(final))
    if final.get("status") in DETERMINATE_STATUSES and final.get("ok") is not True:
        errors.append("determinate artifact requires ok=true")
    return errors


def _existing_case_artifact(case_dir: Path) -> dict[str, Any] | None:
    path = case_dir / "final_result.json"
    if not path.is_file():
        return None
    try:
        final = load_json(path)
    except Exception:
        return None
    if (
        not isinstance(final, dict)
        or final.get("schema_version") != FINAL_SCHEMA_VERSION
        or final.get("status") not in _COMPLETED_STATUSES
        or _artifact_validation_errors(final)
    ):
        return None
    return final


def _artifact_signature(path: Path) -> tuple[int, int, int, str] | None:
    try:
        stat = path.stat()
        return stat.st_ino, stat.st_size, stat.st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _select_resume_cases(
    cases: list[dict[str, Any]],
    out_root: Path,
    args: argparse.Namespace,
    metadata_hashes: dict[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    to_run: list[dict[str, Any]] = []
    to_reuse: list[dict[str, Any]] = []
    counts = {"total": len(cases), "completed": 0, "inconclusive": 0, "stale_metadata": 0, "retry": 0, "skipped": 0}
    for case in cases:
        artifact = _existing_case_artifact(safe_case_dir(out_root, case["cve_id"], case["binary_name"]))
        status = str(artifact["status"]) if artifact else None
        stale = bool(
            artifact
            and metadata_hashes.get(case["cve_id"])
            and artifact.get("metadata_sha256") != metadata_hashes[case["cve_id"]]
        )
        if status is not None:
            counts["completed"] += 1
            counts["inconclusive"] += status == "inconclusive"
            counts["stale_metadata"] += stale
        if args.resume == "all":
            run_it = True
        elif args.resume == "inconclusive":
            run_it = stale or status == "inconclusive"
        else:
            run_it = stale or status is None or (status == "inconclusive" and args.retry_inconclusive)
        if run_it:
            to_run.append(case)
            counts["retry"] += 1
        else:
            to_reuse.append(case)
            counts["skipped"] += 1
    return to_run, to_reuse, counts


def _case_command(case: dict[str, Any], args: argparse.Namespace, binary_path: Path, case_dir: Path) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "claudeagent.agent_loop",
        "--cve-id",
        case["cve_id"],
        "--metadata-json",
        str(expand(args.metadata_json)),
        "--binary",
        str(binary_path),
        "--output-dir",
        str(case_dir),
        "--max-turns",
        str(args.max_turns),
        "--finalization-turns",
        str(args.finalization_turns),
        "--api-timeout",
        str(args.api_timeout),
        "--api-max-retries",
        str(args.api_max_retries),
        "--api-turn-retries",
        str(args.api_turn_retries),
    ]
    if args.model:
        command += ["--model", args.model]
    if args.base_url:
        command += ["--base-url", args.base_url]
    if args.model_profile:
        command += ["--model-profile", args.model_profile]
    if args.no_strict:
        command.append("--no-strict")
    return command


def _empty_record(case: dict[str, Any], binary_path: Path, case_dir: Path) -> dict[str, Any]:
    return {
        "cve_id": case["cve_id"],
        "binary": case["binary_name"],
        "binary_path": str(binary_path),
        "expected": case["expected"],
        "output_dir": str(case_dir),
        "inconclusive_reason": "",
        "usage_totals": {},
        "timing": {},
        "model_turns": 0,
    }


def _update_record_from_final(record: dict[str, Any], final: dict[str, Any], *, wall_seconds: float | None = None) -> None:
    usage = final.get("usage_metrics") if isinstance(final.get("usage_metrics"), dict) else {}
    predicted = str(final.get("status", "error"))
    expected = record["expected"]
    record.update({
        "predicted": predicted,
        "confidence": final.get("confidence"),
        "ok": bool(final.get("ok")),
        "correct": None if expected == "unknown" else predicted == expected,
        "evidence_id_count": len(final.get("evidence_ids", []) or []),
        "harness_metrics": final.get("harness_metrics", {}),
        "schema_validation_errors": final.get("schema_validation_errors", []),
        "inconclusive_reason": final.get("inconclusive_reason", ""),
        "usage_totals": rename_usage(usage.get("totals", {})),
        "timing": final.get("timing", {}),
        "model_turns": usage.get("model_turns", 0),
        "metadata_sha256": final.get("metadata_sha256", ""),
    })
    if wall_seconds is not None:
        record["wall_seconds"] = round(wall_seconds, 2)


def run_one_case(case: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    binary_path = resolve_binary(args.binaries_root, args.variant, case["binary_name"], args.compiler, args.opt)
    case_dir = safe_case_dir(expand(args.out_root), case["cve_id"], case["binary_name"])
    record = _empty_record(case, binary_path, case_dir)
    if not binary_path.is_file():
        record.update({"predicted": "not_found", "ok": False, "error": "binary file missing", "correct": False})
        return record
    final_path = case_dir / "final_result.json"
    prior_signature = _artifact_signature(final_path)
    started = time.time()
    try:
        proc = subprocess.run(
            _case_command(case, args, binary_path, case_dir),
            cwd=str(PACKAGE_PARENT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=args.case_timeout,
        )
        record["agent_returncode"] = proc.returncode
        if proc.stderr.strip():
            record["stderr_tail"] = proc.stderr.strip()[-600:]
    except subprocess.TimeoutExpired:
        record.update({"predicted": "timeout", "ok": False, "error": f"case timeout after {args.case_timeout}s", "correct": False})
        return record
    if not final_path.is_file():
        record.update({"predicted": "error", "ok": False, "error": "no final_result.json produced", "correct": False})
        return record
    if prior_signature is not None and _artifact_signature(final_path) == prior_signature:
        record.update({"predicted": "error", "ok": False, "error": "case subprocess did not produce a fresh final_result.json", "correct": False})
        return record
    try:
        final = load_json(final_path)
    except Exception as exc:
        record.update({"predicted": "error", "ok": False, "error": f"unreadable final_result: {exc}", "correct": False})
        return record
    errors = _artifact_validation_errors(final)
    if errors:
        record.update({"predicted": "error", "ok": False, "error": "invalid final_result artifact", "schema_validation_errors": errors, "correct": False})
        return record
    _update_record_from_final(record, final, wall_seconds=time.time() - started)
    return record


def _record_from_artifact(case: dict[str, Any], case_dir: Path) -> dict[str, Any]:
    record = _empty_record(case, Path(), case_dir)
    record["reused"] = True
    artifact = _existing_case_artifact(case_dir)
    if artifact is None:
        record.update({"predicted": "error", "ok": False, "error": "no valid final_result.json (reused)", "correct": False})
        return record
    _update_record_from_final(record, artifact)
    return record


def aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    outcomes = list(VERDICTS) + ["not_found", "timeout", "error"]
    confusion = {expected: {outcome: 0 for outcome in outcomes} for expected in VERDICTS}
    repair_names = (
        "schema_repair_attempts",
        "no_evidence_verdicts",
        "tool_failures",
        "command_failures",
        "evidence_summary_calls",
        "evidence_summary_updates",
        "evidence_summary_revisions",
        "evidence_summary_failures",
    )
    totals = {name: 0 for name in repair_names}
    correct = 0
    scored = 0
    for record in records:
        expected = record.get("expected")
        predicted = record.get("predicted", "error")
        if expected in confusion:
            confusion[expected][predicted if predicted in outcomes else "error"] += 1
            scored += 1
            correct += bool(record.get("correct"))
        metrics = record.get("harness_metrics") or {}
        for name in repair_names:
            totals[name] += int(metrics.get(name, 0) or 0)
    return {
        "total_cases": len(records),
        "scored_cases": scored,
        "correct": correct,
        "accuracy": round(correct / scored, 4) if scored else 0.0,
        "confusion_matrix": confusion,
        "repair_totals": totals,
    }


def bootstrap_api_key(args: argparse.Namespace) -> str | None:
    try:
        profile = resolve_profile(args)
    except ValueError:
        return None
    if os.environ.get(profile.api_key_env):
        return profile.api_key_env
    imported = import_env_from_interactive_shell([profile.api_key_env])
    return profile.api_key_env if imported and os.environ.get(profile.api_key_env) else None


def run_batch(args: argparse.Namespace) -> int:
    cases = load_cases(args.testset, args.groundtruth, args.cve)
    if args.limit > 0:
        cases = cases[: args.limit]
    try:
        profile = resolve_profile(args)
    except ValueError as exc:
        raise SystemExit(f"model config error: {exc}") from exc
    try:
        metadata_by_cve = load_metadata_index(args.metadata_json)
    except Exception as exc:
        raise SystemExit(f"metadata error: {exc}") from exc
    selected_cves = {case["cve_id"] for case in cases}
    metadata_hashes = required_metadata_hashes(metadata_by_cve, selected_cves)
    missing = sorted(selected_cves - set(metadata_hashes))
    if missing:
        raise SystemExit(f"metadata missing for selected CVE(s): {missing}")
    for cve_id in sorted(selected_cves):
        try:
            validate_metadata_prompt_input(metadata_by_cve[cve_id])
        except ValueError as exc:
            raise SystemExit(f"metadata input rejected for {cve_id}: {exc}") from exc

    out_root = expand(args.out_root)
    to_run, to_reuse, counts = _select_resume_cases(cases, out_root, args, metadata_hashes)
    if args.dry_run:
        missing_binaries = [
            case
            for case in cases
            if not resolve_binary(args.binaries_root, args.variant, case["binary_name"], args.compiler, args.opt).is_file()
        ]
        print("BATCH_DRY_RUN")
        print("testset:", args.testset)
        print("groundtruth:", args.groundtruth)
        print("binaries_root:", str(expand(args.binaries_root) / args.variant))
        print("metadata:", args.metadata_json)
        print("total_cases:", len(cases))
        print("by_expected:", {value: sum(case["expected"] == value for case in cases) for value in (*VERDICTS, "unknown")})
        print("metadata_hashes:", metadata_hashes)
        print("resume_mode:", args.resume, "retry_inconclusive:", args.retry_inconclusive)
        print("resume_counts:", counts)
        print("missing_binaries:", len(missing_binaries))
        for case in missing_binaries[:10]:
            print("  MISSING", case["cve_id"], case["binary_name"])
        return 0

    out_root.mkdir(parents=True, exist_ok=True)
    if not bootstrap_api_key(args) and not resolve_api_key(profile):
        print(f"WARNING: API key for profile {profile.name!r} is not available to worker subprocesses.", file=sys.stderr)
    started = time.time()
    print(
        f"resume={args.resume} retry_inconclusive={args.retry_inconclusive} "
        f"total={counts['total']} retry={counts['retry']} skipped={counts['skipped']} "
        f"(completed={counts['completed']} inconclusive={counts['inconclusive']} stale_metadata={counts['stale_metadata']})",
        file=sys.stderr,
    )
    records = [
        _record_from_artifact(case, safe_case_dir(out_root, case["cve_id"], case["binary_name"]))
        for case in to_reuse
    ]
    with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as pool:
        futures = {pool.submit(run_one_case, case, args): case for case in to_run}
        for future in as_completed(futures):
            record = future.result()
            records.append(record)
            mark = "OK " if record.get("correct") else "XX "
            print(f"{mark}{record['cve_id']} {record['binary']}: predicted={record.get('predicted')} expected={record['expected']}", file=sys.stderr)
    records.sort(key=lambda record: (record["cve_id"], record["binary"]))
    wall_seconds = round(time.time() - started, 2)
    metrics = batch_metrics_pptagent(records, batch_wall_seconds=wall_seconds)
    (out_root / "batch_metrics.json").write_text(jdump(metrics) + "\n", encoding="utf-8")
    by_cve: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        by_cve.setdefault(record["cve_id"], []).append(record)
    (out_root / "batch_results.json").write_text(jdump({"results": records, "by_cve": by_cve}) + "\n", encoding="utf-8")
    summary = aggregate(records)
    summary["wall_seconds"] = wall_seconds
    print(jdump(summary), file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="claudeagent batch patch-presence detection")
    parser.add_argument("--testset", required=True, help="label-free CVE/binary pick list")
    parser.add_argument("--groundtruth", required=True, help="labeled groundtruth used only for scoring")
    parser.add_argument("--binaries-root", default=DEFAULT_BINARIES_ROOT)
    parser.add_argument("--variant", default=DEFAULT_VARIANT)
    parser.add_argument("--compiler", default="gcc")
    parser.add_argument("--opt", default="o0", choices=["o0", "o1", "o2", "o3"])
    parser.add_argument("--metadata-json", default=DEFAULT_METADATA)
    parser.add_argument("--out-root", required=True)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--cve", default="")
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--case-timeout", type=int, default=900)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", default="auto", choices=RESUME_MODES)
    parser.add_argument("--retry-inconclusive", action="store_true")
    parser.add_argument("--model", default="")
    parser.add_argument("--base-url", default="")
    parser.add_argument("--model-profile", default="")
    parser.add_argument("--no-strict", action="store_true")
    parser.add_argument("--max-turns", type=int, default=20)
    parser.add_argument("--finalization-turns", type=int, default=3)
    parser.add_argument("--api-timeout", type=int, default=240)
    parser.add_argument("--api-max-retries", type=int, default=3)
    parser.add_argument("--api-turn-retries", type=int, default=1)
    return parser


def main(argv: list[str] | None = None) -> int:
    return run_batch(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
