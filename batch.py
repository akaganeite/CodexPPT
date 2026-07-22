"""Batch runner over the curl testset.

Each (CVE, binary) case runs as an isolated subprocess of the single-case loop,
so there is no shared AGENT_CONTEXT state between cases. Groundtruth maps
vuln -> absent, patch -> present, not_affected -> not_affected. Per-case results
are scored into the pptagent-shaped ``batch_metrics.json`` (binary_metrics with
DSR/A/P/R/F1, not_affected_metrics, overall_DSR, classification_counts,
inconclusive_status, usage_totals/usage_mean) plus a ``batch_results.json``
case-detail file -- so claudeagent and pptagent outputs are directly comparable.

Run:
    python3 -m claudeagent.batch --out-root <dir> [--limit N] [--cve CVE-...] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from claudeagent.common import ROOT, VERDICTS, expand, jdump, load_json
from claudeagent.host import import_env_from_interactive_shell
from claudeagent.model_config import interactive_env_keys, resolve_profile


PACKAGE_PARENT = ROOT.parent  # so `python3 -m claudeagent.agent_loop` resolves
DEFAULT_GROUNDTRUTH = "/home/zhangxb/extdisk/dataset4ppt/curl/exports/groundtruth_with_not_affected.json"
DEFAULT_BINARIES_ROOT = "~/extdisk/dataset4ppt/curl/binaries"
DEFAULT_VARIANT = "target/curl_stripped"
DEFAULT_METADATA = "/home/zhangxb/ClawSpace/agent/straight_detect/metadata/curl/curl_project_source_analysis.behavior.json"

# Groundtruth list name -> expected verdict.
LABEL_TO_STATUS = {"vuln": "absent", "patch": "present", "not_affected": "not_affected"}


# ---------------------------------------------------------------------------
# pptagent-shaped batch metrics.
#
# These functions reproduce the output schema of
# ../pptagent/evaluation/metrics.py so claudeagent and pptagent batch_metrics.json
# are directly comparable. The usage-token keys are renamed from OpenAI Responses
# API names (input_tokens/output_tokens/...) to the chat-style names pptagent's
# model_client emits (prompt_tokens/completion_tokens/...), matching
# ../pptagent/core/model_client.py:_responses_usage_to_chat_usage. validator.*
# fields are omitted (claudeagent has no separate validator process).
# ---------------------------------------------------------------------------

# Responses-API (flattened) usage key -> pptagent usage key.
_USAGE_KEY_MAP = {
    "input_tokens": "prompt_tokens",
    "output_tokens": "completion_tokens",
    "total_tokens": "total_tokens",
    "input_tokens_details.cached_tokens": "prompt_tokens_details.cached_tokens",
    "output_tokens_details.reasoning_tokens": "completion_tokens_details.reasoning_tokens",
}
# pptagent-style keys dropped entirely (not in the reference schema).
_USAGE_DROP_KEYS = {
    "input_tokens_details.cache_write_tokens",
}


def rename_usage(totals: dict[str, Any]) -> dict[str, int | float]:
    """Translate a case's Responses-API usage totals to pptagent key names.

    Renames input/output/total/cached to prompt/completion/total/cached and
    derives ``prompt_cache_hit_tokens`` (= cached) and ``prompt_cache_miss_tokens``
    (= input - cached). reasoning_tokens is kept (mapped to
    ``completion_tokens_details.reasoning_tokens``, matching pptagent's
    _responses_usage_to_chat_usage). Only cache_write_tokens is dropped (absent
    from the pptagent reference schema). Keys not in the map and not derived are
    dropped, so usage_totals only carries pptagent-comparable fields.
    """
    if not isinstance(totals, dict):
        return {}
    out: dict[str, int | float] = {}
    for key, value in totals.items():
        if key in _USAGE_DROP_KEYS:
            continue
        mapped = _USAGE_KEY_MAP.get(key)
        if mapped is None:
            continue  # unknown key -> drop (strict pptagent-only schema)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            out[mapped] = value
    input_tokens = totals.get("input_tokens")
    cached = (totals.get("input_tokens_details") or {}).get("cached_tokens") \
        if isinstance(totals.get("input_tokens_details"), dict) \
        else totals.get("input_tokens_details.cached_tokens")
    if isinstance(input_tokens, (int, float)) and not isinstance(input_tokens, bool):
        cached_val = cached if isinstance(cached, (int, float)) and not isinstance(cached, bool) else 0
        out["prompt_cache_hit_tokens"] = cached_val
        out["prompt_cache_miss_tokens"] = input_tokens - cached_val
    return out


def safe_ratio(numerator: int, denominator: int) -> float:
    """Divide with a zero-denominator guard, rounded to 6 decimals."""
    return round(numerator / denominator, 6) if denominator else 0.0


def _sum_usage(records: list[dict[str, Any]]) -> dict[str, int | float]:
    """Sum per-case usage_totals and case wall times across all records.

    Mirrors pptagent metrics._sum_usage: accumulates every numeric key in each
    case's (already-renamed) usage_totals and sums timing.wall_seconds into
    case_wall_seconds_sum.
    """
    usage_totals: dict[str, int | float] = {}
    case_wall_sum = 0.0
    for item in records:
        for key, value in (item.get("usage_totals") or {}).items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                usage_totals[key] = usage_totals.get(key, 0) + value
        wall = (item.get("timing") or {}).get("wall_seconds")
        if isinstance(wall, (int, float)) and not isinstance(wall, bool):
            case_wall_sum += float(wall)
    usage_totals["case_wall_seconds_sum"] = round(case_wall_sum, 3)
    return usage_totals


def _mean_usage(usage_totals: dict[str, int | float], cases: int) -> dict[str, float]:
    """Per-case means of each usage total (rounded to 6 decimals)."""
    if cases <= 0:
        return {key: 0.0 for key in usage_totals}
    return {
        key: round(float(value) / cases, 6)
        for key, value in usage_totals.items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    }


def batch_metrics_pptagent(
    records: list[dict[str, Any]], batch_wall_seconds: float | None = None
) -> dict[str, Any]:
    """Compute the pptagent-shaped batch metrics JSON from compact case records.

    binary_metrics excludes ground-truth not_affected cases: its DSR is correct
    binary decisions over all binary-scope cases, while A/P/R/F1 are computed only
    over explicit present/absent predictions. not_affected_metrics reports
    ground-truth not_affected accuracy. overall_metrics.overall_DSR is the
    all-class correct rate over present/absent/not_affected expectations.
    """
    evaluated = []
    affected = []
    not_affected_rows = []
    for item in records:
        expected = str(item.get("expected") or "")
        if not expected:
            continue
        row = {**item, "_expected_status": expected}
        evaluated.append(row)
        if expected == "not_affected":
            not_affected_rows.append(row)
        else:
            affected.append(row)

    tp = sum(1 for it in affected if it["_expected_status"] == "present" and it.get("predicted") == "present")
    tn = sum(1 for it in affected if it["_expected_status"] == "absent" and it.get("predicted") == "absent")
    fp = sum(1 for it in affected if it["_expected_status"] == "absent" and it.get("predicted") == "present")
    fn = sum(1 for it in affected if it["_expected_status"] == "present" and it.get("predicted") == "absent")

    precision = safe_ratio(tp, tp + fp)
    recall = safe_ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 6) if precision + recall else 0.0
    binary_correct = tp + tn
    binary_decided = tp + tn + fp + fn
    binary_total = len(affected)
    not_affected_correct = sum(1 for it in not_affected_rows if it.get("predicted") == "not_affected")
    ternary_correct = sum(1 for it in evaluated if it.get("predicted") == it["_expected_status"])
    inconclusive_status = Counter(
        str(it.get("inconclusive_reason", "") or "unspecified")
        for it in records
        if it.get("predicted") == "inconclusive"
    )
    usage_totals = _sum_usage(records)
    if batch_wall_seconds is not None:
        usage_totals["batch_wall_seconds"] = round(batch_wall_seconds, 3)

    usage_mean = _mean_usage(usage_totals, len(records))
    if batch_wall_seconds is not None:
        usage_mean["batch_wall_seconds"] = round(batch_wall_seconds / len(records), 6) if records else 0.0

    return {
        "binary_metrics": {
            "DSR": safe_ratio(binary_correct, binary_total),
            "A": safe_ratio(binary_correct, binary_decided),
            "P": precision,
            "F1": f1,
            "R": recall,
        },
        "not_affected_metrics": {
            "not_affected_accuracy": safe_ratio(not_affected_correct, len(not_affected_rows)),
        },
        "overall_metrics": {
            "overall_DSR": safe_ratio(ternary_correct, len(evaluated)),
        },
        "classification_counts": {
            "TN": tn,
            "TP": tp,
            "FN": fn,
            "FP": fp,
            "TC": binary_total,
            "not-affected": sum(1 for it in records if it.get("predicted") == "not_affected"),
            "inconclusive": sum(1 for it in records if it.get("predicted") == "inconclusive"),
        },
        "inconclusive_status": dict(sorted(inconclusive_status.items())),
        "usage_totals": usage_totals,
        "usage_mean": usage_mean,
    }


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


# A binary name already carrying a ``-<compiler>-O[0-3]`` suffix needs no further
# decoration (mirrors pptagent's COMPILER_OPT_RE). Anchored at the end so a
# mid-name ``-O0`` does not falsely match.
_COMPILER_OPT_RE = re.compile(r"-.+-O[0-3]$")

# When ``compiler == DEPLOY_COMPILER`` the on-disk artifact carries a ``-deployed``
# tail instead of ``-<compiler>-O<opt>`` (the Ubuntu/Debian deployed testset).
# ``opt`` is meaningless for deployed binaries and is ignored.
DEPLOY_COMPILER = "deploy"
_DEPLOY_SUFFIX = "-deployed"


def _normalized_opt(opt: str) -> str:
    """Return an uppercase optimization level without a leading dash (``o2``->``O2``)."""
    value = str(opt or "o0").strip()
    if not value:
        return "O0"
    if value.startswith("-"):
        value = value[1:]
    return value.upper()


def _suffixed_binary_name(binary_name: str, compiler: str, opt: str) -> str:
    """Append the build suffix a groundtruth short name lacks.

    gcc layout: ``-<compiler>-<OPT>`` (e.g. ``openssl-1.1.0b-openssl-gcc-O2``).
    deploy layout: ``-deployed`` (e.g. ``openssl-1.0.1f-1ubuntu9-libssl.so.1.0.0-deployed``);
    ``opt`` is ignored. A name already ending in ``-.+-O[0-3]`` is returned as-is.
    """
    compiler = str(compiler or "gcc").strip() or "gcc"
    if compiler == DEPLOY_COMPILER:
        if binary_name.endswith(_DEPLOY_SUFFIX):
            return binary_name
        return f"{binary_name}{_DEPLOY_SUFFIX}"
    if _COMPILER_OPT_RE.search(binary_name):
        return binary_name
    return f"{binary_name}-{compiler}-{_normalized_opt(opt)}"


def resolve_binary(
    binaries_root: str, variant: str, binary_name: str, compiler: str = "gcc", opt: str = "o0"
) -> Path:
    """Resolve a groundtruth binary_name to an on-disk path under variant.

    Mirrors pptagent's ``resolve_binary_name`` (evaluation/case_builder.py): probe the
    exact name first, then the compiler/opt-suffixed variant, falling back to a
    ``<name>-*<suffix>`` glob (the deployed/gcc layouts both encode build identity
    in the filename tail, so a glob on that tail picks the right artifact when the
    groundtruth stem is a prefix). Returns a deterministic path even if nothing
    matches, so preflight reports the missing file against a descriptive name.

    When several optimization levels coexist on disk (e.g. ``-gcc-O0`` and
    ``-gcc-O2`` for one short name), pinning via ``compiler``/``opt`` resolves to
    ``-gcc-O2`` instead of the lexicographically-first ``-gcc-O0`` that a plain
    ``sorted()[0]`` would pick. ``compiler="deploy"`` targets the Ubuntu/Debian
    deployed testset, whose artifacts carry a ``-deployed`` tail with no opt.
    """
    variant_dir = expand(binaries_root) / variant
    if (variant_dir / binary_name).is_file():
        return variant_dir / binary_name
    suffixed = _suffixed_binary_name(binary_name, compiler, opt)
    if suffixed != binary_name and (variant_dir / suffixed).is_file():
        return variant_dir / suffixed
    # glob fallback: the groundtruth stem may be a prefix of the real filename,
    # but the build suffix tail must still match (so -gcc-O2 never resolves to -gcc-O0).
    if suffixed != binary_name:
        tail = suffixed[len(binary_name):]
        matches = sorted(p for p in variant_dir.glob(f"{binary_name}*{tail}") if p.is_file())
        if matches:
            return matches[0]
    return variant_dir / suffixed


def safe_case_dir(out_root: Path, cve_id: str, binary_name: str) -> Path:
    safe = binary_name.replace("/", "_")
    return out_root / cve_id / safe


# Resume modes decide which already-run cases get re-run vs. reused as-is.
#   auto        - skip every case with a completed final_result.json (present/
#                 absent/not_affected/inconclusive); re-run only missing/error/
#                 timeout. This is the safe default: a finished case, even an
#                 inconclusive one, is a legitimate result and is not retried
#                 unless asked.
#   error       - same selection as ``auto`` (re-run missing/error/timeout only).
#                 Kept as an explicit alias so a retest script reads clearly.
#   inconclusive- re-run ONLY cases whose existing artifact is inconclusive;
#                 leave missing/error/timeout and all determinate results alone.
#                 Use this to retry the "gave up at max-turns" cases with more
#                 turns while preserving every other result.
#   all         - re-run every case (resume disabled).
RESUME_MODES = ("auto", "all", "error", "inconclusive")
# Statuses that count as "a completed result worth keeping" under ``auto``.
_COMPLETED_STATUSES = {"present", "absent", "not_affected", "inconclusive"}
# ``error``/``timeout`` are *not* in _COMPLETED_STATUSES: a timeout never writes
# final_result.json, and an error means the artifact is missing/unreadable, so
# both surface as None below and get re-run under auto/error.


def _existing_case_status(case_dir: Path) -> str | None:
    """Return the on-disk ``status`` of a case, or None if it must be re-run.

    None covers: no final_result.json, an unreadable file, a missing/unknown
    ``status`` field. Any of the four verdicts is returned as-is. A subprocess
    timeout writes nothing, so it also surfaces as None -> re-run.
    """
    final_path = case_dir / "final_result.json"
    if not final_path.is_file():
        return None
    try:
        final = load_json(final_path)
    except Exception:
        return None
    status = final.get("status")
    return str(status) if status in _COMPLETED_STATUSES else None


def _select_resume_cases(
    cases: list[dict[str, Any]], out_root: Path, args: argparse.Namespace
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    """Split ``cases`` into (to_run, to_reuse) under the resume policy.

    Returns a counts dict for logging: total, completed, inconclusive, retry
    (== len(to_run)), skipped (== len(to_reuse)).
    """
    mode = args.resume
    retry_inc = getattr(args, "retry_inconclusive", False)
    to_run: list[dict[str, Any]] = []
    to_reuse: list[dict[str, Any]] = []
    counts = {"total": len(cases), "completed": 0, "inconclusive": 0, "retry": 0, "skipped": 0}

    for case in cases:
        case_dir = safe_case_dir(out_root, case["cve_id"], case["binary_name"])
        status = _existing_case_status(case_dir)
        if status is not None:
            counts["completed"] += 1
            if status == "inconclusive":
                counts["inconclusive"] += 1

        if mode == "all":
            run_it = True
        elif mode == "inconclusive":
            # Only re-run cases that ARE inconclusive; everything else is reused.
            run_it = status == "inconclusive"
        else:  # auto / error
            # Re-run anything without a completed artifact. inconclusive counts
            # as completed and is skipped, unless --retry-inconclusive opts in.
            if status is None:
                run_it = True
            elif status == "inconclusive":
                run_it = bool(retry_inc)
            else:
                run_it = False

        if run_it:
            to_run.append(case)
            counts["retry"] += 1
        else:
            to_reuse.append(case)
            counts["skipped"] += 1
    return to_run, to_reuse, counts


def run_one_case(case: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    binary_path = resolve_binary(
        args.binaries_root, args.variant, case["binary_name"], args.compiler, args.opt
    )
    case_dir = safe_case_dir(expand(args.out_root), case["cve_id"], case["binary_name"])
    record = {
        "cve_id": case["cve_id"],
        "binary": case["binary_name"],
        "binary_path": str(binary_path),
        "expected": case["expected"],
        "output_dir": str(case_dir),
        # pptagent-shaped extras; populated from final_result.json on success and
        # left empty on error/timeout/not_found so usage aggregation skips them.
        "inconclusive_reason": "",
        "usage_totals": {},
        "timing": {},
        "model_turns": 0,
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
        "--api-turn-retries", str(args.api_turn_retries),
    ]
    if args.model:
        cmd += ["--model", args.model]
    if args.base_url:
        cmd += ["--base-url", args.base_url]
    if args.model_profile:
        cmd += ["--model-profile", args.model_profile]
    if args.no_strict:
        cmd += ["--no-strict"]

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
    usage_metrics = final.get("usage_metrics") if isinstance(final.get("usage_metrics"), dict) else {}
    record.update({
        "predicted": predicted,
        "confidence": final.get("confidence"),
        "ok": bool(final.get("ok")),
        "correct": predicted == case["expected"],
        "evidence_id_count": len(final.get("evidence_ids", []) or []),
        "harness_metrics": final.get("harness_metrics", {}),
        "wall_seconds": round(time.time() - started, 2),
        "schema_validation_errors": final.get("schema_validation_errors", []),
        # pptagent-shaped extras, read straight from the artifact.
        "inconclusive_reason": final.get("inconclusive_reason", ""),
        "usage_totals": rename_usage(usage_metrics.get("totals", {})),
        "timing": final.get("timing", {}),
        "model_turns": usage_metrics.get("model_turns", 0),
    })
    return record


def _record_from_artifact(case: dict[str, Any], case_dir: Path) -> dict[str, Any]:
    """Rebuild a record from an existing final_result.json (resume reuse path).

    Mirrors the field mapping at the end of run_one_case, but without a fresh
    wall-clock (the artifact already ran). Used so a resumed batch still reports
    full-set metrics across both re-run and reused cases.
    """
    record = {
        "cve_id": case["cve_id"],
        "binary": case["binary_name"],
        "binary_path": "",
        "expected": case["expected"],
        "output_dir": str(case_dir),
        "inconclusive_reason": "",
        "usage_totals": {},
        "timing": {},
        "model_turns": 0,
        "reused": True,
    }
    final_path = case_dir / "final_result.json"
    if not final_path.is_file():
        record.update({"predicted": "error", "ok": False, "error": "no final_result.json (reused)", "correct": False})
        return record
    try:
        final = load_json(final_path)
    except Exception as exc:
        record.update({"predicted": "error", "ok": False, "error": f"unreadable reused final_result: {exc}", "correct": False})
        return record
    predicted = str(final.get("status", "error"))
    usage_metrics = final.get("usage_metrics") if isinstance(final.get("usage_metrics"), dict) else {}
    record.update({
        "predicted": predicted,
        "confidence": final.get("confidence"),
        "ok": bool(final.get("ok")),
        "correct": predicted == case["expected"],
        "evidence_id_count": len(final.get("evidence_ids", []) or []),
        "harness_metrics": final.get("harness_metrics", {}),
        "wall_seconds": (final.get("timing", {}) or {}).get("wall_seconds", 0),
        "schema_validation_errors": final.get("schema_validation_errors", []),
        "inconclusive_reason": final.get("inconclusive_reason", ""),
        "usage_totals": rename_usage(usage_metrics.get("totals", {})),
        "timing": final.get("timing", {}),
        "model_turns": usage_metrics.get("model_turns", 0),
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


def resolve_api_key_env(args: argparse.Namespace) -> str | None:
    """The env var name the selected profile reads its API key from."""
    try:
        return resolve_profile(args).api_key_env
    except ValueError:
        return None


def bootstrap_api_key(args: argparse.Namespace) -> str | None:
    """Ensure the profile's API-key env var is exported into this process.

    Each case runs as a subprocess inheriting this environment, so the key must
    live here (not in the interactive shell each subprocess can't reach under
    --jobs). For the cliproxy profile the key is PPTAGENT_API_KEY, which only
    exists in the interactive zsh; import it once up front. Returns the env var
    name on success, None if it could not be resolved/imported.
    """
    key_env = resolve_api_key_env(args)
    if not key_env:
        return None
    if os.environ.get(key_env):
        return key_env
    imported = import_env_from_interactive_shell([key_env])
    if imported and os.environ.get(key_env):
        return key_env
    return None


def run_batch(args: argparse.Namespace) -> int:
    cases = load_cases(args.groundtruth, args.cve)
    if args.limit > 0:
        cases = cases[: args.limit]
    out_root = expand(args.out_root)

    # Validate the config/profile before launching any subprocess, so a typo in
    # --model-profile or a malformed model_config.json fails fast with a clear
    # message instead of N failing worker cases.
    try:
        resolve_profile(args)
    except ValueError as exc:
        raise SystemExit(f"model config error: {exc}")

    if args.dry_run:
        missing = [c for c in cases if not resolve_binary(args.binaries_root, args.variant, c["binary_name"], args.compiler, args.opt).is_file()]
        _, _, counts = _select_resume_cases(cases, out_root, args)
        print("BATCH_DRY_RUN")
        print("groundtruth:", args.groundtruth)
        print("binaries_root:", str(expand(args.binaries_root) / args.variant))
        print("metadata:", args.metadata_json)
        print("total_cases:", len(cases))
        print("by_expected:", {v: sum(1 for c in cases if c["expected"] == v) for v in VERDICTS})
        print("resume_mode:", args.resume, "retry_inconclusive:", getattr(args, "retry_inconclusive", False))
        print("resume_counts:", counts)
        print("missing_binaries:", len(missing))
        for c in missing[:10]:
            print("  MISSING", c["cve_id"], c["binary_name"])
        return 0

    out_root.mkdir(parents=True, exist_ok=True)
    key_env = bootstrap_api_key(args)
    if not key_env:
        profile_name = args.model_profile or "active"
        print(
            f"WARNING: could not resolve/import the API-key env var for profile "
            f"{profile_name!r}; subprocesses may fail to authenticate. "
            f"Set it in your shell or use --model-profile with a profile whose key is available.",
            file=sys.stderr,
        )

    # Resume: reuse completed cases (auto skips inconclusive too) and only
    # re-run the ones the mode selects. Metrics are still computed over the
    # full set: reused cases are rebuilt from their on-disk artifacts.
    to_run, to_reuse, counts = _select_resume_cases(cases, out_root, args)
    print(
        f"resume={args.resume} retry_inconclusive={getattr(args, 'retry_inconclusive', False)} "
        f"total={counts['total']} retry={counts['retry']} skipped={counts['skipped']} "
        f"(completed={counts['completed']} inconclusive={counts['inconclusive']})",
        file=sys.stderr,
    )
    records: list[dict[str, Any]] = [
        _record_from_artifact(case, safe_case_dir(out_root, case["cve_id"], case["binary_name"]))
        for case in to_reuse
    ]
    started = time.time()
    with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as pool:
        futures = {pool.submit(run_one_case, case, args): case for case in to_run}
        for done in as_completed(futures):
            rec = done.result()
            records.append(rec)
            mark = "OK " if rec.get("correct") else "XX "
            print(f"{mark}{rec['cve_id']} {rec['binary']}: predicted={rec.get('predicted')} expected={rec['expected']}", file=sys.stderr)

    records.sort(key=lambda r: (r["cve_id"], r["binary"]))
    wall_seconds = round(time.time() - started, 2)

    # pptagent-shaped metrics + case-detail file (directly comparable to
    # pptagent batch_metrics.json / batch_results.json).
    metrics = batch_metrics_pptagent(records, batch_wall_seconds=wall_seconds)
    (out_root / "batch_metrics.json").write_text(jdump(metrics) + "\n", encoding="utf-8")
    by_cve: dict[str, list[dict[str, Any]]] = {}
    for rec in records:
        by_cve.setdefault(rec["cve_id"], []).append(rec)
    (out_root / "batch_results.json").write_text(
        jdump({"results": records, "by_cve": by_cve}) + "\n", encoding="utf-8"
    )

    # Keep the legacy accuracy/confusion summary for the stderr log only; it is
    # not written to disk (the on-disk metrics file is the pptagent shape above).
    summary = aggregate(records)
    summary["wall_seconds"] = wall_seconds
    print(jdump(summary), file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="claudeagent batch patch-presence detection over the curl testset")
    parser.add_argument("--groundtruth", default=DEFAULT_GROUNDTRUTH)
    parser.add_argument("--binaries-root", default=DEFAULT_BINARIES_ROOT)
    parser.add_argument("--variant", default=DEFAULT_VARIANT, help="subpath under binaries-root, e.g. target/curl_stripped")
    parser.add_argument("--compiler", default="gcc",
                        help="build suffix for short groundtruth names: 'gcc' -> -gcc-O<opt>; 'deploy' targets the "
                             "Ubuntu/Debian deployed testset (-deployed tail, opt ignored)")
    parser.add_argument("--opt", default="o0", choices=["o0", "o1", "o2", "o3"],
                        help="optimization level appended with --compiler gcc (o0/o1/o2/o3); ignored when --compiler deploy")
    parser.add_argument("--metadata-json", default=DEFAULT_METADATA)
    parser.add_argument("--out-root", required=True)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--cve", default="", help="restrict to a single CVE id")
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--case-timeout", type=int, default=900)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", default="auto", choices=RESUME_MODES,
                        help="auto: skip completed results (incl. inconclusive), re-run only "
                             "missing/error/timeout; error: same as auto (explicit alias); "
                             "inconclusive: re-run ONLY inconclusive cases; all: re-run everything")
    parser.add_argument("--retry-inconclusive", dest="retry_inconclusive", action="store_true",
                        help="with --resume auto/error, also re-run inconclusive cases "
                             "(e.g. to retry max-turns give-ups with a larger --max-turns)")
    # Passthrough to the single-case loop.
    parser.add_argument("--model", default="")
    parser.add_argument("--base-url", default="")
    parser.add_argument("--model-profile", default="",
                        help="config profile name or alias (see model_config.json); default is the config's active_profile")
    parser.add_argument("--no-strict", action="store_true")
    parser.add_argument("--max-turns", type=int, default=20)
    parser.add_argument("--finalization-turns", type=int, default=3)
    parser.add_argument("--api-timeout", type=int, default=240)
    parser.add_argument("--api-max-retries", type=int, default=3)
    parser.add_argument("--api-turn-retries", type=int, default=1,
                        help="per-case whole-turn retries across long upstream outage windows")
    return parser


def main(argv: list[str] | None = None) -> int:
    return run_batch(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
