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
import hashlib
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
from claudeagent.decision import FINAL_SCHEMA_VERSION
from claudeagent.evidence_verifier import (
    EvidenceVerifierConfig,
    evidence_verifier_config_digest,
)
from claudeagent.finalize import validate_final_result_artifact
from claudeagent.host import import_env_from_interactive_shell
from claudeagent.model_config import reasoning_param, resolve_api_key, resolve_profile
from claudeagent.patchspec import (
    PatchSpecModelConfig,
    ensure_patch_spec,
    patch_spec_cache_key,
    patch_spec_cache_path,
)


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

    def numeric_leaves(value: Any, prefix: str = "") -> list[tuple[str, int | float]]:
        leaves: list[tuple[str, int | float]] = []
        if isinstance(value, dict):
            for key, item in value.items():
                child = f"{prefix}.{key}" if prefix else str(key)
                leaves.extend(numeric_leaves(item, child))
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            leaves.append((prefix, value))
        return leaves

    out: dict[str, int | float] = {}
    for key, value in numeric_leaves(totals):
        if key in _USAGE_DROP_KEYS:
            continue
        mapped = _USAGE_KEY_MAP.get(key)
        if mapped is None:
            continue  # unknown key -> drop (strict pptagent-only schema)
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


def load_metadata_index(metadata_path: str) -> dict[str, dict[str, Any]]:
    """Load batch metadata once and index normalized objects by CVE id."""
    raw = load_json(metadata_path)
    indexed: dict[str, dict[str, Any]] = {}
    if isinstance(raw, dict) and isinstance(raw.get("cve_id"), str):
        candidates = [raw]
    elif isinstance(raw, dict):
        candidates = []
        for key, value in raw.items():
            if not isinstance(value, dict):
                continue
            item = dict(value)
            item.setdefault("cve_id", str(key))
            candidates.append(item)
    elif isinstance(raw, list):
        candidates = [item for item in raw if isinstance(item, dict)]
    else:
        raise ValueError("metadata JSON must be a CVE object, object map, or list")

    for candidate in candidates:
        cve_id = candidate.get("cve_id")
        if not isinstance(cve_id, str) or not cve_id:
            continue
        item = dict(candidate)
        item.setdefault("project", "curl")
        indexed[cve_id] = item
    return indexed


def build_patchspec_config(
    args: argparse.Namespace, profile: Any, api_key: str
) -> PatchSpecModelConfig:
    """Resolve the same effective provider settings for batch pre-generation."""
    timeout = profile.api_timeout if profile.api_timeout is not None else args.api_timeout
    max_retries = (
        profile.api_max_retries
        if profile.api_max_retries is not None
        else args.api_max_retries
    )
    return PatchSpecModelConfig.from_profile(
        profile,
        api_key=api_key,
        base_url=args.base_url or None,
        model=args.model or None,
        reasoning_effort=profile.reasoning_effort,
        timeout=timeout,
        max_retries=max_retries,
    )


def requested_evidence_verifier_digest(args: argparse.Namespace, profile: Any) -> str:
    if str(getattr(args, "evidence_verifier", "llm")) != "llm":
        return ""
    return evidence_verifier_config_digest(EvidenceVerifierConfig(
        api_key="",
        base_url=str(getattr(args, "base_url", "") or profile.base_url),
        model=str(getattr(args, "model", "") or profile.model),
        reasoning=reasoning_param(profile),
        timeout=int(getattr(args, "api_timeout", 240)),
        max_retries=int(getattr(args, "api_max_retries", 3)),
        strict=not bool(getattr(args, "no_strict", False)),
    ))


def required_patchspec_keys(
    metadata_by_cve: dict[str, dict[str, Any]],
    cve_ids: set[str] | list[str],
    config: PatchSpecModelConfig,
) -> dict[str, str]:
    """Compute cache fingerprints without performing model or filesystem I/O."""
    return {
        cve_id: patch_spec_cache_key(
            metadata_by_cve[cve_id],
            cve_id=cve_id,
            model=config.model,
            reasoning_effort=config.reasoning_effort,
            reasoning=config.reasoning,
        )
        for cve_id in sorted(set(cve_ids))
        if cve_id in metadata_by_cve
    }


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


def prepare_patch_specs(
    metadata_by_cve: dict[str, dict[str, Any]],
    cve_ids: set[str] | list[str],
    *,
    config: PatchSpecModelConfig,
    cache_dir: Path,
    dry_run: bool,
    max_workers: int,
    ensure_fn: Any = None,
) -> tuple[dict[str, Any], dict[str, str], float]:
    """Resolve exactly one PatchSpec per distinct CVE.

    The returned result map is the sole source of paths handed to case workers;
    failures are isolated by CVE so unrelated cases can continue. ``dry_run`` is
    passed through unchanged, relying on the PatchSpec layer's no-network,
    no-write contract.
    """
    ensure = ensure_fn or ensure_patch_spec
    ordered = sorted(set(cve_ids))
    results: dict[str, Any] = {}
    failures: dict[str, str] = {}
    started = time.time()

    def resolve_one(cve_id: str) -> Any:
        metadata = metadata_by_cve.get(cve_id)
        if metadata is None:
            raise ValueError(f"CVE not found in metadata JSON: {cve_id}")
        return ensure(
            metadata,
            cve_id=cve_id,
            config=config,
            cache_dir=cache_dir,
            dry_run=dry_run,
        )

    if ordered:
        with ThreadPoolExecutor(max_workers=min(max(1, max_workers), len(ordered))) as pool:
            futures = {pool.submit(resolve_one, cve_id): cve_id for cve_id in ordered}
            for done in as_completed(futures):
                cve_id = futures[done]
                try:
                    results[cve_id] = done.result()
                except Exception as exc:
                    failures[cve_id] = repr(exc)
    return results, failures, round(time.time() - started, 3)


def patchspec_manifest_entry(
    result: Any, *, cache_dir: Path | None = None, cve_id: str = ""
) -> dict[str, Any]:
    """Return a JSON-safe audit record without duplicating the full spec."""
    usage = result.usage if isinstance(getattr(result, "usage", None), dict) else {}
    cache_hit = bool(getattr(result, "cache_hit", False))
    result_mode = str(getattr(result, "generation_mode", "unknown"))
    spec = result.spec if isinstance(getattr(result, "spec", None), dict) else {}
    generation = spec.get("generation") if isinstance(spec.get("generation"), dict) else {}
    generation_mode = str(generation.get("mode", result_mode))
    if cache_hit:
        resolution_mode = "cache_hit"
    elif result_mode == "dry_run_skeleton":
        resolution_mode = "deterministic_skeleton"
    else:
        resolution_mode = "generated"
    path = str(getattr(result, "path", "") or "")
    if not path and cache_dir is not None and cve_id:
        path = str(patch_spec_cache_path(cache_dir, cve_id, str(result.cache_key)))
    return {
        "path": path,
        "digest": str(getattr(result, "digest", "") or ""),
        "cache_key": str(getattr(result, "cache_key", "") or ""),
        "generation_mode": generation_mode,
        "resolution_mode": resolution_mode,
        "cache_hit": cache_hit,
        "usage": usage,
    }


def patchspec_batch_metrics(
    results: dict[str, Any], failures: dict[str, str], wall_seconds: float
) -> dict[str, Any]:
    """Aggregate current-run PatchSpec cost once per CVE, never per case."""
    manifest_entries = [patchspec_manifest_entry(result) for result in results.values()]
    generation_counts = Counter(entry["generation_mode"] for entry in manifest_entries)
    resolution_counts = Counter(entry["resolution_mode"] for entry in manifest_entries)
    totals: dict[str, int | float] = {}
    model_turns = 0
    for result in results.values():
        usage = result.usage if isinstance(getattr(result, "usage", None), dict) else {}
        attempts = usage.get("attempts")
        turns = usage.get("model_turns", len(attempts) if isinstance(attempts, list) else 0)
        if isinstance(turns, (int, float)) and not isinstance(turns, bool):
            model_turns += int(turns)
        raw_totals = usage.get("total", usage.get("totals", usage))
        renamed = rename_usage(raw_totals if isinstance(raw_totals, dict) else {})
        for key, value in renamed.items():
            totals[key] = totals.get(key, 0) + value
    return {
        "cves": len(results) + len(failures),
        "successful_cves": len(results),
        "failed_cves": len(failures),
        "generation_counts": dict(sorted(generation_counts.items())),
        "resolution_counts": dict(sorted(resolution_counts.items())),
        "model_turns": model_turns,
        "usage_totals": totals,
        "wall_seconds": round(wall_seconds, 3),
    }


def _patch_spec_fields(final: dict[str, Any]) -> dict[str, Any]:
    """Extract PatchSpec audit fields from current or transitional artifacts."""
    nested = final.get("patch_spec") if isinstance(final.get("patch_spec"), dict) else {}
    usage_metrics = final.get("usage_metrics") if isinstance(final.get("usage_metrics"), dict) else {}
    usage = usage_metrics.get("patch_spec_generation")
    if not isinstance(usage, dict):
        usage = final.get("patch_spec_usage") if isinstance(final.get("patch_spec_usage"), dict) else {}
    return {
        "patch_spec_digest": nested.get("digest", final.get("patch_spec_digest", "")),
        "patch_spec_cache_key": nested.get("cache_key", final.get("patch_spec_cache_key", "")),
        "patch_spec_generation_mode": nested.get(
            "generation_mode", final.get("patch_spec_generation_mode", "")
        ),
        "patch_spec_resolution_mode": nested.get(
            "resolution_mode", final.get("patch_spec_resolution_mode", "")
        ),
        "patch_spec_usage": usage,
    }


def _evidence_verifier_fields(final: dict[str, Any]) -> dict[str, Any]:
    """Extract independent verifier audit/usage without mixing investigation cost."""
    audit = (
        final.get("evidence_verification")
        if isinstance(final.get("evidence_verification"), dict)
        else {}
    )
    usage_metrics = final.get("usage_metrics") if isinstance(final.get("usage_metrics"), dict) else {}
    usage = (
        usage_metrics.get("evidence_verifier")
        if isinstance(usage_metrics.get("evidence_verifier"), dict)
        else {}
    )
    raw_turns = usage.get("model_turns", 0)
    model_turns = (
        int(raw_turns)
        if isinstance(raw_turns, (int, float)) and not isinstance(raw_turns, bool)
        else 0
    )
    return {
        "evidence_verification": audit,
        "evidence_verifier_mode": str(audit.get("mode", "")),
        "evidence_verifier_outcome": str(audit.get("outcome", "")),
        "evidence_verifier_config_digest": str(audit.get("config_digest", "")),
        "evidence_verifier_model_turns": model_turns,
        "evidence_verifier_usage_totals": rename_usage(usage.get("totals", {})),
    }


def evidence_verifier_batch_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate verifier outcomes and tokens separately from investigator usage."""
    mode_counts = Counter(str(item.get("evidence_verifier_mode", "") or "unknown") for item in records)
    outcome_counts = Counter(
        str(item.get("evidence_verifier_outcome", "") or "unknown") for item in records
    )
    totals: dict[str, int | float] = {}
    model_turns = 0
    for item in records:
        raw_turns = item.get("evidence_verifier_model_turns", 0)
        if isinstance(raw_turns, (int, float)) and not isinstance(raw_turns, bool):
            model_turns += int(raw_turns)
        for key, value in (item.get("evidence_verifier_usage_totals") or {}).items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                totals[key] = totals.get(key, 0) + value
    return {
        "mode_counts": dict(sorted(mode_counts.items())),
        "outcome_counts": dict(sorted(outcome_counts.items())),
        "model_turns": model_turns,
        "usage_totals": totals,
        "usage_mean": _mean_usage(totals, len(records)),
    }


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


def _artifact_validation_errors(final: Any) -> list[str]:
    """Reject artifacts that could bypass Host/verifier fail-closed rules."""
    if not isinstance(final, dict):
        return ["final_result.json is not an object"]
    errors: list[str] = []
    recorded = final.get("schema_validation_errors")
    if isinstance(recorded, list) and recorded:
        errors.append("artifact records schema_validation_errors")
    errors.extend(validate_final_result_artifact(final))
    if final.get("status") in {"present", "absent", "not_affected"} and final.get("ok") is not True:
        errors.append("determinate artifact requires ok=true")
    return errors


def _existing_case_artifact(case_dir: Path) -> dict[str, Any] | None:
    """Load a completed case artifact, or return None when it is unusable."""
    final_path = case_dir / "final_result.json"
    if not final_path.is_file():
        return None
    try:
        final = load_json(final_path)
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
    """Fingerprint an artifact so a failed retry cannot reuse a stale result."""
    try:
        stat = path.stat()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None
    return stat.st_ino, stat.st_size, stat.st_mtime_ns, digest


def _existing_case_status(case_dir: Path) -> str | None:
    """Return the on-disk ``status`` of a case, or None if it must be re-run.

    None covers: no final_result.json, an unreadable file, a missing/unknown
    ``status`` field. Any of the four verdicts is returned as-is. A subprocess
    timeout writes nothing, so it also surfaces as None -> re-run.
    """
    final = _existing_case_artifact(case_dir)
    return str(final["status"]) if final is not None else None


def _select_resume_cases(
    cases: list[dict[str, Any]],
    out_root: Path,
    args: argparse.Namespace,
    patchspec_keys: dict[str, str] | None = None,
    evidence_verifier_digest: str = "",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    """Split ``cases`` into (to_run, to_reuse) under the resume policy.

    Returns a counts dict for logging: total, completed, inconclusive, retry
    (== len(to_run)), skipped (== len(to_reuse)).
    """
    mode = args.resume
    retry_inc = getattr(args, "retry_inconclusive", False)
    to_run: list[dict[str, Any]] = []
    to_reuse: list[dict[str, Any]] = []
    counts = {
        "total": len(cases),
        "completed": 0,
        "inconclusive": 0,
        "stale_patchspec": 0,
        "stale_evidence_verifier": 0,
        "retry": 0,
        "skipped": 0,
    }

    for case in cases:
        case_dir = safe_case_dir(out_root, case["cve_id"], case["binary_name"])
        artifact = _existing_case_artifact(case_dir)
        status = str(artifact["status"]) if artifact is not None else None
        required_key = (patchspec_keys or {}).get(case["cve_id"], "")
        actual_key = _patch_spec_fields(artifact or {}).get("patch_spec_cache_key", "")
        stale_patchspec = bool(status and required_key and actual_key != required_key)
        requested_verifier_mode = str(getattr(args, "evidence_verifier", "llm"))
        actual_verifier_mode = _evidence_verifier_fields(artifact or {}).get(
            "evidence_verifier_mode", ""
        )
        actual_verifier_digest = _evidence_verifier_fields(artifact or {}).get(
            "evidence_verifier_config_digest", ""
        )
        stale_evidence_verifier = bool(
            status
            and (
                actual_verifier_mode != requested_verifier_mode
                or (
                    requested_verifier_mode == "llm"
                    and evidence_verifier_digest
                    and actual_verifier_digest
                    and actual_verifier_digest != evidence_verifier_digest
                )
            )
        )
        if status is not None:
            counts["completed"] += 1
            if status == "inconclusive":
                counts["inconclusive"] += 1
            if stale_patchspec:
                counts["stale_patchspec"] += 1
            if stale_evidence_verifier:
                counts["stale_evidence_verifier"] += 1

        # auto/error are consistency-preserving resume modes: a completed case
        # from a different PatchSpec fingerprint is not reusable. The explicit
        # inconclusive-only mode retains its narrow selection contract.
        stale = stale_patchspec or stale_evidence_verifier
        policy_status = None if stale and mode in {"auto", "error"} else status

        if mode == "all":
            run_it = True
        elif mode == "inconclusive":
            # Only re-run cases that ARE inconclusive; everything else is reused.
            run_it = status == "inconclusive"
        else:  # auto / error
            # Re-run anything without a completed artifact. inconclusive counts
            # as completed and is skipped, unless --retry-inconclusive opts in.
            if policy_status is None:
                run_it = True
            elif policy_status == "inconclusive":
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


def _case_command(
    case: dict[str, Any],
    args: argparse.Namespace,
    binary_path: Path,
    case_dir: Path,
    patchspec_path: Path,
) -> list[str]:
    """Build the isolated single-case command with an explicit shared PatchSpec."""
    cmd = [
        sys.executable, "-m", "claudeagent.agent_loop",
        "--cve-id", case["cve_id"],
        "--metadata-json", str(expand(args.metadata_json)),
        "--patchspec-json", str(patchspec_path),
        "--binary", str(binary_path),
        "--output-dir", str(case_dir),
        "--max-turns", str(args.max_turns),
        "--finalization-turns", str(args.finalization_turns),
        "--api-timeout", str(args.api_timeout),
        "--api-max-retries", str(args.api_max_retries),
        "--api-turn-retries", str(args.api_turn_retries),
        "--evidence-verifier", str(getattr(args, "evidence_verifier", "llm")),
    ]
    if args.model:
        cmd += ["--model", args.model]
    if args.base_url:
        cmd += ["--base-url", args.base_url]
    if args.model_profile:
        cmd += ["--model-profile", args.model_profile]
    if args.no_strict:
        cmd += ["--no-strict"]
    return cmd


def run_one_case(
    case: dict[str, Any], args: argparse.Namespace, patchspec_path: Path
) -> dict[str, Any]:
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
        "evidence_verifier_config_digest": "",
        "evidence_verifier_model_turns": 0,
        "evidence_verifier_usage_totals": {},
    }
    if not binary_path.is_file():
        record.update({"predicted": "not_found", "ok": False, "error": "binary file missing", "correct": False})
        return record

    cmd = _case_command(case, args, binary_path, case_dir, patchspec_path)

    final_path = case_dir / "final_result.json"
    prior_final_signature = _artifact_signature(final_path)
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

    if not final_path.is_file():
        record.update({"predicted": "error", "ok": False, "error": "no final_result.json produced", "correct": False})
        return record
    if prior_final_signature is not None and _artifact_signature(final_path) == prior_final_signature:
        record.update({
            "predicted": "error",
            "ok": False,
            "error": (
                "case subprocess did not produce a fresh final_result.json; "
                f"ignored stale artifact (returncode={record.get('agent_returncode')})"
            ),
            "correct": False,
        })
        return record
    try:
        final = load_json(final_path)
    except Exception as exc:
        record.update({"predicted": "error", "ok": False, "error": f"unreadable final_result: {exc}", "correct": False})
        return record
    artifact_errors = _artifact_validation_errors(final)
    if artifact_errors:
        record.update({
            "predicted": "error",
            "ok": False,
            "error": "invalid final_result artifact",
            "schema_validation_errors": artifact_errors,
            "correct": False,
        })
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
        **_patch_spec_fields(final),
        **_evidence_verifier_fields(final),
    })
    return record


def _record_patchspec_failure(
    case: dict[str, Any], args: argparse.Namespace, error: str
) -> dict[str, Any]:
    """Create a scored case record when CVE-level PatchSpec preparation failed."""
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
        "inconclusive_reason": "",
        "usage_totals": {},
        "timing": {},
        "model_turns": 0,
        "evidence_verifier_config_digest": "",
        "evidence_verifier_model_turns": 0,
        "evidence_verifier_usage_totals": {},
        "correct": False,
        "ok": False,
    }
    if not binary_path.is_file():
        record.update({"predicted": "not_found", "error": "binary file missing"})
    else:
        record.update({"predicted": "error", "error": f"PatchSpec preparation failed: {error}"})
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
        "evidence_verifier_config_digest": "",
        "evidence_verifier_model_turns": 0,
        "evidence_verifier_usage_totals": {},
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
    artifact_errors = _artifact_validation_errors(final)
    if artifact_errors:
        record.update({
            "predicted": "error",
            "ok": False,
            "error": "invalid reused final_result artifact",
            "schema_validation_errors": artifact_errors,
            "correct": False,
        })
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
        **_patch_spec_fields(final),
        **_evidence_verifier_fields(final),
    })
    return record


def aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    outcomes = list(VERDICTS) + ["not_found", "timeout", "error"]
    confusion = {exp: {pred: 0 for pred in outcomes} for exp in VERDICTS}
    correct = 0
    scored = 0
    repair_totals = {
        "schema_repair_attempts": 0,
        "no_evidence_verdicts": 0,
        "tool_failures": 0,
        "command_failures": 0,
        "evidence_verifier_calls": 0,
        "evidence_verifier_accepts": 0,
        "evidence_verifier_rejections": 0,
        "evidence_verifier_repairs": 0,
        "evidence_verifier_failures": 0,
    }
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
    cache_dir = out_root / "_patchspec"

    # Validate the config/profile before launching any subprocess, so a typo in
    # --model-profile or a malformed model_config.json fails fast with a clear
    # message instead of N failing worker cases.
    try:
        profile = resolve_profile(args)
    except ValueError as exc:
        raise SystemExit(f"model config error: {exc}")
    try:
        metadata_by_cve = load_metadata_index(args.metadata_json)
    except Exception as exc:
        raise SystemExit(f"metadata error: {exc}") from exc

    selected_cves = {case["cve_id"] for case in cases}
    key_config = build_patchspec_config(args, profile, api_key="")
    patchspec_keys = required_patchspec_keys(metadata_by_cve, selected_cves, key_config)
    missing_metadata = sorted(selected_cves - set(patchspec_keys))
    if missing_metadata:
        raise SystemExit(f"metadata missing for selected CVE(s): {missing_metadata}")
    verifier_digest = requested_evidence_verifier_digest(args, profile)

    # Resume selection is PatchSpec-aware under auto/error: completed results
    # produced with a different metadata/prompt/model fingerprint are stale.
    to_run, to_reuse, counts = _select_resume_cases(
        cases,
        out_root,
        args,
        patchspec_keys=patchspec_keys,
        evidence_verifier_digest=verifier_digest,
    )
    patchspec_cves = {case["cve_id"] for case in to_run}

    if args.dry_run:
        missing = [c for c in cases if not resolve_binary(args.binaries_root, args.variant, c["binary_name"], args.compiler, args.opt).is_file()]
        patchspec_results, patchspec_failures, patchspec_wall = prepare_patch_specs(
            metadata_by_cve,
            patchspec_cves,
            config=key_config,
            cache_dir=cache_dir,
            dry_run=True,
            max_workers=args.max_workers,
        )
        manifest = {
            cve_id: patchspec_manifest_entry(result, cache_dir=cache_dir, cve_id=cve_id)
            for cve_id, result in sorted(patchspec_results.items())
        }
        print("BATCH_DRY_RUN")
        print("groundtruth:", args.groundtruth)
        print("binaries_root:", str(expand(args.binaries_root) / args.variant))
        print("metadata:", args.metadata_json)
        print("total_cases:", len(cases))
        print("by_expected:", {v: sum(1 for c in cases if c["expected"] == v) for v in VERDICTS})
        print("resume_mode:", args.resume, "retry_inconclusive:", getattr(args, "retry_inconclusive", False))
        print("evidence_verifier:", args.evidence_verifier)
        print("resume_counts:", counts)
        print("patchspec_cves:", len(patchspec_cves))
        print("patchspec_metrics:", patchspec_batch_metrics(patchspec_results, patchspec_failures, patchspec_wall))
        for cve_id, entry in manifest.items():
            print(
                "  PATCHSPEC",
                cve_id,
                f"mode={entry['generation_mode']}",
                f"digest={entry['digest']}",
                f"path={entry['path']}",
            )
        for cve_id, error in sorted(patchspec_failures.items()):
            print("  PATCHSPEC_ERROR", cve_id, error)
        print("missing_binaries:", len(missing))
        for c in missing[:10]:
            print("  MISSING", c["cve_id"], c["binary_name"])
        return 1 if patchspec_failures else 0

    out_root.mkdir(parents=True, exist_ok=True)
    key_env = bootstrap_api_key(args)
    api_key = resolve_api_key(profile)
    if not key_env:
        profile_name = args.model_profile or "active"
        print(
            f"WARNING: could not resolve/import the API-key env var for profile "
            f"{profile_name!r}; subprocesses may fail to authenticate. "
            f"Set it in your shell or use --model-profile with a profile whose key is available.",
            file=sys.stderr,
        )

    started = time.time()
    generation_config = build_patchspec_config(args, profile, api_key=api_key)
    patchspec_results, patchspec_failures, patchspec_wall = prepare_patch_specs(
        metadata_by_cve,
        patchspec_cves,
        config=generation_config,
        cache_dir=cache_dir,
        dry_run=False,
        max_workers=args.max_workers,
    )
    patchspec_paths: dict[str, Path] = {}
    for cve_id, result in list(patchspec_results.items()):
        path = Path(result.path).expanduser() if result.path else None
        if path is None or not path.is_file():
            patchspec_failures[cve_id] = "ensure_patch_spec returned no persisted artifact"
            del patchspec_results[cve_id]
            continue
        patchspec_paths[cve_id] = path

    patchspec_manifest = {
        cve_id: patchspec_manifest_entry(result, cache_dir=cache_dir, cve_id=cve_id)
        for cve_id, result in sorted(patchspec_results.items())
    }
    # A full/partial resume may not resolve a spec in this process at all. Keep
    # the fingerprint used by reused case artifacts in the run manifest, while
    # charging zero current-run PatchSpec usage.
    for case in to_reuse:
        cve_id = case["cve_id"]
        if cve_id in patchspec_manifest:
            continue
        artifact = _existing_case_artifact(
            safe_case_dir(out_root, cve_id, case["binary_name"])
        )
        fields = _patch_spec_fields(artifact or {})
        cache_key = str(fields.get("patch_spec_cache_key", "") or "")
        path = ""
        if re.fullmatch(r"[0-9a-f]{64}", cache_key):
            path = str(patch_spec_cache_path(cache_dir, cve_id, cache_key))
        patchspec_manifest[cve_id] = {
            "path": path,
            "digest": str(fields.get("patch_spec_digest", "") or ""),
            "cache_key": cache_key,
            "generation_mode": str(fields.get("patch_spec_generation_mode", "") or "unknown"),
            "resolution_mode": "reused",
            "cache_hit": False,
            "usage": {},
        }
    for cve_id, error in sorted(patchspec_failures.items()):
        patchspec_manifest[cve_id] = {
            "path": "",
            "digest": "",
            "cache_key": patchspec_keys.get(cve_id, ""),
            "generation_mode": "error",
            "resolution_mode": "error",
            "cache_hit": False,
            "usage": {},
            "error": error,
        }
    patchspec_metrics = patchspec_batch_metrics(
        patchspec_results, patchspec_failures, patchspec_wall
    )
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "manifest.json").write_text(
        jdump({"patchspec": patchspec_manifest, "metrics": patchspec_metrics}) + "\n",
        encoding="utf-8",
    )
    print(
        f"patchspec_cves={patchspec_metrics['cves']} "
        f"modes={patchspec_metrics['generation_counts']} "
        f"failures={patchspec_metrics['failed_cves']} "
        f"wall_seconds={patchspec_metrics['wall_seconds']}",
        file=sys.stderr,
    )
    for cve_id, error in sorted(patchspec_failures.items()):
        print(f"PATCHSPEC_ERROR {cve_id}: {error}", file=sys.stderr)

    print(
        f"resume={args.resume} retry_inconclusive={getattr(args, 'retry_inconclusive', False)} "
        f"total={counts['total']} retry={counts['retry']} skipped={counts['skipped']} "
        f"(completed={counts['completed']} inconclusive={counts['inconclusive']} "
        f"stale_patchspec={counts['stale_patchspec']} "
        f"stale_evidence_verifier={counts['stale_evidence_verifier']})",
        file=sys.stderr,
    )
    records: list[dict[str, Any]] = [
        _record_from_artifact(case, safe_case_dir(out_root, case["cve_id"], case["binary_name"]))
        for case in to_reuse
    ]
    runnable: list[dict[str, Any]] = []
    for case in to_run:
        error = patchspec_failures.get(case["cve_id"])
        if error:
            records.append(_record_patchspec_failure(case, args, error))
        else:
            runnable.append(case)

    with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as pool:
        futures = {
            pool.submit(run_one_case, case, args, patchspec_paths[case["cve_id"]]): case
            for case in runnable
        }
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
    metrics["patchspec_metrics"] = patchspec_metrics
    metrics["evidence_verifier_metrics"] = evidence_verifier_batch_metrics(records)
    (out_root / "batch_metrics.json").write_text(jdump(metrics) + "\n", encoding="utf-8")
    by_cve: dict[str, list[dict[str, Any]]] = {}
    for rec in records:
        by_cve.setdefault(rec["cve_id"], []).append(rec)
    (out_root / "batch_results.json").write_text(
        jdump({"results": records, "by_cve": by_cve, "patchspec": patchspec_manifest}) + "\n",
        encoding="utf-8",
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
    parser.add_argument(
        "--evidence-verifier",
        default="llm",
        choices=["llm", "off"],
        help="single-case independent evidence verifier mode (default: llm)",
    )
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
