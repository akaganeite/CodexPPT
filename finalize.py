"""Final verdict validation, repair payloads, and artifact writing.

Validation combines JSON schema, ledger citations, behavior-scoped support
references, evidence polarity, determinate/inconclusive consistency, and a
version/path-string rejection. Schema/gate failures are returned to the model as
a repair payload (never raised), so the loop can fix the verdict instead of
crashing.
"""

from __future__ import annotations

import re
import time
from typing import Any

from claudeagent.common import jdump, write_artifact
from claudeagent.decision import validate_support_records
from claudeagent.runtime import AGENT_CONTEXT, bump_metric, evidence_ids_in_ledger, harness_metrics
from claudeagent.schema_validate import (
    DETERMINATE_STATUSES,
    INCONCLUSIVE_REASONS,
    final_tool_parameters_schema,
    load_final_result_schema,
    validate_json_schema,
)


# Determinate verdicts must rely on binary semantics, not version/release/path labels.
VERSION_EVIDENCE_RE = re.compile(
    r"\b[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9_.]+)?\b|"
    r"\bpre-?[0-9]+\.[0-9]+\.[0-9]+|"
    r"\bbefore\s+[0-9]+\.[0-9]+\.[0-9]+|"
    r"\bfixed\s+in\s+[0-9]+\.[0-9]+\.[0-9]+|"
    r"/home/|/media/|/extdisk/|file path|target filename|target file name|"
    r"binary filename|binary file name|directory name|binary name|"
    r"naming convention|path contains|path indicates",
    re.IGNORECASE,
)


def validate_final_tool_args(candidate: dict[str, Any]) -> list[str]:
    errors = validate_json_schema(candidate, final_tool_parameters_schema())
    status = str(candidate.get("status", ""))
    evidence_ids = candidate.get("evidence_ids")
    if not isinstance(evidence_ids, list):
        evidence_ids = []

    unknown_ids = sorted(set(str(item) for item in evidence_ids) - evidence_ids_in_ledger())
    if unknown_ids:
        errors.append(f"$.evidence_ids: unknown evidence id(s) not in the ledger: {unknown_ids}")
    if status in DETERMINATE_STATUSES and not evidence_ids:
        errors.append(f"$.evidence_ids: {status} verdicts must cite at least one evidence id from the ledger")
    errors.extend(validate_support_records(
        candidate.get("supports"),
        status=status,
        evidence_ids=evidence_ids,
        behavior_contract=AGENT_CONTEXT.get("patch_spec_behavior_contract", []),
        evidence_ledger=AGENT_CONTEXT.get("evidence_ledger", []),
    ))

    reason = candidate.get("inconclusive_reason")
    if reason not in INCONCLUSIVE_REASONS:
        errors.append(f"$.inconclusive_reason: expected one of {sorted(INCONCLUSIVE_REASONS)}")
    if status == "inconclusive" and reason in {"", "none", None}:
        errors.append("$.inconclusive_reason: inconclusive verdicts must name a concrete reason")
    if status != "inconclusive" and reason not in {"", "none", None}:
        errors.append("$.inconclusive_reason: determinate verdicts should use 'none'")

    if status in DETERMINATE_STATUSES:
        evidence = candidate.get("evidence") if isinstance(candidate.get("evidence"), list) else []
        supports = candidate.get("supports") if isinstance(candidate.get("supports"), list) else []
        support_summaries = [
            str(item.get("summary", "")) for item in supports if isinstance(item, dict)
        ]
        verdict_text = "\n".join([
            *(str(item) for item in evidence),
            *support_summaries,
            str(candidate.get("reasoning", "")),
        ])
        if VERSION_EVIDENCE_RE.search(verdict_text):
            errors.append(
                "$.supports/evidence/reasoning: determinate verdict appears to rely on version strings, "
                "filenames, paths, or release labels instead of semantic binary evidence"
            )
    return errors


def compact_known_evidence_ids() -> dict[str, Any]:
    ids = sorted(evidence_ids_in_ledger())
    return {"count": len(ids), "head": ids[:12], "tail": ids[-12:] if len(ids) > 12 else []}


def compact_rejected_tool_args(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": candidate.get("status"),
        "confidence": candidate.get("confidence"),
        "supports": candidate.get("supports", []),
        "evidence_ids": candidate.get("evidence_ids", []),
        "decisive_addresses": candidate.get("decisive_addresses", []),
        "inconclusive_reason": candidate.get("inconclusive_reason", ""),
    }


def submit_detection_result(
    status: str,
    confidence: str,
    supports: list[dict[str, Any]],
    evidence: list[str],
    evidence_ids: list[str],
    reasoning: str,
    decisive_addresses: list[str],
    inconclusive_reason: str,
) -> dict[str, Any]:
    candidate = {
        "status": status,
        "confidence": confidence,
        "supports": supports,
        "evidence": evidence,
        "evidence_ids": evidence_ids,
        "reasoning": reasoning,
        "decisive_addresses": decisive_addresses,
        "inconclusive_reason": inconclusive_reason,
    }
    validation_errors = validate_final_tool_args(candidate)
    if validation_errors:
        bump_metric("schema_repair_attempts")
        if status in DETERMINATE_STATUSES and not evidence_ids:
            bump_metric("no_evidence_verdicts")
        return {
            "ok": False,
            "error": "submit_detection_result arguments failed schema/evidence validation; repair and call again",
            "schema_errors": validation_errors,
            "known_evidence_ids": compact_known_evidence_ids(),
            "rejected_candidate": compact_rejected_tool_args(candidate),
            "repair_instruction": (
                "Repair the rejected tool arguments; do not restart the investigation. Keep the same "
                "status if the cited evidence_ids still support it. Cite only evidence_ids returned by "
                "previous tool calls. Each support must use a real PatchSpec behavior_id and at least "
                "one real evidence id; top-level evidence_ids must exactly equal the support evidence "
                "union. Pure no-match evidence can only support observed_side=ambiguous. "
                "present/absent/not_affected require at least one support. If "
                "the only problem is wording, remove version numbers, release ranges, filenames, and "
                "paths from evidence/reasoning and restate the verdict using local binary semantics "
                "(disassembly, symbols, strings, imports, constants, offsets, control flow). Downgrade "
                "to inconclusive with a concrete reason only when ledger evidence is genuinely "
                "insufficient."
            ),
        }
    metadata = AGENT_CONTEXT["metadata"]
    return {
        "ok": True,
        "project": metadata.get("project", "curl"),
        "cve_id": metadata.get("cve_id", AGENT_CONTEXT.get("cve_id", "")),
        "binary": AGENT_CONTEXT["binary_path"],
        "status": status,
        "confidence": confidence,
        "supports": supports,
        "evidence": evidence,
        "evidence_ids": evidence_ids,
        "reasoning": reasoning,
        "decisive_addresses": decisive_addresses,
        "inconclusive_reason": inconclusive_reason,
        "completed_at_epoch": time.time(),
    }


def flatten_numeric_usage(obj: Any, prefix: str = "") -> dict[str, int | float]:
    flat: dict[str, int | float] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            flat.update(flatten_numeric_usage(value, child))
    elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
        flat[prefix] = obj
    return flat


def aggregate_usage(transcript: list[dict[str, Any]]) -> dict[str, Any]:
    totals: dict[str, int | float] = {}
    by_turn: list[dict[str, Any]] = []
    for entry in transcript:
        usage = entry.get("usage")
        if not isinstance(usage, dict):
            continue
        flat = flatten_numeric_usage(usage)
        for key, value in flat.items():
            totals[key] = totals.get(key, 0) + value
        by_turn.append({"turn": entry.get("turn"), "usage": usage})
    return {"provider": "openai-responses", "model_turns": len(by_turn), "totals": totals, "by_turn": by_turn}


def validate_final_result_artifact(result: dict[str, Any]) -> list[str]:
    errors = validate_json_schema(result, load_final_result_schema())
    status = str(result.get("status", ""))
    evidence_ids = result.get("evidence_ids") if isinstance(result.get("evidence_ids"), list) else []
    ledger_ids = {
        str(item.get("evidence_id"))
        for item in result.get("evidence_ledger", [])
        if isinstance(item, dict) and item.get("evidence_id")
    }
    unknown_ids = sorted(set(str(item) for item in evidence_ids) - ledger_ids)
    if unknown_ids:
        errors.append(f"$.evidence_ids: unknown evidence id(s) in artifact ledger: {unknown_ids}")
    if status in DETERMINATE_STATUSES and not evidence_ids:
        errors.append(f"$.evidence_ids: {status} artifact must cite at least one evidence id")
    errors.extend(validate_support_records(
        result.get("supports"),
        status=status,
        evidence_ids=evidence_ids,
        behavior_contract=(result.get("patch_spec") or {}).get("behavior_contract", []),
        evidence_ledger=result.get("evidence_ledger", []),
    ))
    if status == "inconclusive" and result.get("inconclusive_reason") in {"", "none", None}:
        errors.append("$.inconclusive_reason: inconclusive artifact must name a concrete reason")
    return errors


def build_final_artifact(result: dict[str, Any], transcript: list[dict[str, Any]], start_epoch: float) -> tuple[dict[str, Any], list[str]]:
    timing = {"wall_seconds": round(time.time() - start_epoch, 3)}
    usage = aggregate_usage(transcript)
    usage["timing"] = timing
    patch_spec_info = AGENT_CONTEXT.get("patch_spec_info", {})
    if not isinstance(patch_spec_info, dict):
        patch_spec_info = {}
    patch_spec_usage = patch_spec_info.get("usage")
    usage["patch_spec_generation"] = patch_spec_usage if isinstance(patch_spec_usage, dict) else {}
    out = dict(result)
    out["timing"] = timing
    out["usage_metrics"] = usage
    out["observations"] = AGENT_CONTEXT.get("observations", [])
    out["evidence_ledger"] = AGENT_CONTEXT.get("evidence_ledger", [])
    out["harness_metrics"] = harness_metrics()
    out["patch_spec"] = {
        "digest": str(patch_spec_info.get("digest", "")),
        "generation_mode": str(patch_spec_info.get("generation_mode", "not_generated")),
        "resolution_mode": str(patch_spec_info.get("resolution_mode", "not_resolved")),
        "cache_key": str(patch_spec_info.get("cache_key", "")),
        "cache_hit": bool(patch_spec_info.get("cache_hit", False)),
        "behavior_contract": [
            dict(item)
            for item in AGENT_CONTEXT.get("patch_spec_behavior_contract", [])
            if isinstance(item, dict)
        ],
    }
    return out, validate_final_result_artifact(out)


def write_run_outputs(output_dir: str, result: dict[str, Any], transcript: list[dict[str, Any]], start_epoch: float) -> dict[str, Any]:
    out, schema_errors = build_final_artifact(result, transcript, start_epoch)
    if schema_errors:
        out["ok"] = False
        out["schema_validation_errors"] = schema_errors
    write_artifact(output_dir, "final_result.json", jdump(out) + "\n")
    write_artifact(output_dir, "transcript.json", jdump(transcript) + "\n")
    write_artifact(output_dir, "usage_metrics.json", jdump(out["usage_metrics"]) + "\n")
    return out


def compact_rejected_preview(preview: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": preview.get("status"),
        "confidence": preview.get("confidence"),
        "supports": preview.get("supports", []),
        "evidence_ids": preview.get("evidence_ids", []),
        "inconclusive_reason": preview.get("inconclusive_reason", ""),
        "observation_count": len(preview.get("observations", [])) if isinstance(preview.get("observations"), list) else 0,
        "evidence_ledger_ids": [
            item.get("evidence_id")
            for item in preview.get("evidence_ledger", [])
            if isinstance(item, dict) and item.get("evidence_id")
        ],
        "harness_metrics": preview.get("harness_metrics", {}),
    }


def preflight_missing_result(metadata: dict[str, Any], binary: str, preflight: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": False,
        "project": metadata.get("project", "curl"),
        "cve_id": metadata.get("cve_id", AGENT_CONTEXT.get("cve_id", "")),
        "binary": binary,
        "status": "inconclusive",
        "confidence": "low",
        "supports": [],
        "evidence": [],
        "evidence_ids": [],
        "reasoning": f"host preflight failed: {jdump(preflight)}",
        "decisive_addresses": [],
        "inconclusive_reason": "unsupported_binary",
        "preflight": preflight,
        "completed_at_epoch": time.time(),
    }


def max_turns_fallback_result(metadata: dict[str, Any], binary: str, max_turns: int) -> dict[str, Any]:
    return {
        "ok": True,
        "project": metadata.get("project", "curl"),
        "cve_id": metadata.get("cve_id", AGENT_CONTEXT.get("cve_id", "")),
        "binary": binary,
        "status": "inconclusive",
        "confidence": "low",
        "supports": [],
        "evidence": [],
        "evidence_ids": [],
        "reasoning": (
            f"Model did not submit a compliant detection result within {max_turns} evidence turns "
            "and finalization did not produce a valid verdict."
        ),
        "decisive_addresses": [],
        "inconclusive_reason": "insufficient_tool_budget",
        "completed_at_epoch": time.time(),
    }


def api_failure_fallback_result(metadata: dict[str, Any], binary: str, error: str) -> dict[str, Any]:
    """Inconclusive result written when the model API is unreachable after all
    retries. The run still produces a valid artifact (so a batch can score it)
    rather than dying empty-handed."""
    return {
        "ok": False,
        "project": metadata.get("project", "curl"),
        "cve_id": metadata.get("cve_id", AGENT_CONTEXT.get("cve_id", "")),
        "binary": binary,
        "status": "inconclusive",
        "confidence": "low",
        "supports": [],
        "evidence": [],
        "evidence_ids": [],
        "reasoning": f"Model API failed after all retries; no verdict could be sampled. Error: {error}",
        "decisive_addresses": [],
        "inconclusive_reason": "tool_failure",
        "completed_at_epoch": time.time(),
    }
