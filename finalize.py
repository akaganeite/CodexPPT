"""Direct evidence-cited finalization and artifact writing."""

from __future__ import annotations

import re
import time
from typing import Any

from claudeagent.common import jdump, write_artifact
from claudeagent.runtime import AGENT_CONTEXT, bump_metric, harness_metrics
from claudeagent.schema_validate import (
    DETERMINATE_STATUSES,
    INCONCLUSIVE_REASONS,
    final_tool_parameters_schema,
    load_final_result_schema,
    validate_json_schema,
)
from claudeagent.truncation import text_head_tail


FINAL_SCHEMA_VERSION = "final_result.v6"
_UNSET = object()

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


def _bounded_fallback_summary(value: Any) -> str:
    """Keep Host-generated fallback reasoning within the artifact schema limit."""
    text = str(value or "")
    if len(text) <= 3800:
        return text
    parts = text_head_tail(text, 3500)
    return f"{parts['head']}\n... {parts['omitted_chars']} chars omitted ...\n{parts['tail']}"[:3800]


def _ledger_by_id(evidence_ledger: Any) -> dict[str, dict[str, Any]]:
    items = evidence_ledger if isinstance(evidence_ledger, list) else []
    return {
        str(item.get("evidence_id")): item
        for item in items
        if isinstance(item, dict) and item.get("evidence_id")
    }


def resolve_final_tool_args(
    candidate: dict[str, Any],
    *,
    evidence_ledger: Any,
) -> tuple[dict[str, Any], list[str]]:
    """Validate one direct verdict and derive its canonical evidence projection."""
    errors = validate_json_schema(candidate, final_tool_parameters_schema())
    status = str(candidate.get("status", ""))
    raw_ids = candidate.get("evidence_ids")
    evidence_ids = [str(value) for value in raw_ids] if isinstance(raw_ids, list) else []
    if len(evidence_ids) != len(set(evidence_ids)):
        errors.append("$.evidence_ids: duplicate evidence ids are not allowed")

    ledger_by_id = _ledger_by_id(evidence_ledger)
    unknown_ids = sorted(set(evidence_ids) - set(ledger_by_id))
    if unknown_ids:
        errors.append(f"$.evidence_ids: unknown evidence id(s) not in the ledger: {unknown_ids}")
    cited = [ledger_by_id[item] for item in evidence_ids if item in ledger_by_id]
    pending_ids = [
        str(item.get("evidence_id", ""))
        for item in cited
        if str(item.get("claim_status", "pending")) != "summarized"
    ]
    if pending_ids:
        errors.append(
            "$.evidence_ids: cited evidence must be summarized with summarize_evidence "
            f"before finalization; pending id(s): {pending_ids}"
        )
    if status in DETERMINATE_STATUSES and not evidence_ids:
        errors.append(f"$.evidence_ids: {status} verdicts require cited target-binary evidence")
    invalid_polarity_ids = [
        str(item.get("evidence_id", ""))
        for item in cited
        if item.get("polarity") not in {"positive", "negative"}
    ]
    if invalid_polarity_ids:
        errors.append(
            "$.evidence_ids: cited evidence has invalid Host-recorded polarity: "
            f"{invalid_polarity_ids}"
        )
    if status in DETERMINATE_STATUSES and cited and all(
        str(item.get("polarity", "positive")) == "negative" for item in cited
    ):
        errors.append(
            "$.evidence_ids: determinate verdicts require positive target-binary evidence; "
            "pure no-match/anchor-miss evidence is insufficient"
        )

    reason = candidate.get("inconclusive_reason")
    if reason not in INCONCLUSIVE_REASONS:
        errors.append(f"$.inconclusive_reason: expected one of {sorted(INCONCLUSIVE_REASONS)}")
    if status == "inconclusive" and reason in {"", "none", None}:
        errors.append("$.inconclusive_reason: inconclusive verdicts must name a concrete reason")
    if status != "inconclusive" and reason not in {"", "none", None}:
        errors.append("$.inconclusive_reason: determinate verdicts should use 'none'")

    reasoning = str(candidate.get("reasoning", ""))
    if status in DETERMINATE_STATUSES:
        verdict_text = "\n".join([*(str(item.get("claim", "")) for item in cited), reasoning])
        if VERSION_EVIDENCE_RE.search(verdict_text):
            errors.append(
                "$.reasoning/evidence_ids: determinate verdict appears to rely on version "
                "strings, filenames, paths, or release labels instead of semantic binary evidence"
            )

    canonical = {
        "schema_version": FINAL_SCHEMA_VERSION,
        "status": status,
        "confidence": candidate.get("confidence"),
        "evidence": [str(item.get("claim", "")) for item in cited],
        "evidence_ids": evidence_ids,
        "reasoning": reasoning,
        "decisive_addresses": (
            [str(value) for value in candidate.get("decisive_addresses", [])]
            if isinstance(candidate.get("decisive_addresses"), list)
            else []
        ),
        "inconclusive_reason": reason,
    }
    return canonical, errors


def compact_known_evidence_ids() -> dict[str, Any]:
    ledger = [
        item
        for item in AGENT_CONTEXT.get("evidence_ledger", [])
        if isinstance(item, dict) and item.get("evidence_id")
    ]
    ids = sorted(str(item["evidence_id"]) for item in ledger)
    summarized = sorted(
        str(item["evidence_id"])
        for item in ledger
        if item.get("claim_status") == "summarized"
    )
    return {
        "count": len(ids),
        "head": ids[:12],
        "tail": ids[-12:] if len(ids) > 12 else [],
        "summarized": summarized[:24],
        "pending": sorted(set(ids) - set(summarized))[:24],
    }


def compact_rejected_tool_args(candidate: dict[str, Any]) -> dict[str, Any]:
    """Return only the direct final-tool fields in a repair response."""
    fields = (
        "status",
        "confidence",
        "evidence_ids",
        "reasoning",
        "decisive_addresses",
        "inconclusive_reason",
    )
    return {field: candidate.get(field) for field in fields if field in candidate}


def submit_detection_result(
    status: str,
    confidence: str,
    evidence_ids: Any = _UNSET,
    reasoning: Any = _UNSET,
    decisive_addresses: Any = _UNSET,
    inconclusive_reason: Any = _UNSET,
    **extra: Any,
) -> dict[str, Any]:
    """Validate the investigator's direct verdict without inventing evidence."""
    candidate: dict[str, Any] = {"status": status, "confidence": confidence, **extra}
    if evidence_ids is not _UNSET:
        candidate["evidence_ids"] = evidence_ids
    if reasoning is not _UNSET:
        candidate["reasoning"] = reasoning
    if decisive_addresses is not _UNSET:
        candidate["decisive_addresses"] = decisive_addresses
    if inconclusive_reason is not _UNSET:
        candidate["inconclusive_reason"] = inconclusive_reason

    canonical, validation_errors = resolve_final_tool_args(
        candidate,
        evidence_ledger=AGENT_CONTEXT.get("evidence_ledger", []),
    )
    if validation_errors:
        bump_metric("schema_repair_attempts")
        cited_ids = candidate.get("evidence_ids", [])
        if status in DETERMINATE_STATUSES and not cited_ids:
            bump_metric("no_evidence_verdicts")
        return {
            "ok": False,
            "error": "submit_detection_result arguments failed schema/evidence validation; repair and call again",
            "schema_errors": validation_errors,
            "known_evidence_ids": compact_known_evidence_ids(),
            "rejected_candidate": compact_rejected_tool_args(candidate),
            "repair_instruction": (
                "Repair the rejected direct verdict without restarting the investigation. Cite only "
                "real ledger evidence_ids and summarize every cited pending item first. Determinate "
                "statuses require positive target-binary evidence; an anchor miss alone is not enough. "
                "Remove versions, paths, filenames, release chronology, and unsupported interpretations "
                "from reasoning. Use inconclusive only when the binary evidence is genuinely unresolved."
            ),
        }
    metadata = AGENT_CONTEXT["metadata"]
    return {
        "ok": True,
        "project": metadata.get("project", "curl"),
        "cve_id": metadata.get("cve_id", AGENT_CONTEXT.get("cve_id", "")),
        "binary": AGENT_CONTEXT["binary_path"],
        **canonical,
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
    return {
        "provider": "openai-responses",
        "model_turns": len(by_turn),
        "totals": totals,
        "by_turn": by_turn,
    }


def _validate_ledger_provenance(
    result: dict[str, Any],
    errors: list[str],
) -> None:
    observations = result.get("observations")
    observation_by_id: dict[str, dict[str, Any]] = {}
    if isinstance(observations, list):
        observation_ids = [
            str(item.get("observation_id"))
            for item in observations
            if isinstance(item, dict) and item.get("observation_id")
        ]
        if len(observation_ids) != len(set(observation_ids)):
            errors.append("$.observations: duplicate observation_id values are not allowed")
        observation_by_id = {
            str(item["observation_id"]): item
            for item in observations
            if isinstance(item, dict) and item.get("observation_id")
        }

    cited_ids = {str(value) for value in result.get("evidence_ids", []) if isinstance(value, str)}
    determinate = str(result.get("status", "")) in DETERMINATE_STATUSES
    ledger = result.get("evidence_ledger")
    if not isinstance(ledger, list):
        return
    evidence_ids = [
        str(item.get("evidence_id"))
        for item in ledger
        if isinstance(item, dict) and item.get("evidence_id")
    ]
    if len(evidence_ids) != len(set(evidence_ids)):
        errors.append("$.evidence_ledger: duplicate evidence_id values are not allowed")

    for index, evidence in enumerate(ledger):
        if not isinstance(evidence, dict):
            continue
        prefix = f"$.evidence_ledger[{index}]"
        observation_id = str(evidence.get("observation_id", ""))
        observation = observation_by_id.get(observation_id)
        if observation is None:
            errors.append(f"{prefix}.observation_id: unknown observation id {observation_id!r}")
        elif determinate and str(evidence.get("evidence_id", "")) in cited_ids:
            if observation.get("tool") != "run_python":
                errors.append(f"{prefix}.observation_id: determinate evidence must come from run_python")
            if observation.get("ok") is not True or observation.get("exit_code") != 0:
                errors.append(
                    f"{prefix}.observation_id: determinate evidence must come from a successful observation"
                )

        status = evidence.get("claim_status")
        source = evidence.get("claim_source")
        revision = evidence.get("claim_revision")
        created_at = evidence.get("created_response_index")
        returned_at = evidence.get("returned_response_index")
        updated_at = evidence.get("claim_updated_response_index")
        if (
            isinstance(created_at, int)
            and not isinstance(created_at, bool)
            and isinstance(returned_at, int)
            and not isinstance(returned_at, bool)
            and returned_at < created_at
        ):
            errors.append(f"{prefix}.returned_response_index: evidence cannot be returned before it was created")
        if status == "pending":
            if source != "host" or revision != 0 or evidence.get("claim") != evidence.get("host_claim"):
                errors.append(f"{prefix}: pending evidence must retain the Host claim/source at revision 0")
            if updated_at is not None:
                errors.append(f"{prefix}.claim_updated_response_index: pending evidence cannot record a claim update")
        elif status == "summarized":
            if source != "main_agent" or not isinstance(revision, int) or revision < 1:
                errors.append(f"{prefix}: summarized evidence requires main_agent source and revision >= 1")
            if (
                not isinstance(returned_at, int)
                or isinstance(returned_at, bool)
                or not isinstance(updated_at, int)
                or isinstance(updated_at, bool)
                or updated_at <= returned_at
            ):
                errors.append(f"{prefix}: summarized evidence must be updated after it was returned")


def validate_final_result_artifact(result: dict[str, Any]) -> list[str]:
    """Validate serialized artifacts against schema and ledger provenance."""
    errors = validate_json_schema(result, load_final_result_schema())
    _validate_ledger_provenance(result, errors)
    candidate = {
        "status": result.get("status"),
        "confidence": result.get("confidence"),
        "evidence_ids": result.get("evidence_ids"),
        "reasoning": result.get("reasoning"),
        "decisive_addresses": result.get("decisive_addresses"),
        "inconclusive_reason": result.get("inconclusive_reason"),
    }
    canonical, decision_errors = resolve_final_tool_args(
        candidate,
        evidence_ledger=result.get("evidence_ledger", []),
    )
    errors.extend(decision_errors)
    for field in (
        "schema_version",
        "status",
        "confidence",
        "evidence",
        "evidence_ids",
        "reasoning",
        "decisive_addresses",
        "inconclusive_reason",
    ):
        if result.get(field) != canonical.get(field):
            errors.append(f"$.{field}: artifact value diverges from Host-derived canonical projection")
    return errors


def build_final_artifact(
    result: dict[str, Any],
    transcript: list[dict[str, Any]],
    start_epoch: float,
) -> tuple[dict[str, Any], list[str]]:
    timing = {"wall_seconds": round(time.time() - start_epoch, 3)}
    usage = aggregate_usage(transcript)
    usage["timing"] = timing
    out = dict(result)
    out["timing"] = timing
    out["usage_metrics"] = usage
    out["metadata_sha256"] = str(AGENT_CONTEXT.get("metadata_sha256", ""))
    out["observations"] = AGENT_CONTEXT.get("observations", [])
    out["evidence_ledger"] = AGENT_CONTEXT.get("evidence_ledger", [])
    out["harness_metrics"] = harness_metrics()
    return out, validate_final_result_artifact(out)


def write_run_outputs(
    output_dir: str,
    result: dict[str, Any],
    transcript: list[dict[str, Any]],
    start_epoch: float,
) -> dict[str, Any]:
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


def _fallback_result(
    metadata: dict[str, Any],
    binary: str,
    *,
    ok: bool,
    summary: str,
    inconclusive_reason: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "ok": ok,
        "project": metadata.get("project", "curl"),
        "cve_id": metadata.get("cve_id", AGENT_CONTEXT.get("cve_id", "")),
        "binary": binary,
        "schema_version": FINAL_SCHEMA_VERSION,
        "status": "inconclusive",
        "confidence": "low",
        "evidence": [],
        "evidence_ids": [],
        "reasoning": _bounded_fallback_summary(summary),
        "decisive_addresses": [],
        "inconclusive_reason": inconclusive_reason,
        "completed_at_epoch": time.time(),
        **(extra or {}),
    }


def preflight_missing_result(metadata: dict[str, Any], binary: str, preflight: dict[str, Any]) -> dict[str, Any]:
    return _fallback_result(
        metadata,
        binary,
        ok=False,
        summary=f"host preflight failed: {jdump(preflight)}",
        inconclusive_reason="unsupported_binary",
        extra={"preflight": preflight},
    )


def max_turns_fallback_result(metadata: dict[str, Any], binary: str, max_turns: int) -> dict[str, Any]:
    return _fallback_result(
        metadata,
        binary,
        ok=True,
        summary=(
            f"Model did not submit a compliant detection result within {max_turns} evidence turns "
            "and finalization did not produce a valid verdict."
        ),
        inconclusive_reason="insufficient_tool_budget",
    )


def api_failure_fallback_result(metadata: dict[str, Any], binary: str, error: str) -> dict[str, Any]:
    return _fallback_result(
        metadata,
        binary,
        ok=False,
        summary=f"Model API failed after all retries; no verdict could be sampled. Error: {error}",
        inconclusive_reason="tool_failure",
    )
