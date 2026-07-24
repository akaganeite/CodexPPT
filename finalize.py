"""Direct evidence-cited finalization and artifact writing."""

from __future__ import annotations

import copy
import re
import time
from typing import Any

from claudeagent.common import jdump, write_artifact
from claudeagent.evidence_summary import (
    HEX_ADDRESS_RE,
    MAX_VERIFICATION_ADDRESS_RANGES,
    MAX_VERIFICATION_EXCERPT_LINES,
)
from claudeagent.runtime import AGENT_CONTEXT, bump_metric, harness_metrics
from claudeagent.schema_validate import (
    DETERMINATE_STATUSES,
    INCONCLUSIVE_REASONS,
    final_tool_parameters_schema,
    load_final_result_schema,
    resolve_schema_refs,
    validate_json_schema,
)
from claudeagent.truncation import text_head_tail


FINAL_SCHEMA_VERSION = "final_result.v7"
MAX_CITED_EVIDENCE = 8
_UNSET = object()

VERIFICATION_MODES = {"on", "off"}
VERIFICATION_OUTCOMES = {
    "off",
    "skipped",
    "confirmed",
    "contradicted",
    "unresolved",
}
VERIFICATION_RELATIONS = {"supported", "contradicted", "insufficient"}
VERIFICATION_COVERAGE = {"not_run", "complete", "incomplete", "uncertain"}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VERIFIER_EVIDENCE_ID_RE = re.compile(r"^vev_[0-9]{4,}$")

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
    if len(evidence_ids) > MAX_CITED_EVIDENCE:
        errors.append(
            f"$.evidence_ids: cite at most {MAX_CITED_EVIDENCE} evidence items, "
            f"got {len(evidence_ids)}"
        )

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
    if status in {"present", "absent"} and cited and not any(
        isinstance(item.get("verification_locators"), list)
        and bool(item.get("verification_locators"))
        for item in cited
    ):
        errors.append(
            f"$.evidence_ids: {status} verdicts require at least one cited evidence "
            "item with a verification address range"
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
                "Cite at most eight items, and include a verification address range for present/absent. "
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


def empty_verification_usage() -> dict[str, Any]:
    """Return the canonical zero-usage document for off/skipped verification."""
    return {
        "provider": "none",
        "model": "",
        "model_turns": 0,
        "totals": {},
        "by_turn": [],
        "timing": {"wall_seconds": 0.0},
    }


def _compact_verification_usage(usage: dict[str, Any]) -> dict[str, Any]:
    return {
        "provider": str(usage.get("provider", "")),
        "model": str(usage.get("model", "")),
        "model_turns": usage.get("model_turns", 0),
        "totals": copy.deepcopy(usage.get("totals", {})),
    }


def _default_verification_repair() -> dict[str, Any]:
    return {
        "requested": False,
        "run_python_calls": 0,
        "schema_repairs": 0,
        "resubmitted": False,
        "reverified": False,
    }


def build_verification_bundle(
    *,
    mode: str,
    protocol_version: str,
    config_digest: str,
    initial_status: str,
    final_status: str,
    recommended_status: str,
    outcome: str,
    claim_checks: list[dict[str, Any]] | None = None,
    coverage_status: str = "not_run",
    coverage_reason: str = "",
    verdict_evidence_ids: list[str] | None = None,
    reason: str = "",
    sessions: list[dict[str, Any]] | None = None,
    repair: dict[str, Any] | None = None,
    full: dict[str, Any] | None = None,
    transcript: list[dict[str, Any]] | None = None,
    usage: dict[str, Any] | None = None,
    timing: dict[str, Any] | None = None,
    error: str = "",
) -> dict[str, Any]:
    """Build the caller-supplied compact/full verification artifact bundle."""
    usage_document = (
        copy.deepcopy(usage) if isinstance(usage, dict) else empty_verification_usage()
    )
    usage_timing = usage_document.get("timing")
    effective_timing = (
        copy.deepcopy(timing)
        if isinstance(timing, dict)
        else copy.deepcopy(usage_timing)
        if isinstance(usage_timing, dict)
        else {"wall_seconds": 0.0}
    )
    effective_repair = _default_verification_repair()
    if isinstance(repair, dict):
        effective_repair.update(copy.deepcopy(repair))
    audit = {
        "mode": mode,
        "protocol_version": protocol_version,
        "config_digest": config_digest,
        "initial_status": initial_status,
        "final_status": final_status,
        "recommended_status": recommended_status,
        "outcome": outcome,
        "claim_checks": copy.deepcopy(claim_checks or []),
        "coverage_status": coverage_status,
        "coverage_reason": str(coverage_reason or ""),
        "verdict_evidence_ids": list(verdict_evidence_ids or []),
        "reason": str(reason or ""),
        "sessions": copy.deepcopy(sessions or []),
        "repair": effective_repair,
        "usage": _compact_verification_usage(usage_document),
        "timing": effective_timing,
        "error": str(error or ""),
    }
    full_document = copy.deepcopy(full) if isinstance(full, dict) else {}
    full_document["audit"] = copy.deepcopy(audit)
    full_document.setdefault("sessions", [])
    return {
        "audit": audit,
        "full": full_document,
        "transcript": copy.deepcopy(transcript or []),
        "usage": usage_document,
    }


def verification_off_bundle(status: str) -> dict[str, Any]:
    """Build deterministic artifacts when Verify Agent is disabled."""
    return build_verification_bundle(
        mode="off",
        protocol_version="",
        config_digest="",
        initial_status=status,
        final_status=status,
        recommended_status=status,
        outcome="off",
    )


def verification_skipped_bundle(
    status: str,
    *,
    protocol_version: str,
    config_digest: str,
    reason: str = "Verify Agent skips inconclusive results.",
) -> dict[str, Any]:
    """Build deterministic artifacts when an enabled verifier is not invoked."""
    return build_verification_bundle(
        mode="on",
        protocol_version=protocol_version,
        config_digest=config_digest,
        initial_status=status,
        final_status=status,
        recommended_status=status,
        outcome="skipped",
        reason=reason,
    )


def verification_conflict_bundle(
    *,
    initial_status: str,
    protocol_version: str,
    config_digest: str,
    claim_checks: list[dict[str, Any]],
    coverage_status: str,
    coverage_reason: str,
    verdict_evidence_ids: list[str],
    reason: str,
    sessions: list[dict[str, Any]],
    repair: dict[str, Any],
    full: dict[str, Any],
    transcript: list[dict[str, Any]],
    usage: dict[str, Any],
    recommended_status: str = "inconclusive",
    timing: dict[str, Any] | None = None,
    error: str = "",
) -> dict[str, Any]:
    """Build the terminal audit for a contradiction that survives one repair."""
    conflict_repair = copy.deepcopy(repair)
    conflict_repair["requested"] = True
    return build_verification_bundle(
        mode="on",
        protocol_version=protocol_version,
        config_digest=config_digest,
        initial_status=initial_status,
        final_status="inconclusive",
        recommended_status=recommended_status,
        outcome="contradicted",
        claim_checks=claim_checks,
        coverage_status=coverage_status,
        coverage_reason=coverage_reason,
        verdict_evidence_ids=verdict_evidence_ids,
        reason=reason,
        sessions=sessions,
        repair=conflict_repair,
        full=full,
        transcript=transcript,
        usage=usage,
        timing=timing,
        error=error,
    )


def _normalize_verification_bundle(bundle: Any) -> dict[str, Any]:
    """Copy and minimally validate the four caller-owned verification documents."""
    if not isinstance(bundle, dict):
        raise ValueError("verification_bundle must be an object")
    missing = [key for key in ("audit", "full", "transcript", "usage") if key not in bundle]
    if missing:
        raise ValueError(f"verification_bundle is missing required keys: {missing}")
    audit = bundle.get("audit")
    full = bundle.get("full")
    transcript = bundle.get("transcript")
    usage = bundle.get("usage")
    if not isinstance(audit, dict):
        raise ValueError("verification_bundle.audit must be an object")
    if not isinstance(full, dict):
        raise ValueError("verification_bundle.full must be an object")
    if not isinstance(transcript, list):
        raise ValueError("verification_bundle.transcript must be an array")
    if not isinstance(usage, dict):
        raise ValueError("verification_bundle.usage must be an object")
    required_usage = {"provider", "model", "model_turns", "totals", "by_turn", "timing"}
    missing_usage = sorted(required_usage - set(usage))
    if missing_usage:
        raise ValueError(
            f"verification_bundle.usage is missing required keys: {missing_usage}"
        )
    if not isinstance(usage.get("model_turns"), int) or isinstance(
        usage.get("model_turns"), bool
    ) or usage["model_turns"] < 0:
        raise ValueError("verification_bundle.usage.model_turns must be a non-negative integer")
    if not isinstance(usage.get("totals"), dict):
        raise ValueError("verification_bundle.usage.totals must be an object")
    if not isinstance(usage.get("by_turn"), list):
        raise ValueError("verification_bundle.usage.by_turn must be an array")
    if not isinstance(usage.get("timing"), dict):
        raise ValueError("verification_bundle.usage.timing must be an object")
    normalized = {
        "audit": copy.deepcopy(audit),
        "full": copy.deepcopy(full),
        "transcript": copy.deepcopy(transcript),
        "usage": copy.deepcopy(usage),
    }
    expected_usage = _compact_verification_usage(normalized["usage"])
    if normalized["audit"].get("usage") != expected_usage:
        raise ValueError(
            "verification_bundle.audit.usage must match the separate verifier usage document"
        )
    normalized["full"]["audit"] = copy.deepcopy(normalized["audit"])
    normalized["full"].setdefault("sessions", [])
    return normalized


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
        verification_excerpt = evidence.get("verification_excerpt")
        verification_locators = evidence.get("verification_locators")
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
            if verification_excerpt != [] or verification_locators != []:
                errors.append(f"{prefix}: pending evidence cannot record verification excerpts or locators")
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
            if (
                not isinstance(verification_excerpt, list)
                or not verification_excerpt
                or len(verification_excerpt) > MAX_VERIFICATION_EXCERPT_LINES
            ):
                errors.append(
                    f"{prefix}.verification_excerpt: summarized evidence requires 1-"
                    f"{MAX_VERIFICATION_EXCERPT_LINES} lines"
                )
            elif observation is not None:
                observation_lines = {
                    line
                    for field in ("stdout_head", "stdout_tail", "stderr_tail")
                    for line in str(observation.get(field, "")).splitlines()
                }
                for line_index, line in enumerate(verification_excerpt):
                    if not isinstance(line, str) or line not in observation_lines:
                        errors.append(
                            f"{prefix}.verification_excerpt[{line_index}]: must be an exact "
                            "line from the parent observation output"
                        )
            if (
                not isinstance(verification_locators, list)
                or len(verification_locators) > MAX_VERIFICATION_ADDRESS_RANGES
            ):
                errors.append(
                    f"{prefix}.verification_locators: expected at most "
                    f"{MAX_VERIFICATION_ADDRESS_RANGES} address ranges"
                )
            elif isinstance(verification_locators, list):
                for locator_index, locator in enumerate(verification_locators):
                    locator_prefix = f"{prefix}.verification_locators[{locator_index}]"
                    if not isinstance(locator, dict) or set(locator) != {"start", "end"}:
                        errors.append(f"{locator_prefix}: must contain only start and end")
                        continue
                    start = locator.get("start")
                    end = locator.get("end")
                    if not isinstance(start, str) or not HEX_ADDRESS_RE.fullmatch(start):
                        errors.append(f"{locator_prefix}.start: invalid hexadecimal address")
                        continue
                    if not isinstance(end, str) or not HEX_ADDRESS_RE.fullmatch(end):
                        errors.append(f"{locator_prefix}.end: invalid hexadecimal address")
                        continue
                    if int(start, 16) > int(end, 16):
                        errors.append(f"{locator_prefix}: start must be less than or equal to end")


def _validate_verification_audit(
    result: dict[str, Any],
    errors: list[str],
) -> None:
    """Validate Host-level mode/outcome policy without grading evidence semantics."""
    audit = result.get("verification")
    if not isinstance(audit, dict):
        return
    mode = str(audit.get("mode", ""))
    outcome = str(audit.get("outcome", ""))
    initial_status = str(audit.get("initial_status", ""))
    final_status = str(audit.get("final_status", ""))
    recommended_status = str(audit.get("recommended_status", ""))
    result_status = str(result.get("status", ""))
    statuses = DETERMINATE_STATUSES | {"inconclusive"}

    if mode not in VERIFICATION_MODES:
        errors.append(f"$.verification.mode: unsupported mode {mode!r}")
    if outcome not in VERIFICATION_OUTCOMES:
        errors.append(f"$.verification.outcome: unsupported outcome {outcome!r}")
    for field, value in (
        ("initial_status", initial_status),
        ("final_status", final_status),
        ("recommended_status", recommended_status),
    ):
        if value not in statuses:
            errors.append(f"$.verification.{field}: unsupported verdict status {value!r}")
    if final_status != result_status:
        errors.append(
            "$.verification.final_status: must equal the serialized final result status"
        )

    sessions = audit.get("sessions")
    session_items = sessions if isinstance(sessions, list) else []
    session_indexes = [
        item.get("session_index")
        for item in session_items
        if isinstance(item, dict) and isinstance(item.get("session_index"), int)
    ]
    if len(session_indexes) != len(set(session_indexes)):
        errors.append("$.verification.sessions: duplicate session_index values are not allowed")
    if session_indexes and session_indexes != list(range(1, len(session_indexes) + 1)):
        errors.append("$.verification.sessions: session_index values must be consecutive from 1")
    for index, session in enumerate(session_items):
        if not isinstance(session, dict):
            continue
        prefix = f"$.verification.sessions[{index}]"
        for budget_name, call_name in (
            ("claim_budget", "claim_calls"),
            ("verdict_budget", "verdict_calls"),
        ):
            budget = session.get(budget_name)
            calls = session.get(call_name)
            if (
                isinstance(budget, int)
                and not isinstance(budget, bool)
                and isinstance(calls, int)
                and not isinstance(calls, bool)
                and calls > budget
            ):
                errors.append(f"{prefix}.{call_name}: cannot exceed {budget_name}")

    claim_checks = audit.get("claim_checks")
    checks = claim_checks if isinstance(claim_checks, list) else []
    checked_ids = [
        str(item.get("evidence_id", ""))
        for item in checks
        if isinstance(item, dict)
    ]
    if len(checked_ids) != len(set(checked_ids)):
        errors.append("$.verification.claim_checks: duplicate evidence_id values are not allowed")
    for index, check in enumerate(checks):
        if not isinstance(check, dict):
            continue
        relation = str(check.get("relation", ""))
        if relation not in VERIFICATION_RELATIONS:
            errors.append(
                f"$.verification.claim_checks[{index}].relation: unsupported relation {relation!r}"
            )
        verifier_ids = check.get("verifier_evidence_ids")
        verifier_id_text = (
            [str(item) for item in verifier_ids]
            if isinstance(verifier_ids, list)
            else []
        )
        if isinstance(verifier_ids, list) and len(verifier_id_text) != len(
            set(verifier_id_text)
        ):
            errors.append(
                f"$.verification.claim_checks[{index}].verifier_evidence_ids: duplicates are not allowed"
            )
        invalid_verifier_ids = [
            item for item in verifier_id_text if not _VERIFIER_EVIDENCE_ID_RE.fullmatch(item)
        ]
        if invalid_verifier_ids:
            errors.append(
                f"$.verification.claim_checks[{index}].verifier_evidence_ids: "
                f"invalid verifier ID(s) {invalid_verifier_ids}"
            )

    verdict_ids = audit.get("verdict_evidence_ids")
    verdict_id_text = (
        [str(item) for item in verdict_ids]
        if isinstance(verdict_ids, list)
        else []
    )
    if isinstance(verdict_ids, list) and len(verdict_id_text) != len(
        set(verdict_id_text)
    ):
        errors.append("$.verification.verdict_evidence_ids: duplicates are not allowed")
    invalid_verdict_ids = [
        item for item in verdict_id_text if not _VERIFIER_EVIDENCE_ID_RE.fullmatch(item)
    ]
    if invalid_verdict_ids:
        errors.append(
            "$.verification.verdict_evidence_ids: invalid verifier ID(s) "
            f"{invalid_verdict_ids}"
        )

    coverage_status = str(audit.get("coverage_status", ""))
    if coverage_status not in VERIFICATION_COVERAGE:
        errors.append(
            f"$.verification.coverage_status: unsupported status {coverage_status!r}"
        )

    repair = audit.get("repair")
    repair_data = repair if isinstance(repair, dict) else {}
    requested = repair_data.get("requested") is True
    resubmitted = repair_data.get("resubmitted") is True
    reverified = repair_data.get("reverified") is True
    if resubmitted and not requested:
        errors.append("$.verification.repair.resubmitted: requires requested=true")
    if reverified and not resubmitted:
        errors.append("$.verification.repair.reverified: requires resubmitted=true")

    if mode == "off":
        if outcome != "off":
            errors.append("$.verification.outcome: mode=off requires outcome=off")
        if audit.get("protocol_version") not in {"", None}:
            errors.append("$.verification.protocol_version: mode=off requires an empty value")
        if audit.get("config_digest") not in {"", None}:
            errors.append("$.verification.config_digest: mode=off requires an empty value")
        if session_items or checks or requested:
            errors.append("$.verification: mode=off cannot contain sessions, claim checks, or repair")
        if recommended_status != final_status:
            errors.append("$.verification.recommended_status: mode=off must preserve final status")
        if coverage_status != "not_run":
            errors.append("$.verification.coverage_status: mode=off requires not_run")
    elif mode == "on":
        protocol_version = audit.get("protocol_version")
        config_digest = audit.get("config_digest")
        if not isinstance(protocol_version, str) or not protocol_version:
            errors.append("$.verification.protocol_version: mode=on requires a version")
        if not isinstance(config_digest, str) or not _SHA256_RE.fullmatch(config_digest):
            errors.append("$.verification.config_digest: mode=on requires a SHA-256 digest")
        if outcome == "off":
            errors.append("$.verification.outcome: mode=on cannot use outcome=off")
        if outcome == "skipped":
            if initial_status != "inconclusive" or final_status != "inconclusive":
                errors.append(
                    "$.verification: skipped verification requires an inconclusive initial/final status"
                )
            if session_items or checks or requested:
                errors.append(
                    "$.verification: skipped verification cannot contain sessions, claim checks, or repair"
                )
            if recommended_status != final_status:
                errors.append(
                    "$.verification.recommended_status: skipped verification must preserve final status"
                )
            if coverage_status != "not_run":
                errors.append("$.verification.coverage_status: skipped verification requires not_run")
        elif outcome in {"confirmed", "unresolved", "contradicted"}:
            if initial_status not in DETERMINATE_STATUSES:
                errors.append(
                    "$.verification.initial_status: executed verification requires a determinate candidate"
                )
            if not session_items:
                errors.append("$.verification.sessions: executed verification requires a session")
            if coverage_status == "not_run":
                errors.append(
                    "$.verification.coverage_status: executed verification cannot use not_run"
                )
            if session_items and str(session_items[-1].get("outcome", "")) != outcome:
                errors.append(
                    "$.verification.sessions: final session outcome must match top-level outcome"
                )
            if not str(audit.get("coverage_reason", "")):
                errors.append(
                    "$.verification.coverage_reason: executed verification requires a reason"
                )
            if not str(audit.get("reason", "")):
                errors.append("$.verification.reason: executed verification requires a reason")
        if outcome == "confirmed":
            if final_status not in DETERMINATE_STATUSES:
                errors.append("$.verification.final_status: confirmed requires a determinate result")
            if recommended_status != final_status:
                errors.append(
                    "$.verification.recommended_status: confirmed must match final status"
                )
            if coverage_status != "complete":
                errors.append("$.verification.coverage_status: confirmed requires complete coverage")
            if not checks:
                errors.append("$.verification.claim_checks: confirmed requires claim checks")
            elif set(checked_ids) != set(result.get("evidence_ids", [])):
                errors.append(
                    "$.verification.claim_checks: confirmed checks must match final evidence_ids"
                )
            decisive_checks = [
                item for item in checks if isinstance(item, dict) and item.get("decisive") is True
            ]
            if not decisive_checks:
                errors.append(
                    "$.verification.claim_checks: confirmed requires at least one decisive claim"
                )
            if any(item.get("relation") == "contradicted" for item in checks):
                errors.append(
                    "$.verification.claim_checks: confirmed cannot contain a contradicted claim"
                )
            if any(item.get("relation") != "supported" for item in decisive_checks):
                errors.append(
                    "$.verification.claim_checks: every decisive confirmed claim must be supported"
                )
        elif outcome == "unresolved":
            # Deliberately do not downgrade or reject a retained determinate verdict.
            if final_status not in DETERMINATE_STATUSES:
                errors.append(
                    "$.verification.final_status: unresolved verification retains a determinate result"
                )
            if recommended_status not in {final_status, "inconclusive"}:
                errors.append(
                    "$.verification.recommended_status: unresolved may retain final status or recommend inconclusive"
                )
            if set(checked_ids) != set(result.get("evidence_ids", [])):
                errors.append(
                    "$.verification.claim_checks: unresolved checks must match final evidence_ids"
                )
            if any(item.get("relation") == "contradicted" for item in checks):
                errors.append(
                    "$.verification.claim_checks: unresolved cannot contain a contradicted claim"
                )
        elif outcome == "contradicted":
            conceded_to_inconclusive = resubmitted and not reverified
            if final_status != "inconclusive":
                errors.append(
                    "$.verification: a contradicted verification requires an inconclusive final result"
                )
            elif (
                not conceded_to_inconclusive
                and result.get("inconclusive_reason") != "conflicting_evidence"
            ):
                errors.append(
                    "$.verification: failed repair or a second contradiction requires "
                    "inconclusive/conflicting_evidence"
                )
            if not requested:
                errors.append("$.verification.repair.requested: terminal contradiction requires one repair attempt")


def validate_final_result_artifact(result: dict[str, Any]) -> list[str]:
    """Validate serialized artifacts against schema and ledger provenance."""
    schema = load_final_result_schema()
    errors = validate_json_schema(result, resolve_schema_refs(schema, schema))
    _validate_ledger_provenance(result, errors)
    _validate_verification_audit(result, errors)
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
    *,
    verification_bundle: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    verification = _normalize_verification_bundle(verification_bundle)
    timing = {"wall_seconds": round(time.time() - start_epoch, 3)}
    usage = aggregate_usage(transcript)
    usage["timing"] = timing
    out = dict(result)
    out["completed_at_epoch"] = time.time()
    out["timing"] = timing
    out["usage_metrics"] = usage
    out["verification"] = verification["audit"]
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
    *,
    verification_bundle: dict[str, Any],
) -> dict[str, Any]:
    verification = _normalize_verification_bundle(verification_bundle)
    out, schema_errors = build_final_artifact(
        result,
        transcript,
        start_epoch,
        verification_bundle=verification,
    )
    if schema_errors:
        out["ok"] = False
        out["schema_validation_errors"] = schema_errors
    write_artifact(output_dir, "verification.json", jdump(verification["full"]) + "\n")
    write_artifact(
        output_dir,
        "verification_transcript.json",
        jdump(verification["transcript"]) + "\n",
    )
    write_artifact(
        output_dir,
        "verification_usage_metrics.json",
        jdump(verification["usage"]) + "\n",
    )
    write_artifact(output_dir, "transcript.json", jdump(transcript) + "\n")
    write_artifact(output_dir, "usage_metrics.json", jdump(out["usage_metrics"]) + "\n")
    # final_result is the resume marker and must only appear after every auxiliary artifact.
    write_artifact(output_dir, "final_result.json", jdump(out) + "\n")
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


def conflicting_evidence_result(
    metadata: dict[str, Any],
    binary: str,
    summary: str,
) -> dict[str, Any]:
    """Return the canonical result after a verifier contradiction survives repair."""
    return _fallback_result(
        metadata,
        binary,
        ok=True,
        summary=summary,
        inconclusive_reason="conflicting_evidence",
    )


def api_failure_fallback_result(metadata: dict[str, Any], binary: str, error: str) -> dict[str, Any]:
    return _fallback_result(
        metadata,
        binary,
        ok=False,
        summary=f"Model API failed after all retries; no verdict could be sampled. Error: {error}",
        inconclusive_reason="tool_failure",
    )
