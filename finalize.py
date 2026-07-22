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
from claudeagent.decision import (
    FINAL_SCHEMA_VERSION,
    aggregate_verdict,
    fallback_decision_fields,
    project_legacy_fields,
    resolve_behavior_claims,
    support_evidence_ids,
    validate_claim_record,
    validate_support_records,
)
from claudeagent.evidence_verifier import (
    EvidenceVerifierSession,
    validate_verification,
    verifier_audit,
    verifier_usage,
)
from claudeagent.runtime import AGENT_CONTEXT, bump_metric, evidence_ids_in_ledger, harness_metrics
from claudeagent.schema_validate import (
    DETERMINATE_STATUSES,
    INCONCLUSIVE_REASONS,
    final_tool_parameters_schema,
    load_final_result_schema,
    validate_json_schema,
)
from claudeagent.truncation import text_head_tail


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
    """Keep Host-generated fallback claims within the final schema limit."""
    text = str(value or "")
    if len(text) <= 3800:
        return text
    parts = text_head_tail(text, 3500)
    return (
        f"{parts['head']}\n... {parts['omitted_chars']} chars omitted ...\n"
        f"{parts['tail']}"
    )[:3800]


def resolve_final_tool_args(
    candidate: dict[str, Any],
    *,
    behavior_contract: list[dict[str, Any]],
    evidence_ledger: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[str]]:
    """Validate a model submission and derive the canonical/legacy decision."""
    errors = validate_json_schema(candidate, final_tool_parameters_schema())
    supports = candidate.get("supports") if isinstance(candidate.get("supports"), list) else []
    claim = candidate.get("claim") if isinstance(candidate.get("claim"), dict) else {}
    behavior_claims = resolve_behavior_claims(supports, claim, behavior_contract)
    verdict = aggregate_verdict(behavior_claims)
    derived_status = str(verdict["status"])
    legacy = project_legacy_fields(supports, claim)

    errors.extend(validate_support_records(
        supports,
        status=derived_status,
        evidence_ids=support_evidence_ids(supports),
        behavior_contract=behavior_contract,
        evidence_ledger=evidence_ledger,
    ))
    errors.extend(validate_claim_record(
        claim,
        supports=supports,
        behavior_contract=behavior_contract,
    ))

    submitted_status = str(candidate.get("status", ""))
    if submitted_status != derived_status:
        errors.append(
            f"$.status: submitted {submitted_status!r}, but Host derived {derived_status!r} "
            f"using rule {verdict['rule']!r}"
        )

    reason = candidate.get("inconclusive_reason")
    if reason not in INCONCLUSIVE_REASONS:
        errors.append(f"$.inconclusive_reason: expected one of {sorted(INCONCLUSIVE_REASONS)}")
    if derived_status == "inconclusive" and reason in {"", "none", None}:
        errors.append("$.inconclusive_reason: inconclusive verdicts must name a concrete reason")
    if derived_status != "inconclusive" and reason not in {"", "none", None}:
        errors.append("$.inconclusive_reason: determinate verdicts should use 'none'")
    if derived_status in DETERMINATE_STATUSES and not legacy["evidence_ids"]:
        errors.append(f"$.supports: Host-derived {derived_status} verdict requires cited evidence")

    if derived_status in DETERMINATE_STATUSES:
        verdict_text = "\n".join([
            *(str(item) for item in legacy["evidence"]),
            str(legacy["reasoning"]),
        ])
        if VERSION_EVIDENCE_RE.search(verdict_text):
            errors.append(
                "$.supports/claim: determinate verdict appears to rely on version strings, "
                "filenames, paths, or release labels instead of semantic binary evidence"
            )

    canonical = {
        "schema_version": FINAL_SCHEMA_VERSION,
        "status": derived_status,
        "confidence": candidate.get("confidence"),
        "supports": supports,
        "claim": claim,
        "verdict": verdict,
        **legacy,
        "inconclusive_reason": reason,
    }
    return canonical, errors


def compact_known_evidence_ids() -> dict[str, Any]:
    ids = sorted(evidence_ids_in_ledger())
    return {"count": len(ids), "head": ids[:12], "tail": ids[-12:] if len(ids) > 12 else []}


def compact_rejected_tool_args(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": candidate.get("status"),
        "confidence": candidate.get("confidence"),
        "supports": candidate.get("supports", []),
        "claim": candidate.get("claim", {}),
        "inconclusive_reason": candidate.get("inconclusive_reason", ""),
    }


def submit_detection_result(
    status: str,
    confidence: str,
    supports: list[dict[str, Any]],
    claim: dict[str, Any],
    inconclusive_reason: str,
) -> dict[str, Any]:
    candidate = {
        "status": status,
        "confidence": confidence,
        "supports": supports,
        "claim": claim,
        "inconclusive_reason": inconclusive_reason,
    }
    canonical, validation_errors = resolve_final_tool_args(
        candidate,
        behavior_contract=AGENT_CONTEXT.get("patch_spec_behavior_contract", []),
        evidence_ledger=AGENT_CONTEXT.get("evidence_ledger", []),
    )
    if validation_errors:
        bump_metric("schema_repair_attempts")
        if status in DETERMINATE_STATUSES and not support_evidence_ids(supports):
            bump_metric("no_evidence_verdicts")
        return {
            "ok": False,
            "error": "submit_detection_result arguments failed schema/evidence validation; repair and call again",
            "schema_errors": validation_errors,
            "known_evidence_ids": compact_known_evidence_ids(),
            "rejected_candidate": compact_rejected_tool_args(candidate),
            "repair_instruction": (
                "Repair the rejected supports/claim; do not restart the investigation. Cite only real "
                "ledger evidence and PatchSpec behavior ids. Claim every submitted support exactly "
                "once. List each required behavior with no single decisive side in "
                "claim.unresolved_behavior_ids. Pure no-match evidence can only support ambiguous. "
                "The submitted status must equal the Host-derived behavior aggregation reported in "
                "schema_errors. Remove versions, paths, filenames, and release chronology from support "
                "summaries and claim.summary. Downgrade to inconclusive only when the binary evidence "
                "is genuinely unresolved."
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


def verify_detection_result(result: dict[str, Any]) -> dict[str, Any]:
    """Run the independent semantic gate after the Host artifact preflight."""
    verifier_session = AGENT_CONTEXT.get("evidence_verifier_session")
    verifier_mode = str(AGENT_CONTEXT.get("evidence_verifier_mode", "off"))
    if isinstance(verifier_session, EvidenceVerifierSession):
        verification = verifier_session.verify(
            result,
            evidence_ledger=AGENT_CONTEXT.get("evidence_ledger", []),
            observations=AGENT_CONTEXT.get("observations", []),
        )
    elif verifier_mode == "llm" and result.get("status") in DETERMINATE_STATUSES:
        verification = {
            "decision": "fail_closed",
            "reason": "tool_failure",
            "summary": (
                "Independent evidence verification was configured but unavailable; "
                "the determinate claim was not accepted."
            ),
        }
    else:
        verification = {"decision": "accept"}

    if verification.get("decision") == "repair":
        return {
            "ok": False,
            "tool": "submit_detection_result",
            "error": (
                "independent evidence verification rejected the determinate claim; "
                "repair supports/claim once using existing evidence"
            ),
            "verifier_repair_required": True,
            "verification": verification.get("verification", {}),
            "known_evidence_ids": compact_known_evidence_ids(),
            "rejected_candidate": compact_rejected_tool_args(result),
            "repair_instruction": verification.get("repair_instruction", ""),
        }
    if verification.get("decision") == "fail_closed":
        reason = str(verification.get("reason", "tool_failure"))
        fallback = _fallback_result(
            AGENT_CONTEXT["metadata"],
            AGENT_CONTEXT["binary_path"],
            ok=reason != "tool_failure",
            summary=str(verification.get("summary", "Independent evidence verification failed.")),
            inconclusive_reason=reason,
        )
        if reason == "tool_failure":
            # Internal dispatch marker: the artifact is terminal even though
            # ok=false accurately records verifier/API failure. The loop strips
            # this marker before writing final_result.json.
            fallback["_terminal_submit"] = True
        return fallback
    return result


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


def validate_final_result_artifact(
    result: dict[str, Any],
    *,
    check_verifier: bool = True,
) -> list[str]:
    errors = validate_json_schema(result, load_final_result_schema())
    patch_spec = result.get("patch_spec") if isinstance(result.get("patch_spec"), dict) else {}
    artifact_candidate = {
        "status": result.get("status"),
        "confidence": result.get("confidence"),
        "supports": result.get("supports"),
        "claim": result.get("claim"),
        "inconclusive_reason": result.get("inconclusive_reason"),
    }
    canonical, decision_errors = resolve_final_tool_args(
        artifact_candidate,
        behavior_contract=patch_spec.get("behavior_contract", []),
        evidence_ledger=result.get("evidence_ledger", []),
    )
    errors.extend(decision_errors)
    for field in (
        "schema_version",
        "status",
        "evidence",
        "evidence_ids",
        "reasoning",
        "decisive_addresses",
        "verdict",
    ):
        if result.get(field) != canonical.get(field):
            errors.append(
                f"$.{field}: artifact value diverges from Host-derived canonical projection"
            )
    verification = (
        result.get("evidence_verification")
        if isinstance(result.get("evidence_verification"), dict)
        else {}
    )
    mode = str(verification.get("mode", ""))
    outcome = str(verification.get("outcome", ""))
    attempts = (
        verification.get("attempts")
        if isinstance(verification.get("attempts"), list)
        else []
    )
    attempt_outcomes = [
        str(item.get("outcome", ""))
        for item in attempts
        if isinstance(item, dict)
    ]
    if check_verifier and verification.get("repair_pending") is True:
        errors.append("$.evidence_verification.repair_pending: final artifacts cannot remain pending")
    if not check_verifier:
        return errors

    status = str(result.get("status", ""))
    reason = str(result.get("inconclusive_reason", ""))
    if mode == "off" and outcome != "off":
        errors.append("$.evidence_verification.outcome: off mode requires outcome=off")
    if mode == "llm" and outcome == "off":
        errors.append("$.evidence_verification.outcome: llm mode cannot use outcome=off")
    if mode == "off" and (
        verification.get("model")
        or verification.get("reasoning") is not None
        or verification.get("config_digest")
    ):
        errors.append(
            "$.evidence_verification: off mode must not record model/reasoning/config_digest"
        )
    if mode == "llm" and outcome != "not_run":
        digest = str(verification.get("config_digest", ""))
        if not verification.get("model") or not re.fullmatch(r"[0-9a-f]{64}", digest):
            errors.append(
                "$.evidence_verification: executed llm verification requires model and config_digest"
            )
    if status in DETERMINATE_STATUSES:
        if mode == "llm" and outcome not in {"accepted", "accepted_after_repair"}:
            errors.append(
                "$.evidence_verification.outcome: determinate llm-mode artifacts require "
                "accepted or accepted_after_repair"
            )
        if mode == "off" and outcome != "off":
            errors.append(
                "$.evidence_verification.outcome: determinate off-mode artifacts require off"
            )
        if mode == "llm" and outcome in {"accepted", "accepted_after_repair"}:
            accepted_attempts = [
                item
                for item in attempts
                if isinstance(item, dict)
                and item.get("outcome") == "accept"
                and isinstance(item.get("verification"), dict)
            ]
            if not accepted_attempts:
                errors.append(
                    "$.evidence_verification.attempts: accepted determinate artifacts require "
                    "an accepted verifier report"
                )
            else:
                verifier_errors = validate_verification(accepted_attempts[-1]["verification"], result)
                errors.extend(
                    f"$.evidence_verification.attempts: {item}"
                    for item in verifier_errors
                )
        if mode == "off" and verification.get("attempts"):
            errors.append(
                "$.evidence_verification.attempts: off-mode artifacts must not contain verifier calls"
            )
    if outcome == "accepted" and attempt_outcomes != ["accept"]:
        errors.append(
            "$.evidence_verification.attempts: accepted requires exactly one accept attempt"
        )
    if outcome == "accepted_after_repair" and attempt_outcomes != ["repair", "accept"]:
        errors.append(
            "$.evidence_verification.attempts: accepted_after_repair requires repair then accept"
        )
    if outcome in {"accepted", "accepted_after_repair"} and status not in DETERMINATE_STATUSES:
        errors.append(
            "$.evidence_verification.outcome: accepted outcomes require a determinate result"
        )
    if outcome == "rejected_after_repair":
        if attempt_outcomes != ["repair", "repair"]:
            errors.append(
                "$.evidence_verification.attempts: rejected_after_repair requires two repair outcomes"
            )
        if status != "inconclusive" or reason != "conflicting_evidence":
            errors.append(
                "$.evidence_verification.outcome: rejected_after_repair requires "
                "inconclusive/conflicting_evidence"
            )
    if outcome == "repair_not_completed":
        if attempt_outcomes != ["repair", "abandoned"]:
            errors.append(
                "$.evidence_verification.attempts: repair_not_completed requires repair then abandoned"
            )
        if status != "inconclusive" or reason != "conflicting_evidence":
            errors.append(
                "$.evidence_verification.outcome: repair_not_completed requires "
                "inconclusive/conflicting_evidence"
            )
    if outcome == "tool_failure":
        if not attempt_outcomes or attempt_outcomes[-1] != "error":
            errors.append(
                "$.evidence_verification.attempts: tool_failure requires a final error outcome"
            )
        if status != "inconclusive" or reason != "tool_failure" or result.get("ok") is not False:
            errors.append(
                "$.evidence_verification.outcome: tool_failure requires "
                "ok=false and inconclusive/tool_failure"
            )
    if outcome == "repaired_to_inconclusive":
        if attempt_outcomes != ["repair"] or status != "inconclusive":
            errors.append(
                "$.evidence_verification.outcome: repaired_to_inconclusive requires "
                "one repair attempt and an inconclusive result"
            )
    if outcome in {"off", "not_run", "skipped_inconclusive"} and attempt_outcomes:
        errors.append(
            f"$.evidence_verification.attempts: {outcome} must not contain verifier attempts"
        )
    if outcome == "skipped_inconclusive" and status != "inconclusive":
        errors.append(
            "$.evidence_verification.outcome: skipped_inconclusive requires an inconclusive result"
        )
    if outcome == "repair_requested":
        errors.append("$.evidence_verification.outcome: repair_requested cannot be final")
    return errors


def build_final_artifact(
    result: dict[str, Any],
    transcript: list[dict[str, Any]],
    start_epoch: float,
    *,
    check_verifier: bool = True,
) -> tuple[dict[str, Any], list[str]]:
    timing = {"wall_seconds": round(time.time() - start_epoch, 3)}
    usage = aggregate_usage(transcript)
    usage["timing"] = timing
    patch_spec_info = AGENT_CONTEXT.get("patch_spec_info", {})
    if not isinstance(patch_spec_info, dict):
        patch_spec_info = {}
    patch_spec_usage = patch_spec_info.get("usage")
    usage["patch_spec_generation"] = patch_spec_usage if isinstance(patch_spec_usage, dict) else {}
    verifier_session = AGENT_CONTEXT.get("evidence_verifier_session")
    verifier_mode = str(AGENT_CONTEXT.get("evidence_verifier_mode", "off"))
    usage["evidence_verifier"] = verifier_usage(verifier_session)
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
    out["evidence_verification"] = verifier_audit(
        verifier_session,
        mode=verifier_mode,
    )
    return out, validate_final_result_artifact(out, check_verifier=check_verifier)


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
        "claim": preview.get("claim", {}),
        "verdict": preview.get("verdict", {}),
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
    summary = _bounded_fallback_summary(summary)
    return {
        "ok": ok,
        "project": metadata.get("project", "curl"),
        "cve_id": metadata.get("cve_id", AGENT_CONTEXT.get("cve_id", "")),
        "binary": binary,
        "status": "inconclusive",
        "confidence": "low",
        **fallback_decision_fields(
            AGENT_CONTEXT.get("patch_spec_behavior_contract", []),
            summary=summary,
        ),
        "inconclusive_reason": inconclusive_reason,
        **(extra or {}),
        "completed_at_epoch": time.time(),
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
    """Inconclusive result written when the model API is unreachable after all
    retries. The run still produces a valid artifact (so a batch can score it)
    rather than dying empty-handed."""
    return _fallback_result(
        metadata,
        binary,
        ok=False,
        summary=f"Model API failed after all retries; no verdict could be sampled. Error: {error}",
        inconclusive_reason="tool_failure",
    )


def verifier_pending_fallback_result(
    metadata: dict[str, Any],
    binary: str,
    *,
    error: str = "Verifier-requested repair was not completed before the run ended.",
    inconclusive_reason: str = "conflicting_evidence",
) -> dict[str, Any]:
    """Fail closed when a verifier repair cannot reach a second valid submit."""
    session = AGENT_CONTEXT.get("evidence_verifier_session")
    if isinstance(session, EvidenceVerifierSession):
        tool_failure = inconclusive_reason == "tool_failure"
        session.abandon_pending(
            outcome="tool_failure" if tool_failure else "repair_not_completed",
            error=error,
            attempt_outcome="error" if tool_failure else "abandoned",
        )
    return _fallback_result(
        metadata,
        binary,
        ok=inconclusive_reason != "tool_failure",
        summary=error,
        inconclusive_reason=inconclusive_reason,
    )
