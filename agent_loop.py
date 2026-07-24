"""Single-case model/tool loop over the OpenAI Responses API.

The investigator receives complete answer-scrubbed CVE metadata, inspects only
an anonymized target binary, and must finalize through an evidence-cited tool.
Tool and schema failures repair in-band; API failures produce a valid
inconclusive artifact for batch accounting.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any

from claudeagent.binary_workspace import prepare_anonymous_binary
from claudeagent.common import FINAL_RESULT_SCHEMA, SYSTEM_PROMPT, compact_json, expand, jdump
from claudeagent.finalize import (
    api_failure_fallback_result,
    build_verification_bundle,
    conflicting_evidence_result,
    max_turns_fallback_result,
    preflight_missing_result,
    verification_off_bundle,
    verification_skipped_bundle,
    write_run_outputs,
)
from claudeagent.host import (
    import_env_from_interactive_shell,
    load_cve_metadata,
    load_env_files,
    preflight_detection_inputs,
)
from claudeagent.metadata_input import metadata_sha256, validate_metadata_prompt_input
from claudeagent.model_config import (
    ModelProfile,
    apply_profile_to_args,
    interactive_env_keys,
    reasoning_param,
    resolve_api_key,
    resolve_profile,
)
from claudeagent.observations import compact_tool_result_for_model
from claudeagent.prompting import (
    append_finalization_budget_prompt,
    append_finalization_prompt,
    build_task,
    repair_finalization_prompt,
)
from claudeagent.responses_client import responses_create
from claudeagent.runtime import (
    AGENT_CONTEXT,
    begin_model_response,
    bump_metric,
    harness_metrics,
    initialize_agent_context,
    mark_evidence_returned,
)
from claudeagent.sandbox import preflight_sandbox
from claudeagent.schema_validate import load_final_result_schema
from claudeagent.tools_registry import (
    FINALIZATION_TOOL_FUNCS,
    TOOL_FUNCS,
    finalization_tools,
    load_tools,
)
from claudeagent.verify_agent import VERIFY_AGENT_PROTOCOL_VERSION, VerifyAgentSession
from claudeagent.verify_config import (
    ResolvedVerifyAgentSettings,
    resolve_verify_agent_settings,
)


@dataclass(frozen=True)
class PendingSubmission:
    """A Host-valid main-agent result waiting for independent verification."""

    result: dict[str, Any]
    call: dict[str, Any]
    call_id: str
    turn_label: int | str


class FailedVerifyAgentSession:
    """Minimal unresolved session used when verifier construction itself fails."""

    def __init__(
        self,
        settings: ResolvedVerifyAgentSettings,
        candidate: dict[str, Any],
        error: str,
        wall_seconds: float,
    ) -> None:
        self.settings = settings
        self.candidate = copy.deepcopy(candidate)
        self.outcome = "unresolved"
        self.failure_kind = "internal_failure"
        self.error = error
        self.wall_seconds = wall_seconds
        self.claim_calls = 0
        self.verdict_calls = 0
        self.protocol_repairs = 0
        self.evidence_ledger: list[dict[str, Any]] = []
        self.transcript = [{"stage": "construction_failure", "error": error}]
        self.verification = {
            "action": "unresolved",
            "claim_checks": [
                {
                    "evidence_id": str(evidence_id),
                    "relation": "insufficient",
                    "decisive": False,
                    "verifier_evidence_ids": [],
                    "reason": "Verify Agent failed before this claim could be checked.",
                }
                for evidence_id in candidate.get("evidence_ids", [])
            ],
            "coverage_status": "uncertain",
            "coverage_reason": "Verify Agent failed before independent checks could start.",
            "recommended_status": str(candidate.get("status", "inconclusive")),
            "verdict_evidence_ids": [],
            "reason": f"Verify Agent construction failure: {error}"[:2400],
        }

    def report(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "verification": copy.deepcopy(self.verification),
            "claim_calls": 0,
            "verdict_calls": 0,
            "protocol_repairs": 0,
            "failure_kind": self.failure_kind,
            "error": self.error,
        }

    def audit(self) -> dict[str, Any]:
        return {
            "protocol_version": VERIFY_AGENT_PROTOCOL_VERSION,
            "model": self.settings.config.model,
            "config_digest": self.settings.config_digest,
            "outcome": self.outcome,
            "failure_kind": self.failure_kind,
            "error": self.error,
            "claim_budget": len(self.candidate.get("evidence_ids", [])),
            "claim_calls": 0,
            "verdict_budget": self.settings.config.verdict_calls,
            "verdict_calls": 0,
            "protocol_repairs": 0,
            "wall_seconds": self.wall_seconds,
            "verification": copy.deepcopy(self.verification),
            "observations": [],
            "evidence_ledger": [],
        }

    def usage_summary(self) -> dict[str, Any]:
        return {
            "provider": "openai-responses",
            "model": self.settings.config.model,
            "model_turns": 0,
            "totals": {},
            "by_turn": [],
            "timing": {"wall_seconds": self.wall_seconds},
        }


VerificationSession = VerifyAgentSession | FailedVerifyAgentSession


def cited_evidence_for_verification(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    """Project only cited claim/excerpt/locator fields into verifier input."""
    ledger_by_id = {
        str(item.get("evidence_id")): item
        for item in AGENT_CONTEXT.get("evidence_ledger", [])
        if isinstance(item, dict) and item.get("evidence_id")
    }
    projected: list[dict[str, Any]] = []
    for evidence_id in candidate.get("evidence_ids", []):
        item = ledger_by_id.get(str(evidence_id))
        if item is None:
            raise ValueError(f"cited evidence id {evidence_id!r} is missing from the ledger")
        projected.append({
            "evidence_id": str(evidence_id),
            "claim": str(item.get("claim", "")),
            "excerpt": copy.deepcopy(item.get("verification_excerpt", [])),
            "address_ranges": copy.deepcopy(item.get("verification_locators", [])),
        })
    return projected


def _merge_numeric_tree(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if isinstance(value, dict):
            child = target.setdefault(key, {})
            if not isinstance(child, dict):
                child = {}
                target[key] = child
            _merge_numeric_tree(child, value)
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            current = target.get(key, 0)
            target[key] = (current if isinstance(current, (int, float)) else 0) + value


def _merge_verification_usage(sessions: list[VerificationSession]) -> dict[str, Any]:
    summaries = [session.usage_summary() for session in sessions]
    providers = {str(item.get("provider", "")) for item in summaries if item.get("provider")}
    models = {str(item.get("model", "")) for item in summaries if item.get("model")}
    totals: dict[str, Any] = {}
    by_turn: list[dict[str, Any]] = []
    wall_seconds = 0.0
    model_turns = 0
    for session_index, summary in enumerate(summaries, 1):
        model_turns += int(summary.get("model_turns", 0) or 0)
        if isinstance(summary.get("totals"), dict):
            _merge_numeric_tree(totals, summary["totals"])
        timing = summary.get("timing")
        if isinstance(timing, dict):
            wall_seconds += float(timing.get("wall_seconds", 0.0) or 0.0)
        for turn in summary.get("by_turn", []):
            if isinstance(turn, dict):
                by_turn.append({"session_index": session_index, **copy.deepcopy(turn)})
    return {
        "provider": next(iter(providers)) if len(providers) == 1 else "mixed" if providers else "",
        "model": next(iter(models)) if len(models) == 1 else "mixed" if models else "",
        "model_turns": model_turns,
        "totals": totals,
        "by_turn": by_turn,
        "timing": {"wall_seconds": round(wall_seconds, 3)},
    }


def _compact_verification_session(session: VerificationSession, session_index: int) -> dict[str, Any]:
    audit = session.audit()
    outcome = str(audit.get("outcome", "unresolved"))
    if outcome not in {"confirmed", "contradicted", "unresolved"}:
        outcome = "unresolved"
    return {
        "session_index": session_index,
        "outcome": outcome,
        "claim_budget": int(audit.get("claim_budget", 0) or 0),
        "claim_calls": int(audit.get("claim_calls", 0) or 0),
        "verdict_budget": int(audit.get("verdict_budget", 0) or 0),
        "verdict_calls": int(audit.get("verdict_calls", 0) or 0),
        "protocol_repairs": int(audit.get("protocol_repairs", 0) or 0),
        "failure_kind": str(audit.get("failure_kind", "")),
        "wall_seconds": float(audit.get("wall_seconds", 0.0) or 0.0),
    }


def _verification_bundle_from_sessions(
    *,
    sessions: list[VerificationSession],
    config_digest: str,
    initial_status: str,
    final_status: str,
    repair: dict[str, Any] | None = None,
    force_outcome: str = "",
) -> dict[str, Any]:
    if not sessions:
        raise ValueError("executed verification requires at least one session")
    final_report = sessions[-1].report()
    verification = final_report.get("verification")
    verification = verification if isinstance(verification, dict) else {}
    outcome = force_outcome or str(final_report.get("outcome", "unresolved"))
    if outcome not in {"confirmed", "contradicted", "unresolved"}:
        outcome = "unresolved"
    compact_sessions = [
        _compact_verification_session(session, index)
        for index, session in enumerate(sessions, 1)
    ]
    full_sessions = [
        {"session_index": index, **session.audit()}
        for index, session in enumerate(sessions, 1)
    ]
    transcript = [
        {"session_index": index, "items": copy.deepcopy(session.transcript)}
        for index, session in enumerate(sessions, 1)
    ]
    usage = _merge_verification_usage(sessions)
    return build_verification_bundle(
        mode="on",
        protocol_version=VERIFY_AGENT_PROTOCOL_VERSION,
        config_digest=config_digest,
        initial_status=initial_status,
        final_status=final_status,
        recommended_status=str(verification.get("recommended_status", final_status)),
        outcome=outcome,
        claim_checks=(
            copy.deepcopy(verification.get("claim_checks", []))
            if isinstance(verification.get("claim_checks"), list)
            else []
        ),
        coverage_status=str(verification.get("coverage_status", "uncertain")),
        coverage_reason=str(verification.get("coverage_reason", "")),
        verdict_evidence_ids=(
            list(verification.get("verdict_evidence_ids", []))
            if isinstance(verification.get("verdict_evidence_ids"), list)
            else []
        ),
        reason=str(verification.get("reason", "")),
        sessions=compact_sessions,
        repair=repair,
        full={"sessions": full_sessions},
        transcript=transcript,
        usage=usage,
        error=str(final_report.get("error", ""))[:4000],
    )


def _verification_repair_guidance(
    candidate: dict[str, Any],
    cited_evidence: list[dict[str, Any]],
    session: VerificationSession,
) -> dict[str, Any]:
    report = session.report()
    verification = report.get("verification")
    verification = verification if isinstance(verification, dict) else {}
    contradicted_checks = [
        copy.deepcopy(item)
        for item in verification.get("claim_checks", [])
        if isinstance(item, dict) and item.get("relation") == "contradicted"
    ]
    cited_by_id = {
        str(item.get("evidence_id", "")): item
        for item in cited_evidence
        if isinstance(item, dict)
    }
    verifier_by_id = {
        str(item.get("evidence_id", "")): item
        for item in session.evidence_ledger
        if isinstance(item, dict) and item.get("evidence_id")
    }

    def compact_verifier_evidence(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "evidence_id": str(item.get("evidence_id", "")),
            "phase": str(item.get("phase", "")),
            "target_evidence_id": str(item.get("target_evidence_id", "")),
            "ok": item.get("ok") is True,
            "excerpt": [
                str(line)[:4000]
                for line in item.get("excerpt", [])[:12]
                if isinstance(line, str) and line.strip()
            ],
        }

    findings: list[dict[str, Any]] = []
    for check in contradicted_checks:
        evidence_id = str(check.get("evidence_id", ""))
        source = cited_by_id.get(evidence_id, {})
        verifier_items = [
            compact_verifier_evidence(verifier_by_id[str(verifier_id)])
            for verifier_id in check.get("verifier_evidence_ids", [])
            if str(verifier_id) in verifier_by_id
        ]
        findings.append({
            "evidence_id": evidence_id,
            "reason": str(check.get("reason", "")),
            "main_address_ranges": copy.deepcopy(source.get("address_ranges", [])),
            "verifier_evidence": verifier_items,
        })
    verdict_evidence = [
        compact_verifier_evidence(verifier_by_id[str(verifier_id)])
        for verifier_id in verification.get("verdict_evidence_ids", [])
        if str(verifier_id) in verifier_by_id
    ]
    return {
        "ok": False,
        "error": (
            "Independent binary verification contradicted the submitted result. "
            "Reinspect the target once, summarize any main-agent evidence you will cite, "
            "and submit one repaired result."
        ),
        "verification_outcome": "contradicted",
        "recommended_status": str(verification.get("recommended_status", "inconclusive")),
        "coverage_reason": str(verification.get("coverage_reason", "")),
        "reason": str(verification.get("reason", "")),
        "candidate_decisive_addresses": list(candidate.get("decisive_addresses", [])),
        "main_evidence_address_ranges": [
            {
                "evidence_id": str(item.get("evidence_id", "")),
                "address_ranges": copy.deepcopy(item.get("address_ranges", [])),
            }
            for item in cited_evidence
            if isinstance(item, dict)
        ],
        "contradicted_claims": findings,
        "independent_verdict_evidence": verdict_evidence,
        "repair_contract": {
            "run_python_calls_remaining": 1,
            "schema_repairs_remaining": 1,
            "verifier_evidence_is_guidance_only": True,
            "verifier_evidence_cannot_be_cited": True,
        },
    }


def _function_call_output(call_id: str, result: dict[str, Any], *, raw: bool = False) -> dict[str, Any]:
    """Build the function output item fed back into the next Responses turn."""
    payload = result if raw else compact_tool_result_for_model(result)
    return {
        "type": "function_call_output",
        "call_id": call_id,
        "output": compact_json(payload) if isinstance(payload, (dict, list)) else str(payload),
    }


def handle_tool_calls(
    *,
    output_items: list[dict[str, Any]],
    input_items: list[dict[str, Any]],
    transcript: list[dict[str, Any]],
    turn_label: int | str,
    allowed_tools: dict[str, Any],
) -> PendingSubmission | None:
    """Dispatch one model response and defer every valid final submission."""
    begin_model_response()
    function_calls = [item for item in output_items if item.get("type") == "function_call"]
    if not function_calls:
        input_items.append({
            "type": "message",
            "role": "user",
            "content": (
                "You must use tools. Summarize any evidence you intend to cite, then call "
                "submit_detection_result; plain text is not a valid final answer."
            ),
        })
        return None

    for call_index, call in enumerate(function_calls, 1):
        bump_metric("tool_calls")
        fn = call.get("name")
        raw_args = call.get("arguments") or "{}"
        summary_metrics_before: tuple[int, int] | None = None
        if fn == "summarize_evidence":
            metrics = harness_metrics()
            summary_metrics_before = (
                metrics["evidence_summary_calls"],
                metrics["evidence_summary_failures"],
            )
        call_id = call.get("call_id") or call.get("id") or ""
        try:
            call_args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            if not isinstance(call_args, dict):
                raise ValueError("tool arguments must be a JSON object")
            if fn not in allowed_tools:
                result = {"ok": False, "error": f"tool not available in this phase: {fn}"}
                bump_metric("tool_failures")
            else:
                result = allowed_tools[fn](**call_args)
        except Exception as exc:
            result = {"ok": False, "error": repr(exc), "tool": fn, "arguments": raw_args}
            bump_metric("tool_failures")
            if summary_metrics_before is not None:
                current_metrics = harness_metrics()
                if current_metrics["evidence_summary_calls"] == summary_metrics_before[0]:
                    bump_metric("evidence_summary_calls")
                if current_metrics["evidence_summary_failures"] == summary_metrics_before[1]:
                    bump_metric("evidence_summary_failures")
            if fn == "submit_detection_result":
                bump_metric("schema_repair_attempts")

        transcript.append({
            "turn": turn_label,
            "tool": fn,
            "call_index": call_index,
            "arguments": raw_args,
            "result": copy.deepcopy(result),
        })

        if fn == "submit_detection_result" and result.get("ok"):
            return PendingSubmission(
                result=copy.deepcopy(result),
                call=copy.deepcopy(call),
                call_id=str(call_id),
                turn_label=turn_label,
            )

        submit_repair = fn == "submit_detection_result" and not result.get("ok")
        input_items.append(call)
        input_items.append(_function_call_output(call_id, result, raw=submit_repair))
        if fn == "run_python" and isinstance(result.get("evidence"), list):
            mark_evidence_returned(result["evidence"])
    return None


def last_submit_needs_repair(transcript: list[dict[str, Any]]) -> bool:
    if not transcript:
        return False
    last = transcript[-1]
    if last.get("tool") != "submit_detection_result":
        return False
    result = last.get("result")
    if not isinstance(result, dict) or result.get("ok"):
        return False
    return bool(result.get("schema_errors") or (result.get("error") and result.get("tool") == "submit_detection_result"))


def last_tool_call_needs_forced_submit(transcript: list[dict[str, Any]]) -> bool:
    if not transcript:
        return False
    last = transcript[-1]
    if last.get("tool") == "submit_detection_result":
        return last_submit_needs_repair(transcript)
    if last.get("tool") == "summarize_evidence":
        return True
    result = last.get("result")
    return isinstance(result, dict) and not result.get("ok") and "tool not available" in str(result.get("error", ""))


def provider_config(args: argparse.Namespace) -> tuple[str, str, str, ModelProfile]:
    """Resolve the active model profile and apply its non-secret defaults."""
    profile = resolve_profile(args)
    apply_profile_to_args(args, profile)
    return resolve_api_key(profile), args.base_url, args.model, profile


def _sample(
    args: argparse.Namespace,
    instructions: str,
    input_items: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    api_key: str,
    base_url: str,
    model: str,
    profile: ModelProfile,
) -> dict[str, Any]:
    return responses_create(
        instructions=instructions,
        input_items=input_items,
        tools=tools,
        api_key=api_key,
        base_url=base_url,
        model=model,
        timeout=args.api_timeout,
        max_retries=args.api_max_retries,
        reasoning=reasoning_param(profile),
    )


def _sample_turn(
    args: argparse.Namespace,
    instructions: str,
    input_items: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    api_key: str,
    base_url: str,
    model: str,
    profile: ModelProfile,
) -> dict[str, Any]:
    """Retry complete turns to span intermittent upstream outage windows."""
    last_exc: Exception | None = None
    for attempt in range(1, max(1, args.api_turn_retries) + 1):
        try:
            return _sample(args, instructions, input_items, tools, api_key, base_url, model, profile)
        except Exception as exc:
            last_exc = exc
            if attempt == args.api_turn_retries:
                break
            time.sleep(min(20.0 * attempt, 60.0))
    assert last_exc is not None
    raise last_exc


def _extract_output_items(resp: dict[str, Any]) -> list[dict[str, Any]]:
    output = resp.get("output")
    return output if isinstance(output, list) else []


def _nonexecuted_verification_bundle(
    args: argparse.Namespace,
    status: str,
    settings: ResolvedVerifyAgentSettings | None,
    *,
    reason: str,
) -> dict[str, Any]:
    if args.verify_agent == "off":
        return verification_off_bundle(status)
    if settings is None:
        raise ValueError("enabled Verify Agent requires resolved settings")
    return verification_skipped_bundle(
        status,
        protocol_version=VERIFY_AGENT_PROTOCOL_VERSION,
        config_digest=settings.config_digest,
        reason=reason,
    )


def _record_verifier_session_metrics(session: VerificationSession) -> None:
    report = session.report()
    bump_metric("verify_agent_sessions")
    bump_metric("verify_agent_claim_calls", int(report.get("claim_calls", 0) or 0))
    bump_metric("verify_agent_verdict_calls", int(report.get("verdict_calls", 0) or 0))
    outcome = str(report.get("outcome", "unresolved"))
    if outcome == "confirmed":
        bump_metric("verify_agent_confirms")
    elif outcome == "contradicted":
        bump_metric("verify_agent_contradictions")
    else:
        bump_metric("verify_agent_unresolved")
    if report.get("failure_kind"):
        bump_metric("verify_agent_failures")


def verifier_scratch_root(main_scratch: str) -> str:
    """Return a sibling verifier tree that is outside the main /scratch mount."""
    path = os.path.abspath(main_scratch)
    return f"{path}-verification"


def _run_verify_session(
    *,
    settings: ResolvedVerifyAgentSettings,
    metadata: dict[str, Any],
    candidate: dict[str, Any],
    cited_evidence: list[dict[str, Any]],
    binary: str,
    scratch: str,
) -> VerificationSession:
    started = time.time()
    try:
        session = VerifyAgentSession(
            config=settings.config,
            metadata=metadata,
            candidate=candidate,
            cited_evidence=cited_evidence,
            binary_path=binary,
            # Keep verifier scripts outside the main Agent's /scratch bind mount.
            # A sibling tree remains available for artifacts but cannot be read by
            # the one-shot main repair inspection.
            scratch_root=verifier_scratch_root(scratch),
        )
    except Exception as exc:
        failed = FailedVerifyAgentSession(
            settings,
            candidate,
            repr(exc),
            round(time.time() - started, 3),
        )
        _record_verifier_session_metrics(failed)
        return failed
    try:
        session.run()
    except Exception as exc:  # Defensive: verifier failure must not discard the main result.
        error = repr(exc)
        session.outcome = "unresolved"
        session.failure_kind = "internal_failure"
        session.error = error
        session.wall_seconds = round(time.time() - started, 3)
        session.verification = {
            "action": "unresolved",
            "claim_checks": [
                {
                    "evidence_id": str(evidence_id),
                    "relation": "insufficient",
                    "decisive": False,
                    "verifier_evidence_ids": [],
                    "reason": "Verify Agent failed before this claim could be checked.",
                }
                for evidence_id in candidate.get("evidence_ids", [])
            ],
            "coverage_status": "uncertain",
            "coverage_reason": "Verify Agent failed before completing its independent checks.",
            "recommended_status": str(candidate.get("status", "inconclusive")),
            "verdict_evidence_ids": [],
            "reason": f"Verify Agent internal failure: {error}"[:2400],
        }
    _record_verifier_session_metrics(session)
    return session


def _run_verification_repair(
    *,
    args: argparse.Namespace,
    instructions: str,
    input_items: list[dict[str, Any]],
    transcript: list[dict[str, Any]],
    initial_submission: PendingSubmission,
    initial_cited_evidence: list[dict[str, Any]],
    verification_session: VerificationSession,
    tools: list[dict[str, Any]],
    api_key: str,
    base_url: str,
    model: str,
    profile: ModelProfile,
) -> tuple[PendingSubmission | None, dict[str, Any], str]:
    repair = {
        "requested": True,
        "run_python_calls": 0,
        "schema_repairs": 0,
        "resubmitted": False,
        "reverified": False,
    }
    bump_metric("verify_agent_main_repairs")
    guidance = _verification_repair_guidance(
        initial_submission.result,
        initial_cited_evidence,
        verification_session,
    )
    input_items.append(copy.deepcopy(initial_submission.call))
    input_items.append(
        _function_call_output(initial_submission.call_id, guidance, raw=True)
    )
    transcript.append({
        "stage": "verification_repair_requested",
        "submission_turn": initial_submission.turn_label,
        "guidance": copy.deepcopy(guidance),
    })

    def one_shot_run_python(**kwargs: Any) -> dict[str, Any]:
        if repair["run_python_calls"] >= 1:
            return {
                "ok": False,
                "error": "verification repair permits at most one run_python call",
            }
        repair["run_python_calls"] += 1
        return TOOL_FUNCS["run_python"](**kwargs)

    repair_tools = dict(FINALIZATION_TOOL_FUNCS)
    repair_tools["run_python"] = one_shot_run_python
    invalid_submit_attempts = 0
    for repair_turn in range(1, 5):
        inspection_open = (
            repair["run_python_calls"] == 0 and repair["schema_repairs"] == 0
        )
        exposed_tools = tools if inspection_open else finalization_tools(tools)
        allowed_tools = repair_tools if inspection_open else FINALIZATION_TOOL_FUNCS
        turn_label = f"verify-repair-{repair_turn}"
        try:
            response = _sample_turn(
                args,
                instructions,
                input_items,
                exposed_tools,
                api_key,
                base_url,
                model,
                profile,
            )
        except Exception as exc:
            error = repr(exc)
            transcript.append({
                "turn": turn_label,
                "stage": "verification_repair_api_failure",
                "error": error,
            })
            return None, repair, error
        output_items = _extract_output_items(response)
        transcript.append({
            "turn": turn_label,
            "output": output_items,
            "usage": response.get("usage", {}),
        })
        before = len(transcript)
        pending = handle_tool_calls(
            output_items=output_items,
            input_items=input_items,
            transcript=transcript,
            turn_label=turn_label,
            allowed_tools=allowed_tools,
        )
        for item in transcript[before:]:
            if item.get("tool") != "submit_detection_result":
                continue
            result = item.get("result")
            if isinstance(result, dict) and not result.get("ok"):
                invalid_submit_attempts += 1
                repair["schema_repairs"] = min(1, invalid_submit_attempts)
        if invalid_submit_attempts > 1:
            return None, repair, "main-agent repair exceeded one schema repair"
        if pending is not None:
            repair["resubmitted"] = True
            return pending, repair, ""
    return None, repair, "main-agent repair did not produce a valid submission"


def _write_completed_submission(
    *,
    args: argparse.Namespace,
    metadata: dict[str, Any],
    binary: str,
    scratch: str,
    pending: PendingSubmission,
    instructions: str,
    input_items: list[dict[str, Any]],
    transcript: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    api_key: str,
    base_url: str,
    model: str,
    profile: ModelProfile,
    verify_settings: ResolvedVerifyAgentSettings | None,
    start_epoch: float,
) -> dict[str, Any]:
    candidate = pending.result
    initial_status = str(candidate.get("status", "inconclusive"))
    if args.verify_agent == "off":
        return write_run_outputs(
            args.output_dir,
            candidate,
            transcript,
            start_epoch,
            verification_bundle=verification_off_bundle(initial_status),
        )
    if verify_settings is None:
        raise ValueError("enabled Verify Agent requires resolved settings")
    if initial_status == "inconclusive":
        return write_run_outputs(
            args.output_dir,
            candidate,
            transcript,
            start_epoch,
            verification_bundle=_nonexecuted_verification_bundle(
                args,
                initial_status,
                verify_settings,
                reason="Verify Agent skips main-agent inconclusive submissions.",
            ),
        )

    initial_cited = cited_evidence_for_verification(candidate)
    sessions = [
        _run_verify_session(
            settings=verify_settings,
            metadata=metadata,
            candidate=candidate,
            cited_evidence=initial_cited,
            binary=binary,
            scratch=scratch,
        )
    ]
    initial_outcome = str(sessions[0].report().get("outcome", "unresolved"))
    if initial_outcome != "contradicted":
        bundle = _verification_bundle_from_sessions(
            sessions=sessions,
            config_digest=verify_settings.config_digest,
            initial_status=initial_status,
            final_status=initial_status,
        )
        return write_run_outputs(
            args.output_dir,
            candidate,
            transcript,
            start_epoch,
            verification_bundle=bundle,
        )

    repaired, repair, repair_error = _run_verification_repair(
        args=args,
        instructions=instructions,
        input_items=input_items,
        transcript=transcript,
        initial_submission=pending,
        initial_cited_evidence=initial_cited,
        verification_session=sessions[0],
        tools=tools,
        api_key=api_key,
        base_url=base_url,
        model=model,
        profile=profile,
    )
    if repaired is None:
        conflict = conflicting_evidence_result(
            metadata,
            binary,
            repair_error or "Independent verification contradicted the submitted evidence.",
        )
        bundle = _verification_bundle_from_sessions(
            sessions=sessions,
            config_digest=verify_settings.config_digest,
            initial_status=initial_status,
            final_status="inconclusive",
            repair=repair,
            force_outcome="contradicted",
        )
        return write_run_outputs(
            args.output_dir,
            conflict,
            transcript,
            start_epoch,
            verification_bundle=bundle,
        )

    if repaired.result.get("status") == "inconclusive":
        bundle = _verification_bundle_from_sessions(
            sessions=sessions,
            config_digest=verify_settings.config_digest,
            initial_status=initial_status,
            final_status="inconclusive",
            repair=repair,
            force_outcome="contradicted",
        )
        return write_run_outputs(
            args.output_dir,
            repaired.result,
            transcript,
            start_epoch,
            verification_bundle=bundle,
        )

    repaired_candidate = repaired.result
    repair["reverified"] = True
    bump_metric("verify_agent_rechecks")
    repaired_cited = cited_evidence_for_verification(repaired_candidate)
    sessions.append(
        _run_verify_session(
            settings=verify_settings,
            metadata=metadata,
            candidate=repaired_candidate,
            cited_evidence=repaired_cited,
            binary=binary,
            scratch=scratch,
        )
    )
    final_outcome = str(sessions[-1].report().get("outcome", "unresolved"))
    if final_outcome == "contradicted":
        verification = sessions[-1].report().get("verification")
        reason = (
            str(verification.get("reason", ""))
            if isinstance(verification, dict)
            else "Independent verification contradicted the repaired result."
        )
        conflict = conflicting_evidence_result(metadata, binary, reason)
        bundle = _verification_bundle_from_sessions(
            sessions=sessions,
            config_digest=verify_settings.config_digest,
            initial_status=initial_status,
            final_status="inconclusive",
            repair=repair,
            force_outcome="contradicted",
        )
        return write_run_outputs(
            args.output_dir,
            conflict,
            transcript,
            start_epoch,
            verification_bundle=bundle,
        )

    final_status = str(repaired_candidate.get("status", "inconclusive"))
    bundle = _verification_bundle_from_sessions(
        sessions=sessions,
        config_digest=verify_settings.config_digest,
        initial_status=initial_status,
        final_status=final_status,
        repair=repair,
    )
    return write_run_outputs(
        args.output_dir,
        repaired_candidate,
        transcript,
        start_epoch,
        verification_bundle=bundle,
    )


def _write_api_failure(
    metadata: dict[str, Any],
    binary: str,
    error: Exception,
    transcript: list[dict[str, Any]],
    turn: int | str,
    output_dir: str,
    start_epoch: float,
    args: argparse.Namespace,
    verify_settings: ResolvedVerifyAgentSettings | None,
) -> int:
    transcript.append({"turn": turn, "stage": "api_failure", "error": repr(error)})
    result = api_failure_fallback_result(metadata, binary, repr(error))
    bundle = _nonexecuted_verification_bundle(
        args,
        "inconclusive",
        verify_settings,
        reason="Verify Agent skipped because the main Agent API failed.",
    )
    print(jdump(write_run_outputs(
        output_dir,
        result,
        transcript,
        start_epoch,
        verification_bundle=bundle,
    )))
    return 1


def run_agent(args: argparse.Namespace) -> int:
    start_epoch = time.time()
    metadata = load_cve_metadata(args)
    try:
        validate_metadata_prompt_input(metadata)
    except ValueError as exc:
        raise SystemExit(f"metadata input rejected: {exc}") from exc
    workspace = prepare_anonymous_binary(args.binary)
    try:
        return _run_agent_body(args, metadata, workspace, start_epoch)
    finally:
        workspace.cleanup()


def _run_agent_body(args: argparse.Namespace, metadata: dict[str, Any], workspace: Any, start_epoch: float) -> int:
    binary = str(workspace.binary_path)
    metadata_hash = metadata_sha256(metadata, str(metadata.get("cve_id") or args.cve_id) or None)
    scratch = str(expand(args.output_dir) / "scratch") if args.output_dir else tempfile.mkdtemp(prefix="claudeagent-scratch-")
    os.makedirs(scratch, exist_ok=True)
    profile = resolve_profile(args)
    apply_profile_to_args(args, profile)
    verify_settings = (
        resolve_verify_agent_settings(args, main_profile=profile)
        if args.verify_agent == "on"
        else None
    )
    preflight = preflight_detection_inputs(binary, metadata)
    initialize_agent_context(
        metadata,
        binary,
        args.cve_id,
        args.output_dir,
        scratch,
        metadata_sha256=metadata_hash,
    )
    transcript: list[dict[str, Any]] = [
        {"stage": "host_preflight", "result": preflight},
        {"stage": "metadata_input", "metadata_sha256": metadata_hash},
    ]
    if not preflight.get("ok"):
        result = preflight_missing_result(metadata, binary, preflight)
        bundle = _nonexecuted_verification_bundle(
            args,
            "inconclusive",
            verify_settings,
            reason="Verify Agent skipped because Host preflight failed.",
        )
        print(jdump(write_run_outputs(
            args.output_dir,
            result,
            transcript,
            start_epoch,
            verification_bundle=bundle,
        )))
        return 1

    load_env_files(args.env_file)
    if args.import_interactive_env:
        keys = interactive_env_keys(profile)
        if verify_settings is not None:
            keys.append(verify_settings.api_key_env)
        import_env_from_interactive_shell(sorted(set(keys)))
    api_key, base_url, model, profile = provider_config(args)
    if not api_key:
        raise SystemExit(
            f"API key for profile {profile.name!r} is not set (env var {profile.api_key_env!r}). "
            "Use --dry-run for local validation only."
        )
    if args.verify_agent == "on":
        try:
            verify_settings = resolve_verify_agent_settings(
                args,
                main_profile=profile,
                require_api_key=True,
            )
        except ValueError as exc:
            raise SystemExit(f"verify-agent model config error: {exc}") from exc

    instructions = SYSTEM_PROMPT.read_text()
    task_content = build_task(metadata, binary, preflight)
    tools = load_tools(strict=not args.no_strict)
    input_items: list[dict[str, Any]] = [{"type": "message", "role": "user", "content": task_content}]

    def complete(pending: PendingSubmission) -> dict[str, Any]:
        return _write_completed_submission(
            args=args,
            metadata=metadata,
            binary=binary,
            scratch=scratch,
            pending=pending,
            instructions=instructions,
            input_items=input_items,
            transcript=transcript,
            tools=tools,
            api_key=api_key,
            base_url=base_url,
            model=model,
            profile=profile,
            verify_settings=verify_settings,
            start_epoch=start_epoch,
        )

    for turn in range(1, args.max_turns + 1):
        try:
            resp = _sample_turn(args, instructions, input_items, tools, api_key, base_url, model, profile)
        except Exception as exc:
            return _write_api_failure(
                metadata,
                binary,
                exc,
                transcript,
                turn,
                args.output_dir,
                start_epoch,
                args,
                verify_settings,
            )
        output_items = _extract_output_items(resp)
        transcript.append({"turn": turn, "output": output_items, "usage": resp.get("usage", {})})
        if args.verbose:
            print(f"\n--- model turn {turn} ---", file=sys.stderr)
            print(jdump(output_items), file=sys.stderr)
        pending = handle_tool_calls(
            output_items=output_items,
            input_items=input_items,
            transcript=transcript,
            turn_label=turn,
            allowed_tools=TOOL_FUNCS,
        )
        if pending is not None:
            print(jdump(complete(pending)))
            return 0

    if args.finalize_on_max_turns:
        append_finalization_prompt(input_items, args.max_turns)
        for finalize_turn in range(1, args.finalization_turns + 1):
            remaining = args.finalization_turns - finalize_turn
            if finalize_turn > 1:
                append_finalization_budget_prompt(input_items, remaining + 1)
            turn_tools = finalization_tools(tools) if remaining == 0 else tools
            allowed_tools = FINALIZATION_TOOL_FUNCS if remaining == 0 else TOOL_FUNCS
            turn_label = f"finalize-{finalize_turn}"
            try:
                resp = _sample_turn(args, instructions, input_items, turn_tools, api_key, base_url, model, profile)
            except Exception as exc:
                return _write_api_failure(
                    metadata,
                    binary,
                    exc,
                    transcript,
                    turn_label,
                    args.output_dir,
                    start_epoch,
                    args,
                    verify_settings,
                )
            output_items = _extract_output_items(resp)
            transcript.append({"turn": turn_label, "output": output_items, "usage": resp.get("usage", {})})
            if args.verbose:
                print(f"\n--- model {turn_label} ---", file=sys.stderr)
                print(jdump(output_items), file=sys.stderr)
            pending = handle_tool_calls(
                output_items=output_items,
                input_items=input_items,
                transcript=transcript,
                turn_label=turn_label,
                allowed_tools=allowed_tools,
            )
            if pending is not None:
                print(jdump(complete(pending)))
                return 0

        for repair_turn in range(1, 3):
            if not last_tool_call_needs_forced_submit(transcript):
                break
            input_items.append({"type": "message", "role": "user", "content": repair_finalization_prompt()})
            turn_label = f"repair-{repair_turn}"
            try:
                resp = _sample_turn(
                    args,
                    instructions,
                    input_items,
                    finalization_tools(tools),
                    api_key,
                    base_url,
                    model,
                    profile,
                )
            except Exception as exc:
                return _write_api_failure(
                    metadata,
                    binary,
                    exc,
                    transcript,
                    turn_label,
                    args.output_dir,
                    start_epoch,
                    args,
                    verify_settings,
                )
            output_items = _extract_output_items(resp)
            transcript.append({"turn": turn_label, "output": output_items, "usage": resp.get("usage", {})})
            pending = handle_tool_calls(
                output_items=output_items,
                input_items=input_items,
                transcript=transcript,
                turn_label=turn_label,
                allowed_tools=FINALIZATION_TOOL_FUNCS,
            )
            if pending is not None:
                print(jdump(complete(pending)))
                return 0

    result = max_turns_fallback_result(metadata, binary, args.max_turns)
    bundle = _nonexecuted_verification_bundle(
        args,
        "inconclusive",
        verify_settings,
        reason="Verify Agent skipped because the main Agent did not submit a determinate result.",
    )
    print(jdump(write_run_outputs(
        args.output_dir,
        result,
        transcript,
        start_epoch,
        verification_bundle=bundle,
    )))
    return 0


def dry_run(args: argparse.Namespace) -> int:
    metadata = load_cve_metadata(args)
    try:
        validate_metadata_prompt_input(metadata)
    except ValueError as exc:
        raise SystemExit(f"metadata input rejected: {exc}") from exc
    metadata_hash = metadata_sha256(metadata, str(metadata.get("cve_id") or args.cve_id) or None)
    workspace = prepare_anonymous_binary(args.binary)
    try:
        binary = str(workspace.binary_path)
        tools = load_tools(strict=not args.no_strict)
        load_final_result_schema()
        preflight = preflight_detection_inputs(binary, metadata)
        _, base_url, model, profile = provider_config(args)
        verify_settings = (
            resolve_verify_agent_settings(args, main_profile=profile)
            if args.verify_agent == "on"
            else None
        )
        task_content = build_task(metadata, binary, preflight)
        initialize_agent_context(metadata, binary, args.cve_id, metadata_sha256=metadata_hash)
        print("TOOLS_OK", len(tools), [tool["name"] for tool in tools])
        print("FINAL_RESULT_SCHEMA_OK", FINAL_RESULT_SCHEMA)
        print("MODEL_PROFILE", profile.name)
        print("MODEL", model)
        print("BASE_URL", base_url)
        print("REASONING_EFFORT", profile.reasoning_effort)
        print("REASONING_MODE", profile.reasoning_mode)
        print("VERIFY_AGENT", args.verify_agent)
        if verify_settings is not None:
            print("VERIFY_MODEL_PROFILE", verify_settings.profile_name)
            print("VERIFY_MODEL", verify_settings.config.model)
            print("VERIFY_CONFIG_DIGEST", verify_settings.config_digest)
            print("VERIFY_CLAIM_CALLS", "N cited evidence items")
            print("VERIFY_VERDICT_CALLS", verify_settings.config.verdict_calls)
        print("METADATA_SHA256", metadata_hash)
        print("SYSTEM_PROMPT_CHARS", len(SYSTEM_PROMPT.read_text()))
        print("TASK_CHARS", len(task_content))
        print("SANDBOX_PREFLIGHT")
        print(jdump(preflight_sandbox()))
        print("HOST_PREFLIGHT")
        print(jdump(preflight))
        return 0
    finally:
        workspace.cleanup()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="claudeagent single-case patch-presence detection")
    parser.add_argument("--cve-id", default="")
    parser.add_argument("--cve-json", default="", help="path to a single CVE metadata JSON object")
    parser.add_argument("--cve-inline-json", default="", help="inline CVE metadata JSON object")
    parser.add_argument("--metadata-json", default="", help="path to a metadata map/list; needs --cve-id")
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--model", default="", help="override the config profile's model")
    parser.add_argument("--base-url", default="", help="override the config profile's base_url")
    parser.add_argument("--model-profile", default="", help="config profile name or alias")
    parser.add_argument("--env-file", default="")
    parser.add_argument("--import-interactive-env", action="store_true")
    parser.add_argument("--no-strict", action="store_true", help="drop tool strict flags")
    parser.add_argument("--reasoning-effort", default="low", help="override the profile effort")
    parser.add_argument("--max-turns", type=int, default=20)
    parser.add_argument("--finalize-on-max-turns", action="store_true", default=True)
    parser.add_argument("--no-finalize-on-max-turns", dest="finalize_on_max_turns", action="store_false")
    parser.add_argument("--finalization-turns", type=int, default=3)
    parser.add_argument("--api-timeout", type=int, default=240)
    parser.add_argument("--api-max-retries", type=int, default=3)
    parser.add_argument("--api-turn-retries", type=int, default=1)
    parser.add_argument("--verify-agent", choices=["on", "off"], default="on")
    parser.add_argument(
        "--verify-model-profile",
        default="",
        help="independent verifier profile; defaults to the effective main profile",
    )
    parser.add_argument(
        "--verify-verdict-calls",
        type=int,
        default=5,
        help="maximum verifier whole-verdict run_python calls after claim checks",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        profile = resolve_profile(args)
        if args.verify_agent == "on":
            resolve_verify_agent_settings(args, main_profile=profile)
    except ValueError as exc:
        raise SystemExit(f"model config error: {exc}") from exc
    return dry_run(args) if args.dry_run else run_agent(args)


if __name__ == "__main__":
    raise SystemExit(main())
