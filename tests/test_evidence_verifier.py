"""Offline tests for the independent LLM evidence-verification stage.

    python3 -m claudeagent.tests.test_evidence_verifier
"""

from __future__ import annotations

import json
import sys

from claudeagent.evidence_verifier import (
    MAX_VERIFIER_PAYLOAD_CHARS,
    EvidenceVerifierConfig,
    EvidenceVerifierSession,
    build_verifier_payload,
    validate_verification,
)
from claudeagent.finalize import (
    build_final_artifact,
    submit_detection_result,
    validate_final_result_artifact,
    verify_detection_result,
    verifier_pending_fallback_result,
)
from claudeagent.runtime import (
    AGENT_CONTEXT,
    configure_evidence_verifier,
    initialize_agent_context,
    record_evidence,
)


PATCH_SPEC = {
    "schema_version": "patchspec.v1",
    "source": {"cve_id": "CVE-TEST", "project": "curl", "metadata_sha256": "abc"},
    "hunks": [{"hunk_id": "H001", "header": "boundary check"}],
    "anchors": [{"anchor_id": "A001", "kind": "function", "value": "tailmatch"}],
    "behaviors": [{
        "behavior_id": "B001",
        "required": True,
        "hunk_ids": ["H001"],
        "function_anchor_ids": ["A001"],
        "trusted": {
            "old_indicators": [{"kind": "source_line", "ref": "/old/0"}],
            "new_indicators": [{"kind": "source_line", "ref": "/new/0"}],
        },
        "advisory": {
            "security_invariant": "A match must respect the label boundary.",
            "old_semantics": "Suffix equality alone accepts the value.",
            "new_semantics": "A preceding boundary is also required.",
            "compiler_equivalent_forms": [],
            "applicability": [],
        },
    }],
}
SOURCE_EXCERPTS = [
    {"ref": "/old/0", "value": "return suffix_equal();"},
    {"ref": "/new/0", "value": "return boundary && suffix_equal();"},
]


def _support(evidence_id: str, *, side: str = "new") -> dict:
    return {
        "support_id": "sup_0001",
        "behavior_id": "B001",
        "observed_side": side,
        "summary": "The bounded target code implements the boundary guard.",
        "evidence_ids": [evidence_id],
        "decisive_addresses": ["0x1010"],
    }


def _candidate(evidence_id: str, *, side: str = "new") -> dict:
    support = _support(evidence_id, side=side)
    return {
        "schema_version": "final_result.v3",
        "status": "present" if side == "new" else "absent",
        "confidence": "high",
        "supports": [support],
        "claim": {
            "summary": "The required behavior is established by the cited target code.",
            "support_ids": ["sup_0001"],
            "unresolved_behavior_ids": [],
        },
        "verdict": {
            "status": "present" if side == "new" else "absent",
            "rule": "all_applicable_required_new" if side == "new" else "required_old_behavior",
            "behavior_claims": [{
                "behavior_id": "B001",
                "required": True,
                "resolved_side": side,
                "resolution": "consistent",
                "support_ids": ["sup_0001"],
            }],
        },
    }


def _verification(evidence_id: str, *, action: str) -> dict:
    if action == "accept":
        return {
            "action": "accept",
            "claim_relation": "supported",
            "support_checks": [{
                "support_id": "sup_0001",
                "checked_evidence_ids": [evidence_id],
                "relation": "direct",
                "assessed_side": "new",
                "reason": "The cited guard and branch directly implement the NEW behavior.",
            }],
            "missing_behavior_ids": [],
            "repair_instruction": "",
        }
    return {
        "action": "repair",
        "claim_relation": "insufficient",
        "support_checks": [{
            "support_id": "sup_0001",
            "checked_evidence_ids": [evidence_id],
            "relation": "insufficient",
            "assessed_side": "ambiguous",
            "reason": "The excerpt localizes the code but does not show the claimed boundary guard.",
        }],
        "missing_behavior_ids": [],
        "repair_instruction": "Bind the support to evidence that shows the guard, or submit inconclusive.",
    }


def _response(verification: dict, *, tokens: int = 10) -> dict:
    return {
        "output": [{
            "type": "function_call",
            "call_id": "call_verify",
            "name": "submit_evidence_verification",
            "arguments": json.dumps(verification),
        }],
        "usage": {
            "input_tokens": tokens,
            "output_tokens": 2,
            "total_tokens": tokens + 2,
        },
    }


def _config(*, strict: bool = True) -> EvidenceVerifierConfig:
    return EvidenceVerifierConfig(
        api_key="test-key",
        base_url="https://example.invalid/v1",
        model="gpt-5.5",
        reasoning={"effort": "medium"},
        timeout=1,
        max_retries=1,
        strict=strict,
    )


def _run() -> int:
    failures: list[str] = []

    def check(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    evidence = {
        "evidence_id": "ev_0001",
        "observation_id": "obs_0001",
        "kind": "semantic_probe",
        "claim": "NEW-side discriminator matched.",
        "supporting_excerpt": ["Authorization: Digest", "0x1010: cmp eax,1"],
        "location": {"behavior_id": "B001", "matched_side": "new_only"},
        "confidence": "supporting",
        "polarity": "positive",
    }
    uncited = {
        "evidence_id": "ev_9999",
        "observation_id": "obs_9999",
        "kind": "command_output",
        "claim": "UNCITED_LEDGER_SECRET",
        "supporting_excerpt": ["UNCITED_LEDGER_SECRET"],
        "location": {},
        "confidence": "supporting",
        "polarity": "positive",
    }
    observation = {
        "observation_id": "obs_0001",
        "tool": "run_semantic_probe",
        "command": ["objdump", "/host/SECRET_BINARY_PATH"],
        "command_text": "objdump /host/SECRET_BINARY_PATH",
        "ok": True,
        "exit_code": 0,
        "stdout_head": "0x1010: cmp eax,1",
        "stdout_tail": "0x1014: jne 0x1020",
        "stderr_tail": "",
        "truncated": False,
        "parsed_facts": {
            "probe_definition": {"new_expectation": ["cmp", "jne"]},
            "matched_side": "new_only",
        },
    }
    payload = build_verifier_payload(
        patch_spec=PATCH_SPEC,
        source_excerpts=SOURCE_EXCERPTS,
        candidate=_candidate("ev_0001"),
        evidence_ledger=[evidence, uncited],
        observations=[observation, {"observation_id": "obs_9999", "stdout_head": "SECRET"}],
    )
    rendered = json.dumps(payload, ensure_ascii=False)
    check("uncited ledger omitted", "UNCITED_LEDGER_SECRET" not in rendered and "ev_9999" not in rendered)
    check("host command/path omitted", "command_text" not in rendered and "SECRET_BINARY_PATH" not in rendered)
    check("WAF-sensitive evidence encoded", "Authorization: Digest" not in rendered and "b64:" in rendered)
    check("probe definition retained", "probe_definition" in rendered and "new_expectation" in rendered)
    check("PatchSpec source identity omitted", "CVE-TEST" not in rendered and "metadata_sha256" not in rendered)

    oversized = dict(evidence)
    oversized["supporting_excerpt"] = ["X" * 120_000]
    bounded_payload = build_verifier_payload(
        patch_spec=PATCH_SPEC,
        source_excerpts=SOURCE_EXCERPTS,
        candidate=_candidate("ev_0001"),
        evidence_ledger=[oversized],
        observations=[observation],
    )
    bounded_rendered = json.dumps(bounded_payload, ensure_ascii=False, separators=(",", ":"))
    check("ledger evidence is bounded", len(bounded_rendered) <= MAX_VERIFIER_PAYLOAD_CHARS)
    check("oversized evidence is truncated", "X" * 120_000 not in bounded_rendered)

    bad = _verification("ev_WRONG", action="accept")
    check(
        "evidence set mismatch rejected",
        any("exactly match" in item for item in validate_verification(bad, _candidate("ev_0001"))),
    )
    reversed_side = _verification("ev_0001", action="accept")
    reversed_side["support_checks"][0]["assessed_side"] = "old"
    check(
        "assessed side mismatch rejects accept",
        any("accept requires" in item for item in validate_verification(reversed_side, _candidate("ev_0001"))),
    )

    calls: list[dict] = []

    def accept_client(**kwargs):
        calls.append(kwargs)
        return _response(_verification("ev_0001", action="accept"))

    session = EvidenceVerifierSession(
        mode="llm",
        config=_config(strict=False),
        patch_spec=PATCH_SPEC,
        source_excerpts=SOURCE_EXCERPTS,
        client=accept_client,
    )
    accepted = session.verify(
        _candidate("ev_0001"),
        evidence_ledger=[evidence],
        observations=[observation],
    )
    check("valid verifier accept", accepted.get("decision") == "accept" and session.final_outcome == "accepted")
    check("fresh required-tool request", calls and calls[0].get("tool_choice") == "required" and calls[0].get("store") is False)
    check("no-strict respected", calls and "strict" not in calls[0]["tools"][0])
    check("accept usage recorded", session.usage_summary()["totals"].get("input_tokens") == 10)

    repair_responses = [
        _response(_verification("ev_0001", action="repair"), tokens=3),
        _response(_verification("ev_0001", action="accept"), tokens=4),
    ]
    repaired_session = EvidenceVerifierSession(
        mode="llm",
        config=_config(),
        patch_spec=PATCH_SPEC,
        source_excerpts=SOURCE_EXCERPTS,
        client=lambda **kwargs: repair_responses.pop(0),
    )
    first = repaired_session.verify(_candidate("ev_0001"), evidence_ledger=[evidence], observations=[observation])
    second = repaired_session.verify(_candidate("ev_0001"), evidence_ledger=[evidence], observations=[observation])
    check("one repair then accept", first.get("decision") == "repair" and second.get("decision") == "accept")
    check("accepted-after-repair audit", repaired_session.final_outcome == "accepted_after_repair")
    check("verifier usage merged", repaired_session.usage_summary()["totals"].get("input_tokens") == 7)

    reject_responses = [
        _response(_verification("ev_0001", action="repair")),
        _response(_verification("ev_0001", action="repair")),
    ]
    rejected_session = EvidenceVerifierSession(
        mode="llm",
        config=_config(),
        patch_spec=PATCH_SPEC,
        source_excerpts=SOURCE_EXCERPTS,
        client=lambda **kwargs: reject_responses.pop(0),
    )
    rejected_session.verify(_candidate("ev_0001"), evidence_ledger=[evidence], observations=[observation])
    rejected = rejected_session.verify(_candidate("ev_0001"), evidence_ledger=[evidence], observations=[observation])
    check("second rejection fails closed", rejected == {
        "decision": "fail_closed",
        "reason": "conflicting_evidence",
        "summary": "Independent evidence verification rejected the repaired determinate claim; the cited evidence remains conflicting or insufficient.",
    })

    failed_session = EvidenceVerifierSession(
        mode="llm",
        config=_config(),
        patch_spec=PATCH_SPEC,
        source_excerpts=SOURCE_EXCERPTS,
        client=lambda **kwargs: (_ for _ in ()).throw(RuntimeError("offline")),
    )
    failed = failed_session.verify(_candidate("ev_0001"), evidence_ledger=[evidence], observations=[observation])
    check("API failure fails closed", failed.get("reason") == "tool_failure" and failed_session.final_outcome == "tool_failure")

    no_call = lambda **kwargs: (_ for _ in ()).throw(AssertionError("verifier should not run"))
    off_session = EvidenceVerifierSession("off", _config(), PATCH_SPEC, SOURCE_EXCERPTS, client=no_call)
    check("off skips model", off_session.verify(_candidate("ev_0001"), evidence_ledger=[], observations=[])["decision"] == "accept")
    inconclusive_session = EvidenceVerifierSession("llm", _config(), PATCH_SPEC, SOURCE_EXCERPTS, client=no_call)
    check(
        "inconclusive skips model",
        inconclusive_session.verify({"status": "inconclusive"}, evidence_ledger=[], observations=[])["decision"] == "accept"
        and inconclusive_session.final_outcome == "skipped_inconclusive",
    )

    # Finalization integration: first semantic rejection repairs; the second
    # rejection returns a canonical inconclusive artifact instead of guessing.
    initialize_agent_context(
        {"cve_id": "CVE-TEST", "project": "curl"},
        "/anonymous/target_binary",
        patch_spec={"behaviors": [{"behavior_id": "B001", "required": True}]},
        evidence_verifier_mode="llm",
    )
    ev = record_evidence(
        observation_id="obs_0001",
        kind="disassembly_predicates",
        claim="guard",
        excerpts=["0x1010: cmp eax,1"],
    )
    integration_responses = [
        _response(_verification(ev["evidence_id"], action="repair")),
        _response(_verification(ev["evidence_id"], action="repair")),
    ]
    integration_session = EvidenceVerifierSession(
        mode="llm",
        config=_config(),
        patch_spec=PATCH_SPEC,
        source_excerpts=SOURCE_EXCERPTS,
        client=lambda **kwargs: integration_responses.pop(0),
    )
    configure_evidence_verifier(integration_session)
    support = _support(ev["evidence_id"])
    claim = {
        "summary": "The required behavior is established by the cited target code.",
        "support_ids": ["sup_0001"],
        "unresolved_behavior_ids": [],
    }
    first_submit = verify_detection_result(
        submit_detection_result("present", "high", [support], claim, "none")
    )
    second_submit = verify_detection_result(
        submit_detection_result("present", "high", [support], claim, "none")
    )
    check("submit returns verifier repair", first_submit.get("verifier_repair_required") is True)
    check(
        "submit second rejection is inconclusive",
        second_submit.get("ok") is True
        and second_submit.get("status") == "inconclusive"
        and second_submit.get("inconclusive_reason") == "conflicting_evidence",
    )
    rejected_artifact, rejected_errors = build_final_artifact(second_submit, [], 0.0)
    check("second rejection artifact valid", not rejected_errors)
    check(
        "second rejection audit sequence",
        rejected_artifact.get("evidence_verification", {}).get("outcome")
        == "rejected_after_repair",
    )

    # A verifier/API error is terminal but accurately records ok=false and
    # tool_failure rather than masquerading as an evidence conflict.
    initialize_agent_context(
        {"cve_id": "CVE-TEST", "project": "curl"},
        "/anonymous/target_binary",
        patch_spec={"behaviors": [{"behavior_id": "B001", "required": True}]},
        evidence_verifier_mode="llm",
    )
    ev = record_evidence(
        observation_id="obs_0001",
        kind="disassembly_predicates",
        claim="guard",
        excerpts=["0x1010: cmp eax,1"],
    )
    api_failure_session = EvidenceVerifierSession(
        mode="llm",
        config=_config(),
        patch_spec=PATCH_SPEC,
        source_excerpts=SOURCE_EXCERPTS,
        client=lambda **kwargs: (_ for _ in ()).throw(RuntimeError("offline")),
    )
    configure_evidence_verifier(api_failure_session)
    support = _support(ev["evidence_id"])
    api_failed_submit = verify_detection_result(
        submit_detection_result("present", "high", [support], claim, "none")
    )
    check(
        "verifier API failure is terminal ok=false",
        api_failed_submit.get("_terminal_submit") is True
        and api_failed_submit.get("ok") is False
        and api_failed_submit.get("inconclusive_reason") == "tool_failure",
    )
    api_failed_submit.pop("_terminal_submit", None)
    unused_artifact, api_failure_errors = build_final_artifact(api_failed_submit, [], 0.0)
    check("verifier API failure artifact valid", not api_failure_errors)

    # If the investigator repair turn itself cannot be sampled, preserve the
    # same tool-failure classification and close the pending state.
    pending_responses = [_response(_verification(ev["evidence_id"], action="repair"))]
    pending_session = EvidenceVerifierSession(
        mode="llm",
        config=_config(),
        patch_spec=PATCH_SPEC,
        source_excerpts=SOURCE_EXCERPTS,
        client=lambda **kwargs: pending_responses.pop(0),
    )
    configure_evidence_verifier(pending_session)
    pending = verify_detection_result(
        submit_detection_result("present", "high", [support], claim, "none")
    )
    check("repair pending before sampling failure", pending.get("verifier_repair_required") is True)
    repair_api_failed = verifier_pending_fallback_result(
        AGENT_CONTEXT["metadata"],
        AGENT_CONTEXT["binary_path"],
        error="repair sampling offline",
        inconclusive_reason="tool_failure",
    )
    unused_artifact, repair_api_errors = build_final_artifact(repair_api_failed, [], 0.0)
    check(
        "repair sampling API failure classified",
        repair_api_failed.get("ok") is False
        and repair_api_failed.get("inconclusive_reason") == "tool_failure"
        and not repair_api_errors,
    )

    # Accepted verifier usage is separate from investigator totals in artifacts.
    initialize_agent_context(
        {"cve_id": "CVE-TEST", "project": "curl"},
        "/anonymous/target_binary",
        patch_spec={"behaviors": [{"behavior_id": "B001", "required": True}]},
        evidence_verifier_mode="llm",
    )
    ev = record_evidence(
        observation_id="obs_0001",
        kind="disassembly_predicates",
        claim="guard",
        excerpts=["0x1010: cmp eax,1"],
    )
    accept_session = EvidenceVerifierSession(
        mode="llm",
        config=_config(),
        patch_spec=PATCH_SPEC,
        source_excerpts=SOURCE_EXCERPTS,
        client=lambda **kwargs: _response(_verification(ev["evidence_id"], action="accept"), tokens=11),
    )
    configure_evidence_verifier(accept_session)
    support = _support(ev["evidence_id"])
    accepted_submit = verify_detection_result(
        submit_detection_result("present", "high", [support], claim, "none")
    )
    artifact, artifact_errors = build_final_artifact(
        accepted_submit,
        [{"turn": 1, "usage": {"input_tokens": 3, "output_tokens": 1}}],
        0.0,
    )
    check("verified artifact schema-valid", not artifact_errors)
    check("artifact verifier accepted", artifact.get("evidence_verification", {}).get("outcome") == "accepted")
    check("artifact verifier fingerprinted", len(artifact.get("evidence_verification", {}).get("config_digest", "")) == 64)
    check("investigator usage unchanged", artifact.get("usage_metrics", {}).get("totals", {}).get("input_tokens") == 3)
    check("verifier usage separate", artifact.get("usage_metrics", {}).get("evidence_verifier", {}).get("totals", {}).get("input_tokens") == 11)
    check("verifier not evidence", len(AGENT_CONTEXT.get("evidence_ledger", [])) == 1)
    artifact["evidence_verification"]["attempts"] = []
    check(
        "accepted audit tamper rejected",
        any("accepted verifier report" in item for item in validate_final_result_artifact(artifact)),
    )

    if failures:
        print("EVIDENCE VERIFIER TESTS FAILED:")
        for failure in failures:
            print("  -", failure)
        return 1
    print("EVIDENCE VERIFIER TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
