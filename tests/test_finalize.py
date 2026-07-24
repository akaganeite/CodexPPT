"""Offline checks for direct evidence-cited finalization.

    python3 -m claudeagent.tests.test_finalize
"""

from __future__ import annotations

import copy
import json
import tempfile
import time
from unittest.mock import patch

from claudeagent.finalize import (
    build_verification_bundle,
    build_final_artifact,
    conflicting_evidence_result,
    max_turns_fallback_result,
    submit_detection_result,
    validate_final_result_artifact,
    verification_conflict_bundle,
    verification_off_bundle,
    verification_skipped_bundle,
    write_run_outputs,
)
from claudeagent.runtime import AGENT_CONTEXT, initialize_agent_context, record_evidence


def _add_observation(observation_id: str) -> None:
    AGENT_CONTEXT["observations"].append({
        "observation_id": observation_id,
        "tool": "run_python",
        "command": ["python3", "-I", "/work/script.py"],
        "command_text": "python3 -I /work/script.py",
        "exit_code": 0,
        "ok": True,
        "stdout_head": "0x1010: cmp eax, 8",
        "stdout_tail": "",
        "stderr_tail": "",
        "truncated": False,
        "truncation": {},
        "parsed_facts": {},
    })


def _summarized_evidence(
    *,
    polarity: str = "positive",
    with_locator: bool = True,
) -> dict:
    _add_observation("obs_0001")
    evidence = record_evidence(
        observation_id="obs_0001",
        kind="disassembly",
        claim="Host captured a comparison in the target binary.",
        excerpts=["0x1010: cmp eax, 8"],
        polarity=polarity,
    )
    evidence.update({
        "claim": "The target comparison enforces the relevant bound.",
        "claim_source": "main_agent",
        "claim_status": "summarized",
        "claim_revision": 1,
        "created_response_index": 1,
        "returned_response_index": 1,
        "claim_updated_response_index": 2,
        "verification_excerpt": ["0x1010: cmp eax, 8"],
        "verification_locators": (
            [{"start": "0x1010", "end": "0x1010"}] if with_locator else []
        ),
    })
    return evidence


def _verification_usage(tokens: int = 17) -> dict:
    return {
        "provider": "openai-responses",
        "model": "gpt-test",
        "model_turns": 1,
        "totals": {"total_tokens": tokens},
        "by_turn": [{"turn": 1, "usage": {"total_tokens": tokens}}],
        "timing": {"wall_seconds": 0.25},
    }


def _verification_session(outcome: str) -> dict:
    return {
        "session_index": 1,
        "outcome": outcome,
        "claim_budget": 1,
        "claim_calls": 1,
        "verdict_budget": 5,
        "verdict_calls": 1,
        "protocol_repairs": 0,
        "failure_kind": "",
        "wall_seconds": 0.25,
    }


def _claim_check(relation: str = "supported") -> dict:
    return {
        "evidence_id": "ev_0001",
        "relation": relation,
        "decisive": True,
        "verifier_evidence_ids": ["vev_0001"],
        "reason": "The verifier independently inspected the cited branch.",
    }


def _executed_verification_bundle(
    outcome: str,
    *,
    final_status: str = "present",
    recommended_status: str | None = None,
) -> dict:
    coverage = "complete" if outcome == "confirmed" else "uncertain"
    return build_verification_bundle(
        mode="on",
        protocol_version="verify_agent.v1",
        config_digest="b" * 64,
        initial_status="present",
        final_status=final_status,
        recommended_status=(
            recommended_status
            if recommended_status is not None
            else final_status
        ),
        outcome=outcome,
        claim_checks=[_claim_check()],
        coverage_status=coverage,
        coverage_reason="The cited behavior was independently revisited.",
        verdict_evidence_ids=["vev_0001"],
        reason="Independent verification completed.",
        sessions=[_verification_session(outcome)],
        full={"sessions": [{"observations": [], "evidence_ledger": []}]},
        transcript=[{"stage": "verification_input"}],
        usage=_verification_usage(),
    )


def _run() -> int:
    failures: list[str] = []

    def check(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    with tempfile.TemporaryDirectory() as tmp:
        metadata = {"cve_id": "CVE-TEST", "project": "demo", "description": "bound check"}
        initialize_agent_context(metadata, "/workspace/binary", "CVE-TEST", tmp, tmp)
        pending = record_evidence(
            observation_id="obs_0001",
            kind="disassembly",
            claim="Host claim",
            excerpts=["0x1010: cmp eax, 8"],
        )
        rejected = submit_detection_result(
            status="present",
            confidence="high",
            evidence_ids=[pending["evidence_id"]],
            reasoning="The target code enforces the bound.",
            decisive_addresses=["0x1010"],
            inconclusive_reason="none",
        )
        check("pending evidence rejected", not rejected["ok"] and "summarized" in str(rejected["schema_errors"]))

        initialize_agent_context(metadata, "/workspace/binary", "CVE-TEST", tmp, tmp)
        no_evidence = submit_detection_result(
            status="present",
            confidence="high",
            evidence_ids=[],
            reasoning="The target code enforces the bound.",
            decisive_addresses=["0x1010"],
            inconclusive_reason="none",
        )
        check("determinate verdict needs evidence", not no_evidence["ok"])

        initialize_agent_context(metadata, "/workspace/binary", "CVE-TEST", tmp, tmp)
        evidence = _summarized_evidence()
        accepted = submit_detection_result(
            status="present",
            confidence="high",
            evidence_ids=[evidence["evidence_id"]],
            reasoning="The comparison at 0x1010 enforces the relevant upper bound.",
            decisive_addresses=["0x1010"],
            inconclusive_reason="none",
        )
        artifact, errors = build_final_artifact(
            accepted,
            [],
            time.time(),
            verification_bundle=verification_off_bundle("present"),
        )
        check("summarized positive evidence accepted", accepted["ok"] and not errors)
        check("artifact uses v7 direct fields", artifact.get("schema_version") == "final_result.v7" and "metadata_sha256" in artifact)
        check(
            "artifact stores compact off verification",
            artifact.get("verification", {}).get("mode") == "off"
            and artifact.get("verification", {}).get("outcome") == "off",
        )
        check("artifact records cited claim", artifact.get("evidence") == [evidence["claim"]])

        unresolved_artifact, unresolved_errors = build_final_artifact(
            accepted,
            [],
            time.time(),
            verification_bundle=_executed_verification_bundle(
                "unresolved",
                recommended_status="inconclusive",
            ),
        )
        check(
            "unresolved verification retains determinate result",
            unresolved_artifact.get("status") == "present" and not unresolved_errors,
        )
        check(
            "verifier usage remains independent",
            unresolved_artifact["verification"]["usage"]["totals"].get("total_tokens") == 17
            and unresolved_artifact["usage_metrics"]["totals"].get("total_tokens", 0) == 0,
        )
        inconsistent_usage = _executed_verification_bundle("unresolved")
        inconsistent_usage["audit"]["usage"]["model_turns"] = 99
        try:
            build_final_artifact(
                accepted,
                [],
                time.time(),
                verification_bundle=inconsistent_usage,
            )
            check("split verifier usage is rejected", False)
        except ValueError:
            check("split verifier usage is rejected", True)

        mismatched_status = copy.deepcopy(unresolved_artifact)
        mismatched_status["verification"]["final_status"] = "absent"
        check(
            "verification final status must match artifact",
            any(
                "must equal the serialized final result status" in error
                for error in validate_final_result_artifact(mismatched_status)
            ),
        )
        invalid_off = copy.deepcopy(artifact)
        invalid_off["verification"]["outcome"] = "confirmed"
        check(
            "off verification rejects executed outcome",
            any(
                "mode=off requires outcome=off" in error
                for error in validate_final_result_artifact(invalid_off)
            ),
        )

        write_order: list[str] = []
        written_payloads: dict[str, object] = {}

        def capture_write(_output_dir: str, name: str, content: str):
            write_order.append(name)
            written_payloads[name] = json.loads(content)
            return None

        executed_bundle = _executed_verification_bundle("confirmed")
        with patch("claudeagent.finalize.write_artifact", side_effect=capture_write):
            written = write_run_outputs(
                tmp,
                accepted,
                [],
                time.time(),
                verification_bundle=executed_bundle,
            )
        check(
            "verification auxiliary artifacts precede final result",
            write_order == [
                "verification.json",
                "verification_transcript.json",
                "verification_usage_metrics.json",
                "transcript.json",
                "usage_metrics.json",
                "final_result.json",
            ],
        )
        check(
            "full verification audit is written separately",
            isinstance(written_payloads.get("verification.json"), dict)
            and written_payloads["verification.json"].get("audit") == written["verification"],
        )
        tampered_confirmed = copy.deepcopy(written)
        tampered_confirmed["verification"]["claim_checks"][0]["relation"] = "insufficient"
        check(
            "confirmed artifact revalidates decisive claim relations",
            any(
                "decisive confirmed claim must be supported" in error
                for error in validate_final_result_artifact(tampered_confirmed)
            ),
        )
        tampered_unresolved = copy.deepcopy(unresolved_artifact)
        tampered_unresolved["verification"]["claim_checks"][0]["relation"] = "contradicted"
        check(
            "unresolved artifact rejects contradicted claims",
            any(
                "unresolved cannot contain a contradicted claim" in error
                for error in validate_final_result_artifact(tampered_unresolved)
            ),
        )
        check(
            "separate verifier usage is preserved",
            written_payloads.get("verification_usage_metrics.json") == executed_bundle["usage"],
        )

        bad_excerpt_artifact = copy.deepcopy(artifact)
        bad_excerpt_artifact["evidence_ledger"][0]["verification_excerpt"] = [
            "0x9999: invented"
        ]
        check(
            "artifact rejects invented verification excerpt",
            any(
                "exact line" in error
                for error in validate_final_result_artifact(bad_excerpt_artifact)
            ),
        )
        inverted_locator_artifact = copy.deepcopy(artifact)
        inverted_locator_artifact["evidence_ledger"][0]["verification_locators"] = [{
            "start": "0x1020",
            "end": "0x1010",
        }]
        check(
            "artifact rejects inverted verification locator",
            any(
                "start must be less than or equal to end" in error
                for error in validate_final_result_artifact(inverted_locator_artifact)
            ),
        )

        initialize_agent_context(metadata, "/workspace/binary", "CVE-TEST", tmp, tmp)
        no_locator = _summarized_evidence(with_locator=False)
        missing_locator = submit_detection_result(
            status="present",
            confidence="high",
            evidence_ids=[no_locator["evidence_id"]],
            reasoning="The target code enforces the bound.",
            decisive_addresses=["0x1010"],
            inconclusive_reason="none",
        )
        check(
            "present verdict requires a verification locator",
            not missing_locator["ok"]
            and "verification address range" in str(missing_locator["schema_errors"]),
        )
        not_affected = submit_detection_result(
            status="not_affected",
            confidence="high",
            evidence_ids=[no_locator["evidence_id"]],
            reasoning="The inspected architecture lacks the affected execution mode.",
            decisive_addresses=[],
            inconclusive_reason="none",
        )
        check("not_affected may cite non-address evidence", not_affected["ok"])

        initialize_agent_context(metadata, "/workspace/binary", "CVE-TEST", tmp, tmp)
        _add_observation("obs_0001")
        too_many: list[dict] = []
        for _index in range(9):
            item = record_evidence(
                observation_id="obs_0001",
                kind="disassembly",
                claim="Host captured a comparison in the target binary.",
                excerpts=["0x1010: cmp eax, 8"],
            )
            item.update({
                "claim": "The target comparison enforces the relevant bound.",
                "claim_source": "main_agent",
                "claim_status": "summarized",
                "claim_revision": 1,
                "created_response_index": 1,
                "returned_response_index": 1,
                "claim_updated_response_index": 2,
                "verification_excerpt": ["0x1010: cmp eax, 8"],
                "verification_locators": [{"start": "0x1010", "end": "0x1010"}],
            })
            too_many.append(item)
        oversized_citation = submit_detection_result(
            status="present",
            confidence="high",
            evidence_ids=[item["evidence_id"] for item in too_many],
            reasoning="The cited target comparisons enforce the relevant bound.",
            decisive_addresses=["0x1010"],
            inconclusive_reason="none",
        )
        check(
            "final citations limited to eight",
            not oversized_citation["ok"] and "at most 8" in str(oversized_citation["schema_errors"]),
        )

        initialize_agent_context(metadata, "/workspace/binary", "CVE-TEST", tmp, tmp)
        negative = _summarized_evidence(polarity="negative")
        only_negative = submit_detection_result(
            status="absent",
            confidence="medium",
            evidence_ids=[negative["evidence_id"]],
            reasoning="No matching anchor was printed.",
            decisive_addresses=[],
            inconclusive_reason="none",
        )
        check("negative-only determinate verdict rejected", not only_negative["ok"])

        inconclusive = submit_detection_result(
            status="inconclusive",
            confidence="low",
            evidence_ids=[],
            reasoning="The stripped target code could not be localized.",
            decisive_addresses=[],
            inconclusive_reason="no_binary_anchor",
        )
        check("inconclusive without citations accepted", inconclusive["ok"])

        conflict_result = conflicting_evidence_result(
            metadata,
            "/workspace/binary",
            "Independent binary evidence contradicted the candidate after one repair attempt.",
        )
        conflict_bundle = verification_conflict_bundle(
            initial_status="present",
            protocol_version="verify_agent.v1",
            config_digest="c" * 64,
            claim_checks=[_claim_check("contradicted")],
            coverage_status="incomplete",
            coverage_reason="A decisive cited claim was contradicted.",
            verdict_evidence_ids=["vev_0001"],
            reason="The contradiction remained after the repair.",
            sessions=[_verification_session("contradicted")],
            repair={
                "requested": True,
                "run_python_calls": 1,
                "schema_repairs": 0,
                "resubmitted": True,
                "reverified": True,
            },
            full={"sessions": [{"observations": [], "evidence_ledger": []}]},
            transcript=[],
            usage=_verification_usage(),
        )
        conflict_artifact, conflict_errors = build_final_artifact(
            conflict_result,
            [],
            time.time(),
            verification_bundle=conflict_bundle,
        )
        check(
            "terminal contradiction records conflict fallback",
            conflict_artifact["status"] == "inconclusive"
            and conflict_artifact["verification"]["outcome"] == "contradicted"
            and not conflict_errors,
        )

        fallback = max_turns_fallback_result(metadata, "/workspace/binary", 2)
        _, fallback_errors = build_final_artifact(
            fallback,
            [],
            time.time(),
            verification_bundle=verification_skipped_bundle(
                "inconclusive",
                protocol_version="verify_agent.v1",
                config_digest="a" * 64,
            ),
        )
        check("fallback artifact validates", not fallback_errors)

    if failures:
        print("FINALIZE TESTS FAILED:")
        for failure in failures:
            print("  -", failure)
        return 1
    print("FINALIZE TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(_run())
