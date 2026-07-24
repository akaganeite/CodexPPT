"""Offline checks for direct evidence-cited finalization.

    python3 -m claudeagent.tests.test_finalize
"""

from __future__ import annotations

import tempfile
import time

from claudeagent.finalize import (
    build_final_artifact,
    max_turns_fallback_result,
    submit_detection_result,
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


def _summarized_evidence(*, polarity: str = "positive") -> dict:
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
    })
    return evidence


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
        artifact, errors = build_final_artifact(accepted, [], time.time())
        check("summarized positive evidence accepted", accepted["ok"] and not errors)
        check("artifact uses v6 direct fields", artifact.get("schema_version") == "final_result.v6" and "metadata_sha256" in artifact)
        check("artifact records cited claim", artifact.get("evidence") == [evidence["claim"]])

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

        fallback = max_turns_fallback_result(metadata, "/workspace/binary", 2)
        _, fallback_errors = build_final_artifact(fallback, [], time.time())
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
