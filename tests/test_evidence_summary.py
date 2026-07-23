"""Offline tests for main-agent evidence summarization.

    python3 -m claudeagent.tests.test_evidence_summary
"""

from __future__ import annotations

import copy
import sys

from claudeagent.evidence_summary import summarize_evidence
from claudeagent.observations import compact_tool_result_for_model
from claudeagent.runtime import (
    AGENT_CONTEXT,
    begin_model_response,
    harness_metrics,
    initialize_agent_context,
    mark_evidence_returned,
    record_evidence,
)


def _run() -> int:
    failures: list[str] = []

    def check(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    initialize_agent_context(
        {"cve_id": "CVE-TEST", "project": "curl"},
        "/anonymous/target_binary",
    )
    begin_model_response()
    ev1 = record_evidence(
        observation_id="obs_0001",
        kind="disassembly_predicates",
        claim="Host observed command output for the target predicate.",
        excerpts=["0x1010: cmp eax, 16", "0x1013: ja 0x1030"],
        location={"address": "0x1010"},
    )
    ev2 = record_evidence(
        observation_id="obs_0001",
        kind="disassembly_calls",
        claim="Host observed command output for the target call.",
        excerpts=["0x1018: call memcpy"],
        location={"address": "0x1018"},
    )
    ev_other = record_evidence(
        observation_id="obs_0002",
        kind="strings_match",
        claim="Host observed a string match.",
        excerpts=["cookie domain"],
    )
    immutable = {
        item["evidence_id"]: {
            key: copy.deepcopy(item[key])
            for key in (
                "observation_id",
                "kind",
                "host_claim",
                "supporting_excerpt",
                "location",
                "polarity",
            )
        }
        for item in (ev1, ev2, ev_other)
    }
    check(
        "evidence starts pending",
        all(
            item["claim"] == item["host_claim"]
            and item["claim_source"] == "host"
            and item["claim_status"] == "pending"
            and item["claim_revision"] == 0
            and item["created_response_index"] == 1
            and item["returned_response_index"] is None
            for item in (ev1, ev2, ev_other)
        ),
    )

    invisible = summarize_evidence(
        observation_id="obs_0001",
        claims=[{"evidence_id": ev1["evidence_id"], "claim": "A guard controls the copy."}],
    )
    check(
        "unreturned evidence rejected",
        invisible.get("ok") is False and "earlier model response" in invisible.get("error", ""),
    )
    check("visibility failure leaves pending", ev1["claim_status"] == "pending")

    mark_evidence_returned([ev1, ev2, ev_other])
    begin_model_response()
    first = summarize_evidence(
        observation_id="obs_0001",
        claims=[
            {
                "evidence_id": ev1["evidence_id"],
                "claim": "The unsigned length comparison branches around the following copy.",
            },
            {
                "evidence_id": ev2["evidence_id"],
                "claim": "The guarded path reaches the memory-copy call.",
            },
        ],
    )
    check(
        "batch summary succeeds",
        first.get("ok") is True
        and first.get("updated_count") == 2
        and first.get("revision_count") == 0,
    )
    check(
        "summary updates existing evidence",
        len(AGENT_CONTEXT["evidence_ledger"]) == 3
        and [item["evidence_id"] for item in AGENT_CONTEXT["evidence_ledger"]]
        == ["ev_0001", "ev_0002", "ev_0003"]
        and ev1["claim_source"] == "main_agent"
        and ev1["claim_status"] == "summarized"
        and ev1["claim_revision"] == 1
        and ev1["returned_response_index"] == 1
        and ev1["claim_updated_response_index"] == 2,
    )
    check(
        "provenance fields remain immutable",
        all(
            all(item[key] == immutable[item["evidence_id"]][key] for key in immutable[item["evidence_id"]])
            for item in (ev1, ev2, ev_other)
        ),
    )
    compact = compact_tool_result_for_model(first)
    check(
        "summary result is replayable",
        compact.get("tool") == "summarize_evidence"
        and compact.get("evidence", [{}])[0].get("claim_status") == "summarized"
        and compact.get("evidence", [{}])[0].get("host_claim") == ev1["host_claim"],
    )

    idempotent = summarize_evidence(
        observation_id="obs_0001",
        claims=[{"evidence_id": ev1["evidence_id"], "claim": ev1["claim"]}],
    )
    check(
        "same summary is idempotent",
        idempotent.get("idempotent_evidence_ids") == [ev1["evidence_id"]]
        and idempotent.get("updated_count") == 0
        and idempotent.get("revision_count") == 0
        and ev1["claim_revision"] == 1,
    )

    revised = summarize_evidence(
        observation_id="obs_0001",
        claims=[{
            "evidence_id": ev1["evidence_id"],
            "claim": "The length guard controls whether execution reaches the copy call.",
        }],
    )
    check(
        "different summary creates revision",
        revised.get("revision_count") == 1 and ev1["claim_revision"] == 2,
    )

    before_atomic = copy.deepcopy(ev1)
    atomic_failure = summarize_evidence(
        observation_id="obs_0001",
        claims=[
            {"evidence_id": ev1["evidence_id"], "claim": "MUST NOT COMMIT"},
            {"evidence_id": "ev_9999", "claim": "Unknown evidence."},
        ],
    )
    check(
        "batch failure is atomic",
        atomic_failure.get("ok") is False and ev1 == before_atomic,
    )
    cross_observation = summarize_evidence(
        observation_id="obs_0001",
        claims=[{"evidence_id": ev_other["evidence_id"], "claim": "Wrong observation."}],
    )
    check(
        "cross-observation evidence rejected",
        cross_observation.get("ok") is False and "belongs to observation" in cross_observation.get("error", ""),
    )
    duplicate = summarize_evidence(
        observation_id="obs_0001",
        claims=[
            {"evidence_id": ev1["evidence_id"], "claim": "First."},
            {"evidence_id": ev1["evidence_id"], "claim": "Second."},
        ],
    )
    check(
        "duplicate evidence id rejected",
        duplicate.get("ok") is False and "duplicate evidence id" in duplicate.get("error", ""),
    )

    begin_model_response()
    same_response = record_evidence(
        observation_id="obs_0003",
        kind="command_output",
        claim="Host observed the current response output.",
        excerpts=["0x2000: test eax,eax"],
    )
    too_early = summarize_evidence(
        observation_id="obs_0003",
        claims=[{"evidence_id": same_response["evidence_id"], "claim": "The test checks zero."}],
    )
    check(
        "same-response evidence rejected",
        too_early.get("ok") is False and same_response["claim_status"] == "pending",
    )
    mark_evidence_returned([same_response])
    begin_model_response()
    later = summarize_evidence(
        observation_id="obs_0003",
        claims=[{"evidence_id": same_response["evidence_id"], "claim": "The test checks zero."}],
    )
    check(
        "later response can summarize",
        later.get("ok") is True and same_response["claim_status"] == "summarized",
    )

    metrics = harness_metrics()
    check("summary calls counted", metrics["evidence_summary_calls"] == 9)
    check("summary updates counted", metrics["evidence_summary_updates"] == 3)
    check("summary revisions counted", metrics["evidence_summary_revisions"] == 1)
    check("summary failures counted", metrics["evidence_summary_failures"] == 5)

    if failures:
        print("EVIDENCE SUMMARY TESTS FAILED:")
        for failure in failures:
            print("  -", failure)
        return 1
    print("EVIDENCE SUMMARY TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
