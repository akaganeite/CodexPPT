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


def _add_observation(observation_id: str, lines: list[str]) -> None:
    AGENT_CONTEXT["observations"].append({
        "observation_id": observation_id,
        "tool": "run_python",
        "command": ["python3", "-I", "/work/script.py"],
        "command_text": "python3 -I /work/script.py",
        "exit_code": 0,
        "ok": True,
        "stdout_head": "\n".join(lines),
        "stdout_tail": "",
        "stderr_tail": "",
        "truncated": False,
        "truncation": {},
        "parsed_facts": {},
    })


def _claim(
    evidence_id: str,
    claim: str,
    excerpt: list[str],
    address_ranges: list[dict[str, str]] | None = None,
) -> dict:
    return {
        "evidence_id": evidence_id,
        "claim": claim,
        "excerpt": excerpt,
        "address_ranges": address_ranges if address_ranges is not None else [],
    }


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
    _add_observation(
        "obs_0001",
        [
            "0x1010: cmp eax, 16",
            "0x1013: ja 0x1030",
            "0x1018: call memcpy",
            *(f"0x{0x1100 + index:x}: nop" for index in range(13)),
        ],
    )
    _add_observation("obs_0002", ["cookie domain"])
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
            and item["verification_excerpt"] == []
            and item["verification_locators"] == []
            for item in (ev1, ev2, ev_other)
        ),
    )

    invisible = summarize_evidence(
        observation_id="obs_0001",
        claims=[_claim(
            ev1["evidence_id"],
            "A guard controls the copy.",
            ["0x1010: cmp eax, 16"],
            [{"start": "0x1010", "end": "0x1030"}],
        )],
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
            _claim(
                ev1["evidence_id"],
                "The unsigned length comparison branches around the following copy.",
                ["0x1010: cmp eax, 16", "0x1013: ja 0x1030"],
                [{"start": "0x001010", "end": "0x1030"}],
            ),
            _claim(
                ev2["evidence_id"],
                "The guarded path reaches the memory-copy call.",
                ["0x1018: call memcpy"],
                [{"start": "0x1018", "end": "0x1018"}],
            ),
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
        "verification fields stored and addresses normalized",
        ev1["verification_excerpt"] == ["0x1010: cmp eax, 16", "0x1013: ja 0x1030"]
        and ev1["verification_locators"] == [{"start": "0x1010", "end": "0x1030"}],
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
        and compact.get("evidence", [{}])[0].get("host_claim") == ev1["host_claim"]
        and compact.get("evidence", [{}])[0].get("verification_locators")
        == [{"start": "0x1010", "end": "0x1030"}],
    )

    idempotent = summarize_evidence(
        observation_id="obs_0001",
        claims=[_claim(
            ev1["evidence_id"],
            ev1["claim"],
            list(ev1["verification_excerpt"]),
            copy.deepcopy(ev1["verification_locators"]),
        )],
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
        claims=[_claim(
            ev1["evidence_id"],
            "The length guard controls whether execution reaches the copy call.",
            list(ev1["verification_excerpt"]),
            copy.deepcopy(ev1["verification_locators"]),
        )],
    )
    check(
        "different summary creates revision",
        revised.get("revision_count") == 1 and ev1["claim_revision"] == 2,
    )

    locator_revision = summarize_evidence(
        observation_id="obs_0001",
        claims=[_claim(
            ev1["evidence_id"],
            ev1["claim"],
            list(ev1["verification_excerpt"]),
            [{"start": "0x1000", "end": "0x1030"}],
        )],
    )
    check(
        "different locator creates revision",
        locator_revision.get("revision_count") == 1 and ev1["claim_revision"] == 3,
    )

    excerpt_revision = summarize_evidence(
        observation_id="obs_0001",
        claims=[_claim(
            ev1["evidence_id"],
            ev1["claim"],
            ["0x1010: cmp eax, 16"],
            copy.deepcopy(ev1["verification_locators"]),
        )],
    )
    check(
        "different excerpt creates revision",
        excerpt_revision.get("revision_count") == 1 and ev1["claim_revision"] == 4,
    )

    before_atomic = copy.deepcopy(ev1)
    atomic_failure = summarize_evidence(
        observation_id="obs_0001",
        claims=[
            _claim(ev1["evidence_id"], "MUST NOT COMMIT", ["0x1010: cmp eax, 16"]),
            _claim("ev_9999", "Unknown evidence.", ["0x1013: ja 0x1030"]),
        ],
    )
    check(
        "batch failure is atomic",
        atomic_failure.get("ok") is False and ev1 == before_atomic,
    )
    cross_observation = summarize_evidence(
        observation_id="obs_0001",
        claims=[_claim(ev_other["evidence_id"], "Wrong observation.", ["0x1010: cmp eax, 16"])],
    )
    check(
        "cross-observation evidence rejected",
        cross_observation.get("ok") is False and "belongs to observation" in cross_observation.get("error", ""),
    )
    duplicate = summarize_evidence(
        observation_id="obs_0001",
        claims=[
            _claim(ev1["evidence_id"], "First.", ["0x1010: cmp eax, 16"]),
            _claim(ev1["evidence_id"], "Second.", ["0x1013: ja 0x1030"]),
        ],
    )
    check(
        "duplicate evidence id rejected",
        duplicate.get("ok") is False and "duplicate evidence id" in duplicate.get("error", ""),
    )

    wrong_excerpt = summarize_evidence(
        observation_id="obs_0001",
        claims=[_claim(ev1["evidence_id"], "Wrong excerpt.", ["0x9999: invented"])],
    )
    check(
        "invented excerpt rejected",
        wrong_excerpt.get("ok") is False and "exact line" in wrong_excerpt.get("error", ""),
    )
    too_many_excerpt_lines = summarize_evidence(
        observation_id="obs_0001",
        claims=[_claim(
            ev1["evidence_id"],
            "Too many lines.",
            [f"0x{0x1100 + index:x}: nop" for index in range(13)],
        )],
    )
    check("excerpt line limit enforced", too_many_excerpt_lines.get("ok") is False)
    bad_address = summarize_evidence(
        observation_id="obs_0001",
        claims=[_claim(
            ev1["evidence_id"],
            "Bad address.",
            ["0x1010: cmp eax, 16"],
            [{"start": "1010", "end": "0x1030"}],
        )],
    )
    check("address syntax enforced", bad_address.get("ok") is False)
    inverted_address = summarize_evidence(
        observation_id="obs_0001",
        claims=[_claim(
            ev1["evidence_id"],
            "Inverted address.",
            ["0x1010: cmp eax, 16"],
            [{"start": "0x1030", "end": "0x1010"}],
        )],
    )
    check("address ordering enforced", inverted_address.get("ok") is False)
    too_many_ranges = summarize_evidence(
        observation_id="obs_0001",
        claims=[_claim(
            ev1["evidence_id"],
            "Too many ranges.",
            ["0x1010: cmp eax, 16"],
            [{"start": f"0x{index:x}", "end": f"0x{index:x}"} for index in range(5)],
        )],
    )
    check("address range limit enforced", too_many_ranges.get("ok") is False)

    begin_model_response()
    _add_observation("obs_0003", ["0x2000: test eax,eax"])
    same_response = record_evidence(
        observation_id="obs_0003",
        kind="command_output",
        claim="Host observed the current response output.",
        excerpts=["0x2000: test eax,eax"],
    )
    too_early = summarize_evidence(
        observation_id="obs_0003",
        claims=[_claim(
            same_response["evidence_id"],
            "The test checks zero.",
            ["0x2000: test eax,eax"],
            [{"start": "0x2000", "end": "0x2000"}],
        )],
    )
    check(
        "same-response evidence rejected",
        too_early.get("ok") is False and same_response["claim_status"] == "pending",
    )
    mark_evidence_returned([same_response])
    begin_model_response()
    later = summarize_evidence(
        observation_id="obs_0003",
        claims=[_claim(
            same_response["evidence_id"],
            "The test checks zero.",
            ["0x2000: test eax,eax"],
            [{"start": "0x2000", "end": "0x2000"}],
        )],
    )
    check(
        "later response can summarize",
        later.get("ok") is True and same_response["claim_status"] == "summarized",
    )

    metrics = harness_metrics()
    check("summary calls counted", metrics["evidence_summary_calls"] == 16)
    check("summary updates counted", metrics["evidence_summary_updates"] == 3)
    check("summary revisions counted", metrics["evidence_summary_revisions"] == 3)
    check("summary failures counted", metrics["evidence_summary_failures"] == 10)

    if failures:
        print("EVIDENCE SUMMARY TESTS FAILED:")
        for failure in failures:
            print("  -", failure)
        return 1
    print("EVIDENCE SUMMARY TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
