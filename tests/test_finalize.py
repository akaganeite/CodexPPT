"""Tests for finalize validation: evidence-id gate, version reject, schema/repair.

    python3 -m claudeagent.tests.test_finalize
"""

from __future__ import annotations

import sys
import time

from claudeagent.finalize import (
    api_failure_fallback_result,
    build_final_artifact,
    max_turns_fallback_result,
    preflight_missing_result,
    submit_detection_result,
    validate_final_result_artifact,
)
from claudeagent.runtime import AGENT_CONTEXT, initialize_agent_context, record_evidence


PATCH_SPEC = {
    "behaviors": [
        {"behavior_id": "B001", "required": True},
        {"behavior_id": "B002", "required": True},
    ]
}


def _support(
    evidence_id: str,
    *,
    support_id: str = "sup_0001",
    behavior_id: str = "B001",
    side: str = "new",
    summary: str = "The inspected code contains the patched instruction shape.",
) -> dict:
    return {
        "support_id": support_id,
        "behavior_id": behavior_id,
        "observed_side": side,
        "summary": summary,
        "evidence_ids": [evidence_id],
        "decisive_addresses": ["0x6f64d"],
    }


def _claim(
    supports: list[dict],
    *,
    summary: str = "The required security behaviors are resolved by target-binary evidence.",
    unresolved: list[str] | None = None,
) -> dict:
    return {
        "summary": summary,
        "support_ids": [str(item["support_id"]) for item in supports],
        "unresolved_behavior_ids": list(unresolved or []),
    }


def _run() -> int:
    failures = []

    def check(label: str, cond: bool) -> None:
        if not cond:
            failures.append(label)

    # Fresh context with evidence for two required PatchSpec behaviors.
    initialize_agent_context(
        {"cve_id": "CVE-2013-0249", "project": "curl"},
        "/tmp/curl_stripped",
        patch_spec=PATCH_SPEC,
    )
    ev1 = record_evidence(
        observation_id="obs_0001", kind="disassembly_predicates", claim="guard",
        excerpts=["0x10: cmp eax, 1"],
    )
    ev2 = record_evidence(
        observation_id="obs_0002", kind="disassembly_calls", claim="bounded call",
        excerpts=["0x20: call bounded_copy"],
    )
    new1 = _support(ev1["evidence_id"], behavior_id="B001", side="new")
    new2 = _support(
        ev2["evidence_id"], support_id="sup_0002", behavior_id="B002", side="new"
    )
    present_supports = [new1, new2]

    # 1. Host aggregation rejects a status assertion with unresolved behaviors.
    empty_claim = _claim([], summary="No required behavior was resolved.", unresolved=["B001", "B002"])
    r = submit_detection_result("present", "low", [], empty_claim, "none")
    check(
        "host-derived status mismatch rejected",
        r["ok"] is False and any("Host derived 'inconclusive'" in e for e in r["schema_errors"]),
    )

    # 2. unknown evidence ids are rejected through their support records.
    bad_supports = [
        _support("ev_9999", behavior_id="B001"),
        new2,
    ]
    r = submit_detection_result("present", "high", bad_supports, _claim(bad_supports), "none")
    check("unknown-id rejected", r["ok"] is False and any("unknown evidence id" in e for e in r["schema_errors"]))

    # 3. version strings in claim text are rejected.
    r = submit_detection_result(
        "present", "high", present_supports,
        _claim(present_supports, summary="fixed in 7.29.0 per release"), "none",
    )
    check("version-string rejected", r["ok"] is False and any("version strings" in e for e in r["schema_errors"]))

    # 4. inconclusive with reason none -> rejected
    r = submit_detection_result("inconclusive", "low", [], empty_claim, "none")
    check("inconclusive-none rejected", r["ok"] is False)

    # 5. determinate with reason != none -> rejected
    r = submit_detection_result("present", "high", present_supports, _claim(present_supports), "other")
    check("determinate-with-reason rejected", r["ok"] is False)

    # 6. bad enum status -> rejected by schema
    r = submit_detection_result("patched", "high", present_supports, _claim(present_supports), "none")
    check("bad-status rejected", r["ok"] is False)

    # 7. valid present verdict is Host-derived and legacy fields are projected.
    r = submit_detection_result("present", "high", present_supports, _claim(present_supports), "none")
    check(
        "valid-present accepted",
        r["ok"] is True and r["status"] == "present" and r["cve_id"] == "CVE-2013-0249",
    )
    check(
        "legacy projection derived",
        r.get("evidence") == [new1["summary"], new2["summary"]]
        and r.get("evidence_ids") == [ev1["evidence_id"], ev2["evidence_id"]]
        and r.get("reasoning") == _claim(present_supports)["summary"],
    )
    check(
        "verdict aggregation recorded",
        r.get("verdict", {}).get("rule") == "all_applicable_required_new",
    )

    # 8. valid inconclusive with concrete reason -> accepted
    r = submit_detection_result("inconclusive", "low", [], empty_claim, "no_binary_anchor")
    check("valid-inconclusive accepted", r["ok"] is True and r["status"] == "inconclusive")

    # 9. PatchSpec provenance is recorded separately and never becomes evidence.
    initialize_agent_context(
        {"cve_id": "CVE-2013-1944", "project": "curl"},
        "/tmp/curl_stripped",
        patch_spec_info={
            "digest": "abc123",
            "generation_mode": "model",
            "resolution_mode": "generated",
            "cache_key": "cache123",
            "cache_hit": False,
            "usage": {"input_tokens": 10, "output_tokens": 4},
        },
        patch_spec=PATCH_SPEC,
    )
    accepted = submit_detection_result("inconclusive", "low", [], empty_claim, "no_binary_anchor")
    artifact, errors = build_final_artifact(accepted, [], time.time())
    check("patchspec artifact valid", not errors and artifact.get("patch_spec", {}).get("digest") == "abc123")
    check(
        "patchspec behavior contract recorded",
        artifact.get("patch_spec", {}).get("behavior_contract") == [
            {"behavior_id": "B001", "required": True},
            {"behavior_id": "B002", "required": True},
        ],
    )
    check(
        "patchspec usage separate",
        artifact.get("usage_metrics", {}).get("patch_spec_generation", {}).get("input_tokens") == 10
        and artifact.get("usage_metrics", {}).get("totals") == {},
    )
    check("patchspec not evidence", AGENT_CONTEXT.get("evidence_ledger") == [])

    # 10. invented behavior ids are rejected.
    ev = record_evidence(observation_id="obs_0003", kind="disassembly", claim="x", excerpts=["cmp eax, 1"])
    ev_b2 = record_evidence(
        observation_id="obs_0004", kind="disassembly", claim="y", excerpts=["call bounded_copy"]
    )
    current_new2 = _support(
        ev_b2["evidence_id"], support_id="sup_0002", behavior_id="B002", side="new"
    )
    unknown_supports = [
        _support(ev["evidence_id"], behavior_id="B999"),
        _support(
            ev["evidence_id"], support_id="sup_0002", behavior_id="B002", side="new"
        ),
    ]
    r = submit_detection_result(
        "present", "high", unknown_supports, _claim(unknown_supports), "none",
    )
    check("unknown behavior rejected", r["ok"] is False and any("unknown behavior id" in e for e in r["schema_errors"]))

    # 11. every support must be referenced by the structured claim.
    r = submit_detection_result(
        "present", "high", present_supports,
        {**_claim(present_supports), "support_ids": ["sup_0001"]}, "none",
    )
    check("orphan support rejected", r["ok"] is False and any("orphan" in e for e in r["schema_errors"]))

    # 12. a pure negative/no-match observation cannot establish OLD/NEW/not-applicable.
    negative = record_evidence(
        observation_id="obs_0005", kind="no_pipeline_match", claim="no match",
        excerpts=["stdout_lines=0"], polarity="negative",
    )
    old_negative = _support(negative["evidence_id"], side="old")
    old_negative_supports = [old_negative, current_new2]
    r = submit_detection_result("absent", "medium", old_negative_supports, _claim(old_negative_supports), "none")
    check("negative-only old rejected", r["ok"] is False and any("positive target-binary evidence" in e for e in r["schema_errors"]))

    # 13. the same negative observation may be represented honestly as ambiguous.
    ambiguous_support = _support(
        negative["evidence_id"], side="ambiguous", summary="The bounded search found no discriminator."
    )
    ambiguous_claim = _claim(
        [ambiguous_support],
        summary="The local search did not distinguish either required behavior.",
        unresolved=["B001", "B002"],
    )
    r = submit_detection_result(
        "inconclusive", "low", [ambiguous_support], ambiguous_claim, "no_binary_anchor",
    )
    check("negative ambiguous accepted", r["ok"] is True)

    # 14. support summaries are subject to the same version/path leakage gate.
    version_supports = [
        _support(ev["evidence_id"], summary="This is fixed in 7.29.0"),
        _support(
            ev["evidence_id"], support_id="sup_0002", behavior_id="B002", side="new"
        ),
    ]
    r = submit_detection_result("present", "high", version_supports, _claim(version_supports), "none")
    check("support version rejected", r["ok"] is False and any("version strings" in e for e in r["schema_errors"]))

    # 15. one positively observed OLD required behavior is enough for absent.
    old1 = _support(ev["evidence_id"], side="old")
    absent_claim = _claim(
        [old1], summary="One required behavior retains the vulnerable side.", unresolved=["B002"]
    )
    r = submit_detection_result("absent", "high", [old1], absent_claim, "none")
    check("required old derives absent", r["ok"] is True and r["verdict"]["rule"] == "required_old_behavior")

    # 16. all required behaviors positively not-applicable derive not_affected.
    na1 = _support(ev["evidence_id"], side="not_applicable")
    na2 = _support(
        ev["evidence_id"], support_id="sup_0002", behavior_id="B002",
        side="not_applicable",
    )
    na_supports = [na1, na2]
    r = submit_detection_result("not_affected", "high", na_supports, _claim(na_supports), "none")
    check("all not-applicable derives not_affected", r["ok"] is True)

    # 17. tampering with a projected legacy field invalidates the artifact.
    current_present = [_support(ev["evidence_id"]), current_new2]
    valid_present = submit_detection_result(
        "present", "high", current_present, _claim(current_present), "none"
    )
    artifact, errors = build_final_artifact(valid_present, [], time.time())
    artifact["evidence_ids"] = []
    tamper_errors = validate_final_result_artifact(artifact)
    check("legacy tamper rejected", not errors and any("diverges" in item for item in tamper_errors))

    # 18-20. Every host fallback emits the canonical v3 claim/verdict shape.
    fallback_results = [
        preflight_missing_result(
            {"cve_id": "CVE-X", "project": "curl"}, "/tmp/binary", {"ok": False}
        ),
        max_turns_fallback_result(
            {"cve_id": "CVE-X", "project": "curl"}, "/tmp/binary", 20
        ),
        api_failure_fallback_result(
            {"cve_id": "CVE-X", "project": "curl"}, "/tmp/binary", "offline"
        ),
    ]
    for index, fallback in enumerate(fallback_results, 18):
        fallback_artifact, fallback_errors = build_final_artifact(fallback, [], time.time())
        check(
            f"fallback {index} schema-valid",
            not fallback_errors
            and fallback_artifact.get("schema_version") == "final_result.v3"
            and fallback_artifact.get("evidence_verification", {}).get("mode") == "off"
            and fallback_artifact.get("verdict", {}).get("status") == "inconclusive",
        )

    # 21. Long transport errors remain a valid bounded fallback claim.
    long_fallback = api_failure_fallback_result(
        {"cve_id": "CVE-X", "project": "curl"},
        "/tmp/binary",
        "X" * 6000,
    )
    long_artifact, long_errors = build_final_artifact(long_fallback, [], time.time())
    check(
        "long fallback summary bounded",
        not long_errors and len(long_artifact.get("claim", {}).get("summary", "")) <= 4000,
    )

    if failures:
        print("FINALIZE TESTS FAILED:")
        for line in failures:
            print("  -", line)
        return 1
    print("FINALIZE TESTS PASSED (21 cases)")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
