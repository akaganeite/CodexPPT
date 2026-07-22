"""Tests for finalize validation: evidence-id gate, version reject, schema/repair.

    python3 -m claudeagent.tests.test_finalize
"""

from __future__ import annotations

import sys
import time

from claudeagent.finalize import build_final_artifact, submit_detection_result
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


def _run() -> int:
    failures = []

    def check(label: str, cond: bool) -> None:
        if not cond:
            failures.append(label)

    # Fresh context with one ledger evidence id.
    initialize_agent_context(
        {"cve_id": "CVE-2013-0249", "project": "curl"},
        "/tmp/curl_stripped",
        patch_spec=PATCH_SPEC,
    )
    ev = record_evidence(observation_id="obs_0001", kind="strings_match", claim="x", excerpts=["a"])
    good_id = ev["evidence_id"]

    # 1. determinate with NO evidence_ids -> rejected
    r = submit_detection_result("present", "high", [], ["semantic evidence"], [], "uses snprintf bounds", ["0x6f64d"], "none")
    check("determinate-no-evidence rejected", r["ok"] is False and any("at least one evidence id" in e for e in r["schema_errors"]))

    # 2. unknown evidence id -> rejected
    r = submit_detection_result(
        "present", "high", [_support("ev_9999")], ["e"], ["ev_9999"],
        "bounded copy", ["0x1"], "none",
    )
    check("unknown-id rejected", r["ok"] is False and any("unknown evidence id" in e for e in r["schema_errors"]))

    # 3. version-string in reasoning -> rejected
    r = submit_detection_result(
        "present", "high", [_support(good_id)], ["e"], [good_id],
        "fixed in 7.29.0 per release", ["0x1"], "none",
    )
    check("version-string rejected", r["ok"] is False and any("version strings" in e for e in r["schema_errors"]))

    # 4. inconclusive with reason none -> rejected
    r = submit_detection_result("inconclusive", "low", [], [], [], "unclear", [], "none")
    check("inconclusive-none rejected", r["ok"] is False)

    # 5. determinate with reason != none -> rejected
    r = submit_detection_result(
        "present", "high", [_support(good_id)], ["e"], [good_id],
        "bounded snprintf call", ["0x1"], "other",
    )
    check("determinate-with-reason rejected", r["ok"] is False)

    # 6. bad enum status -> rejected by schema
    r = submit_detection_result(
        "patched", "high", [_support(good_id)], ["e"], [good_id], "x", [], "none",
    )
    check("bad-status rejected", r["ok"] is False)

    # 7. valid present verdict -> accepted
    r = submit_detection_result(
        "present", "high", [_support(good_id)],
        ["URI build at decisive address uses a bounded printf-style call with explicit size."],
        [good_id], "Bounded snprintf-style construction matches the patch intent.",
        ["0x6f64d"], "none",
    )
    check("valid-present accepted", r["ok"] is True and r["status"] == "present" and r["cve_id"] == "CVE-2013-0249")

    # 8. valid inconclusive with concrete reason -> accepted
    r = submit_detection_result(
        "inconclusive", "low", [], [], [], "insufficient anchors", [], "no_binary_anchor",
    )
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
    accepted = submit_detection_result(
        "inconclusive", "low", [], [], [], "not enough binary evidence", [], "no_binary_anchor",
    )
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
    ev = record_evidence(observation_id="obs_0002", kind="disassembly", claim="x", excerpts=["cmp eax, 1"])
    r = submit_detection_result(
        "present", "high", [_support(ev["evidence_id"], behavior_id="B999")],
        ["guard"], [ev["evidence_id"]], "guard exists", ["0x2"], "none",
    )
    check("unknown behavior rejected", r["ok"] is False and any("unknown behavior id" in e for e in r["schema_errors"]))

    # 11. supports cannot be decorative: their evidence union must equal the top-level ids.
    r = submit_detection_result(
        "present", "high", [_support(ev["evidence_id"])],
        ["guard"], [], "guard exists", ["0x2"], "none",
    )
    check("support union mismatch rejected", r["ok"] is False and any("support" in e and "union" in e for e in r["schema_errors"]))

    # 12. a pure negative/no-match observation cannot establish OLD/NEW/not-applicable.
    negative = record_evidence(
        observation_id="obs_0003", kind="no_pipeline_match", claim="no match",
        excerpts=["stdout_lines=0"], polarity="negative",
    )
    r = submit_detection_result(
        "absent", "medium", [_support(negative["evidence_id"], side="old")],
        ["no match"], [negative["evidence_id"]], "anchor was missing", [], "none",
    )
    check("negative-only old rejected", r["ok"] is False and any("positive target-binary evidence" in e for e in r["schema_errors"]))

    # 13. the same negative observation may be represented honestly as ambiguous.
    ambiguous_support = _support(
        negative["evidence_id"], side="ambiguous", summary="The bounded search found no discriminator."
    )
    r = submit_detection_result(
        "inconclusive", "low", [ambiguous_support], [ambiguous_support["summary"]],
        [negative["evidence_id"]], "The local search did not distinguish either side.", [],
        "no_binary_anchor",
    )
    check("negative ambiguous accepted", r["ok"] is True)

    # 14. support summaries are subject to the same version/path leakage gate.
    r = submit_detection_result(
        "present", "high", [_support(ev["evidence_id"], summary="This is fixed in 7.29.0")],
        ["guard"], [ev["evidence_id"]], "guard exists", ["0x2"], "none",
    )
    check("support version rejected", r["ok"] is False and any("version strings" in e for e in r["schema_errors"]))

    if failures:
        print("FINALIZE TESTS FAILED:")
        for line in failures:
            print("  -", line)
        return 1
    print("FINALIZE TESTS PASSED (14 cases)")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
