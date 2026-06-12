"""Tests for finalize validation: evidence-id gate, version reject, schema/repair.

    python3 -m claudeagent.tests.test_finalize
"""

from __future__ import annotations

import sys

from claudeagent.finalize import submit_detection_result
from claudeagent.runtime import initialize_agent_context, record_evidence


def _run() -> int:
    failures = []

    def check(label: str, cond: bool) -> None:
        if not cond:
            failures.append(label)

    # Fresh context with one ledger evidence id.
    initialize_agent_context({"cve_id": "CVE-2013-0249", "project": "curl"}, "/tmp/curl_stripped")
    ev = record_evidence(observation_id="obs_0001", kind="strings_match", claim="x", excerpts=["a"])
    good_id = ev["evidence_id"]

    # 1. determinate with NO evidence_ids -> rejected
    r = submit_detection_result("present", "high", ["semantic evidence"], [], "uses snprintf bounds", ["0x6f64d"], "none")
    check("determinate-no-evidence rejected", r["ok"] is False and any("at least one evidence id" in e for e in r["schema_errors"]))

    # 2. unknown evidence id -> rejected
    r = submit_detection_result("present", "high", ["e"], ["ev_9999"], "bounded copy", ["0x1"], "none")
    check("unknown-id rejected", r["ok"] is False and any("unknown evidence id" in e for e in r["schema_errors"]))

    # 3. version-string in reasoning -> rejected
    r = submit_detection_result("present", "high", ["e"], [good_id], "fixed in 7.29.0 per release", ["0x1"], "none")
    check("version-string rejected", r["ok"] is False and any("version strings" in e for e in r["schema_errors"]))

    # 4. inconclusive with reason none -> rejected
    r = submit_detection_result("inconclusive", "low", [], [], "unclear", [], "none")
    check("inconclusive-none rejected", r["ok"] is False)

    # 5. determinate with reason != none -> rejected
    r = submit_detection_result("present", "high", ["e"], [good_id], "bounded snprintf call", ["0x1"], "other")
    check("determinate-with-reason rejected", r["ok"] is False)

    # 6. bad enum status -> rejected by schema
    r = submit_detection_result("patched", "high", ["e"], [good_id], "x", [], "none")
    check("bad-status rejected", r["ok"] is False)

    # 7. valid present verdict -> accepted
    r = submit_detection_result(
        "present", "high",
        ["URI build at decisive address uses a bounded printf-style call with explicit size."],
        [good_id], "Bounded snprintf-style construction matches the patch intent.",
        ["0x6f64d"], "none",
    )
    check("valid-present accepted", r["ok"] is True and r["status"] == "present" and r["cve_id"] == "CVE-2013-0249")

    # 8. valid inconclusive with concrete reason -> accepted
    r = submit_detection_result("inconclusive", "low", [], [], "insufficient anchors", [], "no_binary_anchor")
    check("valid-inconclusive accepted", r["ok"] is True and r["status"] == "inconclusive")

    if failures:
        print("FINALIZE TESTS FAILED:")
        for line in failures:
            print("  -", line)
        return 1
    print("FINALIZE TESTS PASSED (8 cases)")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
