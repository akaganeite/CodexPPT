"""Offline tests for structured claim resolution and verdict aggregation.

    python3 -m claudeagent.tests.test_decision
"""

from __future__ import annotations

import sys

from claudeagent.decision import (
    aggregate_verdict,
    fallback_decision_fields,
    project_legacy_fields,
    resolve_behavior_claims,
    validate_claim_record,
)


CONTRACT = [
    {"behavior_id": "B001", "required": True},
    {"behavior_id": "B002", "required": True},
    {"behavior_id": "B003", "required": False},
]


def _support(support_id: str, behavior_id: str, side: str, evidence_id: str) -> dict:
    return {
        "support_id": support_id,
        "behavior_id": behavior_id,
        "observed_side": side,
        "summary": f"{behavior_id} observed as {side}",
        "evidence_ids": [evidence_id],
        "decisive_addresses": [f"0x{int(evidence_id[-1]) + 10:x}"],
    }


def _claim(supports: list[dict], unresolved: list[str] | None = None) -> dict:
    return {
        "summary": "Host aggregates the required behavior sides.",
        "support_ids": [item["support_id"] for item in supports],
        "unresolved_behavior_ids": list(unresolved or []),
    }


def _verdict(supports: list[dict], claim: dict) -> dict:
    return aggregate_verdict(resolve_behavior_claims(supports, claim, CONTRACT))


def _run() -> int:
    failures: list[str] = []

    def check(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    new = _support("sup_0001", "B001", "new", "ev_0001")
    new2 = _support("sup_0002", "B002", "new", "ev_0002")
    na2 = _support("sup_0002", "B002", "not_applicable", "ev_0002")
    old = _support("sup_0001", "B001", "old", "ev_0001")
    ambiguous = _support("sup_0002", "B002", "ambiguous", "ev_0002")

    check("all new -> present", _verdict([new, new2], _claim([new, new2]))["status"] == "present")
    check("new + n/a -> present", _verdict([new, na2], _claim([new, na2]))["status"] == "present")
    na1 = _support("sup_0001", "B001", "not_applicable", "ev_0001")
    check(
        "all n/a -> not_affected",
        _verdict([na1, na2], _claim([na1, na2]))["status"] == "not_affected",
    )
    check(
        "old + unresolved -> absent",
        _verdict([old], _claim([old], ["B002"]))["status"] == "absent",
    )
    check(
        "new + ambiguous -> inconclusive",
        _verdict([new, ambiguous], _claim([new, ambiguous], ["B002"]))["status"]
        == "inconclusive",
    )

    conflict_new = _support("sup_0002", "B001", "new", "ev_0002")
    conflict_claim = _claim([old, conflict_new], ["B001", "B002"])
    conflict_claims = resolve_behavior_claims([old, conflict_new], conflict_claim, CONTRACT)
    check(
        "same behavior old+new conflicts",
        conflict_claims[0]["resolved_side"] == "ambiguous"
        and conflict_claims[0]["resolution"] == "conflicting",
    )

    optional_old = _support("sup_0003", "B003", "old", "ev_0003")
    optional_supports = [new, new2, optional_old]
    check(
        "optional old ignored",
        _verdict(optional_supports, _claim(optional_supports))["status"] == "present",
    )

    missing_claim = _claim([new])
    check(
        "missing required behavior must be unresolved",
        any("B002" in item for item in validate_claim_record(
            missing_claim, supports=[new], behavior_contract=CONTRACT
        )),
    )
    orphan_claim = {**_claim([new, new2]), "support_ids": ["sup_0001"]}
    check(
        "orphan support rejected",
        any("orphan" in item for item in validate_claim_record(
            orphan_claim, supports=[new, new2], behavior_contract=CONTRACT
        )),
    )

    projection = project_legacy_fields([new2, new], {
        "summary": "ordered claim",
        "support_ids": ["sup_0001", "sup_0002"],
        "unresolved_behavior_ids": [],
    })
    check(
        "legacy projection follows claim order",
        projection["evidence_ids"] == ["ev_0001", "ev_0002"]
        and projection["reasoning"] == "ordered claim",
    )

    fallback = fallback_decision_fields(CONTRACT, summary="budget exhausted")
    check(
        "fallback is structured inconclusive",
        fallback["verdict"]["status"] == "inconclusive"
        and fallback["claim"]["unresolved_behavior_ids"] == ["B001", "B002"],
    )

    if failures:
        print("DECISION TESTS FAILED:")
        for failure in failures:
            print("  -", failure)
        return 1
    print("DECISION TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
