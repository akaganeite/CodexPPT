"""Offline tests for behavior-scoped support validation.

    python3 -m claudeagent.tests.test_supports
"""

from __future__ import annotations

import sys

from claudeagent.decision import support_evidence_ids, validate_support_records


CONTRACT = [
    {"behavior_id": "B001", "required": True},
    {"behavior_id": "B002", "required": False},
]
LEDGER = [
    {"evidence_id": "ev_0001", "polarity": "positive"},
    {"evidence_id": "ev_0002", "polarity": "negative"},
]


def _support(
    support_id: str,
    behavior_id: str,
    side: str,
    evidence_ids: list[str],
) -> dict:
    return {
        "support_id": support_id,
        "behavior_id": behavior_id,
        "observed_side": side,
        "summary": "bounded target-binary observation",
        "evidence_ids": evidence_ids,
        "decisive_addresses": ["0x10"],
    }


def _errors(supports: list[dict], status: str, evidence_ids: list[str]) -> list[str]:
    return validate_support_records(
        supports,
        status=status,
        evidence_ids=evidence_ids,
        behavior_contract=CONTRACT,
        evidence_ledger=LEDGER,
    )


def _run() -> int:
    failures: list[str] = []

    def check(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    valid = [_support("sup_0001", "B001", "new", ["ev_0001"])]
    check("valid support accepted", not _errors(valid, "present", ["ev_0001"]))
    check("stable evidence union", support_evidence_ids(valid + [
        _support("sup_0002", "B002", "ambiguous", ["ev_0001", "ev_0002"])
    ]) == ["ev_0001", "ev_0002"])

    check(
        "invented behavior rejected",
        any("unknown behavior" in item for item in _errors(
            [_support("sup_0001", "B999", "new", ["ev_0001"])], "present", ["ev_0001"]
        )),
    )
    check(
        "duplicate support id rejected",
        any("duplicate support" in item for item in _errors(
            [
                _support("sup_0001", "B001", "new", ["ev_0001"]),
                _support("sup_0001", "B002", "ambiguous", ["ev_0002"]),
            ],
            "present",
            ["ev_0001", "ev_0002"],
        )),
    )
    check(
        "union mismatch rejected",
        any("union" in item for item in _errors(valid, "present", [])),
    )
    check(
        "negative new rejected",
        any("positive target-binary evidence" in item for item in _errors(
            [_support("sup_0001", "B001", "new", ["ev_0002"])], "present", ["ev_0002"]
        )),
    )
    check(
        "negative ambiguous accepted",
        not _errors(
            [_support("sup_0001", "B001", "ambiguous", ["ev_0002"])],
            "inconclusive",
            ["ev_0002"],
        ),
    )
    check(
        "determinate empty rejected",
        any("require at least one" in item for item in _errors([], "absent", [])),
    )
    check("inconclusive empty accepted", not _errors([], "inconclusive", []))

    if failures:
        print("SUPPORT TESTS FAILED:")
        for failure in failures:
            print("  -", failure)
        return 1
    print("SUPPORT TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
