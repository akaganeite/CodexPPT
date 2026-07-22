"""Behavior-scoped support contracts and deterministic validation.

Supports explain how target-binary evidence relates to one PatchSpec behavior.
They are final-decision annotations, not observations, and therefore never enter
the evidence ledger.  This module deliberately performs structural validation
only; semantic entailment is handled by the later independent verifier stage.
"""

from __future__ import annotations

import re
from typing import Any


SUPPORT_ID_RE = re.compile(r"^sup_[0-9]{4}$")
OBSERVED_SIDES = {"old", "new", "ambiguous", "not_applicable"}
POSITIVE_REQUIRED_SIDES = {"old", "new", "not_applicable"}


def support_evidence_ids(supports: Any) -> list[str]:
    """Return the stable, de-duplicated evidence-id union from supports."""
    out: list[str] = []
    seen: set[str] = set()
    if not isinstance(supports, list):
        return out
    for support in supports:
        if not isinstance(support, dict) or not isinstance(support.get("evidence_ids"), list):
            continue
        for value in support["evidence_ids"]:
            evidence_id = str(value)
            if evidence_id not in seen:
                seen.add(evidence_id)
                out.append(evidence_id)
    return out


def validate_support_records(
    supports: Any,
    *,
    status: str,
    evidence_ids: Any,
    behavior_contract: Any,
    evidence_ledger: Any,
    path: str = "$.supports",
) -> list[str]:
    """Validate support identities, references, and evidence polarity.

    The JSON schema checks the basic wire shape.  These checks cover relations
    that JSON schema cannot express: references into the current PatchSpec and
    ledger, uniqueness, exact top-level evidence coverage, and the rule that an
    OLD/NEW/not-applicable conclusion cannot be based only on negative no-match
    observations.
    """
    errors: list[str] = []
    if not isinstance(supports, list):
        return errors

    contract_items = behavior_contract if isinstance(behavior_contract, list) else []
    behavior_ids = {
        str(item.get("behavior_id"))
        for item in contract_items
        if isinstance(item, dict) and item.get("behavior_id")
    }
    ledger_items = evidence_ledger if isinstance(evidence_ledger, list) else []
    ledger_by_id = {
        str(item.get("evidence_id")): item
        for item in ledger_items
        if isinstance(item, dict) and item.get("evidence_id")
    }

    seen_support_ids: set[str] = set()
    for index, support in enumerate(supports):
        if not isinstance(support, dict):
            continue
        item_path = f"{path}[{index}]"
        support_id = str(support.get("support_id", ""))
        if not SUPPORT_ID_RE.fullmatch(support_id):
            errors.append(f"{item_path}.support_id: expected sup_XXXX")
        elif support_id in seen_support_ids:
            errors.append(f"{item_path}.support_id: duplicate support id {support_id!r}")
        seen_support_ids.add(support_id)

        behavior_id = str(support.get("behavior_id", ""))
        if behavior_id not in behavior_ids:
            errors.append(
                f"{item_path}.behavior_id: unknown behavior id {behavior_id!r}; "
                f"expected one of {sorted(behavior_ids)}"
            )

        side = str(support.get("observed_side", ""))
        if side and side not in OBSERVED_SIDES:
            errors.append(f"{item_path}.observed_side: unknown side {side!r}")

        raw_ids = support.get("evidence_ids")
        item_ids = [str(value) for value in raw_ids] if isinstance(raw_ids, list) else []
        if len(item_ids) != len(set(item_ids)):
            errors.append(f"{item_path}.evidence_ids: duplicate evidence ids are not allowed")
        unknown_ids = sorted(set(item_ids) - set(ledger_by_id))
        if unknown_ids:
            errors.append(
                f"{item_path}.evidence_ids: unknown evidence id(s) not in the ledger: {unknown_ids}"
            )
        known_items = [ledger_by_id[evidence_id] for evidence_id in item_ids if evidence_id in ledger_by_id]
        if side in POSITIVE_REQUIRED_SIDES and known_items and all(
            str(item.get("polarity", "positive")) == "negative" for item in known_items
        ):
            errors.append(
                f"{item_path}: observed_side={side!r} requires positive target-binary evidence; "
                "pure no-match/anchor-miss evidence can only support ambiguous"
            )

    top_ids = [str(value) for value in evidence_ids] if isinstance(evidence_ids, list) else []
    if len(top_ids) != len(set(top_ids)):
        errors.append("$.evidence_ids: duplicate evidence ids are not allowed")
    support_ids = support_evidence_ids(supports)
    if set(top_ids) != set(support_ids):
        errors.append(
            "$.evidence_ids: must exactly equal the de-duplicated union of "
            f"supports[*].evidence_ids (top={sorted(set(top_ids))}, supports={sorted(set(support_ids))})"
        )
    if status in {"present", "absent", "not_affected"} and not supports:
        errors.append(f"{path}: {status} verdicts require at least one behavior support")
    return errors
