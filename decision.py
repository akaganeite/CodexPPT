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
DECISIVE_SIDES = {"old", "new", "not_applicable"}
FINAL_SCHEMA_VERSION = "final_result.v4"


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


def support_decisive_addresses(supports: Any) -> list[str]:
    """Return the stable, de-duplicated address union from supports."""
    out: list[str] = []
    seen: set[str] = set()
    if not isinstance(supports, list):
        return out
    for support in supports:
        if not isinstance(support, dict) or not isinstance(support.get("decisive_addresses"), list):
            continue
        for value in support["decisive_addresses"]:
            address = str(value)
            if address not in seen:
                seen.add(address)
                out.append(address)
    return out


def required_behavior_ids(behavior_contract: Any) -> list[str]:
    """Return required behavior ids in PatchSpec order."""
    if not isinstance(behavior_contract, list):
        return []
    return [
        str(item.get("behavior_id"))
        for item in behavior_contract
        if isinstance(item, dict) and item.get("behavior_id") and item.get("required") is True
    ]


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


def validate_claim_record(
    claim: Any,
    *,
    supports: Any,
    behavior_contract: Any,
    path: str = "$.claim",
) -> list[str]:
    """Validate claim references and required-behavior resolution coverage."""
    errors: list[str] = []
    if not isinstance(claim, dict) or not isinstance(supports, list):
        return errors

    support_items = [item for item in supports if isinstance(item, dict)]
    support_by_id = {
        str(item.get("support_id")): item for item in support_items if item.get("support_id")
    }
    raw_support_ids = claim.get("support_ids")
    claim_support_ids = (
        [str(value) for value in raw_support_ids] if isinstance(raw_support_ids, list) else []
    )
    if len(claim_support_ids) != len(set(claim_support_ids)):
        errors.append(f"{path}.support_ids: duplicate support ids are not allowed")
    unknown_support_ids = sorted(set(claim_support_ids) - set(support_by_id))
    if unknown_support_ids:
        errors.append(
            f"{path}.support_ids: unknown support id(s): {unknown_support_ids}"
        )
    orphan_support_ids = sorted(set(support_by_id) - set(claim_support_ids))
    if orphan_support_ids:
        errors.append(
            f"{path}.support_ids: every submitted support must be claimed; orphan id(s): "
            f"{orphan_support_ids}"
        )

    contract_items = behavior_contract if isinstance(behavior_contract, list) else []
    known_behavior_ids = {
        str(item.get("behavior_id"))
        for item in contract_items
        if isinstance(item, dict) and item.get("behavior_id")
    }
    required_ids = set(required_behavior_ids(contract_items))
    raw_unresolved = claim.get("unresolved_behavior_ids")
    unresolved_ids = (
        [str(value) for value in raw_unresolved] if isinstance(raw_unresolved, list) else []
    )
    if len(unresolved_ids) != len(set(unresolved_ids)):
        errors.append(f"{path}.unresolved_behavior_ids: duplicate behavior ids are not allowed")
    unknown_unresolved = sorted(set(unresolved_ids) - known_behavior_ids)
    if unknown_unresolved:
        errors.append(
            f"{path}.unresolved_behavior_ids: unknown behavior id(s): {unknown_unresolved}"
        )
    optional_unresolved = sorted(set(unresolved_ids) - required_ids)
    if optional_unresolved:
        errors.append(
            f"{path}.unresolved_behavior_ids: only required behaviors may be unresolved: "
            f"{optional_unresolved}"
        )

    claimed_supports = [
        support_by_id[support_id]
        for support_id in claim_support_ids
        if support_id in support_by_id
    ]
    supports_by_behavior: dict[str, list[dict[str, Any]]] = {}
    for support in claimed_supports:
        supports_by_behavior.setdefault(str(support.get("behavior_id", "")), []).append(support)

    unresolved_set = set(unresolved_ids)
    for behavior_id in required_behavior_ids(contract_items):
        behavior_supports = supports_by_behavior.get(behavior_id, [])
        decisive = {
            str(item.get("observed_side"))
            for item in behavior_supports
            if str(item.get("observed_side")) in DECISIVE_SIDES
        }
        is_unresolved = behavior_id in unresolved_set
        if len(decisive) == 1 and is_unresolved:
            errors.append(
                f"{path}.unresolved_behavior_ids: {behavior_id} has a consistent decisive side "
                "and must not be declared unresolved"
            )
        if len(decisive) != 1 and not is_unresolved:
            reason = "conflicting decisive sides" if len(decisive) > 1 else "no decisive side"
            errors.append(
                f"{path}.unresolved_behavior_ids: {behavior_id} has {reason} and must be listed"
            )
    return errors


def resolve_behavior_claims(
    supports: Any,
    claim: Any,
    behavior_contract: Any,
) -> list[dict[str, Any]]:
    """Resolve each PatchSpec behavior to one host-derived side."""
    support_items = [item for item in supports if isinstance(item, dict)] if isinstance(supports, list) else []
    support_by_id = {
        str(item.get("support_id")): item for item in support_items if item.get("support_id")
    }
    claim_support_ids = (
        [str(value) for value in claim.get("support_ids", [])]
        if isinstance(claim, dict) and isinstance(claim.get("support_ids"), list)
        else []
    )
    raw_unresolved = (
        claim.get("unresolved_behavior_ids", [])
        if isinstance(claim, dict) and isinstance(claim.get("unresolved_behavior_ids"), list)
        else []
    )
    unresolved = {str(value) for value in raw_unresolved}
    ordered_supports = [support_by_id[item] for item in claim_support_ids if item in support_by_id]

    out: list[dict[str, Any]] = []
    contract_items = behavior_contract if isinstance(behavior_contract, list) else []
    for contract in contract_items:
        if not isinstance(contract, dict) or not contract.get("behavior_id"):
            continue
        behavior_id = str(contract["behavior_id"])
        behavior_supports = [
            item for item in ordered_supports if str(item.get("behavior_id")) == behavior_id
        ]
        support_ids = [str(item.get("support_id")) for item in behavior_supports]
        sides = [str(item.get("observed_side", "")) for item in behavior_supports]
        decisive = {side for side in sides if side in DECISIVE_SIDES}
        if len(decisive) > 1:
            resolved_side = "ambiguous"
            resolution = "conflicting"
        elif behavior_id in unresolved:
            resolved_side = "ambiguous"
            resolution = "declared_unresolved"
        elif len(decisive) == 1:
            resolved_side = next(iter(decisive))
            resolution = "consistent_with_ambiguous" if "ambiguous" in sides else "consistent"
        elif behavior_supports:
            resolved_side = "ambiguous"
            resolution = "ambiguous_only"
        else:
            resolved_side = "ambiguous"
            resolution = "missing_support"
        out.append({
            "behavior_id": behavior_id,
            "required": bool(contract.get("required", False)),
            "resolved_side": resolved_side,
            "resolution": resolution,
            "support_ids": support_ids,
        })
    return out


def aggregate_verdict(behavior_claims: Any) -> dict[str, Any]:
    """Aggregate required behavior sides into the canonical verdict."""
    claims = behavior_claims if isinstance(behavior_claims, list) else []
    required = [item for item in claims if isinstance(item, dict) and item.get("required") is True]
    if not required:
        return {"status": "inconclusive", "rule": "no_required_behaviors", "behavior_claims": claims}
    sides = [str(item.get("resolved_side", "ambiguous")) for item in required]
    if "old" in sides:
        return {"status": "absent", "rule": "required_old_behavior", "behavior_claims": claims}
    if "ambiguous" in sides:
        return {"status": "inconclusive", "rule": "unresolved_required_behavior", "behavior_claims": claims}
    if all(side == "not_applicable" for side in sides):
        return {"status": "not_affected", "rule": "all_required_not_applicable", "behavior_claims": claims}
    if all(side in {"new", "not_applicable"} for side in sides) and "new" in sides:
        return {"status": "present", "rule": "all_applicable_required_new", "behavior_claims": claims}
    return {"status": "inconclusive", "rule": "unsupported_behavior_combination", "behavior_claims": claims}


def project_legacy_fields(supports: Any, claim: Any) -> dict[str, Any]:
    """Project canonical supports/claim into the legacy result fields."""
    support_items = [item for item in supports if isinstance(item, dict)] if isinstance(supports, list) else []
    support_by_id = {
        str(item.get("support_id")): item for item in support_items if item.get("support_id")
    }
    support_ids = (
        [str(value) for value in claim.get("support_ids", [])]
        if isinstance(claim, dict) and isinstance(claim.get("support_ids"), list)
        else []
    )
    ordered = [support_by_id[support_id] for support_id in support_ids if support_id in support_by_id]
    return {
        "evidence": [str(item.get("summary", "")) for item in ordered],
        "evidence_ids": support_evidence_ids(ordered),
        "reasoning": str(claim.get("summary", "")) if isinstance(claim, dict) else "",
        "decisive_addresses": support_decisive_addresses(ordered),
    }


def fallback_decision_fields(
    behavior_contract: Any,
    *,
    summary: str,
) -> dict[str, Any]:
    """Build canonical and legacy fields for a host-generated inconclusive result."""
    contract_items = behavior_contract if isinstance(behavior_contract, list) else []
    claim = {
        "summary": summary,
        "support_ids": [],
        "unresolved_behavior_ids": required_behavior_ids(contract_items),
    }
    behavior_claims = resolve_behavior_claims([], claim, contract_items)
    verdict = aggregate_verdict(behavior_claims)
    return {
        "schema_version": FINAL_SCHEMA_VERSION,
        "supports": [],
        "claim": claim,
        "verdict": verdict,
        **project_legacy_fields([], claim),
    }
