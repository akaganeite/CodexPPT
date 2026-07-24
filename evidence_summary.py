"""Main-agent claims and verification locators over existing evidence.

The tool never creates evidence. It can only annotate evidence that the model
already received in an earlier response, preserving the Host's original claim
and immutable observation/supporting-excerpt provenance.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from claudeagent.runtime import AGENT_CONTEXT, bump_metric, ensure_runtime_state


MAX_CLAIMS_PER_CALL = 16
MAX_CLAIM_CHARS = 2000
MAX_VERIFICATION_EXCERPT_LINES = 12
MAX_VERIFICATION_ADDRESS_RANGES = 4
HEX_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]+$")


def _error(message: str) -> dict[str, Any]:
    bump_metric("evidence_summary_failures")
    return {"ok": False, "tool": "summarize_evidence", "error": message}


def _normalize_excerpt(
    value: Any,
    *,
    claim_index: int,
) -> list[str] | str:
    path = f"claims[{claim_index}].excerpt"
    if not isinstance(value, list) or not value:
        return f"{path} must contain at least one excerpt line"
    if len(value) > MAX_VERIFICATION_EXCERPT_LINES:
        return f"{path} exceeds {MAX_VERIFICATION_EXCERPT_LINES} lines"
    normalized: list[str] = []
    for line_index, line in enumerate(value):
        if not isinstance(line, str) or not line:
            return f"{path}[{line_index}] must be a non-empty string"
        if "\n" in line or "\r" in line:
            return f"{path}[{line_index}] must contain exactly one line"
        normalized.append(line)
    return normalized


def _normalize_address_ranges(
    value: Any,
    *,
    claim_index: int,
) -> list[dict[str, str]] | str:
    path = f"claims[{claim_index}].address_ranges"
    if not isinstance(value, list):
        return f"{path} must be an array"
    if len(value) > MAX_VERIFICATION_ADDRESS_RANGES:
        return f"{path} exceeds {MAX_VERIFICATION_ADDRESS_RANGES} ranges"
    normalized: list[dict[str, str]] = []
    for range_index, address_range in enumerate(value):
        item_path = f"{path}[{range_index}]"
        if not isinstance(address_range, dict) or set(address_range) != {"start", "end"}:
            return f"{item_path} must contain only start and end"
        start = address_range.get("start")
        end = address_range.get("end")
        if not isinstance(start, str) or not HEX_ADDRESS_RE.fullmatch(start):
            return f"{item_path}.start must be a 0x-prefixed hexadecimal address"
        if not isinstance(end, str) or not HEX_ADDRESS_RE.fullmatch(end):
            return f"{item_path}.end must be a 0x-prefixed hexadecimal address"
        start_value = int(start, 16)
        end_value = int(end, 16)
        if start_value > end_value:
            return f"{item_path}: start must be less than or equal to end"
        normalized.append({"start": hex(start_value), "end": hex(end_value)})
    return normalized


def summarize_evidence(
    *,
    observation_id: Any = "",
    claims: Any = None,
    **unexpected: Any,
) -> dict[str, Any]:
    """Attach model-authored claims to evidence from one prior observation."""
    ensure_runtime_state()
    bump_metric("evidence_summary_calls")

    if unexpected:
        return _error(
            f"unexpected argument(s): {sorted(str(key) for key in unexpected)}"
        )
    if not isinstance(observation_id, str) or not observation_id.strip():
        return _error("observation_id must be a non-empty string")
    observation_id = observation_id.strip()
    if not isinstance(claims, list) or not claims:
        return _error("claims must contain at least one evidence claim")
    if len(claims) > MAX_CLAIMS_PER_CALL:
        return _error(f"claims exceeds {MAX_CLAIMS_PER_CALL} items")

    observations = AGENT_CONTEXT.get("observations", [])
    observation = next(
        (
            item
            for item in observations
            if isinstance(item, dict)
            and str(item.get("observation_id", "")) == observation_id
        ),
        None,
    )
    if observation is None:
        return _error(f"observation id {observation_id!r} is not in the observation ledger")
    ledger = AGENT_CONTEXT.get("evidence_ledger", [])
    ledger_by_id = {
        str(item.get("evidence_id")): item
        for item in ledger
        if isinstance(item, dict) and item.get("evidence_id")
    }
    current_response = int(AGENT_CONTEXT.get("current_model_response", 0))
    normalized: list[tuple[dict[str, Any], str, list[str], list[dict[str, str]]]] = []
    seen_ids: set[str] = set()

    for index, entry in enumerate(claims):
        required_fields = {"evidence_id", "claim", "excerpt", "address_ranges"}
        if not isinstance(entry, dict) or set(entry) != required_fields:
            return _error(
                f"claims[{index}] must contain only evidence_id, claim, excerpt, and address_ranges"
            )
        evidence_id = entry.get("evidence_id")
        claim = entry.get("claim")
        if not isinstance(evidence_id, str) or not evidence_id.strip():
            return _error(f"claims[{index}].evidence_id must be a non-empty string")
        evidence_id = evidence_id.strip()
        if evidence_id in seen_ids:
            return _error(f"claims contains duplicate evidence id {evidence_id!r}")
        seen_ids.add(evidence_id)
        if not isinstance(claim, str) or not claim.strip():
            return _error(f"claims[{index}].claim must be a non-empty string")
        claim = claim.strip()
        if len(claim) > MAX_CLAIM_CHARS:
            return _error(
                f"claims[{index}].claim exceeds {MAX_CLAIM_CHARS} characters"
            )
        excerpt = _normalize_excerpt(
            entry.get("excerpt"),
            claim_index=index,
        )
        if isinstance(excerpt, str):
            return _error(excerpt)
        address_ranges = _normalize_address_ranges(
            entry.get("address_ranges"),
            claim_index=index,
        )
        if isinstance(address_ranges, str):
            return _error(address_ranges)

        evidence = ledger_by_id.get(evidence_id)
        if evidence is None:
            return _error(f"evidence id {evidence_id!r} is not in the ledger")
        if str(evidence.get("observation_id", "")) != observation_id:
            return _error(
                f"evidence id {evidence_id!r} belongs to observation "
                f"{evidence.get('observation_id')!r}, not {observation_id!r}"
            )
        returned_response = evidence.get("returned_response_index")
        if (
            not isinstance(returned_response, int)
            or isinstance(returned_response, bool)
            or returned_response >= current_response
        ):
            return _error(
                f"evidence id {evidence_id!r} was not returned in an earlier model response"
            )
        normalized.append((evidence, claim, excerpt, address_ranges))

    updated = 0
    revised = 0
    idempotent_ids: list[str] = []
    for evidence, claim, excerpt, address_ranges in normalized:
        evidence_id = str(evidence["evidence_id"])
        if (
            evidence.get("claim_status") == "summarized"
            and evidence.get("claim") == claim
            and evidence.get("verification_excerpt") == excerpt
            and evidence.get("verification_locators") == address_ranges
        ):
            idempotent_ids.append(evidence_id)
            continue
        previous_status = str(evidence.get("claim_status", "pending"))
        revision = int(evidence.get("claim_revision", 0)) + 1
        evidence["claim"] = claim
        evidence["claim_source"] = "main_agent"
        evidence["claim_status"] = "summarized"
        evidence["claim_revision"] = revision
        evidence["claim_updated_response_index"] = current_response
        evidence["verification_excerpt"] = list(excerpt)
        evidence["verification_locators"] = copy.deepcopy(address_ranges)
        if previous_status == "summarized":
            revised += 1
        else:
            updated += 1

    if updated:
        bump_metric("evidence_summary_updates", updated)
    if revised:
        bump_metric("evidence_summary_revisions", revised)

    return {
        "ok": True,
        "tool": "summarize_evidence",
        "observation_id": observation_id,
        "evidence": [copy.deepcopy(evidence) for evidence, _claim, _excerpt, _ranges in normalized],
        "updated_count": updated,
        "revision_count": revised,
        "idempotent_evidence_ids": idempotent_ids,
    }
