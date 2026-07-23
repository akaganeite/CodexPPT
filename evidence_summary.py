"""Main-agent natural-language claims over existing evidence ledger items.

The tool never creates evidence. It can only annotate evidence that the model
already received in an earlier response, preserving the Host's original claim
and immutable observation/excerpt provenance.
"""

from __future__ import annotations

import copy
from typing import Any

from claudeagent.runtime import AGENT_CONTEXT, bump_metric, ensure_runtime_state


MAX_CLAIMS_PER_CALL = 16
MAX_CLAIM_CHARS = 2000


def _error(message: str) -> dict[str, Any]:
    bump_metric("evidence_summary_failures")
    return {"ok": False, "tool": "summarize_evidence", "error": message}


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

    ledger = AGENT_CONTEXT.get("evidence_ledger", [])
    ledger_by_id = {
        str(item.get("evidence_id")): item
        for item in ledger
        if isinstance(item, dict) and item.get("evidence_id")
    }
    current_response = int(AGENT_CONTEXT.get("current_model_response", 0))
    normalized: list[tuple[dict[str, Any], str]] = []
    seen_ids: set[str] = set()

    for index, entry in enumerate(claims):
        if not isinstance(entry, dict) or set(entry) != {"evidence_id", "claim"}:
            return _error(
                f"claims[{index}] must contain only evidence_id and claim"
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
        normalized.append((evidence, claim))

    updated = 0
    revised = 0
    idempotent_ids: list[str] = []
    for evidence, claim in normalized:
        evidence_id = str(evidence["evidence_id"])
        if evidence.get("claim_status") == "summarized" and evidence.get("claim") == claim:
            idempotent_ids.append(evidence_id)
            continue
        previous_status = str(evidence.get("claim_status", "pending"))
        revision = int(evidence.get("claim_revision", 0)) + 1
        evidence["claim"] = claim
        evidence["claim_source"] = "main_agent"
        evidence["claim_status"] = "summarized"
        evidence["claim_revision"] = revision
        evidence["claim_updated_response_index"] = current_response
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
        "evidence": [copy.deepcopy(evidence) for evidence, _claim in normalized],
        "updated_count": updated,
        "revision_count": revised,
        "idempotent_evidence_ids": idempotent_ids,
    }
