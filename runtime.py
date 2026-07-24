"""Mutable per-case runtime state: ledger, id minting, and metrics.

This is the heart of the "the observation is the citable evidence" design: every
recorded observation can mint one or more evidence ledger items with stable
``ev_XXXX`` ids that the model later cites in its final verdict.
"""

from __future__ import annotations

from typing import Any

from claudeagent.common import compact_lines


AGENT_CONTEXT: dict[str, Any] = {}


def next_id(prefix: str, counter_key: str) -> str:
    value = int(AGENT_CONTEXT.get(counter_key, 0)) + 1
    AGENT_CONTEXT[counter_key] = value
    return f"{prefix}_{value:04d}"


def bump_metric(name: str, amount: int = 1) -> None:
    metrics = AGENT_CONTEXT.setdefault("metrics", {})
    metrics[name] = int(metrics.get(name, 0)) + amount


def bump_command_failure() -> None:
    bump_metric("tool_failures")
    bump_metric("command_failures")


def ensure_runtime_state() -> None:
    AGENT_CONTEXT.setdefault("observations", [])
    AGENT_CONTEXT.setdefault("evidence_ledger", [])
    AGENT_CONTEXT.setdefault("metadata_sha256", "")
    AGENT_CONTEXT.setdefault("observation_counter", 0)
    AGENT_CONTEXT.setdefault("evidence_counter", 0)
    AGENT_CONTEXT.setdefault("script_counter", 0)
    AGENT_CONTEXT.setdefault("model_response_counter", 0)
    AGENT_CONTEXT.setdefault("current_model_response", 0)
    AGENT_CONTEXT.setdefault("metrics", {})


def initialize_agent_context(
    metadata: dict[str, Any],
    binary: str,
    cve_id: str = "",
    output_dir: str = "",
    scratch_dir: str = "",
    metadata_sha256: str = "",
) -> None:
    if not metadata_sha256:
        from claudeagent.metadata_input import metadata_sha256 as compute_metadata_sha256

        metadata_sha256 = compute_metadata_sha256(
            metadata,
            str(metadata.get("cve_id") or cve_id or "") or None,
        )
    AGENT_CONTEXT.clear()
    AGENT_CONTEXT.update({
        "metadata": metadata,
        "binary_path": binary,
        "cve_id": metadata.get("cve_id", cve_id),
        "output_dir": output_dir,
        "scratch_dir": scratch_dir,
        "metadata_sha256": metadata_sha256,
        "observations": [],
        "evidence_ledger": [],
        "observation_counter": 0,
        "evidence_counter": 0,
        "script_counter": 0,
        "model_response_counter": 0,
        "current_model_response": 0,
        "metrics": {},
    })
def begin_model_response() -> int:
    """Advance the monotonic response index used for evidence visibility checks."""
    ensure_runtime_state()
    response_index = int(AGENT_CONTEXT.get("model_response_counter", 0)) + 1
    AGENT_CONTEXT["model_response_counter"] = response_index
    AGENT_CONTEXT["current_model_response"] = response_index
    return response_index


def record_evidence(
    *,
    observation_id: str,
    kind: str,
    claim: str,
    excerpts: list[str],
    location: dict[str, Any] | None = None,
    confidence: str = "supporting",
    excerpt_limit: int = 8,
    polarity: str = "positive",
) -> dict[str, Any]:
    ensure_runtime_state()
    if polarity not in {"positive", "negative"}:
        raise ValueError("evidence polarity must be 'positive' or 'negative'")
    evidence_id = next_id("ev", "evidence_counter")
    host_claim = str(claim)
    item = {
        "evidence_id": evidence_id,
        "observation_id": observation_id,
        "kind": kind,
        "host_claim": host_claim,
        "claim": host_claim,
        "claim_source": "host",
        "claim_status": "pending",
        "claim_revision": 0,
        "created_response_index": int(AGENT_CONTEXT.get("current_model_response", 0)),
        "returned_response_index": None,
        "supporting_excerpt": compact_lines(excerpts, limit=excerpt_limit),
        "verification_excerpt": [],
        "verification_locators": [],
        "location": location or {},
        "confidence": confidence,
        "polarity": polarity,
    }
    AGENT_CONTEXT["evidence_ledger"].append(item)
    return item


def mark_evidence_returned(
    evidence: list[dict[str, Any]],
    *,
    response_index: int | None = None,
) -> None:
    """Mark ledger items whose tool output was appended to the model context."""
    ensure_runtime_state()
    returned_at = (
        int(AGENT_CONTEXT.get("current_model_response", 0))
        if response_index is None
        else int(response_index)
    )
    evidence_ids = {
        str(item.get("evidence_id"))
        for item in evidence
        if isinstance(item, dict) and item.get("evidence_id")
    }
    if not evidence_ids:
        return
    for item in AGENT_CONTEXT.get("evidence_ledger", []):
        if not isinstance(item, dict) or str(item.get("evidence_id", "")) not in evidence_ids:
            continue
        if item.get("returned_response_index") is None:
            item["returned_response_index"] = returned_at


def evidence_ids_in_ledger() -> set[str]:
    ensure_runtime_state()
    return {
        str(item.get("evidence_id"))
        for item in AGENT_CONTEXT.get("evidence_ledger", [])
        if isinstance(item, dict) and item.get("evidence_id")
    }


def harness_metrics() -> dict[str, int]:
    ensure_runtime_state()
    metrics = {key: int(value) for key, value in AGENT_CONTEXT.get("metrics", {}).items() if isinstance(value, int)}
    metrics["observations_count"] = len(AGENT_CONTEXT.get("observations", []))
    metrics["evidence_count"] = len(AGENT_CONTEXT.get("evidence_ledger", []))
    metrics.setdefault("tool_calls", 0)
    metrics.setdefault("tool_failures", 0)
    metrics.setdefault("command_failures", 0)
    metrics.setdefault("truncated_observations", 0)
    metrics.setdefault("schema_repair_attempts", 0)
    metrics.setdefault("no_evidence_verdicts", 0)
    metrics.setdefault("evidence_summary_calls", 0)
    metrics.setdefault("evidence_summary_updates", 0)
    metrics.setdefault("evidence_summary_revisions", 0)
    metrics.setdefault("evidence_summary_failures", 0)
    return metrics
