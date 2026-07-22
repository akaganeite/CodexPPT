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
    AGENT_CONTEXT.setdefault("observation_counter", 0)
    AGENT_CONTEXT.setdefault("evidence_counter", 0)
    AGENT_CONTEXT.setdefault("script_counter", 0)
    AGENT_CONTEXT.setdefault("metrics", {})


def initialize_agent_context(
    metadata: dict[str, Any],
    binary: str,
    cve_id: str = "",
    output_dir: str = "",
    scratch_dir: str = "",
    patch_spec_info: dict[str, Any] | None = None,
) -> None:
    AGENT_CONTEXT.clear()
    AGENT_CONTEXT.update({
        "metadata": metadata,
        "binary_path": binary,
        "cve_id": metadata.get("cve_id", cve_id),
        "output_dir": output_dir,
        "scratch_dir": scratch_dir,
        "patch_spec_info": patch_spec_info or {
            "digest": "",
            "generation_mode": "not_generated",
            "resolution_mode": "not_resolved",
            "cache_key": "",
            "cache_hit": False,
            "usage": {},
        },
        "observations": [],
        "evidence_ledger": [],
        "observation_counter": 0,
        "evidence_counter": 0,
        "script_counter": 0,
        "metrics": {},
    })


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
    evidence_id = next_id("ev", "evidence_counter")
    item = {
        "evidence_id": evidence_id,
        "observation_id": observation_id,
        "kind": kind,
        "claim": claim,
        "supporting_excerpt": compact_lines(excerpts, limit=excerpt_limit),
        "location": location or {},
        "confidence": confidence,
        "polarity": polarity,
    }
    AGENT_CONTEXT["evidence_ledger"].append(item)
    return item


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
    return metrics
