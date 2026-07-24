"""Task payload and finalization prompt construction."""

from __future__ import annotations

from typing import Any

from claudeagent.common import compact_json
from claudeagent.metadata_input import validate_metadata_prompt_input


def build_task(
    metadata: dict[str, Any],
    binary: str,
    preflight: dict[str, Any],
) -> str:
    """Render the complete, answer-scrubbed CVE metadata for one investigation."""
    validate_metadata_prompt_input(metadata)
    binary_facts = dict(preflight.get("binary", {}))
    binary_facts["path"] = "/workspace/binary"
    if isinstance(binary_facts.get("file"), str) and binary:
        binary_facts["file"] = binary_facts["file"].replace(binary, "/workspace/binary")
    payload = {
        "cve": metadata.get("cve_id", ""),
        "cve_metadata": metadata,
        "target_binary": "/workspace/binary",
        "scratch_dir": "/scratch",
        "binary_facts": binary_facts,
        "symbol_hint": preflight.get("symbol_hint", {}),
        "mode_contract": {
            "metadata_is_guidance_not_evidence": True,
            "cited_evidence_must_be_summarized": True,
            "summary_requires_exact_excerpt_lines": True,
            "present_absent_require_address_locator": True,
            "max_cited_evidence_ids": 8,
            "finish_tool": "submit_detection_result",
        },
    }
    return compact_json(payload)


def append_finalization_prompt(input_items: list[dict[str, Any]], max_turns: int) -> None:
    input_items.append({
        "type": "message",
        "role": "user",
        "content": (
            f"Evidence budget reached after {max_turns} turns. Finalize now: if the ledger "
            "evidence is decisive, summarize every item you will cite with exact returned lines "
            "and address ranges, then call "
            "submit_detection_result with status, evidence_ids, reasoning, and decisive addresses. "
            "Otherwise run at most one narrow deciding run_python call; on the following response "
            "summarize it and submit. Do not start a broad new search. Determinate wording must use "
            "target-binary semantics only, never versions, paths, filenames, or release chronology. "
            "If evidence remains insufficient, submit inconclusive with a concrete reason."
        ),
    })


def append_finalization_budget_prompt(
    input_items: list[dict[str, Any]],
    remaining_turns: int,
) -> None:
    if remaining_turns <= 1:
        content = (
            "Last-mile budget exhausted. Summarize any pending evidence you intend to cite, "
            "including exact returned lines and address ranges, then call submit_detection_result "
            "with existing evidence_ids. Do not inspect further. "
            "Use inconclusive with a concrete reason if the evidence is not decisive."
        )
    else:
        content = (
            f"Last-mile budget remaining: {remaining_turns}. Summarize the last evidence_ids and "
            "their exact lines/address ranges, then submit if decisive; otherwise run one narrow "
            "deciding run_python call, summarize its "
            "evidence on the following response, and submit. No broad search."
        )
    input_items.append({"type": "message", "role": "user", "content": content})


def repair_finalization_prompt() -> str:
    """Return the forced-submit instruction used after an invalid final call."""
    return (
        "Repair/finalization only: the previous response did not produce an accepted "
        "submit_detection_result. Do not call run_python. Summarize every pending evidence "
        "item you intend to cite with exact returned lines and address ranges, then submit a "
        "direct status using existing evidence_ids, "
        "reasoning, and decisive addresses. If the evidence is not decisive, submit "
        "inconclusive with a concrete reason."
    )
