"""Task payload and finalization prompt construction.

The per-case user message carries a prompt-safe PatchSpec plus its exact source
excerpts, target-binary facts (including ELF class/arch), and the evidence
citation contract. Full CVE metadata and PatchSpec generation provenance stay
host-side.
"""

from __future__ import annotations

from typing import Any

from claudeagent.common import FINAL_RESULT_SCHEMA, jdump
from claudeagent.schema_validate import final_tool_parameters_schema, load_final_result_schema


def build_task(
    patch_spec: dict[str, Any],
    source_excerpts: list[dict[str, Any]],
    binary: str,
    preflight: dict[str, Any],
) -> str:
    final_schema = load_final_result_schema()
    behaviors = patch_spec.get("behaviors") if isinstance(patch_spec.get("behaviors"), list) else []
    behavior_support_contract = [
        {
            "behavior_id": item.get("behavior_id"),
            "required": bool(item.get("required", False)),
        }
        for item in behaviors
        if isinstance(item, dict) and isinstance(item.get("behavior_id"), str)
    ]
    binary_facts = dict(preflight.get("binary", {}))
    binary_facts["path"] = "/workspace/binary"
    if isinstance(binary_facts.get("file"), str) and binary:
        binary_facts["file"] = binary_facts["file"].replace(binary, "/workspace/binary")
    payload = {
        "cve": (patch_spec.get("source") or {}).get("cve_id", ""),
        "patch_spec": patch_spec,
        "patch_spec_source_excerpts": source_excerpts,
        "behavior_support_contract": behavior_support_contract,
        "target_binary": "/workspace/binary",
        "scratch_dir": "/scratch",
        "binary_facts": binary_facts,
        "symbol_hint": preflight.get("symbol_hint", {}),
        "harness_protocol": [
            "read PatchSpec -> check arch early -> use localization anchors -> find offsets -> compare trusted old/new indicators -> decide",
            "PatchSpec advisory semantics guide investigation but are not target-binary evidence",
            "an anchor miss alone cannot prove absent or not_affected",
            "determinate verdicts require target-binary evidence_ids returned by inspection tools",
            "summarize every evidence item before citing it in a support",
            "group cited evidence into behavior-scoped supports with observed_side old/new/ambiguous/not_applicable",
            "claim every support id and explicitly list unresolved required behavior ids",
            "Host derives the canonical verdict and legacy evidence fields from supports + claim",
            "use inconclusive with a concrete reason when evidence or applicability is unresolved",
        ],
        "observation_contract": {
            "tool_outputs_include": "observation_id, tool, command, exit_code, stdout_head/tail, stderr_tail, truncation, parsed_facts, pending evidence",
            "final_verdict_must_cite": "evidence_ids returned by inspection tools and updated to claim_status=summarized",
            "summary_timing": "summarize only evidence returned in an earlier model response; summarize the previous result before the next inspection or submit",
            "support_must_bind": "one PatchSpec behavior_id, one observed_side, and one or more cited evidence_ids",
            "if_truncated": "use stdout_head/stdout_tail and run a narrower command/window before relying on omitted content",
        },
        "constraints": {
            "target_binary_only_evidence": True,
            "no_debug_or_source_artifacts": True,
            "do_not_use_version_or_path_as_evidence": True,
            "do_not_invent_observations": True,
            "patch_spec_is_not_evidence": True,
            "trusted_indicators_require_binary_confirmation": True,
            "supports_are_not_new_evidence": True,
            "summaries_are_not_new_evidence": True,
            "cited_evidence_must_be_summarized": True,
            "negative_anchor_miss_only_supports_ambiguous": True,
            "host_derives_status_and_legacy_fields": True,
            "determinate_claim_may_receive_one_independent_verifier_repair": True,
            "verifier_feedback_is_not_evidence": True,
            "finish_tool": "submit_detection_result",
            "determinate_status_requires_evidence_ids": True,
        },
        "submit_detection_result_schema": final_tool_parameters_schema(),
        "final_result_artifact_schema_path": str(FINAL_RESULT_SCHEMA),
        "final_result_status_enum": final_schema.get("properties", {}).get("status", {}).get("enum", []),
    }
    return jdump(payload)


def append_finalization_prompt(input_items: list[dict[str, Any]], max_turns: int) -> None:
    input_items.append({
        "type": "message",
        "role": "user",
        "content": (
            f"Evidence budget reached after {max_turns} turns. Finalize now: if the ledger "
            "evidence is decisive, summarize every item you will cite and call "
            "submit_detection_result. Otherwise run at most one narrow "
            "deciding run_python call (a targeted strings/objdump window); on the following "
            "response summarize its evidence and submit. Do not "
            "start a broad new search. Determinate evidence/reasoning must be target-binary "
            "semantics only: no versions, filenames, paths, or release chronology. If evidence "
            "remains insufficient, submit inconclusive with a concrete reason. Create behavior-scoped "
            "supports using only summarized evidence, claim every support id, and list every "
            "unresolved required behavior id."
        ),
    })


def append_finalization_budget_prompt(input_items: list[dict[str, Any]], remaining_turns: int) -> None:
    if remaining_turns <= 1:
        content = (
            "Last-mile budget exhausted. Summarize any pending evidence you intend to cite, then "
            "call submit_detection_result with valid JSON using existing evidence_ids. Do not "
            "inspect further. If the evidence is not "
            "decisive, submit inconclusive with a concrete reason. Determinate wording must omit "
            "versions, paths, filenames, and release chronology. Include behavior-scoped supports "
            "and a claim that covers every submitted support and required behavior."
        )
    else:
        content = (
            f"Last-mile budget remaining: {remaining_turns}. Summarize the last evidence_ids and "
            "submit if they are "
            "decisive; otherwise run one narrow evidence-deciding run_python call, then summarize "
            "its returned evidence on the following response. No broad "
            "search. Final determinate wording must be binary-local only. Bind cited evidence into "
            "behavior-scoped supports before submitting."
        )
    input_items.append({"type": "message", "role": "user", "content": content})
