"""Task payload and finalization prompt construction.

The per-case user message reproduces the inputs that made direct `codex exec`
detection effective: the CVE metadata up front, the target-binary facts
(including ELF class/arch, for early not_affected filtering), and an explicit
evidence-citation contract.
"""

from __future__ import annotations

from typing import Any

from claudeagent.common import FINAL_RESULT_SCHEMA, jdump
from claudeagent.runtime import AGENT_CONTEXT
from claudeagent.schema_validate import final_tool_parameters_schema, load_final_result_schema


def build_task(metadata: dict[str, Any], binary: str, preflight: dict[str, Any]) -> str:
    final_schema = load_final_result_schema()
    payload = {
        "cve": metadata.get("cve_id", ""),
        "cve_metadata": metadata,
        "target_binary": binary,
        "scratch_dir": AGENT_CONTEXT.get("scratch_dir", ""),
        "binary_facts": preflight.get("binary", {}),
        "symbol_hint": preflight.get("symbol_hint", {}),
        "harness_protocol": [
            "read metadata -> check arch early -> extract anchors -> find offsets -> disassemble -> decide",
            "determinate verdicts require target-binary evidence_ids returned by tool calls",
            "use inconclusive with a concrete reason when evidence or applicability is unresolved",
        ],
        "observation_contract": {
            "tool_outputs_include": "observation_id, tool, command, exit_code, stdout_head/tail, stderr_tail, truncation, parsed_facts, evidence",
            "final_verdict_must_cite": "evidence_ids returned in tool output evidence items",
            "if_truncated": "use stdout_head/stdout_tail and run a narrower command/window before relying on omitted content",
        },
        "constraints": {
            "target_binary_only_evidence": True,
            "no_debug_or_source_artifacts": True,
            "do_not_use_version_or_path_as_evidence": True,
            "do_not_invent_observations": True,
            "finish_tool": "submit_detection_result",
            "determinate_status_requires_evidence_ids": True,
        },
        "submit_detection_result_schema": final_tool_parameters_schema(),
        "final_result_artifact_schema_path": str(FINAL_RESULT_SCHEMA),
        "final_result_status_enum": final_schema.get("properties", {}).get("status", {}).get("enum", []),
    }
    return jdump(payload)


def append_finalization_prompt(messages: list[dict[str, Any]], max_turns: int) -> None:
    messages.append({
        "role": "user",
        "content": (
            f"Evidence budget reached after {max_turns} turns. Finalize now: if the ledger "
            "evidence is decisive, call submit_detection_result. Otherwise run at most one narrow "
            "deciding tool call (a targeted strings_grep, objdump_window, or objdump pipeline), then "
            "submit. Do not start a broad new search. Determinate evidence/reasoning must be "
            "target-binary semantics only: no versions, filenames, paths, or release chronology. If "
            "evidence remains insufficient, submit inconclusive with a concrete reason."
        ),
    })


def append_finalization_budget_prompt(messages: list[dict[str, Any]], remaining_turns: int) -> None:
    if remaining_turns <= 1:
        content = (
            "Last-mile budget exhausted. Your next response must call submit_detection_result with "
            "valid JSON using existing evidence_ids. Do not inspect further. If the evidence is not "
            "decisive, submit inconclusive with a concrete reason. Determinate wording must omit "
            "versions, paths, filenames, and release chronology."
        )
    else:
        content = (
            f"Last-mile budget remaining: {remaining_turns}. Submit if the last evidence_ids are "
            "decisive; otherwise run one narrow evidence-deciding tool call. No broad search. Final "
            "determinate wording must be binary-local only."
        )
    messages.append({"role": "user", "content": content})
