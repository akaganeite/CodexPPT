"""Tool schema loading and the runtime function registry.

Tools use the OpenAI Responses flat shape: each entry is
``{type:"function", name, description, strict, parameters}`` (the name sits at
the top level, not nested under ``function`` as in chat-completions).
"""

from __future__ import annotations

from typing import Any

from claudeagent.common import TOOLS_JSON, load_json
from claudeagent.evidence_summary import summarize_evidence
from claudeagent.finalize import submit_detection_result
from claudeagent.run_python_tool import run_python
from claudeagent.schema_validate import final_tool_parameters_schema


TOOL_FUNCS = {
    "run_python": run_python,
    "summarize_evidence": summarize_evidence,
    "submit_detection_result": submit_detection_result,
}

FINALIZATION_TOOL_NAMES = {"summarize_evidence", "submit_detection_result"}
FINALIZATION_TOOL_FUNCS = {
    name: handler for name, handler in TOOL_FUNCS.items() if name in FINALIZATION_TOOL_NAMES
}


def load_tools(strict: bool) -> list[dict[str, Any]]:
    tools = load_json(TOOLS_JSON)
    final_parameters = final_tool_parameters_schema()
    for tool in tools:
        if tool.get("name") == "submit_detection_result":
            tool["parameters"] = final_parameters
    if not strict:
        for tool in tools:
            tool.pop("strict", None)
    return tools


def finalization_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the non-inspection tools allowed during finalization/repair."""
    return [tool for tool in tools if tool.get("name") in FINALIZATION_TOOL_NAMES]
