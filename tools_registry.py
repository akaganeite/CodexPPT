"""Tool schema loading and the runtime function registry."""

from __future__ import annotations

from typing import Any

from claudeagent.common import TOOLS_JSON, load_json
from claudeagent.finalize import submit_detection_result
from claudeagent.schema_validate import final_tool_parameters_schema
from claudeagent.tools import objdump_window, run_command, strings_grep


TOOL_FUNCS = {
    "run_command": run_command,
    "strings_grep": strings_grep,
    "objdump_window": objdump_window,
    "submit_detection_result": submit_detection_result,
}


def load_tools(strict: bool) -> list[dict[str, Any]]:
    tools = load_json(TOOLS_JSON)
    final_parameters = final_tool_parameters_schema()
    for tool in tools:
        function = tool.get("function", {})
        if function.get("name") == "submit_detection_result":
            function["parameters"] = final_parameters
    if not strict:
        for tool in tools:
            tool.get("function", {}).pop("strict", None)
    return tools


def submit_tool_only(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [tool for tool in tools if tool.get("function", {}).get("name") == "submit_detection_result"]
