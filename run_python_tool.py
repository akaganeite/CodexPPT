"""The single inspection tool: run a model-authored Python script in the sandbox.

This replaces the former suite of fine-grained binutils tools (run_command /
strings_grep / objdump_window / string_xrefs / symbol_xrefs). Instead of
offering narrow operations, the model writes arbitrary Python and we execute it
confined (see sandbox.py). The script can call file/readelf/objdump/strings via
subprocess and do its own parsing/arith -- full freedom within the sandbox.

Evidence policy (per CLAUDE.md: the gate is structural, not semantic): every
run_python mints one ``obs_XXXX`` observation and, via the generic fallback in
observations.evidence_from_command_observation, one ``command_output``
``ev_XXXX`` ledger item. The model cites that id; finalize's evidence-id gate
checks the id is real, not that the excerpt semantically supports the verdict.
No rich parsed_facts extraction and no script-content auditing -- maximum
freedom, minimal structural accountability.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from claudeagent.observations import (
    evidence_from_command_observation,
    observation_from_host_result,
    tool_response_from_observation,
)
from claudeagent.runtime import AGENT_CONTEXT, bump_command_failure, next_id
from claudeagent.sandbox import run_in_sandbox


def run_python(script: str, timeout_sec: int = 0, max_output_chars: int = 0) -> dict[str, Any]:
    """Execute a Python script in the bubblewrap sandbox.

    - ``script``: full Python source. Written to ``scratch/script_NNNN.py``.
    - ``timeout_sec``: 0 means default (240s).
    - ``max_output_chars``: 0 means default (60000).

    Returns a tool_response dict (observation + evidence). See
    ``tool_response_from_observation`` for the shape.
    """
    scratch_dir = str(AGENT_CONTEXT.get("scratch_dir", ""))
    binary_path = str(AGENT_CONTEXT.get("binary_path", ""))
    if not scratch_dir or not binary_path:
        return {"ok": False, "error": "AGENT_CONTEXT scratch_dir/binary_path not initialized"}

    script_name = f"{next_id('script', 'script_counter')}.py"
    script_path = Path(scratch_dir) / script_name
    try:
        script_path.write_text(str(script), encoding="utf-8")
    except OSError as exc:
        bump_command_failure()
        return {"ok": False, "error": f"failed to write script to scratch: {exc!r}", "tool": "run_python"}

    timeout = timeout_sec if timeout_sec and timeout_sec > 0 else 240
    stdout_budget = max_output_chars if max_output_chars and max_output_chars > 0 else 60000

    result = run_in_sandbox(
        script_path=str(script_path),
        scratch_dir=scratch_dir,
        binary_path=binary_path,
        timeout=timeout,
        max_output_chars=None,  # let observation_from_host_result do head/tail budgeting
    )
    if not result.get("ok"):
        bump_command_failure()

    observation = observation_from_host_result(
        tool="run_python",
        command=["python3", "-S", str(script_path)],
        proc=result,
        stdout_budget=stdout_budget,
        parsed_facts={"command": "python3"},  # minimal; no rich extraction by design
    )
    evidence = evidence_from_command_observation(observation)
    return tool_response_from_observation(observation, evidence)
