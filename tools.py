"""Tool functions exposed to the model: a general run_command plus two thin
binutils conveniences. Every tool produces a typed observation and mints ledger
evidence; the model cites the returned evidence ids in its final verdict.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from claudeagent.command_policy import Decision, decide_command
from claudeagent.host import run_host_cmd
from claudeagent.observations import (
    DEFAULT_TEXT_BUDGET,
    evidence_from_command_observation,
    negative_evidence,
    observation_from_host_result,
    tool_response_from_observation,
)
from claudeagent.runtime import AGENT_CONTEXT, bump_command_failure, record_evidence


def target_binary() -> str:
    return str(AGENT_CONTEXT["binary_path"])


def compile_regex(pattern: str, ignore_case: bool) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE if ignore_case else 0)


def _validation_failure(tool: str, command: list[str], error: str, parsed_facts: dict[str, Any]) -> dict[str, Any]:
    observation = observation_from_host_result(
        tool=tool,
        command=command,
        proc={"ok": False, "returncode": None, "elapsed_sec": 0, "stdout": "", "stderr": "", "error": error},
        stdout_budget=DEFAULT_TEXT_BUDGET,
        parsed_facts=parsed_facts,
    )
    bump_command_failure()
    return tool_response_from_observation(observation)


def run_command(argv: list[str], timeout_sec: int, max_output_chars: int) -> dict[str, Any]:
    """Run one bounded, read-only command against the target binary.

    Pipelines must use exactly ["sh", "-lc", "<pipeline>"]. The command policy
    rejects anything outside the binutils/filter allowlist, any debug/source
    option, and any path other than the one target binary.
    """
    decision, reason = decide_command(argv, target_binary())
    if decision is not Decision.ALLOW:
        return _validation_failure("run_command", argv, reason, {"validation_error": reason})

    timeout = timeout_sec if timeout_sec and timeout_sec > 0 else 240
    max_chars = max_output_chars if max_output_chars and max_output_chars > 0 else 60000
    exec_argv = ["/bin/sh", "-c", argv[2]] if len(argv) == 3 and argv[0] == "sh" and argv[1] == "-lc" else argv
    result = run_host_cmd(exec_argv, timeout=timeout)
    if not result.get("ok"):
        bump_command_failure()
    observation = observation_from_host_result(
        tool="run_command",
        command=argv,
        proc=result,
        stdout_budget=max_chars,
    )
    evidence = evidence_from_command_observation(observation)
    return tool_response_from_observation(observation, evidence)


def strings_grep(pattern: str, ignore_case: bool, max_matches: int) -> dict[str, Any]:
    """Run `strings -a -tx` on the target binary and return matching offset lines."""
    limit = max_matches if max_matches and max_matches > 0 else 80
    command = ["strings", "-a", "-tx", target_binary()]
    try:
        regex = compile_regex(pattern, ignore_case)
    except re.error as exc:
        return _validation_failure(
            "strings_grep", command, f"invalid regex: {exc}",
            {"pattern": pattern, "ignore_case": ignore_case, "validation_error": f"invalid regex: {exc}"},
        )
    proc = run_host_cmd(command, timeout=60)
    matches = [line for line in str(proc.get("stdout", "")).splitlines() if regex.search(line)]
    shown = matches[:limit]
    parsed_facts = {
        "command": "strings",
        "pattern": pattern,
        "ignore_case": ignore_case,
        "total_matches": len(matches),
        "matches": shown,
        "match_limit": limit,
        "matches_truncated": len(matches) > limit,
        "underlying_stdout_chars": len(str(proc.get("stdout", ""))),
    }
    observed = dict(proc)
    observed["stdout"] = "\n".join(shown)
    observation = observation_from_host_result(
        tool="strings_grep",
        command=command,
        proc=observed,
        stdout_budget=DEFAULT_TEXT_BUDGET,
        parsed_facts=parsed_facts,
    )
    evidence = []
    if shown:
        evidence.append(record_evidence(
            observation_id=observation["observation_id"],
            kind="strings_match",
            claim=f"strings output matched regex {pattern!r} (offset text lines).",
            excerpts=shown,
            excerpt_limit=16,
        ))
    elif proc.get("ok"):
        evidence.append(negative_evidence(
            observation=observation,
            kind="no_string_match",
            claim=f"strings output had no matches for regex {pattern!r}.",
            excerpts=[f"pattern={pattern!r}", "total_matches=0", f"ignore_case={ignore_case}"],
        ))
    if not proc.get("ok"):
        bump_command_failure()
    return tool_response_from_observation(observation, evidence)


def objdump_window(start_address: str, stop_address: str, syntax: str, max_output_chars: int) -> dict[str, Any]:
    """Return a bounded objdump disassembly window for the target binary."""
    max_chars = max_output_chars if max_output_chars and max_output_chars > 0 else 30000
    args = ["objdump", "-d"]
    if syntax == "intel":
        args.append("-Mintel")
    args.append(target_binary())
    args.extend([f"--start-address={start_address}", f"--stop-address={stop_address}"])

    decision, reason = decide_command(args, target_binary())
    if decision is not Decision.ALLOW:
        return _validation_failure(
            "objdump_window", args, reason,
            {"start_address": start_address, "stop_address": stop_address, "validation_error": reason},
        )

    result = run_host_cmd(args, timeout=90)
    stdout_lines = str(result.get("stdout", "")).splitlines()
    semantic_lines = [
        line for line in stdout_lines
        if re.search(r"\b(cmp|test|and|or|xor|set[a-z]+|cmov[a-z]+|j[a-z]+|call|lea)\b", line)
    ]
    parsed_facts = {
        "command": "objdump",
        "start_address": start_address,
        "stop_address": stop_address,
        "syntax": syntax,
        "line_count": len(stdout_lines),
        "window_lines": [line.strip() for line in stdout_lines if line.strip()][:24],
        "semantic_instruction_lines": [line.strip() for line in semantic_lines if line.strip()][:24],
    }
    observation = observation_from_host_result(
        tool="objdump_window",
        command=args,
        proc=result,
        stdout_budget=max_chars,
        parsed_facts=parsed_facts,
    )
    evidence = []
    if parsed_facts["window_lines"]:
        evidence.append(record_evidence(
            observation_id=observation["observation_id"],
            kind="disassembly_window",
            claim=f"objdump returned disassembly window {start_address}-{stop_address}.",
            excerpts=list(parsed_facts["window_lines"]),
            location={"address_range": f"{start_address}-{stop_address}"},
            excerpt_limit=24,
        ))
    if parsed_facts["semantic_instruction_lines"]:
        evidence.append(record_evidence(
            observation_id=observation["observation_id"],
            kind="disassembly_semantic_ops",
            claim=(
                f"objdump window {start_address}-{stop_address} contains comparison, bitwise, "
                "branch, call, or address-load instructions."
            ),
            excerpts=list(parsed_facts["semantic_instruction_lines"]),
            location={"address_range": f"{start_address}-{stop_address}"},
            excerpt_limit=24,
        ))
    if not result.get("ok"):
        bump_command_failure()
    return tool_response_from_observation(observation, evidence)
