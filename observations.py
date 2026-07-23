"""Typed observations and generic evidence extraction.

Every command an inspection tool runs becomes an ``obs_XXXX`` observation, and the
salient parts of that observation are minted into pending ``ev_XXXX`` ledger items.
The Host preserves a neutral claim and the raw excerpts; the main investigator
must later attach a natural-language claim before an evidence id can be cited.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

from claudeagent.common import compact_lines
from claudeagent.runtime import AGENT_CONTEXT, bump_metric, ensure_runtime_state, next_id, record_evidence
from claudeagent.truncation import text_head_tail


DEFAULT_TEXT_BUDGET = 60000
DEFAULT_STDERR_BUDGET = 12000
MODEL_STDOUT_BUDGET = 6000
MODEL_STDERR_BUDGET = 2000
MODEL_LIST_LIMIT = 12
MODEL_STRING_LIMIT = 1200


def parsed_facts_for_command(argv: list[str], stdout: str, stderr: str, returncode: int | None) -> dict[str, Any]:
    command = Path(argv[0]).name if argv else ""
    facts: dict[str, Any] = {"command": command}
    lines = stdout.splitlines()
    if command == "file":
        facts["file_summary"] = stdout.strip()
    elif command in {"sha1sum", "sha256sum"}:
        facts["checksum_line"] = stdout.strip().splitlines()[:1]
    elif command == "nm":
        facts["line_count"] = len(lines)
        facts["defined_text_symbols_sample"] = [
            line.strip()
            for line in lines
            if len(line.strip().split()) >= 3 and line.strip().split()[1].lower() in {"t", "w"}
        ][:12]
    elif command == "readelf":
        needed_libraries = []
        for line in lines:
            if "NEEDED" not in line:
                continue
            match = re.search(r"\[([^\]]+)\]", line)
            if match:
                needed_libraries.append(match.group(1))
        facts["line_count"] = len(lines)
        facts["section_mentions"] = compact_lines(
            [line for line in lines if re.search(r"\.(text|rodata|dynsym|symtab|rela?|plt)\b", line)],
            limit=12,
        )
        facts["needed_libraries"] = needed_libraries[:40]
        facts["dynamic_libraries"] = compact_lines(
            [line for line in lines if "Shared library:" in line or "NEEDED" in line],
            limit=20,
        )
    elif command == "objdump":
        facts["line_count"] = len(lines)
        facts["call_lines_sample"] = compact_lines(
            [line for line in lines if re.search(r"\bcall", line)],
            limit=16,
        )
        facts["cmp_test_lines_sample"] = compact_lines(
            [line for line in lines if re.search(r"\b(cmp|test|and|or|xor|lea|set[a-z]+)\b", line)],
            limit=16,
        )
    elif command == "strings":
        facts["line_count"] = len(lines)
        # With `strings -a -tx` each line is "<hexoffset> <text>"; keep offset-bearing samples.
        offset_lines = [line.strip() for line in lines if re.match(r"\s*[0-9a-fA-F]+\s+\S", line)]
        facts["strings_sample"] = compact_lines(offset_lines or lines, limit=16)
    else:
        facts["line_count"] = len(lines)
    if command == "sh" and returncode == 1 and not stdout.strip():
        facts["empty_filter_result"] = True
        facts["shell_script"] = argv[2] if len(argv) >= 3 else ""
    if returncode not in {0, None}:
        facts["nonzero_returncode"] = returncode
    if stderr.strip():
        facts["stderr_sample"] = compact_lines(stderr.splitlines(), limit=6)
    return facts


def observation_from_host_result(
    *,
    tool: str,
    command: list[str],
    proc: dict[str, Any],
    stdout_budget: int,
    stderr_budget: int = DEFAULT_STDERR_BUDGET,
    parsed_facts: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ensure_runtime_state()
    observation_id = next_id("obs", "observation_counter")
    stdout = str(proc.get("stdout", ""))
    stderr = str(proc.get("stderr", ""))
    stdout_parts = text_head_tail(stdout, stdout_budget)
    stderr_parts = text_head_tail(stderr, stderr_budget)
    truncated = bool(stdout_parts["truncated"] or stderr_parts["truncated"])
    if truncated:
        bump_metric("truncated_observations")
    observation = {
        "observation_id": observation_id,
        "tool": tool,
        "command": command,
        "command_text": " ".join(shlex.quote(x) for x in command),
        "exit_code": proc.get("returncode"),
        "ok": bool(proc.get("ok")),
        "elapsed_sec": proc.get("elapsed_sec"),
        "stdout_head": stdout_parts["head"],
        "stdout_tail": stdout_parts["tail"],
        "stderr_tail": stderr_parts["tail"] or stderr_parts["head"],
        "truncated": truncated,
        "truncation": {
            "stdout_omitted_bytes": stdout_parts["omitted_bytes"],
            "stdout_omitted_chars": stdout_parts["omitted_chars"],
            "stderr_omitted_bytes": stderr_parts["omitted_bytes"],
            "stderr_omitted_chars": stderr_parts["omitted_chars"],
            "stdout_original_bytes": stdout_parts["original_bytes"],
            "stdout_original_chars": stdout_parts["original_chars"],
            "stderr_original_bytes": stderr_parts["original_bytes"],
            "stderr_original_chars": stderr_parts["original_chars"],
        },
        "parsed_facts": parsed_facts or parsed_facts_for_command(command, stdout, stderr, proc.get("returncode")),
    }
    if proc.get("error"):
        observation["error"] = proc.get("error")
    if extra:
        observation.update(extra)
    AGENT_CONTEXT["observations"].append(observation)
    return observation


def tool_response_from_observation(observation: dict[str, Any], evidence: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "ok": observation.get("ok", False),
        "observation_id": observation["observation_id"],
        "tool": observation["tool"],
        "command": observation.get("command", []),
        "command_text": observation.get("command_text", ""),
        "exit_code": observation.get("exit_code"),
        "stdout_head": observation.get("stdout_head", ""),
        "stdout_tail": observation.get("stdout_tail", ""),
        "stderr_tail": observation.get("stderr_tail", ""),
        "truncated": observation.get("truncated", False),
        "truncation": observation.get("truncation", {}),
        "parsed_facts": observation.get("parsed_facts", {}),
        "evidence": evidence or [],
        "error": observation.get("error", ""),
    }


def compact_value_for_model(value: Any, *, depth: int = 0) -> Any:
    if isinstance(value, str):
        if len(value) <= MODEL_STRING_LIMIT:
            return value
        parts = text_head_tail(value, MODEL_STRING_LIMIT)
        return {
            "head": parts["head"],
            "tail": parts["tail"],
            "omitted_chars": parts["omitted_chars"],
            "original_chars": parts["original_chars"],
        }
    if isinstance(value, list):
        items = [compact_value_for_model(item, depth=depth + 1) for item in value[:MODEL_LIST_LIMIT]]
        if len(value) > MODEL_LIST_LIMIT:
            items.append({"omitted_items": len(value) - MODEL_LIST_LIMIT, "original_items": len(value)})
        return items
    if isinstance(value, dict):
        return {key: compact_value_for_model(item, depth=depth + 1) for key, item in value.items()}
    return value


def compact_evidence_for_model(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compacted = []
    for item in evidence[:16]:
        excerpts = item.get("supporting_excerpt") if isinstance(item.get("supporting_excerpt"), list) else []
        compacted.append({
            "evidence_id": item.get("evidence_id"),
            "observation_id": item.get("observation_id"),
            "kind": item.get("kind"),
            "host_claim": compact_value_for_model(item.get("host_claim", "")),
            "claim": item.get("claim"),
            "claim_source": item.get("claim_source", "host"),
            "claim_status": item.get("claim_status", "pending"),
            "claim_revision": item.get("claim_revision", 0),
            "supporting_excerpt": compact_value_for_model(excerpts[:8]),
            "location": compact_value_for_model(item.get("location", {})),
            "polarity": item.get("polarity", "positive"),
        })
    if len(evidence) > 16:
        compacted.append({"omitted_evidence_items": len(evidence) - 16, "original_items": len(evidence)})
    return compacted


def compact_tool_result_for_model(result: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(result, dict):
        return result
    if result.get("tool") == "summarize_evidence":
        return {
            "_compacted_for_model": True,
            "ok": result.get("ok", False),
            "tool": "summarize_evidence",
            "observation_id": result.get("observation_id", ""),
            "evidence": compact_evidence_for_model(
                result.get("evidence", []) if isinstance(result.get("evidence"), list) else []
            ),
            "updated_count": result.get("updated_count", 0),
            "revision_count": result.get("revision_count", 0),
            "idempotent_evidence_ids": result.get("idempotent_evidence_ids", []),
            "error": result.get("error", ""),
        }
    stdout_text = f"{result.get('stdout_head', '')}\n{result.get('stdout_tail', '')}"
    stderr_text = str(result.get("stderr_tail", ""))
    stdout_parts = text_head_tail(stdout_text.strip(), MODEL_STDOUT_BUDGET)
    stderr_parts = text_head_tail(stderr_text, MODEL_STDERR_BUDGET)
    return {
        "_compacted_for_model": True,
        "ok": result.get("ok", False),
        "observation_id": result.get("observation_id", ""),
        "tool": result.get("tool", ""),
        "command_text": result.get("command_text", ""),
        "exit_code": result.get("exit_code"),
        "stdout_head": stdout_parts["head"],
        "stdout_tail": stdout_parts["tail"],
        "stderr_tail": stderr_parts["tail"] or stderr_parts["head"],
        "truncated": bool(result.get("truncated") or stdout_parts["truncated"] or stderr_parts["truncated"]),
        "truncation": {
            **(result.get("truncation") if isinstance(result.get("truncation"), dict) else {}),
            "model_stdout_omitted_chars": stdout_parts["omitted_chars"],
            "model_stderr_omitted_chars": stderr_parts["omitted_chars"],
        },
        "parsed_facts": compact_value_for_model(result.get("parsed_facts", {})),
        "evidence": compact_evidence_for_model(result.get("evidence", []) if isinstance(result.get("evidence"), list) else []),
        "error": result.get("error", ""),
    }


def negative_evidence(
    *,
    observation: dict[str, Any],
    kind: str,
    claim: str,
    excerpts: list[str],
    location: dict[str, Any] | None = None,
    excerpt_limit: int = 8,
) -> dict[str, Any]:
    return record_evidence(
        observation_id=observation["observation_id"],
        kind=kind,
        claim=claim,
        excerpts=excerpts,
        location=location,
        confidence="supporting",
        excerpt_limit=excerpt_limit,
        polarity="negative",
    )


def evidence_from_command_observation(observation: dict[str, Any]) -> list[dict[str, Any]]:
    """Mint ledger evidence from a generic command observation's parsed facts."""
    facts = observation.get("parsed_facts") if isinstance(observation.get("parsed_facts"), dict) else {}
    obs_id = observation["observation_id"]
    evidence: list[dict[str, Any]] = []

    def add(kind: str, claim: str, excerpts: list[str], limit: int = 12) -> None:
        if excerpts:
            evidence.append(record_evidence(
                observation_id=obs_id, kind=kind, claim=claim, excerpts=excerpts, excerpt_limit=limit,
            ))

    if facts.get("file_summary"):
        add("file_summary", "file identified the target artifact format and ELF class/arch.", [str(facts["file_summary"])])
    if facts.get("defined_text_symbols_sample"):
        add("symbol_sample", "nm reported defined text symbols that can anchor analysis.", list(facts["defined_text_symbols_sample"]))
    if facts.get("needed_libraries"):
        add(
            "needed_libraries_complete",
            "readelf dynamic section listed the binary's NEEDED shared libraries.",
            [f"NEEDED {item}" for item in facts["needed_libraries"]],
            limit=40,
        )
    if facts.get("dynamic_libraries") and not facts.get("needed_libraries"):
        add("dynamic_libraries", "readelf reported linked shared libraries.", list(facts["dynamic_libraries"]))
    if facts.get("section_mentions"):
        add("elf_sections", "readelf reported relevant ELF sections.", list(facts["section_mentions"]))
    if facts.get("strings_sample"):
        add(
            "strings_output",
            "strings output contains offset-bearing rodata anchors for the current hypothesis.",
            list(facts["strings_sample"]),
            limit=16,
        )
    if facts.get("call_lines_sample"):
        add(
            "disassembly_calls",
            "objdump disassembly contains call instructions in the inspected window.",
            list(facts["call_lines_sample"]),
            limit=16,
        )
    if facts.get("cmp_test_lines_sample"):
        add(
            "disassembly_predicates",
            "objdump disassembly contains comparison/bitwise/lea instructions in the inspected window.",
            list(facts["cmp_test_lines_sample"]),
            limit=16,
        )

    # Fallback: record whatever bounded stdout we captured so the observation is citable.
    if not evidence and observation.get("ok") and (observation.get("stdout_head") or observation.get("stdout_tail")):
        excerpts = compact_lines(
            [
                *str(observation.get("stdout_head", "")).splitlines(),
                *str(observation.get("stdout_tail", "")).splitlines(),
            ],
            limit=8,
        )
        add("command_output", "bounded command output was recorded for the current hypothesis.", excerpts)

    if not evidence and facts.get("empty_filter_result"):
        evidence.append(negative_evidence(
            observation=observation,
            kind="no_pipeline_match",
            claim="read-only shell/filter pipeline produced no stdout matches.",
            excerpts=[
                f"script={facts.get('shell_script', '')}",
                "exit_code=1",
                "stdout_lines=0",
            ],
        ))
    return evidence
