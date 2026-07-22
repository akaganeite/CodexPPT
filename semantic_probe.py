"""PatchSpec-scoped semantic probes over bounded target-binary windows.

The model supplies a behavior id and two small OLD/NEW discriminator
definitions, but never executable code.  The Host validates the request, runs
a fixed objdump extractor inside the existing bubblewrap sandbox, and matches
the discriminator regexes deterministically.  Probe results become ordinary
target-binary observations/evidence; PatchSpec text itself remains non-evidence.
"""

from __future__ import annotations

import json
import re
import struct
import tempfile
from pathlib import Path
from typing import Any

from claudeagent.observations import observation_from_host_result, tool_response_from_observation
from claudeagent.runtime import (
    AGENT_CONTEXT,
    bump_command_failure,
    bump_metric,
    next_id,
    record_evidence,
)
from claudeagent.sandbox import SANDBOX_BINARY, run_in_sandbox


PROBE_KINDS = {"guard_before_focus", "ordered_sequence", "call_order"}
MAX_PROBE_BYTES = 0x10000
MAX_REGEXES_PER_SET = 8
MAX_REGEX_LENGTH = 160
MAX_LOCALIZATION_EVIDENCE = 8
MAX_INSTRUCTION_GAP = 64
HEX_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]+$")
INSTRUCTION_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s*(.*)$")
HEX_BYTE_RE = re.compile(r"^[0-9a-fA-F]{2}$")

# This script is intentionally constant.  Model-authored strings are never
# interpolated into Python or shell text; only validated integer addresses are
# placed in the adjacent JSON config file.
FIXED_OBJDUMP_SCRIPT = """\
import json
import os
import subprocess
import sys

config_path = os.path.splitext(__file__)[0] + ".json"
with open(config_path, "r", encoding="utf-8") as handle:
    config = json.load(handle)

argv = ["objdump", "-d"]
if config["intel_syntax"]:
    argv.append("-Mintel")
argv.extend(
    [
        "--start-address=" + hex(int(config["start_address"])),
        "--stop-address=" + hex(int(config["stop_address"])),
        "/workspace/binary",
    ]
)
proc = subprocess.run(
    argv,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
sys.stdout.write(proc.stdout)
sys.stderr.write(proc.stderr)
raise SystemExit(proc.returncode)
"""


def _error(message: str) -> dict[str, Any]:
    return {"ok": False, "tool": "run_semantic_probe", "error": message}


def _parse_address(value: Any, field: str) -> tuple[int | None, str | None]:
    if not isinstance(value, str) or not HEX_ADDRESS_RE.fullmatch(value):
        return None, f"{field} must be a hexadecimal string such as 0x401000"
    return int(value, 16), None


def _unsafe_regex_reason(pattern: Any) -> str | None:
    if not isinstance(pattern, str) or not pattern:
        return "must be a non-empty string"
    if len(pattern) > MAX_REGEX_LENGTH:
        return f"exceeds {MAX_REGEX_LENGTH} characters"
    if any(ord(char) < 0x20 or ord(char) > 0x7E for char in pattern):
        return "must contain printable ASCII only"
    if "(?" in pattern:
        return "lookaround and special groups are not allowed"
    if re.search(r"\\[1-9]", pattern):
        return "backreferences are not allowed"
    if "{" in pattern or "}" in pattern:
        return "bounded/repetition braces are not allowed"
    if re.search(r"\)[*+?]", pattern):
        return "quantified groups are not allowed"
    if re.search(r"(?:\.\*|\.\+).*(?:\.\*|\.\+)", pattern):
        return "multiple unbounded wildcards are not allowed"
    if not re.search(r"[A-Za-z0-9]", pattern):
        return "must contain at least one literal alphanumeric discriminator"
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        return f"does not compile: {exc}"
    return None


def _validate_expectation(value: Any, field: str) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return None, [f"{field} must be an object"]
    if set(value) != {"required_regexes", "forbidden_regexes", "ordered"}:
        errors.append(
            f"{field} must contain only required_regexes, forbidden_regexes, and ordered"
        )
    required = value.get("required_regexes")
    forbidden = value.get("forbidden_regexes")
    ordered = value.get("ordered")
    if not isinstance(required, list) or not required:
        errors.append(f"{field}.required_regexes must contain 1-{MAX_REGEXES_PER_SET} patterns")
        required = []
    elif len(required) > MAX_REGEXES_PER_SET:
        errors.append(f"{field}.required_regexes exceeds {MAX_REGEXES_PER_SET} patterns")
    if not isinstance(forbidden, list):
        errors.append(f"{field}.forbidden_regexes must be an array")
        forbidden = []
    elif len(forbidden) > MAX_REGEXES_PER_SET:
        errors.append(f"{field}.forbidden_regexes exceeds {MAX_REGEXES_PER_SET} patterns")
    if not isinstance(ordered, bool):
        errors.append(f"{field}.ordered must be boolean")
    for group_name, patterns in (("required_regexes", required), ("forbidden_regexes", forbidden)):
        for index, pattern in enumerate(patterns):
            reason = _unsafe_regex_reason(pattern)
            if reason:
                errors.append(f"{field}.{group_name}[{index}] {reason}")
    if errors:
        return None, errors
    return {
        "required_regexes": list(required),
        "forbidden_regexes": list(forbidden),
        "ordered": ordered,
    }, []


def parse_objdump_instructions(stdout: str) -> list[dict[str, Any]]:
    """Return normalized address/text records from objdump -d output."""
    instructions: list[dict[str, Any]] = []
    for raw_line in stdout.splitlines():
        match = INSTRUCTION_LINE_RE.match(raw_line)
        if not match:
            continue
        tokens = match.group(2).split()
        byte_count = 0
        while byte_count < len(tokens) and HEX_BYTE_RE.fullmatch(tokens[byte_count]):
            byte_count += 1
        if byte_count == 0 or byte_count == len(tokens):
            continue
        address = int(match.group(1), 16)
        text = " ".join(tokens[byte_count:])
        if not text:
            continue
        instructions.append({
            "address": address,
            "address_hex": f"0x{address:x}",
            "text": text,
            "line": f"0x{address:x}: {text}",
        })
    return instructions


def _pattern_positions(pattern: str, instructions: list[dict[str, Any]]) -> list[int]:
    compiled = re.compile(pattern, re.IGNORECASE)
    return [index for index, item in enumerate(instructions) if compiled.search(str(item["text"]))]


def _ordered_match(
    patterns: list[str],
    instructions: list[dict[str, Any]],
    max_instruction_gap: int,
    focus_positions: list[int],
    probe_kind: str,
) -> tuple[list[int], int] | None:
    position_sets = [_pattern_positions(pattern, instructions) for pattern in patterns]
    if any(not positions for positions in position_sets):
        return None
    paths: dict[int, list[int]] = {position: [position] for position in position_sets[0]}
    for positions in position_sets[1:]:
        next_paths: dict[int, list[int]] = {}
        for position in positions:
            candidates = [
                (previous, path)
                for previous, path in paths.items()
                if previous < position and position - previous - 1 <= max_instruction_gap
            ]
            if candidates:
                previous, path = max(candidates, key=lambda item: item[0])
                next_paths[position] = [*path, position]
        if not next_paths:
            return None
        paths = next_paths
    candidates: list[tuple[list[int], int, int]] = []
    for path in paths.values():
        for focus_position in focus_positions:
            if probe_kind == "guard_before_focus":
                distance = focus_position - path[-1]
                compatible = 0 <= distance <= max_instruction_gap
            elif path[0] <= focus_position <= path[-1]:
                distance = 0
                compatible = True
            else:
                distance = min(abs(focus_position - path[0]), abs(focus_position - path[-1]))
                compatible = distance <= max_instruction_gap
            if compatible:
                candidates.append((path, focus_position, distance))
    if not candidates:
        return None
    path, focus_position, _ = min(
        candidates,
        key=lambda item: (item[2], item[0][-1] - item[0][0], item[0], item[1]),
    )
    return path, focus_position


def _unordered_match(
    patterns: list[str],
    instructions: list[dict[str, Any]],
    max_instruction_gap: int,
    focus_positions: list[int],
    probe_kind: str,
) -> tuple[list[int], int] | None:
    position_sets = [_pattern_positions(pattern, instructions) for pattern in patterns]
    if any(not positions for positions in position_sets):
        return None
    candidates: list[tuple[list[int], int]] = []
    for focus_position in focus_positions:
        selected: list[int] = []
        for positions in position_sets:
            if probe_kind == "guard_before_focus":
                eligible = [
                    position
                    for position in positions
                    if 0 <= focus_position - position <= max_instruction_gap
                ]
            else:
                eligible = [
                    position
                    for position in positions
                    if abs(position - focus_position) <= max_instruction_gap
                ]
            if not eligible:
                selected = []
                break
            selected.append(min(eligible, key=lambda position: (abs(position - focus_position), position)))
        if selected:
            candidates.append((selected, focus_position))
    if not candidates:
        return None
    return min(
        candidates,
        key=lambda item: (max(item[0]) - min(item[0]), item[0], item[1]),
    )


def match_expectation(
    expectation: dict[str, Any],
    instructions: list[dict[str, Any]],
    *,
    focus_regex: str,
    max_instruction_gap: int,
    probe_kind: str = "ordered_sequence",
) -> dict[str, Any]:
    """Evaluate one OLD/NEW discriminator against normalized instructions."""
    focus_positions = _pattern_positions(focus_regex, instructions)
    required = [str(value) for value in expectation.get("required_regexes", [])]
    forbidden = [str(value) for value in expectation.get("forbidden_regexes", [])]
    if expectation.get("ordered"):
        match = _ordered_match(
            required,
            instructions,
            max_instruction_gap,
            focus_positions,
            probe_kind,
        )
    else:
        match = _unordered_match(
            required,
            instructions,
            max_instruction_gap,
            focus_positions,
            probe_kind,
        )

    if match is None:
        required_positions = None
        focus_position = None
        forbidden_positions: list[int] = []
    else:
        required_positions, focus_position = match
        context_start = max(0, min([*required_positions, focus_position]) - max_instruction_gap)
        context_stop = min(
            len(instructions) - 1,
            max([*required_positions, focus_position]) + max_instruction_gap,
        )
        forbidden_positions = sorted({
            position
            for pattern in forbidden
            for position in _pattern_positions(pattern, instructions)
            if context_start <= position <= context_stop
        })

    matched = required_positions is not None and not forbidden_positions
    selected = sorted(set([
        *([focus_position] if focus_position is not None else focus_positions[:1]),
        *((required_positions or [])[:MAX_REGEXES_PER_SET]),
        *(forbidden_positions[:2]),
    ]))
    return {
        "matched": matched,
        "focus_matched": bool(focus_positions),
        "required_matched": required_positions is not None,
        "forbidden_matched": bool(forbidden_positions),
        "matched_addresses": [instructions[index]["address_hex"] for index in selected],
        "matched_lines": [instructions[index]["line"] for index in selected],
    }


def classify_probe(
    instructions: list[dict[str, Any]],
    *,
    focus_regex: str,
    old_expectation: dict[str, Any],
    new_expectation: dict[str, Any],
    max_instruction_gap: int,
    probe_kind: str = "ordered_sequence",
) -> dict[str, Any]:
    """Evaluate both sides and return the deterministic four-way match."""
    old_match = match_expectation(
        old_expectation,
        instructions,
        focus_regex=focus_regex,
        max_instruction_gap=max_instruction_gap,
        probe_kind=probe_kind,
    )
    new_match = match_expectation(
        new_expectation,
        instructions,
        focus_regex=focus_regex,
        max_instruction_gap=max_instruction_gap,
        probe_kind=probe_kind,
    )
    if old_match["matched"] and new_match["matched"]:
        matched_side = "both"
    elif old_match["matched"]:
        matched_side = "old_only"
    elif new_match["matched"]:
        matched_side = "new_only"
    else:
        matched_side = "neither"
    matched_lines = list(dict.fromkeys([
        *old_match["matched_lines"],
        *new_match["matched_lines"],
    ]))
    matched_addresses = list(dict.fromkeys([
        *old_match["matched_addresses"],
        *new_match["matched_addresses"],
    ]))
    return {
        "matched_side": matched_side,
        "old_match": old_match,
        "new_match": new_match,
        "matched_lines": matched_lines,
        "matched_addresses": matched_addresses,
    }


def executable_ranges(binary_path: str) -> tuple[list[tuple[int, int]], int | None, str | None]:
    """Read executable, file-backed PT_LOAD ranges directly from an ELF file."""
    try:
        with open(binary_path, "rb") as handle:
            header = handle.read(64)
            if len(header) < 52 or header[:4] != b"\x7fELF":
                return [], None, "target is not a supported ELF binary"
            elf_class = header[4]
            elf_data = header[5]
            if elf_data == 1:
                endian = "<"
            elif elf_data == 2:
                endian = ">"
            else:
                return [], None, "ELF has an unsupported byte order"
            machine = struct.unpack_from(endian + "H", header, 18)[0]
            if elf_class == 1:
                phoff = struct.unpack_from(endian + "I", header, 28)[0]
                phentsize = struct.unpack_from(endian + "H", header, 42)[0]
                phnum = struct.unpack_from(endian + "H", header, 44)[0]
                minimum_phentsize = 32
            elif elf_class == 2:
                phoff = struct.unpack_from(endian + "Q", header, 32)[0]
                phentsize = struct.unpack_from(endian + "H", header, 54)[0]
                phnum = struct.unpack_from(endian + "H", header, 56)[0]
                minimum_phentsize = 56
            else:
                return [], machine, "ELF has an unsupported class"
            if phnum in {0, 0xFFFF} or phentsize < minimum_phentsize or phnum > 4096:
                return [], machine, "ELF program-header table is missing or unsupported"

            ranges: list[tuple[int, int]] = []
            for index in range(phnum):
                handle.seek(phoff + index * phentsize)
                entry = handle.read(phentsize)
                if len(entry) < minimum_phentsize:
                    return [], machine, "ELF program-header table is truncated"
                if elf_class == 1:
                    segment_type = struct.unpack_from(endian + "I", entry, 0)[0]
                    virtual_address = struct.unpack_from(endian + "I", entry, 8)[0]
                    file_size = struct.unpack_from(endian + "I", entry, 16)[0]
                    flags = struct.unpack_from(endian + "I", entry, 24)[0]
                else:
                    segment_type = struct.unpack_from(endian + "I", entry, 0)[0]
                    flags = struct.unpack_from(endian + "I", entry, 4)[0]
                    virtual_address = struct.unpack_from(endian + "Q", entry, 16)[0]
                    file_size = struct.unpack_from(endian + "Q", entry, 32)[0]
                if segment_type == 1 and flags & 0x1 and file_size:
                    ranges.append((virtual_address, virtual_address + file_size))
    except (OSError, struct.error) as exc:
        return [], None, f"could not parse target ELF program headers: {exc!r}"
    if not ranges:
        return [], machine, "ELF has no executable file-backed LOAD segment"
    return ranges, machine, None


def _probe_evidence(
    observation: dict[str, Any],
    *,
    behavior_id: str,
    probe_kind: str,
    start_address: int,
    stop_address: int,
    result: dict[str, Any],
) -> dict[str, Any]:
    matched_side = str(result["matched_side"])
    claim_by_side = {
        "old_only": "The bounded semantic probe matched only the OLD-side discriminator.",
        "new_only": "The bounded semantic probe matched only the NEW-side discriminator.",
        "both": "The bounded semantic probe matched both OLD and NEW discriminators and is ambiguous.",
        "neither": "The bounded semantic probe matched neither discriminator and is ambiguous.",
    }
    excerpts = [
        f"matched_side={matched_side}",
        f"window=0x{start_address:x}..0x{stop_address:x}",
        *result.get("matched_lines", []),
    ]
    return record_evidence(
        observation_id=observation["observation_id"],
        kind="semantic_probe",
        claim=claim_by_side[matched_side],
        excerpts=excerpts,
        location={
            "behavior_id": behavior_id,
            "probe_kind": probe_kind,
            "start_address": f"0x{start_address:x}",
            "stop_address": f"0x{stop_address:x}",
            "matched_side": matched_side,
            "matched_addresses": list(result.get("matched_addresses", [])),
        },
        confidence="supporting",
        excerpt_limit=16,
        polarity="negative" if matched_side == "neither" else "positive",
    )


def run_semantic_probe(
    *,
    behavior_id: str,
    localization_evidence_ids: list[str],
    probe_kind: str,
    start_address: str,
    stop_address: str,
    focus_regex: str,
    old_expectation: dict[str, Any],
    new_expectation: dict[str, Any],
    max_instruction_gap: int,
) -> dict[str, Any]:
    """Run a validated OLD/NEW discriminator over one executable address window."""
    bump_metric("semantic_probe_calls")
    known_behaviors = {
        str(item.get("behavior_id"))
        for item in AGENT_CONTEXT.get("patch_spec_behavior_contract", [])
        if isinstance(item, dict) and item.get("behavior_id")
    }
    if behavior_id not in known_behaviors:
        return _error(
            f"unknown behavior_id {behavior_id!r}; expected one of {sorted(known_behaviors)}"
        )
    if probe_kind not in PROBE_KINDS:
        return _error(f"probe_kind must be one of {sorted(PROBE_KINDS)}")

    if not isinstance(localization_evidence_ids, list) or not localization_evidence_ids:
        return _error("localization_evidence_ids must contain at least one ledger evidence id")
    if len(localization_evidence_ids) > MAX_LOCALIZATION_EVIDENCE:
        return _error(
            f"localization_evidence_ids exceeds {MAX_LOCALIZATION_EVIDENCE} items"
        )
    normalized_ids = [str(value) for value in localization_evidence_ids]
    if len(normalized_ids) != len(set(normalized_ids)):
        return _error("localization_evidence_ids must not contain duplicates")
    ledger_by_id = {
        str(item.get("evidence_id")): item
        for item in AGENT_CONTEXT.get("evidence_ledger", [])
        if isinstance(item, dict) and item.get("evidence_id")
    }
    unknown_ids = sorted(set(normalized_ids) - set(ledger_by_id))
    if unknown_ids:
        return _error(f"localization evidence id(s) not in the ledger: {unknown_ids}")
    if not any(
        str(ledger_by_id[evidence_id].get("polarity", "positive")) == "positive"
        and str(ledger_by_id[evidence_id].get("kind", "")) != "semantic_probe"
        for evidence_id in normalized_ids
    ):
        return _error(
            "localization requires at least one positive non-probe target-binary evidence item"
        )

    start, start_error = _parse_address(start_address, "start_address")
    stop, stop_error = _parse_address(stop_address, "stop_address")
    if start_error or stop_error:
        return _error("; ".join(error for error in (start_error, stop_error) if error))
    assert start is not None and stop is not None
    if stop <= start:
        return _error("stop_address must be greater than start_address")
    if stop - start > MAX_PROBE_BYTES:
        return _error(f"probe window exceeds the {MAX_PROBE_BYTES}-byte limit")
    if not isinstance(max_instruction_gap, int) or isinstance(max_instruction_gap, bool):
        return _error("max_instruction_gap must be an integer")
    if not 0 <= max_instruction_gap <= MAX_INSTRUCTION_GAP:
        return _error(f"max_instruction_gap must be between 0 and {MAX_INSTRUCTION_GAP}")

    focus_reason = _unsafe_regex_reason(focus_regex)
    if focus_reason:
        return _error(f"focus_regex {focus_reason}")
    normalized_old, old_errors = _validate_expectation(old_expectation, "old_expectation")
    normalized_new, new_errors = _validate_expectation(new_expectation, "new_expectation")
    if old_errors or new_errors:
        return _error("; ".join([*old_errors, *new_errors]))
    assert normalized_old is not None and normalized_new is not None
    if normalized_old == normalized_new:
        return _error("old_expectation and new_expectation must be different discriminators")

    binary_path = str(AGENT_CONTEXT.get("binary_path", ""))
    scratch_dir = str(AGENT_CONTEXT.get("scratch_dir", ""))
    if not binary_path or not scratch_dir:
        return _error("AGENT_CONTEXT scratch_dir/binary_path not initialized")
    ranges, machine, ranges_error = executable_ranges(binary_path)
    if ranges_error:
        bump_command_failure()
        return _error(ranges_error)
    if not any(start >= range_start and stop <= range_stop for range_start, range_stop in ranges):
        rendered = [f"0x{range_start:x}..0x{range_stop:x}" for range_start, range_stop in ranges[:8]]
        return _error(
            "probe window must be wholly contained in one executable ELF range; "
            f"available ranges include {rendered}"
        )

    probe_name = next_id("semantic_probe", "semantic_probe_counter")
    try:
        probe_dir = Path(tempfile.mkdtemp(prefix=f"{probe_name}-", dir=scratch_dir))
        script_path = probe_dir / "probe.py"
        config_path = probe_dir / "probe.json"
        script_path.write_text(FIXED_OBJDUMP_SCRIPT, encoding="utf-8")
        config_path.write_text(
            json.dumps({
                "start_address": start,
                "stop_address": stop,
                "intel_syntax": machine in {3, 62},
            }),
            encoding="utf-8",
        )
    except OSError as exc:
        bump_command_failure()
        return _error(f"failed to prepare semantic probe: {exc!r}")

    proc = run_in_sandbox(
        script_path=str(script_path),
        scratch_dir=scratch_dir,
        binary_path=binary_path,
        timeout=30,
        max_output_chars=None,
    )
    command = ["objdump", "-d"]
    if machine in {3, 62}:
        command.append("-Mintel")
    command.extend([
        f"--start-address=0x{start:x}",
        f"--stop-address=0x{stop:x}",
        SANDBOX_BINARY,
    ])
    definition = {
        "behavior_id": behavior_id,
        "localization_evidence_ids": normalized_ids,
        "probe_kind": probe_kind,
        "start_address": f"0x{start:x}",
        "stop_address": f"0x{stop:x}",
        "focus_regex": focus_regex,
        "old_expectation": normalized_old,
        "new_expectation": normalized_new,
        "max_instruction_gap": max_instruction_gap,
    }
    if not proc.get("ok"):
        bump_command_failure()
        observation = observation_from_host_result(
            tool="run_semantic_probe",
            command=command,
            proc=proc,
            stdout_budget=12000,
            parsed_facts={"command": "objdump", "probe_definition": definition},
        )
        return tool_response_from_observation(observation, [])

    instructions = parse_objdump_instructions(str(proc.get("stdout", "")))
    if not instructions:
        bump_command_failure()
        empty_proc = {
            **proc,
            "ok": False,
            "stdout": "",
            "error": "bounded objdump window contained no complete instructions",
        }
        observation = observation_from_host_result(
            tool="run_semantic_probe",
            command=command,
            proc=empty_proc,
            stdout_budget=12000,
            parsed_facts={
                "command": "objdump",
                "probe_definition": definition,
                "instruction_count": 0,
            },
        )
        return tool_response_from_observation(observation, [])
    result = classify_probe(
        instructions,
        focus_regex=focus_regex,
        old_expectation=normalized_old,
        new_expectation=normalized_new,
        max_instruction_gap=max_instruction_gap,
        probe_kind=probe_kind,
    )
    parsed_facts = {
        "command": "objdump",
        "probe_definition": definition,
        "instruction_count": len(instructions),
        **result,
    }
    summary_proc = {
        **proc,
        "stdout": json.dumps({
            "matched_side": result["matched_side"],
            "instruction_count": len(instructions),
            "matched_addresses": result["matched_addresses"],
            "matched_lines": result["matched_lines"],
        }, ensure_ascii=False, indent=2),
    }
    observation = observation_from_host_result(
        tool="run_semantic_probe",
        command=command,
        proc=summary_proc,
        stdout_budget=12000,
        parsed_facts=parsed_facts,
    )
    evidence = _probe_evidence(
        observation,
        behavior_id=behavior_id,
        probe_kind=probe_kind,
        start_address=start,
        stop_address=stop,
        result=result,
    )
    return tool_response_from_observation(observation, [evidence])
