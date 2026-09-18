"""Read-only Ghidra inspection tools.

The tools in this module expose bounded, structured Ghidra observations to the
model. They deliberately avoid raw script/eval/project access: every response is
sanitized to ``target_binary`` plus addresses, carries an observation id, and
mints evidence only from raw instruction/CFG/P-code-backed excerpts.
"""

from __future__ import annotations

import fcntl
import itertools
import json
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Iterator

from pydantic import Field

GHIDRA_STDOUT_BUDGET = 20000
GHIDRA_PARSED_FACTS_BUDGET = 30000
MAX_FUNCTION_INSTRUCTIONS = 5000
MAX_BLOCKS = 500


@dataclass
class GhidraRuntime:
    cache_entry: Path
    install_dir: Path | None
    query_log: Path
    timeout_sec: int

    @property
    def binary(self) -> Path:
        return self.cache_entry / "target_binary"

    @property
    def project(self) -> Path:
        return self.cache_entry / "project"


RUNTIME: GhidraRuntime | None = None
OBSERVATION_COUNTER = itertools.count(1)
PROCESS_QUERY_SLOT: Any | None = None
PROCESS_QUERY_SLOT_ROOT: Path | None = None


def configure_runtime(
    cache_entry: Path,
    install_dir: Path | None,
    query_log: Path,
    timeout_sec: int,
) -> None:
    global PROCESS_QUERY_SLOT, PROCESS_QUERY_SLOT_ROOT, RUNTIME
    resolved_cache = cache_entry.expanduser().resolve()
    if PROCESS_QUERY_SLOT is not None and PROCESS_QUERY_SLOT_ROOT != resolved_cache.parent:
        PROCESS_QUERY_SLOT.close()
        PROCESS_QUERY_SLOT = None
        PROCESS_QUERY_SLOT_ROOT = None
    RUNTIME = GhidraRuntime(
        cache_entry=resolved_cache,
        install_dir=install_dir.expanduser().resolve() if install_dir is not None else None,
        query_log=query_log.expanduser().resolve(),
        timeout_sec=timeout_sec,
    )


def ghidra_is_available() -> bool:
    return bool(
        RUNTIME is not None
        and RUNTIME.binary.is_file()
        and RUNTIME.project.is_dir()
        and (RUNTIME.cache_entry / "analysis_meta.json").is_file()
    )


def _sanitize(text: Any) -> str:
    value = str(text)
    if RUNTIME is not None:
        for path in (
            RUNTIME.binary,
            RUNTIME.project,
            RUNTIME.cache_entry,
            RUNTIME.install_dir,
            RUNTIME.query_log,
        ):
            if path is None:
                continue
            value = value.replace(str(path), "target_binary")
    value = re.sub(
        r"(?<![A-Za-z0-9_.-])/(?:[A-Za-z0-9._+@-]+/)+[A-Za-z0-9._+@-]*",
        "target_binary",
        value,
    )
    return value


def _sanitize_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _sanitize_json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_json_value(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_json_value(item) for item in value]
    if isinstance(value, str) or isinstance(value, Path):
        return _sanitize(value)
    return value


def _head_tail(text: str, budget: int) -> tuple[str, str, bool, int]:
    if len(text) <= budget:
        return text, "", False, 0
    head_size = budget * 2 // 3
    tail_size = budget - head_size
    return text[:head_size], text[-tail_size:], True, len(text) - budget


def _bounded_parsed_facts(value: dict[str, Any]) -> tuple[dict[str, Any], bool, int]:
    encoded = json.dumps(value, ensure_ascii=False, default=str)
    if len(encoded) <= GHIDRA_PARSED_FACTS_BUDGET:
        return value, False, 0
    preview_budget = GHIDRA_PARSED_FACTS_BUDGET - 1000
    return {
        "available": bool(value.get("available")),
        "status": "parsed_facts_truncated",
        "top_level_keys": sorted(str(key) for key in value)[:80],
        "json_preview": encoded[:preview_budget],
        "omitted_chars": len(encoded) - preview_budget,
    }, True, len(encoded) - preview_budget


def _response(
    tool: str,
    args: dict[str, Any],
    stdout: str,
    parsed_facts: dict[str, Any],
    evidence_specs: list[dict[str, Any]] | None = None,
    *,
    ok: bool = True,
    error: str = "",
    elapsed: float = 0.0,
) -> dict[str, Any]:
    observation_id = f"ghidra_obs_{next(OBSERVATION_COUNTER):04d}"
    sanitized_stdout = _sanitize(stdout)
    stdout_head, stdout_tail, truncated, omitted_chars = _head_tail(
        sanitized_stdout,
        GHIDRA_STDOUT_BUDGET,
    )
    sanitized_facts = _sanitize_json_value(parsed_facts)
    bounded_facts, facts_truncated, facts_omitted_chars = _bounded_parsed_facts(sanitized_facts)
    evidence: list[dict[str, Any]] = []
    if ok:
        for index, spec in enumerate(evidence_specs or [], 1):
            evidence.append(
                {
                    "evidence_id": f"{observation_id}_ev_{index:02d}",
                    "observation_id": observation_id,
                    "kind": spec["kind"],
                    "claim": _sanitize(spec["claim"]),
                    "supporting_excerpt": [_sanitize(item) for item in spec.get("excerpts", [])[:8]],
                    "location": _sanitize_json_value(spec.get("location", {})),
                    "polarity": spec.get("polarity", "positive"),
                    "raw_backed": spec["kind"] != "ghidra_decompile_slice",
                }
            )
    result = {
        "ok": ok,
        "observation_id": observation_id,
        "tool": tool,
        "target": "target_binary",
        "elapsed_sec": round(elapsed, 3),
        "stdout_head": stdout_head,
        "stdout_tail": stdout_tail,
        "stderr_tail": "",
        "truncated": truncated or facts_truncated,
        "truncation": {
            "stdout_omitted_chars": omitted_chars,
            "parsed_facts_omitted_chars": facts_omitted_chars,
        },
        "parsed_facts": bounded_facts,
        "evidence": evidence,
        "error": _sanitize(error),
    }
    record_ghidra_query(tool, args, result)
    return result


def record_ghidra_query(tool: str, args: dict[str, Any], result: dict[str, Any]) -> None:
    if RUNTIME is None:
        return
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tool": tool,
        "arguments": args,
        "elapsed_sec": result.get("elapsed_sec", 0),
        "ok": bool(result.get("ok")),
        "observation_id": result.get("observation_id", ""),
        "result_size_chars": len(json.dumps(result, ensure_ascii=False, default=str)),
    }
    RUNTIME.query_log.parent.mkdir(parents=True, exist_ok=True)
    with RUNTIME.query_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    with (RUNTIME.cache_entry / "tool_queries.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _unavailable(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    started = time.time()
    reason = "Ghidra runtime is not configured for target_binary"
    return _response(
        tool,
        args,
        f"Ghidra unavailable for target_binary: {reason}",
        {"available": False, "reason": reason, "status": "unavailable"},
        ok=False,
        error=str(reason),
        elapsed=time.time() - started,
    )


def _addr_int(addr: Any) -> int:
    text = str(addr).strip()
    if text.startswith("0x"):
        return int(text, 16)
    return int(text, 16)


def _fmt_addr(addr: Any) -> str:
    try:
        return f"0x{_addr_int(addr):x}"
    except Exception:
        return str(addr)


def _addr(program: Any, text: str) -> Any:
    cleaned = str(text).strip()
    if cleaned.startswith("candidate_"):
        cleaned = cleaned.split("candidate_", 1)[1]
    if cleaned.startswith("function:"):
        cleaned = cleaned.split(":", 1)[1]
    cleaned = cleaned.strip()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(cleaned)


@contextmanager
def _open_program() -> Iterator[tuple[Any, Any, Any, Any]]:
    if not ghidra_is_available():
        raise RuntimeError("Ghidra is not enabled")
    assert RUNTIME is not None
    try:
        import pyghidra  # type: ignore

        _hold_process_query_slot()
        if RUNTIME.install_dir is not None:
            pyghidra.start(install_dir=str(RUNTIME.install_dir))
        else:
            pyghidra.start()
        from ghidra.util.task import TaskMonitor  # type: ignore

        with (RUNTIME.cache_entry / "query.lock").open("a+", encoding="utf-8") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            with pyghidra.open_program(
                str(RUNTIME.binary),
                project_location=str(RUNTIME.project),
                project_name="project",
                analyze=False,
                program_name="target_binary",
            ) as api:
                program = api.getCurrentProgram()
                yield api, program, program.getListing(), TaskMonitor.DUMMY
    except Exception as exc:
        raise RuntimeError(f"Ghidra query failed: {exc!r}") from exc


def _hold_process_query_slot() -> None:
    """Keep one cross-process JVM slot for the lifetime of this MCP process."""

    global PROCESS_QUERY_SLOT, PROCESS_QUERY_SLOT_ROOT
    if PROCESS_QUERY_SLOT is not None:
        return
    assert RUNTIME is not None
    slot_path = RUNTIME.cache_entry.parent / ".query-jvm.lock"
    handle = slot_path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    except Exception:
        handle.close()
        raise
    PROCESS_QUERY_SLOT = handle
    PROCESS_QUERY_SLOT_ROOT = RUNTIME.cache_entry.parent


def _function_for(program: Any, function: str) -> Any:
    fm = program.getFunctionManager()
    address = _addr(program, function)
    func = fm.getFunctionAt(address) or fm.getFunctionContaining(address)
    if func is None:
        raise ValueError(f"no function contains {function}")
    return func


def _function_ranges(func: Any, limit: int = 64) -> list[dict[str, str]]:
    ranges = []
    for item in func.getBody().getAddressRanges():
        if len(ranges) >= limit:
            break
        ranges.append({"start": _fmt_addr(item.getMinAddress()), "end": _fmt_addr(item.getMaxAddress())})
    return ranges


def _instruction_lines(listing: Any, address_set: Any, limit: int = MAX_FUNCTION_INSTRUCTIONS) -> list[dict[str, Any]]:
    rows = []
    for inst in listing.getInstructions(address_set, True):
        if len(rows) >= limit:
            break
        rows.append({
            "address": _fmt_addr(inst.getAddress()),
            "mnemonic": str(inst.getMnemonicString()),
            "instruction": str(inst),
            "text": f"{_fmt_addr(inst.getAddress())}: {inst}",
        })
    return rows


def _callee_name(program: Any, inst: Any) -> str:
    refs = program.getReferenceManager().getReferencesFrom(inst.getAddress())
    fm = program.getFunctionManager()
    for ref in refs:
        try:
            if ref.getReferenceType().isCall():
                target = ref.getToAddress()
                func = fm.getFunctionAt(target) or fm.getFunctionContaining(target)
                return str(func.getName()) if func else _fmt_addr(target)
        except Exception:
            continue
    return ""


def _function_call_edges(program: Any, func: Any, listing: Any) -> list[dict[str, str]]:
    edges = []
    for inst in listing.getInstructions(func.getBody(), True):
        if len(edges) >= 100:
            break
        callee = _callee_name(program, inst)
        if callee:
            edges.append({"site": _fmt_addr(inst.getAddress()), "callee": callee, "instruction": str(inst)})
    return edges


def _function_covers_giant_text(program: Any, func: Any) -> tuple[bool, dict[str, Any]]:
    try:
        text_block = program.getMemory().getBlock(".text")
        if text_block is None:
            return False, {}
        text_size = int(text_block.getSize())
        body_size = int(func.getBody().getNumAddresses())
        ratio = body_size / text_size if text_size else 0.0
        return bool(text_size >= 65536 and ratio >= 0.5), {
            "text_size": text_size,
            "function_body_size": body_size,
            "text_coverage_ratio": round(ratio, 4),
        }
    except Exception:
        return False, {}


def _constants_from_instruction(text: str) -> list[str]:
    return re.findall(r"0x[0-9a-fA-F]+|\b\d{2,}\b", text)


def _is_generic_constant(text: str) -> bool:
    try:
        value = int(text, 16) if str(text).lower().startswith("0x") else int(text, 10)
    except ValueError:
        return False
    return 0 <= value <= 0xFF


def _match_pattern(pattern: str, text: str) -> bool:
    try:
        return re.search(pattern, text, re.IGNORECASE) is not None
    except re.error:
        return pattern.lower() in text.lower()


def _block_id(block: Any) -> str:
    return _fmt_addr(block.getFirstStartAddress())


def _all_blocks(program: Any, monitor: Any, func: Any | None = None) -> list[Any]:
    try:
        from ghidra.program.model.block import BasicBlockModel  # type: ignore

        model = BasicBlockModel(program)
        blocks = []
        for block in model.getCodeBlocks(monitor):
            if len(blocks) >= MAX_BLOCKS:
                break
            if func is not None:
                try:
                    if not func.getBody().contains(block.getFirstStartAddress()):
                        continue
                except Exception:
                    continue
            blocks.append(block)
        return blocks
    except Exception:
        return []


def _block_lines(program: Any, listing: Any, block: Any, limit: int = 80) -> list[str]:
    try:
        from ghidra.program.model.address import AddressSet  # type: ignore

        aset = AddressSet(block.getFirstStartAddress(), block.getMaxAddress())
        return [row["text"] for row in _instruction_lines(listing, aset, limit)]
    except Exception:
        return []


def _block_edges(block: Any, monitor: Any, direction: str) -> list[str]:
    refs = block.getDestinations(monitor) if direction == "successors" else block.getSources(monitor)
    out = []
    try:
        for ref in refs:
            target = ref.getDestinationBlock() if direction == "successors" else ref.getSourceBlock()
            out.append(_block_id(target))
    except Exception:
        return out
    return out[:40]


def _block_containing(blocks: list[Any], address: Any) -> Any | None:
    target = _addr_int(address)
    for block in blocks:
        try:
            lo = _addr_int(block.getFirstStartAddress())
            hi = _addr_int(block.getMaxAddress())
            if lo <= target <= hi:
                return block
        except Exception:
            continue
    return None


def ghidra_locate_function(
    strings: Annotated[list[str], Field(max_length=40)],
    calls: Annotated[list[str], Field(max_length=40)],
    constants: Annotated[list[str], Field(max_length=40)],
    field_offsets: Annotated[list[str], Field(max_length=40)],
    max_candidates: Annotated[int, Field(ge=1, le=40)],
) -> dict[str, Any]:
    """Rank Ghidra functions by string/call/constant/field-offset anchors."""

    tool = "ghidra_locate_function"
    args = {
        "strings": strings,
        "calls": calls,
        "constants": constants,
        "field_offsets": field_offsets,
        "max_candidates": max_candidates,
    }
    if not ghidra_is_available():
        return _unavailable(tool, args)
    started = time.time()
    try:
        limit = max(1, min(int(max_candidates or 20), 40))
        with _open_program() as (_api, program, listing, _monitor):
            fm = program.getFunctionManager()
            references = program.getReferenceManager()
            candidates = []
            string_needles = [str(item) for item in strings or [] if str(item).strip()]
            string_hits: dict[str, list[dict[str, str]]] = {}
            if string_needles:
                for data in listing.getDefinedData(True):
                    try:
                        value = str(data.getValue())
                        matched = [needle for needle in string_needles if needle.lower() in value.lower()]
                        if not matched:
                            continue
                        for reference in references.getReferencesTo(data.getAddress()):
                            owner = fm.getFunctionContaining(reference.getFromAddress())
                            if owner is None:
                                continue
                            owner_key = _fmt_addr(owner.getEntryPoint())
                            for needle in matched:
                                string_hits.setdefault(owner_key, []).append({
                                    "kind": "string_xref",
                                    "anchor": needle,
                                    "site": _fmt_addr(reference.getFromAddress()),
                                    "string_address": _fmt_addr(data.getAddress()),
                                    "value_excerpt": value[:160],
                                })
                    except Exception:
                        continue
            normalized_constants = [str(c).lower() for c in constants or [] if str(c).strip()]
            normalized_offsets = [str(c).lower() for c in field_offsets or [] if str(c).strip()]
            for func in fm.getFunctions(True):
                score = 0
                entry = _fmt_addr(func.getEntryPoint())
                matches: list[dict[str, str]] = list(string_hits.get(entry, []))
                score += 3 * len(matches)
                calls_seen: list[dict[str, str]] = []
                instr_rows = _instruction_lines(listing, func.getBody(), 1200)
                operand_text = "\n".join(row["instruction"] for row in instr_rows).lower()
                for inst in listing.getInstructions(func.getBody(), True):
                    callee = _callee_name(program, inst)
                    if callee:
                        calls_seen.append({"site": _fmt_addr(inst.getAddress()), "callee": callee})
                        for needle in calls or []:
                            if needle and needle.lower() in callee.lower():
                                score += 4
                                matches.append({"kind": "call", "anchor": str(needle), "site": _fmt_addr(inst.getAddress())})
                    if len(calls_seen) >= 100:
                        break
                for constant in normalized_constants:
                    if constant and constant in operand_text:
                        score += 1
                        matches.append({"kind": "constant", "anchor": constant})
                for offset in normalized_offsets:
                    if offset and offset in operand_text:
                        score += 2
                        matches.append({"kind": "field_offset", "anchor": offset})
                if score:
                    if matches and all(
                        item.get("kind") == "constant" and _is_generic_constant(item.get("anchor", ""))
                        for item in matches
                    ):
                        continue
                    anchor_kinds = sorted({str(item.get("kind", "")) for item in matches if item.get("kind")})
                    candidates.append({
                        "candidate_id": f"candidate_{entry}",
                        "entry": entry,
                        "name": str(func.getName()),
                        "body_ranges": _function_ranges(func)[:8],
                        "score": score,
                        "anchor_kinds": anchor_kinds,
                        "weak_anchor_only": len(anchor_kinds) < 2,
                        "requires_raw_verification": True,
                        "matched_anchors": matches[:12],
                        "calls_sample": calls_seen[:8],
                        "instruction_sample": [row["text"] for row in instr_rows[:6]],
                    })
            candidates.sort(key=lambda item: (-int(item["score"]), item["entry"]))
            selected = candidates[:limit]
        stdout = "\n".join(
            f"{row['candidate_id']} score={row['score']} name={row['name']} ranges={row['body_ranges']} anchors={row['matched_anchors'][:6]}"
            for row in selected
        ) or "No Ghidra function candidates matched the supplied anchors."
        facts = {
            "available": True,
            "candidate_count": len(selected),
            "candidates": selected,
            "truncated_candidates": max(0, len(candidates) - len(selected)),
            "weak_anchor_only_count": sum(bool(item.get("weak_anchor_only")) for item in selected),
        }
        evidence = [{
            "kind": "ghidra_function_candidate",
            "claim": (
                f"Ghidra returned {len(selected)} navigation candidate(s); each requires raw CFG or "
                "instruction verification before it can be treated as the target function."
            ),
            "excerpts": stdout.splitlines()[:8],
            "location": {"tool": tool},
        }] if selected else []
        return _response(tool, args, stdout, facts, evidence, elapsed=time.time() - started)
    except Exception as exc:
        return _response(tool, args, f"Ghidra locate failed: {exc!r}", {"available": False}, ok=False, error=repr(exc), elapsed=time.time() - started)


def ghidra_function_summary(function: Annotated[str, Field(min_length=1, max_length=128)]) -> dict[str, Any]:
    """Summarize a Ghidra function at/containing ``function``."""

    tool = "ghidra_function_summary"
    args = {"function": function}
    if not ghidra_is_available():
        return _unavailable(tool, args)
    started = time.time()
    try:
        with _open_program() as (_api, program, listing, monitor):
            func = _function_for(program, function)
            giant_text, boundary = _function_covers_giant_text(program, func)
            if giant_text:
                raise ValueError(
                    "function boundary is unresolved: candidate covers most of the executable .text section; "
                    "use a narrower CFG/address slice instead"
                )
            instr_rows = _instruction_lines(listing, func.getBody(), MAX_FUNCTION_INSTRUCTIONS + 1)
            if len(instr_rows) > MAX_FUNCTION_INSTRUCTIONS:
                raise ValueError(
                    "function boundary is unresolved or too large: raw instruction cap reached; "
                    "use a narrower CFG/address slice instead"
                )
            calls = _function_call_edges(program, func, listing)
            returns = [row["text"] for row in instr_rows if row["mnemonic"].lower().startswith(("ret", "b")) and "ret" in row["mnemonic"].lower()][:20]
            branch_lines = [row["text"] for row in instr_rows if re.match(r"j|b", row["mnemonic"].lower())][:40]
            constants = []
            for row in instr_rows:
                constants.extend(_constants_from_instruction(row["text"]))
                if len(constants) >= 60:
                    break
            blocks = _all_blocks(program, monitor, func)
            facts = {
                "available": True,
                "entry": _fmt_addr(func.getEntryPoint()),
                "name": str(func.getName()),
                "body_ranges": _function_ranges(func),
                "instruction_count_sampled": len(instr_rows),
                "basic_block_count": len(blocks),
                "basic_blocks_truncated": len(blocks) >= MAX_BLOCKS,
                "boundary": boundary,
                "calls": calls[:40],
                "returns": returns,
                "branch_lines": branch_lines[:30],
                "constants_sample": sorted(set(constants), key=constants.index)[:40],
                "raw_instruction_sample": [row["text"] for row in instr_rows[:24]],
            }
        stdout = "\n".join([
            f"function {_fmt_addr(func.getEntryPoint())} {func.getName()}",
            f"body_ranges={facts['body_ranges']}",
            f"basic_blocks={facts['basic_block_count']} instructions_sampled={facts['instruction_count_sampled']}",
            "calls:",
            *[f"  {c['site']}: {c['callee']} ; {c['instruction']}" for c in facts["calls"][:20]],
            "branches:",
            *facts["branch_lines"][:20],
            "returns:",
            *facts["returns"][:12],
        ])
        evidence = [{
            "kind": "ghidra_function_summary",
            "claim": f"Ghidra summarized function at {_fmt_addr(func.getEntryPoint())}.",
            "excerpts": stdout.splitlines()[:12],
            "location": {"function": _fmt_addr(func.getEntryPoint())},
        }]
        return _response(tool, args, stdout, facts, evidence, elapsed=time.time() - started)
    except Exception as exc:
        return _response(tool, args, f"Ghidra summary failed: {exc!r}", {"available": False}, ok=False, error=repr(exc), elapsed=time.time() - started)


def ghidra_cfg_slice(
    function: Annotated[str, Field(min_length=1, max_length=128)],
    address: Annotated[str, Field(min_length=1, max_length=128)],
    radius_blocks: Annotated[int, Field(ge=0, le=8)],
) -> dict[str, Any]:
    """Return bounded basic blocks around an address inside a function."""

    tool = "ghidra_cfg_slice"
    args = {"function": function, "address": address, "radius_blocks": radius_blocks}
    if not ghidra_is_available():
        return _unavailable(tool, args)
    started = time.time()
    try:
        with _open_program() as (_api, program, listing, monitor):
            func = _function_for(program, function)
            target = _addr(program, address)
            blocks = _all_blocks(program, monitor, func)
            center = _block_containing(blocks, target)
            selected_blocks = []
            if center is not None:
                radius = max(0, min(int(radius_blocks or 2), 8))
                by_id = {_block_id(block): block for block in blocks}
                frontier = [center]
                seen = {_block_id(center)}
                for _ in range(radius):
                    next_frontier = []
                    for block in frontier:
                        for neighbor_id in _block_edges(block, monitor, "successors") + _block_edges(block, monitor, "predecessors"):
                            if neighbor_id not in seen and neighbor_id in by_id:
                                seen.add(neighbor_id)
                                next_frontier.append(by_id[neighbor_id])
                    frontier = next_frontier
                selected_blocks = [by_id[item] for item in sorted(seen, key=lambda x: int(x, 16) if x.startswith("0x") else 0)]
            if not selected_blocks:
                instr_rows = _instruction_lines(listing, func.getBody(), 300)
                target_int = _addr_int(target)
                nearest = min(range(len(instr_rows)), key=lambda i: abs(_addr_int(instr_rows[i]["address"]) - target_int)) if instr_rows else 0
                window = instr_rows[max(0, nearest - 20): nearest + 30]
                facts = {
                    "available": True,
                    "cfg_available": False,
                    "function": _fmt_addr(func.getEntryPoint()),
                    "address": _fmt_addr(target),
                    "instruction_window": [row["text"] for row in window],
                }
                stdout = "\n".join(facts["instruction_window"])
            else:
                block_facts = []
                for block in selected_blocks[:16]:
                    lines = _block_lines(program, listing, block, 32)
                    block_facts.append({
                        "id": _block_id(block),
                        "start": _fmt_addr(block.getFirstStartAddress()),
                        "end": _fmt_addr(block.getMaxAddress()),
                        "successors": _block_edges(block, monitor, "successors"),
                        "predecessors": _block_edges(block, monitor, "predecessors"),
                        "instructions": lines[:32],
                    })
                facts = {
                    "available": True,
                    "cfg_available": True,
                    "function": _fmt_addr(func.getEntryPoint()),
                    "address": _fmt_addr(target),
                    "center_block": _block_id(center),
                    "blocks": block_facts,
                }
                stdout_lines = []
                for block in block_facts:
                    stdout_lines.append(f"block {block['id']} succ={block['successors']} pred={block['predecessors']}")
                    stdout_lines.extend(block["instructions"][:30])
                stdout = "\n".join(stdout_lines)
        evidence = [{
            "kind": "ghidra_cfg_slice",
            "claim": f"Ghidra returned CFG/instruction slice around {_fmt_addr(target)}.",
            "excerpts": stdout.splitlines()[:16],
            "location": {"function": facts.get("function"), "address": facts.get("address"), "center_block": facts.get("center_block", "")},
        }]
        return _response(tool, args, stdout, facts, evidence, elapsed=time.time() - started)
    except Exception as exc:
        return _response(tool, args, f"Ghidra CFG slice failed: {exc!r}", {"available": False}, ok=False, error=repr(exc), elapsed=time.time() - started)


def ghidra_path_probe(
    function: Annotated[str, Field(min_length=1, max_length=128)],
    from_address: Annotated[str, Field(min_length=1, max_length=128)],
    to_address: Annotated[str, Field(max_length=128)],
    require_patterns: Annotated[list[str], Field(max_length=12)],
    forbid_patterns: Annotated[list[str], Field(max_length=12)],
) -> dict[str, Any]:
    """Probe bounded local block paths inside a function."""

    tool = "ghidra_path_probe"
    args = {
        "function": function,
        "from_address": from_address,
        "to_address": to_address,
        "require_patterns": require_patterns,
        "forbid_patterns": forbid_patterns,
    }
    if not ghidra_is_available():
        return _unavailable(tool, args)
    started = time.time()
    try:
        with _open_program() as (_api, program, listing, monitor):
            func = _function_for(program, function)
            blocks = _all_blocks(program, monitor, func)
            start_block = _block_containing(blocks, _addr(program, from_address))
            if start_block is None:
                raise ValueError(f"no basic block contains {from_address}")
            target_blocks: set[str] = set()
            if to_address.strip().lower() in {"", "return", "ret", "terminal"}:
                for block in blocks:
                    lines = _block_lines(program, listing, block, 20)
                    if not _block_edges(block, monitor, "successors") or any(re.search(r"\bret", line, re.IGNORECASE) for line in lines):
                        target_blocks.add(_block_id(block))
            else:
                target = _block_containing(blocks, _addr(program, to_address))
                if target is not None:
                    target_blocks.add(_block_id(target))
            by_id = {_block_id(block): block for block in blocks}
            queue: list[tuple[str, list[str]]] = [(_block_id(start_block), [_block_id(start_block)])]
            seen = {_block_id(start_block)}
            found_path: list[str] = []
            explored_edges = 0
            while queue and explored_edges < 5000:
                block_id, path = queue.pop(0)
                if block_id in target_blocks and (len(path) > 1 or block_id == _block_id(start_block)):
                    found_path = path
                    break
                for succ in _block_edges(by_id[block_id], monitor, "successors"):
                    explored_edges += 1
                    if succ in by_id and succ not in seen:
                        seen.add(succ)
                        queue.append((succ, path + [succ]))
            path_lines: list[str] = []
            for block_id in found_path[:60]:
                path_lines.append(f"block {block_id}")
                path_lines.extend(_block_lines(program, listing, by_id[block_id], 40))
            path_text = "\n".join(path_lines)
            required = {pat: _match_pattern(pat, path_text) for pat in require_patterns or []}
            forbidden = {pat: _match_pattern(pat, path_text) for pat in forbid_patterns or []}
            facts = {
                "available": True,
                "path_probe_available": True,
                "function": _fmt_addr(func.getEntryPoint()),
                "from_block": _block_id(start_block),
                "target_blocks": sorted(target_blocks),
                "path_exists": bool(found_path),
                "path_blocks": found_path[:60],
                "explored_blocks": len(seen),
                "explored_edges": explored_edges,
                "require_patterns": required,
                "forbid_patterns": forbidden,
                "path_instruction_excerpt": path_lines[:120],
            }
        stdout = "\n".join([
            f"path_exists={facts['path_exists']} from={facts['from_block']} targets={facts['target_blocks']}",
            f"require_patterns={required}",
            f"forbid_patterns={forbidden}",
            *path_lines[:120],
        ])
        evidence = [{
            "kind": "ghidra_path_fact",
            "claim": f"Ghidra path probe from {from_address} to {to_address or 'terminal'} found path_exists={bool(found_path)}.",
            "excerpts": stdout.splitlines()[:20],
            "location": {"function": facts["function"], "from_block": facts["from_block"], "target_blocks": facts["target_blocks"]},
        }]
        return _response(tool, args, stdout, facts, evidence, elapsed=time.time() - started)
    except Exception as exc:
        return _response(tool, args, f"Ghidra path probe failed: {exc!r}", {"available": False, "path_probe_available": False}, ok=False, error=repr(exc), elapsed=time.time() - started)


def ghidra_call_args(
    function: Annotated[str, Field(min_length=1, max_length=128)],
    call_address: Annotated[str, Field(min_length=1, max_length=128)],
) -> dict[str, Any]:
    """Return call-site instruction, nearby setup, and P-code slice."""

    tool = "ghidra_call_args"
    args = {"function": function, "call_address": call_address}
    if not ghidra_is_available():
        return _unavailable(tool, args)
    started = time.time()
    try:
        with _open_program() as (_api, program, listing, _monitor):
            func = _function_for(program, function)
            target = _addr(program, call_address)
            rows = _instruction_lines(listing, func.getBody(), MAX_FUNCTION_INSTRUCTIONS)
            index = next((i for i, row in enumerate(rows) if _addr_int(row["address"]) == _addr_int(target)), -1)
            if index < 0:
                raise ValueError(f"no instruction at {call_address} in function")
            window = rows[max(0, index - 12): index + 8]
            instr = listing.getInstructionAt(target)
            pcode = []
            try:
                pcode = [str(op) for op in instr.getPcode()][:40]
            except Exception:
                pass
            callee = _callee_name(program, instr)
            facts = {
                "available": True,
                "function": _fmt_addr(func.getEntryPoint()),
                "call_address": _fmt_addr(target),
                "callee": callee,
                "call_instruction": rows[index]["text"],
                "setup_window": [row["text"] for row in window],
                "pcode": pcode,
            }
        stdout = "\n".join([
            f"call_site={facts['call_address']} callee={callee}",
            facts["call_instruction"],
            "setup_window:",
            *facts["setup_window"],
            "pcode:",
            *pcode[:30],
        ])
        evidence = [{
            "kind": "ghidra_call_args",
            "claim": f"Ghidra recovered call-site context at {facts['call_address']}.",
            "excerpts": stdout.splitlines()[:24],
            "location": {"function": facts["function"], "call_address": facts["call_address"], "callee": callee},
        }]
        return _response(tool, args, stdout, facts, evidence, elapsed=time.time() - started)
    except Exception as exc:
        return _response(tool, args, f"Ghidra call args failed: {exc!r}", {"available": False}, ok=False, error=repr(exc), elapsed=time.time() - started)


def ghidra_decompile_slice(
    function: Annotated[str, Field(min_length=1, max_length=128)],
    address: Annotated[str, Field(min_length=1, max_length=128)],
    max_lines: Annotated[int, Field(ge=1, le=80)],
) -> dict[str, Any]:
    """Return a bounded recovered pseudocode slice with address context."""

    tool = "ghidra_decompile_slice"
    args = {"function": function, "address": address, "max_lines": max_lines}
    if not ghidra_is_available():
        return _unavailable(tool, args)
    started = time.time()
    try:
        with _open_program() as (_api, program, listing, monitor):
            func = _function_for(program, function)
            target = _addr(program, address)
            try:
                from ghidra.app.decompiler import DecompInterface  # type: ignore

                interface = DecompInterface()
                interface.openProgram(program)
                assert RUNTIME is not None
                decomp = interface.decompileFunction(func, min(int(RUNTIME.timeout_sec), 60), monitor)
                if not decomp.decompileCompleted():
                    raise RuntimeError(str(decomp.getErrorMessage()))
                code = str(decomp.getDecompiledFunction().getC())
                pseudo_lines = code.splitlines()
            except Exception as exc:
                pseudo_lines = [f"Decompiler unavailable: {exc!r}"]
            limit = max(1, min(int(max_lines or 40), 80))
            rows = _instruction_lines(listing, func.getBody(), 300)
            target_int = _addr_int(target)
            nearest = min(range(len(rows)), key=lambda i: abs(_addr_int(rows[i]["address"]) - target_int)) if rows else 0
            raw_window = [row["text"] for row in rows[max(0, nearest - 8): nearest + 12]]
            facts = {
                "available": True,
                "function": _fmt_addr(func.getEntryPoint()),
                "address": _fmt_addr(target),
                "view": "recovered_decompiler_view_not_final_evidence_by_itself",
                "pseudocode": pseudo_lines[:limit],
                "raw_instruction_window": raw_window,
            }
        stdout = "\n".join([
            "RECOVERED VIEW: decompiler output is advisory; use raw instructions/CFG as final evidence.",
            *pseudo_lines[:limit],
            "raw_instruction_window:",
            *raw_window,
        ])
        evidence = [{
            "kind": "ghidra_decompile_slice",
            "claim": f"Ghidra decompiler slice around {facts['address']} with raw instruction mapping window.",
            "excerpts": stdout.splitlines()[:24],
            "location": {"function": facts["function"], "address": facts["address"], "view": facts["view"]},
        }]
        return _response(tool, args, stdout, facts, evidence, elapsed=time.time() - started)
    except Exception as exc:
        return _response(tool, args, f"Ghidra decompile slice failed: {exc!r}", {"available": False}, ok=False, error=repr(exc), elapsed=time.time() - started)
