"""Offline tests for PatchSpec-guided bounded semantic probes.

    python3 -m claudeagent.tests.test_semantic_probe
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from claudeagent.runtime import AGENT_CONTEXT, initialize_agent_context, record_evidence
from claudeagent.semantic_probe import (
    FIXED_OBJDUMP_SCRIPT,
    _unsafe_regex_reason,
    classify_probe,
    executable_ranges,
    parse_objdump_instructions,
    run_semantic_probe,
)
from claudeagent.tools_registry import TOOL_FUNCS, load_tools


PATCH_SPEC = {"behaviors": [{"behavior_id": "B001", "required": True}]}


def _expect(required: list[str], forbidden: list[str] | None = None, *, ordered: bool = True) -> dict:
    return {
        "required_regexes": required,
        "forbidden_regexes": list(forbidden or []),
        "ordered": ordered,
    }


def _instructions(*texts: str) -> list[dict]:
    return [
        {
            "address": 0x1000 + index * 4,
            "address_hex": f"0x{0x1000 + index * 4:x}",
            "text": text,
            "line": f"0x{0x1000 + index * 4:x}: {text}",
        }
        for index, text in enumerate(texts)
    ]


def _classify(items: list[dict], old: dict, new: dict, *, gap: int = 8) -> str:
    return str(classify_probe(
        items,
        focus_regex=r"\bcall\b",
        old_expectation=old,
        new_expectation=new,
        max_instruction_gap=gap,
    )["matched_side"])


def _run() -> int:
    failures: list[str] = []

    def check(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    old = _expect([r"\bcall\b.*copy"], [r"\bcmp\b"])
    new = _expect([r"\bcmp\b", r"\bj[a-z]+\b", r"\bcall\b.*copy"])
    check(
        "new-only classification",
        _classify(_instructions("cmp eax,0x10", "ja 0x1020", "call copy@plt"), old, new) == "new_only",
    )
    check(
        "old-only classification",
        _classify(_instructions("mov edi,eax", "call copy@plt"), old, new) == "old_only",
    )
    check(
        "both classification",
        _classify(
            _instructions("call copy@plt"),
            _expect([r"\bcall\b"]),
            _expect([r"copy"]),
        ) == "both",
    )
    check(
        "neither classification",
        _classify(
            _instructions("call unrelated@plt"),
            _expect([r"strcpy"]),
            _expect([r"memcpy"]),
        ) == "neither",
    )
    gap_result = classify_probe(
        _instructions("cmp eax,0x10", "nop", "ja 0x1020", "call copy@plt"),
        focus_regex=r"\bcall\b",
        old_expectation=old,
        new_expectation=new,
        max_instruction_gap=0,
    )
    check(
        "ordered gap enforced",
        gap_result["matched_side"] == "old_only" and gap_result["new_match"]["matched"] is False,
    )
    distant = classify_probe(
        _instructions("call focus@plt", *("nop" for _ in range(10)), "cmp eax,0x10"),
        focus_regex=r"\bcall\b",
        old_expectation=_expect([r"missing_old"]),
        new_expectation=_expect([r"\bcmp\b"]),
        max_instruction_gap=2,
    )
    check("required match must be near focus", distant["matched_side"] == "neither")
    guard_after_focus = classify_probe(
        _instructions("call copy@plt", "cmp eax,0x10"),
        focus_regex=r"\bcall\b",
        old_expectation=_expect([r"missing_old"]),
        new_expectation=_expect([r"\bcmp\b"]),
        max_instruction_gap=2,
        probe_kind="guard_before_focus",
    )
    check("guard must precede focus", guard_after_focus["matched_side"] == "neither")

    parsed = parse_objdump_instructions(
        "    1000:\t48 83 ec 08          \tsub rsp,0x8\n"
        "    1004:\t00 00 00 \n"
        "    1007:\te8 00 00 00 00       \tcall 100c <copy>\n"
    )
    check("objdump parser skips byte continuation", [item["text"] for item in parsed] == ["sub rsp,0x8", "call 100c <copy>"])
    check("lookaround rejected", bool(_unsafe_regex_reason(r"(?=call)")))
    check("backreference rejected", bool(_unsafe_regex_reason(r"(call)\\1")))
    check("degenerate wildcard rejected", bool(_unsafe_regex_reason(r".*")))

    tools = {item.get("name") for item in load_tools(strict=True)}
    check("semantic probe registered", "run_semantic_probe" in tools and "run_semantic_probe" in TOOL_FUNCS)

    binary = "/bin/true"
    if not os.path.isfile(binary):
        print("SKIP: /bin/true unavailable")
        return 0
    ranges, _, range_error = executable_ranges(binary)
    check("ELF executable ranges parsed", not range_error and bool(ranges))
    if range_error or not ranges:
        print("SEMANTIC PROBE TESTS FAILED:", failures)
        return 1
    range_start, range_stop = ranges[0]
    start = range_start
    stop = min(range_start + 0x200, range_stop)

    with tempfile.TemporaryDirectory(prefix="claudeagent-semantic-probe-") as tmp:
        initialize_agent_context(
            {"cve_id": "CVE-TEST", "project": "curl"},
            binary,
            "CVE-TEST",
            tmp,
            tmp,
            patch_spec=PATCH_SPEC,
        )
        positive = record_evidence(
            observation_id="obs_0001",
            kind="disassembly_calls",
            claim="localized executable code",
            excerpts=[f"0x{start:x}: candidate code"],
        )
        negative = record_evidence(
            observation_id="obs_0002",
            kind="no_pipeline_match",
            claim="no match",
            excerpts=["stdout_lines=0"],
            polarity="negative",
        )
        base = {
            "behavior_id": "B001",
            "localization_evidence_ids": [positive["evidence_id"]],
            "probe_kind": "ordered_sequence",
            "start_address": f"0x{start:x}",
            "stop_address": f"0x{stop:x}",
            "focus_regex": r"[A-Za-z]",
            "old_expectation": _expect([r"[A-Za-z]"]),
            "new_expectation": _expect(["SEMANTIC_PROBE_INJECTION_SENTINEL"]),
            "max_instruction_gap": 8,
        }

        check("unknown behavior rejected", run_semantic_probe(**{**base, "behavior_id": "B999"})["ok"] is False)
        check(
            "unknown localization evidence rejected",
            run_semantic_probe(**{**base, "localization_evidence_ids": ["ev_9999"]})["ok"] is False,
        )
        check(
            "negative-only localization rejected",
            run_semantic_probe(**{
                **base,
                "localization_evidence_ids": [negative["evidence_id"]],
            })["ok"] is False,
        )
        check(
            "reverse range rejected",
            run_semantic_probe(**{**base, "stop_address": f"0x{start:x}"})["ok"] is False,
        )
        check(
            "non-executable range rejected",
            run_semantic_probe(**{**base, "start_address": "0x0", "stop_address": "0x10"})["ok"] is False,
        )
        check(
            "identical expectations rejected",
            run_semantic_probe(**{**base, "new_expectation": base["old_expectation"]})["ok"] is False,
        )
        check(
            "unsafe regex rejected",
            run_semantic_probe(**{**base, "focus_regex": r"(?=call)"})["ok"] is False,
        )

        result = run_semantic_probe(**base)
        check("end-to-end semantic probe succeeds", result.get("ok") is True)
        check("probe classifies old-only", result.get("parsed_facts", {}).get("matched_side") == "old_only")
        evidence = result.get("evidence") or []
        location = evidence[0].get("location", {}) if evidence else {}
        check(
            "probe evidence bound to behavior/side",
            bool(evidence)
            and evidence[0].get("kind") == "semantic_probe"
            and location.get("behavior_id") == "B001"
            and location.get("matched_side") == "old_only",
        )
        check(
            "probe definition retained",
            result.get("parsed_facts", {}).get("probe_definition", {}).get("focus_regex") == r"[A-Za-z]",
        )
        check("host binary path hidden", binary not in str(result.get("command_text", "")))
        check("sandbox binary path shown", "/workspace/binary" in str(result.get("command_text", "")))
        check("raw disassembly not persisted", "Disassembly of section" not in str(result.get("stdout_head", "")))

        scripts = list(Path(tmp).rglob("probe.py"))
        check("fixed script created", len(scripts) == 1)
        if scripts:
            script_text = scripts[0].read_text(errors="replace")
            check("fixed script exact", script_text == FIXED_OBJDUMP_SCRIPT)
            check("model regex not interpolated", "SEMANTIC_PROBE_INJECTION_SENTINEL" not in script_text)
        check("observation stored", AGENT_CONTEXT.get("observations", [])[-1].get("tool") == "run_semantic_probe")

    if failures:
        print("SEMANTIC PROBE TESTS FAILED:")
        for failure in failures:
            print("  -", failure)
        return 1
    print("SEMANTIC PROBE TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
