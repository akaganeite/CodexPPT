"""Offline dispatch checks for the direct model/tool loop.

    python3 -m claudeagent.tests.test_responses_loop
"""

from __future__ import annotations

import json
import tempfile

from claudeagent import agent_loop
from claudeagent.evidence_summary import summarize_evidence
from claudeagent.finalize import submit_detection_result
from claudeagent.runtime import AGENT_CONTEXT, next_id, record_evidence, initialize_agent_context


def _stub_run_python(**_: object) -> dict:
    observation_id = next_id("obs", "observation_counter")
    AGENT_CONTEXT["observations"].append({
        "observation_id": observation_id,
        "tool": "run_python",
        "command": ["python3", "-I", "/work/script.py"],
        "command_text": "python3 -I /work/script.py",
        "exit_code": 0,
        "ok": True,
        "stdout_head": "0x1010: cmp eax, 8",
        "stdout_tail": "",
        "stderr_tail": "",
        "truncated": False,
        "truncation": {},
        "parsed_facts": {},
    })
    evidence = record_evidence(
        observation_id=observation_id,
        kind="disassembly",
        claim="Host captured a target comparison.",
        excerpts=["0x1010: cmp eax, 8"],
    )
    return {"ok": True, "observation_id": observation_id, "evidence": [evidence]}


def _call(call_id: str, name: str, arguments: dict) -> dict:
    return {"type": "function_call", "call_id": call_id, "name": name, "arguments": json.dumps(arguments)}


def _run() -> int:
    failures: list[str] = []

    def check(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    allowed = {
        "run_python": _stub_run_python,
        "summarize_evidence": summarize_evidence,
        "submit_detection_result": submit_detection_result,
    }
    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context({"cve_id": "CVE-X", "project": "demo"}, "/workspace/binary", "CVE-X", tmp, tmp)
        input_items: list[dict] = []
        transcript: list[dict] = []
        done, final = agent_loop.handle_tool_calls(
            output_items=[{"type": "message", "role": "assistant", "content": "plain text"}],
            input_items=input_items,
            transcript=transcript,
            turn_label=1,
            allowed_tools=allowed,
            output_dir=tmp,
            start_epoch=0.0,
        )
        check("plain response is nudged", not done and final is None and input_items[0]["type"] == "message")

        input_items.clear()
        transcript.clear()
        done, final = agent_loop.handle_tool_calls(
            output_items=[_call("inspect", "run_python", {"script": "print(1)", "timeout_sec": 0, "max_output_chars": 0})],
            input_items=input_items,
            transcript=transcript,
            turn_label=2,
            allowed_tools=allowed,
            output_dir=tmp,
            start_epoch=0.0,
        )
        evidence = AGENT_CONTEXT["evidence_ledger"][0]
        check("inspection mints pending returned evidence", not done and evidence["claim_status"] == "pending" and evidence["returned_response_index"] == 2)

        summary = _call("summary", "summarize_evidence", {
            "observation_id": "obs_0001",
            "claims": [{"evidence_id": "ev_0001", "claim": "The target comparison enforces the bound."}],
        })
        submit = _call("submit", "submit_detection_result", {
            "status": "present",
            "confidence": "high",
            "evidence_ids": ["ev_0001"],
            "reasoning": "The comparison at 0x1010 enforces the relevant upper bound.",
            "decisive_addresses": ["0x1010"],
            "inconclusive_reason": "none",
        })
        input_items.clear()
        transcript.clear()
        done, final = agent_loop.handle_tool_calls(
            output_items=[summary, submit],
            input_items=input_items,
            transcript=transcript,
            turn_label=3,
            allowed_tools=allowed,
            output_dir=tmp,
            start_epoch=0.0,
        )
        check("summary then direct submit finishes", done and final is not None and final.get("status") == "present")
        check("summary provenance retained", evidence["claim_status"] == "summarized" and evidence["claim_revision"] == 1)

    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context({"cve_id": "CVE-Y", "project": "demo"}, "/workspace/binary", "CVE-Y", tmp, tmp)
        input_items = []
        transcript = []
        invalid = _call("bad", "submit_detection_result", {
            "status": "present",
            "confidence": "high",
            "evidence_ids": [],
            "reasoning": "Unsupported.",
            "decisive_addresses": [],
            "inconclusive_reason": "none",
        })
        done, final = agent_loop.handle_tool_calls(
            output_items=[invalid],
            input_items=input_items,
            transcript=transcript,
            turn_label=4,
            allowed_tools=allowed,
            output_dir=tmp,
            start_epoch=0.0,
        )
        repair = json.loads(input_items[-1]["output"])
        check("invalid direct submit repairs", not done and final is None and repair.get("schema_errors"))

    if failures:
        print("RESPONSES LOOP TESTS FAILED:")
        for failure in failures:
            print("  -", failure)
        return 1
    print("RESPONSES LOOP TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(_run())
