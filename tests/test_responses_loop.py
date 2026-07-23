"""Tests for the Responses-API agent loop dispatch (handle_tool_calls).

    python3 -m claudeagent.tests.test_responses_loop

These do NOT call the network: we feed synthetic Responses ``output`` arrays
into handle_tool_calls and assert the input_items it appends (function_call echo
+ function_call_output), the transcript, and the submit success/repair paths.
run_python is exercised via a stub so the test does not depend on the sandbox.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from types import SimpleNamespace

from claudeagent import agent_loop
from claudeagent.runtime import (
    AGENT_CONTEXT,
    configure_evidence_verifier,
    harness_metrics,
    initialize_agent_context,
    mark_evidence_returned,
    record_evidence,
)


PATCH_SPEC = {"behaviors": [{"behavior_id": "B001", "required": True}]}


def _mark_summarized(evidence: dict, claim: str | None = None) -> dict:
    evidence["returned_response_index"] = int(evidence.get("created_response_index", 0))
    evidence["claim"] = claim or evidence["claim"]
    evidence["claim_source"] = "main_agent"
    evidence["claim_status"] = "summarized"
    evidence["claim_revision"] = max(1, int(evidence.get("claim_revision", 0)))
    evidence["claim_updated_response_index"] = max(
        1,
        int(evidence["returned_response_index"]) + 1,
    )
    return evidence


def _stub_run_python(**kwargs):
    """Minimal stand-in for run_python that mints an observation + evidence."""
    from claudeagent.observations import (
        evidence_from_command_observation,
        observation_from_host_result,
        tool_response_from_observation,
    )
    script = kwargs.get("script", "")
    obs = observation_from_host_result(
        tool="run_python",
        command=["python3", "-S", "/scratch/x.py"],
        proc={"ok": True, "returncode": 0, "elapsed_sec": 0.1, "cmd": "x", "stdout": "probe ok\n", "stderr": ""},
        stdout_budget=60000,
        parsed_facts={"command": "python3"},
    )
    ev = evidence_from_command_observation(obs)
    return tool_response_from_observation(obs, ev)


def _run() -> int:
    failures: list[str] = []

    def check(label: str, cond: bool) -> None:
        if not cond:
            failures.append(label)

    allowed = {
        "run_python": _stub_run_python,
        "summarize_evidence": agent_loop.TOOL_FUNCS["summarize_evidence"],
        "submit_detection_result": agent_loop.TOOL_FUNCS["submit_detection_result"],
    }

    # --- 1. a run_python function_call is echoed + produces a function_call_output ---
    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context(
            {"cve_id": "CVE-2013-0249", "project": "curl"},
            "/tmp/curl", "CVE-2013-0249", tmp, tmp, patch_spec=PATCH_SPEC,
        )
        input_items: list[dict] = []
        transcript: list[dict] = []
        fc = {"type": "function_call", "id": "call_1", "name": "run_python",
              "arguments": json.dumps({"script": "print('x')", "timeout_sec": 0, "max_output_chars": 0})}
        done, final = agent_loop.handle_tool_calls(
            output_items=[fc], input_items=input_items, transcript=transcript,
            turn_label=1, allowed_tools=allowed, output_dir=tmp, start_epoch=0.0,
        )
        check("run_python not done", done is False)
        # input_items should contain the echoed function_call then its output.
        check("echoed function_call", input_items and input_items[0].get("type") == "function_call" and input_items[0].get("name") == "run_python")
        check("function_call_output appended", len(input_items) >= 2 and input_items[1].get("type") == "function_call_output" and input_items[1].get("call_id") == "call_1")
        check("output is compact json string", isinstance(input_items[1].get("output"), str))
        check("transcript recorded", transcript and transcript[-1]["tool"] == "run_python")
        check(
            "inspection evidence starts pending",
            AGENT_CONTEXT["evidence_ledger"][0].get("claim_status") == "pending"
            and AGENT_CONTEXT["evidence_ledger"][0].get("returned_response_index") == 1,
        )
        original_inspection_evidence = transcript[0]["result"]["evidence"][0]
        summary_fc = {
            "type": "function_call",
            "id": "call_1_summary",
            "name": "summarize_evidence",
            "arguments": json.dumps({
                "observation_id": "obs_0001",
                "claims": [{
                    "evidence_id": "ev_0001",
                    "claim": "The returned output records the inspection command result.",
                }],
            }),
        }
        done, final = agent_loop.handle_tool_calls(
            output_items=[summary_fc],
            input_items=input_items,
            transcript=transcript,
            turn_label="1-summary",
            allowed_tools=allowed,
            output_dir=tmp,
            start_epoch=0.0,
        )
        check("next-response summary succeeds", done is False and final is None)
        check(
            "inspection transcript remains immutable",
            original_inspection_evidence.get("claim_source") == "host"
            and original_inspection_evidence.get("claim_status") == "pending"
            and original_inspection_evidence.get("claim_revision") == 0
            and original_inspection_evidence.get("claim")
            == original_inspection_evidence.get("host_claim")
            and AGENT_CONTEXT["evidence_ledger"][0].get("claim_source") == "main_agent",
        )

    # --- 2. summarize(previous) + submit can complete in one response. ---
    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context(
            {"cve_id": "CVE-2013-0249", "project": "curl"},
            "/tmp/curl", "CVE-2013-0249", tmp, tmp, patch_spec=PATCH_SPEC,
        )
        ev = record_evidence(observation_id="obs_0001", kind="strings_match", claim="anchor", excerpts=["snprintf"])
        mark_evidence_returned([ev], response_index=0)
        eid = ev["evidence_id"]
        input_items = []
        transcript = []
        summarize_fc = {
            "type": "function_call",
            "id": "call_2_summary",
            "name": "summarize_evidence",
            "arguments": json.dumps({
                "observation_id": "obs_0001",
                "claims": [{
                    "evidence_id": eid,
                    "claim": "The observed bounded call implements the required behavior.",
                }],
            }),
        }
        submit_fc = {"type": "function_call", "id": "call_2", "name": "submit_detection_result",
              "arguments": json.dumps({
                  "status": "present", "confidence": "high",
                  "supports": [{
                      "support_id": "sup_0001", "behavior_id": "B001", "observed_side": "new",
                      "summary": "The bounded call implements the patched behavior.",
                      "evidence_ids": [eid], "decisive_addresses": ["0x6f64d"],
                  }],
                  "claim": {
                      "summary": "The required behavior uses a bounded call.",
                      "support_ids": ["sup_0001"], "unresolved_behavior_ids": [],
                  },
                  "inconclusive_reason": "none",
              })}
        done, final = agent_loop.handle_tool_calls(
            output_items=[summarize_fc, submit_fc], input_items=input_items, transcript=transcript,
            turn_label=2, allowed_tools=allowed, output_dir=tmp, start_epoch=0.0,
        )
        check("submit success done", done is True)
        check("submit success final returned", isinstance(final, dict) and final.get("status") == "present")
        # The artifact file should have been written.
        check("final_result.json written", os.path.isfile(os.path.join(tmp, "final_result.json")))
        check(
            "summary output enters model context",
            len(input_items) >= 2
            and input_items[0].get("name") == "summarize_evidence"
            and json.loads(input_items[1].get("output", "{}")).get("evidence", [{}])[0].get("claim")
            == "The observed bounded call implements the required behavior.",
        )
        check(
            "artifact preserves summary provenance",
            final.get("evidence_ledger", [{}])[0].get("host_claim") == "anchor"
            and final.get("evidence_ledger", [{}])[0].get("claim_source") == "main_agent"
            and final.get("evidence_ledger", [{}])[0].get("claim_status") == "summarized"
            and final.get("evidence_ledger", [{}])[0].get("claim_revision") == 1,
        )
        check(
            "transcript preserves summary call",
            [item.get("tool") for item in transcript] == [
                "summarize_evidence",
                "submit_detection_result",
            ],
        )

    # --- 3. submit with bad args -> repair path (function_call_output carries the repair) ---
    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context(
            {"cve_id": "CVE-2013-0249", "project": "curl"},
            "/tmp/curl", "CVE-2013-0249", tmp, tmp, patch_spec=PATCH_SPEC,
        )
        # No evidence in ledger -> citing ev_9999 is unknown, AND determinate with no valid id.
        input_items = []
        transcript = []
        fc = {"type": "function_call", "id": "call_3", "name": "submit_detection_result",
              "arguments": json.dumps({
                  "status": "present", "confidence": "high",
                  "supports": [{
                      "support_id": "sup_0001", "behavior_id": "B001", "observed_side": "new",
                      "summary": "Invented evidence must be rejected.",
                      "evidence_ids": ["ev_9999"], "decisive_addresses": ["0x1"],
                  }],
                  "claim": {
                      "summary": "The invented evidence allegedly supports the behavior.",
                      "support_ids": ["sup_0001"], "unresolved_behavior_ids": [],
                  },
                  "inconclusive_reason": "none",
              })}
        done, final = agent_loop.handle_tool_calls(
            output_items=[fc], input_items=input_items, transcript=transcript,
            turn_label=3, allowed_tools=allowed, output_dir=tmp, start_epoch=0.0,
        )
        check("submit repair not done", done is False)
        check("submit repair echoed call", input_items and input_items[0].get("type") == "function_call")
        check("submit repair output is fco", len(input_items) >= 2 and input_items[1].get("type") == "function_call_output")
        repair_payload = json.loads(input_items[1]["output"])
        check("repair payload has schema_errors", bool(repair_payload.get("schema_errors")))
        check("repair payload has known_evidence_ids", "known_evidence_ids" in repair_payload)

    # --- 4. no function_call -> user nudge appended ---
    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context({"cve_id": "CVE-X", "project": "curl"}, "/tmp/curl", "CVE-X", tmp, tmp)
        input_items = []
        transcript = []
        done, final = agent_loop.handle_tool_calls(
            output_items=[{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "thinking..."}]}],
            input_items=input_items, transcript=transcript,
            turn_label=4, allowed_tools=allowed, output_dir=tmp, start_epoch=0.0,
        )
        check("no-call not done", done is False)
        check("nudge appended", input_items and input_items[0].get("type") == "message" and input_items[0].get("role") == "user")

    # --- 5. multiple function_calls in one response are all dispatched ---
    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context({"cve_id": "CVE-Y", "project": "curl"}, "/tmp/curl", "CVE-Y", tmp, tmp)
        input_items = []
        transcript = []
        fc1 = {"type": "function_call", "id": "c1", "name": "run_python",
               "arguments": json.dumps({"script": "print(1)", "timeout_sec": 0, "max_output_chars": 0})}
        fc2 = {"type": "function_call", "id": "c2", "name": "run_python",
               "arguments": json.dumps({"script": "print(2)", "timeout_sec": 0, "max_output_chars": 0})}
        done, final = agent_loop.handle_tool_calls(
            output_items=[fc1, fc2], input_items=input_items, transcript=transcript,
            turn_label=5, allowed_tools=allowed, output_dir=tmp, start_epoch=0.0,
        )
        check("multi-call not done", done is False)
        # 2 calls * 2 items (echo + output) = 4 input items.
        check("multi-call 4 items", len(input_items) == 4)
        check("multi-call transcript 2", len([t for t in transcript if t.get("tool") == "run_python"]) == 2)

    # --- 6. verifier repair is recognized and restricts inspection tools. ---
    verifier_repair_transcript = [{
        "tool": "submit_detection_result",
        "result": {
            "ok": False,
            "verifier_repair_required": True,
            "error": "repair claim",
        },
    }]
    check(
        "verifier repair recognized",
        agent_loop.last_submit_needs_repair(verifier_repair_transcript),
    )
    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context(
            {"cve_id": "CVE-Z", "project": "curl"},
            "/tmp/curl",
            "CVE-Z",
            tmp,
            tmp,
        )
        configure_evidence_verifier(SimpleNamespace(mode="llm", repair_pending=True))
        input_items = []
        transcript = []
        fc = {
            "type": "function_call",
            "id": "repair-run",
            "name": "run_python",
            "arguments": json.dumps({
                "script": "print('should not run')",
                "timeout_sec": 0,
                "max_output_chars": 0,
            }),
        }
        done, final = agent_loop.handle_tool_calls(
            output_items=[fc],
            input_items=input_items,
            transcript=transcript,
            turn_label="verifier-repair",
            allowed_tools=allowed,
            output_dir=tmp,
            start_epoch=0.0,
        )
        check("verifier repair run_python blocked", done is False and final is None)
        check(
            "verifier repair block recorded",
            "only summarize_evidence and submit_detection_result"
            in str(transcript[-1].get("result", {}).get("error", "")),
        )

    # --- 7. a parallel second submit cannot consume repair before feedback. ---
    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context(
            {"cve_id": "CVE-P", "project": "curl"},
            "/tmp/curl",
            "CVE-P",
            tmp,
            tmp,
            patch_spec=PATCH_SPEC,
            evidence_verifier_mode="llm",
        )
        ev = record_evidence(
            observation_id="obs_0001",
            kind="disassembly_predicates",
            claim="guard",
            excerpts=["0x1010: test eax,eax"],
        )
        _mark_summarized(ev, "The target predicate implements the required guard.")
        repair_state = SimpleNamespace(mode="llm", repair_pending=False)
        configure_evidence_verifier(repair_state)
        submit_args = json.dumps({
            "status": "present",
            "confidence": "high",
            "supports": [{
                "support_id": "sup_0001",
                "behavior_id": "B001",
                "observed_side": "new",
                "summary": "The bounded code implements the NEW behavior.",
                "evidence_ids": [ev["evidence_id"]],
                "decisive_addresses": ["0x1010"],
            }],
            "claim": {
                "summary": "The required behavior is established as NEW.",
                "support_ids": ["sup_0001"],
                "unresolved_behavior_ids": [],
            },
            "inconclusive_reason": "none",
        })
        calls = [
            {"type": "function_call", "id": "parallel-1", "name": "submit_detection_result", "arguments": submit_args},
            {"type": "function_call", "id": "parallel-2", "name": "submit_detection_result", "arguments": submit_args},
        ]
        verifier_calls = 0
        original_verify = agent_loop.verify_detection_result

        def reject_once(result):
            nonlocal verifier_calls
            verifier_calls += 1
            repair_state.repair_pending = True
            return {
                "ok": False,
                "tool": "submit_detection_result",
                "verifier_repair_required": True,
                "error": "repair claim",
                "verification": {},
                "repair_instruction": "Use direct evidence or submit inconclusive.",
            }

        agent_loop.verify_detection_result = reject_once
        try:
            input_items = []
            transcript = []
            done, final = agent_loop.handle_tool_calls(
                output_items=calls,
                input_items=input_items,
                transcript=transcript,
                turn_label=7,
                allowed_tools=allowed,
                output_dir=tmp,
                start_epoch=0.0,
            )
        finally:
            agent_loop.verify_detection_result = original_verify
        check("parallel submit waits for feedback", done is False and final is None)
        check("parallel submit invokes verifier once", verifier_calls == 1)
        check(
            "parallel second submit blocked",
            len(transcript) == 2
            and "wait for the evidence-verifier feedback"
            in str(transcript[1].get("result", {}).get("error", "")),
        )

    # --- 8. summarize(previous) may be followed by another inspection call. ---
    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context(
            {"cve_id": "CVE-S", "project": "curl"},
            "/tmp/curl",
            "CVE-S",
            tmp,
            tmp,
        )
        previous = record_evidence(
            observation_id="obs_0001",
            kind="command_output",
            claim="Host observed the previous command output.",
            excerpts=["0x1000: cmp eax, 4"],
        )
        mark_evidence_returned([previous], response_index=0)
        calls = [
            {
                "type": "function_call",
                "id": "summary-before-next",
                "name": "summarize_evidence",
                "arguments": json.dumps({
                    "observation_id": "obs_0001",
                    "claims": [{
                        "evidence_id": previous["evidence_id"],
                        "claim": "The comparison checks the input length.",
                    }],
                }),
            },
            {
                "type": "function_call",
                "id": "next-inspection",
                "name": "run_python",
                "arguments": json.dumps({
                    "script": "print('next')",
                    "timeout_sec": 0,
                    "max_output_chars": 0,
                }),
            },
        ]
        input_items = []
        transcript = []
        done, final = agent_loop.handle_tool_calls(
            output_items=calls,
            input_items=input_items,
            transcript=transcript,
            turn_label=8,
            allowed_tools=allowed,
            output_dir=tmp,
            start_epoch=0.0,
        )
        check("summary then inspect remains nonterminal", done is False and final is None)
        check(
            "summary then inspect ordering",
            [item.get("tool") for item in transcript]
            == ["summarize_evidence", "run_python"],
        )
        check(
            "old evidence summarized new evidence pending",
            previous.get("claim_status") == "summarized"
            and AGENT_CONTEXT["evidence_ledger"][-1].get("claim_status") == "pending",
        )

    # --- 9. evidence produced earlier in the same response is not visible yet. ---
    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context(
            {"cve_id": "CVE-V", "project": "curl"},
            "/tmp/curl",
            "CVE-V",
            tmp,
            tmp,
        )
        calls = [
            {
                "type": "function_call",
                "id": "same-response-inspection",
                "name": "run_python",
                "arguments": json.dumps({
                    "script": "print('same response')",
                    "timeout_sec": 0,
                    "max_output_chars": 0,
                }),
            },
            {
                "type": "function_call",
                "id": "same-response-summary",
                "name": "summarize_evidence",
                "arguments": json.dumps({
                    "observation_id": "obs_0001",
                    "claims": [{
                        "evidence_id": "ev_0001",
                        "claim": "This claim was guessed before seeing the output.",
                    }],
                }),
            },
        ]
        input_items = []
        transcript = []
        done, final = agent_loop.handle_tool_calls(
            output_items=calls,
            input_items=input_items,
            transcript=transcript,
            turn_label=9,
            allowed_tools=allowed,
            output_dir=tmp,
            start_epoch=0.0,
        )
        check("same-response summary is nonterminal", done is False and final is None)
        check(
            "same-response summary rejected",
            transcript[-1].get("result", {}).get("ok") is False
            and "earlier model response" in transcript[-1].get("result", {}).get("error", ""),
        )
        check(
            "same-response rejection leaves pending",
            AGENT_CONTEXT["evidence_ledger"][0].get("claim_status") == "pending",
        )

    # --- 10. verifier repair accepts summarize + submit, while run_python stays blocked. ---
    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context(
            {"cve_id": "CVE-R", "project": "curl"},
            "/tmp/curl",
            "CVE-R",
            tmp,
            tmp,
            patch_spec=PATCH_SPEC,
            evidence_verifier_mode="llm",
        )
        repair_ev = record_evidence(
            observation_id="obs_0001",
            kind="command_output",
            claim="Host observed an unresolved target-code window.",
            excerpts=["0x3000: test eax,eax"],
        )
        mark_evidence_returned([repair_ev], response_index=0)
        configure_evidence_verifier(SimpleNamespace(mode="llm", repair_pending=True))
        calls = [
            {
                "type": "function_call",
                "id": "repair-summary",
                "name": "summarize_evidence",
                "arguments": json.dumps({
                    "observation_id": "obs_0001",
                    "claims": [{
                        "evidence_id": repair_ev["evidence_id"],
                        "claim": "The bounded window does not distinguish OLD from NEW.",
                    }],
                }),
            },
            {
                "type": "function_call",
                "id": "repair-submit",
                "name": "submit_detection_result",
                "arguments": json.dumps({
                    "status": "inconclusive",
                    "confidence": "low",
                    "supports": [{
                        "support_id": "sup_0001",
                        "behavior_id": "B001",
                        "observed_side": "ambiguous",
                        "summary": "The bounded window does not distinguish either behavior.",
                        "evidence_ids": [repair_ev["evidence_id"]],
                        "decisive_addresses": ["0x3000"],
                    }],
                    "claim": {
                        "summary": "The required behavior remains unresolved.",
                        "support_ids": ["sup_0001"],
                        "unresolved_behavior_ids": ["B001"],
                    },
                    "inconclusive_reason": "conflicting_evidence",
                }),
            },
        ]
        input_items = []
        transcript = []
        done, final = agent_loop.handle_tool_calls(
            output_items=calls,
            input_items=input_items,
            transcript=transcript,
            turn_label="verifier-repair-summary",
            allowed_tools=allowed,
            output_dir=tmp,
            start_epoch=0.0,
        )
        check(
            "verifier repair summary and submit accepted",
            done is True
            and final is not None
            and final.get("status") == "inconclusive"
            and repair_ev.get("claim_revision") == 1,
        )
        check(
            "verifier repair call order retained",
            [item.get("tool") for item in transcript]
            == ["summarize_evidence", "submit_detection_result"],
        )

    # --- 11. a failed verifier-repair summary blocks the sibling submit. ---
    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context(
            {"cve_id": "CVE-RF", "project": "curl"},
            "/tmp/curl",
            "CVE-RF",
            tmp,
            tmp,
            patch_spec=PATCH_SPEC,
            evidence_verifier_mode="llm",
        )
        configure_evidence_verifier(SimpleNamespace(mode="llm", repair_pending=True))
        calls = [
            {
                "type": "function_call",
                "id": "failed-repair-summary",
                "name": "summarize_evidence",
                "arguments": json.dumps({
                    "observation_id": "obs_0001",
                    "claims": [{
                        "evidence_id": "ev_9999",
                        "claim": "Unknown evidence must fail.",
                    }],
                }),
            },
            {
                "type": "function_call",
                "id": "blocked-repair-submit",
                "name": "submit_detection_result",
                "arguments": json.dumps({
                    "status": "inconclusive",
                    "confidence": "low",
                    "supports": [],
                    "claim": {
                        "summary": "The required behavior remains unresolved.",
                        "support_ids": [],
                        "unresolved_behavior_ids": ["B001"],
                    },
                    "inconclusive_reason": "conflicting_evidence",
                }),
            },
        ]
        input_items = []
        transcript = []
        done, final = agent_loop.handle_tool_calls(
            output_items=calls,
            input_items=input_items,
            transcript=transcript,
            turn_label="verifier-repair-failed-summary",
            allowed_tools=allowed,
            output_dir=tmp,
            start_epoch=0.0,
        )
        check("failed repair summary is nonterminal", done is False and final is None)
        check(
            "failed repair summary blocks submit",
            len(transcript) == 2
            and transcript[0].get("result", {}).get("ok") is False
            and "single evidence-verifier repair response was invalid"
            in transcript[1].get("result", {}).get("error", ""),
        )

    # --- 12. revisions update the ledger while old claims remain in transcript. ---
    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context(
            {"cve_id": "CVE-REV", "project": "curl"},
            "/tmp/curl",
            "CVE-REV",
            tmp,
            tmp,
            patch_spec=PATCH_SPEC,
        )
        revision_ev = record_evidence(
            observation_id="obs_0001",
            kind="command_output",
            claim="Host observed a target-code comparison.",
            excerpts=["0x4000: cmp eax, 8"],
        )
        mark_evidence_returned([revision_ev], response_index=0)
        input_items = []
        transcript = []
        first_summary = {
            "type": "function_call",
            "id": "revision-one",
            "name": "summarize_evidence",
            "arguments": json.dumps({
                "observation_id": "obs_0001",
                "claims": [{
                    "evidence_id": revision_ev["evidence_id"],
                    "claim": "The comparison checks a length value.",
                }],
            }),
        }
        done, final = agent_loop.handle_tool_calls(
            output_items=[first_summary],
            input_items=input_items,
            transcript=transcript,
            turn_label="revision-1",
            allowed_tools=allowed,
            output_dir=tmp,
            start_epoch=0.0,
        )
        check("first revision remains nonterminal", done is False and final is None)
        revised_summary = {
            "type": "function_call",
            "id": "revision-two",
            "name": "summarize_evidence",
            "arguments": json.dumps({
                "observation_id": "obs_0001",
                "claims": [{
                    "evidence_id": revision_ev["evidence_id"],
                    "claim": "The comparison enforces the required upper length bound.",
                }],
            }),
        }
        revision_submit = {
            "type": "function_call",
            "id": "revision-submit",
            "name": "submit_detection_result",
            "arguments": json.dumps({
                "status": "present",
                "confidence": "high",
                "supports": [{
                    "support_id": "sup_0001",
                    "behavior_id": "B001",
                    "observed_side": "new",
                    "summary": "The comparison enforces the required bound.",
                    "evidence_ids": [revision_ev["evidence_id"]],
                    "decisive_addresses": ["0x4000"],
                }],
                "claim": {
                    "summary": "The required bounded behavior is present.",
                    "support_ids": ["sup_0001"],
                    "unresolved_behavior_ids": [],
                },
                "inconclusive_reason": "none",
            }),
        }
        done, final = agent_loop.handle_tool_calls(
            output_items=[revised_summary, revision_submit],
            input_items=input_items,
            transcript=transcript,
            turn_label="revision-2",
            allowed_tools=allowed,
            output_dir=tmp,
            start_epoch=0.0,
        )
        check(
            "revised claim finalizes",
            done is True
            and final is not None
            and final.get("evidence_ledger", [{}])[0].get("claim_revision") == 2,
        )
        check(
            "transcript retains old and new claims",
            transcript[0].get("result", {}).get("evidence", [{}])[0].get("claim")
            == "The comparison checks a length value."
            and transcript[1].get("result", {}).get("evidence", [{}])[0].get("claim")
            == "The comparison enforces the required upper length bound.",
        )
        with open(os.path.join(tmp, "transcript.json"), encoding="utf-8") as handle:
            saved_transcript = json.load(handle)
        check(
            "saved transcript retains claim revisions",
            saved_transcript[0].get("result", {}).get("evidence", [{}])[0].get("claim")
            == "The comparison checks a length value."
            and saved_transcript[1].get("result", {}).get("evidence", [{}])[0].get("claim")
            == "The comparison enforces the required upper length bound.",
        )

    # --- 13. malformed summary dispatches still count summary failures. ---
    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context(
            {"cve_id": "CVE-MALFORMED", "project": "curl"},
            "/tmp/curl",
            "CVE-MALFORMED",
            tmp,
            tmp,
        )
        malformed = {
            "type": "function_call",
            "id": "malformed-summary",
            "name": "summarize_evidence",
            "arguments": "{not-json",
        }
        input_items = []
        transcript = []
        done, final = agent_loop.handle_tool_calls(
            output_items=[malformed],
            input_items=input_items,
            transcript=transcript,
            turn_label="malformed-summary",
            allowed_tools=allowed,
            output_dir=tmp,
            start_epoch=0.0,
        )
        metrics = harness_metrics()
        check("malformed summary is nonterminal", done is False and final is None)
        check(
            "malformed summary metrics counted",
            metrics["evidence_summary_calls"] == 1
            and metrics["evidence_summary_failures"] == 1,
        )

    if failures:
        print("FAIL:", failures)
        return 1
    print("RESPONSES LOOP TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
