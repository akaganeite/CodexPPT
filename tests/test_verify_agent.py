"""Offline checks for the bounded independent Verify Agent.

    python3 -m claudeagent.tests.test_verify_agent
"""

from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

from claudeagent.runtime import AGENT_CONTEXT
from claudeagent.verify_agent import (
    VERIFY_AGENT_PROMPT,
    VerifyAgentConfig,
    VerifyAgentSession,
    build_verify_agent_payload,
    verify_agent_config_digest,
)


METADATA = {
    "cve_id": "CVE-TEST-0001",
    "project": "demo",
    "description": "A missing bounds check permits an oversized copy.",
    "changes": [{"old": "copy without guard", "new": "guard then copy"}],
}


def _candidate(*, evidence_ids: list[str] | None = None, status: str = "present") -> dict:
    return {
        "schema_version": "final_result.v7",
        "status": status,
        "confidence": "high",
        "evidence": ["MODEL_VISIBLE_BUT_NOT_PAYLOAD_AUTHORITY"],
        "evidence_ids": evidence_ids if evidence_ids is not None else ["ev_0001", "ev_0002"],
        "reasoning": "The guarded copy path implements the patched behavior.",
        "decisive_addresses": ["0x1010", "0x1020"],
        "inconclusive_reason": "none" if status != "inconclusive" else "other",
        "observations": [{"stdout_head": "RAW_OBSERVATION_SECRET"}],
        "transcript": [{"content": "TRANSCRIPT_SECRET"}],
        "binary": "/home/example/REAL_BINARY_SECRET",
    }


def _evidence(evidence_id: str, start: int) -> dict:
    return {
        "evidence_id": evidence_id,
        "observation_id": "RAW_OBSERVATION_ID_SECRET",
        "claim": f"The comparison at 0x{start:x} controls the copy path.",
        "verification_excerpt": [
            f"0x{start:x}: cmp eax, 0x100",
            f"0x{start + 4:x}: ja 0x{start + 0x20:x}",
        ],
        "verification_locators": [{
            "start": f"0x{start:x}",
            "end": f"0x{start + 0x30:x}",
        }],
        "supporting_excerpt": ["SUPPORTING_EXCERPT_SECRET"],
        "command": ["objdump", "/home/example/COMMAND_PATH_SECRET"],
    }


def _config(**overrides: object) -> VerifyAgentConfig:
    values = {
        "api_key": "SECRET_API_KEY",
        "base_url": "https://example.invalid/v1",
        "model": "gpt-5.5",
        "reasoning": {"effort": "medium"},
        "api_timeout": 1,
        "api_max_retries": 1,
        "api_turn_retries": 1,
        "strict": False,
        "verdict_calls": 5,
        "max_protocol_repairs": 2,
    }
    values.update(overrides)
    return VerifyAgentConfig(**values)


def _tool_call(call_id: str, name: str, arguments: dict) -> dict:
    return {
        "type": "function_call",
        "call_id": call_id,
        "name": name,
        "arguments": json.dumps(arguments),
    }


def _response(call: dict | None, *, tokens: int = 1, extra_calls: list[dict] | None = None) -> dict:
    output = [] if call is None else [call]
    output.extend(extra_calls or [])
    return {
        "output": output,
        "usage": {
            "input_tokens": tokens,
            "output_tokens": 2,
            "total_tokens": tokens + 2,
            "details": {"cached_tokens": 1},
        },
    }


def _run_args(phase: str, evidence_id: str, marker: str) -> dict:
    return {
        "phase": phase,
        "evidence_id": evidence_id,
        "script": f"print({marker!r})",
        "timeout_sec": 0,
        "max_output_chars": 0,
    }


def _confirmed_result() -> dict:
    return {
        "action": "confirmed",
        "claim_checks": [
            {
                "evidence_id": "ev_0001",
                "relation": "supported",
                "decisive": True,
                "verifier_evidence_ids": ["vev_0001"],
                "reason": "The branch bypasses the copy when the bound is exceeded.",
            },
            {
                "evidence_id": "ev_0002",
                "relation": "supported",
                "decisive": False,
                "verifier_evidence_ids": ["vev_0002"],
                "reason": "The adjacent block is consistent with the guarded path.",
            },
        ],
        "coverage_status": "complete",
        "coverage_reason": "The relevant guarded copy behavior was independently inspected.",
        "recommended_status": "present",
        "verdict_evidence_ids": ["vev_0007"],
        "reason": "The target implements the patched guard and no opposite path was found.",
    }


def _run() -> int:
    failures: list[str] = []

    def check(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    prompt = VERIFY_AGENT_PROMPT.read_text(encoding="utf-8")
    discouraged_wording = "un" + "trusted"
    check("prompt uses neutral claim wording", discouraged_wording not in prompt.lower())
    check("prompt defines patch-presence direction", "present: positive binary evidence establishes the patched behavior" in prompt)
    check("prompt treats submitted reasoning as data", "submitted reasoning" in prompt)
    try:
        _config(verdict_calls=6)
        check("verdict budget is capped at five", False)
    except ValueError:
        check("verdict budget is capped at five", True)

    descriptors = [_evidence("ev_0001", 0x1010), _evidence("ev_0002", 0x2010)]
    payload = build_verify_agent_payload(
        metadata=METADATA,
        candidate=_candidate(),
        cited_evidence=descriptors,
        verdict_calls=5,
    )
    rendered_payload = json.dumps(payload, ensure_ascii=False)
    check("payload keeps descriptor aliases", payload["cited_evidence"][0]["excerpt"][0].startswith("0x1010") and payload["cited_evidence"][0]["address_ranges"][0]["start"] == "0x1010")
    check("payload omits raw observation", "RAW_OBSERVATION_SECRET" not in rendered_payload and "RAW_OBSERVATION_ID_SECRET" not in rendered_payload)
    check("payload omits transcript", "TRANSCRIPT_SECRET" not in rendered_payload)
    check("payload omits host paths and raw command", "REAL_BINARY_SECRET" not in rendered_payload and "COMMAND_PATH_SECRET" not in rendered_payload)
    check("payload omits supporting excerpt", "SUPPORTING_EXCERPT_SECRET" not in rendered_payload)
    check("payload uses fixed target path", payload.get("target_binary") == "/workspace/binary")

    try:
        build_verify_agent_payload(
            metadata=METADATA,
            candidate=_candidate(),
            cited_evidence=[_evidence("ev_0001", 0x1010)],
        )
        check("payload rejects missing cited descriptor", False)
    except ValueError:
        check("payload rejects missing cited descriptor", True)

    try:
        no_locator = [_evidence("ev_0001", 0x1010), _evidence("ev_0002", 0x2010)]
        for item in no_locator:
            item["verification_locators"] = []
        build_verify_agent_payload(
            metadata=METADATA,
            candidate=_candidate(),
            cited_evidence=no_locator,
        )
        check("present payload requires a locator", False)
    except ValueError:
        check("present payload requires a locator", True)

    full_responses = [
        _response(_tool_call("c1", "run_python", _run_args("claim", "ev_0001", "claim-1"))),
        _response(_tool_call("c2", "run_python", _run_args("claim", "ev_0002", "claim-2"))),
        *[
            _response(_tool_call(f"v{index}", "run_python", _run_args("verdict", "", f"verdict-{index}")))
            for index in range(1, 6)
        ],
        _response(_tool_call("submit", "submit_verification_result", _confirmed_result())),
    ]
    provider_calls: list[dict] = []
    sandbox_calls: list[dict] = []

    def full_client(**kwargs):
        provider_calls.append(copy.deepcopy(kwargs))
        return full_responses.pop(0)

    def full_sandbox(**kwargs):
        sandbox_calls.append(copy.deepcopy(kwargs))
        script_name = Path(kwargs["script_path"]).name
        return {
            "ok": True,
            "returncode": 0,
            "elapsed_sec": 0.01,
            "stdout": f"{script_name}: independently inspected 0x1010\n",
            "stderr": "",
        }

    previous_context = copy.deepcopy(AGENT_CONTEXT)
    AGENT_CONTEXT.clear()
    AGENT_CONTEXT.update({"sentinel": {"kept": True}})
    expected_context = copy.deepcopy(AGENT_CONTEXT)
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "binary"
        binary.write_bytes(b"\x7fELFtest")
        session = VerifyAgentSession(
            config=_config(),
            metadata=METADATA,
            candidate=_candidate(),
            cited_evidence=descriptors,
            binary_path=str(binary),
            scratch_root=tmp,
            client=full_client,
            sandbox_runner=full_sandbox,
        )
        report = session.run()
        check("full verifier confirms", report["outcome"] == "confirmed" and report["verification"]["action"] == "confirmed")
        check("N plus five tool budget", report["claim_calls"] == 2 and report["verdict_calls"] == 5 and len(sandbox_calls) == 7)
        check("local verifier IDs", [item["observation_id"] for item in session.observations] == [f"vobs_{index:04d}" for index in range(1, 8)] and [item["evidence_id"] for item in session.evidence_ledger] == [f"vev_{index:04d}" for index in range(1, 8)])
        check("scratch is isolated", all(Path(call["scratch_dir"]).parent == Path(tmp) and Path(call["script_path"]).parent == Path(call["scratch_dir"]) for call in sandbox_calls))
        check("sandbox target remains Host-only", all(call["binary_path"] == str(binary) for call in sandbox_calls) and str(binary) not in json.dumps(provider_calls, ensure_ascii=False))
        check("one call per response request", len(provider_calls) == 8)
        check("required stateless responses", all(call["tool_choice"] == "required" and call["store"] is False for call in provider_calls))
        check("strict disabled on copied tools", all("strict" not in tool for call in provider_calls for tool in call["tools"]))
        check("submit-only after budget", [tool["name"] for tool in provider_calls[-1]["tools"]] == ["submit_verification_result"])
        check("main runtime untouched", AGENT_CONTEXT == expected_context)
        usage = session.usage_summary()
        check("usage remains separate and merged", usage["model_turns"] == 8 and usage["totals"].get("input_tokens") == 8 and usage["totals"].get("details", {}).get("cached_tokens") == 8)
        audit = session.audit()
        check("audit includes bounded state", audit["claim_calls"] == 2 and audit["verdict_calls"] == 5 and len(audit["observations"]) == 7 and len(audit["evidence_ledger"]) == 7)
        check("audit excludes API key", "SECRET_API_KEY" not in json.dumps(audit, ensure_ascii=False) and "SECRET_API_KEY" not in session.config_digest)
        check("config digest stable", session.config_digest == verify_agent_config_digest(_config()))
    AGENT_CONTEXT.clear()
    AGENT_CONTEXT.update(previous_context)

    protocol_responses = [
        _response(None),
        _response(
            _tool_call("m1", "run_python", _run_args("claim", "ev_0001", "one")),
            extra_calls=[_tool_call("m2", "run_python", _run_args("claim", "ev_0002", "two"))],
        ),
        _response(None),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "binary"
        binary.write_bytes(b"ELF")
        protocol_session = VerifyAgentSession(
            config=_config(),
            metadata=METADATA,
            candidate=_candidate(),
            cited_evidence=descriptors,
            binary_path=str(binary),
            scratch_root=tmp,
            client=lambda **_kwargs: protocol_responses.pop(0),
            sandbox_runner=lambda **_kwargs: (_ for _ in ()).throw(AssertionError("must not run")),
        )
        protocol_report = protocol_session.run()
        check("two protocol repairs then unresolved", protocol_report["outcome"] == "unresolved" and protocol_report["failure_kind"] == "protocol_failure" and protocol_report["protocol_repairs"] == 2 and protocol_session.protocol_errors == 3)
        check("malformed multi-call executes nothing", protocol_report["claim_calls"] == 0 and not protocol_session.observations)

    failed_submit = {
        "action": "confirmed",
        "claim_checks": [{
            "evidence_id": "ev_0001",
            "relation": "supported",
            "decisive": True,
            "verifier_evidence_ids": ["vev_0001"],
            "reason": "Incorrectly treats a failed inspection as support.",
        }],
        "coverage_status": "complete",
        "coverage_reason": "Claimed complete.",
        "recommended_status": "present",
        "verdict_evidence_ids": [],
        "reason": "Claimed confirmed.",
    }
    insufficient_submit = {
        "action": "unresolved",
        "claim_checks": [{
            "evidence_id": "ev_0001",
            "relation": "insufficient",
            "decisive": False,
            "verifier_evidence_ids": ["vev_0001"],
            "reason": "The dedicated inspection failed and did not establish the claim.",
        }],
        "coverage_status": "uncertain",
        "coverage_reason": "The relevant code could not be inspected.",
        "recommended_status": "present",
        "verdict_evidence_ids": [],
        "reason": "The submitted verdict was not disproved but could not be confirmed.",
    }
    repair_responses = [
        _response(_tool_call("early", "run_python", _run_args("verdict", "", "too-early"))),
        _response(_tool_call("claim", "run_python", _run_args("claim", "ev_0001", "claim"))),
        _response(_tool_call("bad-submit", "submit_verification_result", failed_submit)),
        _response(_tool_call("good-submit", "submit_verification_result", insufficient_submit)),
    ]
    failed_sandbox_calls: list[dict] = []
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "binary"
        binary.write_bytes(b"ELF")

        def failed_sandbox(**kwargs):
            failed_sandbox_calls.append(kwargs)
            return {
                "ok": False,
                "returncode": 1,
                "elapsed_sec": 0.01,
                "stdout": "",
                "stderr": "objdump failed",
                "error": "inspection failed",
            }

        repair_session = VerifyAgentSession(
            config=_config(),
            metadata=METADATA,
            candidate=_candidate(evidence_ids=["ev_0001"]),
            cited_evidence=[_evidence("ev_0001", 0x1010)],
            binary_path=str(binary),
            scratch_root=tmp,
            client=lambda **_kwargs: repair_responses.pop(0),
            sandbox_runner=failed_sandbox,
        )
        repair_report = repair_session.run()
        check("cross-phase call repairs without consuming budget", repair_report["claim_calls"] == 1 and repair_report["verdict_calls"] == 0 and len(failed_sandbox_calls) == 1)
        check("failed tool consumes claim opportunity", repair_session._claim_attempts["ev_0001"]["ok"] is False and len(repair_session.evidence_ledger) == 1)
        check("failed claim must be insufficient", repair_report["outcome"] == "unresolved" and repair_report["failure_kind"] == "" and repair_report["verification"]["claim_checks"][0]["relation"] == "insufficient")
        check("protocol repairs are bounded and recoverable", repair_report["protocol_repairs"] == 2)

    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "binary"
        binary.write_bytes(b"ELF")
        api_session = VerifyAgentSession(
            config=_config(),
            metadata=METADATA,
            candidate=_candidate(evidence_ids=["ev_0001"]),
            cited_evidence=[_evidence("ev_0001", 0x1010)],
            binary_path=str(binary),
            scratch_root=tmp,
            client=lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("offline")),
        )
        api_report = api_session.run()
        check("API failure is unresolved with audit reason", api_report["outcome"] == "unresolved" and api_report["failure_kind"] == "api_failure" and api_report["verification"]["action"] == "unresolved")

    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "binary"
        binary.write_bytes(b"ELF")
        validation_session = VerifyAgentSession(
            config=_config(verdict_calls=0),
            metadata=METADATA,
            candidate=_candidate(evidence_ids=["ev_0001"]),
            cited_evidence=[_evidence("ev_0001", 0x1010)],
            binary_path=str(binary),
            scratch_root=tmp,
            client=lambda **_kwargs: (_ for _ in ()).throw(AssertionError("not sampled")),
        )
        validation_session._claim_attempts["ev_0001"] = {
            "observation_id": "vobs_0001",
            "evidence_id": "vev_0001",
            "ok": True,
        }
        validation_session.evidence_ledger.extend([
            {
                "evidence_id": "vev_0001",
                "observation_id": "vobs_0001",
                "phase": "claim",
                "ok": True,
                "excerpt": ["0x1010: cmp eax, 0x100"],
            },
            {
                "evidence_id": "vev_0002",
                "observation_id": "vobs_0002",
                "phase": "verdict",
                "ok": False,
                "excerpt": [],
            },
            {
                "evidence_id": "vev_0003",
                "observation_id": "vobs_0003",
                "phase": "verdict",
                "ok": True,
                "excerpt": [],
            },
        ])
        contradicted_unresolved = copy.deepcopy(insufficient_submit)
        contradicted_unresolved["claim_checks"][0]["relation"] = "contradicted"
        contradicted_unresolved["claim_checks"][0]["verifier_evidence_ids"] = ["vev_0001"]
        check(
            "unresolved rejects explicit contradiction",
            any(
                "requires action=contradicted" in error
                for error in validation_session._verification_errors(contradicted_unresolved)
            ),
        )
        claim_only_opposite = {
            "action": "contradicted",
            "claim_checks": [{
                "evidence_id": "ev_0001",
                "relation": "supported",
                "decisive": True,
                "verifier_evidence_ids": ["vev_0001"],
                "reason": "The dedicated claim inspection supports the submitted claim.",
            }],
            "coverage_status": "complete",
            "coverage_reason": "The submitted claim was checked.",
            "recommended_status": "absent",
            "verdict_evidence_ids": ["vev_0001"],
            "reason": "A claim-phase observation alone must not establish an opposite verdict.",
        }
        check(
            "contradiction requires claim contradiction or verdict-phase evidence",
            any(
                "verdict-phase evidence" in error
                for error in validation_session._verification_errors(claim_only_opposite)
            ),
        )
        empty_opposite = copy.deepcopy(claim_only_opposite)
        empty_opposite["verdict_evidence_ids"] = ["vev_0003"]
        check(
            "empty verifier output cannot support an opposite verdict",
            any(
                "non-empty returned excerpts" in error
                for error in validation_session._verification_errors(empty_opposite)
            ),
        )
        failed_verdict_support = {
            "action": "confirmed",
            "claim_checks": [{
                "evidence_id": "ev_0001",
                "relation": "supported",
                "decisive": True,
                "verifier_evidence_ids": ["vev_0001"],
                "reason": "The successful claim inspection supports the decisive behavior.",
            }],
            "coverage_status": "complete",
            "coverage_reason": "Claimed complete.",
            "recommended_status": "present",
            "verdict_evidence_ids": ["vev_0002"],
            "reason": "The failed verdict inspection must not be used as support.",
        }
        check(
            "failed verifier observation cannot support verdict",
            any(
                "verdict support requires successful observations" in error
                for error in validation_session._verification_errors(failed_verdict_support)
            ),
        )

    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / "binary"
        binary.write_bytes(b"ELF")
        owned_session = VerifyAgentSession(
            config=_config(),
            metadata=METADATA,
            candidate=_candidate(evidence_ids=["ev_0001"]),
            cited_evidence=[_evidence("ev_0001", 0x1010)],
            binary_path=str(binary),
            client=lambda **_kwargs: (_ for _ in ()).throw(AssertionError("not sampled")),
        )
        owned_scratch = Path(owned_session.scratch_dir)
        check("internally owned scratch exists", owned_scratch.is_dir())
        owned_session.close()
        check("close removes internally owned scratch", not owned_scratch.exists())

    if failures:
        print("VERIFY AGENT TESTS FAILED:")
        for failure in failures:
            print("  -", failure)
        return 1
    print("VERIFY AGENT TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(_run())
