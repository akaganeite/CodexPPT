"""Offline dispatch and Verify Agent coordination checks.

    python3 -m claudeagent.tests.test_responses_loop
"""

from __future__ import annotations

import json
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

from claudeagent import agent_loop
from claudeagent.evidence_summary import summarize_evidence
from claudeagent.finalize import submit_detection_result
from claudeagent.model_config import ModelProfile
from claudeagent.runtime import (
    AGENT_CONTEXT,
    initialize_agent_context,
    next_id,
    record_evidence,
)


VERIFY_DIGEST = "a" * 64


def _stub_run_python(**_: object) -> dict[str, Any]:
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


def _call(call_id: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "function_call",
        "call_id": call_id,
        "name": name,
        "arguments": json.dumps(arguments),
    }


def _submit_call(
    call_id: str,
    *,
    status: str,
    evidence_ids: list[str],
) -> dict[str, Any]:
    return _call(call_id, "submit_detection_result", {
        "status": status,
        "confidence": "low" if status == "inconclusive" else "high",
        "evidence_ids": evidence_ids,
        "reasoning": (
            "The target comparison at 0x1010 establishes the selected behavior."
            if status != "inconclusive"
            else "The target behavior remains unresolved."
        ),
        "decisive_addresses": ["0x1010"] if evidence_ids else [],
        "inconclusive_reason": "none" if status != "inconclusive" else "other",
    })


def _allowed_tools() -> dict[str, Any]:
    return {
        "run_python": _stub_run_python,
        "summarize_evidence": summarize_evidence,
        "submit_detection_result": submit_detection_result,
    }


def _prepare_determinate_submission(
    tmp: str,
    *,
    status: str = "present",
) -> tuple[agent_loop.PendingSubmission, list[dict[str, Any]], list[dict[str, Any]]]:
    initialize_agent_context(
        {"cve_id": "CVE-X", "project": "demo", "description": "bounds check"},
        "/workspace/binary",
        "CVE-X",
        tmp,
        tmp,
    )
    input_items: list[dict[str, Any]] = []
    transcript: list[dict[str, Any]] = []
    pending = agent_loop.handle_tool_calls(
        output_items=[_call(
            "inspect",
            "run_python",
            {"script": "print(1)", "timeout_sec": 0, "max_output_chars": 0},
        )],
        input_items=input_items,
        transcript=transcript,
        turn_label=1,
        allowed_tools=_allowed_tools(),
    )
    if pending is not None:
        raise AssertionError("inspection unexpectedly produced a submission")
    summary = _call("summary", "summarize_evidence", {
        "observation_id": "obs_0001",
        "claims": [{
            "evidence_id": "ev_0001",
            "claim": "The target comparison enforces the bound.",
            "excerpt": ["0x1010: cmp eax, 8"],
            "address_ranges": [{"start": "0x1010", "end": "0x1010"}],
        }],
    })
    submission = agent_loop.handle_tool_calls(
        output_items=[summary, _submit_call(
            f"submit-{status}",
            status=status,
            evidence_ids=["ev_0001"],
        )],
        input_items=input_items,
        transcript=transcript,
        turn_label=2,
        allowed_tools=_allowed_tools(),
    )
    if submission is None:
        raise AssertionError("valid determinate submission was not deferred")
    return submission, input_items, transcript


def _prepare_inconclusive_submission(
    tmp: str,
) -> tuple[agent_loop.PendingSubmission, list[dict[str, Any]], list[dict[str, Any]]]:
    initialize_agent_context(
        {"cve_id": "CVE-I", "project": "demo", "description": "bounds check"},
        "/workspace/binary",
        "CVE-I",
        tmp,
        tmp,
    )
    input_items: list[dict[str, Any]] = []
    transcript: list[dict[str, Any]] = []
    submission = agent_loop.handle_tool_calls(
        output_items=[_submit_call(
            "submit-inconclusive",
            status="inconclusive",
            evidence_ids=[],
        )],
        input_items=input_items,
        transcript=transcript,
        turn_label=1,
        allowed_tools=_allowed_tools(),
    )
    if submission is None:
        raise AssertionError("valid inconclusive submission was not deferred")
    return submission, input_items, transcript


class _FakeVerifySession:
    def __init__(self, outcome: str, candidate_status: str) -> None:
        relation = {
            "confirmed": "supported",
            "contradicted": "contradicted",
            "unresolved": "insufficient",
        }[outcome]
        coverage = {
            "confirmed": "complete",
            "contradicted": "incomplete",
            "unresolved": "uncertain",
        }[outcome]
        recommended = (
            candidate_status
            if outcome == "confirmed"
            else "inconclusive"
            if outcome == "unresolved"
            else ("absent" if candidate_status == "present" else "present")
        )
        self.outcome = outcome
        self.failure_kind = ""
        self.error = ""
        self.wall_seconds = 0.01
        self.transcript = [{"turn": 1, "usage": {"input_tokens": 2}}]
        self.evidence_ledger = [{
            "evidence_id": "vev_0001",
            "excerpt": ["0x1010: cmp eax, 8"],
            "address_ranges": [{"start": "0x1010", "end": "0x1010"}],
        }]
        self.verification = {
            "action": outcome,
            "claim_checks": [{
                "evidence_id": "ev_0001",
                "relation": relation,
                "decisive": True,
                "verifier_evidence_ids": ["vev_0001"],
                "reason": f"Verifier classified the cited claim as {relation}.",
            }],
            "coverage_status": coverage,
            "coverage_reason": f"Verifier coverage is {coverage}.",
            "recommended_status": recommended,
            "verdict_evidence_ids": ["vev_0001"],
            "reason": f"Verifier outcome is {outcome}.",
        }

    def report(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "verification": self.verification,
            "claim_calls": 1,
            "verdict_calls": 1,
            "protocol_repairs": 0,
            "failure_kind": self.failure_kind,
            "error": self.error,
        }

    def audit(self) -> dict[str, Any]:
        return {
            "protocol_version": "verify_agent.v1",
            "config_digest": VERIFY_DIGEST,
            "input_digest": "b" * 64,
            "outcome": self.outcome,
            "claim_budget": 1,
            "claim_calls": 1,
            "verdict_budget": 5,
            "verdict_calls": 1,
            "protocol_repairs": 0,
            "failure_kind": self.failure_kind,
            "error": self.error,
            "verification": self.verification,
            "observations": [],
            "evidence_ledger": self.evidence_ledger,
            "wall_seconds": self.wall_seconds,
        }

    def usage_summary(self) -> dict[str, Any]:
        return {
            "provider": "openai-responses",
            "model": "fake-verifier",
            "model_turns": 1,
            "totals": {"input_tokens": 2, "output_tokens": 1},
            "by_turn": [{"turn": 1, "usage": {"input_tokens": 2, "output_tokens": 1}}],
            "timing": {"wall_seconds": self.wall_seconds},
        }


@contextmanager
def _patched(obj: Any, name: str, value: Any) -> Iterator[None]:
    previous = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, previous)


def _profile() -> ModelProfile:
    return ModelProfile(
        name="main",
        base_url="http://example.invalid/v1",
        model="fake-main",
        reasoning_effort="low",
        reasoning_mode="on",
        api_key_env="TEST_API_KEY",
        api_key_file=None,
        api_key_field=None,
        api_timeout=None,
        api_max_retries=None,
        api_turn_retries=None,
    )


def _args(tmp: str, mode: str) -> SimpleNamespace:
    return SimpleNamespace(
        verify_agent=mode,
        output_dir=tmp,
        api_turn_retries=1,
    )


def _complete(
    *,
    tmp: str,
    pending: agent_loop.PendingSubmission,
    input_items: list[dict[str, Any]],
    transcript: list[dict[str, Any]],
    mode: str,
    sessions: list[_FakeVerifySession],
    repair_responses: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    queued_sessions = iter(sessions)
    queued_responses = iter(repair_responses or [])

    def verify_session(**_: Any) -> _FakeVerifySession:
        return next(queued_sessions)

    def sample_turn(*_: Any, **__: Any) -> dict[str, Any]:
        return next(queued_responses)

    settings = SimpleNamespace(config_digest=VERIFY_DIGEST) if mode == "on" else None
    with _patched(agent_loop, "_run_verify_session", verify_session), _patched(
        agent_loop,
        "_sample_turn",
        sample_turn,
    ):
        return agent_loop._write_completed_submission(
            args=_args(tmp, mode),
            metadata=AGENT_CONTEXT["metadata"],
            binary=AGENT_CONTEXT["binary_path"],
            scratch=tmp,
            pending=pending,
            instructions="test instructions",
            input_items=input_items,
            transcript=transcript,
            tools=[],
            api_key="test-key",
            base_url="http://example.invalid/v1",
            model="fake-main",
            profile=_profile(),
            verify_settings=settings,
            start_epoch=time.time(),
        )


def _run() -> int:
    failures: list[str] = []

    def check(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    with tempfile.TemporaryDirectory() as tmp:
        main_scratch = Path(tmp) / "scratch"
        main_scratch.mkdir()
        verifier_scratch = Path(agent_loop.verifier_scratch_root(str(main_scratch)))
        check(
            "verifier scratch is outside main scratch mount",
            verifier_scratch.parent == main_scratch.parent
            and verifier_scratch != main_scratch
            and main_scratch not in verifier_scratch.parents,
        )
        initialize_agent_context(
            {"cve_id": "CVE-F", "project": "demo"},
            "/workspace/binary",
            "CVE-F",
            tmp,
            str(main_scratch),
        )

        def fail_construction(**_: Any) -> Any:
            raise OSError("scratch unavailable")

        settings = SimpleNamespace(
            config=SimpleNamespace(model="fake-verifier", verdict_calls=5),
            config_digest=VERIFY_DIGEST,
        )
        with _patched(agent_loop, "VerifyAgentSession", fail_construction):
            failed_session = agent_loop._run_verify_session(
                settings=settings,
                metadata=AGENT_CONTEXT["metadata"],
                candidate={"status": "present", "evidence_ids": ["ev_0001"]},
                cited_evidence=[],
                binary="/workspace/binary",
                scratch=str(main_scratch),
            )
        check(
            "verifier construction failure becomes unresolved",
            failed_session.report().get("outcome") == "unresolved"
            and failed_session.report().get("failure_kind") == "internal_failure",
        )

    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context(
            {"cve_id": "CVE-P", "project": "demo"},
            "/workspace/binary",
            "CVE-P",
            tmp,
            tmp,
        )
        input_items: list[dict[str, Any]] = []
        transcript: list[dict[str, Any]] = []
        pending = agent_loop.handle_tool_calls(
            output_items=[{"type": "message", "role": "assistant", "content": "plain text"}],
            input_items=input_items,
            transcript=transcript,
            turn_label=1,
            allowed_tools=_allowed_tools(),
        )
        check("plain response is nudged", pending is None and input_items[0]["type"] == "message")

    with tempfile.TemporaryDirectory() as tmp:
        pending, input_items, transcript = _prepare_determinate_submission(tmp)
        evidence = AGENT_CONTEXT["evidence_ledger"][0]
        check("valid submit returns PendingSubmission", isinstance(pending, agent_loop.PendingSubmission))
        check("candidate is deferred without artifact", not (Path(tmp) / "final_result.json").exists())
        check("pending preserves submit call", pending.call_id == "submit-present" and pending.result["status"] == "present")
        check("summary provenance retained", evidence["claim_status"] == "summarized" and evidence["claim_revision"] == 1)
        check("verification locator retained", evidence["verification_locators"] == [{"start": "0x1010", "end": "0x1010"}])

    with tempfile.TemporaryDirectory() as tmp:
        initialize_agent_context(
            {"cve_id": "CVE-Y", "project": "demo"},
            "/workspace/binary",
            "CVE-Y",
            tmp,
            tmp,
        )
        input_items = []
        transcript = []
        invalid = _submit_call("bad", status="present", evidence_ids=[])
        pending = agent_loop.handle_tool_calls(
            output_items=[invalid],
            input_items=input_items,
            transcript=transcript,
            turn_label=1,
            allowed_tools=_allowed_tools(),
        )
        repair = json.loads(input_items[-1]["output"])
        check("invalid direct submit repairs", pending is None and repair.get("schema_errors"))

    with tempfile.TemporaryDirectory() as tmp:
        pending, input_items, transcript = _prepare_determinate_submission(tmp)
        failed_verifier = _FakeVerifySession("unresolved", "present")
        failed_verifier.failure_kind = "api_failure"
        failed_verifier.error = "x" * 5000
        artifact = _complete(
            tmp=tmp,
            pending=pending,
            input_items=input_items,
            transcript=transcript,
            mode="off",
            sessions=[],
        )
        check("off mode retains candidate", artifact.get("status") == "present")
        check("off mode records no verification", artifact.get("verification", {}).get("outcome") == "off")
        check("off mode artifact validates", not artifact.get("schema_validation_errors"))

    with tempfile.TemporaryDirectory() as tmp:
        pending, input_items, transcript = _prepare_inconclusive_submission(tmp)
        artifact = _complete(
            tmp=tmp,
            pending=pending,
            input_items=input_items,
            transcript=transcript,
            mode="on",
            sessions=[],
        )
        check("inconclusive skips verifier", artifact.get("verification", {}).get("outcome") == "skipped")
        check("skipped inconclusive validates", not artifact.get("schema_validation_errors"))

    with tempfile.TemporaryDirectory() as tmp:
        pending, input_items, transcript = _prepare_determinate_submission(tmp)
        artifact = _complete(
            tmp=tmp,
            pending=pending,
            input_items=input_items,
            transcript=transcript,
            mode="on",
            sessions=[_FakeVerifySession("confirmed", "present")],
        )
        check("confirmed retains determinate result", artifact.get("status") == "present")
        check("confirmed outcome recorded", artifact.get("verification", {}).get("outcome") == "confirmed")
        check("confirmed artifact validates", not artifact.get("schema_validation_errors"))

    with tempfile.TemporaryDirectory() as tmp:
        pending, input_items, transcript = _prepare_determinate_submission(tmp)
        artifact = _complete(
            tmp=tmp,
            pending=pending,
            input_items=input_items,
            transcript=transcript,
            mode="on",
            sessions=[failed_verifier],
        )
        check("unresolved retains main result", artifact.get("status") == "present")
        check("unresolved outcome recorded", artifact.get("verification", {}).get("outcome") == "unresolved")
        check("compact verifier errors are bounded", len(artifact.get("verification", {}).get("error", "")) == 4000)
        check("unresolved artifact validates", not artifact.get("schema_validation_errors"))

    with tempfile.TemporaryDirectory() as tmp:
        pending, input_items, transcript = _prepare_determinate_submission(tmp)
        repair_response = {
            "output": [_submit_call(
                "repair-inconclusive",
                status="inconclusive",
                evidence_ids=[],
            )],
            "usage": {"input_tokens": 3, "output_tokens": 1},
        }
        artifact = _complete(
            tmp=tmp,
            pending=pending,
            input_items=input_items,
            transcript=transcript,
            mode="on",
            sessions=[_FakeVerifySession("contradicted", "present")],
            repair_responses=[repair_response],
        )
        audit = artifact.get("verification", {})
        check("repaired inconclusive is retained", artifact.get("status") == "inconclusive")
        check("repaired inconclusive keeps its reason", artifact.get("inconclusive_reason") == "other")
        check("repaired inconclusive skips recheck", len(audit.get("sessions", [])) == 1 and audit.get("repair", {}).get("reverified") is False)
        check("repaired inconclusive artifact validates", not artifact.get("schema_validation_errors"))

    with tempfile.TemporaryDirectory() as tmp:
        pending, input_items, transcript = _prepare_determinate_submission(tmp)
        repair_response = {
            "output": [_submit_call("repair-submit", status="absent", evidence_ids=["ev_0001"])],
            "usage": {"input_tokens": 3, "output_tokens": 1},
        }
        artifact = _complete(
            tmp=tmp,
            pending=pending,
            input_items=input_items,
            transcript=transcript,
            mode="on",
            sessions=[
                _FakeVerifySession("contradicted", "present"),
                _FakeVerifySession("confirmed", "absent"),
            ],
            repair_responses=[repair_response],
        )
        audit = artifact.get("verification", {})
        check("contradiction repair can change result", artifact.get("status") == "absent")
        check("repaired candidate is freshly reverified", len(audit.get("sessions", [])) == 2 and audit.get("outcome") == "confirmed")
        check("repair provenance recorded", audit.get("repair", {}).get("resubmitted") is True and audit.get("repair", {}).get("reverified") is True)
        check("repaired artifact validates", not artifact.get("schema_validation_errors"))

    with tempfile.TemporaryDirectory() as tmp:
        pending, input_items, transcript = _prepare_determinate_submission(tmp)
        repair_response = {
            "output": [_submit_call("repair-submit", status="absent", evidence_ids=["ev_0001"])],
            "usage": {"input_tokens": 3, "output_tokens": 1},
        }
        artifact = _complete(
            tmp=tmp,
            pending=pending,
            input_items=input_items,
            transcript=transcript,
            mode="on",
            sessions=[
                _FakeVerifySession("contradicted", "present"),
                _FakeVerifySession("contradicted", "absent"),
            ],
            repair_responses=[repair_response],
        )
        check("second contradiction becomes inconclusive", artifact.get("status") == "inconclusive")
        check("second contradiction records conflict", artifact.get("inconclusive_reason") == "conflicting_evidence")
        check("terminal contradiction outcome recorded", artifact.get("verification", {}).get("outcome") == "contradicted")
        check("terminal contradiction validates", not artifact.get("schema_validation_errors"))

    if failures:
        print("RESPONSES LOOP TESTS FAILED:")
        for failure in failures:
            print("  -", failure)
        return 1
    print("RESPONSES LOOP TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(_run())
