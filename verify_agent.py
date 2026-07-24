"""Bounded, independent binary verification agent.

The verifier receives answer-scrubbed CVE metadata, a Host-canonical main-agent
candidate, and only the candidate's cited evidence descriptors. It reopens the
target binary through its own sandboxed ``run_python`` surface and keeps all
``vobs_*``/``vev_*`` state separate from the main agent runtime.
"""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from claudeagent.common import compact_json
from claudeagent.metadata_input import validate_metadata_prompt_input
from claudeagent.model_config import ModelProfile, reasoning_param
from claudeagent.responses_client import responses_create
from claudeagent.sandbox import run_in_sandbox
from claudeagent.schema_validate import DETERMINATE_STATUSES, validate_json_schema
from claudeagent.truncation import text_head_tail


VERIFY_AGENT_PROTOCOL_VERSION = "verify_agent.v1"
VERIFY_AGENT_PROMPT_VERSION = "verify_agent_prompt.v1"
VERIFY_AGENT_RESULT_POLICY_VERSION = "verify_agent_result_policy.v1"
VERIFY_AGENT_PROMPT = Path(__file__).resolve().parent / "prompts" / "verify_agent.txt"
DEFAULT_VERDICT_CALLS = 5
MAX_VERDICT_CALLS = 5
MAX_CITED_EVIDENCE = 8
MAX_PROTOCOL_REPAIRS = 2
MAX_EXCERPT_LINES = 12
MAX_ADDRESS_RANGES = 4
DEFAULT_TOOL_TIMEOUT = 240
DEFAULT_TOOL_OUTPUT_CHARS = 60_000
MAX_TOOL_TIMEOUT = 600
MAX_TOOL_OUTPUT_CHARS = 120_000


RUN_PYTHON_TOOL: dict[str, Any] = {
    "type": "function",
    "name": "run_python",
    "strict": True,
    "description": (
        "Run a Python script in the isolated verifier sandbox. The target is available only at "
        "/workspace/binary and /scratch is writable. Use phase=claim once for each cited evidence "
        "ID, then phase=verdict for optional whole-verdict checks."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "required": ["phase", "evidence_id", "script", "timeout_sec", "max_output_chars"],
        "properties": {
            "phase": {"type": "string", "enum": ["claim", "verdict"]},
            "evidence_id": {
                "type": "string",
                "description": (
                    "For phase=claim, the cited ev_* ID being checked. For phase=verdict, use an "
                    "empty string."
                ),
            },
            "script": {
                "type": "string",
                "minLength": 1,
                "maxLength": 100_000,
                "description": (
                    "Python source that inspects /workspace/binary with standard-library code and "
                    "available binutils. Print the verification findings to stdout."
                ),
            },
            "timeout_sec": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_TOOL_TIMEOUT,
                "description": "0 uses the 240 second default.",
            },
            "max_output_chars": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_TOOL_OUTPUT_CHARS,
                "description": "0 uses the 60000 character default.",
            },
        },
    },
}


SUBMIT_VERIFICATION_RESULT_TOOL: dict[str, Any] = {
    "type": "function",
    "name": "submit_verification_result",
    "strict": True,
    "description": (
        "Submit the independent verification after every cited evidence claim has received its "
        "dedicated claim-phase inspection."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "action",
            "claim_checks",
            "coverage_status",
            "coverage_reason",
            "recommended_status",
            "verdict_evidence_ids",
            "reason",
        ],
        "properties": {
            "action": {
                "type": "string",
                "enum": ["confirmed", "contradicted", "unresolved"],
            },
            "claim_checks": {
                "type": "array",
                "maxItems": MAX_CITED_EVIDENCE,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "evidence_id",
                        "relation",
                        "decisive",
                        "verifier_evidence_ids",
                        "reason",
                    ],
                    "properties": {
                        "evidence_id": {"type": "string", "minLength": 1},
                        "relation": {
                            "type": "string",
                            "enum": ["supported", "contradicted", "insufficient"],
                        },
                        "decisive": {"type": "boolean"},
                        "verifier_evidence_ids": {
                            "type": "array",
                            "maxItems": 20,
                            "items": {"type": "string"},
                        },
                        "reason": {"type": "string", "minLength": 1, "maxLength": 1600},
                    },
                },
            },
            "coverage_status": {
                "type": "string",
                "enum": ["complete", "incomplete", "uncertain"],
            },
            "coverage_reason": {"type": "string", "minLength": 1, "maxLength": 1600},
            "recommended_status": {
                "type": "string",
                "enum": ["present", "absent", "not_affected", "inconclusive"],
            },
            "verdict_evidence_ids": {
                "type": "array",
                "maxItems": 30,
                "items": {"type": "string"},
            },
            "reason": {"type": "string", "minLength": 1, "maxLength": 2400},
        },
    },
}


@dataclass(frozen=True)
class VerifyAgentConfig:
    """Provider settings and Host-enforced verifier budgets."""

    api_key: str
    base_url: str
    model: str
    reasoning: dict[str, Any] | None
    api_timeout: int = 240
    api_max_retries: int = 3
    api_turn_retries: int = 1
    strict: bool = True
    verdict_calls: int = DEFAULT_VERDICT_CALLS
    max_protocol_repairs: int = MAX_PROTOCOL_REPAIRS

    def __post_init__(self) -> None:
        if self.api_timeout <= 0:
            raise ValueError("verify-agent api_timeout must be positive")
        if self.api_max_retries <= 0:
            raise ValueError("verify-agent api_max_retries must be positive")
        if self.api_turn_retries <= 0:
            raise ValueError("verify-agent api_turn_retries must be positive")
        if not 0 <= self.verdict_calls <= MAX_VERDICT_CALLS:
            raise ValueError(
                f"verify-agent verdict_calls must be between 0 and {MAX_VERDICT_CALLS}"
            )
        if not 0 <= self.max_protocol_repairs <= MAX_PROTOCOL_REPAIRS:
            raise ValueError(
                "verify-agent max_protocol_repairs must be between 0 and "
                f"{MAX_PROTOCOL_REPAIRS}"
            )


def verify_agent_config_from_profile(
    profile: ModelProfile,
    api_key: str,
    *,
    verdict_calls: int = DEFAULT_VERDICT_CALLS,
    strict: bool = True,
) -> VerifyAgentConfig:
    """Construct verifier settings using the repository's model-profile semantics."""
    return VerifyAgentConfig(
        api_key=api_key,
        base_url=profile.base_url,
        model=profile.model,
        reasoning=reasoning_param(profile),
        api_timeout=profile.api_timeout if profile.api_timeout is not None else 240,
        api_max_retries=(
            profile.api_max_retries if profile.api_max_retries is not None else 3
        ),
        api_turn_retries=(
            profile.api_turn_retries if profile.api_turn_retries is not None else 1
        ),
        strict=strict,
        verdict_calls=verdict_calls,
    )


def _prompt_text() -> str:
    return VERIFY_AGENT_PROMPT.read_text(encoding="utf-8")


def verify_agent_config_digest(config: VerifyAgentConfig) -> str:
    """Fingerprint verifier behavior without including credentials."""
    payload = {
        "protocol_version": VERIFY_AGENT_PROTOCOL_VERSION,
        "prompt_version": VERIFY_AGENT_PROMPT_VERSION,
        "instructions": _prompt_text(),
        "tools": [RUN_PYTHON_TOOL, SUBMIT_VERIFICATION_RESULT_TOOL],
        "base_url": config.base_url.rstrip("/"),
        "model": config.model,
        "reasoning": config.reasoning,
        "api_timeout": config.api_timeout,
        "api_max_retries": config.api_max_retries,
        "api_turn_retries": config.api_turn_retries,
        "strict": config.strict,
        "verdict_calls": config.verdict_calls,
        "max_protocol_repairs": config.max_protocol_repairs,
        "result_policy": {
            "version": VERIFY_AGENT_RESULT_POLICY_VERSION,
            "insufficient_is_contradicted": False,
            "unresolved_retains_main_candidate": True,
            "confirmed_requires_complete_coverage": True,
            "contradiction_main_repairs": 1,
            "main_repair_model_responses": 4,
            "main_repair_run_python_calls": 1,
            "main_repair_schema_repairs": 1,
            "determinate_repair_gets_fresh_verification": True,
            "repaired_inconclusive_skips_reverification": True,
            "repair_failure_result": "inconclusive/conflicting_evidence",
            "second_contradiction_result": "inconclusive/conflicting_evidence",
        },
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _candidate_projection(candidate: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        raise ValueError("verify-agent candidate must be an object")
    status = str(candidate.get("status", ""))
    if status not in DETERMINATE_STATUSES | {"inconclusive"}:
        raise ValueError(f"verify-agent candidate has invalid status {status!r}")
    evidence_ids = candidate.get("evidence_ids")
    if not isinstance(evidence_ids, list) or not all(
        isinstance(item, str) and item for item in evidence_ids
    ):
        raise ValueError("verify-agent candidate evidence_ids must be a string array")
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("verify-agent candidate evidence_ids contain duplicates")
    if len(evidence_ids) > MAX_CITED_EVIDENCE:
        raise ValueError(
            f"verify-agent accepts at most {MAX_CITED_EVIDENCE} cited evidence IDs"
        )
    decisive_addresses = candidate.get("decisive_addresses", [])
    if not isinstance(decisive_addresses, list) or not all(
        isinstance(item, str) for item in decisive_addresses
    ):
        raise ValueError("verify-agent candidate decisive_addresses must be a string array")
    return {
        "status": status,
        "confidence": str(candidate.get("confidence", "")),
        "evidence_ids": list(evidence_ids),
        "reasoning": str(candidate.get("reasoning", "")),
        "decisive_addresses": list(decisive_addresses),
        "inconclusive_reason": str(candidate.get("inconclusive_reason", "")),
    }


def _normalize_address(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"{path} must be a 0x-prefixed hexadecimal address")
    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{path} must be a 0x-prefixed hexadecimal address") from exc
    if parsed < 0:
        raise ValueError(f"{path} must be non-negative")
    return f"0x{parsed:x}"


def _evidence_projection(item: Any, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError(f"cited_evidence[{index}] must be an object")
    evidence_id = item.get("evidence_id")
    claim = item.get("claim")
    if not isinstance(evidence_id, str) or not evidence_id:
        raise ValueError(f"cited_evidence[{index}].evidence_id must be non-empty")
    if not isinstance(claim, str) or not claim.strip():
        raise ValueError(f"cited_evidence[{index}].claim must be non-empty")

    excerpt = item.get("excerpt", item.get("verification_excerpt", []))
    ranges = item.get("address_ranges", item.get("verification_locators", []))
    if not isinstance(excerpt, list) or not all(isinstance(line, str) for line in excerpt):
        raise ValueError(f"cited_evidence[{index}].excerpt must be a string array")
    if not excerpt:
        raise ValueError(f"cited_evidence[{index}].excerpt must not be empty")
    if len(excerpt) > MAX_EXCERPT_LINES:
        raise ValueError(
            f"cited_evidence[{index}].excerpt exceeds {MAX_EXCERPT_LINES} lines"
        )
    if not isinstance(ranges, list):
        raise ValueError(f"cited_evidence[{index}].address_ranges must be an array")
    if len(ranges) > MAX_ADDRESS_RANGES:
        raise ValueError(
            f"cited_evidence[{index}].address_ranges exceeds {MAX_ADDRESS_RANGES} items"
        )
    normalized_ranges: list[dict[str, str]] = []
    for range_index, address_range in enumerate(ranges):
        if not isinstance(address_range, dict) or set(address_range) != {"start", "end"}:
            raise ValueError(
                f"cited_evidence[{index}].address_ranges[{range_index}] must contain only start/end"
            )
        start = _normalize_address(
            address_range.get("start"),
            f"cited_evidence[{index}].address_ranges[{range_index}].start",
        )
        end = _normalize_address(
            address_range.get("end"),
            f"cited_evidence[{index}].address_ranges[{range_index}].end",
        )
        if int(start, 16) > int(end, 16):
            raise ValueError(
                f"cited_evidence[{index}].address_ranges[{range_index}] start exceeds end"
            )
        normalized_ranges.append({"start": start, "end": end})
    return {
        "evidence_id": evidence_id,
        "claim": claim.strip(),
        "excerpt": list(excerpt),
        "address_ranges": normalized_ranges,
    }


def build_verify_agent_payload(
    *,
    metadata: dict[str, Any],
    candidate: dict[str, Any],
    cited_evidence: list[dict[str, Any]],
    verdict_calls: int = DEFAULT_VERDICT_CALLS,
) -> dict[str, Any]:
    """Build the allowlisted verifier input without main observations or paths."""
    validate_metadata_prompt_input(metadata)
    projected_candidate = _candidate_projection(candidate)
    if not isinstance(cited_evidence, list):
        raise ValueError("verify-agent cited_evidence must be an array")
    projected_by_id: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(cited_evidence):
        projected = _evidence_projection(item, index)
        evidence_id = projected["evidence_id"]
        if evidence_id in projected_by_id:
            raise ValueError(f"verify-agent cited_evidence duplicates {evidence_id!r}")
        projected_by_id[evidence_id] = projected
    candidate_ids = projected_candidate["evidence_ids"]
    if set(projected_by_id) != set(candidate_ids):
        raise ValueError(
            "verify-agent cited_evidence IDs must exactly match candidate evidence_ids "
            f"(candidate={candidate_ids}, cited={sorted(projected_by_id)})"
        )
    ordered_evidence = [projected_by_id[evidence_id] for evidence_id in candidate_ids]
    if projected_candidate["status"] in {"present", "absent"} and ordered_evidence:
        if not any(item["address_ranges"] for item in ordered_evidence):
            raise ValueError(
                "present/absent verification requires at least one cited evidence address range"
            )
    return {
        "task": "Independently verify the submitted binary patch-presence result.",
        "cve_metadata": copy.deepcopy(metadata),
        "candidate": projected_candidate,
        "cited_evidence": ordered_evidence,
        "target_binary": "/workspace/binary",
        "scratch_dir": "/scratch",
        "budgets": {
            "claim_calls": len(candidate_ids),
            "verdict_calls": int(verdict_calls),
        },
    }


def _merge_usage(usage_attempts: list[dict[str, Any]]) -> dict[str, Any]:
    totals: dict[str, Any] = {}

    def merge(target: dict[str, Any], source: dict[str, Any]) -> None:
        for key, value in source.items():
            if isinstance(value, dict):
                child = target.setdefault(key, {})
                if not isinstance(child, dict):
                    child = {}
                    target[key] = child
                merge(child, value)
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                current = target.get(key, 0)
                target[key] = (current if isinstance(current, (int, float)) else 0) + value

    for usage in usage_attempts:
        merge(totals, usage)
    return totals


def _tool_copy(tool: dict[str, Any], *, strict: bool) -> dict[str, Any]:
    copied = copy.deepcopy(tool)
    if not strict:
        copied.pop("strict", None)
    return copied


@dataclass
class VerifyAgentSession:
    """Run one bounded verifier conversation with entirely local evidence state."""

    config: VerifyAgentConfig
    metadata: dict[str, Any]
    candidate: dict[str, Any]
    cited_evidence: list[dict[str, Any]]
    binary_path: str
    scratch_root: str = ""
    client: Callable[..., dict[str, Any]] = responses_create
    sandbox_runner: Callable[..., dict[str, Any]] = run_in_sandbox
    transcript: list[dict[str, Any]] = field(default_factory=list, init=False)
    usage_attempts: list[dict[str, Any]] = field(default_factory=list, init=False)
    observations: list[dict[str, Any]] = field(default_factory=list, init=False)
    evidence_ledger: list[dict[str, Any]] = field(default_factory=list, init=False)
    outcome: str = field(default="not_run", init=False)
    failure_kind: str = field(default="", init=False)
    error: str = field(default="", init=False)
    verification: dict[str, Any] | None = field(default=None, init=False)
    claim_calls: int = field(default=0, init=False)
    verdict_calls: int = field(default=0, init=False)
    protocol_repairs: int = field(default=0, init=False)
    protocol_errors: int = field(default=0, init=False)
    wall_seconds: float = field(default=0.0, init=False)
    scratch_dir: str = field(default="", init=False)
    payload: dict[str, Any] = field(default_factory=dict, init=False)
    input_digest: str = field(default="", init=False)
    _claim_attempts: dict[str, dict[str, Any]] = field(default_factory=dict, init=False)
    _script_counter: int = field(default=0, init=False)
    _observation_counter: int = field(default=0, init=False)
    _evidence_counter: int = field(default=0, init=False)
    _finished: bool = field(default=False, init=False)
    _scratch_owner: Any = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.payload = build_verify_agent_payload(
            metadata=self.metadata,
            candidate=self.candidate,
            cited_evidence=self.cited_evidence,
            verdict_calls=self.config.verdict_calls,
        )
        self.input_digest = _sha256_json(self.payload)
        self.transcript.append({
            "stage": "verification_input",
            "payload": copy.deepcopy(self.payload),
            "input_digest": self.input_digest,
        })
        if self.scratch_root:
            root = Path(self.scratch_root).expanduser()
            root.mkdir(parents=True, exist_ok=True)
            self.scratch_dir = tempfile.mkdtemp(prefix="verify-agent-", dir=str(root))
        else:
            self._scratch_owner = tempfile.TemporaryDirectory(
                prefix="claudeagent-verify-"
            )
            self.scratch_dir = self._scratch_owner.name

    def close(self) -> None:
        """Remove an internally owned temporary scratch directory."""
        if self._scratch_owner is not None:
            self._scratch_owner.cleanup()
            self._scratch_owner = None

    def __enter__(self) -> VerifyAgentSession:
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        self.close()

    @property
    def config_digest(self) -> str:
        return verify_agent_config_digest(self.config)

    @property
    def cited_ids(self) -> list[str]:
        return list(self.payload["candidate"]["evidence_ids"])

    def _available_tools(self) -> list[dict[str, Any]]:
        claims_complete = len(self._claim_attempts) == len(self.cited_ids)
        tools: list[dict[str, Any]] = []
        if not claims_complete or self.verdict_calls < self.config.verdict_calls:
            tools.append(_tool_copy(RUN_PYTHON_TOOL, strict=self.config.strict))
        if claims_complete:
            tools.append(
                _tool_copy(SUBMIT_VERIFICATION_RESULT_TOOL, strict=self.config.strict)
            )
        return tools

    def _sample_turn(
        self,
        input_items: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        last_error: Exception | None = None
        for attempt in range(1, self.config.api_turn_retries + 1):
            try:
                return self.client(
                    instructions=_prompt_text(),
                    input_items=input_items,
                    tools=tools,
                    api_key=self.config.api_key,
                    base_url=self.config.base_url,
                    model=self.config.model,
                    timeout=self.config.api_timeout,
                    max_retries=self.config.api_max_retries,
                    tool_choice="required",
                    store=False,
                    reasoning=copy.deepcopy(self.config.reasoning),
                )
            except Exception as exc:
                last_error = exc
                if attempt < self.config.api_turn_retries:
                    time.sleep(min(20.0 * attempt, 60.0))
        assert last_error is not None
        raise last_error

    def _next_local_id(self, prefix: str) -> str:
        if prefix == "vobs":
            self._observation_counter += 1
            value = self._observation_counter
        elif prefix == "vev":
            self._evidence_counter += 1
            value = self._evidence_counter
        else:
            raise ValueError(f"unsupported verifier id prefix {prefix!r}")
        return f"{prefix}_{value:04d}"

    def _run_python(self, arguments: dict[str, Any]) -> dict[str, Any]:
        phase = str(arguments["phase"])
        target_evidence_id = str(arguments["evidence_id"])
        script = str(arguments["script"])
        timeout = int(arguments["timeout_sec"]) or DEFAULT_TOOL_TIMEOUT
        output_budget = int(arguments["max_output_chars"]) or DEFAULT_TOOL_OUTPUT_CHARS

        self._script_counter += 1
        script_path = Path(self.scratch_dir) / f"verify_script_{self._script_counter:04d}.py"
        try:
            script_path.write_text(script, encoding="utf-8")
            proc = self.sandbox_runner(
                script_path=str(script_path),
                scratch_dir=self.scratch_dir,
                binary_path=self.binary_path,
                timeout=timeout,
                max_output_chars=None,
            )
            if not isinstance(proc, dict):
                raise TypeError("sandbox runner returned a non-object result")
        except Exception as exc:
            proc = {
                "ok": False,
                "returncode": None,
                "elapsed_sec": 0.0,
                "stdout": "",
                "stderr": "",
                "error": repr(exc),
            }

        stdout_parts = text_head_tail(str(proc.get("stdout", "")), output_budget)
        stderr_parts = text_head_tail(
            str(proc.get("stderr", "")),
            min(12_000, max(2_000, output_budget // 5)),
        )
        observation_id = self._next_local_id("vobs")
        evidence_id = self._next_local_id("vev")
        observation = {
            "observation_id": observation_id,
            "tool": "run_python",
            "phase": phase,
            "target_evidence_id": target_evidence_id,
            "command": ["python3", "-S", f"/scratch/{script_path.name}"],
            "exit_code": proc.get("returncode"),
            "ok": bool(proc.get("ok")),
            "elapsed_sec": proc.get("elapsed_sec"),
            "stdout_head": stdout_parts["head"],
            "stdout_tail": stdout_parts["tail"],
            "stderr_tail": stderr_parts["tail"] or stderr_parts["head"],
            "truncated": bool(stdout_parts["truncated"] or stderr_parts["truncated"]),
            "truncation": {
                "stdout_omitted_chars": stdout_parts["omitted_chars"],
                "stderr_omitted_chars": stderr_parts["omitted_chars"],
                "stdout_original_chars": stdout_parts["original_chars"],
                "stderr_original_chars": stderr_parts["original_chars"],
            },
            "script_sha256": hashlib.sha256(script.encode("utf-8")).hexdigest(),
            "error": str(proc.get("error", "")),
        }
        lines = [
            line.strip()
            for text in (
                observation["stdout_head"],
                observation["stdout_tail"],
                observation["stderr_tail"],
                observation["error"],
            )
            for line in str(text).splitlines()
            if line.strip()
        ]
        if len(lines) > 16:
            lines = [*lines[:8], *lines[-8:]]
        evidence = {
            "evidence_id": evidence_id,
            "observation_id": observation_id,
            "phase": phase,
            "target_evidence_id": target_evidence_id,
            "ok": observation["ok"],
            "excerpt": lines,
        }
        self.observations.append(observation)
        self.evidence_ledger.append(evidence)
        if phase == "claim":
            self.claim_calls += 1
            self._claim_attempts[target_evidence_id] = {
                "observation_id": observation_id,
                "evidence_id": evidence_id,
                "ok": observation["ok"],
            }
        else:
            self.verdict_calls += 1
        return {
            "ok": observation["ok"],
            "tool": "run_python",
            "phase": phase,
            "target_evidence_id": target_evidence_id,
            "observation_id": observation_id,
            "exit_code": observation["exit_code"],
            "stdout_head": observation["stdout_head"],
            "stdout_tail": observation["stdout_tail"],
            "stderr_tail": observation["stderr_tail"],
            "truncated": observation["truncated"],
            "truncation": observation["truncation"],
            "verifier_evidence": [copy.deepcopy(evidence)],
            "error": observation["error"],
        }

    def _run_arguments_error(self, arguments: Any) -> str:
        errors = validate_json_schema(arguments, RUN_PYTHON_TOOL["parameters"])
        if errors:
            return "; ".join(errors)
        if not isinstance(arguments, dict):
            return "run_python arguments must be an object"
        phase = str(arguments.get("phase", ""))
        evidence_id = str(arguments.get("evidence_id", ""))
        claims_complete = len(self._claim_attempts) == len(self.cited_ids)
        if phase == "claim":
            if evidence_id not in self.cited_ids:
                return f"claim phase requires one cited evidence ID; got {evidence_id!r}"
            if evidence_id in self._claim_attempts:
                return f"claim phase already attempted evidence ID {evidence_id!r}"
            if claims_complete:
                return "claim phase is complete; use verdict phase or submit"
        elif phase == "verdict":
            if not claims_complete:
                pending = [item for item in self.cited_ids if item not in self._claim_attempts]
                return f"verdict phase is unavailable until claim checks complete: {pending}"
            if evidence_id:
                return "verdict phase requires an empty evidence_id"
            if self.verdict_calls >= self.config.verdict_calls:
                return "verdict-phase run_python budget is exhausted; submit now"
        return ""

    def _verification_errors(self, verification: Any) -> list[str]:
        errors = validate_json_schema(
            verification,
            SUBMIT_VERIFICATION_RESULT_TOOL["parameters"],
        )
        if not isinstance(verification, dict):
            return errors or ["submit_verification_result arguments must be an object"]
        checks = [
            item for item in verification.get("claim_checks", []) if isinstance(item, dict)
        ]
        check_ids = [str(item.get("evidence_id", "")) for item in checks]
        if len(check_ids) != len(set(check_ids)):
            errors.append("$.claim_checks: duplicate evidence_id values are not allowed")
        if set(check_ids) != set(self.cited_ids) or len(check_ids) != len(self.cited_ids):
            errors.append(
                "$.claim_checks: must contain exactly one check for every cited evidence ID"
            )
        verifier_by_id = {
            str(item["evidence_id"]): item
            for item in self.evidence_ledger
            if isinstance(item, dict) and item.get("evidence_id")
        }
        known_verifier_ids = set(verifier_by_id)
        check_by_id = {
            str(item.get("evidence_id", "")): item
            for item in checks
            if item.get("evidence_id")
        }
        for evidence_id in self.cited_ids:
            check = check_by_id.get(evidence_id)
            if check is None:
                continue
            verifier_ids = [str(item) for item in check.get("verifier_evidence_ids", [])]
            if len(verifier_ids) != len(set(verifier_ids)):
                errors.append(
                    f"$.claim_checks[{evidence_id}].verifier_evidence_ids: duplicates are not allowed"
                )
            unknown = sorted(set(verifier_ids) - known_verifier_ids)
            if unknown:
                errors.append(
                    f"$.claim_checks[{evidence_id}].verifier_evidence_ids: unknown IDs {unknown}"
                )
            attempt = self._claim_attempts.get(evidence_id)
            if attempt and str(attempt["evidence_id"]) not in verifier_ids:
                errors.append(
                    f"$.claim_checks[{evidence_id}].verifier_evidence_ids: must cite its dedicated "
                    f"claim inspection {attempt['evidence_id']}"
                )
            if attempt and not attempt["ok"] and check.get("relation") != "insufficient":
                errors.append(
                    f"$.claim_checks[{evidence_id}].relation: failed inspection requires insufficient"
                )
            if check.get("relation") in {"supported", "contradicted"}:
                failed_ids = [
                    verifier_id
                    for verifier_id in verifier_ids
                    if verifier_id in verifier_by_id
                    and verifier_by_id[verifier_id].get("ok") is not True
                ]
                if failed_ids:
                    errors.append(
                        f"$.claim_checks[{evidence_id}].verifier_evidence_ids: "
                        f"supported/contradicted checks require successful observations; failed {failed_ids}"
                    )
                empty_ids = [
                    verifier_id
                    for verifier_id in verifier_ids
                    if verifier_id in verifier_by_id
                    and not any(
                        isinstance(line, str) and line.strip()
                        for line in verifier_by_id[verifier_id].get("excerpt", [])
                    )
                ]
                if empty_ids:
                    errors.append(
                        f"$.claim_checks[{evidence_id}].verifier_evidence_ids: "
                        "supported/contradicted checks require non-empty returned excerpts; "
                        f"empty {empty_ids}"
                    )

        verdict_ids = [str(item) for item in verification.get("verdict_evidence_ids", [])]
        if len(verdict_ids) != len(set(verdict_ids)):
            errors.append("$.verdict_evidence_ids: duplicates are not allowed")
        unknown_verdict_ids = sorted(set(verdict_ids) - known_verifier_ids)
        if unknown_verdict_ids:
            errors.append(f"$.verdict_evidence_ids: unknown IDs {unknown_verdict_ids}")
        failed_verdict_ids = [
            verifier_id
            for verifier_id in verdict_ids
            if verifier_id in verifier_by_id
            and verifier_by_id[verifier_id].get("ok") is not True
        ]
        if failed_verdict_ids:
            errors.append(
                "$.verdict_evidence_ids: verdict support requires successful observations; "
                f"failed {failed_verdict_ids}"
            )
        empty_verdict_ids = [
            verifier_id
            for verifier_id in verdict_ids
            if verifier_id in verifier_by_id
            and not any(
                isinstance(line, str) and line.strip()
                for line in verifier_by_id[verifier_id].get("excerpt", [])
            )
        ]
        if empty_verdict_ids:
            errors.append(
                "$.verdict_evidence_ids: verdict support requires non-empty returned excerpts; "
                f"empty {empty_verdict_ids}"
            )

        action = str(verification.get("action", ""))
        candidate_status = str(self.payload["candidate"]["status"])
        recommended = str(verification.get("recommended_status", ""))
        decisive_checks = [item for item in checks if item.get("decisive") is True]
        contradicted_checks = [
            item for item in checks if item.get("relation") == "contradicted"
        ]
        if action == "confirmed":
            if recommended != candidate_status:
                errors.append("$.recommended_status: confirmed must preserve the submitted status")
            if verification.get("coverage_status") != "complete":
                errors.append("$.coverage_status: confirmed requires complete coverage")
            if not decisive_checks:
                errors.append("$.claim_checks: confirmed requires at least one decisive claim")
            if any(item.get("relation") != "supported" for item in decisive_checks):
                errors.append("$.claim_checks: every decisive claim must be supported to confirm")
            if any(item.get("relation") == "contradicted" for item in checks):
                errors.append("$.claim_checks: confirmed cannot contain a contradicted claim")
        elif action == "contradicted":
            if recommended == candidate_status:
                errors.append(
                    "$.recommended_status: contradicted must recommend a different status or inconclusive"
                )
            has_opposite_evidence = any(
                verifier_by_id.get(verifier_id, {}).get("phase") == "verdict"
                for verifier_id in verdict_ids
            )
            if not contradicted_checks and not has_opposite_evidence:
                errors.append(
                    "$.action: contradicted requires a contradicted cited claim or independent "
                    "verdict-phase evidence"
                )
        elif action == "unresolved":
            if recommended not in {candidate_status, "inconclusive"}:
                errors.append(
                    "$.recommended_status: unresolved may retain the submitted status or recommend "
                    "inconclusive"
                )
            if contradicted_checks:
                errors.append(
                    "$.action: any contradicted cited claim requires action=contradicted"
                )
        return errors

    def _protocol_repair(
        self,
        *,
        message: str,
        input_items: list[dict[str, Any]],
        call: dict[str, Any] | None = None,
    ) -> bool:
        self.protocol_errors += 1
        self.transcript.append({
            "stage": "protocol_error",
            "error": message,
            "repair_number": self.protocol_repairs + 1,
        })
        if self.protocol_repairs >= self.config.max_protocol_repairs:
            return False
        self.protocol_repairs += 1
        repair = {
            "ok": False,
            "tool": str(call.get("name", "")) if isinstance(call, dict) else "verify_agent",
            "error": message,
            "protocol_repair": self.protocol_repairs,
            "protocol_repairs_remaining": (
                self.config.max_protocol_repairs - self.protocol_repairs
            ),
            "pending_claim_evidence_ids": [
                item for item in self.cited_ids if item not in self._claim_attempts
            ],
            "verdict_calls_remaining": max(
                0, self.config.verdict_calls - self.verdict_calls
            ),
        }
        call_id = ""
        if isinstance(call, dict):
            call_id = str(call.get("call_id") or call.get("id") or "")
        if isinstance(call, dict) and call_id:
            input_items.append(copy.deepcopy(call))
            input_items.append({
                "type": "function_call_output",
                "call_id": call_id,
                "output": compact_json(repair),
            })
        else:
            input_items.append({
                "type": "message",
                "role": "user",
                "content": compact_json(repair),
            })
        return True

    def _fallback_verification(self, reason: str) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        for evidence_id in self.cited_ids:
            attempt = self._claim_attempts.get(evidence_id)
            verifier_ids = [str(attempt["evidence_id"])] if attempt else []
            checks.append({
                "evidence_id": evidence_id,
                "relation": "insufficient",
                "decisive": False,
                "verifier_evidence_ids": verifier_ids,
                "reason": "The independent verification did not complete this claim assessment.",
            })
        return {
            "action": "unresolved",
            "claim_checks": checks,
            "coverage_status": "uncertain",
            "coverage_reason": "Independent verification did not complete the required checks.",
            "recommended_status": str(self.payload["candidate"]["status"]),
            "verdict_evidence_ids": [],
            "reason": reason[:2400] or "Independent verification was unresolved.",
        }

    def _finish(
        self,
        *,
        verification: dict[str, Any] | None,
        outcome: str,
        start_epoch: float,
        failure_kind: str = "",
        error: str = "",
    ) -> dict[str, Any]:
        self.verification = copy.deepcopy(verification)
        self.outcome = outcome
        self.failure_kind = failure_kind
        self.error = error
        self.wall_seconds = round(time.time() - start_epoch, 3)
        self._finished = True
        return self.report()

    def run(self) -> dict[str, Any]:
        """Execute the bounded verification loop and return a compact session report."""
        if self._finished:
            return self.report()
        start_epoch = time.time()
        if self.payload["candidate"]["status"] == "inconclusive":
            return self._finish(
                verification=None,
                outcome="skipped_inconclusive",
                start_epoch=start_epoch,
            )

        input_items: list[dict[str, Any]] = [{
            "type": "message",
            "role": "user",
            "content": compact_json(self.payload),
        }]
        max_responses = (
            len(self.cited_ids)
            + self.config.verdict_calls
            + self.config.max_protocol_repairs
            + 3
        )
        for turn in range(1, max_responses + 1):
            tools = self._available_tools()
            try:
                response = self._sample_turn(input_items, tools)
            except Exception as exc:
                error = repr(exc)
                fallback = self._fallback_verification(
                    f"Verify Agent model request failed: {error}"
                )
                self.transcript.append({"turn": turn, "stage": "api_failure", "error": error})
                return self._finish(
                    verification=fallback,
                    outcome="unresolved",
                    start_epoch=start_epoch,
                    failure_kind="api_failure",
                    error=error,
                )

            usage = response.get("usage")
            if isinstance(usage, dict):
                self.usage_attempts.append(copy.deepcopy(usage))
            output = response.get("output")
            output_items = output if isinstance(output, list) else []
            self.transcript.append({
                "turn": turn,
                "stage": "model_response",
                "output": copy.deepcopy(output_items),
                "usage": copy.deepcopy(usage) if isinstance(usage, dict) else {},
            })
            calls = [
                item
                for item in output_items
                if isinstance(item, dict) and item.get("type") == "function_call"
            ]
            if len(calls) != 1:
                message = "each Verify Agent response must contain exactly one tool call"
                if self._protocol_repair(message=message, input_items=input_items):
                    continue
                fallback = self._fallback_verification(message)
                return self._finish(
                    verification=fallback,
                    outcome="unresolved",
                    start_epoch=start_epoch,
                    failure_kind="protocol_failure",
                    error=message,
                )

            call = calls[0]
            name = str(call.get("name", ""))
            raw_arguments = call.get("arguments", "{}")
            try:
                arguments = (
                    json.loads(raw_arguments)
                    if isinstance(raw_arguments, str)
                    else raw_arguments
                )
            except json.JSONDecodeError as exc:
                arguments = None
                message = f"{name} arguments are invalid JSON: {exc}"
                if self._protocol_repair(
                    message=message,
                    input_items=input_items,
                    call=call,
                ):
                    continue
                fallback = self._fallback_verification(message)
                return self._finish(
                    verification=fallback,
                    outcome="unresolved",
                    start_epoch=start_epoch,
                    failure_kind="protocol_failure",
                    error=message,
                )

            if name == "run_python":
                message = self._run_arguments_error(arguments)
                if message:
                    if self._protocol_repair(
                        message=message,
                        input_items=input_items,
                        call=call,
                    ):
                        continue
                    fallback = self._fallback_verification(message)
                    return self._finish(
                        verification=fallback,
                        outcome="unresolved",
                        start_epoch=start_epoch,
                        failure_kind="protocol_failure",
                        error=message,
                    )
                assert isinstance(arguments, dict)
                call_id = str(call.get("call_id") or call.get("id") or "")
                if not call_id:
                    message = "run_python tool call is missing call_id"
                    if self._protocol_repair(message=message, input_items=input_items):
                        continue
                    fallback = self._fallback_verification(message)
                    return self._finish(
                        verification=fallback,
                        outcome="unresolved",
                        start_epoch=start_epoch,
                        failure_kind="protocol_failure",
                        error=message,
                    )
                result = self._run_python(arguments)
                self.transcript.append({
                    "turn": turn,
                    "stage": "tool_result",
                    "tool": name,
                    "arguments": copy.deepcopy(arguments),
                    "result": copy.deepcopy(result),
                })
                input_items.append(copy.deepcopy(call))
                input_items.append({
                    "type": "function_call_output",
                    "call_id": call_id,
                    "output": compact_json(result),
                })
                continue

            if name == "submit_verification_result":
                if len(self._claim_attempts) != len(self.cited_ids):
                    pending = [
                        item for item in self.cited_ids if item not in self._claim_attempts
                    ]
                    message = f"submit is unavailable until claim checks complete: {pending}"
                    if self._protocol_repair(
                        message=message,
                        input_items=input_items,
                        call=call,
                    ):
                        continue
                    fallback = self._fallback_verification(message)
                    return self._finish(
                        verification=fallback,
                        outcome="unresolved",
                        start_epoch=start_epoch,
                        failure_kind="protocol_failure",
                        error=message,
                    )
                errors = self._verification_errors(arguments)
                if errors:
                    message = "; ".join(errors)
                    if self._protocol_repair(
                        message=message,
                        input_items=input_items,
                        call=call,
                    ):
                        continue
                    fallback = self._fallback_verification(message)
                    return self._finish(
                        verification=fallback,
                        outcome="unresolved",
                        start_epoch=start_epoch,
                        failure_kind="protocol_failure",
                        error=message,
                    )
                assert isinstance(arguments, dict)
                self.transcript.append({
                    "turn": turn,
                    "stage": "verification_result",
                    "tool": name,
                    "arguments": copy.deepcopy(arguments),
                })
                return self._finish(
                    verification=arguments,
                    outcome=str(arguments["action"]),
                    start_epoch=start_epoch,
                )

            message = f"tool {name!r} is not available to Verify Agent"
            if self._protocol_repair(
                message=message,
                input_items=input_items,
                call=call,
            ):
                continue
            fallback = self._fallback_verification(message)
            return self._finish(
                verification=fallback,
                outcome="unresolved",
                start_epoch=start_epoch,
                failure_kind="protocol_failure",
                error=message,
            )

        message = "Verify Agent exhausted its bounded response budget without a valid submission"
        fallback = self._fallback_verification(message)
        return self._finish(
            verification=fallback,
            outcome="unresolved",
            start_epoch=start_epoch,
            failure_kind="protocol_failure",
            error=message,
        )

    def report(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "verification": copy.deepcopy(self.verification),
            "claim_calls": self.claim_calls,
            "verdict_calls": self.verdict_calls,
            "protocol_repairs": self.protocol_repairs,
            "failure_kind": self.failure_kind,
            "error": self.error,
        }

    def audit(self) -> dict[str, Any]:
        """Return the verifier's compact protocol and local-evidence audit."""
        return {
            "protocol_version": VERIFY_AGENT_PROTOCOL_VERSION,
            "prompt_version": VERIFY_AGENT_PROMPT_VERSION,
            "model": self.config.model,
            "reasoning": copy.deepcopy(self.config.reasoning),
            "config_digest": self.config_digest,
            "input_digest": self.input_digest,
            "outcome": self.outcome,
            "failure_kind": self.failure_kind,
            "error": self.error,
            "claim_budget": len(self.cited_ids),
            "claim_calls": self.claim_calls,
            "verdict_budget": self.config.verdict_calls,
            "verdict_calls": self.verdict_calls,
            "protocol_repair_budget": self.config.max_protocol_repairs,
            "protocol_repairs": self.protocol_repairs,
            "protocol_errors": self.protocol_errors,
            "wall_seconds": self.wall_seconds,
            "verification": copy.deepcopy(self.verification),
            "observations": copy.deepcopy(self.observations),
            "evidence_ledger": copy.deepcopy(self.evidence_ledger),
        }

    def usage_summary(self) -> dict[str, Any]:
        return {
            "provider": "openai-responses",
            "model": self.config.model,
            "model_turns": len(self.usage_attempts),
            "totals": _merge_usage(self.usage_attempts),
            "by_turn": [
                {"turn": index, "usage": copy.deepcopy(usage)}
                for index, usage in enumerate(self.usage_attempts, 1)
            ],
            "timing": {"wall_seconds": self.wall_seconds},
        }
