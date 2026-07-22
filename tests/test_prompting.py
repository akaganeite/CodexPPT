"""Tests for PatchSpec prompt isolation and single-case resolution.

    python3 -m claudeagent.tests.test_prompting
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import tempfile
from pathlib import Path

from claudeagent import agent_loop
from claudeagent.patchspec import (
    PatchSpecModelConfig,
    build_deterministic_skeleton,
    prompt_view,
    resolve_source_excerpts,
    write_patch_spec,
)
from claudeagent.prompting import build_task
from claudeagent.runtime import initialize_agent_context


def _metadata() -> dict:
    return {
        "cve_id": "CVE-2013-1944",
        "project": "curl",
        "functions": ["tailmatch"],
        "root_cause_analysis": {
            "unsafe_mechanism": "A suffix match can ignore the DNS label boundary."
        },
        "patch_intent_analysis": {
            "intended_security_property": "A matching suffix must begin at a label boundary."
        },
        "patch_hunk": [
            {
                "header": "tailmatch boundary check",
                "old_lines": [
                    "return Curl_raw_equal(little, bigone + biglen - littlelen);",
                ],
                "new_lines": [
                    "if (hostname_len == cookie_domain_len) return TRUE;",
                    "return hostname[hostname_len - cookie_domain_len - 1] == '.';",
                ],
            }
        ],
        "commit_message": "RAW_COMMIT_MESSAGE_MUST_NOT_REACH_INVESTIGATOR",
        "reduced_function_code": "RAW_REDUCED_CODE_MUST_NOT_REACH_INVESTIGATOR",
    }


def _config() -> PatchSpecModelConfig:
    return PatchSpecModelConfig(
        api_key="",
        base_url="https://unused.invalid/v1",
        model="gpt-5.5",
        reasoning_effort="medium",
        reasoning={"effort": "medium"},
    )


def _run() -> int:
    failures: list[str] = []

    def check(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    metadata = _metadata()
    spec = build_deterministic_skeleton(
        metadata,
        model="GENERATION_MODEL_MUST_NOT_REACH_INVESTIGATOR",
        reasoning_effort="medium",
        reasoning={"effort": "medium"},
    )
    safe_spec = prompt_view(spec)
    excerpts = resolve_source_excerpts(metadata, spec)
    initialize_agent_context(metadata, "/anonymous/target_binary", scratch_dir="/scratch")
    rendered = build_task(
        safe_spec,
        excerpts,
        "/anonymous/target_binary",
        {
            "binary": {"path": "/anonymous/target_binary", "file": "ELF 64-bit"},
            "symbol_hint": {"has_useful_symbols": False},
        },
    )
    payload = json.loads(rendered)

    check("prompt has PatchSpec", payload.get("patch_spec") == safe_spec)
    check(
        "prompt has behavior support contract",
        payload.get("behavior_support_contract") == [{"behavior_id": "B001", "required": True}],
    )
    check("prompt has leaf excerpts", payload.get("patch_spec_source_excerpts") == excerpts)
    check("prompt uses sandbox binary path", payload.get("target_binary") == "/workspace/binary")
    check("prompt hides host binary path", "/anonymous/target_binary" not in rendered)
    check("prompt omits full metadata key", "cve_metadata" not in payload)
    check("prompt omits generation block", "generation" not in payload.get("patch_spec", {}))
    prompt_indicators = payload["patch_spec"]["behaviors"][0]["trusted"]
    check(
        "prompt source text is not duplicated in indicators",
        all(
            "value" not in indicator
            for side in ("old_indicators", "new_indicators")
            for indicator in prompt_indicators[side]
        ),
    )
    check("prompt omits raw commit message", metadata["commit_message"] not in rendered)
    check("prompt omits raw reduced code", metadata["reduced_function_code"] not in rendered)
    check("prompt omits generation model", "GENERATION_MODEL_MUST_NOT_REACH_INVESTIGATOR" not in rendered)
    check("prompt retains referenced old line", metadata["patch_hunk"][0]["old_lines"][0] in rendered)
    check("prompt retains referenced new line", metadata["patch_hunk"][0]["new_lines"][1] in rendered)
    check(
        "source excerpts are leaf refs",
        all(item.get("ref") != "/patch_hunk/0" for item in excerpts),
    )
    check(
        "PatchSpec is explicitly non-evidence",
        payload.get("constraints", {}).get("patch_spec_is_not_evidence") is True,
    )
    submit_schema = payload.get("submit_detection_result_schema", {})
    check("submit schema requires supports", "supports" in submit_schema.get("required", []))
    check("submit schema requires claim", "claim" in submit_schema.get("required", []))
    check("submit schema omits legacy evidence", "evidence_ids" not in submit_schema.get("properties", {}))

    with tempfile.TemporaryDirectory() as tmp:
        args = argparse.Namespace(
            patchspec_json="",
            output_dir=tmp,
            cve_id=metadata["cve_id"],
        )
        dry_result, dry_resolution = agent_loop._resolve_case_patch_spec(
            args,
            metadata,
            model_config=_config(),
            dry_run=True,
        )
        check("dry-run returns skeleton", dry_resolution == "deterministic_skeleton")
        check("dry-run has no generation usage", dry_result.usage == {})
        check("dry-run does not write PatchSpec", not (Path(tmp) / "patch_spec.json").exists())

    with tempfile.TemporaryDirectory() as tmp:
        spec_path = Path(tmp) / "provided.json"
        write_patch_spec(spec_path, spec)
        args = argparse.Namespace(
            patchspec_json=str(spec_path),
            output_dir=tmp,
            cve_id=metadata["cve_id"],
        )
        loaded, resolution = agent_loop._resolve_case_patch_spec(
            args,
            metadata,
            model_config=_config(),
            dry_run=False,
        )
        info = agent_loop._patch_spec_runtime_info(loaded, resolution)
        check("explicit PatchSpec resolution is provided", resolution == "provided")
        check("provided PatchSpec has no run-local usage", info.get("usage") == {})
        check(
            "generation mode survives strict load",
            info.get("generation_mode") == spec["generation"]["mode"],
        )

        mismatched = copy.deepcopy(metadata)
        mismatched["commit_message"] = "metadata hash changed"
        try:
            agent_loop._resolve_case_patch_spec(
                args,
                mismatched,
                model_config=_config(),
                dry_run=False,
            )
        except SystemExit as exc:
            check("metadata mismatch reports PatchSpec validation", "PatchSpec" in str(exc))
        else:
            check("metadata mismatch is rejected", False)

    if failures:
        print("PROMPTING TESTS FAILED:")
        for failure in failures:
            print("  -", failure)
        return 1
    print("PROMPTING TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
