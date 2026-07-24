"""Offline prompt and tool-contract checks.

    python3 -m claudeagent.tests.test_prompting
"""

from __future__ import annotations

import json

from claudeagent.common import SYSTEM_PROMPT
from claudeagent.prompting import build_task
from claudeagent.tools_registry import load_tools


def _run() -> int:
    failures: list[str] = []

    def check(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    metadata = {
        "cve_id": "CVE-2013-1944",
        "project": "curl",
        "functions": ["tailmatch"],
        "commit_message": "Preserve DNS label boundaries.",
    }
    rendered = build_task(
        metadata,
        "/private/work/target",
        {
            "binary": {"path": "/private/work/target", "file": "/private/work/target: ELF 64-bit"},
            "symbol_hint": {"has_useful_symbols": False},
        },
    )
    payload = json.loads(rendered)
    check("complete metadata supplied", payload.get("cve_metadata") == metadata)
    check("binary is anonymized", payload.get("target_binary") == "/workspace/binary" and "/private/work" not in rendered)
    check("metadata is guidance", payload.get("mode_contract", {}).get("metadata_is_guidance_not_evidence") is True)
    check("task stays compact", "\n" not in rendered)

    unsafe = dict(metadata)
    unsafe["expected_verdict"] = "present"
    try:
        build_task(unsafe, "/binary", {"binary": {}, "symbol_hint": {}})
    except ValueError:
        check("answer fields rejected", True)
    else:
        check("answer fields rejected", False)

    tools = load_tools(strict=True)
    submit = next(item for item in tools if item["name"] == "submit_detection_result")
    required = set(submit["parameters"].get("required", []))
    check(
        "direct final tool schema",
        required == {"status", "confidence", "evidence_ids", "reasoning", "decisive_addresses", "inconclusive_reason"},
    )
    prompt = SYSTEM_PROMPT.read_text()
    check("prompt has binary evidence boundary", "/workspace/binary" in prompt and "summarize_evidence" in prompt)

    if failures:
        print("PROMPTING TESTS FAILED:")
        for failure in failures:
            print("  -", failure)
        return 1
    print("PROMPTING TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(_run())
