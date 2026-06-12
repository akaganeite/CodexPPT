"""Single-case model/tool loop.

Distilled from the codex agent loop: build a prompt (system + task), sample the
model, dispatch each tool call to a handler, feed the bounded result back as a
tool message, and repeat until the model calls submit_detection_result with a
schema-valid, evidence-cited verdict. Tool and schema failures repair in-band;
only model-API failures (after retries) abort.

Run:
    python3 -m claudeagent.agent_loop --cve-id CVE-2013-0249 \
        --metadata-json <behavior.json> --binary <stripped-binary> \
        --output-dir <dir> [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from typing import Any

from claudeagent.common import (
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    FINAL_RESULT_SCHEMA,
    SYSTEM_PROMPT,
    compact_json,
    expand,
    jdump,
)
from claudeagent.finalize import (
    build_final_artifact,
    compact_known_evidence_ids,
    compact_rejected_preview,
    max_turns_fallback_result,
    preflight_missing_result,
    write_run_outputs,
)
from claudeagent.host import (
    import_env_from_interactive_shell,
    load_cve_metadata,
    load_env_files,
    preflight_detection_inputs,
)
from claudeagent.model_client import deepseek_chat
from claudeagent.observations import compact_tool_result_for_model
from claudeagent.prompting import append_finalization_budget_prompt, append_finalization_prompt, build_task
from claudeagent.runtime import bump_metric, initialize_agent_context
from claudeagent.schema_validate import DETERMINATE_STATUSES, load_final_result_schema
from claudeagent.tools_registry import TOOL_FUNCS, load_tools, submit_tool_only


def handle_tool_calls(
    *,
    msg: dict[str, Any],
    messages: list[dict[str, Any]],
    transcript: list[dict[str, Any]],
    turn_label: int | str,
    allowed_tools: dict[str, Any],
    output_dir: str,
    start_epoch: float,
) -> tuple[bool, dict[str, Any] | None]:
    tool_calls = msg.get("tool_calls") or []
    if not tool_calls:
        messages.append({
            "role": "user",
            "content": "You must call submit_detection_result. Plain text is not a valid final answer.",
        })
        return False, None

    messages.append({
        key: value
        for key, value in msg.items()
        if key in ("role", "content", "reasoning_content", "tool_calls") and value is not None
    })
    for call_index, call in enumerate(tool_calls, 1):
        bump_metric("tool_calls")
        fn = call.get("function", {}).get("name")
        raw_args = call.get("function", {}).get("arguments") or "{}"
        try:
            call_args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            if not isinstance(call_args, dict):
                raise ValueError("tool arguments must be a JSON object")
            if fn not in allowed_tools:
                result = {"ok": False, "error": f"tool not available in this phase: {fn}"}
                bump_metric("tool_failures")
            else:
                result = allowed_tools[fn](**call_args)
        except Exception as exc:
            result = {"ok": False, "error": repr(exc), "tool": fn, "arguments": raw_args}
            bump_metric("tool_failures")
            if fn == "submit_detection_result":
                bump_metric("schema_repair_attempts")

        transcript.append({
            "turn": turn_label,
            "tool": fn,
            "call_index": call_index,
            "arguments": raw_args,
            "result": result,
        })

        if fn == "submit_detection_result" and result.get("ok"):
            preview, schema_errors = build_final_artifact(result, transcript, start_epoch)
            if schema_errors:
                bump_metric("schema_repair_attempts")
                if result.get("status") in DETERMINATE_STATUSES and not result.get("evidence_ids"):
                    bump_metric("no_evidence_verdicts")
                repair_result = {
                    "ok": False,
                    "error": "final_result.json failed schema validation before write; repair and call submit_detection_result again",
                    "schema_errors": schema_errors,
                    "known_evidence_ids": compact_known_evidence_ids(),
                    "rejected_preview": compact_rejected_preview(preview),
                }
                transcript[-1]["result"] = repair_result
                messages.append({"role": "tool", "tool_call_id": call.get("id"), "content": compact_json(repair_result)})
                continue
            return True, write_run_outputs(output_dir, result, transcript, start_epoch)

        messages.append({
            "role": "tool",
            "tool_call_id": call.get("id"),
            "content": compact_json(compact_tool_result_for_model(result)),
        })
    return False, None


def last_submit_needs_repair(transcript: list[dict[str, Any]]) -> bool:
    if not transcript:
        return False
    last = transcript[-1]
    if last.get("tool") != "submit_detection_result":
        return False
    result = last.get("result")
    if not isinstance(result, dict) or result.get("ok"):
        return False
    if result.get("schema_errors"):
        return True
    return bool(result.get("error") and result.get("tool") == "submit_detection_result")


def last_tool_call_needs_forced_submit(transcript: list[dict[str, Any]]) -> bool:
    if not transcript:
        return False
    last = transcript[-1]
    if last.get("tool") == "submit_detection_result":
        return last_submit_needs_repair(transcript)
    result = last.get("result")
    if not isinstance(result, dict) or result.get("ok"):
        return False
    return "tool not available in this phase" in str(result.get("error", ""))


def provider_config(args: argparse.Namespace) -> tuple[str, str, str]:
    api_key = os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("OPENAI_API_KEY", "")
    deepseek_base = os.environ.get("DEEPSEEK_BASE_URL", DEFAULT_BASE_URL)
    env_base_url = os.environ.get("OPENAI_BASE_URL") or deepseek_base
    env_model = os.environ.get("DEEPSEEK_MODEL") or os.environ.get("OPENAI_MODEL") or DEFAULT_MODEL
    strict = not args.no_strict
    base_url = args.base_url or (
        env_base_url.rstrip("/") + "/beta"
        if strict and env_base_url.rstrip("/").endswith("api.deepseek.com")
        else env_base_url
    )
    return api_key, base_url, args.model or env_model


def _sample(args: argparse.Namespace, messages, tools, api_key, base_url, model) -> dict[str, Any]:
    return deepseek_chat(
        messages,
        tools,
        api_key=api_key,
        base_url=base_url,
        model=model,
        thinking=args.thinking,
        reasoning_effort=args.reasoning_effort,
        timeout=args.api_timeout,
        max_retries=args.api_max_retries,
    )


def run_agent(args: argparse.Namespace) -> int:
    start_epoch = time.time()
    metadata = load_cve_metadata(args)
    binary = str(expand(args.binary))
    if args.output_dir:
        scratch = str(expand(args.output_dir) / "scratch")
    else:
        scratch = tempfile.mkdtemp(prefix="claudeagent-scratch-")
    os.makedirs(scratch, exist_ok=True)
    initialize_agent_context(metadata, binary, args.cve_id, args.output_dir, scratch)

    preflight = preflight_detection_inputs(binary, metadata)
    if not preflight.get("ok"):
        result = preflight_missing_result(metadata, binary, preflight)
        transcript = [{"stage": "host_preflight", "result": preflight}]
        print(jdump(write_run_outputs(args.output_dir, result, transcript, start_epoch)))
        return 1

    transcript: list[dict[str, Any]] = [{"stage": "host_preflight", "result": preflight}]

    load_env_files(args.env_file)
    if args.import_interactive_env and not (os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("OPENAI_API_KEY")):
        import_env_from_interactive_shell(["DEEPSEEK_API_KEY", "OPENAI_API_KEY"])
    api_key, base_url, model = provider_config(args)
    if not api_key:
        raise SystemExit("DEEPSEEK_API_KEY or OPENAI_API_KEY is not set. Use --dry-run for local validation only.")

    tools = load_tools(strict=not args.no_strict)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT.read_text()},
        {"role": "user", "content": build_task(metadata, binary, preflight)},
    ]

    # Phase 1: bounded exploration.
    for turn in range(1, args.max_turns + 1):
        resp = _sample(args, messages, tools, api_key, base_url, model)
        msg = resp["choices"][0]["message"]
        transcript.append({"turn": turn, "assistant": msg, "usage": resp.get("usage", {})})
        if args.verbose:
            print(f"\n--- model turn {turn} ---", file=sys.stderr)
            print(jdump(msg), file=sys.stderr)
        done, final_result = handle_tool_calls(
            msg=msg, messages=messages, transcript=transcript, turn_label=turn,
            allowed_tools=TOOL_FUNCS, output_dir=args.output_dir, start_epoch=start_epoch,
        )
        if done and final_result is not None:
            print(jdump(final_result))
            return 0

    if args.finalize_on_max_turns:
        # Phase 2: finalize nudge (last turn restricts to submit-only).
        append_finalization_prompt(messages, args.max_turns)
        for finalize_turn in range(1, args.finalization_turns + 1):
            remaining = args.finalization_turns - finalize_turn
            if finalize_turn > 1:
                append_finalization_budget_prompt(messages, remaining + 1)
            turn_tools = submit_tool_only(tools) if remaining == 0 else tools
            allowed = {"submit_detection_result": TOOL_FUNCS["submit_detection_result"]} if remaining == 0 else TOOL_FUNCS
            resp = _sample(args, messages, turn_tools, api_key, base_url, model)
            msg = resp["choices"][0]["message"]
            turn_label = f"finalize-{finalize_turn}"
            transcript.append({"turn": turn_label, "assistant": msg, "usage": resp.get("usage", {})})
            if args.verbose:
                print(f"\n--- model {turn_label} ---", file=sys.stderr)
                print(jdump(msg), file=sys.stderr)
            done, final_result = handle_tool_calls(
                msg=msg, messages=messages, transcript=transcript, turn_label=turn_label,
                allowed_tools=allowed, output_dir=args.output_dir, start_epoch=start_epoch,
            )
            if done and final_result is not None:
                print(jdump(final_result))
                return 0

        # Phase 3: forced repair (submit-only).
        for repair_turn in range(1, 3):
            if not last_tool_call_needs_forced_submit(transcript):
                break
            messages.append({
                "role": "user",
                "content": (
                    "Repair/finalization only: the previous response did not produce an accepted "
                    "submit_detection_result. Do not call inspection tools. Call submit_detection_result "
                    "now using existing evidence_ids from the ledger; if the evidence is not decisive, "
                    "submit inconclusive with a concrete reason."
                ),
            })
            resp = _sample(args, messages, submit_tool_only(tools), api_key, base_url, model)
            msg = resp["choices"][0]["message"]
            turn_label = f"repair-{repair_turn}"
            transcript.append({"turn": turn_label, "assistant": msg, "usage": resp.get("usage", {})})
            if args.verbose:
                print(f"\n--- model {turn_label} ---", file=sys.stderr)
                print(jdump(msg), file=sys.stderr)
            done, final_result = handle_tool_calls(
                msg=msg, messages=messages, transcript=transcript, turn_label=turn_label,
                allowed_tools={"submit_detection_result": TOOL_FUNCS["submit_detection_result"]},
                output_dir=args.output_dir, start_epoch=start_epoch,
            )
            if done and final_result is not None:
                print(jdump(final_result))
                return 0

    result = max_turns_fallback_result(metadata, binary, args.max_turns)
    print(jdump(write_run_outputs(args.output_dir, result, transcript, start_epoch)))
    return 0


def dry_run(args: argparse.Namespace) -> int:
    metadata = load_cve_metadata(args)
    binary = str(expand(args.binary))
    initialize_agent_context(metadata, binary, args.cve_id)
    tools = load_tools(strict=not args.no_strict)
    load_final_result_schema()
    preflight = preflight_detection_inputs(binary, metadata)
    _, base_url, model = provider_config(args)
    print("TOOLS_OK", len(tools), [t["function"]["name"] for t in tools])
    print("FINAL_RESULT_SCHEMA_OK", FINAL_RESULT_SCHEMA)
    print("MODEL", model)
    print("BASE_URL", base_url)
    print("SYSTEM_PROMPT_CHARS", len(SYSTEM_PROMPT.read_text()))
    print("TASK_CHARS", len(build_task(metadata, binary, preflight)))
    print("HOST_PREFLIGHT")
    print(jdump(preflight))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="claudeagent single-case patch-presence detection")
    parser.add_argument("--cve-id", default="")
    parser.add_argument("--cve-json", default="", help="path to a single CVE metadata JSON object")
    parser.add_argument("--cve-inline-json", default="", help="inline CVE metadata JSON object")
    parser.add_argument("--metadata-json", default="", help="path to a {cve_id: metadata} or [metadata] JSON; needs --cve-id")
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--model", default="")
    parser.add_argument("--base-url", default="")
    parser.add_argument("--env-file", default="")
    parser.add_argument("--import-interactive-env", action="store_true")
    parser.add_argument("--no-strict", action="store_true", help="drop tool 'strict' flags (non-strict tool schemas)")
    parser.add_argument("--thinking", action="store_true", help="enable DeepSeek thinking mode")
    parser.add_argument("--reasoning-effort", default="medium")
    parser.add_argument("--max-turns", type=int, default=20)
    parser.add_argument("--finalize-on-max-turns", action="store_true", default=True)
    parser.add_argument("--no-finalize-on-max-turns", dest="finalize_on_max_turns", action="store_false")
    parser.add_argument("--finalization-turns", type=int, default=3)
    parser.add_argument("--api-timeout", type=int, default=240)
    parser.add_argument("--api-max-retries", type=int, default=3)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.dry_run:
        return dry_run(args)
    return run_agent(args)


if __name__ == "__main__":
    raise SystemExit(main())
