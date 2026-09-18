"""Single-case model/tool loop over the OpenAI Responses API.

The investigator receives whitelisted, answer-scrubbed CVE metadata, inspects only
an anonymized target binary, and must finalize through an evidence-cited tool.
Tool and schema failures repair in-band; provider failures produce a distinct
non-verdict artifact for batch accounting.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import tempfile
import time
from dataclasses import replace
from typing import Any

from claudeagent.binary_workspace import prepare_anonymous_binary, resolve_debug_companion
from claudeagent.common import FINAL_RESULT_SCHEMA, SYSTEM_PROMPT, compact_json, expand, jdump
from claudeagent.finalize import (
    api_failure_fallback_result,
    build_final_artifact,
    compact_known_evidence_ids,
    compact_rejected_preview,
    max_turns_fallback_result,
    preflight_missing_result,
    write_run_outputs,
)
from claudeagent.host import (
    binary_sha256,
    import_env_from_interactive_shell,
    load_cve_metadata,
    load_env_files,
    preflight_detection_inputs,
)
from claudeagent.metadata_input import metadata_sha256, validate_metadata_prompt_input
from claudeagent.model_config import (
    ModelProfile,
    REASONING_EFFORTS,
    apply_profile_to_args,
    interactive_env_keys,
    reasoning_param,
    resolve_api_key,
    resolve_profile,
)
from claudeagent.observations import compact_tool_result_for_model
from claudeagent.patch_source import (
    SOURCE_TOOL_NAMES,
    SOURCE_TOOL_CALL_LIMIT,
    build_patch_source_context,
    set_patch_source_context,
)
from claudeagent.prompting import (
    append_finalization_budget_prompt,
    append_finalization_prompt,
    build_task,
    metadata_for_agent,
    repair_finalization_prompt,
)
from claudeagent.responses_client import responses_create
from claudeagent.run_python_tool import retain_scratch_scripts
from claudeagent.runtime import (
    begin_model_response,
    bump_metric,
    harness_metrics,
    initialize_agent_context,
    mark_evidence_returned,
)
from claudeagent.sandbox import preflight_sandbox
from claudeagent.schema_validate import DETERMINATE_STATUSES, load_final_result_schema
from claudeagent.tools_registry import (
    FINALIZATION_TOOL_FUNCS,
    enabled_tool_funcs,
    finalization_tools,
    load_tools,
)


MAX_SOURCE_TOOL_CALLS = SOURCE_TOOL_CALL_LIMIT


def _function_call_output(call_id: str, result: dict[str, Any], *, raw: bool = False) -> dict[str, Any]:
    """Build the function output item fed back into the next Responses turn."""
    payload = result if raw else compact_tool_result_for_model(result)
    return {
        "type": "function_call_output",
        "call_id": call_id,
        "output": compact_json(payload) if isinstance(payload, (dict, list)) else str(payload),
    }


def handle_tool_calls(
    *,
    output_items: list[dict[str, Any]],
    input_items: list[dict[str, Any]],
    transcript: list[dict[str, Any]],
    turn_label: int | str,
    allowed_tools: dict[str, Any],
    output_dir: str,
    start_epoch: float,
    record_response_history: bool = False,
) -> tuple[bool, dict[str, Any] | None]:
    """Dispatch one model response and return a written terminal artifact, if any.

    ``record_response_history`` is used by stateless Responses providers that
    require their thinking output to be supplied again with the next request.
    The whole response is recorded before tool outputs so its reasoning and
    function calls retain their original order.  Other providers keep the
    established compact function-call/function-output history.
    """
    begin_model_response()
    if record_response_history:
        input_items.extend(copy.deepcopy(output_items))
    function_calls = [item for item in output_items if item.get("type") == "function_call"]
    if not function_calls:
        input_items.append({
            "type": "message",
            "role": "user",
            "content": (
                "You must use tools. Summarize any evidence you intend to cite, then call "
                "submit_detection_result; plain text is not a valid final answer."
            ),
        })
        return False, None

    for call_index, call in enumerate(function_calls, 1):
        bump_metric("tool_calls")
        fn = call.get("name")
        is_source_tool = fn in SOURCE_TOOL_NAMES
        if is_source_tool:
            bump_metric("source_tool_calls")
        raw_args = call.get("arguments") or "{}"
        summary_metrics_before: tuple[int, int] | None = None
        if fn == "summarize_evidence":
            metrics = harness_metrics()
            summary_metrics_before = (
                metrics["evidence_summary_calls"],
                metrics["evidence_summary_failures"],
            )
        call_id = call.get("call_id") or call.get("id") or ""
        tool_failure_counted = False
        try:
            call_args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            if not isinstance(call_args, dict):
                raise ValueError("tool arguments must be a JSON object")
            if fn not in allowed_tools:
                result = {"ok": False, "error": f"tool not available in this phase: {fn}"}
                bump_metric("tool_failures")
                tool_failure_counted = True
            elif is_source_tool and harness_metrics()["source_tool_calls"] > MAX_SOURCE_TOOL_CALLS:
                result = {
                    "ok": False,
                    "tool": fn,
                    "error": f"patch-source tool budget exceeded ({MAX_SOURCE_TOOL_CALLS} calls)",
                }
                bump_metric("tool_failures")
                tool_failure_counted = True
            else:
                result = allowed_tools[fn](**call_args)
        except Exception as exc:
            error_text = repr(exc)
            result = {"ok": False, "error": error_text, "tool": fn}
            if not is_source_tool:
                result["arguments"] = raw_args
            bump_metric("tool_failures")
            tool_failure_counted = True
            if summary_metrics_before is not None:
                current_metrics = harness_metrics()
                if current_metrics["evidence_summary_calls"] == summary_metrics_before[0]:
                    bump_metric("evidence_summary_calls")
                if current_metrics["evidence_summary_failures"] == summary_metrics_before[1]:
                    bump_metric("evidence_summary_failures")
            if fn == "submit_detection_result":
                bump_metric("schema_repair_attempts")
        if is_source_tool and not result.get("ok"):
            bump_metric("source_tool_failures")
            if not tool_failure_counted:
                bump_metric("tool_failures")

        transcript.append({
            "turn": turn_label,
            "tool": fn,
            "call_index": call_index,
            "arguments": raw_args,
            "result": copy.deepcopy(result),
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
                if not record_response_history:
                    input_items.append(call)
                input_items.append(_function_call_output(call_id, repair_result, raw=True))
                continue
            return True, write_run_outputs(output_dir, result, transcript, start_epoch)

        submit_repair = fn == "submit_detection_result" and not result.get("ok")
        if not record_response_history:
            input_items.append(call)
        input_items.append(_function_call_output(call_id, result, raw=submit_repair))
        if fn == "run_python" and isinstance(result.get("evidence"), list):
            mark_evidence_returned(result["evidence"])
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
    return bool(result.get("schema_errors") or (result.get("error") and result.get("tool") == "submit_detection_result"))


def last_tool_call_needs_forced_submit(transcript: list[dict[str, Any]]) -> bool:
    if not transcript:
        return False
    last = transcript[-1]
    if last.get("tool") == "submit_detection_result":
        return last_submit_needs_repair(transcript)
    if last.get("tool") == "summarize_evidence":
        return True
    result = last.get("result")
    return isinstance(result, dict) and not result.get("ok") and "tool not available" in str(result.get("error", ""))


def provider_config(args: argparse.Namespace) -> tuple[str, str, str, ModelProfile]:
    """Resolve the active model profile and apply its non-secret defaults."""
    profile = resolve_profile(args)
    apply_profile_to_args(args, profile)
    if args.reasoning_effort:
        profile = replace(profile, reasoning_effort=args.reasoning_effort)
    return resolve_api_key(profile), args.base_url, args.model, profile


def _sample(
    args: argparse.Namespace,
    instructions: str,
    input_items: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    api_key: str,
    base_url: str,
    model: str,
    profile: ModelProfile,
) -> dict[str, Any]:
    return responses_create(
        instructions=instructions,
        input_items=input_items,
        tools=tools,
        api_key=api_key,
        base_url=base_url,
        model=model,
        timeout=args.api_timeout,
        max_retries=args.api_max_retries,
        reasoning=reasoning_param(profile),
        max_output_tokens=profile.max_output_tokens,
        api_protocol=profile.api_protocol,
        history_adapter=profile.history_adapter,
    )


def _sample_turn(
    args: argparse.Namespace,
    instructions: str,
    input_items: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    api_key: str,
    base_url: str,
    model: str,
    profile: ModelProfile,
) -> dict[str, Any]:
    """Retry complete turns to span intermittent upstream outage windows."""
    last_exc: Exception | None = None
    for attempt in range(1, max(1, args.api_turn_retries) + 1):
        try:
            return _sample(args, instructions, input_items, tools, api_key, base_url, model, profile)
        except Exception as exc:
            last_exc = exc
            if attempt == args.api_turn_retries:
                break
            time.sleep(min(20.0 * attempt, 60.0))
    assert last_exc is not None
    raise last_exc


def _extract_output_items(resp: dict[str, Any]) -> list[dict[str, Any]]:
    output = resp.get("output")
    return output if isinstance(output, list) else []


def _write_provider_error(
    metadata: dict[str, Any],
    binary: str,
    error: Exception,
    transcript: list[dict[str, Any]],
    turn: int | str,
    output_dir: str,
    start_epoch: float,
) -> int:
    transcript.append({
        "turn": turn,
        "stage": "provider_error",
        "error": str(error).replace("\x00", "")[:2000],
    })
    result = api_failure_fallback_result(metadata, binary, repr(error))
    print(jdump(write_run_outputs(output_dir, result, transcript, start_epoch)))
    return 1


def run_agent(args: argparse.Namespace) -> int:
    start_epoch = time.time()
    metadata = load_cve_metadata(args)
    try:
        validate_metadata_prompt_input(metadata_for_agent(metadata))
    except ValueError as exc:
        raise SystemExit(f"metadata input rejected: {exc}") from exc
    source_context = None
    set_patch_source_context(None)
    if args.source_repo:
        try:
            source_context = build_patch_source_context(args.source_repo, metadata)
        except Exception as exc:
            raise SystemExit(f"patch-source preflight failed: {exc}") from exc
    try:
        debug_companion = resolve_debug_companion(args.binary, getattr(args, "debug_dir", ""))
    except Exception as exc:
        raise SystemExit(f"debug companion preflight failed: {exc}") from exc
    try:
        workspace = (
            prepare_anonymous_binary(args.binary, debug_companion=debug_companion)
            if debug_companion is not None
            else prepare_anonymous_binary(args.binary)
        )
    except Exception as exc:
        raise SystemExit(f"debug companion merge failed: {exc}") from exc
    scratch = (
        str(expand(args.output_dir) / "scratch")
        if args.output_dir
        else tempfile.mkdtemp(prefix="claudeagent-scratch-")
    )
    os.makedirs(scratch, exist_ok=True)
    try:
        return _run_agent_body(args, metadata, workspace, start_epoch, scratch, source_context)
    finally:
        retain_scratch_scripts(scratch)
        set_patch_source_context(None)
        workspace.cleanup()


def _run_agent_body(
    args: argparse.Namespace,
    metadata: dict[str, Any],
    workspace: Any,
    start_epoch: float,
    scratch: str,
    source_context: Any = None,
) -> int:
    binary = str(workspace.binary_path)
    metadata_hash = metadata_sha256(
        metadata_for_agent(metadata),
        str(metadata.get("cve_id") or args.cve_id) or None,
    )
    preflight = preflight_detection_inputs(binary, metadata)
    initialize_agent_context(
        metadata,
        binary,
        args.cve_id,
        args.output_dir,
        scratch,
        metadata_sha256=metadata_hash,
        source_context_sha256=(
            source_context.source_context_sha256 if source_context is not None else ""
        ),
        debug_companion_sha256=(
            binary_sha256(workspace.debug_companion_path)
            if workspace.debug_companion_path is not None
            else ""
        ),
    )
    set_patch_source_context(source_context)
    source_manifest = (
        source_context.agent_manifest() if source_context is not None else {"available": False}
    )
    transcript: list[dict[str, Any]] = [
        {"stage": "host_preflight", "result": preflight},
        {"stage": "metadata_input", "metadata_sha256": metadata_hash},
        {
            "stage": "patch_source_preflight",
            "enabled": source_context is not None,
            "source_context_sha256": (
                source_context.source_context_sha256 if source_context is not None else ""
            ),
            "manifest": source_manifest,
        },
        {
            "stage": "debug_companion_preflight",
            "enabled": workspace.debug_companion_path is not None,
            "merged": workspace.debug_merged,
            "sha256": (
                binary_sha256(workspace.debug_companion_path)
                if workspace.debug_companion_path is not None
                else ""
            ),
        },
    ]
    if not preflight.get("ok"):
        result = preflight_missing_result(metadata, binary, preflight)
        print(jdump(write_run_outputs(args.output_dir, result, transcript, start_epoch)))
        return 1

    load_env_files(args.env_file)
    if args.import_interactive_env:
        profile = resolve_profile(args)
        import_env_from_interactive_shell(interactive_env_keys(profile))
    api_key, base_url, model, profile = provider_config(args)
    if not api_key:
        raise SystemExit(
            f"API key for profile {profile.name!r} is not set (env var {profile.api_key_env!r}). "
            "Use --dry-run for local validation only."
        )

    instructions = SYSTEM_PROMPT.read_text()
    task_content = build_task(metadata, binary, preflight)
    source_enabled = source_context is not None
    tools = load_tools(strict=not args.no_strict, source_enabled=source_enabled)
    allowed_tools = enabled_tool_funcs(source_enabled=source_enabled)
    record_response_history = profile.history_adapter == "deepseek_responses"
    input_items: list[dict[str, Any]] = [{"type": "message", "role": "user", "content": task_content}]

    for turn in range(1, args.max_turns + 1):
        try:
            resp = _sample_turn(args, instructions, input_items, tools, api_key, base_url, model, profile)
        except Exception as exc:
            return _write_provider_error(metadata, binary, exc, transcript, turn, args.output_dir, start_epoch)
        output_items = _extract_output_items(resp)
        transcript.append({"turn": turn, "output": output_items, "usage": resp.get("usage", {})})
        if args.verbose:
            print(f"\n--- model turn {turn} ---", file=sys.stderr)
            print(jdump(output_items), file=sys.stderr)
        done, final_result = handle_tool_calls(
            output_items=output_items,
            input_items=input_items,
            transcript=transcript,
            turn_label=turn,
            allowed_tools=allowed_tools,
            output_dir=args.output_dir,
            start_epoch=start_epoch,
            record_response_history=record_response_history,
        )
        if done and final_result is not None:
            print(jdump(final_result))
            return 0

    if args.finalize_on_max_turns:
        append_finalization_prompt(input_items, args.max_turns)
        for finalize_turn in range(1, args.finalization_turns + 1):
            remaining = args.finalization_turns - finalize_turn
            if finalize_turn > 1:
                append_finalization_budget_prompt(input_items, remaining + 1)
            non_source_tools = [tool for tool in tools if tool.get("name") not in SOURCE_TOOL_NAMES]
            turn_tools = finalization_tools(tools) if remaining == 0 else non_source_tools
            turn_allowed_tools = (
                FINALIZATION_TOOL_FUNCS
                if remaining == 0
                else enabled_tool_funcs(source_enabled=False)
            )
            turn_label = f"finalize-{finalize_turn}"
            try:
                resp = _sample_turn(args, instructions, input_items, turn_tools, api_key, base_url, model, profile)
            except Exception as exc:
                return _write_provider_error(metadata, binary, exc, transcript, turn_label, args.output_dir, start_epoch)
            output_items = _extract_output_items(resp)
            transcript.append({"turn": turn_label, "output": output_items, "usage": resp.get("usage", {})})
            if args.verbose:
                print(f"\n--- model {turn_label} ---", file=sys.stderr)
                print(jdump(output_items), file=sys.stderr)
            done, final_result = handle_tool_calls(
                output_items=output_items,
                input_items=input_items,
                transcript=transcript,
                turn_label=turn_label,
                allowed_tools=turn_allowed_tools,
                output_dir=args.output_dir,
                start_epoch=start_epoch,
                record_response_history=record_response_history,
            )
            if done and final_result is not None:
                print(jdump(final_result))
                return 0

        for repair_turn in range(1, 3):
            if not last_tool_call_needs_forced_submit(transcript):
                break
            input_items.append({"type": "message", "role": "user", "content": repair_finalization_prompt()})
            turn_label = f"repair-{repair_turn}"
            try:
                resp = _sample_turn(
                    args,
                    instructions,
                    input_items,
                    finalization_tools(tools),
                    api_key,
                    base_url,
                    model,
                    profile,
                )
            except Exception as exc:
                return _write_provider_error(metadata, binary, exc, transcript, turn_label, args.output_dir, start_epoch)
            output_items = _extract_output_items(resp)
            transcript.append({"turn": turn_label, "output": output_items, "usage": resp.get("usage", {})})
            done, final_result = handle_tool_calls(
                output_items=output_items,
                input_items=input_items,
                transcript=transcript,
                turn_label=turn_label,
                allowed_tools=FINALIZATION_TOOL_FUNCS,
                output_dir=args.output_dir,
                start_epoch=start_epoch,
                record_response_history=record_response_history,
            )
            if done and final_result is not None:
                print(jdump(final_result))
                return 0

    result = max_turns_fallback_result(metadata, binary, args.max_turns)
    print(jdump(write_run_outputs(args.output_dir, result, transcript, start_epoch)))
    return 0


def dry_run(args: argparse.Namespace) -> int:
    metadata = load_cve_metadata(args)
    try:
        validate_metadata_prompt_input(metadata_for_agent(metadata))
    except ValueError as exc:
        raise SystemExit(f"metadata input rejected: {exc}") from exc
    metadata_hash = metadata_sha256(
        metadata_for_agent(metadata),
        str(metadata.get("cve_id") or args.cve_id) or None,
    )
    source_context = None
    set_patch_source_context(None)
    if args.source_repo:
        try:
            source_context = build_patch_source_context(args.source_repo, metadata)
        except Exception as exc:
            raise SystemExit(f"patch-source preflight failed: {exc}") from exc
    try:
        debug_companion = resolve_debug_companion(args.binary, getattr(args, "debug_dir", ""))
    except Exception as exc:
        raise SystemExit(f"debug companion preflight failed: {exc}") from exc
    try:
        workspace = (
            prepare_anonymous_binary(args.binary, debug_companion=debug_companion)
            if debug_companion is not None
            else prepare_anonymous_binary(args.binary)
        )
    except Exception as exc:
        raise SystemExit(f"debug companion merge failed: {exc}") from exc
    try:
        binary = str(workspace.binary_path)
        source_enabled = source_context is not None
        set_patch_source_context(source_context)
        tools = load_tools(strict=not args.no_strict, source_enabled=source_enabled)
        load_final_result_schema()
        preflight = preflight_detection_inputs(binary, metadata)
        _, base_url, model, profile = provider_config(args)
        source_manifest = (
            source_context.agent_manifest() if source_context is not None else {"available": False}
        )
        task_content = build_task(metadata, binary, preflight)
        initialize_agent_context(
            metadata,
            binary,
            args.cve_id,
            metadata_sha256=metadata_hash,
            source_context_sha256=(
                source_context.source_context_sha256 if source_context is not None else ""
            ),
            debug_companion_sha256=(
                binary_sha256(workspace.debug_companion_path)
                if workspace.debug_companion_path is not None
                else ""
            ),
        )
        print("TOOLS_OK", len(tools), [tool["name"] for tool in tools])
        print("FINAL_RESULT_SCHEMA_OK", FINAL_RESULT_SCHEMA)
        print("MODEL_PROFILE", profile.name)
        print("MODEL", model)
        print("BASE_URL", base_url)
        print("API_PROTOCOL", profile.api_protocol)
        print("HISTORY_ADAPTER", profile.history_adapter)
        print("REASONING_EFFORT", profile.reasoning_effort)
        print("REASONING_MODE", profile.reasoning_mode)
        print("METADATA_SHA256", metadata_hash)
        print(
            "SOURCE_CONTEXT_SHA256",
            source_context.source_context_sha256 if source_context is not None else "",
        )
        print("PATCH_SOURCE", jdump(source_manifest))
        print("SYSTEM_PROMPT_CHARS", len(SYSTEM_PROMPT.read_text()))
        print("TASK_CHARS", len(task_content))
        print("SANDBOX_PREFLIGHT")
        print(jdump(preflight_sandbox()))
        print("HOST_PREFLIGHT")
        print(jdump(preflight))
        return 0
    finally:
        set_patch_source_context(None)
        workspace.cleanup()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="claudeagent single-case patch-presence detection")
    parser.add_argument("--cve-id", default="")
    parser.add_argument("--cve-json", default="", help="path to a single CVE metadata JSON object")
    parser.add_argument("--cve-inline-json", default="", help="inline CVE metadata JSON object")
    parser.add_argument("--metadata-json", default="", help="path to a metadata map/list; needs --cve-id")
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument(
        "--debug-dir",
        default="",
        help="directory containing <binary-basename>.debug companions to merge before inspection",
    )
    parser.add_argument("--output-dir", default="")
    parser.add_argument(
        "--source-repo",
        default="",
        help="local Git repository containing the patch commit referenced by metadata",
    )
    parser.add_argument("--model", default="", help="override the config profile's model")
    parser.add_argument("--base-url", default="", help="override the config profile's base_url")
    parser.add_argument("--model-profile", default="", help="config profile name or alias")
    parser.add_argument("--env-file", default="")
    parser.add_argument("--import-interactive-env", action="store_true")
    parser.add_argument("--no-strict", action="store_true", help="drop tool strict flags")
    parser.add_argument(
        "--reasoning-effort",
        default="",
        choices=("", *REASONING_EFFORTS),
        help="override the profile effort",
    )
    parser.add_argument("--max-turns", type=int, default=20)
    parser.add_argument("--finalize-on-max-turns", action="store_true", default=True)
    parser.add_argument("--no-finalize-on-max-turns", dest="finalize_on_max_turns", action="store_false")
    parser.add_argument("--finalization-turns", type=int, default=3)
    parser.add_argument("--api-timeout", type=int, default=240)
    parser.add_argument("--api-max-retries", type=int, default=3)
    parser.add_argument("--api-turn-retries", type=int, default=1)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        resolve_profile(args)
    except ValueError as exc:
        raise SystemExit(f"model config error: {exc}") from exc
    return dry_run(args) if args.dry_run else run_agent(args)


if __name__ == "__main__":
    raise SystemExit(main())
