"""Single-case model/tool loop over the OpenAI Responses API.

Build a prompt (instructions + task), sample the model, dispatch each function
call to a handler, feed the bounded result back as a function_call_output item,
and repeat until the model calls submit_detection_result with a schema-valid,
evidence-cited verdict. Tool and schema failures repair in-band; only model-API
failures (after retries) abort.

The Responses API is stateless here: every turn resends the full conversation
as the ``input`` items array. Reasoning items are dropped (we keep only message
+ function_call + function_call_output); this keeps runs reproducible and avoids
reasoning-content round-tripping through the proxy.

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

from claudeagent.binary_workspace import prepare_anonymous_binary
from claudeagent.common import (
    FINAL_RESULT_SCHEMA,
    SYSTEM_PROMPT,
    compact_json,
    expand,
    jdump,
)
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
    import_env_from_interactive_shell,
    load_cve_metadata,
    load_env_files,
    preflight_detection_inputs,
)
from claudeagent.model_config import (
    ModelProfile,
    apply_profile_to_args,
    interactive_env_keys,
    reasoning_param,
    resolve_api_key,
    resolve_profile,
)
from claudeagent.observations import compact_tool_result_for_model
from claudeagent.patchspec import (
    PatchSpecModelConfig,
    PatchSpecResult,
    ensure_patch_spec,
    load_patch_spec,
    prompt_view,
    resolve_source_excerpts,
)
from claudeagent.prompting import append_finalization_budget_prompt, append_finalization_prompt, build_task
from claudeagent.responses_client import responses_create
from claudeagent.runtime import bump_metric, initialize_agent_context
from claudeagent.sandbox import preflight_sandbox
from claudeagent.schema_validate import DETERMINATE_STATUSES, load_final_result_schema
from claudeagent.tools_registry import TOOL_FUNCS, load_tools, submit_tool_only


def _function_call_output(call_id: str, result: dict[str, Any], *, raw: bool = False) -> dict[str, Any]:
    """Build the Responses item that feeds a tool result back to the model.

    By default the result is compacted (stdout budget, evidence trimming) for the
    model's context window. ``raw=True`` passes the full result dict unchanged --
    used for a failed submit_detection_result, whose ``schema_errors`` /
    ``known_evidence_ids`` / ``repair_instruction`` would otherwise be stripped by
    the compactor and leave the model unable to see why its verdict was rejected.
    """
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
) -> tuple[bool, dict[str, Any] | None]:
    """Dispatch function_call items from a Responses output array.

    Echoes each function_call item back into input_items (the model must see its
    own calls), runs it, appends a function_call_output item, and records the
    transcript. Returns (done, final_result).
    """
    function_calls = [item for item in output_items if item.get("type") == "function_call"]
    if not function_calls:
        input_items.append({
            "type": "message",
            "role": "user",
            "content": "You must call submit_detection_result. Plain text is not a valid final answer.",
        })
        return False, None

    for call_index, call in enumerate(function_calls, 1):
        bump_metric("tool_calls")
        fn = call.get("name")
        raw_args = call.get("arguments") or "{}"
        # A Responses function_call carries the tool-call identifier in ``call_id``;
        # ``id`` is the item id (a different, longer token). function_call_output
        # must echo ``call_id``, or the API rejects the next turn with
        # "No tool output found for function call <call_id>". Prefer ``call_id``
        # and fall back to ``id`` only for synthetic test fixtures that set ``id``.
        call_id = call.get("call_id") or call.get("id") or ""
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
                # Echo the submit call and its repair output so the model can fix it.
                # raw=True: the repair carries schema_errors/known_evidence_ids the compactor would drop.
                input_items.append(call)
                input_items.append(_function_call_output(call_id, repair_result, raw=True))
                continue
            return True, write_run_outputs(output_dir, result, transcript, start_epoch)

        # Echo the function_call then feed its output back. A failed submit carries
        # schema_errors/known_evidence_ids/repair_instruction that the compactor would
        # strip; pass it raw so the model can actually repair. Everything else (a
        # run_python observation, or a phase-rejection stub) is compacted normally.
        submit_repair = fn == "submit_detection_result" and not result.get("ok")
        input_items.append(call)
        input_items.append(_function_call_output(call_id, result, raw=submit_repair))
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


def provider_config(args: argparse.Namespace) -> tuple[str, str, str, ModelProfile]:
    """Resolve (api_key, base_url, model, profile) with config as source of truth.

    Priority is CLI flag > config profile field. The model_config.json profile
    names the backend (base_url, model, reasoning effort/mode) and the env var
    that carries the API key; --model / --base-url / --reasoning-effort override
    the profile when set. The old OPENAI_BASE_URL / OPENAI_MODEL ambient-env
    fallbacks are gone - the config file is the single source of truth for which
    backend to talk to. The API key is read from the profile's env var (or its
    key file) and is never logged. The profile is returned so callers can derive
    request-only fields (e.g. reasoning on/off) without re-resolving.
    """
    profile = resolve_profile(args)
    apply_profile_to_args(args, profile)
    api_key = resolve_api_key(profile)
    return api_key, args.base_url, args.model, profile


def _patch_spec_output_path(args: argparse.Namespace) -> str | None:
    if not args.output_dir:
        return None
    return str(expand(args.output_dir) / "patch_spec.json")


def _patch_spec_model_config(
    args: argparse.Namespace,
    *,
    api_key: str,
    base_url: str,
    model: str,
    profile: ModelProfile,
) -> PatchSpecModelConfig:
    return PatchSpecModelConfig(
        api_key=api_key,
        base_url=base_url,
        model=model,
        reasoning_effort=profile.reasoning_effort,
        reasoning=reasoning_param(profile),
        timeout=args.api_timeout,
        max_retries=args.api_max_retries,
    )


def _resolve_case_patch_spec(
    args: argparse.Namespace,
    metadata: dict[str, Any],
    *,
    model_config: PatchSpecModelConfig,
    dry_run: bool,
) -> tuple[PatchSpecResult, str]:
    """Strictly load an explicit spec, or lazily resolve the case-local spec."""
    if args.patchspec_json:
        try:
            result = load_patch_spec(args.patchspec_json, metadata=metadata)
        except Exception as exc:
            raise SystemExit(f"PatchSpec load/validation failed: {exc}") from exc
        return result, "provided"

    try:
        result = ensure_patch_spec(
            metadata,
            cve_id=str(metadata.get("cve_id") or args.cve_id),
            output_path=_patch_spec_output_path(args),
            config=model_config,
            dry_run=dry_run,
        )
    except Exception as exc:
        raise SystemExit(f"PatchSpec generation/validation failed: {exc}") from exc

    if result.cache_hit:
        resolution_mode = "cache_hit"
    elif dry_run:
        resolution_mode = "deterministic_skeleton"
    else:
        resolution_mode = "generated"
    return result, resolution_mode


def _patch_spec_runtime_info(result: PatchSpecResult, resolution_mode: str) -> dict[str, Any]:
    usage = result.usage if isinstance(result.usage, dict) else {}
    generation = result.spec.get("generation") if isinstance(result.spec, dict) else {}
    generation_mode = (
        generation.get("mode", result.generation_mode)
        if isinstance(generation, dict)
        else result.generation_mode
    )
    return {
        "digest": str(result.digest),
        "generation_mode": str(generation_mode),
        "resolution_mode": resolution_mode,
        "cache_key": str(result.cache_key),
        "cache_hit": resolution_mode == "cache_hit",
        # PatchSpecResult.usage is intentionally the usage incurred by this
        # resolution only. Cache/provided/dry-run loads therefore remain empty.
        "usage": usage,
    }


def _patch_spec_transcript_entry(info: dict[str, Any]) -> dict[str, Any]:
    """Record provenance without mixing PatchSpec usage into turn aggregation."""
    return {
        "stage": "patch_spec",
        "digest": info.get("digest", ""),
        "generation_mode": info.get("generation_mode", ""),
        "resolution_mode": info.get("resolution_mode", ""),
        "cache_hit": bool(info.get("cache_hit", False)),
    }


def _sample(args: argparse.Namespace, instructions, input_items, tools, api_key, base_url, model,
            profile: ModelProfile) -> dict[str, Any]:
    # reasoning_mode is a profile property (is this a thinking model?), not a
    # CLI knob: "off" omits the reasoning field entirely (non-thinking models
    # like deepseek-v4-flash-nothinking reject/ignore it); "on" sends the effort.
    # --reasoning-effort overrides the effort value but not the on/off mode.
    reasoning = reasoning_param(profile)
    return responses_create(
        instructions=instructions,
        input_items=input_items,
        tools=tools,
        api_key=api_key,
        base_url=base_url,
        model=model,
        timeout=args.api_timeout,
        max_retries=args.api_max_retries,
        reasoning=reasoning,
    )


def _extract_output_items(resp: dict[str, Any]) -> list[dict[str, Any]]:
    output = resp.get("output")
    return output if isinstance(output, list) else []


def _sample_turn(args: argparse.Namespace, instructions, input_items, tools, api_key, base_url, model,
                 profile: ModelProfile) -> dict[str, Any]:
    """Sample one turn, recovering across long upstream outage windows.

    ``_sample`` already retries individual HTTP requests (``api_max_retries``)
    with short backoff, but the proxy upstream has outages lasting minutes:
    every request in that window reset-resolves, so the per-request retries all
    exhaust within ~30s and the run would fall back to inconclusive. To ride a
    multi-minute outage through to the next healthy window, we retry the whole
    turn ``api_turn_retries`` times with a longer (minute-scale) backoff. Only
    when all turn-level attempts fail do we propagate, so the caller can write
    the inconclusive fallback.
    """
    last_exc: Exception | None = None
    for attempt in range(1, max(1, args.api_turn_retries) + 1):
        try:
            return _sample(args, instructions, input_items, tools, api_key, base_url, model, profile)
        except Exception as exc:
            last_exc = exc
            if attempt == args.api_turn_retries:
                break
            # Minute-scale backoff to span an outage window; capped at 60s.
            time.sleep(min(20.0 * attempt, 60.0))
    assert last_exc is not None
    raise last_exc


def run_agent(args: argparse.Namespace) -> int:
    start_epoch = time.time()
    metadata = load_cve_metadata(args)
    # Copy the binary into a fresh temp dir under a neutral name (target_binary)
    # so the original filename - which encodes the package version - never reaches
    # the prompt, transcript, evidence, or final artifact. The model must judge
    # patch presence from binary semantics, not a version-string lookup. Cleaned up
    # in finally regardless of exit path (early return / exception / normal exit).
    workspace = prepare_anonymous_binary(args.binary)
    try:
        return _run_agent_body(args, metadata, workspace, start_epoch)
    finally:
        workspace.cleanup()


def _run_agent_body(args: argparse.Namespace, metadata: dict[str, Any], workspace: Any, start_epoch: float) -> int:
    binary = str(workspace.binary_path)
    if args.output_dir:
        scratch = str(expand(args.output_dir) / "scratch")
    else:
        scratch = tempfile.mkdtemp(prefix="claudeagent-scratch-")
    os.makedirs(scratch, exist_ok=True)

    preflight = preflight_detection_inputs(binary, metadata)
    if not preflight.get("ok"):
        initialize_agent_context(metadata, binary, args.cve_id, args.output_dir, scratch)
        result = preflight_missing_result(metadata, binary, preflight)
        transcript = [{"stage": "host_preflight", "result": preflight}]
        print(jdump(write_run_outputs(args.output_dir, result, transcript, start_epoch)))
        return 1

    transcript: list[dict[str, Any]] = [{"stage": "host_preflight", "result": preflight}]

    load_env_files(args.env_file)
    # The API key lives in a profile-named env var (e.g. PPTAGENT_API_KEY for
    # the cliproxy profile, OPENAI_API_KEY for aiflexr), so import that var from
    # the interactive shell before resolving the key. resolve_profile reads only
    # args (not the env), so this is safe to call before provider_config.
    if args.import_interactive_env:
        profile = resolve_profile(args)
        import_env_from_interactive_shell(interactive_env_keys(profile))
    api_key, base_url, model, profile = provider_config(args)
    if not api_key:
        raise SystemExit(
            f"API key for profile {getattr(profile, 'name', '?')!r} is not set "
            f"(env var {getattr(profile, 'api_key_env', '?')}). "
            "Use --dry-run for local validation only."
        )

    patch_spec_result, resolution_mode = _resolve_case_patch_spec(
        args,
        metadata,
        model_config=_patch_spec_model_config(
            args,
            api_key=api_key,
            base_url=base_url,
            model=model,
            profile=profile,
        ),
        dry_run=False,
    )
    patch_spec_info = _patch_spec_runtime_info(patch_spec_result, resolution_mode)
    initialize_agent_context(
        metadata,
        binary,
        args.cve_id,
        args.output_dir,
        scratch,
        patch_spec_info,
        patch_spec_result.spec,
    )
    transcript.append(_patch_spec_transcript_entry(patch_spec_info))
    task_patch_spec = prompt_view(patch_spec_result.spec)
    source_excerpts = resolve_source_excerpts(metadata, patch_spec_result.spec)

    tools = load_tools(strict=not args.no_strict)
    instructions = SYSTEM_PROMPT.read_text()
    input_items: list[dict[str, Any]] = [
        {
            "type": "message",
            "role": "user",
            "content": build_task(task_patch_spec, source_excerpts, binary, preflight),
        },
    ]

    # Phase 1: bounded exploration.
    for turn in range(1, args.max_turns + 1):
        try:
            resp = _sample_turn(args, instructions, input_items, tools, api_key, base_url, model, profile)
        except Exception as exc:
            # The proxy upstream is intermittently flaky (connection resets). After all
            # retries are exhausted, write an inconclusive artifact so a batch can still
            # score the case instead of dying empty-handed.
            result = api_failure_fallback_result(metadata, binary, repr(exc))
            transcript.append({"turn": turn, "stage": "api_failure", "error": repr(exc)})
            print(jdump(write_run_outputs(args.output_dir, result, transcript, start_epoch)))
            return 1
        output_items = _extract_output_items(resp)
        transcript.append({"turn": turn, "output": output_items, "usage": resp.get("usage", {})})
        if args.verbose:
            print(f"\n--- model turn {turn} ---", file=sys.stderr)
            print(jdump(output_items), file=sys.stderr)
        done, final_result = handle_tool_calls(
            output_items=output_items, input_items=input_items, transcript=transcript, turn_label=turn,
            allowed_tools=TOOL_FUNCS, output_dir=args.output_dir, start_epoch=start_epoch,
        )
        if done and final_result is not None:
            print(jdump(final_result))
            return 0

    if args.finalize_on_max_turns:
        # Phase 2: finalize nudge (last turn restricts to submit-only).
        append_finalization_prompt(input_items, args.max_turns)
        for finalize_turn in range(1, args.finalization_turns + 1):
            remaining = args.finalization_turns - finalize_turn
            if finalize_turn > 1:
                append_finalization_budget_prompt(input_items, remaining + 1)
            turn_tools = submit_tool_only(tools) if remaining == 0 else tools
            allowed = {"submit_detection_result": TOOL_FUNCS["submit_detection_result"]} if remaining == 0 else TOOL_FUNCS
            resp = _sample_turn(args, instructions, input_items, turn_tools, api_key, base_url, model, profile)
            output_items = _extract_output_items(resp)
            turn_label = f"finalize-{finalize_turn}"
            transcript.append({"turn": turn_label, "output": output_items, "usage": resp.get("usage", {})})
            if args.verbose:
                print(f"\n--- model {turn_label} ---", file=sys.stderr)
                print(jdump(output_items), file=sys.stderr)
            done, final_result = handle_tool_calls(
                output_items=output_items, input_items=input_items, transcript=transcript, turn_label=turn_label,
                allowed_tools=allowed, output_dir=args.output_dir, start_epoch=start_epoch,
            )
            if done and final_result is not None:
                print(jdump(final_result))
                return 0

        # Phase 3: forced repair (submit-only).
        for repair_turn in range(1, 3):
            if not last_tool_call_needs_forced_submit(transcript):
                break
            input_items.append({
                "type": "message",
                "role": "user",
                "content": (
                    "Repair/finalization only: the previous response did not produce an accepted "
                    "submit_detection_result. Do not call run_python. Call submit_detection_result "
                    "now using supports that cite existing evidence_ids from the ledger and a claim "
                    "covering every required behavior; if the evidence is not decisive, submit "
                    "inconclusive with a concrete reason."
                ),
            })
            resp = _sample_turn(args, instructions, input_items, submit_tool_only(tools), api_key, base_url, model, profile)
            output_items = _extract_output_items(resp)
            turn_label = f"repair-{repair_turn}"
            transcript.append({"turn": turn_label, "output": output_items, "usage": resp.get("usage", {})})
            if args.verbose:
                print(f"\n--- model {turn_label} ---", file=sys.stderr)
                print(jdump(output_items), file=sys.stderr)
            done, final_result = handle_tool_calls(
                output_items=output_items, input_items=input_items, transcript=transcript, turn_label=turn_label,
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
    # Anonymize the binary in dry-run too, so the rendered TASK_CHARS prompt and
    # HOST_PREFLIGHT reflect exactly what a real run sends (neutral name, no version).
    workspace = prepare_anonymous_binary(args.binary)
    try:
        binary = str(workspace.binary_path)
        tools = load_tools(strict=not args.no_strict)
        load_final_result_schema()
        preflight = preflight_detection_inputs(binary, metadata)
        api_key, base_url, model, profile = provider_config(args)
        patch_spec_result, resolution_mode = _resolve_case_patch_spec(
            args,
            metadata,
            model_config=_patch_spec_model_config(
                args,
                api_key=api_key,
                base_url=base_url,
                model=model,
                profile=profile,
            ),
            dry_run=True,
        )
        patch_spec_info = _patch_spec_runtime_info(patch_spec_result, resolution_mode)
        initialize_agent_context(
            metadata,
            binary,
            args.cve_id,
            patch_spec_info=patch_spec_info,
            patch_spec=patch_spec_result.spec,
        )
        task_patch_spec = prompt_view(patch_spec_result.spec)
        source_excerpts = resolve_source_excerpts(metadata, patch_spec_result.spec)
        print("TOOLS_OK", len(tools), [t["name"] for t in tools])
        print("FINAL_RESULT_SCHEMA_OK", FINAL_RESULT_SCHEMA)
        print("MODEL_PROFILE", profile.name)
        print("MODEL", model)
        print("BASE_URL", base_url)
        print("REASONING_EFFORT", profile.reasoning_effort)
        print("REASONING_MODE", profile.reasoning_mode)
        print("PATCH_SPEC_DIGEST", patch_spec_result.digest)
        print("PATCH_SPEC_GENERATION_MODE", patch_spec_info["generation_mode"])
        print("PATCH_SPEC_RESOLUTION_MODE", resolution_mode)
        print("PATCH_SPEC_CACHE_HIT", patch_spec_info["cache_hit"])
        print("SYSTEM_PROMPT_CHARS", len(SYSTEM_PROMPT.read_text()))
        print("TASK_CHARS", len(build_task(task_patch_spec, source_excerpts, binary, preflight)))
        print("SANDBOX_PREFLIGHT")
        print(jdump(preflight_sandbox()))
        print("HOST_PREFLIGHT")
        print(jdump(preflight))
        return 0
    finally:
        workspace.cleanup()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="claudeagent single-case patch-presence detection")
    parser.add_argument("--cve-id", default="")
    parser.add_argument("--cve-json", default="", help="path to a single CVE metadata JSON object")
    parser.add_argument("--cve-inline-json", default="", help="inline CVE metadata JSON object")
    parser.add_argument("--metadata-json", default="", help="path to a {cve_id: metadata} or [metadata] JSON; needs --cve-id")
    parser.add_argument(
        "--patchspec-json",
        default="",
        help="strictly load and validate a prebuilt PatchSpec; otherwise lazily use <output-dir>/patch_spec.json",
    )
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--model", default="", help="override the config profile's model")
    parser.add_argument("--base-url", default="", help="override the config profile's base_url")
    parser.add_argument(
        "--model-profile", default="",
        help="config profile name or alias (see model_config.json); default is the config's active_profile",
    )
    parser.add_argument("--env-file", default="")
    parser.add_argument("--import-interactive-env", action="store_true")
    parser.add_argument("--no-strict", action="store_true", help="drop tool 'strict' flags (non-strict tool schemas)")
    parser.add_argument("--reasoning-effort", default="low", help="GPT-5.5 reasoning effort: low|medium|high (default low; high can exceed the API timeout)")
    parser.add_argument("--max-turns", type=int, default=20)
    parser.add_argument("--finalize-on-max-turns", action="store_true", default=True)
    parser.add_argument("--no-finalize-on-max-turns", dest="finalize_on_max_turns", action="store_false")
    parser.add_argument("--finalization-turns", type=int, default=3)
    parser.add_argument("--api-timeout", type=int, default=240)
    parser.add_argument("--api-max-retries", type=int, default=3)
    parser.add_argument("--api-turn-retries", type=int, default=1,
                        help="how many times to retry a whole turn across long upstream outage windows (minute-scale backoff); 1 = no cross-window retry")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # Validate the config/profile up front so a typo in --model-profile or a
    # malformed model_config.json surfaces as a one-line message, not a stack
    # trace deep inside the loop. resolve_profile reads only args (not the env),
    # so it is safe to call before any env/key work.
    try:
        resolve_profile(args)
    except ValueError as exc:
        raise SystemExit(f"model config error: {exc}")
    if args.dry_run:
        return dry_run(args)
    return run_agent(args)


if __name__ == "__main__":
    raise SystemExit(main())
