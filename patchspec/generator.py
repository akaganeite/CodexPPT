"""Model-assisted PatchSpec generation with one repair and safe fallback."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any, Callable

from claudeagent.responses_client import responses_create, waf_safe_output

from .core import (
    PROMPT_VERSION,
    PatchSpecMetadataError,
    PatchSpecValidationError,
    assert_valid_patch_spec,
    build_anchors,
    build_deterministic_skeleton,
    build_hunks,
    canonical_json,
    eligible_indicator_refs,
    metadata_sha256,
    model_input_view,
    patch_spec_cache_key,
    patch_spec_digest,
    prepare_metadata,
    resolve_json_pointer,
)


PATCHSPEC_INSTRUCTIONS = """You compile normalized CVE patch metadata into a PatchSpec advisory layer.
You receive source metadata only: never infer anything about a target binary, installed version, or ground truth.
Call submit_patch_spec exactly once. Partition every hunk into exactly one behavior. Select indicator refs only
from the eligible old/new lists. Summarize semantics, but do not invent source lines, functions, addresses,
symbols, strings, constants, or verdicts. Compiler-equivalent forms and applicability entries are advisory;
they are investigation hints and are not evidence. Do not include release versions, host paths, or ground-truth
labels in advisory text. Metadata string values prefixed with b64: are base64-encoded to pass the transport WAF;
decode them before summarizing. A missing anchor never proves absence or non-applicability."""


SUBMIT_PATCH_SPEC_TOOL: dict[str, Any] = {
    "type": "function",
    "name": "submit_patch_spec",
    "strict": True,
    "description": "Submit the normalized advisory behavior partition for the supplied patch metadata.",
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "required": ["security_invariant", "behaviors"],
        "properties": {
            "security_invariant": {"type": "string", "minLength": 1},
            "behaviors": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "hunk_ids",
                        "old_indicator_refs",
                        "new_indicator_refs",
                        "old_semantics",
                        "new_semantics",
                        "compiler_equivalent_forms",
                        "applicability",
                    ],
                    "properties": {
                        "hunk_ids": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string"},
                        },
                        "old_indicator_refs": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "new_indicator_refs": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "old_semantics": {"type": "string", "minLength": 1},
                        "new_semantics": {"type": "string", "minLength": 1},
                        "compiler_equivalent_forms": {
                            "type": "array",
                            "items": {"type": "string", "minLength": 1},
                        },
                        "applicability": {
                            "type": "array",
                            "items": {"type": "string", "minLength": 1},
                        },
                    },
                },
            },
        },
    },
}


@dataclass(frozen=True)
class PatchSpecModelConfig:
    """Effective Responses settings used for one PatchSpec generation."""

    api_key: str
    base_url: str
    model: str
    reasoning_effort: str
    reasoning: dict[str, Any] | None
    timeout: int = 240
    max_retries: int = 3

    @classmethod
    def from_profile(
        cls,
        profile: Any,
        *,
        api_key: str,
        base_url: str | None = None,
        model: str | None = None,
        reasoning_effort: str | None = None,
        timeout: int | None = None,
        max_retries: int | None = None,
    ) -> "PatchSpecModelConfig":
        effort = reasoning_effort or profile.reasoning_effort
        reasoning = None if getattr(profile, "reasoning_mode", "on") == "off" else {"effort": effort}
        return cls(
            api_key=api_key,
            base_url=base_url or profile.base_url,
            model=model or profile.model,
            reasoning_effort=effort,
            reasoning=reasoning,
            timeout=timeout if timeout is not None else (profile.api_timeout or 240),
            max_retries=max_retries if max_retries is not None else (profile.api_max_retries or 3),
        )


@dataclass(frozen=True)
class PatchSpecResult:
    """Resolved spec plus run-local provenance used by agent/batch integration."""

    spec: dict[str, Any]
    digest: str
    generation_mode: str
    usage: dict[str, Any]
    cache_key: str
    cache_hit: bool
    path: str | None = None

    @property
    def spec_generation_mode(self) -> str:
        generation = self.spec.get("generation") if isinstance(self.spec, dict) else {}
        if isinstance(generation, dict) and isinstance(generation.get("mode"), str):
            return generation["mode"]
        return self.generation_mode

    @property
    def resolution_mode(self) -> str:
        if self.cache_hit:
            return "cache_hit"
        if self.generation_mode == "dry_run_skeleton":
            return "deterministic_skeleton"
        return "generated"

    def as_dict(self, *, include_spec: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "digest": self.digest,
            "generation_mode": self.spec_generation_mode,
            "resolution_mode": self.resolution_mode,
            "usage": copy.deepcopy(self.usage),
            "cache_key": self.cache_key,
            "cache_hit": self.cache_hit,
            "path": self.path,
        }
        if include_spec:
            value["spec"] = copy.deepcopy(self.spec)
        return value


def _dedupe_strings(values: Any, field: str) -> list[str]:
    if not isinstance(values, list) or not all(isinstance(item, str) and item.strip() for item in values):
        raise PatchSpecValidationError([f"{field} must be an array of non-empty strings"])
    return list(dict.fromkeys(item.strip() for item in values))


def _trusted_indicator(metadata: dict[str, Any], ref: str) -> dict[str, Any]:
    value = resolve_json_pointer(metadata, ref)
    kind = "source_sequence" if isinstance(value, list) else "source_line"
    return {"kind": kind, "value": copy.deepcopy(value), "ref": ref}


def _validate_and_assemble_draft(
    draft: Any,
    metadata: dict[str, Any],
    *,
    config: PatchSpecModelConfig,
    mode: str,
    cache_key: str,
    usage: dict[str, Any],
    errors: list[str],
) -> dict[str, Any]:
    if not isinstance(draft, dict):
        raise PatchSpecValidationError(["submit_patch_spec arguments must be an object"])
    if set(draft) != {"security_invariant", "behaviors"}:
        raise PatchSpecValidationError(["submit_patch_spec must contain only security_invariant and behaviors"])
    invariant = draft.get("security_invariant")
    raw_behaviors = draft.get("behaviors")
    if not isinstance(invariant, str) or not invariant.strip():
        raise PatchSpecValidationError(["security_invariant must be a non-empty string"])
    if not isinstance(raw_behaviors, list) or not raw_behaviors:
        raise PatchSpecValidationError(["behaviors must be a non-empty array"])

    hunks = build_hunks(metadata)
    anchors = build_anchors(metadata)
    all_hunk_ids = [hunk["hunk_id"] for hunk in hunks]
    hunk_position = {hunk_id: index for index, hunk_id in enumerate(all_hunk_ids)}
    eligible = eligible_indicator_refs(metadata)
    function_anchor_ids = [
        anchor["anchor_id"] for anchor in anchors if anchor["kind"] == "function"
    ]
    assembled: list[dict[str, Any]] = []
    covered: list[str] = []
    required_fields = {
        "hunk_ids",
        "old_indicator_refs",
        "new_indicator_refs",
        "old_semantics",
        "new_semantics",
        "compiler_equivalent_forms",
        "applicability",
    }
    for index, raw in enumerate(raw_behaviors):
        if not isinstance(raw, dict) or set(raw) != required_fields:
            raise PatchSpecValidationError([f"behaviors[{index}] has missing or additional fields"])
        hunk_ids = _dedupe_strings(raw["hunk_ids"], f"behaviors[{index}].hunk_ids")
        if any(hunk_id not in hunk_position for hunk_id in hunk_ids):
            raise PatchSpecValidationError([f"behaviors[{index}].hunk_ids contains an unknown hunk"])
        covered.extend(hunk_ids)
        old_refs = _dedupe_strings(raw["old_indicator_refs"], f"behaviors[{index}].old_indicator_refs")
        new_refs = _dedupe_strings(raw["new_indicator_refs"], f"behaviors[{index}].new_indicator_refs")
        allowed_old = {ref for hunk_id in hunk_ids for ref in eligible[hunk_id]["old"]}
        allowed_new = {ref for hunk_id in hunk_ids for ref in eligible[hunk_id]["new"]}
        if any(ref not in allowed_old for ref in old_refs):
            raise PatchSpecValidationError([f"behaviors[{index}].old_indicator_refs is ungrounded or wrong-side"])
        if any(ref not in allowed_new for ref in new_refs):
            raise PatchSpecValidationError([f"behaviors[{index}].new_indicator_refs is ungrounded or wrong-side"])
        if not old_refs and not new_refs:
            raise PatchSpecValidationError([f"behaviors[{index}] must select at least one indicator"])
        for hunk_id in hunk_ids:
            for side, selected_refs in (("old", old_refs), ("new", new_refs)):
                eligible_for_hunk = set(eligible[hunk_id][side])
                if eligible_for_hunk and not (eligible_for_hunk & set(selected_refs)):
                    raise PatchSpecValidationError([
                        f"behaviors[{index}] must select a {side} indicator for {hunk_id}"
                    ])
        old_semantics = raw["old_semantics"]
        new_semantics = raw["new_semantics"]
        if not isinstance(old_semantics, str) or not old_semantics.strip():
            raise PatchSpecValidationError([f"behaviors[{index}].old_semantics must be non-empty"])
        if not isinstance(new_semantics, str) or not new_semantics.strip():
            raise PatchSpecValidationError([f"behaviors[{index}].new_semantics must be non-empty"])
        if " ".join(old_semantics.split()) == " ".join(new_semantics.split()):
            raise PatchSpecValidationError([f"behaviors[{index}] old/new semantics must differ"])
        assembled.append({
            "behavior_id": "",
            "required": True,
            "hunk_ids": sorted(hunk_ids, key=hunk_position.__getitem__),
            "function_anchor_ids": function_anchor_ids,
            "trusted": {
                "old_indicators": [_trusted_indicator(metadata, ref) for ref in old_refs],
                "new_indicators": [_trusted_indicator(metadata, ref) for ref in new_refs],
            },
            "advisory": {
                "security_invariant": invariant.strip(),
                "old_semantics": old_semantics.strip(),
                "new_semantics": new_semantics.strip(),
                "compiler_equivalent_forms": _dedupe_strings(
                    raw["compiler_equivalent_forms"],
                    f"behaviors[{index}].compiler_equivalent_forms",
                ),
                "applicability": _dedupe_strings(
                    raw["applicability"], f"behaviors[{index}].applicability"
                ),
            },
        })
    if sorted(covered, key=lambda item: (hunk_position.get(item, 10**9), item)) != all_hunk_ids:
        raise PatchSpecValidationError(["behaviors must cover every hunk exactly once"])
    assembled.sort(key=lambda behavior: min(hunk_position[item] for item in behavior["hunk_ids"]))
    for index, behavior in enumerate(assembled, 1):
        behavior["behavior_id"] = f"B{index:03d}"

    spec = {
        "schema_version": "patchspec.v1",
        "source": {
            "cve_id": metadata["cve_id"],
            "project": metadata["project"],
            "metadata_sha256": metadata_sha256(metadata),
        },
        "hunks": hunks,
        "anchors": anchors,
        "behaviors": assembled,
        "coverage": {
            "all_hunk_ids": all_hunk_ids,
            "covered_hunk_ids": all_hunk_ids,
            "uncovered_hunk_ids": [],
        },
        "generation": {
            "mode": mode,
            "model": config.model,
            "reasoning_effort": config.reasoning_effort,
            "prompt_version": PROMPT_VERSION,
            "cache_key": cache_key,
            "usage": copy.deepcopy(usage),
            "errors": list(errors),
        },
    }
    assert_valid_patch_spec(spec, metadata)
    return spec


def _extract_tool_arguments(response: dict[str, Any]) -> dict[str, Any]:
    output = response.get("output")
    if not isinstance(output, list):
        raise PatchSpecValidationError(["Responses output is not an array"])
    calls = [
        item for item in output
        if isinstance(item, dict)
        and item.get("type") == "function_call"
        and item.get("name") == "submit_patch_spec"
    ]
    if len(calls) != 1:
        raise PatchSpecValidationError(["model must call submit_patch_spec exactly once"])
    arguments = calls[0].get("arguments")
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError as exc:
            raise PatchSpecValidationError([f"submit_patch_spec arguments are invalid JSON: {exc}"]) from exc
    if not isinstance(arguments, dict):
        raise PatchSpecValidationError(["submit_patch_spec arguments must be an object"])
    return arguments


def _merge_usage(attempts: list[dict[str, Any]]) -> dict[str, Any]:
    if not attempts:
        return {}

    def merge_numeric_tree(target: dict[str, Any], source: dict[str, Any]) -> None:
        for key, value in source.items():
            if isinstance(value, dict):
                child = target.setdefault(key, {})
                if not isinstance(child, dict):
                    child = {}
                    target[key] = child
                merge_numeric_tree(child, value)
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                current = target.get(key, 0)
                if not isinstance(current, (int, float)) or isinstance(current, bool):
                    current = 0
                target[key] = current + value

    totals: dict[str, Any] = {}
    for usage in attempts:
        merge_numeric_tree(totals, usage)
    return {"attempts": copy.deepcopy(attempts), "total": totals}


def _waf_safe_model_value(value: Any) -> Any:
    """Encode only unsafe metadata string leaves, preserving JSON structure."""
    if isinstance(value, str):
        return waf_safe_output(value)
    if isinstance(value, list):
        return [_waf_safe_model_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _waf_safe_model_value(item) for key, item in value.items()}
    return value


def generate_patch_spec(
    metadata: dict[str, Any],
    *,
    cve_id: str | None = None,
    config: PatchSpecModelConfig,
    client: Callable[..., dict[str, Any]] = responses_create,
) -> PatchSpecResult:
    """Generate once, allow one schema/grounding repair, then degrade safely."""
    prepared = prepare_metadata(metadata, cve_id)
    if not config.api_key:
        raise PatchSpecMetadataError("PatchSpec model API key is not configured")
    cache_key = patch_spec_cache_key(
        prepared,
        model=config.model,
        reasoning_effort=config.reasoning_effort,
        reasoning=config.reasoning,
    )
    model_view = model_input_view(prepared)
    base_message = (
        "Compile this allowlisted normalized metadata into the advisory behavior partition.\n"
        + canonical_json(_waf_safe_model_value(model_view))
    )
    usage_attempts: list[dict[str, Any]] = []
    generation_errors: list[str] = []
    previous_error = ""
    for attempt in range(2):
        content = base_message
        if attempt:
            content += (
                "\nThe previous submission failed host validation. Repair it using only eligible refs. "
                f"Errors: {previous_error}"
            )
        try:
            response = client(
                instructions=PATCHSPEC_INSTRUCTIONS,
                input_items=[{"type": "message", "role": "user", "content": content}],
                tools=[copy.deepcopy(SUBMIT_PATCH_SPEC_TOOL)],
                api_key=config.api_key,
                base_url=config.base_url,
                model=config.model,
                timeout=config.timeout,
                max_retries=config.max_retries,
                tool_choice="required",
                store=False,
                reasoning=copy.deepcopy(config.reasoning),
            )
            usage = response.get("usage")
            if isinstance(usage, dict):
                usage_attempts.append(copy.deepcopy(usage))
            draft = _extract_tool_arguments(response)
            combined_usage = _merge_usage(usage_attempts)
            mode = "generated" if attempt == 0 else "repaired"
            spec = _validate_and_assemble_draft(
                draft,
                prepared,
                config=config,
                mode=mode,
                cache_key=cache_key,
                usage=combined_usage,
                errors=generation_errors,
            )
            return PatchSpecResult(
                spec=spec,
                digest=patch_spec_digest(spec),
                generation_mode=mode,
                usage=combined_usage,
                cache_key=cache_key,
                cache_hit=False,
            )
        except Exception as exc:
            previous_error = str(exc)
            generation_errors.append(previous_error)

    combined_usage = _merge_usage(usage_attempts)
    spec = build_deterministic_skeleton(
        prepared,
        model=config.model,
        reasoning_effort=config.reasoning_effort,
        reasoning=config.reasoning,
        mode="degraded",
        cache_key=cache_key,
        usage=combined_usage,
        errors=generation_errors,
    )
    return PatchSpecResult(
        spec=spec,
        digest=patch_spec_digest(spec),
        generation_mode="degraded",
        usage=combined_usage,
        cache_key=cache_key,
        cache_hit=False,
    )
