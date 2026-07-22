"""Deterministic PatchSpec normalization, grounding, and prompt-safe views."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable

from claudeagent.schema_validate import resolve_schema_refs, validate_json_schema


SCHEMA_VERSION = "patchspec.v1"
PROMPT_VERSION = "patchspec-prompt.v1.1"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.json"

_ID_RE = {
    "hunk": re.compile(r"^H\d{3}$"),
    "anchor": re.compile(r"^A\d{3}$"),
    "behavior": re.compile(r"^B\d{3}$"),
}
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"')
_CHAR_RE = re.compile(r"'(?:\\.|[^'\\])'")
_INTEGER_RE = re.compile(r"(?<![A-Za-z0-9_])(?:0[xX][0-9a-fA-F]+|\d+)(?![A-Za-z0-9_])")
_CONTROL_WORDS = {"if", "for", "while", "switch", "return", "sizeof", "defined"}
_ADVISORY_FORBIDDEN_RE = re.compile(
    r"\b[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9_.]+)?\b|"
    r"\bpre-?[0-9]+\.[0-9]+\.[0-9]+|"
    r"\bbefore\s+[0-9]+\.[0-9]+\.[0-9]+|"
    r"\bfixed\s+in\s+[0-9]+\.[0-9]+\.[0-9]+|"
    r"/home/|/media/|/extdisk/|\.\./|file path|target filename|target file name|"
    r"binary filename|binary file name|directory name|binary name|"
    r"naming convention|path contains|path indicates|"
    r"\bground\s*truth\b|\bexpected verdict\b|\bknown (?:vulnerable|patched)\b",
    re.IGNORECASE,
)


class PatchSpecError(ValueError):
    """Base error for deterministic PatchSpec processing."""


class PatchSpecMetadataError(PatchSpecError):
    """Raised when source metadata cannot support a grounded PatchSpec."""


class PatchSpecValidationError(PatchSpecError):
    """Raised when a PatchSpec fails schema or grounding validation."""

    def __init__(self, errors: Iterable[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def canonical_json(value: Any) -> str:
    """Return the stable JSON representation used by hashes and cache keys."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def prepare_metadata(metadata: dict[str, Any], cve_id: str | None = None) -> dict[str, Any]:
    """Copy metadata, inject a missing CVE id, and reject identity conflicts."""
    if not isinstance(metadata, dict):
        raise PatchSpecMetadataError("CVE metadata must be an object")
    prepared = copy.deepcopy(metadata)
    existing = prepared.get("cve_id")
    if cve_id and existing and existing != cve_id:
        raise PatchSpecMetadataError(
            f"metadata cve_id {existing!r} does not match requested {cve_id!r}"
        )
    resolved = cve_id or existing
    if not isinstance(resolved, str) or not resolved:
        raise PatchSpecMetadataError("CVE metadata requires a non-empty cve_id")
    prepared["cve_id"] = resolved
    if not isinstance(prepared.get("project"), str) or not prepared.get("project"):
        prepared["project"] = "unknown"
    try:
        canonical_json(prepared)
    except (TypeError, ValueError) as exc:
        raise PatchSpecMetadataError(f"CVE metadata is not JSON serializable: {exc}") from exc
    return prepared


def metadata_sha256(metadata: dict[str, Any], cve_id: str | None = None) -> str:
    prepared = prepare_metadata(metadata, cve_id)
    return hashlib.sha256(canonical_json(prepared).encode("utf-8")).hexdigest()


def patch_spec_cache_key(
    metadata: dict[str, Any],
    *,
    cve_id: str | None = None,
    model: str,
    reasoning_effort: str,
    reasoning: dict[str, Any] | None = None,
) -> str:
    """Hash all inputs whose change must invalidate a generated PatchSpec."""
    payload = {
        "metadata_sha256": metadata_sha256(metadata, cve_id),
        "schema_version": SCHEMA_VERSION,
        "prompt_version": PROMPT_VERSION,
        "model": model,
        "reasoning_effort": reasoning_effort,
        "reasoning": reasoning,
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _escape_pointer_part(part: str) -> str:
    return part.replace("~", "~0").replace("/", "~1")


def resolve_json_pointer(document: Any, pointer: str) -> Any:
    """Resolve an RFC 6901 JSON Pointer against ``document``."""
    if pointer == "":
        return document
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise KeyError(f"invalid JSON pointer: {pointer!r}")
    current = document
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if not part.isdigit():
                raise KeyError(f"array pointer component is not an index: {pointer!r}")
            index = int(part)
            if index >= len(current):
                raise KeyError(f"array pointer is out of range: {pointer!r}")
            current = current[index]
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise KeyError(f"JSON pointer does not resolve: {pointer!r}")
    return current


def _strip_c_comments(line: str, in_block: bool) -> tuple[str, bool]:
    """Remove comments for token extraction while preserving the source line."""
    output: list[str] = []
    index = 0
    quote = ""
    while index < len(line):
        if in_block:
            end = line.find("*/", index)
            if end < 0:
                return "".join(output), True
            index = end + 2
            in_block = False
            continue
        char = line[index]
        if quote:
            output.append(char)
            if char == "\\" and index + 1 < len(line):
                index += 1
                output.append(line[index])
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            output.append(char)
            index += 1
            continue
        if line.startswith("//", index):
            break
        if line.startswith("/*", index):
            in_block = True
            index += 2
            continue
        output.append(char)
        index += 1
    return "".join(output), in_block


def _source_code_lines(metadata: dict[str, Any]) -> list[tuple[str, str, str]]:
    records: list[tuple[str, str, str]] = []
    hunks = metadata.get("patch_hunk")
    if not isinstance(hunks, list) or not hunks:
        raise PatchSpecMetadataError("metadata.patch_hunk must be a non-empty array")
    for hunk_index, hunk in enumerate(hunks):
        if not isinstance(hunk, dict):
            raise PatchSpecMetadataError(f"patch_hunk[{hunk_index}] must be an object")
        for side in ("old", "new"):
            key = f"{side}_lines"
            lines = hunk.get(key)
            if not isinstance(lines, list) or not all(isinstance(line, str) for line in lines):
                raise PatchSpecMetadataError(f"patch_hunk[{hunk_index}].{key} must be a string array")
            in_block = False
            for line_index, source_line in enumerate(lines):
                code, in_block = _strip_c_comments(source_line, in_block)
                ref = f"/patch_hunk/{hunk_index}/{key}/{line_index}"
                records.append((side, ref, code))
    return records


def build_hunks(metadata: dict[str, Any], cve_id: str | None = None) -> list[dict[str, Any]]:
    prepared = prepare_metadata(metadata, cve_id)
    source_records = _source_code_lines(prepared)
    semantic_lines: dict[int, dict[str, list[str]]] = {}
    for side, ref, code in source_records:
        hunk_index = int(ref.split("/")[2])
        normalized = _normalized_source_line(code)
        if normalized and normalized not in {"{", "}", ";"}:
            semantic_lines.setdefault(hunk_index, {"old": [], "new": []})[side].append(normalized)
    result: list[dict[str, Any]] = []
    for index, hunk in enumerate(prepared["patch_hunk"]):
        sides = semantic_lines.get(index, {"old": [], "new": []})
        # Metadata exporters sometimes preserve whitespace-only diff hunks. They
        # are not security-relevant behaviors and must not make coverage or the
        # deterministic fallback impossible.
        if sides["old"] == sides["new"]:
            continue
        result.append({
            "hunk_id": f"H{index + 1:03d}",
            "ref": f"/patch_hunk/{index}",
            "header": str(hunk.get("header", "")),
            "old_line_refs": [
                f"/patch_hunk/{index}/old_lines/{line_index}"
                for line_index in range(len(hunk["old_lines"]))
            ],
            "new_line_refs": [
                f"/patch_hunk/{index}/new_lines/{line_index}"
                for line_index in range(len(hunk["new_lines"]))
            ],
        })
    if not result:
        raise PatchSpecMetadataError("patch_hunk contains no semantic old/new source change")
    return result


def _anchor_role(sides: set[str], kind: str) -> str:
    # OLD/NEW discrimination belongs exclusively to behavior indicators.
    # Anchors remain search hints even when the underlying token appears on
    # only one patch side; their absence can never carry verdict semantics.
    return "localization"


def _char_canonical(token: str) -> str | None:
    try:
        value = ast.literal_eval(token)
    except (SyntaxError, ValueError):
        return None
    if isinstance(value, str) and len(value) == 1:
        return f"0x{ord(value):02x}"
    return None


def build_anchors(metadata: dict[str, Any], cve_id: str | None = None) -> list[dict[str, Any]]:
    """Extract stable, source-grounded function/callee/literal anchors."""
    prepared = prepare_metadata(metadata, cve_id)
    records: dict[tuple[str, str], dict[str, Any]] = {}

    functions = prepared.get("functions", [])
    if functions is not None and (
        not isinstance(functions, list) or not all(isinstance(item, str) and item for item in functions)
    ):
        raise PatchSpecMetadataError("metadata.functions must be a string array when present")
    function_names = set(functions or [])

    def add(kind: str, value: str, ref: str, side: str, canonical: str | None = None) -> None:
        key = (kind, value)
        item = records.setdefault(
            key,
            {"kind": kind, "value": value, "refs": set(), "sides": set()},
        )
        item["refs"].add(ref)
        item["sides"].add(side)
        if canonical:
            item["canonical_value"] = canonical

    for index, function in enumerate(functions or []):
        add("function", function, f"/functions/{index}", "metadata")

    for side, ref, code in _source_code_lines(prepared):
        if not code.strip():
            continue
        for name in _CALL_RE.findall(code):
            if name not in _CONTROL_WORDS and name not in function_names:
                add("callee", name, ref, side)
        for token in _STRING_RE.findall(code):
            add("string_literal", token, ref, side)
        for token in _CHAR_RE.findall(code):
            canonical = _char_canonical(token)
            value = ast.literal_eval(token) if canonical else token
            add("character_constant", str(value), ref, side, canonical)
        code_without_literals = _STRING_RE.sub("", _CHAR_RE.sub("", code))
        for token in _INTEGER_RE.findall(code_without_literals):
            try:
                canonical = hex(int(token, 0))
            except ValueError:
                canonical = token.lower()
            add("integer_constant", token, ref, side, canonical)

    kind_order = {
        "function": 0,
        "callee": 1,
        "string_literal": 2,
        "character_constant": 3,
        "integer_constant": 4,
    }
    ordered = sorted(
        records.values(),
        key=lambda item: (kind_order[item["kind"]], item["value"], sorted(item["refs"])),
    )
    anchors: list[dict[str, Any]] = []
    side_order = {"metadata": 0, "old": 1, "new": 2}
    for index, raw in enumerate(ordered, 1):
        sides = sorted(raw["sides"], key=side_order.__getitem__)
        anchor = {
            "anchor_id": f"A{index:03d}",
            "kind": raw["kind"],
            "value": raw["value"],
            "role": _anchor_role(set(sides), raw["kind"]),
            "refs": sorted(raw["refs"]),
            "sides": sides,
        }
        if raw.get("canonical_value"):
            anchor["canonical_value"] = raw["canonical_value"]
        anchors.append(anchor)
    return anchors


def _normalized_source_line(value: str) -> str:
    return " ".join(value.strip().split())


def eligible_indicator_refs(
    metadata: dict[str, Any], cve_id: str | None = None
) -> dict[str, dict[str, list[str]]]:
    """Return side-exclusive, non-comment source lines eligible as indicators."""
    prepared = prepare_metadata(metadata, cve_id)
    code_by_hunk: dict[str, dict[str, list[tuple[str, str]]]] = {}
    for side, ref, code in _source_code_lines(prepared):
        hunk_index = int(ref.split("/")[2])
        hunk_id = f"H{hunk_index + 1:03d}"
        normalized = _normalized_source_line(code)
        if not normalized or normalized in {"{", "}", ";"}:
            continue
        code_by_hunk.setdefault(hunk_id, {"old": [], "new": []})[side].append((ref, normalized))

    result: dict[str, dict[str, list[str]]] = {}
    for hunk_id, sides in code_by_hunk.items():
        old_values = {value for _, value in sides["old"]}
        new_values = {value for _, value in sides["new"]}
        old_refs = [ref for ref, value in sides["old"] if value not in new_values]
        new_refs = [ref for ref, value in sides["new"] if value not in old_values]
        # A pure order/control-flow rearrangement may contain the same source
        # lines on both sides. In that case the ordered side sequence itself is
        # the exact grounded discriminator, so degraded fallback remains total.
        if not old_refs and not new_refs:
            old_sequence = [value for _, value in sides["old"]]
            new_sequence = [value for _, value in sides["new"]]
            if old_sequence != new_sequence:
                hunk_index = int(hunk_id[1:]) - 1
                if old_sequence:
                    old_refs = [f"/patch_hunk/{hunk_index}/old_lines"]
                if new_sequence:
                    new_refs = [f"/patch_hunk/{hunk_index}/new_lines"]
        result[hunk_id] = {
            "old": old_refs,
            "new": new_refs,
        }
    for hunk in build_hunks(prepared):
        result.setdefault(hunk["hunk_id"], {"old": [], "new": []})
    return result


def _fallback_text(metadata: dict[str, Any], *paths: tuple[str, ...], default: str) -> str:
    for path in paths:
        value: Any = metadata
        for key in path:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(key)
        if (
            isinstance(value, str)
            and value.strip()
            and not _ADVISORY_FORBIDDEN_RE.search(value)
        ):
            return value.strip()
    return default


def _indicator(metadata: dict[str, Any], ref: str) -> dict[str, Any]:
    try:
        value = resolve_json_pointer(metadata, ref)
    except KeyError as exc:
        raise PatchSpecMetadataError(str(exc)) from exc
    if isinstance(value, str) and value.strip():
        return {"kind": "source_line", "value": value, "ref": ref}
    if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
        if any(_normalized_source_line(item) for item in value):
            return {"kind": "source_sequence", "value": value, "ref": ref}
    raise PatchSpecMetadataError(
        f"indicator ref must resolve to a non-empty source line or source sequence: {ref}"
    )


def build_deterministic_skeleton(
    metadata: dict[str, Any],
    *,
    cve_id: str | None = None,
    model: str = "",
    reasoning_effort: str = "",
    reasoning: dict[str, Any] | None = None,
    mode: str = "deterministic_skeleton",
    cache_key: str | None = None,
    usage: dict[str, Any] | None = None,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    """Build the deterministic, fully grounded minimal PatchSpec fallback."""
    prepared = prepare_metadata(metadata, cve_id)
    hunks = build_hunks(prepared)
    anchors = build_anchors(prepared)
    eligible = eligible_indicator_refs(prepared)
    invariant = _fallback_text(
        prepared,
        ("patch_intent_analysis", "intended_security_property"),
        ("patch_intent_analysis", "summary"),
        ("root_cause_analysis", "summary"),
        ("vulnerability_description",),
        default="The patched implementation must enforce the security-relevant source change.",
    )
    old_summary = _fallback_text(
        prepared,
        ("root_cause_analysis", "unsafe_mechanism"),
        ("root_cause_analysis", "summary"),
        default="The vulnerable implementation follows the old-side source behavior.",
    )
    new_summary = _fallback_text(
        prepared,
        ("patch_intent_analysis", "summary"),
        ("patch_intent_analysis", "intended_security_property"),
        default="The patched implementation follows the new-side source behavior.",
    )
    if _normalized_source_line(old_summary) == _normalized_source_line(new_summary):
        new_summary += " (patched behavior)"
    function_anchor_ids = [
        anchor["anchor_id"] for anchor in anchors if anchor["kind"] == "function"
    ]
    behaviors: list[dict[str, Any]] = []
    for index, hunk in enumerate(hunks, 1):
        sides = eligible[hunk["hunk_id"]]
        if not sides["old"] and not sides["new"]:
            raise PatchSpecMetadataError(
                f"{hunk['hunk_id']} has no side-exclusive source line to discriminate old/new behavior"
            )
        behaviors.append({
            "behavior_id": f"B{index:03d}",
            "required": True,
            "hunk_ids": [hunk["hunk_id"]],
            "function_anchor_ids": function_anchor_ids,
            "trusted": {
                "old_indicators": [_indicator(prepared, ref) for ref in sides["old"]],
                "new_indicators": [_indicator(prepared, ref) for ref in sides["new"]],
            },
            "advisory": {
                "security_invariant": invariant,
                "old_semantics": old_summary,
                "new_semantics": new_summary,
                "compiler_equivalent_forms": [
                    "Equivalent control-flow or data-flow forms may implement the same predicate."
                ],
                "applicability": [
                    "The target contains the patched component or an equivalent implementation."
                ],
            },
        })
    all_hunk_ids = [hunk["hunk_id"] for hunk in hunks]
    if cache_key is None:
        cache_key = patch_spec_cache_key(
            prepared,
            model=model,
            reasoning_effort=reasoning_effort,
            reasoning=reasoning,
        )
    spec = {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "cve_id": prepared["cve_id"],
            "project": prepared["project"],
            "metadata_sha256": metadata_sha256(prepared),
        },
        "hunks": hunks,
        "anchors": anchors,
        "behaviors": behaviors,
        "coverage": {
            "all_hunk_ids": all_hunk_ids,
            "covered_hunk_ids": all_hunk_ids,
            "uncovered_hunk_ids": [],
        },
        "generation": {
            "mode": mode,
            "model": model,
            "reasoning_effort": reasoning_effort,
            "prompt_version": PROMPT_VERSION,
            "cache_key": cache_key,
            "usage": copy.deepcopy(usage or {}),
            "errors": list(errors or []),
        },
    }
    assert_valid_patch_spec(spec, prepared)
    return spec


def load_patch_spec_schema() -> dict[str, Any]:
    try:
        raw = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PatchSpecError(f"cannot load PatchSpec schema: {exc}") from exc
    if not isinstance(raw, dict):
        raise PatchSpecError("PatchSpec schema root must be an object")
    return resolve_schema_refs(raw, raw)


def _duplicates(values: list[str]) -> list[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return sorted(duplicates)


def _normalized_indicator_value(value: Any) -> str | None:
    if isinstance(value, str):
        return _normalized_source_line(value)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return canonical_json([_normalized_source_line(item) for item in value])
    return None


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_strings(item)


def validate_patch_spec(
    spec: Any,
    metadata: dict[str, Any] | None = None,
    cve_id: str | None = None,
) -> list[str]:
    """Validate schema plus source grounding, side polarity, IDs, and coverage."""
    schema = load_patch_spec_schema()
    errors = validate_json_schema(spec, schema)
    if not isinstance(spec, dict) or errors:
        return errors

    source = spec.get("source", {})
    if not _HEX64_RE.fullmatch(str(source.get("metadata_sha256", ""))):
        errors.append("$.source.metadata_sha256: expected lowercase SHA-256")
    generation = spec.get("generation", {})
    if not _HEX64_RE.fullmatch(str(generation.get("cache_key", ""))):
        errors.append("$.generation.cache_key: expected lowercase SHA-256")

    for collection, key, id_kind in (
        (spec.get("hunks", []), "hunk_id", "hunk"),
        (spec.get("anchors", []), "anchor_id", "anchor"),
        (spec.get("behaviors", []), "behavior_id", "behavior"),
    ):
        ids = [item.get(key) for item in collection if isinstance(item, dict)]
        duplicates = _duplicates([item for item in ids if isinstance(item, str)])
        if duplicates:
            errors.append(f"$.{key}: duplicate ids: {duplicates}")
        for item in ids:
            if not isinstance(item, str) or not _ID_RE[id_kind].fullmatch(item):
                errors.append(f"$.{key}: invalid stable id {item!r}")

    hunk_ids = [hunk.get("hunk_id") for hunk in spec.get("hunks", [])]
    anchor_by_id = {
        anchor.get("anchor_id"): anchor
        for anchor in spec.get("anchors", [])
        if isinstance(anchor, dict)
    }
    covered: list[str] = []
    for behavior_index, behavior in enumerate(spec.get("behaviors", [])):
        path = f"$.behaviors[{behavior_index}]"
        behavior_hunks = behavior.get("hunk_ids", [])
        covered.extend(behavior_hunks)
        if any(hunk_id not in hunk_ids for hunk_id in behavior_hunks):
            errors.append(f"{path}.hunk_ids: references an unknown hunk")
        for anchor_id in behavior.get("function_anchor_ids", []):
            anchor = anchor_by_id.get(anchor_id)
            if not anchor or anchor.get("kind") != "function":
                errors.append(f"{path}.function_anchor_ids: {anchor_id!r} is not a function anchor")
        trusted = behavior.get("trusted", {})
        side_values: dict[str, set[str]] = {"old": set(), "new": set()}
        for side in ("old", "new"):
            for indicator_index, indicator in enumerate(trusted.get(f"{side}_indicators", [])):
                ref = indicator.get("ref")
                kind = indicator.get("kind")
                indicator_path = f"{path}.trusted.{side}_indicators[{indicator_index}]"
                line_match = re.fullmatch(
                    r"/patch_hunk/(\d+)/(old|new)_lines/(\d+)", str(ref)
                )
                sequence_match = re.fullmatch(
                    r"/patch_hunk/(\d+)/(old|new)_lines", str(ref)
                )
                match = line_match if kind == "source_line" else sequence_match
                if kind not in {"source_line", "source_sequence"} or not match:
                    errors.append(
                        f"{indicator_path}.ref: kind/ref must identify a source line or side sequence"
                    )
                    continue
                if match.group(2) != side:
                    errors.append(f"{indicator_path}.ref: must reference a {side}-side patch value")
                    continue
                ref_hunk = f"H{int(match.group(1)) + 1:03d}"
                if ref_hunk not in behavior_hunks:
                    errors.append(f"{indicator_path}.ref: line is outside behavior hunk_ids")
                if metadata is not None:
                    try:
                        actual = resolve_json_pointer(prepare_metadata(metadata, cve_id), ref)
                    except (KeyError, PatchSpecMetadataError):
                        errors.append(f"{indicator_path}.ref: does not resolve in source metadata")
                        continue
                    if actual != indicator.get("value"):
                        errors.append(f"{indicator_path}.value: does not equal the referenced source line")
                value = indicator.get("value")
                normalized_value = _normalized_indicator_value(value)
                if normalized_value is None:
                    errors.append(f"{indicator_path}.value: invalid for indicator kind {kind!r}")
                else:
                    side_values[side].add(normalized_value)
        overlap = sorted(side_values["old"] & side_values["new"])
        if overlap:
            errors.append(f"{path}.trusted: identical old/new indicators are not discriminative: {overlap}")
        if not side_values["old"] and not side_values["new"]:
            errors.append(f"{path}.trusted: at least one grounded indicator is required")
        advisory = behavior.get("advisory", {})
        if _normalized_source_line(str(advisory.get("old_semantics", ""))) == _normalized_source_line(
            str(advisory.get("new_semantics", ""))
        ):
            errors.append(f"{path}.advisory: old_semantics and new_semantics must differ")
        if any(_ADVISORY_FORBIDDEN_RE.search(text) for text in _iter_strings(advisory)):
            errors.append(
                f"{path}.advisory: must not contain release versions, host paths, or ground-truth labels"
            )

    duplicate_coverage = _duplicates(covered)
    if duplicate_coverage:
        errors.append(f"$.coverage: hunks must belong to exactly one behavior: {duplicate_coverage}")
    expected_covered = [hunk_id for hunk_id in hunk_ids if hunk_id in set(covered)]
    expected_uncovered = [hunk_id for hunk_id in hunk_ids if hunk_id not in set(covered)]
    coverage = spec.get("coverage", {})
    if coverage.get("all_hunk_ids") != hunk_ids:
        errors.append("$.coverage.all_hunk_ids: must exactly match hunks")
    if coverage.get("covered_hunk_ids") != expected_covered:
        errors.append("$.coverage.covered_hunk_ids: does not match behavior coverage")
    if coverage.get("uncovered_hunk_ids") != expected_uncovered:
        errors.append("$.coverage.uncovered_hunk_ids: does not match behavior coverage")
    if expected_uncovered:
        errors.append(f"$.coverage: security-relevant hunks are uncovered: {expected_uncovered}")

    if metadata is not None:
        try:
            prepared = prepare_metadata(metadata, cve_id)
            if source.get("cve_id") != prepared["cve_id"]:
                errors.append("$.source.cve_id: does not match source metadata")
            if source.get("project") != prepared["project"]:
                errors.append("$.source.project: does not match source metadata")
            if source.get("metadata_sha256") != metadata_sha256(prepared):
                errors.append("$.source.metadata_sha256: does not match source metadata")
            expected_hunks = build_hunks(prepared)
            if spec.get("hunks") != expected_hunks:
                errors.append("$.hunks: deterministic hunk IDs/refs differ from source metadata")
            expected_anchors = build_anchors(prepared)
            if spec.get("anchors") != expected_anchors:
                errors.append("$.anchors: contains missing, reordered, or ungrounded anchors")
            eligible = eligible_indicator_refs(prepared)
            for behavior_index, behavior in enumerate(spec.get("behaviors", [])):
                behavior_hunks = behavior.get("hunk_ids", [])
                for side in ("old", "new"):
                    selected = {
                        indicator.get("ref")
                        for indicator in behavior.get("trusted", {}).get(
                            f"{side}_indicators", []
                        )
                    }
                    allowed = {
                        ref
                        for hunk_id in behavior_hunks
                        for ref in eligible.get(hunk_id, {}).get(side, [])
                    }
                    for indicator in behavior.get("trusted", {}).get(f"{side}_indicators", []):
                        if indicator.get("ref") not in allowed:
                            errors.append(
                                f"$.behaviors[{behavior_index}].trusted.{side}_indicators: "
                                "ref is not a side-exclusive grounded indicator"
                            )
                    for hunk_id in behavior_hunks:
                        eligible_for_hunk = set(eligible.get(hunk_id, {}).get(side, []))
                        if eligible_for_hunk and not (eligible_for_hunk & selected):
                            errors.append(
                                f"$.behaviors[{behavior_index}].trusted.{side}_indicators: "
                                f"must select a grounded indicator for {hunk_id}"
                            )
        except PatchSpecMetadataError as exc:
            errors.append(f"$metadata: {exc}")
    return errors


def assert_valid_patch_spec(
    spec: Any,
    metadata: dict[str, Any] | None = None,
    cve_id: str | None = None,
) -> None:
    errors = validate_patch_spec(spec, metadata, cve_id)
    if errors:
        raise PatchSpecValidationError(errors)


def patch_spec_digest(spec: dict[str, Any]) -> str:
    """Hash semantic/trusted content while excluding generation provenance."""
    assert_valid_patch_spec(spec)
    semantic = {key: value for key, value in spec.items() if key != "generation"}
    return hashlib.sha256(canonical_json(semantic).encode("utf-8")).hexdigest()


def prompt_view(spec: dict[str, Any]) -> dict[str, Any]:
    """Return a compact investigation view without provenance or duplicated source."""
    assert_valid_patch_spec(spec)
    view = copy.deepcopy({key: value for key, value in spec.items() if key != "generation"})
    # Exact source text is supplied once through resolve_source_excerpts(). Keep
    # refs in the spec, but avoid sending the same hunk/indicator lines twice.
    for hunk in view.get("hunks", []):
        hunk.pop("old_line_refs", None)
        hunk.pop("new_line_refs", None)
    for behavior in view.get("behaviors", []):
        trusted = behavior.get("trusted", {})
        for side in ("old_indicators", "new_indicators"):
            for indicator in trusted.get(side, []):
                indicator.pop("value", None)
    return view


def resolve_source_excerpts(
    metadata: dict[str, Any], spec: dict[str, Any], cve_id: str | None = None
) -> list[dict[str, Any]]:
    """Resolve only leaf refs needed by the investigation prompt."""
    prepared = prepare_metadata(metadata, cve_id)
    assert_valid_patch_spec(spec, prepared)
    refs: set[str] = set()
    for behavior in spec["behaviors"]:
        for side in ("old_indicators", "new_indicators"):
            refs.update(item["ref"] for item in behavior["trusted"][side])
    excerpts: list[dict[str, Any]] = []
    for ref in sorted(refs):
        value = resolve_json_pointer(prepared, ref)
        if isinstance(value, dict):
            raise PatchSpecValidationError([f"source excerpt ref is not a source value: {ref}"])
        if isinstance(value, list) and not all(isinstance(item, str) for item in value):
            raise PatchSpecValidationError([f"source excerpt sequence is not a string array: {ref}"])
        excerpts.append({"ref": ref, "value": copy.deepcopy(value)})
    return excerpts


def model_input_view(metadata: dict[str, Any], cve_id: str | None = None) -> dict[str, Any]:
    """Build the allowlisted metadata view sent to the PatchSpec model."""
    prepared = prepare_metadata(metadata, cve_id)
    eligible = eligible_indicator_refs(prepared)
    hunks: list[dict[str, Any]] = []
    for hunk in build_hunks(prepared):
        hunk_id = hunk["hunk_id"]
        hunks.append({
            "hunk_id": hunk_id,
            "header": hunk["header"],
            "eligible_old_indicators": [
                {"ref": ref, "value": resolve_json_pointer(prepared, ref)}
                for ref in eligible[hunk_id]["old"]
            ],
            "eligible_new_indicators": [
                {"ref": ref, "value": resolve_json_pointer(prepared, ref)}
                for ref in eligible[hunk_id]["new"]
            ],
        })
    view: dict[str, Any] = {
        "cve_id": prepared["cve_id"],
        "project": prepared["project"],
        "functions": copy.deepcopy(prepared.get("functions", [])),
        "hunks": hunks,
    }
    if isinstance(prepared.get("cwe"), str):
        view["cwe"] = prepared["cwe"]
    description = prepared.get("vulnerability_description")
    if isinstance(description, str) and not _ADVISORY_FORBIDDEN_RE.search(description):
        view["vulnerability_description"] = description

    root_cause = prepared.get("root_cause_analysis")
    if isinstance(root_cause, dict):
        selected = {
            key: root_cause[key]
            for key in ("summary", "unsafe_mechanism")
            if isinstance(root_cause.get(key), str)
            and not _ADVISORY_FORBIDDEN_RE.search(root_cause[key])
        }
        if selected:
            view["root_cause_analysis"] = selected

    patch_intent = prepared.get("patch_intent_analysis")
    if isinstance(patch_intent, dict):
        selected = {
            key: patch_intent[key]
            for key in ("summary", "intended_security_property")
            if isinstance(patch_intent.get(key), str)
            and not _ADVISORY_FORBIDDEN_RE.search(patch_intent[key])
        }
        behavior_changes = patch_intent.get("behavior_changes")
        if isinstance(behavior_changes, list) and all(
            isinstance(item, str) for item in behavior_changes
        ):
            safe_changes = [
                item for item in behavior_changes if not _ADVISORY_FORBIDDEN_RE.search(item)
            ]
            if safe_changes:
                selected["behavior_changes"] = copy.deepcopy(safe_changes)
        if selected:
            view["patch_intent_analysis"] = selected

    reduced = prepared.get("reduced_function_code")
    if isinstance(reduced, list):
        function_names = set(prepared.get("functions", []))
        safe_reduced = [
            {
                key: value
                for key, value in item.items()
                if key in function_names and isinstance(value, str)
            }
            for item in reduced
            if isinstance(item, dict)
        ]
        safe_reduced = [item for item in safe_reduced if item]
        if safe_reduced:
            view["reduced_function_code"] = safe_reduced
    return view
