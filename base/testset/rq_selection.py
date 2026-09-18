from __future__ import annotations

import json
import re
import shlex
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from RCA.related_file_allowlist import GitSnapshot, _find_function, _is_static_function, walk
from utils.io import write_json


SELECTION_SCHEMA = "rq2-rq3-selection.v1"
RQ3_TAGS = (
    "subtle_modification",
    "function_structural_modification",
    "symbol_duplication",
    "conditional_compilation",
    "security_irrelevant_change",
)
SEMANTIC_TAGS = ("input_sanitization", "data_structure_change", "function_change")
CONTROL_KEYWORDS = {"if", "switch", "for", "while", "do", "case"}
CALL_KEYWORDS = CONTROL_KEYWORDS | {"return", "sizeof", "defined"}
SOURCE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".cxx"}

_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_CONTROL_RE = re.compile(r"\b(?:if|switch|for|while|do|case)\b")
_VALIDATION_RE = re.compile(
    r"\b(?:check|valid|invalid|reject|error|fail|assert|bound|range|limit|max|min|len|length|size|count|overflow|underflow)\b",
    re.IGNORECASE,
)
_DATA_RE = re.compile(r"\b(?:struct|union|enum|typedef|sizeof|alloc|malloc|calloc|realloc|free)\b", re.IGNORECASE)
_STATE_RE = re.compile(r"\b(?:state|status|flag|mode|phase|transition|context|session)\b", re.IGNORECASE)
_MEMORY_RE = re.compile(r"\b(?:memcpy|memmove|memset|strcpy|strcat|buffer|alloc|malloc|calloc|realloc|free)\b", re.IGNORECASE)
_ARITHMETIC_RE = re.compile(r"\b(?:int(?:8|16|32|64)_t|size_t|ssize_t|overflow|underflow|cast)\b|\([^)]*\*[^)]*\)", re.IGNORECASE)
_ERROR_RE = re.compile(r"\b(?:goto\s+err|return\s+(?:-?\w+|NULL)|error|fail|abort|reject)\b", re.IGNORECASE)
_BINARY_FEATURE_ABSENCE_RE = re.compile(
    r"(?:"
    r"(?:target|stripped|debug(?:\s+companion)?)\s+binary.{0,100}?(?:does\s+not|lacks?|absent|not\s+(?:linked|built|compiled)).{0,100}?"
    r"(?:backend|feature|code(?:\s+path)?|component|CONFIG_[A-Z0-9_]+|link)"
    r"|(?:backend|feature|CONFIG_[A-Z0-9_]+).{0,100}?(?:does\s+not|lacks?|absent|disabled|not\s+(?:linked|built|compiled))"
    r"|(?:does\s+not\s+link|not\s+linked|compiled\s+out)"
    r")",
    re.IGNORECASE,
)


def _load_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _export_name(stem: str, suffix: str) -> str:
    return f"{stem}.{suffix}.json" if suffix else f"{stem}.json"


def _resolve_input_paths(project: str, exports: Path, variant: str) -> tuple[Path, Path, str]:
    if variant:
        suffix = variant
        pick = exports / _export_name("testset.pick", suffix)
    else:
        canonical = exports / "testset.pick.json"
        if canonical.is_file():
            pick = canonical
            suffix = ""
        else:
            candidates = sorted(exports.glob("testset.pick.*.json"))
            if not candidates:
                raise ValueError(f"no testset.pick export found under {exports}")
            preferred = [path for path in candidates if path.name == "testset.pick.gcc-O2.json"]
            pick = preferred[0] if preferred else candidates[0]
            suffix = pick.name.removeprefix("testset.pick.").removesuffix(".json")
    if not pick.is_file():
        raise ValueError(f"testset pick export does not exist: {pick}")

    groundtruth = exports / _export_name("groundtruth_with_not_affected", suffix)
    if not groundtruth.is_file():
        groundtruth = exports / _export_name("groundtruth", suffix)
    if not groundtruth.is_file():
        raise ValueError(f"no matching groundtruth export for {pick.name}")
    return pick, groundtruth, suffix


def _diff_path(metadata: dict[str, Any], output: Path, project: str, cve_id: str) -> Path | None:
    related = metadata.get("diff_related") or []
    for item in related:
        if not isinstance(item, dict):
            continue
        value = str(item.get("file") or "")
        if not value:
            continue
        candidate = Path(value)
        if candidate.is_file():
            return candidate
    candidates = sorted((output / "Diff" / project / "diff_files").glob(f"*{cve_id}*.diff"))
    return candidates[0] if candidates else None


def _source_path(path: str) -> bool:
    return Path(path).suffix.lower() in SOURCE_SUFFIXES


def _parse_diff(text: str) -> dict[str, dict[str, list[tuple[int, str]]]]:
    """Return per-file, line-numbered C-family additions and removals."""
    files: dict[str, dict[str, list[tuple[int, str]]]] = {}
    current = ""
    old_line = new_line = 0
    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            try:
                parts = shlex.split(raw)
            except ValueError:
                current = ""
                continue
            if len(parts) >= 4:
                old_path = parts[2].removeprefix("a/")
                new_path = parts[3].removeprefix("b/")
                current = new_path if new_path != "/dev/null" else old_path
                files.setdefault(current, {"added": [], "removed": []})
            continue
        if not current:
            continue
        match = re.match(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
        if match:
            old_line, new_line = int(match.group(1)), int(match.group(2))
            continue
        if raw.startswith("+++") or raw.startswith("---"):
            continue
        if raw.startswith("+"):
            files[current]["added"].append((new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-"):
            files[current]["removed"].append((old_line, raw[1:]))
            old_line += 1
        elif raw.startswith("\\"):
            continue
        else:
            old_line += 1
            new_line += 1
    return {path: data for path, data in files.items() if _source_path(path)}


def _strip_line(line: str) -> str:
    line = re.sub(r"//.*$", "", line)
    line = re.sub(r"/\*.*?\*/", "", line)
    return line.strip()


def _normalise_line(line: str) -> str:
    return re.sub(r"\s+", "", _strip_line(line))


def _calls(lines: list[str]) -> set[str]:
    return {
        name
        for line in lines
        for name in _CALL_RE.findall(line)
        if name not in CALL_KEYWORDS
    }


def _diff_metrics(diff_text: str) -> dict[str, Any]:
    files = _parse_diff(diff_text)
    added = [line for data in files.values() for _, line in data["added"]]
    removed = [line for data in files.values() for _, line in data["removed"]]
    code_added = [line for line in added if _strip_line(line)]
    code_removed = [line for line in removed if _strip_line(line)]
    text = "\n".join([*code_added, *code_removed])
    added_calls, removed_calls = _calls(code_added), _calls(code_removed)
    normalized_added = Counter(_normalise_line(line) for line in added if _normalise_line(line))
    normalized_removed = Counter(_normalise_line(line) for line in removed if _normalise_line(line))
    formatting_only = sum((normalized_added & normalized_removed).values())
    branch_added = bool(_CONTROL_RE.search("\n".join(code_added)))
    call_changed = added_calls != removed_calls
    signals: set[str] = set()
    if _VALIDATION_RE.search(text):
        signals.add("validation")
    if re.search(r"\b(?:len|length|size|count|limit|max|min|bound|range|overflow|underflow)\b", text, re.IGNORECASE):
        signals.add("bounds")
    if _ARITHMETIC_RE.search(text):
        signals.add("arithmetic")
    if _MEMORY_RE.search(text):
        signals.add("memory")
    if call_changed:
        signals.add("api_call")
    if _DATA_RE.search(text):
        signals.add("data_layout")
    if _STATE_RE.search(text):
        signals.add("state")
    if _ERROR_RE.search(text):
        signals.add("error_handling")
    return {
        "files": files,
        "patch_size": max(len(code_added), len(code_removed)),
        "added_lines": code_added,
        "removed_lines": code_removed,
        "branch_added": branch_added,
        "call_changed": call_changed,
        "signals": sorted(signals),
        "formatting_only_lines": formatting_only,
    }


def _function_locations(metadata: dict[str, Any], behavior: dict[str, Any]) -> dict[str, dict[str, Any]]:
    locations: dict[str, dict[str, Any]] = {}
    for location in ((behavior.get("patch_source") or {}).get("locations") or []):
        if not isinstance(location, dict) or not location.get("function"):
            continue
        locations.setdefault(str(location["function"]), dict(location))
    for function, item in ((metadata.get("function_code") or {}).get("by_function") or {}).items():
        entry = locations.setdefault(str(function), {})
        if isinstance(item, dict):
            entry.setdefault("file", str(item.get("file") or ""))
            entry.setdefault("change_type", str(item.get("change_type") or ""))
    return locations


def _function_stats(snapshot: GitSnapshot, path: str, function: str) -> tuple[int, int, bool]:
    source = snapshot.content(path)
    tree = snapshot.tree(path)
    if source is None or tree is None:
        return 0, 0, False
    node = _find_function(tree, source.encode("utf-8", errors="ignore"), function)
    if node is None:
        return 0, 0, False
    line_count = node.end_point[0] - node.start_point[0] + 1
    branch_types = {"if_statement", "switch_statement", "for_statement", "while_statement", "do_statement", "case_statement"}
    estimated_blocks = 1 + sum(1 for item in walk(node) if item.type in branch_types)
    return line_count, estimated_blocks, _is_static_function(node, source.encode("utf-8", errors="ignore"))


def _function_signature(snapshot: GitSnapshot, path: str, function: str) -> str:
    source = snapshot.content(path)
    tree = snapshot.tree(path)
    if source is None or tree is None:
        return ""
    source_bytes = source.encode("utf-8", errors="ignore")
    node = _find_function(tree, source_bytes, function)
    if node is None:
        return ""
    for child in walk(node):
        if child.type == "function_declarator":
            return source_bytes[child.start_byte : child.end_byte].decode("utf-8", errors="ignore").strip()
    return ""


def _duplicate_static_definition(snapshot: GitSnapshot, function: str, origin_path: str) -> bool:
    if not origin_path:
        return False
    source = snapshot.content(origin_path)
    tree = snapshot.tree(origin_path)
    if source is None or tree is None:
        return False
    origin_node = _find_function(tree, source.encode("utf-8", errors="ignore"), function)
    if origin_node is None or not _is_static_function(origin_node, source.encode("utf-8", errors="ignore")):
        return False
    candidates = snapshot.grep_files(rf"\b{re.escape(function)}\s*\(")
    definitions = []
    for path in candidates:
        candidate_source = snapshot.content(path)
        candidate_tree = snapshot.tree(path)
        if candidate_source is None or candidate_tree is None:
            continue
        node = _find_function(candidate_tree, candidate_source.encode("utf-8", errors="ignore"), function)
        if node is not None:
            definitions.append(path)
            if len(definitions) > 1:
                return True
    return False


def _duplicate_debug_symbol(output: Path, project: str, binaries: list[str], function: str) -> bool:
    """Verify duplicate local/global names in an actual target debug companion."""
    debug_dir = output / "binaries" / "target" / f"{project}_debug"
    if not debug_dir.is_dir():
        return False
    for binary in binaries:
        candidates = sorted(debug_dir.glob(f"{binary}-*.debug"))
        for debug_file in candidates:
            try:
                proc = subprocess.run(
                    ["nm", "-a", "--defined-only", "--format=posix", str(debug_file)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    check=False,
                    timeout=30,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            if proc.returncode != 0:
                continue
            definitions = sum(1 for line in proc.stdout.splitlines() if line.split(maxsplit=1)[:1] == [function])
            if definitions > 1:
                return True
    return False


def _review_index(exports: Path) -> dict[str, list[dict[str, Any]]]:
    indexed: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in sorted(exports.glob("not_affected_candidates*.json")):
        for item in _load_json(path, []):
            if not isinstance(item, dict) or not item.get("CVE"):
                continue
            record = dict(item)
            record["_source"] = path.name
            indexed[str(item["CVE"])].append(record)
    return indexed


def _repair_pick_from_tri_state(pick: dict[str, Any], groundtruth: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Keep a 1v1 pick valid after affectedness review relabels old endpoints."""
    original = list(pick.get("binaries") or [])
    selected: list[str] = []
    for label, fallback_index in (("vuln", 0), ("patch", -1)):
        labeled = list(groundtruth.get(label) or [])
        from_original = [binary for binary in original if binary in labeled]
        if from_original:
            selected.append(from_original[0])
        elif labeled:
            selected.append(sorted(labeled)[fallback_index])
    repaired = {
        "CVE": pick.get("CVE", ""),
        "functions": list(pick.get("functions") or groundtruth.get("functions") or []),
        "binaries": list(dict.fromkeys(selected)),
    }
    return repaired, repaired["binaries"] != original


def _variant_coverage(exports: Path) -> dict[str, list[str]]:
    variants: dict[str, set[str]] = defaultdict(set)
    for path in sorted(exports.glob("groundtruth.*.json")):
        suffix = path.name.removeprefix("groundtruth.").removesuffix(".json")
        if not re.fullmatch(r"(?:(?:aarch64)-)?(?:gcc|clang)-O[0-3]", suffix):
            continue
        for item in _load_json(path, []):
            if isinstance(item, dict) and item.get("CVE"):
                variants[str(item["CVE"])].add(suffix)
    return {cve_id: sorted(values) for cve_id, values in variants.items()}


def _cwe_values(metadata: dict[str, Any], behavior: dict[str, Any]) -> list[str]:
    raw = metadata.get("cwe") or behavior.get("cwe") or []
    if isinstance(raw, str):
        raw = [raw]
    values = [str(value) for value in raw if str(value)]
    return sorted(set(values)) or ["CWE-unknown"]


def _quantile_thresholds(values: list[int]) -> list[int]:
    ordered = sorted(value for value in values if value > 0)
    if not ordered:
        return []
    return [ordered[round((len(ordered) - 1) * fraction)] for fraction in (0.25, 0.50, 0.75)]


def _quantile(value: int, thresholds: list[int]) -> str:
    if not value or not thresholds:
        return "unknown"
    for index, threshold in enumerate(thresholds, start=1):
        if value <= threshold:
            return f"Q{index}"
    return "Q4"


def _semantic_categories(metrics: dict[str, Any], structural: bool, intent: str) -> list[str]:
    source = "\n".join([*metrics["added_lines"], *metrics["removed_lines"]])
    categories: list[str] = []
    if (metrics["branch_added"] and _VALIDATION_RE.search("\n".join(metrics["added_lines"]))) or re.search(
        r"\b(?:input sanit|validate|validation|bounds check|range check)\b", intent, re.IGNORECASE
    ):
        categories.append("input_sanitization")
    if _DATA_RE.search(source) or re.search(r"\b(?:data structure|struct(?:ure)? layout|field layout|object lifetime)\b", intent, re.IGNORECASE):
        categories.append("data_structure_change")
    if metrics["call_changed"] or structural or re.search(r"\b(?:function call|argument|parameter|callee|API)\b", intent, re.IGNORECASE):
        categories.append("function_change")
    return categories


def _review_text(items: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for item in items:
        review = item.get("review") or {}
        parts.append(str(review.get("reason") or ""))
        parts.extend(str(value) for value in (review.get("evidence") or []))
    return "\n".join(parts)


def _profile_cve(
    *,
    cve_id: str,
    metadata: dict[str, Any],
    behavior: dict[str, Any],
    pick: dict[str, Any],
    groundtruth: dict[str, Any],
    reviews: list[dict[str, Any]],
    variants: list[str],
    output: Path,
    project: str,
    repo: Path,
) -> dict[str, Any]:
    diff_path = _diff_path(metadata, output, project, cve_id)
    diff_text = diff_path.read_text(encoding="utf-8", errors="ignore") if diff_path else ""
    metrics = _diff_metrics(diff_text)
    locations = _function_locations(metadata, behavior)
    change_types = {str(item.get("change_type") or "") for item in locations.values()}
    structural = bool({"added", "deleted"} & change_types)
    functions = list(pick.get("functions") or metadata.get("functions") or [])
    intent = json.dumps(behavior.get("patch_intent_analysis") or {}, ensure_ascii=False)
    commit = str((metadata.get("function_code") or {}).get("commit") or "")
    snapshot = GitSnapshot(repo, commit)
    parent_snapshot = GitSnapshot(repo, f"{commit}^") if commit else None

    function_lines = 0
    estimated_blocks = 0
    source_duplicate = False
    for function in functions:
        location = locations.get(str(function), {})
        file_path = str(location.get("file") or "")
        line_range = location.get("function_line_range") or []
        if isinstance(line_range, list) and len(line_range) == 2:
            try:
                function_lines = max(function_lines, int(line_range[1]) - int(line_range[0]) + 1)
            except (TypeError, ValueError):
                pass
        if file_path:
            lines, blocks, _ = _function_stats(snapshot, file_path, str(function))
            function_lines = max(function_lines, lines)
            estimated_blocks = max(estimated_blocks, blocks)
            source_duplicate = source_duplicate or _duplicate_static_definition(snapshot, str(function), file_path)
            if parent_snapshot:
                before = _function_signature(parent_snapshot, file_path, str(function))
                after = _function_signature(snapshot, file_path, str(function))
                structural = structural or bool(before != after and (before or after))
    duplicate_symbol = source_duplicate and any(
        _duplicate_debug_symbol(output, project, list(pick.get("binaries") or []), str(function)) for function in functions
    )

    semantic = _semantic_categories(metrics, structural, intent)
    signals = set(metrics["signals"])
    if structural:
        signals.add("function_structure")
    complexity = "3+" if len(signals) >= 3 else str(max(1, len(signals)))
    text = "\n".join([*metrics["added_lines"], *metrics["removed_lines"], intent])
    subtle = (
        0 < metrics["patch_size"] <= 8
        and not metrics["branch_added"]
        and not metrics["call_changed"]
        and not structural
        and bool(re.search(r"(?:->|\.|\b(?:int|long|short|char|size_t|const)\b|\b\d+\b|[=!<>]=?|\+|-)", text))
    )
    irrelevant = bool(metrics["formatting_only_lines"] and metrics["patch_size"] > metrics["formatting_only_lines"])
    review_statuses = sorted(
        {
            str((item.get("review") or {}).get("status") or "")
            for item in reviews
            if (item.get("review") or {}).get("status")
        }
    )
    review_text = _review_text(reviews)
    # RQ3's conditional-compilation failure requires an observable artifact-level
    # consequence, not merely a source file that happens to live under #if.
    # A strict tri-state not_affected label is that evidence: the selected source
    # CVE exists, but this target lacks the relevant compiled feature/code path.
    labels = {
        label: list(groundtruth.get(label) or [])
        for label in ("vuln", "patch", "not_affected")
    }
    conditional = bool(labels["not_affected"]) and bool(_BINARY_FEATURE_ABSENCE_RE.search(review_text))
    rq3: list[str] = []
    if subtle:
        rq3.append("subtle_modification")
    if structural:
        rq3.append("function_structural_modification")
    if duplicate_symbol:
        rq3.append("symbol_duplication")
    if conditional:
        rq3.append("conditional_compilation")
    if irrelevant:
        rq3.append("security_irrelevant_change")
    pick_labels = {name: label for label, names in labels.items() for name in names}
    valid_pair = all(any(pick_labels.get(name) == label for name in pick.get("binaries") or []) for label in ("vuln", "patch"))
    return {
        "cve_id": cve_id,
        "functions": functions,
        "cwe": _cwe_values(metadata, behavior),
        "diff_path": str(diff_path) if diff_path else "",
        "patch_size_lines": metrics["patch_size"],
        "function_size_lines": function_lines,
        "estimated_control_blocks": estimated_blocks,
        "semantic_categories": semantic,
        "semantic_signals": sorted(signals),
        "semantic_complexity": complexity,
        "rq3_categories": rq3,
        "not_affected_binaries": labels["not_affected"],
        "review_statuses": review_statuses,
        "available_compiler_variants": variants,
        "valid_pair": valid_pair,
        "pick_repaired_after_review": bool(pick.get("_repaired_after_review")),
        "patch_evolution": "patch_evolution" in review_statuses,
        "source_analysis_available": bool(diff_path and functions),
    }


def _selection_score(
    profile: dict[str, Any], covered: dict[str, set[str]], rq3_counts: Counter[str]
) -> tuple[float, list[str]]:
    reasons: list[str] = []
    score = 0.0
    for tag in profile["rq3_categories"]:
        if tag not in covered["rq3"]:
            score += 24.0
            reasons.append(f"covers RQ3 {tag}")
        elif rq3_counts[tag] >= 2:
            score -= 4.0 * (rq3_counts[tag] - 1)
    for tag in profile["semantic_categories"]:
        if tag not in covered["semantic"]:
            score += 8.0
            reasons.append(f"covers RQ2 {tag}")
    complexity = profile["semantic_complexity"]
    if complexity not in covered["complexity"]:
        score += 5.0
        reasons.append(f"covers RQ2 complexity {complexity}")
    for key, weight, label in (("patch_size_bucket", 3.0, "patch-size"), ("function_size_bucket", 3.0, "function-size")):
        value = profile[key]
        if value != "unknown" and value not in covered[key]:
            score += weight
            reasons.append(f"covers RQ2 {label} {value}")
    for cwe in profile["cwe"]:
        if cwe not in covered["cwe"]:
            score += 2.0
            reasons.append(f"adds CWE {cwe}")
            break
    for variant in profile["available_compiler_variants"]:
        if variant not in covered["compiler"]:
            score += 1.5
            reasons.append(f"adds compiler variant {variant}")
            break
    score += min(len(profile["semantic_signals"]), 5) * 0.3
    if profile["patch_size_bucket"] == "Q4":
        score += 0.6
    if profile["function_size_bucket"] == "Q4":
        score += 0.6
    return score, reasons


def _select_profiles(profiles: list[dict[str, Any]], count: int) -> list[dict[str, Any]]:
    remaining = list(profiles)
    selected: list[dict[str, Any]] = []
    covered: dict[str, set[str]] = defaultdict(set)
    rq3_counts: Counter[str] = Counter()
    while remaining and len(selected) < count:
        scored = []
        for profile in remaining:
            score, reasons = _selection_score(profile, covered, rq3_counts)
            scored.append((score, len(profile["rq3_categories"]), len(profile["semantic_signals"]), profile["cve_id"], profile, reasons))
        _, _, _, _, chosen, reasons = max(scored, key=lambda item: (item[0], item[1], item[2], item[3]))
        chosen = dict(chosen)
        chosen["selection_score"] = round(_selection_score(chosen, covered, rq3_counts)[0], 2)
        chosen["selection_reasons"] = reasons or ["fills remaining diverse, difficult candidate pool"]
        selected.append(chosen)
        covered["rq3"].update(chosen["rq3_categories"])
        rq3_counts.update(chosen["rq3_categories"])
        covered["semantic"].update(chosen["semantic_categories"])
        covered["complexity"].add(chosen["semantic_complexity"])
        if chosen["patch_size_bucket"] != "unknown":
            covered["patch_size_bucket"].add(chosen["patch_size_bucket"])
        if chosen["function_size_bucket"] != "unknown":
            covered["function_size_bucket"].add(chosen["function_size_bucket"])
        covered["cwe"].update(chosen["cwe"])
        covered["compiler"].update(chosen["available_compiler_variants"])
        remaining = [profile for profile in remaining if profile["cve_id"] != chosen["cve_id"]]
    return selected


def _filtered_exports(
    selected: list[dict[str, Any]], pick_items: dict[str, dict[str, Any]], groundtruth: dict[str, dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    testset: list[dict[str, Any]] = []
    gt: list[dict[str, Any]] = []
    for profile in selected:
        cve_id = profile["cve_id"]
        pick = pick_items[cve_id]
        labels = groundtruth[cve_id]
        binaries = list(pick.get("binaries") or [])
        if "conditional_compilation" in profile["rq3_categories"] and profile["not_affected_binaries"]:
            binaries.append(sorted(profile["not_affected_binaries"])[0])
        binaries = list(dict.fromkeys(binaries))
        binary_set = set(binaries)
        testset.append({"CVE": cve_id, "functions": list(pick.get("functions") or []), "binaries": binaries})
        gt.append(
            {
                "CVE": cve_id,
                "functions": list(labels.get("functions") or pick.get("functions") or []),
                "vuln": [name for name in labels.get("vuln") or [] if name in binary_set],
                "patch": [name for name in labels.get("patch") or [] if name in binary_set],
                "not_affected": [name for name in labels.get("not_affected") or [] if name in binary_set],
            }
        )
    return testset, gt


def select_rq2_rq3_testset(
    *, project: str, repo: Path, output: Path, count: int = 20, variant: str = ""
) -> dict[str, Any]:
    """Create a deterministic, RQ2/RQ3-stratified experiment subset from existing exports."""
    if count < 1:
        raise ValueError("count must be >= 1")
    output = output.expanduser().resolve()
    repo = repo.expanduser().resolve()
    exports = output / "exports"
    pick_path, groundtruth_path, suffix = _resolve_input_paths(project, exports, variant)
    metadata_path = exports / f"{project}_metadata.json"
    if not metadata_path.is_file() and suffix.startswith("aarch64-"):
        metadata_path = exports / f"{project}_metadata.aarch64.json"
    metadata = _load_json(metadata_path, {})
    behavior = _load_json(exports / f"{project}_behavior.json", {})
    pick_items = {str(item["CVE"]): item for item in _load_json(pick_path, []) if isinstance(item, dict) and item.get("CVE")}
    groundtruth = {str(item["CVE"]): item for item in _load_json(groundtruth_path, []) if isinstance(item, dict) and item.get("CVE")}
    reviews = _review_index(exports)
    variants = _variant_coverage(exports)

    profiles: list[dict[str, Any]] = []
    effective_picks: dict[str, dict[str, Any]] = {}
    excluded: dict[str, list[str]] = defaultdict(list)
    for cve_id in sorted(set(pick_items) & set(groundtruth) & set(metadata)):
        effective_pick, repaired = _repair_pick_from_tri_state(pick_items[cve_id], groundtruth[cve_id])
        effective_pick["_repaired_after_review"] = repaired
        effective_picks[cve_id] = effective_pick
        profile = _profile_cve(
            cve_id=cve_id,
            metadata=metadata[cve_id],
            behavior=behavior.get(cve_id) or {},
            pick=effective_pick,
            groundtruth=groundtruth[cve_id],
            reviews=reviews.get(cve_id, []),
            variants=variants.get(cve_id, []),
            output=output,
            project=project,
            repo=repo,
        )
        if profile["patch_evolution"]:
            excluded["patch_evolution"].append(cve_id)
            continue
        if not profile["valid_pair"]:
            excluded["missing_vuln_patch_pair"].append(cve_id)
            continue
        if not profile["source_analysis_available"]:
            excluded["missing_source_analysis"].append(cve_id)
            continue
        profiles.append(profile)

    patch_thresholds = _quantile_thresholds([profile["patch_size_lines"] for profile in profiles])
    function_thresholds = _quantile_thresholds([profile["estimated_control_blocks"] for profile in profiles])
    for profile in profiles:
        profile["patch_size_bucket"] = _quantile(profile["patch_size_lines"], patch_thresholds)
        profile["function_size_bucket"] = _quantile(profile["estimated_control_blocks"], function_thresholds)

    selected = _select_profiles(profiles, count)
    testset, gt = _filtered_exports(selected, effective_picks, groundtruth)
    selected_ids = {profile["cve_id"] for profile in selected}
    coverage = {
        "rq3": sorted({tag for profile in selected for tag in profile["rq3_categories"]}),
        "semantic_categories": sorted({tag for profile in selected for tag in profile["semantic_categories"]}),
        "semantic_complexity": sorted({profile["semantic_complexity"] for profile in selected}),
        "patch_size_buckets": sorted({profile["patch_size_bucket"] for profile in selected if profile["patch_size_bucket"] != "unknown"}),
        "function_size_buckets": sorted(
            {profile["function_size_bucket"] for profile in selected if profile["function_size_bucket"] != "unknown"}
        ),
        "cwes": sorted({cwe for profile in selected for cwe in profile["cwe"]}),
        "compiler_variants": sorted({variant for profile in selected for variant in profile["available_compiler_variants"]}),
    }
    manifest = {
        "schema": SELECTION_SCHEMA,
        "project": project,
        "repo_path": str(repo),
        "source_pick": str(pick_path),
        "source_groundtruth": str(groundtruth_path),
        "variant": suffix or "canonical",
        "requested_count": count,
        "selected_count": len(selected),
        "rule": {
            "patch_evolution": "excluded when any retained affectedness review records patch_evolution",
            "rq3": list(RQ3_TAGS),
            "rq2": {
                "semantic_categories": list(SEMANTIC_TAGS),
                "semantic_complexity": "deterministic source-diff signal count (1, 2, or 3+)",
                "function_size": "estimated control-block quartile within this project",
                "patch_size": "modified source-line quartile within this project",
                "compiler_options": "recorded available export variants",
                "cwe": "metadata diversity signal, not a causal difficulty claim",
            },
            "selection": "greedy maximum coverage, then difficulty and CWE/compiler diversity; deterministic CVE-id tie-break",
            "tri_state_repair": "if a legacy 1v1 endpoint was relabeled not_affected, replace only that endpoint with a valid current vuln/patch target",
        },
        "thresholds": {"patch_size_lines": patch_thresholds, "estimated_control_blocks": function_thresholds},
        "coverage": coverage,
        "selected": selected,
        "excluded": {reason: sorted(cves) for reason, cves in sorted(excluded.items())},
        "eligible_count": len(profiles),
        "unselected_eligible_count": len(profiles) - len(selected_ids),
    }
    output_suffix = suffix
    testset_path = exports / _export_name("pretest.rq2-rq3.pick", output_suffix)
    gt_path = exports / _export_name("groundtruth.rq2-rq3.pick", output_suffix)
    manifest_path = exports / _export_name("rq2-rq3_selection_manifest", output_suffix)
    write_json(testset_path, testset)
    write_json(gt_path, gt)
    write_json(manifest_path, manifest)
    return {
        "project": project,
        "selected_count": len(selected),
        "eligible_count": len(profiles),
        "excluded_patch_evolution": len(excluded["patch_evolution"]),
        "testset": str(testset_path),
        "groundtruth": str(gt_path),
        "manifest": str(manifest_path),
        "coverage": coverage,
    }
