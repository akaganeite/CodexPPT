from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..versions import loose_version_candidates


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
DIFF_FILE_RE = re.compile(r"^diff --git a/(.*?) b/(.*?)$", re.MULTILINE)
DIFF_HUNK_RE = re.compile(r"^@@", re.MULTILINE)
EXPORT_DIR_NAMES = {"export", "exports"}


@dataclass
class CveMetadata:
    cve_id: str
    functions: list[str]
    summary: str = ""
    diff_evidence: list[Any] = field(default_factory=list)
    source_evidence: dict[str, Any] = field(default_factory=dict)
    fixed_versions: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    status: str = "ok"
    reason: str = ""

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def resolve_metadata_path(path: Path, project: str = "") -> Path:
    source = path.expanduser().resolve()
    if source.is_file():
        return source
    if not source.exists():
        raise FileNotFoundError(f"base metadata input does not exist: {source}")
    if not source.is_dir():
        raise ValueError(f"base metadata input is not a file or directory: {source}")

    directories = [source]
    for name in ("exports", "export"):
        candidate = source / name
        if candidate.is_dir():
            directories.append(candidate)
    if project:
        for directory in directories:
            candidate = directory / f"{project}_metadata.json"
            if candidate.is_file():
                return candidate.resolve()
    matches = sorted({candidate.resolve() for directory in directories for candidate in directory.glob("*_metadata.json")})
    if len(matches) == 1:
        return matches[0]
    if not matches:
        suffix = f"{project}_metadata.json" if project else "*_metadata.json"
        raise FileNotFoundError(f"no base metadata file {suffix} found under {source}")
    raise ValueError(f"multiple base metadata files found under {source}; specify the project or exact JSON path")


def load_metadata(path: Path, *, project: str = "", limit_cves: int = 0) -> list[CveMetadata]:
    metadata_path = resolve_metadata_path(path, project)
    raw = json.loads(metadata_path.read_text(encoding="utf-8"))
    items = normalize_metadata_items(raw)
    rows: list[CveMetadata] = []
    for cve_id, item in items:
        item = hydrate_base_metadata_item(item, metadata_path)
        functions = normalize_functions(item)
        fixed_versions = find_fixed_versions(item)
        row = CveMetadata(
            cve_id=cve_id,
            functions=functions,
            summary=str(item.get("summary") or item.get("description") or ""),
            diff_evidence=list(item.get("diff_related") or item.get("diff_evidence") or item.get("references") or []),
            source_evidence=dict(item.get("function_code") or item.get("source_evidence") or {}),
            fixed_versions=fixed_versions,
            raw=item,
        )
        if not row.functions:
            row.status = "metadata_incomplete"
            row.reason = "metadata does not contain changed functions"
        rows.append(row)
        if limit_cves and len(rows) >= limit_cves:
            break
    return rows


def hydrate_base_metadata_item(item: dict[str, Any], metadata_path: Path) -> dict[str, Any]:
    hydrated = dict(item)
    functions = normalize_functions(hydrated)
    function_code = dict(hydrated.get("function_code") or hydrated.get("source_evidence") or {})
    by_function = {
        str(function): dict(detail) if isinstance(detail, dict) else {}
        for function, detail in dict(function_code.get("by_function") or {}).items()
    }
    for function in functions:
        by_function.setdefault(function, {})

    diff_items = normalize_diff_evidence(
        hydrated.get("diff_related") or hydrated.get("diff_evidence") or hydrated.get("references") or [],
        metadata_path,
        functions,
        by_function,
    )
    function_code["by_function"] = by_function
    hydrated["functions"] = functions
    hydrated["function_code"] = function_code
    hydrated["diff_related"] = diff_items
    return hydrated


def normalize_diff_evidence(
    value: Any,
    metadata_path: Path,
    functions: list[str],
    by_function: dict[str, dict[str, Any]],
) -> list[Any]:
    items = value if isinstance(value, list) else [value]
    out: list[Any] = []
    for raw_item in items:
        if not isinstance(raw_item, dict):
            out.append(raw_item)
            continue
        item = dict(raw_item)
        referenced = str(item.get("file") or item.get("path") or "")
        diff_path = resolve_base_artifact_path(referenced, metadata_path) if referenced else None
        if diff_path and diff_path.is_file():
            item["file"] = str(diff_path)
            if not item.get("related_hunks") and not item.get("hunks"):
                try:
                    diff_text = diff_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    diff_text = ""
                hunks = parse_diff_hunks(diff_text)
                item["related_hunks"] = [hunk for _, hunk in hunks]
                infer_function_files(functions, by_function, hunks)
        out.append(item)
    return out


def resolve_base_artifact_path(value: str, metadata_path: Path) -> Path | None:
    if not value:
        return None
    referenced = Path(value).expanduser()
    if referenced.is_file():
        return referenced.resolve()
    dataset_root = metadata_path.parent.parent if metadata_path.parent.name in EXPORT_DIR_NAMES else metadata_path.parent
    candidates = []
    if not referenced.is_absolute():
        candidates.extend((metadata_path.parent / referenced, dataset_root / referenced))
    parts = referenced.parts
    if "Diff" in parts:
        candidates.append(dataset_root.joinpath(*parts[parts.index("Diff") :]))
    candidates.append(dataset_root / "Diff" / referenced.name)
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    matches = list((dataset_root / "Diff").glob(f"**/{referenced.name}")) if (dataset_root / "Diff").is_dir() else []
    return matches[0].resolve() if len(matches) == 1 else referenced


def parse_diff_hunks(diff_text: str) -> list[tuple[str, str]]:
    matches = list(DIFF_FILE_RE.finditer(diff_text))
    out: list[tuple[str, str]] = []
    for index, match in enumerate(matches):
        section_end = matches[index + 1].start() if index + 1 < len(matches) else len(diff_text)
        section = diff_text[match.start() : section_end]
        source_file = match.group(2)
        hunk_starts = [item.start() for item in DIFF_HUNK_RE.finditer(section)]
        if not hunk_starts:
            continue
        header = section[: hunk_starts[0]]
        for hunk_index, start in enumerate(hunk_starts):
            end = hunk_starts[hunk_index + 1] if hunk_index + 1 < len(hunk_starts) else len(section)
            out.append((source_file, header + section[start:end]))
    return out


def infer_function_files(
    functions: list[str],
    by_function: dict[str, dict[str, Any]],
    hunks: list[tuple[str, str]],
) -> None:
    changed_files = list(dict.fromkeys(source_file for source_file, _ in hunks))
    for function in functions:
        detail = by_function.setdefault(function, {})
        if detail.get("file"):
            continue
        matched_files = list(
            dict.fromkeys(
                source_file
                for source_file, hunk in hunks
                if re.search(rf"\b{re.escape(function)}\b", hunk)
            )
        )
        if len(matched_files) == 1:
            detail["file"] = matched_files[0]
        elif len(changed_files) == 1:
            detail["file"] = changed_files[0]


def normalize_metadata_items(raw: Any) -> list[tuple[str, dict[str, Any]]]:
    if isinstance(raw, dict) and "items" in raw and isinstance(raw["items"], list):
        return normalize_metadata_items(raw["items"])
    if isinstance(raw, list):
        out = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            cve_id = detect_cve_id("", item)
            if cve_id:
                out.append((cve_id, {**item, "id": item.get("id") or item.get("CVE") or cve_id}))
        return out
    if isinstance(raw, dict):
        out = []
        for key, value in raw.items():
            if not isinstance(value, dict):
                continue
            cve_id = detect_cve_id(str(key), value)
            if cve_id:
                out.append((cve_id, {**value, "id": value.get("id") or value.get("CVE") or cve_id}))
        return out
    return []


def detect_cve_id(key: str, item: dict[str, Any]) -> str:
    for value in (key, item.get("id"), item.get("CVE"), item.get("cve_id"), item.get("cve")):
        if not value:
            continue
        match = CVE_RE.search(str(value))
        if match:
            return match.group(0).upper()
    return ""


def normalize_functions(item: dict[str, Any]) -> list[str]:
    candidates: list[Any] = []
    for key in ("functions", "changed_functions", "source_functions", "function_names"):
        value = item.get(key)
        if value:
            candidates.append(value)
    function_code = item.get("function_code")
    if isinstance(function_code, dict):
        by_function = function_code.get("by_function")
        if isinstance(by_function, dict):
            candidates.append(list(by_function.keys()))
    out: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        for function in flatten_functions(candidate):
            function = function.strip()
            if function and function not in seen:
                seen.add(function)
                out.append(function)
    return out


def flatten_functions(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(flatten_functions(item))
        return out
    if isinstance(value, dict):
        for key in ("function", "name", "symbol"):
            if value.get(key):
                return [str(value[key])]
        return [str(key) for key in value.keys()]
    return []


def find_fixed_versions(item: dict[str, Any]) -> list[str]:
    values: list[str] = []
    direct_keys = (
        "fixed_versions",
        "upstream_fixed_versions",
        "fixed_version",
        "fixed",
        "fix_versions",
        "patched_versions",
    )
    for key in direct_keys:
        if key in item:
            values.extend(loose_version_candidates(item[key]))
    for key in ("source_evidence", "function_code", "metadata"):
        nested = item.get(key)
        if isinstance(nested, dict):
            for nested_key in direct_keys:
                if nested_key in nested:
                    values.extend(loose_version_candidates(nested[nested_key]))
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def explicit_ubuntu_label(item: dict[str, Any], source_version: str) -> tuple[str, str]:
    containers = [
        item.get("ubuntu_labels"),
        item.get("deployed_labels"),
        item.get("package_labels"),
        item.get("ubuntu_versions"),
    ]
    for container in containers:
        label, reason = _label_from_container(container, source_version)
        if label:
            return label, reason
    return "", ""


def _label_from_container(container: Any, source_version: str) -> tuple[str, str]:
    if isinstance(container, dict):
        if source_version in container:
            return normalize_label(container[source_version]), "explicit metadata label"
        for key, value in container.items():
            if isinstance(value, dict) and str(value.get("version") or value.get("source_version") or key) == source_version:
                return normalize_label(value.get("label") or value.get("status")), "explicit metadata label"
    if isinstance(container, list):
        for item in container:
            if not isinstance(item, dict):
                continue
            version = str(item.get("source_version") or item.get("version") or item.get("package_version") or "")
            if version == source_version:
                return normalize_label(item.get("label") or item.get("status")), "explicit metadata label"
    return "", ""


def normalize_label(value: Any) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    mapping = {
        "affected": "vuln",
        "needed": "vuln",
        "needs_triage": "unknown",
        "released": "patch",
        "fixed": "patch",
        "not affected": "not_affected",
        "not_affected": "not_affected",
        "ignored": "unknown",
        "deferred": "unknown",
        "pending": "unknown",
    }
    return mapping.get(text, text if text in {"vuln", "patch", "not_affected", "unknown"} else "")
