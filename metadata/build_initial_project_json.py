#!/usr/bin/env python3
"""Build initial project CVE JSON from CVE-Dataset New artifacts.

Inputs:
- New/Diff/<project>/source_diff.json
- New/Diff/<project>/diff_files/*.diff
- New/cveinfo/<project>/<project>_parsed.json

The output shape is compatible with project_source_analysis.py.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_DATASET_ROOT = Path("/home/zhangxb/patch/related-works/CVE-Dataset/New")
CODE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
}


@dataclass
class Hunk:
    header: str
    lines: list[str] = field(default_factory=list)

    @property
    def context(self) -> str:
        match = re.match(r"@@\s+[-+0-9, ]+\s+@@\s*(.*)$", self.header)
        return match.group(1).strip() if match else ""


@dataclass
class FileBlock:
    old_path: str
    new_path: str
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def path(self) -> str:
        return self.new_path if self.new_path != "/dev/null" else self.old_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build initial project JSON from source_diff, diff files, and parsed CVE metadata."
    )
    parser.add_argument("--project", required=True, help="Project name, e.g. curl or binutils.")
    parser.add_argument("--dataset-root", type=Path, default=DEFAULT_DATASET_ROOT)
    parser.add_argument("--source-diff", type=Path, default=None)
    parser.add_argument("--diff-dir", type=Path, default=None)
    parser.add_argument("--cveinfo", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--stats-output", type=Path, default=None)
    parser.add_argument("--cve", action="append", default=[], help="Optional CVE filter; repeatable.")
    parser.add_argument("--limit", type=int, default=0, help="Optional max CVEs to emit.")
    parser.add_argument("--strict", action="store_true", help="Fail when source metadata or diff files are missing.")
    return parser.parse_args()


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    tmp.replace(path)


def normalize_source_diff(project: str, data: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(data, dict):
        raise ValueError("source_diff.json must be a JSON object")
    if project in data and isinstance(data[project], dict):
        data = data[project]
    out: dict[str, dict[str, Any]] = {}
    for cve_id, item in data.items():
        if isinstance(cve_id, str) and cve_id.startswith("CVE-") and isinstance(item, dict):
            out[cve_id] = item
    return out


def load_cveinfo(path: Path) -> dict[str, dict[str, Any]]:
    data = read_json(path)
    if not isinstance(data, list):
        raise ValueError(f"cveinfo must be a JSON list: {path}")
    out: dict[str, dict[str, Any]] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("id") or item.get("cve") or item.get("CVE")
        if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
            out[cve_id] = item
    return out


def parse_diff(diff_text: str) -> list[FileBlock]:
    blocks: list[FileBlock] = []
    current: FileBlock | None = None
    current_hunk: Hunk | None = None

    for raw in diff_text.splitlines():
        line = raw.rstrip("\n")
        if line.startswith("diff --git "):
            if current_hunk is not None and current is not None:
                current.hunks.append(current_hunk)
                current_hunk = None
            if current is not None:
                blocks.append(current)
            parts = line.split()
            old_path = parts[2][2:] if len(parts) >= 4 and parts[2].startswith("a/") else ""
            new_path = parts[3][2:] if len(parts) >= 4 and parts[3].startswith("b/") else ""
            current = FileBlock(old_path=old_path, new_path=new_path)
            continue

        if current is None:
            continue

        if line.startswith("@@ "):
            if current_hunk is not None:
                current.hunks.append(current_hunk)
            current_hunk = Hunk(header=line)
            continue

        if current_hunk is not None:
            current_hunk.lines.append(line)

    if current_hunk is not None and current is not None:
        current.hunks.append(current_hunk)
    if current is not None:
        blocks.append(current)
    return blocks


def ident_re(name: str) -> re.Pattern[str]:
    return re.compile(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])")


def call_re(name: str) -> re.Pattern[str]:
    return re.compile(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"\s*\(")


def function_decl_re(name: str) -> re.Pattern[str]:
    return re.compile(
        r"^\s*(?:[A-Za-z_][A-Za-z0-9_*\s]+\s+)+" + re.escape(name) + r"\s*\("
    )


def is_code_path(path: str) -> bool:
    suffix = Path(path).suffix.lower()
    if suffix in CODE_SUFFIXES:
        return True
    return False


def hunk_has_function_definition(function_name: str, hunk: Hunk) -> bool:
    decl = function_decl_re(function_name)
    for line in hunk.lines:
        if not line or line[0] not in {"+", "-"}:
            continue
        content = line[1:]
        if decl.search(content):
            return True
    return False


def hunk_score(function_name: str, hunk: Hunk) -> int:
    i_re = ident_re(function_name)
    c_re = call_re(function_name)
    if hunk_has_function_definition(function_name, hunk):
        return 100
    if i_re.search(hunk.context):
        return 50
    score = 0
    for line in hunk.lines:
        content = line[1:] if line[:1] in {" ", "+", "-"} else line
        if c_re.search(content):
            score = max(score, 35)
        elif i_re.search(content):
            score = max(score, 10)
    return score


def block_score(function_name: str, block: FileBlock) -> int:
    score = 0
    for hunk in block.hunks:
        score = max(score, hunk_score(function_name, hunk))
    if score and is_code_path(block.path):
        score += 5
    return score


def extract_functions(source_item: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for entry in source_item.get("analysis", []) or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("function")
        if isinstance(name, str) and name and name not in out:
            out.append(name)
    return out


def extract_function_types(source_item: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for entry in source_item.get("analysis", []) or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("function")
        change_type = entry.get("type")
        if isinstance(name, str) and name and isinstance(change_type, str):
            out[name] = change_type
    return out


def find_diff_file(project: str, cve_id: str, commit: str, diff_dir: Path) -> Path | None:
    candidates = sorted(diff_dir.glob(f"{project}_{cve_id}_*.diff"))
    if not candidates:
        candidates = sorted(diff_dir.glob(f"*{cve_id}*.diff"))
    if not candidates:
        return None
    if commit:
        lowered = [(p, p.name.lower()) for p in candidates]
        for width in (12, 10, 8, 7):
            prefix = commit[:width].lower()
            for path, name in lowered:
                if prefix and prefix in name:
                    return path
    return candidates[0]


def infer_function_files(functions: list[str], blocks: list[FileBlock]) -> dict[str, dict[str, Any]]:
    code_blocks = [b for b in blocks if is_code_path(b.path)]
    out: dict[str, dict[str, Any]] = {}

    for fn in functions:
        scored = [(block_score(fn, block), block) for block in blocks]
        scored.sort(key=lambda x: x[0], reverse=True)
        best_score, best_block = scored[0] if scored else (0, None)
        inferred_by = ""
        if best_score >= 100:
            inferred_by = "function_definition_hunk_match"
        elif best_score >= 50:
            inferred_by = "function_header_hunk_match"
        elif best_score > 0:
            inferred_by = "function_reference_hunk_match"

        if best_score <= 0 and len(code_blocks) == 1:
            best_block = code_blocks[0]
            inferred_by = "single_code_file_fallback"

        out[fn] = {
            "file": best_block.path if best_block is not None else "",
            "inferred_by": inferred_by,
        }
    return out


def build_project_json(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    project = args.project
    dataset_root = args.dataset_root
    source_diff_path = args.source_diff or dataset_root / "Diff" / project / "source_diff.json"
    diff_dir = args.diff_dir or dataset_root / "Diff" / project / "diff_files"
    cveinfo_path = args.cveinfo or dataset_root / "cveinfo" / project / f"{project}_parsed.json"

    source_diff = normalize_source_diff(project, read_json(source_diff_path))
    cveinfo = load_cveinfo(cveinfo_path)

    selected = list(source_diff.items())
    if args.cve:
        wanted = set(args.cve)
        selected = [(cve, item) for cve, item in selected if cve in wanted]
    if args.limit:
        selected = selected[: args.limit]

    out: dict[str, Any] = {}
    stats: dict[str, Any] = {
        "project": project,
        "source_diff": str(source_diff_path.resolve()),
        "diff_dir": str(diff_dir.resolve()),
        "cveinfo": str(cveinfo_path.resolve()),
        "input_source_diff_cves": len(source_diff),
        "selected_cves": len(selected),
        "emitted_cves": 0,
        "total_functions": 0,
        "diff_files_found": 0,
        "diff_files_missing": 0,
        "cveinfo_found": 0,
        "cveinfo_missing": 0,
        "functions_with_file": 0,
        "functions_without_file": 0,
        "change_types": {},
        "inference_methods": {},
    }

    for cve_id, source_item in selected:
        commit = str(source_item.get("commit") or "")
        functions = extract_functions(source_item)
        function_types = extract_function_types(source_item)
        diff_file = find_diff_file(project, cve_id, commit, diff_dir)
        if diff_file is None:
            stats["diff_files_missing"] += 1
            if args.strict:
                raise FileNotFoundError(f"diff file not found for {cve_id}")
            blocks: list[FileBlock] = []
            diff_file_text = ""
        else:
            stats["diff_files_found"] += 1
            diff_file_text = str(diff_file.resolve())
            blocks = parse_diff(diff_file.read_text(encoding="utf-8", errors="ignore"))
            inferred = infer_function_files(functions, blocks)

        if diff_file is None:
            inferred = {fn: {"file": "", "inferred_by": ""} for fn in functions}

        info = cveinfo.get(cve_id, {})
        if info:
            stats["cveinfo_found"] += 1
        else:
            stats["cveinfo_missing"] += 1
            if args.strict:
                raise KeyError(f"CVE metadata not found for {cve_id}")

        by_function: dict[str, Any] = {}
        for fn in functions:
            file_info = inferred.get(fn, {})
            rel_file = file_info.get("file", "")
            if rel_file:
                stats["functions_with_file"] += 1
            else:
                stats["functions_without_file"] += 1
            change_type = function_types.get(fn, "unknown") or "unknown"
            inferred_by = file_info.get("inferred_by", "unknown") or "unknown"
            stats["change_types"][change_type] = stats["change_types"].get(change_type, 0) + 1
            stats["inference_methods"][inferred_by] = stats["inference_methods"].get(inferred_by, 0) + 1
            by_function[fn] = {
                "file": rel_file,
            }

        stats["total_functions"] += len(functions)

        out[cve_id] = {
            "functions": functions,
            "summary": info.get("summary", ""),
            "cwe": info.get("cwe", []),
            "diff_related": [
                {
                    "file": diff_file_text,
                }
            ],
            "function_code": {
                "commit": commit,
                "by_function": by_function,
            },
        }

    stats["emitted_cves"] = len(out)
    return out, stats


def main() -> int:
    args = parse_args()
    output = args.output or ROOT / args.project / f"{args.project}.json"
    stats_output = args.stats_output

    data, stats = build_project_json(args)
    write_json(output, data)
    if stats_output:
        write_json(stats_output, stats)

    print(f"wrote project json: {output.resolve()}")
    print(
        "stats: "
        f"cves={stats['emitted_cves']} functions={stats['total_functions']} "
        f"diff_found={stats['diff_files_found']} "
        f"functions_with_file={stats['functions_with_file']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
