"""Deterministically repair the metadata export retained by deployed datasets.

Finalization copies the base metadata export verbatim.  A moved dataset can
therefore retain stale absolute diff paths, and older base exports may be wider
than the binaries actually retained by the deployed dataset.  This utility
rebuilds that public metadata view from the deployed run state without invoking
an LLM or redownloading packages.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..io_utils import read_json, write_json
from .metadata import parse_diff_hunks

try:
    from tree_sitter_languages import get_parser

    C_PARSER = get_parser("c")
except Exception:  # pragma: no cover - exercised by the fallback path.
    C_PARSER = None


SOURCE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Backfill deployed metadata from local state, diffs, and git.")
    parser.add_argument("--project", required=True)
    parser.add_argument("--output", required=True, type=Path, help="Final deployed project output directory.")
    parser.add_argument("--repo", required=True, type=Path, help="Local upstream source repository.")
    parser.add_argument(
        "--base-root",
        type=Path,
        default=None,
        help="Parent directory containing source-built project datasets (defaults beside deployed/).",
    )
    parser.add_argument("--arch", default="amd64", help="Deployed groundtruth architecture suffix (default: amd64).")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def git_output(repo: Path, args: list[str]) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        errors="replace",
        check=False,
    )
    return proc.stdout if proc.returncode == 0 else ""


def git_file_exists(repo: Path, revision: str, rel_file: str) -> bool:
    if not revision or not rel_file:
        return False
    proc = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", f"{revision}:{rel_file}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.returncode == 0


def git_file_text(repo: Path, revision: str, rel_file: str) -> str:
    return git_output(repo, ["show", f"{revision}:{rel_file}"])


def is_source_file(path: str) -> bool:
    return Path(path).suffix.lower() in SOURCE_SUFFIXES


def walk_nodes(node: Any) -> Iterable[Any]:
    yield node
    for child in node.children:
        yield from walk_nodes(child)


def defined_functions(source: str) -> set[str]:
    """Return exact C/C++ function-definition names found in source text."""

    if C_PARSER is not None:
        source_bytes = source.encode("utf-8", errors="ignore")
        tree = C_PARSER.parse(source_bytes)
        names: set[str] = set()
        for node in walk_nodes(tree.root_node):
            if node.type != "function_definition":
                continue
            declarator = next((item for item in walk_nodes(node) if item.type == "function_declarator"), None)
            if declarator is None:
                continue
            identifier = next((item for item in walk_nodes(declarator) if item.type == "identifier"), None)
            if identifier is not None:
                names.add(source_bytes[identifier.start_byte : identifier.end_byte].decode("utf-8", errors="ignore"))
        return names

    # A conservative fallback for environments without tree-sitter.
    return set(re.findall(r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{", source, flags=re.DOTALL))


def changed_files(repo: Path, commit: str) -> list[str]:
    return [path for path in git_output(repo, ["diff-tree", "--no-commit-id", "--name-only", "-r", commit]).splitlines() if path]


def matching_definitions(repo: Path, revision: str, function: str, candidates: Iterable[str]) -> list[str]:
    matches: list[str] = []
    for rel_file in sorted(dict.fromkeys(path for path in candidates if is_source_file(path))):
        text = git_file_text(repo, revision, rel_file)
        if function in defined_functions(text):
            matches.append(rel_file)
    return matches


def grep_source_files(repo: Path, revision: str, function: str) -> list[str]:
    output = git_output(repo, ["grep", "-l", "-F", function, revision, "--", "*.c", "*.h", "*.cc", "*.cpp", "*.cxx", "*.hh", "*.hpp"])
    prefix = f"{revision}:"
    return [path.removeprefix(prefix) for path in output.splitlines() if path]


def parent_revision(repo: Path, commit: str) -> str:
    return git_output(repo, ["rev-parse", f"{commit}^"]).strip()


def infer_function_file(repo: Path, commit: str, function: str, hunk_files: list[str]) -> tuple[str, str]:
    """Find one unambiguous definition, preferring changed files and fix revision."""

    if not commit:
        return "", ""
    parent = parent_revision(repo, commit)
    changed = changed_files(repo, commit)
    ordered_candidates = [*hunk_files, *changed]
    for revision, scope, method in (
        (commit, ordered_candidates, "fix_changed_definition"),
        (parent, ordered_candidates, "parent_changed_definition"),
        (commit, grep_source_files(repo, commit, function), "fix_unique_definition"),
        (parent, grep_source_files(repo, parent, function), "parent_unique_definition"),
    ):
        if not revision:
            continue
        matches = matching_definitions(repo, revision, function, scope)
        if len(matches) == 1:
            return matches[0], method
    source_changed = [path for path in ordered_candidates if is_source_file(path)]
    if len(set(source_changed)) == 1:
        return source_changed[0], "single_changed_source_file"
    return "", ""


def locate_diff(base_root: Path, project: str, cve_id: str, previous: str) -> Path | None:
    previous_path = Path(previous).expanduser()
    if previous_path.is_file():
        return previous_path.resolve()
    diff_root = base_root / project / "Diff"
    if not diff_root.is_dir():
        return None
    by_name = list(diff_root.glob(f"**/{previous_path.name}")) if previous_path.name else []
    if len(by_name) == 1:
        return by_name[0].resolve()
    by_cve = list(diff_root.glob(f"**/*{cve_id}*.diff"))
    return by_cve[0].resolve() if len(by_cve) == 1 else None


def groundtruth_cves(path: Path) -> list[str]:
    items = read_json(path)
    if not isinstance(items, list):
        raise ValueError(f"groundtruth must be a list: {path}")
    return [str(item.get("CVE") or "") for item in items if isinstance(item, dict) and item.get("CVE")]


def state_item(row: dict[str, Any]) -> dict[str, Any]:
    raw = dict(row.get("raw") or {})
    functions = list(row.get("functions") or raw.get("functions") or [])
    raw["functions"] = functions
    raw["summary"] = str(row.get("summary") or raw.get("summary") or "")
    if not isinstance(raw.get("cwe"), list):
        raw["cwe"] = []

    source = dict(row.get("source_evidence") or raw.get("function_code") or {})
    by_function = {
        str(name): dict(detail) if isinstance(detail, dict) else {}
        for name, detail in dict(source.get("by_function") or {}).items()
    }
    for function in functions:
        by_function.setdefault(function, {})
    raw["function_code"] = {"commit": str(source.get("commit") or ""), "by_function": by_function}

    evidence = row.get("diff_evidence") or raw.get("diff_related") or []
    raw["diff_related"] = [dict(item) for item in evidence if isinstance(item, dict)]
    return raw


def backfill_project(
    *,
    project: str,
    output: Path,
    repo: Path,
    base_root: Path,
    arch: str,
    write: bool = True,
) -> dict[str, Any]:
    output = output.expanduser().resolve()
    repo = repo.expanduser().resolve()
    base_root = base_root.expanduser().resolve()
    exports = output / "exports"
    groundtruth_path = exports / f"groundtruth.ubuntu-{arch}.json"
    state_path = output / "deployed" / "state" / "metadata_rows.json"
    metadata_path = exports / f"{project}_metadata.json"
    cves = groundtruth_cves(groundtruth_path)
    rows = {str(item.get("cve_id") or ""): item for item in read_json(state_path) if isinstance(item, dict)}
    missing_rows = [cve_id for cve_id in cves if cve_id not in rows]
    if missing_rows:
        raise ValueError(f"missing deployed metadata state for: {', '.join(missing_rows)}")

    metadata: dict[str, Any] = {}
    stats = {
        "schema": "ubuntu-deployed-metadata-backfill-v1",
        "project": project,
        "groundtruth_cves": len(cves),
        "metadata_cves": 0,
        "diff_paths_relocated": 0,
        "diffs_missing": [],
        "hunks_added": 0,
        "function_files_preserved": 0,
        "function_files_inferred": 0,
        "unresolved_functions": [],
    }
    for cve_id in cves:
        item = state_item(rows[cve_id])
        commit = str(item["function_code"].get("commit") or "")
        hunk_files: list[str] = []
        normalized_diffs = []
        for diff_item in item.get("diff_related") or []:
            previous = str(diff_item.get("file") or "")
            diff_path = locate_diff(base_root, project, cve_id, previous)
            if diff_path is None:
                stats["diffs_missing"].append({"cve_id": cve_id, "file": previous})
                normalized_diffs.append(diff_item)
                continue
            if str(diff_path) != previous:
                stats["diff_paths_relocated"] += 1
            text = diff_path.read_text(encoding="utf-8", errors="replace")
            parsed_hunks = parse_diff_hunks(text)
            hunk_files.extend(path for path, _ in parsed_hunks)
            updated = dict(diff_item)
            updated["file"] = str(diff_path)
            if not updated.get("related_hunks"):
                updated["related_hunks"] = [hunk for _, hunk in parsed_hunks]
                stats["hunks_added"] += len(updated["related_hunks"])
            normalized_diffs.append(updated)
        item["diff_related"] = normalized_diffs

        by_function = item["function_code"]["by_function"]
        for function in item["functions"]:
            detail = by_function.setdefault(function, {})
            existing = str(detail.get("file") or "")
            if existing and git_file_exists(repo, commit, existing):
                stats["function_files_preserved"] += 1
                continue
            inferred, method = infer_function_file(repo, commit, function, hunk_files)
            if inferred:
                detail["file"] = inferred
                stats["function_files_inferred"] += 1
            else:
                detail["file"] = ""
                stats["unresolved_functions"].append({"cve_id": cve_id, "function": function})
        metadata[cve_id] = item

    stats["metadata_cves"] = len(metadata)
    if write:
        write_json(metadata_path, metadata)
        write_json(output / "deployed" / "audit" / "metadata_backfill.json", stats)
    return stats


def main() -> int:
    args = parse_args()
    output = args.output.expanduser().resolve()
    default_base_root = output.parent.parent if output.parent.name == "deployed" else output.parent
    stats = backfill_project(
        project=args.project,
        output=output,
        repo=args.repo,
        base_root=args.base_root or default_base_root,
        arch=args.arch,
        write=not args.dry_run,
    )
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
