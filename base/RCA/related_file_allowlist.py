from __future__ import annotations

import re
import shlex
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from tree_sitter_languages import get_parser


ALLOWLIST_SCHEMA = "related_file_allowlist.v2"
DEFAULT_MAX_FILES = 24
SUPPORTED_SUFFIXES = {".c", ".h"}
MAX_SYMBOLS_PER_CVE = 64


C_PARSER = get_parser("c")


def is_supported_source(path: str) -> bool:
    return Path(path).suffix.lower() in SUPPORTED_SUFFIXES


def walk(node: Any):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        children = list(current.children)
        children.reverse()
        stack.extend(children)


def node_text(source: bytes, node: Any) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def _git_output(repo: Path, args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return proc.returncode, proc.stdout.decode("utf-8", errors="ignore")


class GitSnapshot:
    """Small read-only cache around one git revision."""

    def __init__(self, repo: Path, revision: str):
        self.repo = repo
        self.revision = revision
        self._content: dict[str, str | None] = {}
        self._tree: dict[str, Any] = {}

    def content(self, path: str) -> str | None:
        if path not in self._content:
            code, text = _git_output(self.repo, ["show", f"{self.revision}:{path}"])
            self._content[path] = text if code == 0 else None
        return self._content[path]

    def exists(self, path: str) -> bool:
        return self.content(path) is not None

    def tree(self, path: str) -> Any | None:
        if path not in self._tree:
            content = self.content(path)
            if content is None:
                self._tree[path] = None
            else:
                try:
                    self._tree[path] = C_PARSER.parse(content.encode("utf-8", errors="ignore"))
                except Exception:
                    self._tree[path] = None
        return self._tree[path]

    def grep_files(self, pattern: str) -> list[str]:
        code, text = _git_output(
            self.repo,
            ["grep", "-l", "-I", "-P", "-e", pattern, self.revision, "--", "*.c", "*.h"],
        )
        if code not in {0, 1}:
            return []
        prefix = f"{self.revision}:"
        paths = []
        for line in text.splitlines():
            path = line[len(prefix) :] if line.startswith(prefix) else line
            if is_supported_source(path):
                paths.append(path)
        return sorted(set(paths))


def _revision_parent(repo: Path, commit: str) -> str:
    if not commit:
        return ""
    code, text = _git_output(repo, ["rev-parse", f"{commit}^"])
    return text.strip() if code == 0 else ""


def _parse_diff_paths(diff_text: str) -> tuple[list[str], list[str]]:
    supported: list[str] = []
    unsupported: list[str] = []
    seen: set[str] = set()

    for line in diff_text.splitlines():
        if not line.startswith("diff --git "):
            continue
        try:
            parts = shlex.split(line)
        except ValueError:
            continue
        if len(parts) < 4:
            continue
        old_path = parts[2].removeprefix("a/")
        new_path = parts[3].removeprefix("b/")
        path = new_path if new_path != "/dev/null" else old_path
        if not path or path in seen:
            continue
        seen.add(path)
        (supported if is_supported_source(path) else unsupported).append(path)

    return supported, unsupported


def _function_name(node: Any, source: bytes) -> str:
    if node.type != "function_definition":
        return ""
    for child in walk(node):
        if child.type != "function_declarator":
            continue
        for descendant in walk(child):
            if descendant.type == "identifier":
                return node_text(source, descendant)
    return ""


def _find_function(tree: Any, source: bytes, name: str) -> Any | None:
    if tree is None:
        return None
    for node in walk(tree.root_node):
        if node.type == "function_definition" and _function_name(node, source) == name:
            return node
    return None


def _is_static_function(node: Any, source: bytes) -> bool:
    return any(
        child.type == "storage_class_specifier" and node_text(source, child) == "static"
        for child in node.children
    )


def _named_type_matches(node: Any, source: bytes, name: str) -> bool:
    if node.type in {"struct_specifier", "union_specifier", "enum_specifier"}:
        has_body = any(child.type in {"field_declaration_list", "enumerator_list"} for child in node.children)
        return has_body and any(
            child.type == "type_identifier" and node_text(source, child) == name
            for child in node.children
        )
    if node.type != "type_definition":
        return False
    return any(child.type == "identifier" and node_text(source, child) == name for child in walk(node))


def _find_type_definition(tree: Any, source: bytes, name: str) -> bool:
    if tree is None:
        return False
    return any(_named_type_matches(node, source, name) for node in walk(tree.root_node))


def _macro_defined(source: str, name: str) -> bool:
    return bool(re.search(rf"(?m)^\s*#\s*define\s+{re.escape(name)}(?:\s|\(|$)", source))


def _line_overlaps(node: Any, changed_lines: set[int]) -> bool:
    start = node.start_point[0] + 1
    end = node.end_point[0] + 1
    return any(start <= line <= end for line in changed_lines)


def _function_symbols(snapshot: GitSnapshot, path: str, function: str, changed_lines: set[int]) -> tuple[set[str], set[str]]:
    source = snapshot.content(path)
    tree = snapshot.tree(path)
    if source is None or tree is None:
        return set(), set()
    source_bytes = source.encode("utf-8", errors="ignore")
    function_node = _find_function(tree, source_bytes, function)
    if function_node is None:
        return set(), set()

    type_names: set[str] = set()
    macro_candidates: set[str] = set()
    for node in walk(function_node):
        if node.type == "type_identifier":
            type_names.add(node_text(source_bytes, node))
        elif node.type == "identifier" and _line_overlaps(node, changed_lines):
            name = node_text(source_bytes, node)
            if any(char.isupper() for char in name):
                macro_candidates.add(name)
    return type_names, macro_candidates


def _paths_for_function_definitions(snapshot: GitSnapshot, symbols: Iterable[str]) -> list[str]:
    names = sorted({name for name in symbols if name})
    if not names:
        return []
    alternatives = "|".join(re.escape(name) for name in names)
    return snapshot.grep_files(rf"\b(?:{alternatives})\s*\(")


def _paths_for_type_definitions(snapshot: GitSnapshot, symbols: Iterable[str]) -> list[str]:
    names = sorted({name for name in symbols if name})
    if not names:
        return []
    alternatives = "|".join(re.escape(name) for name in names)
    return snapshot.grep_files(rf"\b(?:struct|union|enum)\s+(?:{alternatives})\b|\btypedef\b.*\b(?:{alternatives})\b")


def _paths_for_macros(snapshot: GitSnapshot, symbols: Iterable[str]) -> list[str]:
    names = sorted({name for name in symbols if name})
    if not names:
        return []
    alternatives = "|".join(re.escape(name) for name in names)
    return snapshot.grep_files(rf"^\s*#\s*define\s+(?:{alternatives})(?:\s|\(|$)")


def _path_score(path: str, origin_file: str) -> int | None:
    if path == origin_file:
        return 50
    origin_dir = str(Path(origin_file).parent)
    candidate_dir = str(Path(path).parent)
    if origin_dir == candidate_dir:
        return 30
    if Path(path).suffix.lower() == ".h" and "include" in Path(path).parts:
        return 20
    return None


def _record_file(
    records: dict[str, dict[str, Any]],
    path: str,
    *,
    role: str,
    symbol: str,
    origin_file: str,
    origin_function: str,
    score: int,
) -> None:
    record = records.setdefault(
        path,
        {
            "path": path,
            "roles": [],
            "symbols": [],
            "reasons": [],
            "score": 0,
        },
    )
    if role not in record["roles"]:
        record["roles"].append(role)
    if symbol and {"name": symbol, "kind": role} not in record["symbols"]:
        record["symbols"].append({"name": symbol, "kind": role})
    reason = {
        "kind": role,
        "symbol": symbol,
        "origin_file": origin_file,
        "origin_function": origin_function,
    }
    if reason not in record["reasons"]:
        record["reasons"].append(reason)
    record["score"] = max(record["score"], score)


def _candidate_origins(function_analyses: list[dict[str, Any]]) -> tuple[dict[str, list[dict[str, str]]], dict[str, list[dict[str, str]]], dict[str, list[dict[str, str]]]]:
    callees: dict[str, list[dict[str, str]]] = defaultdict(list)
    types: dict[str, list[dict[str, str]]] = defaultdict(list)
    macros: dict[str, list[dict[str, str]]] = defaultdict(list)

    for analysis in function_analyses:
        function_info = analysis.get("function") or {}
        function = str(function_info.get("name") or "")
        path = str(function_info.get("file") or "")
        if not function or not path or not is_supported_source(path):
            continue
        step_b = analysis.get("step_b") or {}
        changed_lines = {
            int(item["line"])
            for item in step_b.get("changed_lines", []) or []
            if isinstance(item, dict) and isinstance(item.get("line"), int)
        }
        origin = {"origin_file": path, "origin_function": function}
        for name in step_b.get("called_apis", []) or []:
            if isinstance(name, str) and name:
                callees[name].append(origin)
        for item in step_b.get("macros", []) or []:
            if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]:
                macros[item["name"]].append(origin)

        snapshot = analysis.get("_allowlist_snapshot")
        if isinstance(snapshot, GitSnapshot):
            type_names, macro_names = _function_symbols(snapshot, path, function, changed_lines)
            for name in type_names:
                types[name].append(origin)
            for name in macro_names:
                macros[name].append(origin)

    return callees, types, macros


def _resolve_related_files(
    snapshot: GitSnapshot,
    function_analyses: list[dict[str, Any]],
    records: dict[str, dict[str, Any]],
) -> list[dict[str, str]]:
    for analysis in function_analyses:
        analysis["_allowlist_snapshot"] = snapshot
    callees, types, macros = _candidate_origins(function_analyses)
    for analysis in function_analyses:
        analysis.pop("_allowlist_snapshot", None)

    unresolved: list[dict[str, str]] = []
    symbol_total = sum(len(items) for items in (callees, types, macros))
    if symbol_total > MAX_SYMBOLS_PER_CVE:
        # Keep deterministic relation priority when a pathological patch names many symbols.
        def trim(items: dict[str, list[dict[str, str]]], remaining: int) -> dict[str, list[dict[str, str]]]:
            kept = dict(sorted(items.items())[: max(0, remaining)])
            return kept

        callees = trim(callees, MAX_SYMBOLS_PER_CVE)
        remaining = MAX_SYMBOLS_PER_CVE - len(callees)
        types = trim(types, remaining)
        remaining -= len(types)
        macros = trim(macros, remaining)

    function_paths = _paths_for_function_definitions(snapshot, callees)
    for name, origins in sorted(callees.items()):
        matched = False
        for path in function_paths:
            source = snapshot.content(path)
            tree = snapshot.tree(path)
            if source is None or tree is None:
                continue
            source_bytes = source.encode("utf-8", errors="ignore")
            node = _find_function(tree, source_bytes, name)
            if node is None:
                continue
            for origin in origins:
                if _is_static_function(node, source_bytes) and path != origin["origin_file"]:
                    continue
                proximity = _path_score(path, origin["origin_file"])
                if proximity is None:
                    continue
                _record_file(
                    records,
                    path,
                    role="direct_callee",
                    symbol=name,
                    origin_file=origin["origin_file"],
                    origin_function=origin["origin_function"],
                    score=300 + proximity,
                )
                matched = True
        if not matched:
            for origin in origins:
                unresolved.append({"name": name, "kind": "direct_callee", **origin})

    type_paths = _paths_for_type_definitions(snapshot, types)
    for name, origins in sorted(types.items()):
        matched = False
        for path in type_paths:
            source = snapshot.content(path)
            tree = snapshot.tree(path)
            if source is None or tree is None or not _find_type_definition(tree, source.encode("utf-8", errors="ignore"), name):
                continue
            for origin in origins:
                proximity = _path_score(path, origin["origin_file"])
                if proximity is None:
                    continue
                _record_file(
                    records,
                    path,
                    role="type_definition",
                    symbol=name,
                    origin_file=origin["origin_file"],
                    origin_function=origin["origin_function"],
                    score=220 + proximity,
                )
                matched = True
        if not matched:
            for origin in origins:
                unresolved.append({"name": name, "kind": "type_definition", **origin})

    macro_paths = _paths_for_macros(snapshot, macros)
    for name, origins in sorted(macros.items()):
        matched = False
        for path in macro_paths:
            source = snapshot.content(path)
            if source is None or not _macro_defined(source, name):
                continue
            for origin in origins:
                proximity = _path_score(path, origin["origin_file"])
                if proximity is None:
                    continue
                _record_file(
                    records,
                    path,
                    role="macro_definition",
                    symbol=name,
                    origin_file=origin["origin_file"],
                    origin_function=origin["origin_function"],
                    score=200 + proximity,
                )
                matched = True
        if not matched:
            for origin in origins:
                unresolved.append({"name": name, "kind": "macro_definition", **origin})

    return sorted({tuple(sorted(item.items())): item for item in unresolved}.values(), key=lambda item: (item["kind"], item["name"], item["origin_file"]))


def select_file_records(records: Iterable[dict[str, Any]], seed_files: list[str], max_files: int = DEFAULT_MAX_FILES) -> tuple[list[dict[str, Any]], bool]:
    """Keep every patch seed, then fill the remaining budget by evidence score."""
    seed_set = set(seed_files)
    by_path = {record["path"]: record for record in records}
    seed_records = [by_path[path] for path in seed_files if path in by_path]
    related_records = [record for path, record in by_path.items() if path not in seed_set]
    related_records.sort(key=lambda record: (-record["score"], record["path"]))
    available_related = max(0, max_files - len(seed_records))
    selected = [*seed_records, *related_records[:available_related]]
    return selected, len(seed_records) > max_files or len(related_records) > available_related


def _patch_functions(cve_input: dict[str, Any], full_cve: dict[str, Any]) -> list[dict[str, str]]:
    functions: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    analyses = full_cve.get("function_analyses", []) or []
    for analysis in analyses:
        if not isinstance(analysis, dict):
            continue
        function = analysis.get("function") or {}
        name = str(function.get("name") or "")
        path = str(function.get("file") or "")
        if name and (name, path) not in seen:
            functions.append({"name": name, "file": path})
            seen.add((name, path))
    if functions:
        return sorted(functions, key=lambda item: (item["file"], item["name"]))

    function_code = cve_input.get("function_code") or {}
    by_function = function_code.get("by_function") or {}
    for name in cve_input.get("functions", []) or []:
        if not isinstance(name, str) or not name:
            continue
        detail = by_function.get(name) if isinstance(by_function, dict) else {}
        path = str((detail or {}).get("file") or "")
        if (name, path) not in seen:
            functions.append({"name": name, "file": path})
            seen.add((name, path))
    return sorted(functions, key=lambda item: (item["file"], item["name"]))


def _compact_related_files(records: Iterable[dict[str, Any]], seed_files: list[str]) -> list[dict[str, Any]]:
    seed_set = set(seed_files)
    keys = {
        "direct_callee": "functions",
        "type_definition": "types",
        "macro_definition": "macros",
    }
    compact: list[dict[str, Any]] = []
    for record in records:
        if record["path"] in seed_set:
            continue
        grouped: dict[str, set[str]] = defaultdict(set)
        for symbol in record.get("symbols", []):
            if not isinstance(symbol, dict):
                continue
            key = keys.get(symbol.get("kind"))
            name = symbol.get("name")
            if key and isinstance(name, str) and name:
                grouped[key].add(name)
        if not grouped:
            continue
        item: dict[str, Any] = {"path": record["path"]}
        for key in ("functions", "types", "macros"):
            if grouped[key]:
                item[key] = sorted(grouped[key])
        compact.append(item)
    return compact


def _pick_diff_path(cve_input: dict[str, Any], full_cve: dict[str, Any]) -> str:
    for analysis in full_cve.get("function_analyses", []) or []:
        path = ((analysis.get("patch") or {}).get("diff_file") or "").strip()
        if path and Path(path).exists():
            return path
    for item in cve_input.get("diff_related", []) or []:
        path = (item.get("file") or "").strip() if isinstance(item, dict) else ""
        if path and Path(path).exists():
            return path
    return ""


def _pick_commit(cve_input: dict[str, Any], full_cve: dict[str, Any]) -> str:
    for analysis in full_cve.get("function_analyses", []) or []:
        commit = ((analysis.get("function") or {}).get("commit") or "").strip()
        if commit:
            return commit
    function_code = cve_input.get("function_code") or {}
    return str(function_code.get("commit") or "").strip()


def build_cve_allowlist(
    cve_id: str,
    cve_input: dict[str, Any],
    full_cve: dict[str, Any],
    repo_path: str | Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
) -> dict[str, Any]:
    repo = Path(repo_path)
    commit = _pick_commit(cve_input, full_cve)
    diff_path = _pick_diff_path(cve_input, full_cve)
    patch_functions = _patch_functions(cve_input, full_cve)
    if not commit or not diff_path:
        return {
            "fix_commit": commit,
            "parent_commit": "",
            "patch_functions": patch_functions,
            "seed_files": [],
            "truncated": False,
            "related_files": [],
        }

    try:
        diff_text = Path(diff_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        diff_text = ""
    seed_files, _ = _parse_diff_paths(diff_text)
    if not seed_files:
        return {
            "fix_commit": commit,
            "parent_commit": _revision_parent(repo, commit),
            "patch_functions": patch_functions,
            "seed_files": [],
            "truncated": False,
            "related_files": [],
        }

    parent_commit = _revision_parent(repo, commit)
    fix_snapshot = GitSnapshot(repo, commit)
    records: dict[str, dict[str, Any]] = {}
    for path in seed_files:
        _record_file(
            records,
            path,
            role="patch_file",
            symbol="",
            origin_file=path,
            origin_function="",
            score=1000,
        )

    analyses = [dict(item) for item in full_cve.get("function_analyses", []) or [] if isinstance(item, dict)]
    _resolve_related_files(fix_snapshot, analyses, records)
    selected, truncated = select_file_records(records.values(), seed_files, max_files)

    return {
        "fix_commit": commit,
        "parent_commit": parent_commit,
        "patch_functions": patch_functions,
        "seed_files": seed_files,
        "truncated": truncated,
        "related_files": _compact_related_files(selected, seed_files),
    }


def build_project_allowlist(
    project: str,
    repo_path: str | Path,
    input_cves: dict[str, Any],
    full_cves: dict[str, Any],
    selected_cves: set[str] | None = None,
    *,
    max_files: int = DEFAULT_MAX_FILES,
) -> dict[str, Any]:
    cves: dict[str, Any] = {}
    for cve_id in sorted(full_cves):
        if selected_cves and cve_id not in selected_cves:
            continue
        cve_input = input_cves.get(cve_id)
        if not isinstance(cve_input, dict):
            continue
        full_cve = full_cves.get(cve_id) if isinstance(full_cves.get(cve_id), dict) else {}
        cves[cve_id] = build_cve_allowlist(cve_id, cve_input, full_cve, repo_path, max_files=max_files)
    return {
        "schema": ALLOWLIST_SCHEMA,
        "project": project,
        "cves": cves,
    }


def merge_project_allowlist(existing: Any, updates: dict[str, Any]) -> dict[str, Any]:
    current_cves = {}
    if isinstance(existing, dict) and existing.get("schema") == ALLOWLIST_SCHEMA and isinstance(existing.get("cves"), dict):
        current_cves.update(existing["cves"])
    current_cves.update(updates.get("cves") or {})
    return {
        "schema": ALLOWLIST_SCHEMA,
        "project": updates.get("project", ""),
        "cves": {cve_id: current_cves[cve_id] for cve_id in sorted(current_cves)},
    }
