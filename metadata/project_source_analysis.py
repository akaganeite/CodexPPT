#!/usr/bin/env python3
"""
Project-level source analysis for many CVEs.

This script combines the useful behavior of:
  - source_analyze_v2.py: minimal LLM-ready CVE metadata + patch hunks
  - source_analysis.py / step_bc_patch_function.py: AST-based patch variable
    extraction, def/use tracing, source-sink hints, and reduced function generation

Input is a project JSON such as:
  /home/zhangxb/ClawSpace/agent/straight_detect/binutils/binutils.json

Outputs:
  1) a full analysis JSON covering all selected CVEs/functions
  2) a compact JSON shaped for prompt consumption
"""

import argparse
import json
import os
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple


DEFAULT_OUTPUT_DIR = "/home/zhangxb/ClawSpace/agent/patch_presence_workflow/outputs"
DEFAULT_TARGET_ROOT = "/home/zhangxb/patch/related-works/CVE-Dataset/target"

PROJECT_REPO_DEFAULTS = {
    "binutils": "/home/zhangxb/patch/related-works/CVE-Dataset/target/binutils-gdb",
}


try:
    from tree_sitter_languages import get_parser
except Exception as e:
    raise RuntimeError("tree_sitter_languages is required") from e

C_PARSER = get_parser("c")

INTERESTING_STMT_TYPES = {
    "declaration",
    "expression_statement",
    "if_statement",
    "switch_statement",
    "for_statement",
    "while_statement",
    "do_statement",
    "return_statement",
}


@dataclass
class FuncInfo:
    name: str
    file: str
    start: int
    end: int


# Function: Load a JSON file from disk.
# Args: path: path to the JSON file.
# Returns: Parsed JSON object (dict).
def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# Function: Read a UTF-8 text file.
# Args: path: file path.
# Returns: File content as string.
def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


# Function: Read file content at a specific git revision without checkout.
# Args: repo_path: repository root; rel_file: repo-relative path; rev: git rev expression.
# Returns: File content string, or None when unavailable.
def read_file_at_git_rev(repo_path: str, rel_file: str, rev: str) -> Optional[str]:
    """Read file content from a specific git revision without checkout.

    rev examples: <commit>, <commit>^
    Returns None when git show fails.
    """
    try:
        cp = subprocess.run(
            ["git", "-C", repo_path, "show", f"{rev}:{rel_file}"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if cp.returncode != 0:
            return None
        return cp.stdout.decode("utf-8", errors="ignore")
    except Exception:
        return None


# Function: Extract source text covered by an AST node.
# Args: src: full source bytes; node: tree-sitter node.
# Returns: Decoded node text.
def node_text(src: bytes, node: Any) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


# Function: Traverse AST nodes in preorder.
# Args: node: root node.
# Returns: Iterator of nodes in preorder.
def walk(node: Any):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        ch = list(n.children)
        ch.reverse()
        stack.extend(ch)


# Function: Find the first direct child of a given type.
# Args: node: parent node; t: target node type.
# Returns: Matched child node, or None.
def first_child_of_type(node: Any, t: str) -> Optional[Any]:
    for c in node.children:
        if c.type == t:
            return c
    return None


# Function: Get a source line by 1-based line number.
# Args: lines: source lines; line_no: 1-based line index.
# Returns: Line text, or empty string if out of range.
def line_text(lines: List[str], line_no: int) -> str:
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].rstrip("\n")
    return ""


# Function: Parse unified diff and keep NEW-side changed lines inside function range.
# Args: diff_text: unified diff text; rel_file: target file path; func: function range metadata.
# Returns: Mapping new_line_number -> changed line text.
def parse_diff_changed_lines(diff_text: str, rel_file: str, func: FuncInfo) -> Dict[int, str]:
    """Parse unified diff; return NEW-side changed lines that fall inside function range."""
    changed: Dict[int, str] = {}
    in_target_file = False
    in_hunk = False
    old_ln, new_ln = 0, 0

    for raw in diff_text.splitlines():
        line = raw.rstrip("\n")

        if line.startswith("diff --git "):
            in_target_file = False
            in_hunk = False
            parts = line.split(" ")
            if len(parts) >= 4 and parts[3].startswith("b/"):
                in_target_file = (parts[3][2:] == rel_file)
            continue

        if not in_target_file:
            continue

        if line.startswith("@@ "):
            in_hunk = True
            toks = line.split(" ")
            plus_tok, minus_tok = None, None
            for t in toks:
                if t.startswith("+"):
                    plus_tok = t
                if t.startswith("-"):
                    minus_tok = t
            if plus_tok is None or minus_tok is None:
                in_hunk = False
                continue
            try:
                new_ln = int(plus_tok[1:].split(",")[0])
                old_ln = int(minus_tok[1:].split(",")[0])
            except Exception:
                in_hunk = False
            continue

        if not in_hunk:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            if func.start <= new_ln <= func.end:
                changed[new_ln] = line[1:]
            new_ln += 1
            continue

        if line.startswith("-") and not line.startswith("---"):
            old_ln += 1
            continue

        if line.startswith(" "):
            old_ln += 1
            new_ln += 1

    return changed


# Function: Locate function_definition node by function name and expected range.
# Args: src: source bytes; func_name: function name; start/end: expected line range.
# Returns: Best-matched function node, or None.
def parse_function_node(src: bytes, func_name: str, start: int, end: int) -> Optional[Any]:
    tree = C_PARSER.parse(src)
    root = tree.root_node
    candidates = []
    for n in walk(root):
        if n.type != "function_definition":
            continue
        d = first_child_of_type(n, "function_declarator")
        if d is None:
            continue
        ident = None
        for c in walk(d):
            if c.type == "identifier":
                ident = node_text(src, c)
                break
        if ident != func_name:
            continue
        s = n.start_point[0] + 1
        e = n.end_point[0] + 1
        overlap = not (e < start or s > end)
        candidates.append((2 if overlap else 1, n))
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


# Function: Collect parameter identifiers from a function node.
# Args: src: source bytes; fn_node: function_definition node.
# Returns: Set of parameter names.
def collect_params(src: bytes, fn_node: Any) -> Set[str]:
    out: Set[str] = set()
    decl = first_child_of_type(fn_node, "function_declarator")
    if decl is None:
        return out
    for n in walk(decl):
        if n.type == "parameter_declaration":
            for c in walk(n):
                if c.type == "identifier":
                    out.add(node_text(src, c))
    return out


# Function: Collect local variable identifiers declared in function body.
# Args: src: source bytes; fn_node: function_definition node.
# Returns: Set of local variable names.
def collect_locals(src: bytes, fn_node: Any) -> Set[str]:
    out: Set[str] = set()
    body = first_child_of_type(fn_node, "compound_statement")
    if body is None:
        return out
    for n in walk(body):
        if n.type == "declaration":
            for d in walk(n):
                if d.type == "identifier":
                    out.add(node_text(src, d))
    return out


# Function: Collect object-like #define macros up to a line threshold.
# Args: file_lines: full file lines; until_line: scan upper bound line number.
# Returns: Mapping macro_name -> macro_body.
def collect_macros(file_lines: List[str], until_line: int) -> Dict[str, str]:
    macros: Dict[str, str] = {}
    for i, ln in enumerate(file_lines, start=1):
        if i > until_line:
            break
        s = ln.strip()
        if not s.startswith("#define "):
            continue
        rest = s[len("#define "):].strip()
        if not rest:
            continue
        parts = rest.split(None, 1)
        name = parts[0]
        if "(" in name and name.endswith(")"):
            continue
        body = parts[1].strip() if len(parts) > 1 else "1"
        macros[name] = body
    return macros


# Function: Safely evaluate a restricted integer expression.
# Args: expr: expression string.
# Returns: Integer result, or None when unsafe/invalid.
def safe_eval_int(expr: str) -> Optional[int]:
    allowed = set("0123456789abcdefxABCDEFX()+-*/%<>&|^~ ")
    if any(ch not in allowed for ch in expr):
        return None
    try:
        v = eval(expr, {"__builtins__": None}, {})
        if isinstance(v, int):
            return v
    except Exception:
        return None
    return None


# Function: Resolve macro recursively and try to compute a concrete value.
# Args: name: macro name; macros: macro map; depth: recursion depth guard.
# Returns: Resolved value string, or None.
def resolve_macro_value(name: str, macros: Dict[str, str], depth: int = 0) -> Optional[str]:
    if name not in macros or depth > 8:
        return None
    body = macros[name]
    toks = body.replace("(", " ( ").replace(")", " ) ").split()
    resolved = []
    for t in toks:
        if t in macros and t != name:
            rv = resolve_macro_value(t, macros, depth + 1)
            resolved.append(rv if rv is not None else macros[t])
        else:
            resolved.append(t)
    expr = " ".join(resolved)
    iv = safe_eval_int(expr)
    return str(iv) if iv is not None else expr


# Function: Collect identifier tokens from an AST subtree.
# Args: src: source bytes; node: subtree root node.
# Returns: List of identifier names.
def identifiers_in_subtree(src: bytes, node: Optional[Any]) -> List[str]:
    if node is None:
        return []
    out = []
    for n in walk(node):
        if n.type == "identifier":
            out.append(node_text(src, n))
    return out


# Function: Check whether a token looks like a C symbol name.
# Args: s: candidate token.
# Returns: True if symbol-like, else False.
def is_symbol_name(s: str) -> bool:
    return bool(s) and (s[0].isalpha() or s[0] == "_")


# Function: Find nearest ancestor whose type belongs to the target set.
# Args: node: start node; types: accepted ancestor node types.
# Returns: Matched ancestor node, or original node.
def nearest_ancestor(node: Any, types: Set[str]) -> Any:
    cur = node
    while cur is not None:
        if cur.type in types:
            return cur
        cur = cur.parent
    return node


# Function: Get nearest statement-like ancestor used as event anchor.
# Args: node: AST node.
# Returns: Statement anchor node.
def stmt_anchor(node: Any) -> Any:
    return nearest_ancestor(node, INTERESTING_STMT_TYPES)


# Function: Extract variable/api entities from AST nodes overlapping one line.
# Args: src: source bytes; fn_node: function node; line_no: target line number.
# Returns: Dict with vars/apis sets.
def extract_line_entities(src: bytes, fn_node: Any, line_no: int) -> Dict[str, Set[str]]:
    """Extract per-line vars/apis/macros candidates from AST nodes overlapping line."""
    vars_set: Set[str] = set()
    apis_set: Set[str] = set()

    for n in walk(fn_node):
        s = n.start_point[0] + 1
        e = n.end_point[0] + 1
        if not (s <= line_no <= e):
            continue

        if n.type == "call_expression":
            fn = n.child_by_field_name("function")
            for ident in identifiers_in_subtree(src, fn):
                if is_symbol_name(ident):
                    apis_set.add(ident)
            args = n.child_by_field_name("arguments")
            for ident in identifiers_in_subtree(src, args):
                if is_symbol_name(ident):
                    vars_set.add(ident)
            continue

        if n.type == "identifier":
            ident = node_text(src, n)
            if is_symbol_name(ident):
                vars_set.add(ident)

    return {"vars": vars_set, "apis": apis_set}


# Function: Compact code text into single-line style for prompt efficiency.
# Args: text: raw code text; max_lines: maximum lines kept before truncation marker.
# Returns: Compacted code string.
def compact_code_text(text: str, max_lines: int = 8) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    lines = [ln.rstrip() for ln in text.splitlines()]
    if len(lines) > max_lines:
        lines = lines[:max_lines] + ["..."]
    return " ".join(" ".join(lines).split())


# Function: Build compact snippet text for one statement node.
# Args: src: source bytes; stmt: statement node; max_lines: snippet line cap.
# Returns: Compact statement text.
def stmt_snippet(src: bytes, stmt: Any, max_lines: int = 8) -> str:
    return compact_code_text(node_text(src, stmt), max_lines=max_lines)


# Function: Append one def/use event record.
# Args: events: output list; src/lines: source data; stmt: anchor node; var/op/node_type: event core fields; extra: optional fields.
# Returns: None (mutates events list).
def add_event(events: List[Dict[str, Any]], src: bytes, lines: List[str], stmt: Any, var: str, op: str, node_type: str, extra: Optional[Dict[str, Any]] = None):
    ln = stmt.start_point[0] + 1
    end_ln = stmt.end_point[0] + 1
    ev = {
        "line": ln,
        "end_line": end_ln,
        "code": line_text(lines, ln).strip(),
        "stmt_code": stmt_snippet(src, stmt),
        "stmt_code_raw": node_text(src, stmt).strip(),
        "stmt_all_ids": sorted(set([x for x in identifiers_in_subtree(src, stmt) if is_symbol_name(x)])),
        "var": var,
        "op": op,
        "node_type": node_type,
    }
    if extra:
        extra = dict(extra)
        if "stmt_code" in extra:
            extra["stmt_code"] = compact_code_text(extra["stmt_code"])
        if "stmt_code_raw" in extra:
            extra["stmt_code_raw"] = (extra["stmt_code_raw"] or "").strip()
        ev.update(extra)
    events.append(ev)


# Function: Classify intra-function def/use events for tracked variables.
# Args: src: source bytes; fn_node: function node; all_lines: source lines; tracked_vars: variable set to track.
# Returns: De-duplicated event list.
def classify_def_use(src: bytes, fn_node: Any, all_lines: List[str], tracked_vars: Set[str]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    for n in walk(fn_node):
        t = n.type

        if t == "parameter_declaration":
            stmt = nearest_ancestor(n, {"parameter_declaration"})
            for ident in identifiers_in_subtree(src, n):
                if ident in tracked_vars:
                    add_event(events, src, all_lines, stmt, ident, "param_def", t)
            continue

        if t == "declaration":
            stmt = stmt_anchor(n)
            defs = [x for x in identifiers_in_subtree(src, n) if x in tracked_vars]
            for v in sorted(set(defs)):
                add_event(events, src, all_lines, stmt, v, "def_decl", t)
            continue

        if t == "init_declarator":
            stmt = nearest_ancestor(n, {"declaration", "expression_statement"})
            decl = n.child_by_field_name("declarator")
            val = n.child_by_field_name("value")
            defs = [x for x in identifiers_in_subtree(src, decl) if x in tracked_vars]
            uses = [x for x in identifiers_in_subtree(src, val) if x in tracked_vars]
            for v in defs:
                add_event(events, src, all_lines, stmt, v, "def", t)
            for v in uses:
                add_event(events, src, all_lines, stmt, v, "use", t)
            continue

        if t == "assignment_expression":
            stmt = nearest_ancestor(n, {"expression_statement", "declaration"})
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            defs = [x for x in identifiers_in_subtree(src, left) if x in tracked_vars]
            uses = [x for x in identifiers_in_subtree(src, right) if x in tracked_vars]
            rhs_all = [x for x in identifiers_in_subtree(src, right) if is_symbol_name(x)]
            for v in defs:
                add_event(events, src, all_lines, stmt, v, "def", t, {"rhs_vars": sorted(set(rhs_all))})
            for v in uses:
                add_event(events, src, all_lines, stmt, v, "use", t)
            continue

        if t == "update_expression":
            stmt = nearest_ancestor(n, {"expression_statement", "declaration"})
            arg = n.child_by_field_name("argument")
            ids = [x for x in identifiers_in_subtree(src, arg) if x in tracked_vars]
            for v in ids:
                add_event(events, src, all_lines, stmt, v, "def", t)
                add_event(events, src, all_lines, stmt, v, "use", t)
            continue

        if t == "call_expression":
            stmt = nearest_ancestor(n, {"expression_statement", "declaration", "return_statement"})
            fn = n.child_by_field_name("function")
            callee_names = [x for x in identifiers_in_subtree(src, fn) if is_symbol_name(x)]
            callee = callee_names[0] if callee_names else None
            args = n.child_by_field_name("arguments")
            uses = [x for x in identifiers_in_subtree(src, args) if x in tracked_vars]
            for v in uses:
                extra = {"callee": callee} if callee else None
                add_event(events, src, all_lines, stmt, v, "use_call", t, extra)
            continue

        if t in ("if_statement", "switch_statement", "while_statement", "for_statement", "return_statement"):
            stmt = nearest_ancestor(n, {"if_statement", "switch_statement", "while_statement", "for_statement", "return_statement"})
            cond_node = n.child_by_field_name("condition")
            if cond_node is not None:
                ids = [x for x in identifiers_in_subtree(src, cond_node) if x in tracked_vars]
                cond_txt = node_text(src, cond_node)
                override = f"{t}: ({cond_txt})"
            elif t == "return_statement":
                ids = [x for x in identifiers_in_subtree(src, n) if x in tracked_vars]
                override = f"return_statement: {node_text(src, n)}"
            else:
                ids = [x for x in identifiers_in_subtree(src, n) if x in tracked_vars]
                override = node_text(src, n)
            for v in sorted(set(ids)):
                add_event(
                    events,
                    src,
                    all_lines,
                    stmt,
                    v,
                    "use_control",
                    t,
                    {"stmt_code": override, "stmt_code_raw": node_text(src, n)},
                )

    seen = set()
    out = []
    for e in sorted(events, key=lambda x: (x["line"], x["var"], x["op"])):
        k = (e["line"], e["var"], e["op"], e["node_type"], e.get("callee"))
        if k in seen:
            continue
        seen.add(k)
        out.append(e)
    return out


# Function: Group Step-C def/use events by variable.
# Args: events: event list; key_vars: variables to include.
# Returns: Step-C JSON object.
def build_step_c(events: List[Dict[str, Any]], key_vars: List[str]) -> Dict[str, Any]:
    per_var = []
    for v in key_vars:
        ev = [e for e in events if e["var"] == v]
        per_var.append({
            "var": v,
            "defs": [e for e in ev if e["op"] in ("def", "def_decl", "param_def")],
            "uses": [e for e in ev if e["op"].startswith("use")],
            "all_events": ev,
        })
    return {"schema": "step_c.intra_function_def_use.v2", "variables": per_var}


# Function: Build compact focused context blocks from patch lines and events.
# Args: changed_lines: NEW-side patch lines; events: def/use events; lines: source lines.
# Returns: Focused context JSON object.
def build_focused_context(changed_lines: Dict[int, str], events: List[Dict[str, Any]], lines: List[str]) -> Dict[str, Any]:
    """Build compact focused context blocks from patch lines + def/use events."""
    blocks: Dict[str, Dict[str, Any]] = {}

    for ln, code in changed_lines.items():
        raw = code.strip() if code.strip() else line_text(lines, int(ln)).strip()
        key = f"patch:{ln}:{ln}:{raw}"
        blocks[key] = {
            "start_line": int(ln),
            "end_line": int(ln),
            "kind": "patch_line",
            "code": compact_code_text(raw),
            "raw_code": raw,
            "vars": [],
            "all_ids": [],
        }

    for e in events:
        start = int(e.get("line", 0))
        end = int(e.get("end_line", start))
        code = (e.get("stmt_code") or e.get("code") or "").strip()
        raw = (e.get("stmt_code_raw") or e.get("stmt_code") or e.get("code") or "").strip()
        key = f"stmt:{start}:{end}:{code}"
        if key not in blocks:
            blocks[key] = {
                "start_line": start,
                "end_line": end,
                "kind": "stmt",
                "code": code,
                "raw_code": raw,
                "vars": [],
                "all_ids": [],
            }
        if e.get("var") and e["var"] not in blocks[key]["vars"]:
            blocks[key]["vars"].append(e["var"])
        for ident in e.get("stmt_all_ids", []) or []:
            if ident not in blocks[key]["all_ids"]:
                blocks[key]["all_ids"].append(ident)

    compact = sorted(blocks.values(), key=lambda x: (x["start_line"], x["end_line"], x["kind"]))
    for c in compact:
        c["vars"] = sorted(c["vars"])
        c["all_ids"] = sorted(c["all_ids"])

    return {
        "schema": "focused_context.v3",
        "block_count": len(compact),
        "blocks": compact,
    }


# Function: Extract declared identifiers from one declaration node.
# Args: src: source bytes; decl_node: declaration node.
# Returns: Declared variable names only.
def declared_identifiers_in_declaration(src: bytes, decl_node: Any) -> List[str]:
    """Return identifiers that are *declared* by this declaration node.

    Important: this excludes identifiers only used in initializers.
    """
    declared: List[str] = []
    for c in decl_node.children:
        if c.type == "init_declarator":
            d = c.child_by_field_name("declarator")
            ids = [x for x in identifiers_in_subtree(src, d) if is_symbol_name(x)]
            if ids:
                declared.append(ids[-1])
        elif c.type in ("pointer_declarator", "array_declarator", "function_declarator", "identifier"):
            ids = [x for x in identifiers_in_subtree(src, c) if is_symbol_name(x)]
            if ids:
                declared.append(ids[-1])
    # stable unique
    out: List[str] = []
    seen: Set[str] = set()
    for x in declared:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# Function: Index declaration statements by declared variable name.
# Args: src: source bytes; fn_node: function node.
# Returns: Mapping variable -> declaration metadata.
def declaration_nodes_by_var(src: bytes, fn_node: Any) -> Dict[str, Dict[str, Any]]:
    """Index declaration statements by declared variable name.

    Returns: var -> {start_line, end_line, code, ids}
    where ids are all identifiers appearing in that declaration statement.
    """
    out: Dict[str, Dict[str, Any]] = {}
    body = first_child_of_type(fn_node, "compound_statement")
    if body is None:
        return out
    for n in walk(body):
        if n.type != "declaration":
            continue
        declared_ids = declared_identifiers_in_declaration(src, n)
        if not declared_ids:
            continue
        all_ids = [x for x in identifiers_in_subtree(src, n) if is_symbol_name(x)]
        info = {
            "start_line": n.start_point[0] + 1,
            "end_line": n.end_point[0] + 1,
            "code": node_text(src, n).strip(),
            "ids": sorted(set(all_ids)),
        }
        for v in declared_ids:
            out[v] = info
    return out


# Function: Parse unified diff and return both OLD/NEW changed lines in range.
# Args: diff_text: unified diff text; rel_file: target file; func: function metadata.
# Returns: Tuple(old_changed_lines, new_changed_lines).
def parse_diff_old_new_lines(diff_text: str, rel_file: str, func: FuncInfo) -> Tuple[Dict[int, str], Dict[int, str]]:
    """Parse unified diff for target file/function range.

    Returns:
      old_changed_lines: old-side deleted/changed lines (from '-') by old line no
      new_changed_lines: new-side added/changed lines (from '+') by new line no
    """
    old_changed: Dict[int, str] = {}
    new_changed: Dict[int, str] = {}
    in_target_file = False
    in_hunk = False
    old_ln, new_ln = 0, 0

    for raw in diff_text.splitlines():
        line = raw.rstrip("\n")

        if line.startswith("diff --git "):
            in_target_file = False
            in_hunk = False
            parts = line.split(" ")
            if len(parts) >= 4 and parts[3].startswith("b/"):
                in_target_file = (parts[3][2:] == rel_file)
            continue

        if not in_target_file:
            continue

        if line.startswith("@@ "):
            in_hunk = True
            toks = line.split(" ")
            plus_tok, minus_tok = None, None
            for t in toks:
                if t.startswith("+"):
                    plus_tok = t
                if t.startswith("-"):
                    minus_tok = t
            if plus_tok is None or minus_tok is None:
                in_hunk = False
                continue
            try:
                new_ln = int(plus_tok[1:].split(",")[0])
                old_ln = int(minus_tok[1:].split(",")[0])
            except Exception:
                in_hunk = False
            continue

        if not in_hunk:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            if func.start <= new_ln <= func.end:
                new_changed[new_ln] = line[1:]
            new_ln += 1
            continue

        if line.startswith("-") and not line.startswith("---"):
            if func.start <= old_ln <= func.end:
                old_changed[old_ln] = line[1:]
            old_ln += 1
            continue

        if line.startswith(" "):
            old_ln += 1
            new_ln += 1

    return old_changed, new_changed


# Function: Filter events for a target variable set.
# Args: events: all events; vars_set: selected variables.
# Returns: Filtered event list.
def statement_events_for_vars(events: List[Dict[str, Any]], vars_set: Set[str]) -> List[Dict[str, Any]]:
    out = []
    for e in events:
        if e.get("var") in vars_set:
            out.append(e)
    return out


# Function: Parse code lines as temporary C function and extract identifiers/calls.
# Args: code_lines: C statement lines.
# Returns: Dict: {idents, calls}.
def extract_entities_from_code_lines(code_lines: List[str]) -> Dict[str, List[str]]:
    """Extract identifiers/calls from a list of C statement lines using tree-sitter AST."""
    if not code_lines:
        return {"idents": [], "calls": []}

    wrapped = "void __patch_old__(void) {\n" + "\n".join(code_lines) + "\n}\n"
    src = wrapped.encode("utf-8", errors="ignore")
    tree = C_PARSER.parse(src)
    root = tree.root_node

    idents: Set[str] = set()
    calls: Set[str] = set()

    for n in walk(root):
        if n.type == "identifier":
            ident = node_text(src, n)
            if is_symbol_name(ident) and ident != "__patch_old__":
                idents.add(ident)
        elif n.type == "call_expression":
            fn = n.child_by_field_name("function")
            for ident in identifiers_in_subtree(src, fn):
                if is_symbol_name(ident):
                    calls.add(ident)

    return {"idents": sorted(idents), "calls": sorted(calls)}


# Function: Build pre-patch source-to-sink flow seeded by OLD (-) patch lines.
# Args: old_changed_lines: old diff lines; events: pre-patch events; params/locals_/macros: pre-patch symbol sets.
# Returns: Structured source-sink JSON with LLM flow text.
def build_pre_patch_source_sink(
    old_changed_lines: Dict[int, str],
    events: List[Dict[str, Any]],
    params: Set[str],
    locals_: Set[str],
    macros: Dict[str, str],
) -> Dict[str, Any]:
    """Build source->sink flow seeded by old patch lines.

    Heuristic:
    - treat identifiers on old '-' lines as sink-adjacent symbols
    - sink candidates are vars appearing in old lines with call/assignment-like syntax
    - backward sources from defs: param_def -> source:param, def/def_decl with rhs -> source:rhs
    """
    old_text = "\n".join(v for _, v in sorted(old_changed_lines.items()))

    old_entities = extract_entities_from_code_lines([v for _, v in sorted(old_changed_lines.items())])
    sink_calls: Set[str] = set(old_entities.get("calls", []))

    # sink-adjacent vars from old identifiers, then intersect with tracked vars present in current events
    event_vars = set([e.get("var") for e in events if e.get("var")])
    sink_vars: Set[str] = set([x for x in old_entities.get("idents", []) if x in event_vars])

    # fallback: line-based mapping when old identifiers are too sparse
    if not sink_vars:
        for e in events:
            ln = int(e.get("line", 0))
            if ln in old_changed_lines:
                sink_vars.add(e.get("var"))

    # fallback2: lexical inclusion by compact text
    if not sink_vars:
        compact_old = " ".join(old_text.split())
        for e in events:
            stmt = (e.get("stmt_code") or "")
            if stmt and stmt in compact_old:
                sink_vars.add(e.get("var"))

    sink_vars = {v for v in sink_vars if v}

    # build backward source reasoning per sink var
    per_sink = []
    all_sources: Set[str] = set()
    flow_edges = []

    for sv in sorted(sink_vars):
        sv_events = [e for e in events if e.get("var") == sv]
        defs = [e for e in sv_events if e.get("op") in ("param_def", "def", "def_decl")]

        sources = []
        reasoning = []
        for d in defs:
            op = d.get("op")
            if op == "param_def":
                src = f"param:{sv}"
                sources.append(src)
                reasoning.append(f"{sv} defined from function parameter at line {d.get('line')}")
                flow_edges.append({"source": src, "to": sv, "line": d.get("line"), "kind": "param_def"})
                all_sources.add(src)
            elif op in ("def", "def_decl"):
                rhs = d.get("rhs_vars") or []
                if rhs:
                    for rv in rhs:
                        if rv in params:
                            src = f"param:{rv}"
                        elif rv in macros:
                            src = f"macro:{rv}"
                        elif rv in locals_:
                            src = f"local:{rv}"
                        else:
                            src = f"global_or_external:{rv}"
                        sources.append(src)
                        reasoning.append(f"{sv} depends on {rv} at line {d.get('line')}")
                        flow_edges.append({"source": src, "to": sv, "line": d.get("line"), "kind": "rhs_dep"})
                        all_sources.add(src)

        per_sink.append({
            "sink_var": sv,
            "sink_lines": sorted(set([e.get("line") for e in sv_events if int(e.get("line", 0)) in old_changed_lines])),
            "sink_calls": sorted(sink_calls),
            "candidate_sources": sorted(set(sources)),
            "reasoning": reasoning,
        })

    # LLM-readable flow text
    lines = []
    lines.append("[Pre-patch Source-Sink Flow]")
    lines.append(f"Old patch lines (treated as sink region): {sorted(old_changed_lines.keys())}")
    if old_entities.get("idents"):
        lines.append(f"Old-line idents: {', '.join(old_entities['idents'])}")
    if sink_calls:
        lines.append(f"Sink calls in old region: {', '.join(sorted(sink_calls))}")
    lines.append(f"Sink-adjacent variables: {', '.join(sorted(sink_vars)) if sink_vars else '(none)'}")
    for item in per_sink:
        lines.append(f"- Sink var `{item['sink_var']}`")
        if item["candidate_sources"]:
            lines.append(f"  Sources: {', '.join(item['candidate_sources'])}")
        for r in item["reasoning"]:
            lines.append(f"  - {r}")

    return {
        "schema": "pre_patch_source_sink.v1",
        "old_changed_lines": [{"line": k, "code": v} for k, v in sorted(old_changed_lines.items())],
        "old_line_entities": old_entities,
        "sink_calls": sorted(sink_calls),
        "sink_vars": sorted(sink_vars),
        "sources": sorted(all_sources),
        "edges": flow_edges,
        "per_sink": per_sink,
        "llm_flow_text": "\n".join(lines),
    }


# Function: Render reduced C function text from focused blocks and dependency declarations.
# Args: src_lines/src/fn_node: source and function node; params/locals_: symbols; focused_context: selected blocks.
# Returns: Reduced function C code string.
def build_reduced_function_text(
    src_lines: List[str],
    src: bytes,
    fn_node: Any,
    params: Set[str],
    locals_: Set[str],
    focused_context: Dict[str, Any],
) -> str:
    """Render reduced function-like C text from focused blocks.

    Strategy:
    1) Keep original function signature/header (from function start to '{').
    2) Keep required local declarations (dependency closure).
    3) Keep selected focused statement blocks (de-duplicated by span containment).
    4) Close with '}'.
    """
    body = first_child_of_type(fn_node, "compound_statement")
    if body is None:
        return ""

    # Build header from AST byte ranges to avoid line-slice drift.
    header_prefix = src[fn_node.start_byte:body.start_byte].decode("utf-8", errors="ignore").rstrip()
    header = header_prefix + "\n{"
    blocks = [b for b in focused_context.get("blocks", []) if b.get("kind") == "stmt"]
    blocks = sorted(blocks, key=lambda x: (x["start_line"], x["end_line"]))

    # Keep outer statements first; if a statement is fully contained by an already kept
    # control block, skip it to avoid duplication in reduced source.
    kept: List[Dict[str, Any]] = []
    for b in sorted(blocks, key=lambda x: (-(x["end_line"] - x["start_line"]), x["start_line"])):
        s, e = int(b["start_line"]), int(b["end_line"])
        contained = False
        for k in kept:
            ks, ke = int(k["start_line"]), int(k["end_line"])
            if ks <= s and e <= ke:
                contained = True
                break
        if not contained:
            kept.append(b)
    kept = sorted(kept, key=lambda x: (x["start_line"], x["end_line"]))

    # Dependency locals appearing in kept statements.
    needed_locals: Set[str] = set()
    for b in kept:
        for ident in b.get("all_ids", []):
            if ident in locals_ and ident not in params:
                needed_locals.add(ident)

    decl_map = declaration_nodes_by_var(src, fn_node)

    # Local declaration closure: if declaration introduces more locals used in its init,
    # include them as well.
    selected_decl_keys: Set[str] = set()
    changed = True
    while changed:
        changed = False
        for var in list(needed_locals):
            info = decl_map.get(var)
            if not info:
                continue
            key = f"{info['start_line']}:{info['end_line']}:{info['code']}"
            if key in selected_decl_keys:
                continue
            selected_decl_keys.add(key)
            for dep in info.get("ids", []):
                if dep in locals_ and dep not in needed_locals:
                    needed_locals.add(dep)
                    changed = True

    selected_decls = []
    decl_start_lines: Set[int] = set()
    for key in selected_decl_keys:
        parts = key.split(":", 2)
        start_line = int(parts[0])
        end_line = int(parts[1])
        code = parts[2]

        # Drop declarations already covered by a kept statement block (e.g., inner block locals).
        covered = False
        for b in kept:
            bs, be = int(b["start_line"]), int(b["end_line"])
            if bs <= start_line and end_line <= be and (be - bs) >= 1:
                covered = True
                break
        if covered:
            continue

        selected_decls.append((start_line, end_line, code))
        for ln in range(start_line, end_line + 1):
            decl_start_lines.add(ln)
    selected_decls.sort(key=lambda x: x[0])

    out_lines: List[str] = []
    if header.strip():
        out_lines.append(header.rstrip())

    for _, _, decl_code in selected_decls:
        out_lines.append(decl_code.rstrip())

    if selected_decls and kept:
        out_lines.append("")

    for b in kept:
        # If this focused stmt is exactly a declaration we already emitted, skip duplicate.
        if int(b.get("start_line", 0)) in decl_start_lines and int(b.get("end_line", 0)) in decl_start_lines:
            continue
        raw = (b.get("raw_code") or b.get("code") or "").strip()
        if raw:
            out_lines.append(raw)

    out_lines.append("}")
    return "\n".join(out_lines)


# Function: Build strict compact JSON for direct LLM consumption.
# Args: out: full debug JSON object; debug_json_path: path of full debug JSON.
# Returns: Compact JSON object.
def build_llm_compact_json(out: Dict[str, Any], debug_json_path: str) -> Dict[str, Any]:
    """Build strict compact JSON for LLM.

    Required by user:
      - reduced_function_code
      - patch_delta
      - source_sink_flow: sources + edges
      - debug_json_path
    """
    step_b = out.get("step_b", {})
    pre = out.get("pre_patch_source_sink", {})
    red = out.get("reduced_function", {})

    compact = {
        "schema": "patch_presence_llm_compact.v2",
        "debug_json_path": os.path.abspath(debug_json_path),
        "patch_delta": {
            "key_variables": step_b.get("key_variables", []),
            "called_apis_new": step_b.get("called_apis", []),
            "globals_or_external": step_b.get("globals_or_external", []),
            "macros": step_b.get("macros", []),
            "old_calls": pre.get("old_line_entities", {}).get("calls", []),
            "sink_calls_old": pre.get("sink_calls", []),
            "sink_vars_old": pre.get("sink_vars", []),
        },
        "source_sink_flow": {
            "sources": pre.get("sources", []),
            "edges": pre.get("edges", []),
        },
        "reduced_function_code": red.get("code", ""),
    }
    return compact


# Function: CLI entry point for source analysis pipeline.
# Args: --input/--output required; --emit-reduced-c/--emit-llm-json optional output paths.
# Returns: None.


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def infer_project_name(input_path: str, data: Dict[str, Any]) -> str:
    parent = os.path.basename(os.path.dirname(os.path.abspath(input_path)))
    stem = os.path.splitext(os.path.basename(input_path))[0]
    if parent and parent != "straight_detect":
        return parent
    if stem:
        return stem

    for item in data.values():
        for diff_item in item.get("diff_related", []) or []:
            low = str(diff_item.get("file", "")).lower()
            for name in ("binutils", "ffmpeg", "openssl", "qemu", "tcpdump", "libxml2", "php", "curl"):
                if f"/{name}/" in low or f"{name}_" in low:
                    return name
    return "unknown"


def infer_repo_path(project: str, explicit: str = "") -> str:
    if explicit:
        return os.path.abspath(explicit)

    candidates = []
    if project in PROJECT_REPO_DEFAULTS:
        candidates.append(PROJECT_REPO_DEFAULTS[project])
    candidates.extend([
        os.path.join(DEFAULT_TARGET_ROOT, project),
        os.path.join(DEFAULT_TARGET_ROOT, f"{project}-gdb"),
    ])

    for cand in candidates:
        if os.path.isdir(os.path.join(cand, ".git")):
            return cand
    return ""


def read_commit_info(repo_path: str, commit: str) -> Dict[str, str]:
    if not repo_path or not commit:
        return {"title": "", "message": ""}

    cp_title = subprocess.run(
        ["git", "-C", repo_path, "show", "-s", "--format=%s", commit],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    cp_msg = subprocess.run(
        ["git", "-C", repo_path, "show", "-s", "--format=%B", commit],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return {
        "title": cp_title.stdout.decode("utf-8", errors="ignore").strip() if cp_title.returncode == 0 else "",
        "message": cp_msg.stdout.decode("utf-8", errors="ignore").strip() if cp_msg.returncode == 0 else "",
    }


def parse_diff_files(diff_text: str) -> List[str]:
    files: List[str] = []
    for line in diff_text.splitlines():
        if not line.startswith("diff --git "):
            continue
        parts = line.split(" ")
        if len(parts) >= 4 and parts[3].startswith("b/"):
            files.append(parts[3][2:])
    return files


def parse_range_token(tok: str) -> Tuple[int, int]:
    body = tok[1:]
    if "," in body:
        start_s, count_s = body.split(",", 1)
        start = int(start_s)
        count = int(count_s)
    else:
        start = int(body)
        count = 1
    end = start + max(count, 1) - 1
    return start, end


def parse_hunks_for_file(diff_text: str, rel_file: str) -> List[Dict[str, Any]]:
    hunks: List[Dict[str, Any]] = []
    in_target_file = False
    current: Optional[Dict[str, Any]] = None

    for raw in diff_text.splitlines():
        line = raw.rstrip("\n")

        if line.startswith("diff --git "):
            if current:
                hunks.append(current)
                current = None
            in_target_file = False
            parts = line.split(" ")
            if len(parts) >= 4 and parts[3].startswith("b/"):
                in_target_file = (parts[3][2:] == rel_file)
            continue

        if not in_target_file:
            continue

        if line.startswith("@@ "):
            if current:
                hunks.append(current)
            current = {"header": line, "old_lines": [], "new_lines": []}
            continue

        if current is None:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            current["new_lines"].append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            current["old_lines"].append(line[1:])

    if current:
        hunks.append(current)
    return hunks


def filter_hunks_by_line_range(hunks: List[Dict[str, Any]], start_line: int, end_line: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for h in hunks:
        header = h.get("header", "")
        plus = None
        for tok in header.split(" "):
            if tok.startswith("+"):
                plus = tok
                break
        if not plus:
            continue
        try:
            new_start, new_end = parse_range_token(plus)
        except Exception:
            continue
        if not (new_end < start_line or new_start > end_line):
            out.append(h)
    return out if out else hunks


def compact_prompt_code_text(text: str, max_chars: int = 1200) -> str:
    text = (text or "").strip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + "\n..."


def get_prompt_function_code(cve_item: Dict[str, Any], function_name: str) -> str:
    fc = cve_item.get("function_code", {})
    by_fn = fc.get("by_function", {}) if isinstance(fc, dict) else {}
    fn_item = by_fn.get(function_name, {}) if isinstance(by_fn, dict) else {}
    return (fn_item.get("code", "") if isinstance(fn_item, dict) else "").strip()


def function_names_for_cve(cve_item: Dict[str, Any]) -> List[str]:
    names: List[str] = []
    for name in cve_item.get("functions", []) or []:
        if name not in names:
            names.append(name)
    by_fn = (cve_item.get("function_code", {}) or {}).get("by_function", {}) or {}
    for name in by_fn.keys():
        if name not in names:
            names.append(name)
    return names


def function_metadata(cve_item: Dict[str, Any], function_name: str) -> Dict[str, Any]:
    fc = cve_item.get("function_code", {}) or {}
    by_fn = fc.get("by_function", {}) or {}
    item = by_fn.get(function_name, {}) or {}
    return {
        "commit": item.get("commit") or fc.get("commit", ""),
        "file": item.get("file", ""),
        "found": item.get("found"),
        "prompt_code": item.get("code", ""),
    }


def diff_candidates(cve_item: Dict[str, Any], commit: str = "") -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for idx, item in enumerate(cve_item.get("diff_related", []) or []):
        path = item.get("file", "")
        score = 0
        if commit and commit in os.path.basename(path):
            score += 10
        if os.path.exists(path):
            score += 1
        entries.append({
            "index": idx,
            "file": path,
            "related_hunks": item.get("related_hunks", []),
            "score": score,
        })
    entries.sort(key=lambda x: x["score"], reverse=True)
    return entries


def pick_diff_file(cve_item: Dict[str, Any], commit: str) -> str:
    for item in diff_candidates(cve_item, commit):
        if item.get("file"):
            return item["file"]
    return ""


def find_function_node_for_metadata(
    repo_path: str,
    rel_file: str,
    commit: str,
    function_name: str,
) -> Tuple[Optional[Any], str, List[str], bytes, List[str]]:
    warnings: List[str] = []
    src_text = read_file_at_git_rev(repo_path, rel_file, commit) if commit else None
    if not src_text:
        src_path = os.path.join(repo_path, rel_file)
        if os.path.exists(src_path):
            src_text = read_text(src_path)
            warnings.append("post-patch source read from workspace file")
        else:
            warnings.append("post-patch source unavailable")
            return None, "", [], b"", warnings

    src_lines = src_text.splitlines()
    src_bytes = src_text.encode("utf-8", errors="ignore")
    fn_node = parse_function_node_by_name(src_bytes, function_name)
    if fn_node is None:
        warnings.append(f"function not found in post-patch source: {function_name}")
    return fn_node, src_text, src_lines, src_bytes, warnings


def parse_function_node_by_name(src: bytes, function_name: str) -> Optional[Any]:
    tree = C_PARSER.parse(src)
    candidates = []
    for n in walk(tree.root_node):
        if n.type != "function_definition":
            continue
        decl = None
        for c in walk(n):
            if c.type == "function_declarator":
                decl = c
                break
        if decl is None:
            continue
        ident = None
        for c in walk(decl):
            if c.type == "identifier":
                ident = node_text(src, c)
                break
        if ident == function_name:
            candidates.append(n)
    return candidates[0] if candidates else None


def analyze_function(
    project: str,
    cve_id: str,
    cve_item: Dict[str, Any],
    function_name: str,
    repo_path: str,
) -> Dict[str, Any]:
    meta = function_metadata(cve_item, function_name)
    commit = meta.get("commit", "")
    rel_file = meta.get("file", "")
    diff_file = pick_diff_file(cve_item, commit)
    warnings: List[str] = []
    errors: List[str] = []

    if not rel_file and diff_file and os.path.exists(diff_file):
        files = parse_diff_files(read_text(diff_file))
        rel_file = files[0] if files else ""
        warnings.append("function file missing in input; inferred from diff")

    commit_info = read_commit_info(repo_path, commit)
    prompt_code = get_prompt_function_code(cve_item, function_name)

    base = {
        "project": project,
        "cve_id": cve_id,
        "function": {
            "name": function_name,
            "file": rel_file,
            "commit": commit,
            "found_in_input": meta.get("found"),
        },
        "patch": {
            "repo_path": repo_path,
            "diff_file": diff_file,
            "commit": commit,
        },
        "patch_commit_title": commit_info.get("title", ""),
        "patch_commit_message": commit_info.get("message", ""),
        "prompt_source_reduced_function_code": prompt_code,
        "warnings": warnings,
        "errors": errors,
    }

    if not repo_path:
        errors.append("repo_path is required for AST source analysis")
    if not rel_file:
        errors.append("target source file is missing")
    if not diff_file:
        errors.append("diff file is missing")
    if errors:
        return {**base, "analysis_status": "failed"}

    fn_node, src_text, src_lines, src_bytes, node_warnings = find_function_node_for_metadata(
        repo_path, rel_file, commit, function_name
    )
    warnings.extend(node_warnings)
    if fn_node is None:
        errors.append("unable to locate function AST node")
        return {**base, "analysis_status": "failed"}

    func = FuncInfo(
        function_name,
        rel_file,
        fn_node.start_point[0] + 1,
        fn_node.end_point[0] + 1,
    )

    pre_src_text = read_file_at_git_rev(repo_path, rel_file, f"{commit}^") if commit else None
    if not pre_src_text:
        pre_src_text = src_text
        warnings.append("pre-patch source unavailable; reused post-patch source")

    pre_src_lines = pre_src_text.splitlines()
    pre_src_bytes = pre_src_text.encode("utf-8", errors="ignore")
    pre_fn_node = parse_function_node_by_name(pre_src_bytes, function_name)
    if pre_fn_node is None:
        pre_fn_node = fn_node
        warnings.append("pre-patch function AST unavailable; reused post-patch function AST")

    diff_text = read_text(diff_file)
    old_changed_lines, changed_lines = parse_diff_old_new_lines(diff_text, rel_file, func)
    if not changed_lines and not old_changed_lines:
        broad_func = FuncInfo(function_name, rel_file, 0, 10**9)
        old_changed_lines, changed_lines = parse_diff_old_new_lines(diff_text, rel_file, broad_func)
        warnings.append("no changed lines inside AST function range; fell back to whole-file diff lines")

    params = collect_params(src_bytes, fn_node)
    locals_ = collect_locals(src_bytes, fn_node)
    macros = collect_macros(src_lines, func.end)

    pre_params = collect_params(pre_src_bytes, pre_fn_node)
    pre_locals = collect_locals(pre_src_bytes, pre_fn_node)
    pre_macros = collect_macros(pre_src_lines, func.end)

    key_vars: Set[str] = set()
    called_apis: Set[str] = set()
    per_line_entities = []

    for ln, code in sorted(changed_lines.items()):
        line_entities = extract_line_entities(src_bytes, fn_node, ln)
        vars_on_line = {x for x in line_entities["vars"] if is_symbol_name(x)}
        apis_on_line = {x for x in line_entities["apis"] if is_symbol_name(x)}
        vars_on_line = vars_on_line - apis_on_line

        entities = []
        for ident in sorted(vars_on_line | apis_on_line):
            if ident in apis_on_line:
                kind = "called_api"
            elif ident in macros:
                kind = "macro"
            elif ident in locals_ or ident in params:
                kind = "local_or_param"
            else:
                kind = "global_or_external"

            ent: Dict[str, Any] = {"name": ident, "kind": kind}
            if kind == "macro":
                ent["resolved_value"] = resolve_macro_value(ident, macros)
            entities.append(ent)

            if kind == "called_api":
                called_apis.add(ident)
            else:
                key_vars.add(ident)

        per_line_entities.append({"line": ln, "code": code.strip(), "entities": entities})

    step_b = {
        "schema": "step_b.patch_function_entities.v2",
        "function": {"name": func.name, "file": func.file, "line_range": [func.start, func.end]},
        "changed_lines": per_line_entities,
        "key_variables": sorted(key_vars),
        "called_apis": sorted(called_apis),
        "globals_or_external": sorted([v for v in key_vars if v not in locals_ and v not in params and v not in macros]),
        "macros": [
            {"name": m, "value": macros[m], "resolved_value": resolve_macro_value(m, macros)}
            for m in sorted(key_vars) if m in macros
        ],
    }

    events = classify_def_use(src_bytes, fn_node, src_lines, key_vars)
    step_c = build_step_c(events, sorted(key_vars))

    old_entities_seed = extract_entities_from_code_lines([v for _, v in sorted(old_changed_lines.items())])
    pre_tracked_vars = set(key_vars) | set(old_entities_seed.get("idents", []))
    pre_events = classify_def_use(pre_src_bytes, pre_fn_node, pre_src_lines, pre_tracked_vars)
    pre_patch_source_sink = build_pre_patch_source_sink(
        old_changed_lines=old_changed_lines,
        events=pre_events,
        params=pre_params,
        locals_=pre_locals,
        macros=pre_macros,
    )

    focused_context = build_focused_context(changed_lines, events, src_lines)
    reduced_function_text = build_reduced_function_text(
        src_lines=src_lines,
        src=src_bytes,
        fn_node=fn_node,
        params=params,
        locals_=locals_,
        focused_context=focused_context,
    )

    patch_hunks = filter_hunks_by_line_range(parse_hunks_for_file(diff_text, rel_file), func.start, func.end)

    full = {
        **base,
        "analysis_status": "ok",
        "metadata": {
            "post_source": f"git:{commit}:{rel_file}" if commit else os.path.join(repo_path, rel_file),
            "pre_source": f"git:{commit}^:{rel_file}" if commit else os.path.join(repo_path, rel_file),
            "function": step_b["function"],
        },
        "patch_hunk": patch_hunks,
        "step_b": step_b,
        "step_c": step_c,
        "pre_patch_source_sink": pre_patch_source_sink,
        "focused_context": focused_context,
        "reduced_function": {
            "schema": "reduced_function.v1",
            "code": reduced_function_text,
        },
    }
    return full


def build_min_function(full_fn: Dict[str, Any]) -> Dict[str, Any]:
    step_b = full_fn.get("step_b", {})
    pre = full_fn.get("pre_patch_source_sink", {})
    reduced = (full_fn.get("reduced_function", {}) or {}).get("code", "")
    if not reduced:
        reduced = full_fn.get("prompt_source_reduced_function_code", "")

    return {
        "name": (full_fn.get("function", {}) or {}).get("name", ""),
        "file": (full_fn.get("function", {}) or {}).get("file", ""),
        "commit": (full_fn.get("function", {}) or {}).get("commit", ""),
        "analysis_status": full_fn.get("analysis_status", ""),
        "patch_delta": {
            "key_variables": step_b.get("key_variables", []),
            "called_apis_new": step_b.get("called_apis", []),
            "globals_or_external": step_b.get("globals_or_external", []),
            "macros": step_b.get("macros", []),
            "old_calls": pre.get("old_line_entities", {}).get("calls", []),
            "sink_calls_old": pre.get("sink_calls", []),
            "sink_vars_old": pre.get("sink_vars", []),
        },
        "source_sink_flow": {
            "sources": pre.get("sources", []),
            "edges": pre.get("edges", []),
        },
        "patch_hunk": full_fn.get("patch_hunk", []),
        "reduced_function_code": reduced,
        "warnings": full_fn.get("warnings", []),
        "errors": full_fn.get("errors", []),
    }


def build_outputs(
    input_path: str,
    project: str,
    repo_path: str,
    data: Dict[str, Any],
    selected_cves: Optional[Set[str]],
    limit: int,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    full_cves: Dict[str, Any] = {}
    min_cves: Dict[str, Any] = {}

    processed = 0
    for cve_id, cve_item in data.items():
        if selected_cves and cve_id not in selected_cves:
            continue
        if limit and processed >= limit:
            break

        functions = function_names_for_cve(cve_item)
        analyses = []
        for fn in functions:
            analyses.append(analyze_function(project, cve_id, cve_item, fn, repo_path))

        commit = ""
        if analyses:
            commit = (analyses[0].get("function", {}) or {}).get("commit", "")
        commit_info = read_commit_info(repo_path, commit)
        min_functions = [build_min_function(x) for x in analyses]
        all_hunks = []
        for fn_min in min_functions:
            all_hunks.extend(fn_min.get("patch_hunk", []))

        reduced_parts = []
        for fn_min in min_functions:
            code = fn_min.get("reduced_function_code", "")
            if not code:
                continue
            reduced_parts.append({fn_min.get("name", ""): code})

        full_cves[cve_id] = {
            "summary": cve_item.get("summary", ""),
            "cwe": cve_item.get("cwe", []),
            "functions": functions,
            "diff_related": cve_item.get("diff_related", []),
            "function_analyses": analyses,
        }

        min_cves[cve_id] = {
            "project": project,
            "cve_id": cve_id,
            "cwe": (cve_item.get("cwe", []) or [""])[0] if isinstance(cve_item.get("cwe", []), list) else str(cve_item.get("cwe", "")),
            "vulnerability_description": cve_item.get("summary", ""),
            "patch_commit_message": commit_info.get("message", ""),
            "patch_hunk": all_hunks,
            "reduced_function_code": reduced_parts,
            "functions": min_functions,
        }
        min_cves[cve_id]["functions"] = [x.get("name", "") for x in min_functions]
        processed += 1

    full = {
        "schema": "project_source_analysis.full.v1",
        "input": os.path.abspath(input_path),
        "project": project,
        "repo_path": repo_path,
        "cve_count": len(full_cves),
        "cves": full_cves,
    }
    compact = min_cves
    return full, compact


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="project-level CVE JSON, e.g. straight_detect/binutils/binutils.json")
    ap.add_argument("--repo-path", default="", help="git repo path; required if it cannot be inferred")
    ap.add_argument("--project", default="", help="project name; inferred from input path when omitted")
    ap.add_argument("--output-full", default=os.path.join(DEFAULT_OUTPUT_DIR, "project_source_analysis.full.json"))
    ap.add_argument("--output-min", default=os.path.join(DEFAULT_OUTPUT_DIR, "source_analyze_v2.min.json"))
    ap.add_argument("--cve", action="append", default=[], help="optional CVE id filter; can be repeated")
    ap.add_argument("--limit", type=int, default=0, help="optional max number of CVEs to process")
    args = ap.parse_args()

    data = load_json(args.input)
    project = args.project or infer_project_name(args.input, data)
    repo_path = infer_repo_path(project, args.repo_path)
    if not repo_path:
        raise RuntimeError("repo path could not be inferred; pass --repo-path")

    selected_cves = set(args.cve) if args.cve else None
    full, compact = build_outputs(args.input, project, repo_path, data, selected_cves, args.limit)
    write_json(args.output_full, full)
    write_json(args.output_min, compact)
    print(f"Wrote full analysis: {os.path.abspath(args.output_full)}")
    print(f"Wrote compact analysis: {os.path.abspath(args.output_min)}")


if __name__ == "__main__":
    main()
