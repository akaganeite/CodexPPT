#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Git Commit C/C++ Function Analyzer (Batch Mode)

This script automatically analyzes Git commits specified by a details file for multiple projects,
and reports the list of functions added, deleted, or modified in C/C++ source files.
The results are aggregated and output to a JSON file.

Dependencies:
- Git
- Universal Ctags

Usage:
python source_analyzer.py
"""

import sys
import subprocess
import os
import re
import tempfile
import json
from pathlib import Path

from builder.config import BuildConfig
from builder.db import ProjectDB
from builder.logging import get_logger

# --- Core Functions ---

def run_command(command, check=True, cwd=None):
    """Execute a system command and return its standard output"""
    if not cwd:
        raise ValueError("Working directory (cwd) must be specified.")
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=cwd,
            check=check,
            encoding='utf-8',
            errors='ignore'
        )
        return result.stdout.strip()
    except FileNotFoundError:
        print(f"Error: Command '{command[0]}' not found. Please ensure it is installed and in your PATH.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error: Command '{' '.join(command)}' failed in '{cwd}'.")
        print(f"Return code: {e.returncode}")
        print(f"Error output:\n{e.stderr.strip()}")
        if check:
            sys.exit(1)
        return None

def get_changed_c_files(commit_hash, project_path):
    """Get list of changed C/C++/H files in specified commit"""
    command = [
        'git', 'diff-tree', '--no-commit-id', '--name-only', '-r',
        f'{commit_hash}^!', '--', '*.c','*.cpp','*.cc','*.c.in'
    ]
    output = run_command(command, cwd=project_path)
    return output.split('\n') if output and output.strip() else []

def get_file_content_at_commit(commit_spec, file_path, project_path):
    """Get file content from specified commit"""
    if not commit_spec:
        return ""
    command = ['git', 'show', f'{commit_spec}:{file_path}']
    return run_command(command, check=False, cwd=project_path) or ""

def parse_ctags_output(ctags_output):
    """Parse ctags output, build mapping of function name to start/end line numbers"""
    func_map = {}
    line_pattern = re.compile(r'^(\S+)\s+(\S+)\s+(/\^.*?\$/;"|.*?)\s+(.*)$')
    for line in ctags_output.strip().split('\n'):
        match = line_pattern.match(line)
        if not match:
            continue
        name, _, _, rest_str = match.groups()
        rest = rest_str.split('\t')
        kind_field = next((p for p in rest if p.startswith('kind:')), None)
        if not kind_field and rest and rest[0] == 'f':
            kind_field = 'kind:function'
        if kind_field == 'kind:function':
            line_info = next((p for p in rest if p.startswith('line:')), "")
            end_info = next((p for p in rest if p.startswith('end:')), "")
            start_line = int(re.search(r'line:(\d+)', line_info).group(1)) if line_info else 0
            end_line = int(re.search(r'end:(\d+)', end_info).group(1)) if end_info else start_line
            if start_line:
                func_map[name] = {'start': start_line, 'end': end_line}
    return func_map

def parse_diff_hunks(diff_output):
    """Parse diff output, extract changed line numbers"""
    changed_lines_before, changed_lines_after = set(), set()
    hunk_pattern = re.compile(r'^@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@', re.MULTILINE)
    for match in hunk_pattern.finditer(diff_output):
        start_old, count_old, start_new, count_new = match.groups()
        count_old = int(count_old) if count_old else 1
        count_new = int(count_new) if count_new else 1
        start_old, start_new = int(start_old), int(start_new)
        if count_old > 0:
            changed_lines_before.update(range(start_old, start_old + count_old))
        if count_new > 0:
            changed_lines_after.update(range(start_new, start_new + count_new))
    return changed_lines_before, changed_lines_after

def analyze_commit(commit_hash, project_path):
    """Main analysis function, returns a dictionary containing analysis results"""
    print(f"[*] Analyzing Commit: {commit_hash[:7]} in {project_path.name}")
    changed_files = get_changed_c_files(commit_hash, project_path)
    if not changed_files:
        print("    -> No C/C++ source file changes found.")
        return None

    report = {"added": [], "deleted": [], "modified": []}
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        for file_path in changed_files:
            content_before = get_file_content_at_commit(f'{commit_hash}^', file_path, project_path)
            content_after = get_file_content_at_commit(commit_hash, file_path, project_path)

            temp_file_before = temp_path / "before_file.c"
            temp_file_after = temp_path / "after_file.c"
            temp_file_before.write_text(content_before, encoding='utf-8', errors='ignore')
            temp_file_after.write_text(content_after, encoding='utf-8', errors='ignore')

            ctags_cmd = ['ctags', '--kinds-c=f', '--fields=+ne', '-o', '-']
            ctags_out_before = run_command(ctags_cmd + [str(temp_file_before)], cwd=project_path)
            ctags_out_after = run_command(ctags_cmd + [str(temp_file_after)], cwd=project_path)

            map_before = parse_ctags_output(ctags_out_before)
            map_after = parse_ctags_output(ctags_out_after)

            added = set(map_after) - set(map_before)
            deleted = set(map_before) - set(map_after)
            report["added"].extend({"function": func, "file": file_path} for func in added)
            report["deleted"].extend({"function": func, "file": file_path} for func in deleted)

            diff_output = run_command(['git', 'diff', '-U0', f'{commit_hash}^', commit_hash, '--', file_path], cwd=project_path)
            changed_ln_before, changed_ln_after = parse_diff_hunks(diff_output)

            modified_in_file = set()
            potential_modified = set(map_before) & set(map_after)
            for func in potential_modified:
                # Check if the function body overlaps with changed lines
                func_lines_before = range(map_before[func]['start'], map_before[func]['end'] + 1)
                func_lines_after = range(map_after[func]['start'], map_after[func]['end'] + 1)
                if not changed_ln_before.isdisjoint(func_lines_before) or \
                   not changed_ln_after.isdisjoint(func_lines_after):
                    modified_in_file.add(func)
            report["modified"].extend({"function": func, "file": file_path} for func in modified_in_file)

    seen_added_deleted = {(item["function"], item["file"]) for kind in ("added", "deleted") for item in report[kind]}
    formatted_report = []
    seen = set()
    for change_type in ("added", "deleted", "modified"):
        for item in report[change_type]:
            key = (item["function"], item["file"], change_type)
            if change_type == "modified" and (item["function"], item["file"]) in seen_added_deleted:
                continue
            if key in seen:
                continue
            seen.add(key)
            formatted_report.append({"function": item["function"], "type": change_type, "file": item["file"]})
    formatted_report.sort(key=lambda item: (item["function"], item["file"], item["type"]))

    return formatted_report


def run_source_analysis(config: BuildConfig, db: ProjectDB) -> None:
    """Run source analysis for selected fix commits and store changed functions."""
    log = get_logger(config.output, "source_analysis")
    for row in db.selected_fixes(config):
        cve_id = row["cve_id"]
        commit = row["commit_hash"]
        existing = db.conn.execute(
            """
            SELECT
              COUNT(*) AS total,
              SUM(CASE WHEN COALESCE(file_path, '') != '' THEN 1 ELSE 0 END) AS with_file_path
            FROM source_functions
            WHERE cve_id=? AND commit_hash=? AND active=1
            """,
            (cve_id, commit),
        ).fetchone()
        if existing and existing["total"] and existing["with_file_path"]:
            log.trace("reuse source functions", cve=cve_id, commit=commit)
            continue
        if existing and existing["total"] and not existing["with_file_path"]:
            log.trace("refresh source functions missing file paths", cve=cve_id, commit=commit)
        try:
            result = analyze_commit(commit, config.repo)
        except SystemExit as exc:
            log.error("source analyzer exited", cve=cve_id, commit=commit, error=str(exc))
            continue
        except Exception as exc:
            log.error("source analyzer failed", cve=cve_id, commit=commit, error=str(exc))
            continue
        if not result:
            log.warn("source analyzer found no functions", cve=cve_id, commit=commit)
            continue
        db.replace_source_functions(cve_id, commit, result)
        log.trace("source functions recorded", cve=cve_id, commit=commit, functions=[x.get("function") for x in result])
    db.record_stage("source_analysis", "ok", {})

import argparse

# --- Main Execution Logic ---

def main():
    """Main function for automated project processing"""
    parser = argparse.ArgumentParser(description="Git Commit Analyzer")
    parser.add_argument("-p", "--product", required=True, help="Product name (e.g., tcpdump)")
    parser.add_argument("-r", "--repo", required=True, help="Path to the product git repository")
    args = parser.parse_args()

    product_name = args.product
    repo_path = Path(args.repo).resolve()

    if not repo_path.is_dir():
        print(f"Error: Repository path {repo_path} not found.")
        sys.exit(1)

    print(f"\n{'='*20} Processing Project: {product_name} {'='*20}")

    # 1. Read input list from New/Diff/{product}/details.json
    details_path = Path(f"Diff/{product_name}/details.json")
    if not details_path.exists():
        print(f"Error: details.json not found at {details_path}")
        sys.exit(1)

    try:
        with open(details_path, 'r', encoding='utf-8') as f:
            details_data = json.load(f)
    except Exception as e:
        print(f"Error reading details.json: {e}")
        sys.exit(1)

    # 2. Determine output path and load existing results for incremental update
    output_path = Path(f"Diff/{product_name}/source_diff.json")
    existing_results = {}

    if output_path.exists():
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                existing_results = json.load(f)
            print(f"Loaded existing results for {len(existing_results)} CVEs.")
        except Exception as e:
            print(f"Warning: Failed to load existing output (will overwrite): {e}")

    # 3. Analyze commits
    updated_count = 0
    for entry in details_data:
        cve_id = entry.get("cve")
        commit_hash = entry.get("commit")

        if not cve_id or not commit_hash:
            continue

        # Skip if already analyzed
        if cve_id in existing_results and existing_results[cve_id].get("commit") == commit_hash:
            # print(f"Skipping {cve_id} (already analyzed)")
            continue

        print(f"Analyzing {cve_id} ({commit_hash})...")
        analysis_result = analyze_commit(commit_hash, repo_path)

        if analysis_result is not None:
             existing_results[cve_id] = {
                 "commit": commit_hash,
                 "analysis": analysis_result
             }
             updated_count += 1

             # Save incrementally (optional, but safer)
             if updated_count % 5 == 0:
                 with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(existing_results, f, indent=4)

    # 4. Final Save
    print(f"\n[*] Analysis complete. Writing {len(existing_results)} entries to {output_path}...")
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(existing_results, f, indent=4)
        print("[*] Done!")
    except Exception as e:
        print(f"Error writing output file: {e}")

if __name__ == '__main__':
    main()
