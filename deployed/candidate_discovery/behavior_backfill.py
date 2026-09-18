"""Populate behavior metadata for the CVEs retained by a deployed dataset.

The deployed workflow keeps its own final CVE set, which is often broader than
the current base testset.  This utility copies valid base behavior entries when
available and deterministically prepares reduced source context for only the
remaining deployed CVEs before invoking the existing DeepSeek behavior script.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..io_utils import read_json, write_json


ROOT = Path(__file__).resolve().parents[2]
BASE_RCA = ROOT / "base" / "RCA"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Backfill behavior JSON for deployed groundtruth CVEs.")
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
    parser.add_argument("--api-timeout", type=int, default=600)
    parser.add_argument("--retries", type=int, default=2, help="Additional retries for per-CVE model failures.")
    parser.add_argument("--source-only", action="store_true", help="Prepare source metadata but do not invoke DeepSeek.")
    return parser.parse_args()


def groundtruth_cves(path: Path) -> list[str]:
    data = read_json(path)
    if not isinstance(data, list):
        raise ValueError(f"groundtruth must be a list: {path}")
    return [str(item["CVE"]) for item in data if isinstance(item, dict) and item.get("CVE")]


def patch_source_ok(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("commit"), str) and isinstance(value.get("locations"), list)


def behavior_ok(item: Any, functions: list[str]) -> bool:
    if not isinstance(item, dict):
        return False
    if not item.get("root_cause_analysis") or not item.get("patch_intent_analysis") or not patch_source_ok(item.get("patch_source")):
        return False
    anchors = item.get("function_anchors")
    return isinstance(anchors, dict) and all(isinstance(anchors.get(function), list) and len(anchors[function]) >= 5 for function in functions)


def reusable_behavior(
    cves: list[str], metadata: dict[str, Any], *sources: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    """Select one complete behavior entry per deployed CVE in source priority order."""

    out: dict[str, Any] = {}
    missing: list[str] = []
    for cve_id in cves:
        functions = list((metadata.get(cve_id) or {}).get("functions") or [])
        entry = next((source[cve_id] for source in sources if behavior_ok(source.get(cve_id), functions)), None)
        if entry is None:
            missing.append(cve_id)
        else:
            out[cve_id] = entry
    return out, missing


def canonical_commit(repo: Path, commit: str) -> str:
    if not commit:
        return ""
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", f"{commit}^{{commit}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    value = proc.stdout.decode("utf-8", errors="replace").strip()
    return value if proc.returncode == 0 and value else commit


def number_list(value: Any) -> list[int]:
    output: list[int] = []
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            line = int(item.get("line") or 0)
        except (TypeError, ValueError):
            continue
        if line > 0 and line not in output:
            output.append(line)
    return sorted(output)


def source_locations(full_item: dict[str, Any]) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    for analysis in full_item.get("function_analyses") or []:
        if not isinstance(analysis, dict):
            continue
        function = analysis.get("function") if isinstance(analysis.get("function"), dict) else {}
        metadata = analysis.get("metadata") if isinstance(analysis.get("metadata"), dict) else {}
        metadata_function = metadata.get("function") if isinstance(metadata.get("function"), dict) else {}
        step_b = analysis.get("step_b") if isinstance(analysis.get("step_b"), dict) else {}
        step_function = step_b.get("function") if isinstance(step_b.get("function"), dict) else {}
        name = str(function.get("name") or metadata_function.get("name") or step_function.get("name") or "")
        file_path = str(function.get("file") or metadata_function.get("file") or step_function.get("file") or "").removeprefix("./")
        ranges = metadata_function.get("line_range") or step_function.get("line_range") or []
        try:
            function_range = [int(ranges[0]), int(ranges[1])] if len(ranges) == 2 else []
        except (TypeError, ValueError):
            function_range = []
        pre_patch = analysis.get("pre_patch_source_sink") if isinstance(analysis.get("pre_patch_source_sink"), dict) else {}
        location = {
            "function": name,
            "file": file_path,
            "function_line_range": function_range,
            "changed_old_lines": number_list(pre_patch.get("old_changed_lines")),
            "changed_new_lines": number_list(step_b.get("changed_lines")),
        }
        if (name or file_path) and location not in locations:
            locations.append(location)
    return locations


def enrich_generated_patch_source(
    behavior: dict[str, Any], full: dict[str, Any], metadata: dict[str, Any], repo: Path, cve_ids: list[str]
) -> int:
    source_cves = full.get("cves") if isinstance(full.get("cves"), dict) else {}
    updated = 0
    for cve_id in cve_ids:
        item = behavior.get(cve_id)
        if not isinstance(item, dict):
            continue
        metadata_item = metadata.get(cve_id) if isinstance(metadata.get(cve_id), dict) else {}
        commit = str((metadata_item.get("function_code") or {}).get("commit") or "")
        locations = source_locations(source_cves.get(cve_id) if isinstance(source_cves.get(cve_id), dict) else {})
        patch_source = {"commit": canonical_commit(repo, commit), "locations": locations}
        if item.get("patch_source") != patch_source:
            item["patch_source"] = patch_source
            updated += 1
    return updated


def run_command(command: list[str]) -> None:
    proc = subprocess.run(command, cwd=ROOT, check=False)
    if proc.returncode:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(command)}")


def source_analyze(input_path: Path, repo: Path, project: str, full_path: Path, min_path: Path) -> None:
    run_command(
        [
            sys.executable,
            str(BASE_RCA / "project_source_analysis.py"),
            "--input",
            str(input_path),
            "--repo-path",
            str(repo),
            "--project",
            project,
            "--output-full",
            str(full_path),
            "--output-min",
            str(min_path),
        ]
    )


def hunk_payload(text: str) -> list[dict[str, Any]]:
    """Normalize a raw unified hunk enough for the behavior prompt."""

    output = []
    for fragment in re.split(r"(?=^@@ )", text, flags=re.MULTILINE):
        lines = fragment.splitlines()
        if not lines or not lines[0].startswith("@@"):
            continue
        old_lines = [line[1:] for line in lines[1:] if line.startswith("-") and not line.startswith("---")]
        new_lines = [line[1:] for line in lines[1:] if line.startswith("+") and not line.startswith("+++")]
        output.append({"header": lines[0], "old_lines": old_lines, "new_lines": new_lines})
    return output


def hunk_new_start(hunk: str) -> int:
    match = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)", hunk)
    return int(match.group(1)) if match else 1


def fallback_source_context(repo: Path, commit: str, rel_file: str, hunk: str) -> str:
    if not commit or not rel_file:
        return ""
    proc = subprocess.run(
        ["git", "-C", str(repo), "show", f"{commit}:{rel_file}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if proc.returncode:
        return ""
    lines = proc.stdout.decode("utf-8", errors="replace").splitlines()
    start = max(0, hunk_new_start(hunk) - 31)
    end = min(len(lines), start + 100)
    return "\n".join(lines[start:end])


def repair_empty_source_entries(source_min_path: Path, source_full_path: Path, metadata: dict[str, Any], repo: Path) -> list[str]:
    """Provide hunk/file context for macro-expanded functions absent from the C AST."""

    source_min = read_json(source_min_path)
    source_full = read_json(source_full_path)
    if not isinstance(source_min, dict) or not isinstance(source_full, dict):
        return []
    repaired = []
    full_cves = source_full.get("cves") if isinstance(source_full.get("cves"), dict) else {}
    for cve_id, item in source_min.items():
        if not isinstance(item, dict) or (item.get("patch_hunk") and item.get("reduced_function_code")):
            continue
        metadata_item = metadata.get(cve_id) if isinstance(metadata.get(cve_id), dict) else {}
        diff_entries = metadata_item.get("diff_related") if isinstance(metadata_item.get("diff_related"), list) else []
        raw_hunks = [hunk for diff in diff_entries if isinstance(diff, dict) for hunk in diff.get("related_hunks") or [] if isinstance(hunk, str)]
        if not raw_hunks:
            continue
        functions = list(item.get("functions") or metadata_item.get("functions") or [])
        detail_map = (metadata_item.get("function_code") or {}).get("by_function") or {}
        commit = str((metadata_item.get("function_code") or {}).get("commit") or "")
        first_hunk = raw_hunks[0]
        item["patch_hunk"] = [entry for hunk in raw_hunks for entry in hunk_payload(hunk)]
        item["reduced_function_code"] = [
            {
                function: fallback_source_context(
                    repo,
                    commit,
                    str((detail_map.get(function) or {}).get("file") or ""),
                    first_hunk,
                )
            }
            for function in functions
        ]
        full_item = full_cves.get(cve_id) if isinstance(full_cves.get(cve_id), dict) else {}
        analyses = full_item.get("function_analyses") if isinstance(full_item.get("function_analyses"), list) else []
        for analysis in analyses:
            if not isinstance(analysis, dict):
                continue
            function = analysis.get("function") if isinstance(analysis.get("function"), dict) else {}
            function_name = str(function.get("name") or "")
            rel_file = str((detail_map.get(function_name) or {}).get("file") or "")
            if rel_file:
                function["file"] = rel_file
            analysis["step_b"] = {
                "function": {"name": function_name, "file": rel_file, "line_range": []},
                "changed_lines": [],
            }
        repaired.append(cve_id)
    if repaired:
        write_json(source_min_path, source_min)
        write_json(source_full_path, source_full)
    return repaired


def generate_behavior(source_min: Path, behavior_path: Path, cve_ids: list[str], timeout: int) -> None:
    command = [
        sys.executable,
        str(BASE_RCA / "generate_behavior_analysis_deepseek.py"),
        "--input",
        str(source_min),
        "--output",
        str(behavior_path),
        "--resume",
        "--api-timeout",
        str(timeout),
    ]
    for cve_id in cve_ids:
        command.extend(("--cve", cve_id))
    run_command(command)


def backfill_behavior(
    *,
    project: str,
    output: Path,
    repo: Path,
    base_root: Path,
    arch: str = "amd64",
    api_timeout: int = 600,
    retries: int = 2,
    source_only: bool = False,
) -> dict[str, Any]:
    output = output.expanduser().resolve()
    repo = repo.expanduser().resolve()
    base_root = base_root.expanduser().resolve()
    exports = output / "exports"
    audit = output / "deployed" / "audit"
    metadata_path = exports / f"{project}_metadata.json"
    groundtruth_path = exports / f"groundtruth.ubuntu-{arch}.json"
    behavior_path = exports / f"{project}_behavior.json"
    base_behavior_path = base_root / project / "exports" / f"{project}_behavior.json"
    cves = groundtruth_cves(groundtruth_path)
    metadata = read_json(metadata_path)
    if not isinstance(metadata, dict):
        raise ValueError(f"metadata must be a CVE mapping: {metadata_path}")
    absent = [cve_id for cve_id in cves if cve_id not in metadata]
    if absent:
        raise ValueError(f"metadata missing deployed CVEs: {', '.join(absent)}")

    deployed_behavior = read_json(behavior_path) if behavior_path.is_file() else {}
    base_behavior = read_json(base_behavior_path) if base_behavior_path.is_file() else {}
    deployed_behavior = deployed_behavior if isinstance(deployed_behavior, dict) else {}
    base_behavior = base_behavior if isinstance(base_behavior, dict) else {}

    input_path = audit / "behavior_backfill_input.json"
    full_path = audit / "behavior_source_analysis.full.json"
    min_path = audit / "behavior_source_analysis.min.json"
    # A direct/retried behavior generator may have completed before this wrapper
    # regains control. Reattach deterministic source coordinates before judging
    # whether an entry is reusable, without rerunning AST analysis.
    if full_path.is_file() and deployed_behavior:
        existing_full = read_json(full_path)
        existing_cves = list((existing_full.get("cves") or {}).keys()) if isinstance(existing_full, dict) else []
        if existing_cves and enrich_generated_patch_source(deployed_behavior, existing_full, metadata, repo, existing_cves):
            write_json(behavior_path, deployed_behavior)
    behavior, missing = reusable_behavior(cves, metadata, deployed_behavior, base_behavior)
    if missing:
        write_json(input_path, {cve_id: metadata[cve_id] for cve_id in missing})
        source_analyze(input_path, repo, project, full_path, min_path)
        fallback_repaired = repair_empty_source_entries(min_path, full_path, metadata, repo)
        write_json(behavior_path, behavior)
    else:
        fallback_repaired = []
    if missing and not source_only:
            for _ in range(max(0, retries) + 1):
                source_min = read_json(min_path)
                if not isinstance(source_min, dict):
                    raise ValueError(f"source analyzer did not write a CVE mapping: {min_path}")
                pending = [cve_id for cve_id in missing if not behavior_ok(behavior.get(cve_id), list(source_min.get(cve_id, {}).get("functions") or []))]
                if not pending:
                    break
                generate_behavior(min_path, behavior_path, pending, api_timeout)
                behavior = read_json(behavior_path)
                behavior = behavior if isinstance(behavior, dict) else {}
                enrich_generated_patch_source(behavior, read_json(full_path), metadata, repo, pending)
                write_json(behavior_path, behavior)
    else:
        write_json(behavior_path, behavior)

    behavior = read_json(behavior_path) if behavior_path.is_file() else {}
    behavior = behavior if isinstance(behavior, dict) else {}
    incomplete = [cve_id for cve_id in cves if not behavior_ok(behavior.get(cve_id), list(metadata[cve_id].get("functions") or []))]
    # Keep the public export exactly aligned with deployed groundtruth ordering.
    write_json(behavior_path, {cve_id: behavior[cve_id] for cve_id in cves if cve_id in behavior})
    reused_deployed = [
        cve_id
        for cve_id in cves
        if behavior_ok(deployed_behavior.get(cve_id), list(metadata[cve_id].get("functions") or []))
    ]
    reused_base = [
        cve_id
        for cve_id in cves
        if cve_id not in reused_deployed
        and behavior_ok(base_behavior.get(cve_id), list(metadata[cve_id].get("functions") or []))
    ]
    stats = {
        "schema": "ubuntu-deployed-behavior-backfill-v1",
        "project": project,
        "groundtruth_cves": len(cves),
        "reused_deployed": len(reused_deployed),
        "reused_base": len(reused_base),
        "source_analyzed": len(missing),
        "source_fallback_repaired": fallback_repaired,
        "behavior_complete": len(cves) - len(incomplete),
        "incomplete_cves": incomplete,
        "source_only": source_only,
        "behavior": str(behavior_path),
    }
    write_json(audit / "behavior_backfill.json", stats)
    return stats


def main() -> int:
    args = parse_args()
    output = args.output.expanduser().resolve()
    base_root = args.base_root or (output.parent.parent if output.parent.name == "deployed" else output.parent)
    stats = backfill_behavior(
        project=args.project,
        output=output,
        repo=args.repo,
        base_root=base_root,
        arch=args.arch,
        api_timeout=args.api_timeout,
        retries=args.retries,
        source_only=args.source_only,
    )
    print(json.dumps(stats, indent=2))
    return 0 if not stats["incomplete_cves"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
