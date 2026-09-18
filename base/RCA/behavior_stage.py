from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from builder.config import BuildConfig
from builder.db import ProjectDB
from builder.logging import get_logger
from RCA.patch_source import enrich_behavior_file, patch_source_ok
from RCA.related_file_allowlist import ALLOWLIST_SCHEMA
from utils.io import read_json, write_json, write_text
from utils.paths import ROOT


RCA_ROOT = ROOT / "RCA"


def diff_files(diff_path: str) -> list[str]:
    if not diff_path or not Path(diff_path).exists():
        return []
    files: list[str] = []
    for line in Path(diff_path).read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("+++ b/"):
            rel = line[len("+++ b/") :].strip()
            if rel != "/dev/null" and rel not in files:
                files.append(rel)
    return files


def function_definition_pattern(function: str) -> re.Pattern[str]:
    return re.compile(r"(^|[^\w])" + re.escape(function) + r"\s*\(", re.M)


def git_show(repo: Path, commit: str, rel_file: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), "show", f"{commit}:{rel_file}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return proc.stdout.decode("utf-8", errors="replace") if proc.returncode == 0 else ""


def infer_function_file(repo: Path, commit: str, diff_path: str, function: str) -> str:
    candidates = diff_files(diff_path)
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        return ""
    pattern = function_definition_pattern(function)
    matches = []
    for rel_file in candidates:
        text = git_show(repo, commit, rel_file)
        if pattern.search(text):
            matches.append(rel_file)
    if len(matches) == 1:
        return matches[0]
    return matches[0] if matches else candidates[0]


def source_metadata_item(config: BuildConfig, db: ProjectDB, row) -> dict[str, Any]:
    cve_id = row["cve_id"]
    functions = db.functions_for_cve(cve_id)
    details = db.function_details_for_cve(cve_id)
    by_function: dict[str, dict[str, str]] = {}
    diff_path = row["diff_path"] or ""
    commit = row["commit_hash"] or ""
    for detail in details:
        function = detail["function"]
        file_path = detail["file_path"] or infer_function_file(config.repo, commit, diff_path, function)
        by_function.setdefault(
            function,
            {
                "file": file_path,
                "change_type": detail["change_type"] or "",
            },
        )
    return {
        "functions": functions,
        "summary": row["summary"],
        "cwe": json.loads(row["cwe_json"] or "[]"),
        "diff_related": [{"file": diff_path}],
        "function_code": {
            "commit": commit,
            "by_function": by_function or {fn: {"file": ""} for fn in functions},
        },
    }


def write_project_json(config: BuildConfig, db: ProjectDB) -> int:
    data = {}
    for row in db.selected_fixes(config):
        data[row["cve_id"]] = source_metadata_item(config, db, row)
    write_json(config.rca_project_json, data)
    return len(data)


def selected_rca_cves(config: BuildConfig, db: ProjectDB) -> list[str]:
    return sorted({row["cve_id"] for row in db.selected_fixes(config)})


def run_logged_command(cmd: list[str], log_path: Path, cwd: Path) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [str(part) for part in cmd],
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    stdout = proc.stdout.decode("utf-8", errors="replace")
    write_text(log_path, stdout)
    return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, None)


def cve_filters(config: BuildConfig) -> list[str]:
    out = []
    for cve_id in config.cves:
        out.extend(["--cve", cve_id])
    return out


def run_project_source_analysis(config: BuildConfig) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        str(RCA_ROOT / "project_source_analysis.py"),
        "--input",
        str(config.rca_project_json),
        "--project",
        config.project,
        "--repo-path",
        str(config.repo),
        "--output-full",
        str(config.rca_source_full_json),
        "--output-min",
        str(config.rca_source_min_json),
        "--output-allowlist",
        str(config.rca_related_file_allowlist_json),
        *cve_filters(config),
    ]
    return run_logged_command(cmd, config.rca_dir / "logs" / "project_source_analysis.log", ROOT.parent)


def run_behavior_analysis(config: BuildConfig) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        str(RCA_ROOT / "generate_behavior_analysis_deepseek.py"),
        "--input",
        str(config.rca_source_min_json),
        "--output",
        str(config.rca_behavior_json),
        "--resume",
    ]
    if config.metadata_mode != "behavior":
        cmd.append("--dry-run")
    return run_logged_command(cmd, config.rca_dir / "logs" / "generate_behavior_analysis_deepseek.log", ROOT.parent)


def enrich_behavior_patch_source(config: BuildConfig, db: ProjectDB, cve_ids: list[str]) -> int:
    commits = {row["cve_id"]: row["commit_hash"] or "" for row in db.selected_fixes(config)}
    return enrich_behavior_file(
        config.rca_behavior_json,
        config.rca_source_full_json,
        config.repo,
        commits,
        cve_ids,
    )


def mark_source_statuses(
    config: BuildConfig,
    db: ProjectDB,
    cve_ids: list[str],
    forced_status: str = "",
    detail: dict[str, Any] | None = None,
) -> dict[str, int]:
    source_data = read_json(config.rca_source_min_json, {})
    if not isinstance(source_data, dict):
        source_data = {}
    allowlist_data = read_json(config.rca_related_file_allowlist_json, {})
    allowlist_cves = allowlist_data.get("cves", {}) if isinstance(allowlist_data, dict) else {}
    allowlist_schema_ok = isinstance(allowlist_data, dict) and allowlist_data.get("schema") == ALLOWLIST_SCHEMA
    statuses = []
    counts = {"ok": 0, "failed": 0, "missing": 0}
    for cve_id in cve_ids:
        allowlist_item = allowlist_cves.get(cve_id) if isinstance(allowlist_cves, dict) else None
        allowlist_ok = (
            allowlist_schema_ok
            and isinstance(allowlist_item, dict)
        )
        if forced_status:
            status = forced_status
        else:
            item = source_data.get(cve_id)
            status = "ok" if isinstance(item, dict) and item and allowlist_ok else "missing"
        counts[status] = counts.get(status, 0) + 1
        source_detail = {
            "source_min": str(config.rca_source_min_json),
            "related_file_allowlist": str(config.rca_related_file_allowlist_json),
            "related_file_allowlist_schema": ALLOWLIST_SCHEMA,
        }
        source_detail.update(detail or {})
        statuses.append(
            {
                "cve_id": cve_id,
                "mode": "source",
                "status": status,
                "artifact_path": str(config.rca_source_min_json),
                "detail": source_detail,
            }
        )
    db.upsert_many_rca_statuses(statuses)
    return counts


def behavior_item_ok(item: Any, functions: list[str] | None = None) -> bool:
    if not isinstance(item, dict):
        return False
    anchors = item.get("function_anchors")
    if not (
        item.get("root_cause_analysis")
        and item.get("patch_intent_analysis")
        and isinstance(anchors, dict)
        and patch_source_ok(item.get("patch_source"))
    ):
        return False
    for function in functions or []:
        entries = anchors.get(function)
        if not isinstance(entries, list) or len(entries) < 5:
            return False
    return True


def mark_behavior_statuses(config: BuildConfig, db: ProjectDB, cve_ids: list[str]) -> dict[str, int]:
    behavior_data = read_json(config.rca_behavior_json, {})
    if not isinstance(behavior_data, dict):
        behavior_data = {}
    statuses = []
    counts = {"ok": 0, "failed": 0, "missing": 0}
    for cve_id in cve_ids:
        item = behavior_data.get(cve_id)
        if behavior_item_ok(item, db.functions_for_cve(cve_id)):
            status = "ok"
            detail = {"behavior": str(config.rca_behavior_json)}
        elif isinstance(item, dict) and item.get("behavior_analysis_error"):
            status = "failed"
            detail = {"behavior": str(config.rca_behavior_json), "error": item.get("behavior_analysis_error")}
        else:
            status = "missing"
            detail = {"behavior": str(config.rca_behavior_json)}
        counts[status] += 1
        statuses.append(
            {
                "cve_id": cve_id,
                "mode": "behavior",
                "status": status,
                "artifact_path": str(config.rca_behavior_json),
                "detail": detail,
            }
        )
    db.upsert_many_rca_statuses(statuses)
    return counts


def run_rca_metadata(config: BuildConfig, db: ProjectDB) -> None:
    log = get_logger(config.output, "RCA")
    if config.metadata_mode == "skip":
        log.trace("RCA metadata skipped", metadata_mode=config.metadata_mode)
        db.record_stage("RCA", "skipped", {"metadata_mode": config.metadata_mode})
        return

    config.rca_dir.mkdir(parents=True, exist_ok=True)
    project_items = write_project_json(config, db)
    cve_ids = selected_rca_cves(config, db)
    log.trace("RCA project json written", path=str(config.rca_project_json), cves=project_items)
    if project_items == 0:
        log.warn("RCA metadata has no CVEs to analyze")
        db.record_stage("RCA", "skipped", {"metadata_mode": config.metadata_mode, "reason": "no_cves"})
        return

    source_proc = run_project_source_analysis(config)
    if source_proc.returncode:
        log.error(
            "RCA source analysis failed",
            returncode=source_proc.returncode,
            log_path=str(config.rca_dir / "logs" / "project_source_analysis.log"),
        )
        source_counts = mark_source_statuses(
            config,
            db,
            cve_ids,
            forced_status="failed",
            detail={
                "source_full": str(config.rca_source_full_json),
                "source_min": str(config.rca_source_min_json),
                "related_file_allowlist": str(config.rca_related_file_allowlist_json),
                "returncode": source_proc.returncode,
            },
        )
        db.record_stage(
            "RCA",
            "failed",
            {
                "metadata_mode": config.metadata_mode,
                "step": "source",
                "returncode": source_proc.returncode,
                "source_status_counts": source_counts,
            },
        )
        return
    log.trace(
        "RCA source analysis done",
        full=str(config.rca_source_full_json),
        min=str(config.rca_source_min_json),
        related_file_allowlist=str(config.rca_related_file_allowlist_json),
    )
    source_counts = mark_source_statuses(config, db, cve_ids)

    if config.metadata_mode == "source":
        missing_source = db.cves_missing_rca(config, "source")
        db.record_stage(
            "RCA",
            "ok" if not missing_source else "partial",
            {
                "metadata_mode": config.metadata_mode,
                "project_json": str(config.rca_project_json),
                "source_full": str(config.rca_source_full_json),
                "source_min": str(config.rca_source_min_json),
                "related_file_allowlist": str(config.rca_related_file_allowlist_json),
                "source_status_counts": source_counts,
                "missing_source_cves": missing_source,
            },
        )
        return

    if not os.environ.get("DEEPSEEK_API_KEY"):
        log.warn("RCA behavior analysis skipped because DEEPSEEK_API_KEY is not set")
        enriched = enrich_behavior_patch_source(config, db, cve_ids)
        if enriched:
            log.trace("RCA behavior patch source enriched", output=str(config.rca_behavior_json), cves=enriched)
        behavior_counts = mark_behavior_statuses(config, db, cve_ids)
        db.record_stage(
            "RCA",
            "partial",
            {
                "metadata_mode": config.metadata_mode,
                "project_json": str(config.rca_project_json),
                "source_full": str(config.rca_source_full_json),
                "source_min": str(config.rca_source_min_json),
                "related_file_allowlist": str(config.rca_related_file_allowlist_json),
                "behavior_skipped": "missing_DEEPSEEK_API_KEY",
                "behavior_status_counts": behavior_counts,
                "missing_behavior_cves": db.cves_missing_rca(config, "behavior"),
            },
        )
        return

    behavior_proc = run_behavior_analysis(config)
    enriched = enrich_behavior_patch_source(config, db, cve_ids)
    if enriched:
        log.trace("RCA behavior patch source enriched", output=str(config.rca_behavior_json), cves=enriched)
    behavior_counts = mark_behavior_statuses(config, db, cve_ids)
    if behavior_proc.returncode:
        log.error(
            "RCA behavior analysis failed",
            returncode=behavior_proc.returncode,
            log_path=str(config.rca_dir / "logs" / "generate_behavior_analysis_deepseek.log"),
        )
        db.record_stage(
            "RCA",
            "failed",
            {
                "metadata_mode": config.metadata_mode,
                "step": "behavior",
                "returncode": behavior_proc.returncode,
                "behavior_status_counts": behavior_counts,
            },
        )
        return
    log.trace("RCA behavior analysis done", output=str(config.rca_behavior_json))
    missing_behavior = db.cves_missing_rca(config, "behavior")
    db.record_stage(
        "RCA",
        "ok" if not missing_behavior else "partial",
        {
            "metadata_mode": config.metadata_mode,
            "project_json": str(config.rca_project_json),
            "source_full": str(config.rca_source_full_json),
            "source_min": str(config.rca_source_min_json),
            "related_file_allowlist": str(config.rca_related_file_allowlist_json),
            "behavior": str(config.rca_behavior_json),
            "behavior_status_counts": behavior_counts,
            "missing_behavior_cves": missing_behavior,
        },
    )
