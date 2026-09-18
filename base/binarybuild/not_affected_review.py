from __future__ import annotations

from CVEhunt.nvd_constraints import affected_ranges as nvd_affected_ranges

import json
import subprocess
from pathlib import Path
from typing import Any

from binarybuild.affectedness_evidence import artifact_evidence
from builder.config import BuildConfig
from builder.db import ProjectDB
from builder.logging import get_logger
from utils.codex_exec import run_codex_exec_json
from utils.io import write_text
from utils.paths import ROOT


SCHEMA = ROOT / "schemas" / "not_affected_review_result.schema.json"
MAX_REVIEW_BATCH_SIZE = 10
POLICY = "affectedness-audit-v2"
LEGACY_POLICIES = ("affectedness-audit-v1",)


def chunked(items: list[dict[str, Any]], size: int) -> list[list[dict[str, Any]]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def git_commit_for_tag(repo: Path, tag: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-list", "-n", "1", tag],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def tag_contains_commit(repo: Path, tag: str, commit: str) -> bool | None:
    if not tag or not commit:
        return None
    proc = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", commit, tag],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        return True
    if proc.returncode == 1:
        return False
    return None




def fix_context(config: BuildConfig, db: ProjectDB, cve_id: str) -> dict[str, Any]:
    fix = db.conn.execute(
        """
        SELECT f.commit_hash, f.parent_hash, f.diff_path, c.summary
        FROM fix_candidates f
        LEFT JOIN cves c ON c.cve_id=f.cve_id
        WHERE f.cve_id=? AND f.selected=1
        LIMIT 1
        """,
        (cve_id,),
    ).fetchone()
    if not fix:
        return {
            "summary": "",
            "affected_ranges": nvd_affected_ranges(config, db, cve_id),
            "fix_commit": "",
            "fix_parent": "",
            "diff_path": "",
        }
    return {
        "summary": fix["summary"] or "",
        "affected_ranges": nvd_affected_ranges(config, db, cve_id),
        "fix_commit": fix["commit_hash"] or "",
        "fix_parent": fix["parent_hash"] or "",
        "diff_path": resolve_diff_path(config, cve_id, fix["commit_hash"] or "", fix["diff_path"] or ""),
    }


def resolve_diff_path(config: BuildConfig, cve_id: str, commit: str, diff_path: str) -> str:
    path = Path(diff_path or "")
    if path.exists():
        return str(path)
    if not cve_id or not commit:
        return ""
    prefix = f"{config.project}_{cve_id}_{commit[:12]}"
    matches = sorted(config.diff_dir.glob(f"{prefix}*.diff"))
    return str(matches[0]) if matches else ""


def target_group_key(candidate: dict[str, Any]) -> tuple[str, str, str, str, str, str, str]:
    return (
        candidate.get("target_path", ""),
        candidate.get("tag", ""),
        candidate.get("binary_name", ""),
        candidate.get("compiler", ""),
        candidate.get("opt", ""),
        candidate.get("build_profile", ""),
        candidate.get("architecture", "x86_64"),
    )


def source_scope(db: ProjectDB, cve_id: str) -> tuple[list[str], list[str]]:
    functions = db.functions_for_cve(cve_id)
    source_files = sorted(
        {
            str(detail["file_path"])
            for detail in db.function_details_for_cve(cve_id)
            if detail["file_path"]
        }
    )
    return functions, source_files


def candidate_for_prompt(config: BuildConfig, db: ProjectDB, candidate: dict[str, Any], target_commit: str) -> dict[str, Any]:
    context = fix_context(config, db, candidate["cve_id"])
    fix_commit = context.get("fix_commit", "")
    functions, source_files = source_scope(db, candidate["cve_id"])
    return {
        "cve_id": candidate["cve_id"],
        "label": candidate.get("label", ""),
        "current_label": candidate.get("label", ""),
        "missing_functions": [],
        "version": candidate.get("version", ""),
        "summary": context.get("summary", ""),
        "nvd_affected_ranges": context.get("affected_ranges", []),
        "fix_commit": fix_commit,
        "fix_parent": context.get("fix_parent", ""),
        "target_contains_fix_commit": tag_contains_commit(config.repo, candidate.get("tag", ""), fix_commit),
        "diff_path": context.get("diff_path", ""),
        "patch_functions": functions,
        "patch_source_files": source_files,
        "architecture": candidate.get("architecture", config.architecture),
    }


def group_candidates(config: BuildConfig, db: ProjectDB, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str, str, str, str], dict[str, Any]] = {}
    for candidate in candidates:
        key = target_group_key(candidate)
        group = grouped.get(key)
        if group is None:
            group = {
                "target_path": candidate.get("target_path", ""),
                "debug_path": candidate.get("debug_path", ""),
                "tag": candidate.get("tag", ""),
                "target_tag": candidate.get("tag", ""),
                "target_commit": git_commit_for_tag(config.repo, candidate.get("tag", "")),
                "binary_name": candidate.get("binary_name", ""),
                "compiler": candidate.get("compiler", ""),
                "opt": candidate.get("opt", ""),
                "build_profile": candidate.get("build_profile", ""),
                "architecture": candidate.get("architecture", config.architecture),
                "toolchain": config.toolchain.command_details(),
                "artifact_evidence": artifact_evidence(config, candidate),
                "candidates": [],
            }
            grouped[key] = group
        candidate["artifact_evidence"] = group["artifact_evidence"]
        group["candidates"].append(candidate_for_prompt(config, db, candidate, group["target_commit"]))
        group.setdefault("_raw_candidates", []).append(candidate)
    return list(grouped.values())


def flatten_group_candidates(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [candidate for group in groups for candidate in group.get("_raw_candidates", [])]


def prompt_groups(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{key: value for key, value in group.items() if key != "_raw_candidates"} for group in groups]


def render_prompt(config: BuildConfig, groups: list[dict[str, Any]]) -> str:
    return f"""Review target affectedness for selected dataset labels.

Repository:
- project: {config.project}
- source repo: {config.repo}
- output root: {config.output}
- compiler: {config.compiler}
- opt: {config.opt}
- requested architecture/toolchain: {json.dumps(config.toolchain.command_details(), ensure_ascii=False)}

Target groups:
{json.dumps(prompt_groups(groups), ensure_ascii=False, indent=2)[:120000]}

Task:
For every candidate under every target group, audit whether the current selected label is truly applicable.
Audit the produced target artifact, not merely the source release. Use the supplied artifact_evidence first, then inspect the target binary and its debug companion with read-only commands when needed. You may use file, readelf, nm, objdump, strings, ldd, and source/git inspection. You may inspect the listed compile adapter script/spec to learn the actual default build configuration.
Do not use web search or network access: make the decision from the supplied local artifacts, repository, adapter/spec, and build records. Do not rebuild binaries. Do not modify, delete, strip, or replace any file.

Important rule:
- A present symbol does not prove the target is affected.
- A missing symbol does not prove the target is not affected.
- A deleted or renamed old function/source file does not prove not_affected; it may be refactor, patch evolution, or backport.
- Source history alone does not prove the produced artifact contains an optional backend, platform-specific path, or feature-gated code.
- An empty build_profile means the ordinary adapter build, not an unknown build. Inspect the adapter and artifact evidence before treating optional code as reachable.

Classify each candidate as exactly one of:
- affected: the current label is applicable. For current_label=vuln, vulnerable code/behavior is still applicable. For current_label=patch, fixed behavior is present.
- not_affected: the target is genuinely outside the CVE's affected scope, for example version/range excludes it, vulnerable code was not introduced, or platform/config/source precondition clearly contradicts the CVE.
- patch_evolution: fixed behavior is present but through refactor, rename, or migrated source path.
- backport_fix: fixed behavior is present through a backport/cherry-pick that is not the exact selected fix commit.
- missing_fix: current_label=patch but the target does not contain the fix behavior.
- wrong_binary: the selected binary is inconsistent with the CVE/reference target.
- inconclusive: evidence is insufficient.
- failed: review could not be performed.

Rules:
1. Return one JSON item for each candidate.
2. Preserve cve_id and label from the candidate. Fill tag, binary_name, compiler, opt, build_profile, and target_path exactly from the parent target group. missing_functions must be []. The parent architecture is authoritative; do not compare or reuse evidence from another architecture.
3. Before returning affected, patch_evolution, backport_fix, or missing_fix, establish that the relevant behavior is reachable in this target artifact. The release source or fix history is insufficient when the CVE requires an optional dependency, backend, compile option, architecture, or OS path.
4. For not_affected, cite concrete target-specific evidence: architecture/platform, dependency/build configuration, adapter configuration, or combined binary/debug/source facts. Symbol presence or absence is never sufficient by itself.
5. If target_contains_fix_commit is true, do not return not_affected unless independent artifact platform/config evidence proves the CVE scope excludes the target.
6. If the exact fix commit is not in target history but equivalent fix behavior exists, return backport_fix or patch_evolution, not not_affected.
7. Prefer inconclusive over not_affected when the evidence is weak.
8. Return JSON only according to the schema.
"""


def result_item_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        item.get("cve_id", ""),
        item.get("label", item.get("current_label", "")),
        item.get("tag", ""),
        item.get("binary_name", ""),
    )


def record_review_results(db: ProjectDB, log, batch: list[dict[str, Any]], result: dict[str, Any]) -> list[dict[str, Any]]:
    failed: list[dict[str, Any]] = []
    by_key = {result_item_key(item): item for item in result.get("items", [])}
    for candidate in batch:
        item = by_key.get(result_item_key(candidate))
        if not item:
            log.warn("affectedness review item missing from codex result", candidate=candidate)
            failed.append(candidate)
            continue
        review = {
            **candidate,
            "missing_functions": [],
            "status": item.get("status", "inconclusive"),
            "confidence": float(item.get("confidence", 0.0)),
            "reason": item.get("reason", ""),
            "evidence": item.get("evidence", []),
            "suggested_action": item.get("suggested_action", ""),
            "report": {
                **item,
                "policy": POLICY,
                "review_protocol": "artifact-aware-direct-codex-v2",
                "artifact_evidence": candidate.get("artifact_evidence", {}),
            },
        }
        db.upsert_not_affected_review(review)
        log.trace(
            "affectedness review recorded",
            cve=candidate["cve_id"],
            tag=candidate["tag"],
            binary=candidate["binary_name"],
            status=review["status"],
            confidence=review["confidence"],
            architecture=candidate.get("architecture", "x86_64"),
        )
    return failed


def run_not_affected_review_codex(config: BuildConfig, db: ProjectDB, candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    log = get_logger(config.output, "not_affected_review")
    failed: list[dict[str, Any]] = []
    codex_dir = config.codex_dir / "not_affected_review"
    codex_dir.mkdir(parents=True, exist_ok=True)
    batch_size = min(max(1, config.batch_size), MAX_REVIEW_BATCH_SIZE)
    groups = group_candidates(config, db, candidates)
    for idx, group_batch in enumerate(chunked(groups, batch_size), start=1):
        batch = flatten_group_candidates(group_batch)
        prompt_path = codex_dir / f"affectedness-{idx}.prompt.md"
        result_path = codex_dir / f"affectedness-{idx}.result.json"
        events_path = codex_dir / f"affectedness-{idx}.events.jsonl"
        write_text(prompt_path, render_prompt(config, group_batch))
        log.trace("running affectedness review codex batch", policy=POLICY, batch=idx, target_binaries=len(group_batch), candidates=len(batch))
        try:
            result = run_codex_exec_json(
                prompt_path=prompt_path,
                output_path=result_path,
                json_events_path=events_path,
                schema_path=SCHEMA,
                codex_model=config.codex_model,
                codex_sandbox=config.codex_sandbox,
                add_dirs=[config.repo, config.output, ROOT],
                timeout=3600,
            )
        except Exception as exc:
            log.error("affectedness review codex batch failed", batch=idx, error=str(exc))
            failed.extend(batch)
            continue
        failed.extend(record_review_results(db, log, batch, result))
    return failed


def run_not_affected_review(config: BuildConfig, db: ProjectDB) -> None:
    log = get_logger(config.output, "not_affected_review")
    candidates = db.pending_not_affected_candidates(config, policy=POLICY)
    if not candidates:
        log.trace("affectedness review has no pending candidates", architecture=config.architecture, compiler=config.compiler, opt=config.opt, policy=POLICY)
        db.record_stage(
            "not_affected_review",
            "ok",
            {
                "policy": POLICY,
                "candidates": 0,
                "failed": 0,
                "compiler": config.compiler,
                "opt": config.opt,
                "architecture": config.architecture,
            },
        )
        return
    failed = run_not_affected_review_codex(config, db, candidates)
    status = "ok" if not failed else "partial"
    if failed:
        log.warn("affectedness review completed with failed candidates", count=len(failed), candidates=failed)
    reviewed = len(candidates) - len(failed)
    db.record_stage(
        "not_affected_review",
        status,
        {
            "policy": POLICY,
            "candidates": len(candidates),
            "triaged": 0,
            "codex": len(candidates),
            "review_protocol": "artifact-aware-direct-codex-v2",
            "reviewed": reviewed,
            "failed": len(failed),
            "compiler": config.compiler,
            "opt": config.opt,
            "architecture": config.architecture,
        },
    )
