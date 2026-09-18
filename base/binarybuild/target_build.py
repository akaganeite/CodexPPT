from __future__ import annotations

import json
import shutil
from collections import defaultdict
from pathlib import Path

from builder.architecture import matches_elf_architecture
from builder.config import BuildConfig
from builder.db import ProjectDB
from builder.logging import get_logger
from binarybuild.build_log_cleanup import cleanup_current_stage_build_logs
from binarybuild.compile_scripts import ensure_compile_script, load_compile_script, script_path_for_project, spec_path_for_project
from binarybuild.target_mapping_reconcile import reconcile_existing_variant_mappings
from binarybuild.worktree_cleanup import cleanup_project_worktrees, remove_worktrees
from utils.codex_exec import run_codex_exec_json
from utils.io import write_text
from utils.paths import ROOT


SCHEMA = ROOT / "schemas" / "target_build_result.schema.json"


def render_prompt(config: BuildConfig, tasks: list[dict]) -> str:
    script_path = script_path_for_project(config.project)
    spec_path = spec_path_for_project(config.project)
    return f"""Compile target binaries for selected testset tags.

Repository:
- project: {config.project}
- source repo: {config.repo}
- worktree/build root: {config.worktree_root}
- output binary dir: {config.target_bin_dir}
- output binary variant: {config.build_variant}
- reusable compile script: {script_path}
- reusable compile script spec: {spec_path}
- compiler: {config.compiler}
- opt: {config.opt}
- architecture/toolchain contract: {json.dumps(config.toolchain.command_details(), ensure_ascii=False)}

Unique target binary tasks:
{json.dumps(tasks, ensure_ascii=False, indent=2)}

Requirements:
1. You are the compile executor for this batch. Do the build work in this Codex exec session.
2. First inspect the reusable compile script spec if it exists, then use the reusable compile script. Treat the spec as the adapter map and inspect Python implementation details only as needed.
3. Prefer calling the script's Python APIs or adding a small driver around it over ad-hoc shell build commands.
4. If the script fails for this batch, debug the failure, edit the reusable compile script at the script path above, then retry the failed tasks in this same session.
5. If you modify the compile script behavior, public APIs, profiles, candidate paths, compatibility patches, or helper functions, update the spec file at the spec path above in the same session.
6. Do not clean or checkout the source repo directly. Use git worktree or temporary copies under worktree/build root.
7. Each task is unique by tag, version, binary_name, compiler, opt, and architecture. Compile each unique binary at most once.
8. Copy output exactly to the task's output_path field. The filename includes compiler and opt.
9. If that output path already exists and is an ELF file, reuse it and return status ok without recompiling.
10. Return one item per unique target binary task. Missing items are treated as failures by the outer builder.
11. Each item must include cve_id, label, tag, version, binary_name, path, status, and notes.
12. For AArch64, use the supplied cross-toolchain contract exactly. Do not fall back to native tools or an x86 configure target.
13. Validate each copied output with the supplied readelf and return ok only when its ELF Machine matches the requested architecture.
14. Return JSON only according to the schema.
"""


def make_task_key(task: dict) -> tuple[str, str, str]:
    return task["tag"], task["version"], task["binary_name"]


def dedupe_build_tasks(tasks: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict] = []
    for task in tasks:
        key = make_task_key(task)
        if key in seen:
            continue
        seen.add(key)
        unique.append(
            {
                "cve_id": task["cve_id"],
                "label": task["label"],
                "tag": task["tag"],
                "version": task["version"],
                "binary_name": task["binary_name"],
                "compiler": task["compiler"],
                "opt": task["opt"],
                "architecture": task.get("architecture", "x86_64"),
                "output_path": task["output_path"],
            }
        )
    return unique


def task_groups(tasks: list[dict]) -> dict[tuple[str, str, str], list[dict]]:
    grouped: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for task in tasks:
        grouped[make_task_key(task)].append(task)
    return grouped


def target_path(config: BuildConfig, task: dict) -> Path:
    return config.target_bin_dir / config.target_binary_name(task["version"], task["binary_name"])


def materialize_target_path(config: BuildConfig, task: dict, path: str | Path, log, source: str) -> Path | None:
    """Copy a valid Codex/local result into the architecture-specific canonical name."""
    built = Path(path)
    if not matches_elf_architecture(built, config.architecture):
        log.warn(
            "target binary has wrong ELF architecture",
            tag=task["tag"],
            binary=task["binary_name"],
            expected=config.architecture,
            path=str(built),
            source=source,
        )
        return None
    expected = target_path(config, task)
    try:
        same_path = built.resolve() == expected.resolve()
    except OSError:
        same_path = built == expected
    if not same_path:
        try:
            expected.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(built, expected)
        except OSError as exc:
            log.warn(
                "target binary could not be copied to canonical path",
                tag=task["tag"],
                binary=task["binary_name"],
                source_path=str(built),
                expected_path=str(expected),
                error=str(exc),
            )
            return None
        log.trace(
            "target binary normalized to canonical path",
            tag=task["tag"],
            binary=task["binary_name"],
            source_path=str(built),
            expected_path=str(expected),
            architecture=config.architecture,
        )
    if not matches_elf_architecture(expected, config.architecture):
        log.warn(
            "canonical target binary has wrong ELF architecture",
            tag=task["tag"],
            binary=task["binary_name"],
            expected=config.architecture,
            path=str(expected),
            source=source,
        )
        return None
    return expected


def normalize_target_artifact_path(config: BuildConfig, db: ProjectDB, row, path: Path, source: str) -> Path:
    expected = target_path(config, row)
    if path == expected:
        return path
    if not path.exists() or path.name == expected.name:
        return path
    expected.parent.mkdir(parents=True, exist_ok=True)
    if not expected.exists():
        shutil.copy2(path, expected)
    artifact_id = db.upsert_target_artifact(
        {
            "project": config.project,
            "tag": row["tag"],
            "version": row["version"],
            "binary_name": row["binary_name"],
            "compiler": config.compiler,
            "opt": config.opt,
            "architecture": config.architecture,
            "build_profile": "",
            "path": str(expected),
            "status": "ok",
            "report": {"source": source, "copied_from": str(path)},
        }
    )
    db.upsert_target_mapping(
        {
            "cve_id": row["cve_id"],
            "label": row["label"],
            "tag": row["tag"],
            "binary_name": row["binary_name"],
            "compiler": config.compiler,
            "opt": config.opt,
            "architecture": config.architecture,
            "build_profile": "",
            "artifact_id": artifact_id,
            "status": "ok",
            "report": {"source": source, "version": row["version"], "copied_from": str(path)},
        }
    )
    return expected


def existing_target_path(config: BuildConfig, db: ProjectDB, row) -> Path | None:
    mapping = db.target_mapping_for_testset(row, config)
    if mapping:
        path = Path(mapping["path"] or "")
        if path.exists() and matches_elf_architecture(path, config.architecture):
            return normalize_target_artifact_path(config, db, row, path, "normalized_existing_target_mapping")
        relocated = config.target_bin_dir / path.name if path.name else target_path(config, row)
        if relocated.exists() and matches_elf_architecture(relocated, config.architecture):
            relocated = normalize_target_artifact_path(config, db, row, relocated, "normalized_relocated_existing_target_mapping")
            artifact_id = db.upsert_target_artifact(
                {
                    "project": config.project,
                    "tag": row["tag"],
                    "version": row["version"],
                    "binary_name": row["binary_name"],
                    "compiler": config.compiler,
                    "opt": config.opt,
                    "architecture": config.architecture,
                    "build_profile": "",
                    "path": str(relocated),
                    "status": "ok",
                    "report": {"source": "relocated_existing_target_mapping"},
                }
            )
            db.upsert_target_mapping(
                {
                    "cve_id": row["cve_id"],
                    "label": row["label"],
                    "tag": row["tag"],
                    "binary_name": row["binary_name"],
                    "compiler": config.compiler,
                    "opt": config.opt,
                    "architecture": config.architecture,
                    "build_profile": "",
                    "artifact_id": artifact_id,
                    "status": "ok",
                    "report": {"source": "relocated_existing_target_mapping", "version": row["version"]},
                }
            )
            return relocated

    artifact = db.target_artifact_for_task(
        config.project,
        row["tag"],
        row["binary_name"],
        config.compiler,
        config.opt,
        architecture=config.architecture,
    )
    if artifact:
        path = Path(artifact["path"] or "")
        if path.exists() and matches_elf_architecture(path, config.architecture):
            path = normalize_target_artifact_path(config, db, row, path, "normalized_existing_artifact")
            if map_built_binary(db, config, row, str(path), [dict(row)], get_logger(config.output, "target_build"), source="existing_artifact"):
                return path
    return None


def map_built_binary(db: ProjectDB, config: BuildConfig, task: dict, path: str, related: list[dict], log, source: str) -> bool:
    artifact_path = materialize_target_path(config, task, path, log, source)
    if artifact_path is None:
        return False
    artifact_id = db.upsert_target_artifact(
        {
            "project": config.project,
            "tag": task["tag"],
            "version": task["version"],
            "binary_name": task["binary_name"],
            "compiler": config.compiler,
            "opt": config.opt,
            "architecture": config.architecture,
            "build_profile": "",
            "path": path,
            "status": "ok",
            "report": {
                "source": source,
                "version": task["version"],
                "architecture": config.architecture,
                "compiler": config.compiler,
                "opt": config.opt,
            },
        }
    )
    for item_task in related:
        report_json = {
            "source": source,
            "version": item_task["version"],
            "artifact_id": artifact_id,
            "architecture": config.architecture,
            "compiler": config.compiler,
            "opt": config.opt,
        }
        db.upsert_target_mapping(
            {
                "cve_id": item_task["cve_id"],
                "label": item_task["label"],
                "tag": item_task["tag"],
                "binary_name": item_task["binary_name"],
                "compiler": config.compiler,
                "opt": config.opt,
                "architecture": config.architecture,
                "build_profile": "",
                "artifact_id": artifact_id,
                "status": "ok",
                "report": report_json,
            }
        )
        log.trace("target binary mapped", cve=item_task["cve_id"], tag=item_task["tag"], binary=item_task["binary_name"])
    return True


def profile_order_for_task(task: dict) -> tuple[str, ...]:
    if task.get("binary_name") == "libcurl-gnutls":
        return ("shared-gnutls", "static-gnutls")
    return ("static", "shared")


def profile_order_for_task_group(config: BuildConfig, tasks: list[dict]) -> tuple[str, ...]:
    if config.project == "openssl":
        if any(task["binary_name"] in {"libcrypto", "libssl"} for task in tasks):
            return ("shared", "static")
        if any(
            task["binary_name"] == "openssl"
            and str(task.get("version", "")).startswith(("0.9.", "1.0."))
            for task in tasks
        ):
            return ("shared", "static")
    profiles = [profile for task in tasks for profile in profile_order_for_task(task)]
    return tuple(dict.fromkeys(profiles))


def run_target_build_codex(config: BuildConfig, db: ProjectDB, tasks: list[dict], prefix: str = "batch") -> list[dict]:
    log = get_logger(config.output, "target_build")
    grouped = task_groups(tasks)
    unique_tasks = dedupe_build_tasks(tasks)
    pending_tasks = []
    for task in unique_tasks:
        path = target_path(config, task)
        key = make_task_key(task)
        artifact = db.target_artifact_for_task(
            config.project, task["tag"], task["binary_name"], config.compiler, config.opt, architecture=config.architecture
        )
        if artifact and artifact["path"] and matches_elf_architecture(Path(artifact["path"]), config.architecture):
            log.trace("reuse target artifact before codex batch", tag=task["tag"], binary=task["binary_name"], path=artifact["path"])
            if map_built_binary(db, config, task, artifact["path"], grouped[key], log, source="existing_artifact"):
                continue
        if path.exists() and matches_elf_architecture(path, config.architecture):
            log.trace("reuse existing target binary before codex batch", tag=task["tag"], binary=task["binary_name"], path=str(path))
            if map_built_binary(db, config, task, str(path), grouped[key], log, source="existing_path"):
                continue
        pending_tasks.append(task)

    batches = [pending_tasks[i : i + config.batch_size] for i in range(0, len(pending_tasks), config.batch_size)]
    codex_dir = config.codex_dir / "target_build"
    codex_dir.mkdir(parents=True, exist_ok=True)
    failed: list[dict] = []
    for idx, batch in enumerate(batches, start=1):
        prompt_path = codex_dir / f"{prefix}-{idx}.prompt.md"
        result_path = codex_dir / f"{prefix}-{idx}.result.json"
        events_path = codex_dir / f"{prefix}-{idx}.events.jsonl"
        write_text(prompt_path, render_prompt(config, batch))
        log.trace("running target build codex batch", batch=idx, count=len(batch))
        try:
            result = run_codex_exec_json(
                prompt_path=prompt_path,
                output_path=result_path,
                json_events_path=events_path,
                schema_path=SCHEMA,
                codex_model=config.codex_model,
                codex_sandbox=config.codex_sandbox,
                add_dirs=[config.repo, config.output],
                timeout=7200,
            )
        except Exception as exc:
            log.error("target build codex batch failed", batch=idx, error=str(exc))
            failed.extend(batch)
            continue
        returned_by_key = {}
        for item in result.get("items", []):
            key = (item.get("tag", ""), item.get("version", ""), item.get("binary_name", ""))
            returned_by_key[key] = item
        for task in batch:
            key = make_task_key(task)
            item = returned_by_key.get(key)
            if not item:
                failed.append(task)
                log.warn("target build item missing from codex result", task=task)
                continue
            if item.get("status") != "ok":
                failed.append(task)
                log.warn("target build item failed", item=item)
                continue
            path = item.get("path") or str(target_path(config, task))
            if not Path(path).exists():
                failed.append(task)
                log.warn("target build item path missing", item=item, path=path)
                continue
            if not map_built_binary(db, config, task, path, grouped[key], log, source="codex_target_build"):
                failed.append(task)
    return failed


def run_target_build_local(config: BuildConfig, db: ProjectDB, tasks: list[dict], compiler) -> list[dict]:
    log = get_logger(config.output, "target_build")
    grouped = task_groups(tasks)
    unique_tasks = dedupe_build_tasks(tasks)
    failed: list[dict] = []
    success_worktrees: set[Path] = set()
    failed_worktrees: set[Path] = set()

    pending_tasks: list[dict] = []
    for task in unique_tasks:
        path = target_path(config, task)
        key = make_task_key(task)
        artifact = db.target_artifact_for_task(
            config.project, task["tag"], task["binary_name"], config.compiler, config.opt, architecture=config.architecture
        )
        if artifact and artifact["path"] and matches_elf_architecture(Path(artifact["path"]), config.architecture):
            log.trace("reuse target artifact before local build", tag=task["tag"], binary=task["binary_name"], path=artifact["path"])
            if map_built_binary(db, config, task, artifact["path"], grouped[key], log, source="existing_artifact"):
                continue
        if path.exists() and matches_elf_architecture(path, config.architecture):
            log.trace("reuse existing target binary before local build", tag=task["tag"], binary=task["binary_name"], path=str(path))
            if map_built_binary(db, config, task, str(path), grouped[key], log, source="existing_path"):
                continue

        pending_tasks.append(task)

    tasks_by_ref: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for task in pending_tasks:
        tasks_by_ref[(task["tag"], task["version"])].append(task)

    for (tag, _version), ref_tasks in tasks_by_ref.items():
        unresolved = list(ref_tasks)
        notes: dict[tuple[str, str, str], list[str]] = defaultdict(list)
        tried_worktrees: set[Path] = set()

        for profile in profile_order_for_task_group(config, ref_tasks):
            built = compiler.compile_commit(config, tag, "target_build", log, profile=profile)
            if built.worktree:
                tried_worktrees.add(built.worktree)
            if not built.ok:
                for task in unresolved:
                    notes[make_task_key(task)].append(built.notes)
                continue

            completed: list[dict] = []
            for task in unresolved:
                binary_path = compiler.find_binary_by_name(built.worktree, task["binary_name"], profile=profile)
                if not binary_path:
                    notes[make_task_key(task)].append(f"{profile} missing binary {task['binary_name']}")
                    continue

                path = target_path(config, task)
                compiler.copy_binary(binary_path, path)
                if not path.exists():
                    notes[make_task_key(task)].append(f"{profile} output missing after copy")
                    continue
                key = make_task_key(task)
                if not map_built_binary(db, config, task, str(path), grouped[key], log, source="local_target_build"):
                    notes[key].append(f"{profile} output failed target validation")
                    continue
                completed.append(task)
                log.trace("target built locally", tag=task["tag"], binary=task["binary_name"], path=str(path))

            if completed:
                completed_keys = {make_task_key(task) for task in completed}
                unresolved = [task for task in unresolved if make_task_key(task) not in completed_keys]
            if not unresolved:
                break

        if unresolved:
            failed.extend(unresolved)
            failed_worktrees.update(tried_worktrees)
            for task in unresolved:
                log.warn(
                    "local target build failed",
                    tag=task["tag"],
                    binary=task["binary_name"],
                    notes=[note for note in notes[make_task_key(task)] if note],
                )
            continue

        success_worktrees.update(tried_worktrees)
        removed_success = remove_worktrees(config, tried_worktrees, log, success=True, reason=f"target ref succeeded {tag}")
        if removed_success:
            log.trace("target ref worktree cleanup complete", tag=tag, removed=removed_success)
        success_worktrees.difference_update(tried_worktrees)

    success_only = success_worktrees - failed_worktrees
    removed_success = remove_worktrees(config, success_only, log, success=True, reason="target build completed")
    removed_failed = remove_worktrees(config, failed_worktrees, log, success=False, reason="target build failed")
    if removed_success or removed_failed:
        log.trace("target worktree cleanup complete", removed_success=removed_success, removed_failed=removed_failed)
    return failed


def run_target_build(config: BuildConfig, db: ProjectDB) -> None:
    config.target_bin_dir.mkdir(parents=True, exist_ok=True)
    log = get_logger(config.output, "target_build")
    reconciled = reconcile_existing_variant_mappings(config, db, log=log)
    rows = db.testset_entries(config)
    tasks = [
        {
            "cve_id": r["cve_id"],
            "label": r["label"],
            "tag": r["tag"],
            "version": r["version"],
            "binary_name": r["binary_name"],
            "compiler": config.compiler,
            "opt": config.opt,
            "architecture": config.architecture,
            "output_path": str(target_path(config, r)),
        }
        for r in rows
        if r["status"] == "selected"
        and not existing_target_path(config, db, r)
    ]
    if tasks:
        if not ensure_compile_script(config, "target_build", tasks, log=log):
            log.warn("compile script unavailable before codex batch", project=config.project)
            failed = run_target_build_codex(config, db, tasks)
        else:
            compiler = load_compile_script(config.project)
            if compiler:
                failed = run_target_build_local(config, db, tasks, compiler)
                if failed:
                    failed = run_target_build_codex(config, db, failed, prefix="repair")
            else:
                log.warn("compile script failed to load before local target build", project=config.project)
                failed = run_target_build_codex(config, db, tasks)
    else:
        failed = []
        log.trace("target build has no pending compile tasks", compiler=config.compiler, opt=config.opt)
    built = db.conn.execute(
        """
        SELECT COUNT(*)
        FROM target_mappings m
        JOIN target_artifacts a ON a.id=m.artifact_id
        JOIN build_variants v ON v.id=a.build_variant_id
        WHERE v.architecture=? AND v.compiler=? AND v.opt=? AND v.build_profile='' AND m.status='ok'
        """,
        (config.architecture, config.compiler, config.opt),
    ).fetchone()[0]
    artifact_count = db.conn.execute(
        """
        SELECT COUNT(*)
        FROM target_artifacts a
        JOIN build_variants v ON v.id=a.build_variant_id
        WHERE v.architecture=? AND v.compiler=? AND v.opt=? AND v.build_profile='' AND a.status='ok'
        """,
        (config.architecture, config.compiler, config.opt),
    ).fetchone()[0]
    missing = db.testset_missing_target(config)
    status = "ok" if not failed and not missing else "partial"
    if failed:
        log.warn("target build completed with failed tasks", count=len(failed), tasks=failed)
    if missing:
        log.warn("target build has missing target mappings", count=len(missing), cves=missing)
    removed_build_logs = cleanup_current_stage_build_logs(config, log, stage="target_build", success=status == "ok", reason="target build stage completed")
    removed_worktrees = cleanup_project_worktrees(config, log, success=status == "ok", reason="target build stage completed")
    db.record_stage(
        "target_build",
        status,
        {
            "tasks": len(tasks),
            "failed": len(failed),
            "missing_cves": missing,
            "mappings": built,
            "artifacts": artifact_count,
            "reconciled_existing_artifacts": reconciled,
            "compiler": config.compiler,
            "opt": config.opt,
            "architecture": config.architecture,
            "removed_build_logs": removed_build_logs,
            "removed_worktrees": removed_worktrees,
        },
    )
