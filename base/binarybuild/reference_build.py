from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from builder.architecture import matches_elf_architecture
from builder.config import BuildConfig
from builder.db import ProjectDB
from builder.logging import get_logger
from binarybuild.build_log_cleanup import cleanup_current_stage_build_logs
from binarybuild.compile_scripts import ensure_compile_script, load_compile_script, script_path_for_project, spec_path_for_project
from binarybuild.reference_validation import partition_reference_functions, validate_reference_pair
from binarybuild.worktree_cleanup import cleanup_project_worktrees, remove_worktrees
from utils.codex_exec import run_codex_exec_json
from utils.io import write_text
from utils.paths import ROOT


SCHEMA = ROOT / "schemas" / "reference_build_result.schema.json"


def chunked(items: list[dict], size: int) -> list[list[dict]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def cleanup_unreferenced_reference_files(config: BuildConfig, db: ProjectDB, log) -> int:
    if not config.reference_bin_dir.exists():
        return 0
    referenced = {
        Path(path).resolve()
        for row in db.references(config)
        for path in (row["vuln_path"], row["patch_path"])
    }
    scoped_prefixes = tuple(f"{cve_id}-" for cve_id in config.cves)
    removed = 0
    for path in config.reference_bin_dir.iterdir():
        if not path.is_file():
            continue
        if scoped_prefixes and not path.name.startswith(scoped_prefixes):
            continue
        if path.resolve() in referenced:
            continue
        path.unlink()
        removed += 1
        log.trace("removed unreferenced reference binary", path=str(path))
    return removed


def existing_reference_paths(
    config: BuildConfig,
    db: ProjectDB,
    cve_id: str,
    *,
    vuln_functions: list[str],
    patch_functions: list[str],
) -> tuple[Path, Path] | None:
    existing = db.reference_for_cve(cve_id, config)
    if not existing:
        return None
    vuln_path = Path(existing["vuln_path"] or "")
    patch_path = Path(existing["patch_path"] or "")
    validation = validate_reference_pair(
        vuln_path,
        patch_path,
        vuln_functions=vuln_functions,
        patch_functions=patch_functions,
        architecture=config.architecture,
        nm=config.toolchain.nm,
    )
    if validation.valid:
        return vuln_path, patch_path

    relocated_vuln = config.reference_bin_dir / vuln_path.name if vuln_path.name else Path()
    relocated_patch = config.reference_bin_dir / patch_path.name if patch_path.name else Path()
    relocated_validation = validate_reference_pair(
        relocated_vuln,
        relocated_patch,
        vuln_functions=vuln_functions,
        patch_functions=patch_functions,
        architecture=config.architecture,
        nm=config.toolchain.nm,
    )
    if relocated_validation.valid:
        db.upsert_reference(
            {
                "cve_id": cve_id,
                "vuln_commit": existing["vuln_commit"],
                "patch_commit": existing["patch_commit"],
                "binary_name": existing["binary_name"],
                "vuln_path": str(relocated_vuln),
                "patch_path": str(relocated_patch),
                "functions": json.loads(existing["functions_json"] or "[]"),
                "compiler": config.compiler,
                "opt": config.opt,
                "architecture": config.architecture,
                "build_profile": existing["build_profile"] or "",
                "status": "ok",
                "report": json.loads(existing["report_json"] or "{}"),
            }
        )
        return relocated_vuln, relocated_patch
    db.invalidate_reference(existing["id"], relocated_validation.as_dict())
    return None


def functions_from_diff_hunks(diff_path: str) -> list[str]:
    try:
        text = Path(diff_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    functions: list[str] = []
    for line in text.splitlines():
        if not line.startswith("@@"):
            continue
        match = re.search(r"@@\s+(.*)$", line)
        context = match.group(1).strip() if match else ""
        func = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*$", context)
        if func and func.group(1) not in functions:
            functions.append(func.group(1))
    return functions


def test_only_functions_from_diff(diff_path: str) -> set[str]:
    """Return hunk functions that occur only in test or example source files."""
    try:
        lines = Path(diff_path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return set()
    locations: dict[str, set[str]] = {}
    current_file = ""
    for line in lines:
        if line.startswith("+++ b/"):
            current_file = line[6:].split("\t", 1)[0]
            continue
        if not current_file or not line.startswith("@@"):
            continue
        match = re.search(r"@@\s+(.*)$", line)
        context = match.group(1).strip() if match else ""
        func = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*$", context)
        if func:
            locations.setdefault(func.group(1), set()).add(current_file)

    ignored_roots = {"test", "tests", "testing", "example", "examples"}
    return {
        function
        for function, paths in locations.items()
        if paths and all(any(part.lower() in ignored_roots for part in Path(path).parts) for path in paths)
    }


def reference_functions_for_task(db: ProjectDB, row) -> list[str]:
    functions = db.functions_for_cve(row["cve_id"])
    hunk_functions = functions_from_diff_hunks(row["diff_path"])
    test_only_functions = test_only_functions_from_diff(row["diff_path"])
    if functions:
        filtered = [fn for fn in functions if not fn.isupper() and fn not in test_only_functions]
        functions = filtered
    elif hunk_functions:
        functions = [fn for fn in hunk_functions if not fn.isupper() and fn not in test_only_functions]
    return functions


def reference_function_requirements(db: ProjectDB, row) -> tuple[list[str], list[str], list[str]]:
    """Partition source functions by the reference side where they must exist."""
    functions = reference_functions_for_task(db, row)
    vuln_functions, patch_functions = partition_reference_functions(
        functions,
        db.function_details_for_cve(row["cve_id"]),
    )
    return functions, patch_functions, vuln_functions


def build_tasks(config: BuildConfig, db: ProjectDB) -> list[dict]:
    tasks = []
    for row in db.selected_fixes(config):
        functions, patch_functions, vuln_functions = reference_function_requirements(db, row)
        if not functions:
            continue
        if existing_reference_paths(
            config,
            db,
            row["cve_id"],
            vuln_functions=vuln_functions,
            patch_functions=patch_functions,
        ):
            continue
        tasks.append(
            {
                "cve_id": row["cve_id"],
                "patch_commit": row["commit_hash"],
                "vuln_commit": row["parent_hash"] or f"{row['commit_hash']}^",
                "diff_path": row["diff_path"],
                "functions": functions,
                "patch_functions": patch_functions,
                "vuln_functions": vuln_functions,
            }
        )
    return tasks


def render_prompt(config: BuildConfig, tasks: list[dict]) -> str:
    script_path = script_path_for_project(config.project)
    spec_path = spec_path_for_project(config.project)
    return f"""Compile reference binaries for this CVE batch.

Repository:
- project: {config.project}
- source repo: {config.repo}
- allowed worktree/build root: {config.worktree_root}
- output binary dir: {config.reference_bin_dir}
- reusable compile script: {script_path}
- reusable compile script spec: {spec_path}
- compiler: {config.compiler}
- opt: {config.opt}
- architecture/toolchain contract: {json.dumps(config.toolchain.command_details(), ensure_ascii=False)}

Tasks:
{json.dumps(tasks, ensure_ascii=False, indent=2)}

Requirements:
1. First inspect the reusable compile script spec if it exists, then use the reusable compile script. Treat the spec as the adapter map and inspect Python implementation details only as needed.
2. If the script is missing or fails for this batch, edit/create it at the script path above.
3. If you modify the compile script behavior, public APIs, profiles, candidate paths, compatibility patches, or helper functions, update the spec file at the spec path above in the same session.
4. Debug configure/build failures by improving the compile script, then retry this batch.
5. Do not clean or checkout the source repo directly. Use git worktree or temporary copies under the allowed worktree/build root.
6. For each task compile two revisions: vuln_commit and patch_commit.
7. Before compiling, inspect the diff_path. If a listed function is only whitespace, formatting, signature-only, or non-security irrelevant change, omit that function from the functions list for binary selection and report it in notes.
8. Find an ELF executable or shared object containing all remaining functions using nm.
9. Keep binary choice consistent for the pair. If patch chooses libcrypto, vuln must be libcrypto too.
10. Copy outputs using this naming rule:
   - CVE-XXXX-YYYY-vuln-<12char_vuln_commit>-<binary_name>
   - CVE-XXXX-YYYY-patch-<12char_patch_commit>-<binary_name>
11. The copied paths must be under output binary dir.
12. After each task succeeds and the output binaries have been copied, immediately remove that task's successful worktrees and build directories under the worktree/build root, including `.agentic-build-*` directories, temporary build directories, and git worktrees for both vuln and patch revisions. Do not wait until the whole batch finishes.
13. Before returning an ok item for a task, verify the copied output binaries still exist and the task's successful worktree/build directories have been removed.
14. Keep failed worktrees only when needed for debugging; delete failed worktrees once the failure is fixed and the task succeeds.
15. Return JSON only according to the schema.
16. For AArch64, use the supplied cross-toolchain contract exactly, including configure host and compiler flags. Never fall back to native tools or an x86 build.
17. Validate both copied reference ELF files with the supplied readelf. Return ok only when both have the requested ELF Machine.
"""


def output_path(config: BuildConfig, cve_id: str, label: str, commit: str, binary_name: str) -> Path:
    return config.reference_bin_dir / config.reference_binary_name(cve_id, label, commit, binary_name)


def materialize_reference_output(config: BuildConfig, source: str | Path, destination: Path, log, *, cve_id: str, label: str) -> Path | None:
    """Keep reference results under the architecture-specific canonical directory."""
    built = Path(source)
    if not matches_elf_architecture(built, config.architecture):
        log.warn(
            "reference binary has wrong ELF architecture",
            cve=cve_id,
            label=label,
            expected=config.architecture,
            path=str(built),
        )
        return None
    try:
        same_path = built.resolve() == destination.resolve()
    except OSError:
        same_path = built == destination
    if not same_path:
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(built, destination)
        except OSError as exc:
            log.warn(
                "reference binary could not be copied to canonical path",
                cve=cve_id,
                label=label,
                source_path=str(built),
                destination_path=str(destination),
                error=str(exc),
            )
            return None
        log.trace(
            "reference binary normalized to canonical path",
            cve=cve_id,
            label=label,
            source_path=str(built),
            destination_path=str(destination),
            architecture=config.architecture,
        )
    if not matches_elf_architecture(destination, config.architecture):
        log.warn(
            "canonical reference binary has wrong ELF architecture",
            cve=cve_id,
            label=label,
            expected=config.architecture,
            path=str(destination),
        )
        return None
    return destination


def choose_pair_binary(config: BuildConfig, compiler, task: dict, profile: str, log) -> tuple[dict | None, dict | None, str, list[str], set[Path]]:
    patch_functions = task.get("patch_functions", task["functions"])
    vuln_functions = task.get("vuln_functions", task["functions"])
    patch = compiler.compile_commit(config, task["patch_commit"], "reference_build", log, profile=profile)
    vuln = compiler.compile_commit(config, task["vuln_commit"], "reference_build", log, profile=profile)
    worktrees = {build.worktree for build in (patch, vuln) if build.worktree}
    if not patch.ok or not vuln.ok:
        notes = [patch.notes, vuln.notes]
        return None, None, "", [x for x in notes if x], worktrees
    patch_match = compiler.choose_binary(patch.worktree, patch_functions, profile=profile)
    if not patch_match:
        return None, None, "", [f"{profile} patch has no candidate for {patch_functions}"], worktrees
    if patch_match.missing:
        return None, None, "", [f"{profile} patch candidate {patch_match.binary_name} missing {patch_match.missing}"], worktrees
    vuln_match = compiler.choose_binary(vuln.worktree, vuln_functions, preferred=patch_match.binary_name, profile=profile)
    if not vuln_match or vuln_match.binary_name != patch_match.binary_name:
        missing = vuln_match.missing if vuln_match else vuln_functions
        return None, None, "", [f"{profile} vuln missing {missing}"], worktrees
    if vuln_match.missing:
        return None, None, "", [f"{profile} vuln candidate {vuln_match.binary_name} missing {vuln_match.missing}"], worktrees
    return (
        {"commit": vuln.commit, "path": vuln_match.path},
        {"commit": patch.commit, "path": patch_match.path},
        patch_match.binary_name,
        [],
        worktrees,
    )


def profile_order_for_task(config: BuildConfig, task: dict) -> tuple[str, ...]:
    try:
        diff = Path(task["diff_path"]).read_text(encoding="utf-8", errors="replace")
    except OSError:
        diff = ""
    base = ("static", "shared") if "+++ b/apps/" in diff or "--- a/apps/" in diff else ("shared", "static")
    functions = set(task.get("functions", []))
    if config.project == "binutils":
        return ("static", "shared")
    if config.project == "curl":
        if any(function.startswith("gtls_") or function in {"Curl_gtls_connect", "Curl_ssl_gnutls"} for function in functions):
            return ("shared-gnutls", "static-gnutls", *base)
        if functions & {"mbed_connect_step1", "polarssl_connect_step1"}:
            return ("shared-vtls-mbed-polar", "static-vtls-mbed-polar", *base)
        if "+++ b/src/" in diff or "--- a/src/" in diff:
            return ("static", "shared")
    if config.project == "ffmpeg" and any(function.startswith("cbs_jpeg_") for function in functions):
        return ("shared-cbs-jpeg", "static-cbs-jpeg", *base)
    if config.project == "ffmpeg" and "dwa_uncompress" in functions:
        return ("shared-exr-zlib", "static-exr-zlib", *base)
    if config.project == "openssl" and "tls13_process_compressed_certificate" in functions:
        return ("static-zlib", "shared-zlib", *base)
    if config.project == "sqlite" and "vdbeVComment" in functions:
        return ("shared-explain-comments", "static-explain-comments", *base)
    if config.project == "sqlite":
        feature = {
            "CVE-2020-11656": "debug",
            "CVE-2023-7104": "session",
            "CVE-2025-7709": "fts5",
        }.get(task.get("cve_id"))
        if feature:
            # These references must contain the real gated implementation.
            return (f"static-{feature}", f"shared-{feature}")
    return base


def run_reference_build_local(config: BuildConfig, db: ProjectDB, tasks: list[dict], compiler) -> list[dict]:
    log = get_logger(config.output, "reference_build")
    failed: list[dict] = []
    success_worktrees: set[Path] = set()
    failed_worktrees: set[Path] = set()
    for task in tasks:
        cve_id = task["cve_id"]
        if existing_reference_paths(
            config,
            db,
            cve_id,
            vuln_functions=task.get("vuln_functions", task["functions"]),
            patch_functions=task.get("patch_functions", task["functions"]),
        ):
            existing = db.reference_for_cve(cve_id, config)
            log.trace("reuse reference record", cve=cve_id, binary=existing["binary_name"])
            continue
        notes: list[str] = []
        result = (None, None, "", [], set())
        tried_worktrees: set[Path] = set()
        for profile in profile_order_for_task(config, task):
            result = choose_pair_binary(config, compiler, task, profile, log)
            tried_worktrees.update(result[4])
            if result[0] and result[1]:
                break
            notes.extend(result[3])
        vuln, patch, binary_name, pair_notes, _ = result
        notes.extend(pair_notes)
        if not vuln or not patch:
            failed_worktrees.update(tried_worktrees)
            failed.append(task)
            log.warn("local reference build failed", cve=cve_id, notes=notes)
            continue
        vuln_dest = output_path(config, cve_id, "vuln", vuln["commit"], binary_name)
        patch_dest = output_path(config, cve_id, "patch", patch["commit"], binary_name)
        compiler.copy_binary(vuln["path"], vuln_dest)
        compiler.copy_binary(patch["path"], patch_dest)
        validation = validate_reference_pair(
            vuln_dest,
            patch_dest,
            vuln_functions=task.get("vuln_functions", task["functions"]),
            patch_functions=task.get("patch_functions", task["functions"]),
            architecture=config.architecture,
            nm=config.toolchain.nm,
        )
        if not validation.valid:
            vuln_dest.unlink(missing_ok=True)
            patch_dest.unlink(missing_ok=True)
            failed.append(task)
            failed_worktrees.update(tried_worktrees)
            log.warn(
                "reference binary failed validation",
                cve=cve_id,
                vuln=str(vuln_dest),
                patch=str(patch_dest),
                validation=validation.as_dict(),
            )
            continue
        item = {
            "cve_id": cve_id,
            "vuln_commit": vuln["commit"],
            "patch_commit": patch["commit"],
            "binary_name": binary_name,
            "vuln_path": str(vuln_dest),
            "patch_path": str(patch_dest),
            "functions": task["functions"],
            "compiler": config.compiler,
            "opt": config.opt,
            "architecture": config.architecture,
            "build_profile": "",
            "status": "ok",
            "report": {"source": "local_compile_script", "architecture": config.architecture, "notes": notes},
        }
        db.upsert_reference(item)
        success_worktrees.update(tried_worktrees)
        log.trace("reference built locally", cve=cve_id, binary=binary_name, vuln=str(vuln_dest), patch=str(patch_dest))
        removed_success = remove_worktrees(config, tried_worktrees, log, success=True, reason=f"reference task succeeded {cve_id}")
        if removed_success:
            log.trace("reference task worktree cleanup complete", cve=cve_id, removed=removed_success)
        success_worktrees.difference_update(tried_worktrees)
    success_only = success_worktrees - failed_worktrees
    removed_success = remove_worktrees(config, success_only, log, success=True, reason="reference build completed")
    removed_failed = remove_worktrees(config, failed_worktrees, log, success=False, reason="reference build failed")
    if removed_success or removed_failed:
        log.trace("reference worktree cleanup complete", removed_success=removed_success, removed_failed=removed_failed)
    return failed


def repair_reference_script_and_retry(config: BuildConfig, db: ProjectDB, failed: list[dict], log) -> list[dict]:
    if not failed:
        return []
    failure_context = [{"cve_id": item["cve_id"], "patch_commit": item["patch_commit"], "vuln_commit": item["vuln_commit"], "functions": item["functions"], "diff_path": item["diff_path"]} for item in failed]
    if not ensure_compile_script(config, "reference_build", failed, log, failure_context=failure_context):
        return failed
    compiler = load_compile_script(config.project)
    if not compiler:
        return failed
    return run_reference_build_local(config, db, failed, compiler)


def run_reference_build_codex(config: BuildConfig, db: ProjectDB, tasks: list[dict], prefix: str = "batch") -> None:
    log = get_logger(config.output, "reference_build")
    batches = chunked(tasks, config.batch_size)
    codex_dir = config.codex_dir / "reference_build"
    codex_dir.mkdir(parents=True, exist_ok=True)
    tasks_by_cve = {task["cve_id"]: task for task in tasks}
    for idx, batch in enumerate(batches, start=1):
        prompt_path = codex_dir / f"{prefix}-{idx}.prompt.md"
        result_path = codex_dir / f"{prefix}-{idx}.result.json"
        events_path = codex_dir / f"{prefix}-{idx}.events.jsonl"
        write_text(prompt_path, render_prompt(config, batch))
        log.trace("running reference build codex batch", batch=idx, count=len(batch))
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
            log.error("reference build codex batch failed", batch=idx, error=str(exc))
            continue
        for item in result.get("items", []):
            if item.get("status") == "ok":
                cve_id = item.get("cve_id", "")
                task = tasks_by_cve.get(cve_id)
                vuln_path = Path(item.get("vuln_path", ""))
                patch_path = Path(item.get("patch_path", ""))
                if not matches_elf_architecture(vuln_path, config.architecture) or not matches_elf_architecture(patch_path, config.architecture):
                    log.warn(
                        "reference build result rejected for wrong ELF architecture",
                        cve=item.get("cve_id", ""),
                        expected=config.architecture,
                        vuln=str(vuln_path),
                        patch=str(patch_path),
                    )
                    continue
                if task is None:
                    log.warn("reference build result has no matching task", cve=cve_id)
                    continue
                vuln_commit = item.get("vuln_commit", "") or task["vuln_commit"]
                patch_commit = item.get("patch_commit", "") or task["patch_commit"]
                binary_name = item.get("binary_name", "")
                if not binary_name:
                    log.warn("reference build result has no binary name", cve=cve_id)
                    continue
                canonical_vuln = materialize_reference_output(
                    config,
                    vuln_path,
                    output_path(config, cve_id, "vuln", vuln_commit, binary_name),
                    log,
                    cve_id=cve_id,
                    label="vuln",
                )
                canonical_patch = materialize_reference_output(
                    config,
                    patch_path,
                    output_path(config, cve_id, "patch", patch_commit, binary_name),
                    log,
                    cve_id=cve_id,
                    label="patch",
                )
                if canonical_vuln is None or canonical_patch is None:
                    continue
                validation = validate_reference_pair(
                    canonical_vuln,
                    canonical_patch,
                    vuln_functions=task.get("vuln_functions", task["functions"]),
                    patch_functions=task.get("patch_functions", task["functions"]),
                    architecture=config.architecture,
                    nm=config.toolchain.nm,
                )
                if not validation.valid:
                    canonical_vuln.unlink(missing_ok=True)
                    canonical_patch.unlink(missing_ok=True)
                    log.warn(
                        "reference build result rejected after function validation",
                        cve=cve_id,
                        validation=validation.as_dict(),
                    )
                    continue
                db.upsert_reference(
                    {
                        "cve_id": cve_id,
                        "vuln_commit": vuln_commit,
                        "patch_commit": patch_commit,
                        "binary_name": binary_name,
                        "vuln_path": str(canonical_vuln),
                        "patch_path": str(canonical_patch),
                        "functions": item.get("functions", []),
                        "compiler": config.compiler,
                        "opt": config.opt,
                        "architecture": config.architecture,
                        "build_profile": "",
                        "status": "ok",
                        "report": {
                            **item,
                            "vuln_path": str(canonical_vuln),
                            "patch_path": str(canonical_patch),
                            "source_vuln_path": str(vuln_path),
                            "source_patch_path": str(patch_path),
                            "architecture": config.architecture,
                        },
                    }
                )
                log.trace("reference built", cve=cve_id, binary=binary_name, architecture=config.architecture)
            else:
                log.warn("reference build item failed", item=item)


def run_reference_build(config: BuildConfig, db: ProjectDB) -> None:
    config = config.reference_config()
    log = get_logger(config.output, "reference_build")
    config.reference_bin_dir.mkdir(parents=True, exist_ok=True)
    config.worktree_root.mkdir(parents=True, exist_ok=True)
    tasks = build_tasks(config, db)
    if not ensure_compile_script(config, "reference_build", tasks, log):
        log.warn("compile script unavailable before codex batch", project=config.project)
        run_reference_build_codex(config, db, tasks)
    else:
        compiler = load_compile_script(config.project)
        if compiler:
            failed = run_reference_build_local(config, db, tasks, compiler)
            failed = repair_reference_script_and_retry(config, db, failed, log)
            if failed:
                run_reference_build_codex(config, db, failed, prefix="repair")
        else:
            log.warn("compile script failed to load before local reference build", project=config.project)
            run_reference_build_codex(config, db, tasks)
    missing = db.selected_fixes_missing_reference(config)
    status = "ok" if not missing else "partial"
    removed_reference_files = cleanup_unreferenced_reference_files(config, db, log) if status == "ok" else 0
    removed_build_logs = cleanup_current_stage_build_logs(config, log, stage="reference_build", success=status == "ok", reason="reference build stage completed")
    removed_worktrees = cleanup_project_worktrees(config, log, success=status == "ok", reason="reference build stage completed")
    db.record_stage(
        "reference_build",
        status,
        {
            "tasks": len(tasks),
            "references": len(db.references(config)),
            "missing_cves": missing,
            "compiler": config.compiler,
            "opt": config.opt,
            "architecture": config.architecture,
            "removed_build_logs": removed_build_logs,
            "removed_worktrees": removed_worktrees,
            "removed_reference_files": removed_reference_files,
        },
    )
