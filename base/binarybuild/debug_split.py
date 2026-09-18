from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from builder.architecture import matches_elf_architecture
from builder.config import BuildConfig
from builder.db import ProjectDB
from builder.logging import get_logger


@dataclass
class SplitStats:
    processed: int = 0
    reused: int = 0
    missing: int = 0
    failed: int = 0


def is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def command_tool(name: str, fallback: str) -> str:
    path = shutil.which(name)
    if path:
        return path
    fallback_path = shutil.which(fallback)
    if fallback_path:
        return fallback_path
    return name


def run_checked(command: list[str], cwd: Path, log, action: str, target: Path) -> bool:
    proc = subprocess.run(command, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if proc.returncode == 0:
        return True
    log.error(
        "debug split command failed",
        action=action,
        target=str(target),
        command=command,
        returncode=proc.returncode,
        stdout=proc.stdout[-2000:],
        stderr=proc.stderr[-2000:],
    )
    return False


def same_existing_path(left: Path, right: Path) -> bool:
    try:
        return left.exists() and right.exists() and left.resolve() == right.resolve()
    except OSError:
        return False


def split_binary(config: BuildConfig, src: Path, stripped: Path, debug: Path, log) -> str:
    if not src.exists():
        log.warn("binary missing before debug split", path=str(src), stripped=str(stripped), debug=str(debug))
        return "missing"
    if not is_elf(src) or not matches_elf_architecture(src, config.architecture):
        log.warn("skip wrong-architecture binary during debug split", path=str(src), expected=config.architecture)
        return "failed"

    stripped.parent.mkdir(parents=True, exist_ok=True)
    debug.parent.mkdir(parents=True, exist_ok=True)
    if same_existing_path(src, stripped):
        if (
            debug.exists()
            and matches_elf_architecture(stripped, config.architecture)
            and matches_elf_architecture(debug, config.architecture)
        ):
            return "reused"
        log.warn("debug file missing for already stripped binary", stripped=str(stripped), debug=str(debug))
        return "failed"

    objcopy = config.toolchain.objcopy
    strip_tool = config.toolchain.strip
    stripped_tmp = stripped.with_name(stripped.name + ".tmp")
    debug_tmp = debug.with_name(debug.name + ".tmp")
    stripped_tmp.unlink(missing_ok=True)
    debug_tmp.unlink(missing_ok=True)
    try:
        with TemporaryDirectory(prefix="agentic-debug-split-") as temp_dir:
            local_dir = Path(temp_dir)
            local_src = local_dir / "source.elf"
            local_stripped = local_dir / "stripped.elf"
            local_debug = local_dir / debug.name
            shutil.copy2(src, local_src)
            shutil.copy2(local_src, local_stripped)
            if not run_checked(
                [objcopy, "--only-keep-debug", str(local_src), str(local_debug)],
                local_dir,
                log,
                "only-keep-debug",
                src,
            ):
                return "failed"
            if not run_checked([strip_tool, "--strip-unneeded", str(local_stripped)], local_dir, log, "strip", src):
                return "failed"
            if not run_checked(
                [objcopy, f"--add-gnu-debuglink={local_debug}", str(local_stripped)],
                local_dir,
                log,
                "add-gnu-debuglink",
                src,
            ):
                return "failed"
            if not matches_elf_architecture(local_stripped, config.architecture) or not matches_elf_architecture(
                local_debug, config.architecture
            ):
                log.error(
                    "debug split produced wrong ELF architecture",
                    source=str(src),
                    stripped=str(stripped),
                    debug=str(debug),
                    expected=config.architecture,
                )
                return "failed"
            shutil.copy2(local_debug, debug_tmp)
            shutil.copy2(local_stripped, stripped_tmp)
        if not matches_elf_architecture(stripped_tmp, config.architecture) or not matches_elf_architecture(
            debug_tmp, config.architecture
        ):
            log.error(
                "uploaded debug split has wrong ELF architecture",
                source=str(src),
                stripped=str(stripped),
                debug=str(debug),
                expected=config.architecture,
            )
            return "failed"
        debug_tmp.replace(debug)
        stripped_tmp.replace(stripped)
    except OSError as exc:
        log.error("debug split file operation failed", source=str(src), error=str(exc))
        return "failed"
    finally:
        stripped_tmp.unlink(missing_ok=True)
        debug_tmp.unlink(missing_ok=True)
    return "processed"


def resolve_source_path(recorded: str, raw_dir: Path, stripped_dir: Path, stripped_name: str) -> Path | None:
    recorded_path = Path(recorded) if recorded else Path()
    candidates = [raw_dir / stripped_name]
    if recorded_path.name:
        candidates.extend([raw_dir / recorded_path.name, recorded_path])
    candidates.append(stripped_dir / stripped_name)
    if recorded_path.name:
        candidates.append(stripped_dir / recorded_path.name)
    seen: set[Path] = set()
    for candidate in candidates:
        if not str(candidate) or candidate in seen:
            continue
        seen.add(candidate)
        if candidate.exists():
            return candidate
    return None


def release_version_for_tag(db: ProjectDB, tag: str, fallback: str) -> str:
    row = db.conn.execute("SELECT norm_tag, version FROM releases WHERE tag=? LIMIT 1", (tag,)).fetchone()
    if row:
        return row["norm_tag"] or row["version"] or fallback
    return fallback


def load_report_json(row) -> dict[str, Any]:
    try:
        value = json.loads(row["report_json"] or "{}")
    except json.JSONDecodeError:
        value = {}
    return value if isinstance(value, dict) else {}


def merge_report(row, **fields: Any) -> str:
    report = load_report_json(row)
    debug_split = report.get("debug_split", {})
    if not isinstance(debug_split, dict):
        debug_split = {}
    debug_split.update(fields)
    report["debug_split"] = debug_split
    return json.dumps(report, ensure_ascii=False)


def target_rows(config: BuildConfig, db: ProjectDB) -> list[Any]:
    scope, scope_params = db.scope_sql("t", config)
    return list(
        db.conn.execute(
            f"""
            SELECT DISTINCT a.*, v.architecture, v.compiler, v.opt, v.build_profile
            FROM testset_entries t
            JOIN target_mappings m ON m.testset_entry_id=t.id AND m.status='ok'
            JOIN target_artifacts a ON a.id=m.artifact_id AND a.status='ok'
            JOIN build_variants v ON v.id=a.build_variant_id
            WHERE t.status='selected' AND v.architecture=? AND v.compiler=? AND v.opt=? AND v.build_profile=''{scope}
            ORDER BY a.tag, a.binary_name
            """,
            (config.architecture, config.compiler, config.opt, *scope_params),
        )
    )


def update_target_paths(db: ProjectDB, row, stripped: Path, debug: Path, report_json: str) -> None:
    db.conn.execute(
        """
        UPDATE target_artifacts
        SET path=?, debug_path=?, report_json=?, updated_at=CURRENT_TIMESTAMP
        WHERE id=?
        """,
        (db.stored_path(stripped), db.stored_path(debug), report_json, row["id"]),
    )


def split_target_binaries(config: BuildConfig, db: ProjectDB, log) -> tuple[SplitStats, list[Path]]:
    stats = SplitStats()
    processed_sources: list[Path] = []
    for row in target_rows(config, db):
        version = release_version_for_tag(db, row["tag"], row["version"] or "")
        name = config.target_binary_name(version, row["binary_name"])
        recorded_path = str(db.resolve_path(row["path"])) if row["path"] else ""
        source = resolve_source_path(recorded_path, config.target_bin_dir, config.target_stripped_dir, name)
        stripped = config.target_stripped_dir / name
        debug = config.target_debug_dir / f"{name}.debug"
        if source is None:
            stats.missing += 1
            log.warn("target binary not found for debug split", tag=row["tag"], binary=row["binary_name"], name=name, path=row["path"])
            continue
        result = split_binary(config, source, stripped, debug, log)
        if result == "processed":
            stats.processed += 1
        elif result == "reused":
            stats.reused += 1
        elif result == "missing":
            stats.missing += 1
            continue
        else:
            stats.failed += 1
            continue
        report_json = merge_report(row, debug_path=str(debug), stripped_path=str(stripped), original_path=row["path"] or "")
        update_target_paths(db, row, stripped, debug, report_json)
        if source.parent == config.target_bin_dir:
            processed_sources.append(source)
        log.trace("target debug split ready", tag=row["tag"], binary=row["binary_name"], stripped=str(stripped), debug=str(debug))
    db.conn.commit()
    return stats, processed_sources


def remove_processed_raw_files(config: BuildConfig, sources: list[Path], log) -> dict[str, int | bool]:
    removed_files = 0
    for source in sources:
        if source.exists() and source.parent == config.target_bin_dir:
            source.unlink()
            removed_files += 1
    removed_dir = False
    if config.target_bin_dir.exists() and not any(config.target_bin_dir.iterdir()):
        config.target_bin_dir.rmdir()
        removed_dir = True
    if removed_files or removed_dir:
        log.trace("removed processed raw target files", files=removed_files, directory=removed_dir, path=str(config.target_bin_dir))
    return {"files": removed_files, "directory": removed_dir}


def run_debug_split(config: BuildConfig, db: ProjectDB) -> None:
    log = get_logger(config.output, "debug_split")
    target_stats, processed_sources = split_target_binaries(config, db, log)
    failed = target_stats.failed
    missing = target_stats.missing
    removed = {}
    if failed == 0 and missing == 0:
        removed = remove_processed_raw_files(config, processed_sources, log)
    else:
        log.warn("raw binary directories kept because debug split was incomplete", failed=failed, missing=missing)
    status = "ok" if failed == 0 and missing == 0 else "partial"
    db.record_stage(
        "debug_split",
        status,
        {
            "target": target_stats.__dict__,
            "removed_raw_dirs": removed,
            "target_debug_dir": str(config.target_debug_dir),
            "target_stripped_dir": str(config.target_stripped_dir),
            "compiler": config.compiler,
            "opt": config.opt,
            "architecture": config.architecture,
        },
    )
    log.trace("debug split stage complete", status=status, failed=failed, missing=missing, removed_raw_dirs=removed)
