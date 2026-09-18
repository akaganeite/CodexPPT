from __future__ import annotations

from pathlib import Path

from builder.config import BuildConfig
from builder.logging import StageLogger, current_log_root


def should_cleanup_build_logs(config: BuildConfig, success: bool) -> bool:
    if config.cleanup_build_logs == "none":
        return False
    if config.cleanup_build_logs == "all":
        return True
    return success


def remove_build_logs(config: BuildConfig, log_paths: list[str], log: StageLogger, *, success: bool, reason: str) -> int:
    if not should_cleanup_build_logs(config, success):
        return 0
    removed = 0
    for raw_path in log_paths:
        path = Path(raw_path)
        if not path.exists():
            continue
        try:
            path.unlink()
        except OSError as exc:
            log.warn("failed to remove build log", path=str(path), error=str(exc), reason=reason)
            continue
        removed += 1
    if removed:
        log.trace("removed build logs", count=removed, success=success, reason=reason)
    return removed


def remove_build_log_paths(log_paths: list[Path], log: StageLogger, *, reason: str) -> int:
    removed = 0
    for path in log_paths:
        if not path.exists():
            continue
        try:
            path.unlink()
        except OSError as exc:
            log.warn("failed to remove build log", path=str(path), error=str(exc), reason=reason)
            continue
        removed += 1
    if removed:
        log.trace("removed build logs", count=removed, reason=reason)
    return removed


def cleanup_current_stage_build_logs(config: BuildConfig, log: StageLogger, *, stage: str, success: bool, reason: str) -> int:
    if not should_cleanup_build_logs(config, success):
        log.trace(
            "stage build log cleanup skipped",
            stage=stage,
            success=success,
            policy=config.cleanup_build_logs,
            reason=reason,
        )
        return 0
    root = current_log_root(config.output) / "trace" / f"{stage}_builds"
    logs = sorted(root.glob("*.log")) if root.exists() else []
    removed = remove_build_log_paths(logs, log, reason=reason)
    if root.exists():
        try:
            root.rmdir()
        except OSError:
            pass
    log.trace(
        "stage build log cleanup complete",
        stage=stage,
        found=len(logs),
        removed=removed,
        success=success,
        policy=config.cleanup_build_logs,
        reason=reason,
    )
    return removed


def list_build_logs(output: Path, stage: str | None = None) -> list[Path]:
    trace_roots = sorted(path for path in (output / "log").glob("*/trace") if path.is_dir())
    legacy_trace_root = output / "logs" / "trace"
    if legacy_trace_root.exists():
        trace_roots.append(legacy_trace_root)
    if stage:
        roots = [trace_root / f"{stage}_builds" for trace_root in trace_roots]
    else:
        roots = []
        for trace_root in trace_roots:
            roots.extend(sorted(path for path in trace_root.glob("*_builds") if path.is_dir()))
    logs: list[Path] = []
    for root in roots:
        if root.exists():
            logs.extend(sorted(root.glob("*.log")))
    return logs


def remove_existing_build_logs(output: Path, log: StageLogger, stage: str | None = None) -> int:
    removed = remove_build_log_paths(list_build_logs(output, stage), log, reason="manual cleanup command")
    log.trace("manual build log cleanup complete", stage=stage or "all", removed=removed)
    return removed
