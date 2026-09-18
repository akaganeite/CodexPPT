from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from builder.config import BuildConfig
from builder.logging import StageLogger


def should_cleanup(config: BuildConfig, success: bool) -> bool:
    if config.cleanup_worktrees == "none":
        return False
    if config.cleanup_worktrees == "all":
        return True
    return success


def remove_worktree(config: BuildConfig, worktree: Path, log: StageLogger, *, success: bool, reason: str) -> bool:
    if not worktree or not worktree.exists() or not should_cleanup(config, success):
        return False

    proc = subprocess.run(
        ["git", "-C", str(config.repo), "worktree", "remove", "--force", str(worktree)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        log.trace("removed worktree", path=str(worktree), success=success, reason=reason)
        return True

    log.warn("git worktree remove failed", path=str(worktree), stderr=proc.stderr.strip(), reason=reason)
    try:
        shutil.rmtree(worktree)
    except OSError as exc:
        log.warn("failed to delete worktree directory", path=str(worktree), error=str(exc), reason=reason)
        return False
    log.trace("deleted worktree directory", path=str(worktree), success=success, reason=reason)
    return True


def remove_worktrees(config: BuildConfig, worktrees: set[Path], log: StageLogger, *, success: bool, reason: str) -> int:
    removed = 0
    for worktree in sorted(worktrees):
        if remove_worktree(config, worktree, log, success=success, reason=reason):
            removed += 1
    return removed


def list_project_worktrees(output: Path, project: str) -> set[Path]:
    root = output / "worktrees" / project
    if not root.exists():
        return set()
    return {path for path in root.iterdir() if path.is_dir()}


def cleanup_project_worktrees(config: BuildConfig, log: StageLogger, *, success: bool, reason: str) -> int:
    worktrees = list_project_worktrees(config.output, config.project)
    removed = remove_worktrees(config, worktrees, log, success=success, reason=reason)
    if worktrees or removed:
        log.trace(
            "project worktree cleanup complete",
            found=len(worktrees),
            removed=removed,
            success=success,
            policy=config.cleanup_worktrees,
            reason=reason,
        )
    return removed
