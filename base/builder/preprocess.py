from __future__ import annotations

import json
import subprocess

from builder.config import BuildConfig
from builder.db import ProjectDB
from builder.logging import get_logger


def update_git_repo(config: BuildConfig, db: ProjectDB) -> None:
    log = get_logger(config.output, "preprocess")
    commands = [
        ["git", "-C", str(config.repo), "fetch", "--all", "--tags", "--prune"],
    ]
    details = []
    status = "ok"
    for cmd in commands:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        detail = {"command": cmd, "returncode": proc.returncode, "output_tail": proc.stdout[-4000:]}
        details.append(detail)
        if proc.returncode:
            status = "failed"
            log.warn("git repo update failed", **detail)
        else:
            log.trace("git repo update command succeeded", **detail)
    db.record_stage("git_update", status, details)


def write_config(db: ProjectDB, config: BuildConfig) -> None:
    db.set_project_value(
        "build_config",
        {
            "project": config.project,
            "repo": str(config.repo),
            "output": str(config.output),
            "db_path": str(config.db_path),
            "vendor_product": config.vendor_product,
            "latest": config.latest,
            "cves": config.cves,
            "compiler": config.compiler,
            "opt": config.opt,
            "architecture": config.architecture,
            "toolchain": config.toolchain.command_details(),
            "batch_size": config.batch_size,
            "metadata_mode": config.metadata_mode,
            "cleanup_worktrees": config.cleanup_worktrees,
            "cleanup_build_logs": config.cleanup_build_logs,
            "testset_count": config.testset_count,
            "testset_strategy": config.testset_strategy,
            "testset_manifest": str(config.testset_manifest) if config.testset_manifest else "",
        },
    )
