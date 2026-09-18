from __future__ import annotations

from pathlib import Path

from builder.architecture import matches_elf_architecture
from builder.config import BuildConfig
from builder.db import ProjectDB


def reconcile_existing_variant_mappings(
    config: BuildConfig, db: ProjectDB, *, full_scope: bool = False, log=None
) -> int:
    """Reattach selected entries to an exact existing artifact for this variant."""
    rows = db.testset_entries(None if full_scope else config)
    repaired = 0
    for row in rows:
        if row["status"] != "selected" or db.target_mapping_for_testset(row, config):
            continue
        artifact = db.target_artifact_for_task(
            config.project, row["tag"], row["binary_name"], config.compiler, config.opt, architecture=config.architecture
        )
        if not artifact:
            expected_name = config.target_binary_name(row["version"], row["binary_name"])
            stripped = config.target_stripped_dir / expected_name
            debug = config.target_debug_dir / f"{expected_name}.debug"
            if (
                stripped.is_file()
                and debug.is_file()
                and matches_elf_architecture(stripped, config.architecture)
                and matches_elf_architecture(debug, config.architecture)
            ):
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
                        "path": stripped,
                        "status": "ok",
                        "report": {"source": "recovered_split_artifact_reconcile"},
                    }
                )
                db.conn.execute(
                    "UPDATE target_artifacts SET debug_path=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (db.stored_path(debug), artifact_id),
                )
                db.conn.commit()
                artifact = db.target_artifact_for_task(
                    config.project,
                    row["tag"],
                    row["binary_name"],
                    config.compiler,
                    config.opt,
                    architecture=config.architecture,
                )
        if not artifact:
            continue
        path = Path(artifact["path"] or "")
        expected_name = config.target_binary_name(row["version"], row["binary_name"])
        if not path.is_file() or path.name != expected_name or not matches_elf_architecture(path, config.architecture):
            continue
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
                "artifact_id": artifact["id"],
                "status": "ok",
                "report": {
                    "source": "existing_variant_artifact_reconcile",
                    "version": row["version"],
                    "compiler": config.compiler,
                    "opt": config.opt,
                    "architecture": config.architecture,
                },
            }
        )
        repaired += 1
    if repaired and log:
        log.trace(
            "reconciled existing target mappings",
            count=repaired,
            compiler=config.compiler,
            opt=config.opt,
            architecture=config.architecture,
            full_scope=full_scope,
        )
    return repaired
