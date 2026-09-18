from __future__ import annotations

import subprocess
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import DEFAULT, patch

from builder import cli
from builder.config import BuildConfig
from builder.db import ProjectDB


PIPELINE_STAGES = (
    "update_git_repo",
    "update_cve_metadata",
    "run_cve2diff",
    "run_source_analysis",
    "run_reference_build",
    "update_releases",
    "select_default_entries",
    "run_target_build",
    "run_not_affected_review",
    "run_debug_split",
    "export_variant_testset_and_groundtruth",
    "export_outputs",
    "run_rca_metadata",
)


class DatabaseTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.databases: list[ProjectDB] = []

    def tearDown(self) -> None:
        for db in reversed(self.databases):
            db.close()
        self.tempdir.cleanup()

    def open_db(self, name: str = "demo.sqlite") -> ProjectDB:
        db = ProjectDB(self.root / name)
        self.databases.append(db)
        return db

    def close_db(self, db: ProjectDB) -> None:
        if db in self.databases:
            self.databases.remove(db)
        db.close()


def make_config(
    root: Path,
    cves: list[str],
    compiler: str = "clang",
    opt: str = "-O3",
    architecture: str = "x86_64",
) -> BuildConfig:
    return BuildConfig(
        project="demo",
        repo=root / "repo",
        output=root,
        db_path=root / "demo.sqlite",
        vendor_product="demo:demo",
        latest=0,
        cves=cves,
        compiler=compiler,
        opt=opt,
        codex_model="",
        codex_sandbox="danger-full-access",
        batch_size=10,
        github_token="",
        nvd_api_key="",
        metadata_mode="skip",
        resume=True,
        cleanup_worktrees="success",
        cleanup_build_logs="success",
        testset_count=3,
        testset_strategy="chronical",
        architecture=architecture,
    )


def build_args(root: Path, cves: list[str]) -> Namespace:
    repo = root / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    return Namespace(
        project="demo", repo=repo, output=root, db=None, vendor_product="demo:demo",
        latest=None, cve=cves, cve_file=None, compiler="clang", opt="-O3",
        testset_strategy="chronical", testset_count=3, batch_size=10,
        codex_model="", codex_sandbox="danger-full-access", github_token="",
        nvd_api_key="", metadata_mode="skip", cleanup_worktrees="success",
        cleanup_build_logs="success", resume=True, arch="x86_64",
        testset_manifest=None,
    )


def mock_pipeline_stages():
    return patch.multiple(cli, **{name: DEFAULT for name in PIPELINE_STAGES})


def add_testset(db: ProjectDB, cve_id: str, tag: str, label: str = "vuln") -> None:
    version = tag.removeprefix("v")
    db.upsert_cve({"id": cve_id, "summary": cve_id}, selected=True)
    db.upsert_release({"tag": tag, "commit_sha": f"sha-{tag}", "date": "", "version": version, "norm_tag": version})
    db.replace_testset_entries(cve_id, [{"label": label, "version": version, "tag": tag, "binary_name": "tool"}])


def write_elf(path: Path, architecture: str = "x86_64") -> None:
    machine = 0xB7 if architecture == "aarch64" else 0x3E
    header = bytearray(20)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[18:20] = machine.to_bytes(2, "little")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(header)


def add_artifact(
    db: ProjectDB,
    root: Path,
    cve_id: str,
    tag: str,
    compiler: str,
    opt: str,
    split: bool = True,
    architecture: str = "x86_64",
) -> int:
    version = tag.removeprefix("v")
    base_variant = f"{compiler}-{opt.removeprefix('-')}"
    variant = base_variant if architecture == "x86_64" else f"{architecture}-{base_variant}"
    stripped = root / "binaries" / "target" / "demo_stripped" / f"demo-{version}-tool-{variant}"
    debug = root / "binaries" / "target" / "demo_debug" / f"{stripped.name}.debug"
    write_elf(stripped, architecture)
    if split:
        write_elf(debug, architecture)
    artifact_id = db.upsert_target_artifact(
        {
            "project": "demo",
            "tag": tag,
            "version": version,
            "binary_name": "tool",
            "compiler": compiler,
            "opt": opt,
            "architecture": architecture,
            "path": stripped,
            "status": "ok",
        }
    )
    if split:
        db.conn.execute("UPDATE target_artifacts SET debug_path=? WHERE id=?", (db.stored_path(debug), artifact_id))
        db.conn.commit()
    label = db.conn.execute(
        "SELECT label FROM testset_entries WHERE cve_id=? AND tag=? AND binary_name='tool'", (cve_id, tag)
    ).fetchone()["label"]
    db.upsert_target_mapping(
        {"cve_id": cve_id, "label": label, "tag": tag, "binary_name": "tool", "artifact_id": artifact_id, "status": "ok"}
    )
    return artifact_id
