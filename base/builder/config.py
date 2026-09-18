from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from builder.architecture import DEFAULT_ARCHITECTURE, Toolchain, normalize_architecture, resolve_toolchain
from builder.logging import current_log_root
from utils.io import read_json
from utils.paths import ROOT


REFERENCE_COMPILER = "gcc"
REFERENCE_OPT = "-O0"
REFERENCE_BUILD_PROFILE = ""


def path_token(value: str, default: str) -> str:
    token = re.sub(r"[^A-Za-z0-9.+]+", "-", value.strip()).strip("-")
    return token or default


def load_base_config() -> dict[str, Any]:
    data = read_json(ROOT / "config.json", {})
    return data if isinstance(data, dict) else {}


def normalize_testset_strategy(strategy: str) -> str:
    token = re.sub(r"\s+", "-", strategy.strip().lower()).replace("_", "-")
    return token or "chronical"


@dataclass
class BuildConfig:
    project: str
    repo: Path
    output: Path
    db_path: Path
    vendor_product: str
    latest: int
    cves: list[str]
    compiler: str
    opt: str
    codex_model: str
    codex_sandbox: str
    batch_size: int
    github_token: str
    nvd_api_key: str
    metadata_mode: str
    resume: bool
    cleanup_worktrees: str
    cleanup_build_logs: str
    testset_count: int
    testset_strategy: str
    architecture: str = DEFAULT_ARCHITECTURE
    testset_manifest: Path | None = None
    toolchain: Toolchain = field(init=False)

    def __post_init__(self) -> None:
        self.architecture = normalize_architecture(self.architecture)
        self.toolchain = resolve_toolchain(self.architecture, self.compiler)

    def reference_config(self) -> "BuildConfig":
        return replace(self, compiler=REFERENCE_COMPILER, opt=REFERENCE_OPT)

    def with_cves(self, cves: list[str]) -> "BuildConfig":
        return replace(self, cves=list(cves))

    def all_cves_config(self) -> "BuildConfig":
        return replace(self, cves=[])

    @property
    def vendor(self) -> str:
        return self.vendor_product.split(":", 1)[0]

    @property
    def product_name(self) -> str:
        return self.vendor_product.split(":", 1)[1]

    @property
    def compiler_id(self) -> str:
        return path_token(self.compiler, "compiler")

    @property
    def architecture_id(self) -> str:
        return self.architecture

    @property
    def opt_id(self) -> str:
        return path_token(self.opt, "opt")

    @property
    def build_variant(self) -> str:
        base = f"{self.compiler_id}-{self.opt_id}"
        return base if self.architecture == DEFAULT_ARCHITECTURE else f"{self.architecture_id}-{base}"

    @property
    def worktree_root(self) -> Path:
        return self.output / "worktrees" / self.project

    @property
    def diff_dir(self) -> Path:
        return self.output / "Diff" / self.project / "diff_files"

    @property
    def reference_bin_dir(self) -> Path:
        root = self.output / "binaries" / "reference" / self.project
        return root if self.architecture == DEFAULT_ARCHITECTURE else root / self.architecture_id

    @property
    def target_bin_dir(self) -> Path:
        return self.output / "binaries" / "target" / self.project

    @property
    def target_debug_dir(self) -> Path:
        return self.output / "binaries" / "target" / f"{self.project}_debug"

    @property
    def target_stripped_dir(self) -> Path:
        return self.output / "binaries" / "target" / f"{self.project}_stripped"

    def reference_binary_name(self, cve_id: str, label: str, commit: str, binary_name: str) -> str:
        return f"{cve_id}-{label}-{commit[:12]}-{binary_name}"

    def target_binary_name(self, version: str, binary_name: str) -> str:
        return f"{self.project}-{version}-{binary_name}-{self.build_variant}"

    @property
    def codex_dir(self) -> Path:
        return current_log_root(self.output) / "codex_runs"

    @property
    def exports_dir(self) -> Path:
        return self.output / "exports"

    @property
    def rca_dir(self) -> Path:
        return self.output / "RCA"

    @property
    def rca_project_json(self) -> Path:
        return self.rca_dir / f"{self.project}.json"

    @property
    def rca_source_full_json(self) -> Path:
        return self.rca_dir / f"{self.project}_project_source_analysis.full.json"

    @property
    def rca_source_min_json(self) -> Path:
        return self.rca_dir / f"{self.project}_project_source_analysis.min.json"

    @property
    def rca_related_file_allowlist_json(self) -> Path:
        return self.exports_dir / f"{self.project}_related_file_allowlist.json"

    @property
    def rca_behavior_json(self) -> Path:
        return self.exports_dir / f"{self.project}_behavior.json"
