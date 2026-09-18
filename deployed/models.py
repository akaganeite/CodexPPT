"""Serializable records shared by selection, materialization, and export."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class LabeledSourceVersion:
    cve_id: str
    source_package: str
    source_version: str
    ubuntu_version: str
    series: str
    pocket: str
    component: str
    label: str
    reason: str
    provenance: str
    source_url: str = ""
    source_sha256: str = ""
    metadata_functions: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PackagePair:
    cve_id: str
    label: str
    source_package: str
    source_version: str
    series: str
    pocket: str
    component: str
    architecture: str = ""
    publication_date: str = ""
    runtime_package: str = ""
    runtime_version: str = ""
    runtime_url: str = ""
    runtime_sha256: str = ""
    runtime_filename: str = ""
    debug_package: str = ""
    debug_version: str = ""
    debug_url: str = ""
    debug_sha256: str = ""
    debug_filename: str = ""
    status: str = "pending"
    reason: str = ""
    provenance: list[str] = field(default_factory=list)
    requested_functions: list[str] = field(default_factory=list)
    ranking_task_id: str = ""
    candidate_id: str = ""

    @property
    def artifact_key(self) -> tuple[str, str, str, str]:
        return (self.runtime_url, self.debug_url, self.runtime_sha256, self.debug_sha256)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ArtifactResult:
    cve_id: str
    label: str
    source_version: str
    runtime_package: str
    runtime_version: str
    debug_package: str
    debug_version: str
    status: str
    reason: str = ""
    build_id: str = ""
    runtime_elf: str = ""
    debug_file: str = ""
    unstripped_path: str = ""
    stripped_path: str = ""
    debug_path: str = ""
    functions: list[str] = field(default_factory=list)
    found_functions: list[str] = field(default_factory=list)
    missing_functions: list[str] = field(default_factory=list)
    no_disassembly: list[str] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)
