from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent


def string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value]


@dataclass(frozen=True)
class NameRules:
    exact: tuple[str, ...] = ()
    regex: tuple[str, ...] = ()

    @classmethod
    def from_json(cls, data: dict[str, Any] | None) -> "NameRules":
        data = data or {}
        return cls(tuple(string_list(data.get("exact"))), tuple(string_list(data.get("regex"))))

    def matches(self, name: str) -> bool:
        return name in self.exact or any(re.search(pattern, name) for pattern in self.regex)


@dataclass(frozen=True)
class DebugRules(NameRules):
    allow_dbgsym_for_runtime: bool = True
    allow_old_dbg: bool = True

    @classmethod
    def from_json(cls, data: dict[str, Any] | None) -> "DebugRules":
        data = data or {}
        return cls(
            tuple(string_list(data.get("exact"))),
            tuple(string_list(data.get("regex"))),
            bool(data.get("allow_dbgsym_for_runtime", True)),
            bool(data.get("allow_old_dbg", True)),
        )


@dataclass(frozen=True)
class ElfRules:
    so_globs: tuple[str, ...] = ()
    executable_globs: tuple[str, ...] = ()
    exclude_globs: tuple[str, ...] = ()

    @classmethod
    def from_json(cls, data: dict[str, Any] | None) -> "ElfRules":
        data = data or {}
        return cls(
            tuple(string_list(data.get("so_globs"))),
            tuple(string_list(data.get("executable_globs"))),
            tuple(string_list(data.get("exclude_globs"))),
        )


@dataclass(frozen=True)
class ProjectConfig:
    project: str
    source_package: str
    binary_packages: NameRules
    debug_packages: DebugRules
    elf: ElfRules

    def runtime_name_matches(self, package: str) -> bool:
        return self.binary_packages.matches(package)

    def debug_name_matches(self, package: str) -> bool:
        return self.debug_packages.matches(package)


@dataclass(frozen=True)
class Defaults:
    arch: str = "amd64"
    verify_sha256: bool = True


@dataclass(frozen=True)
class ConfigBundle:
    defaults: Defaults
    projects: dict[str, ProjectConfig] = field(default_factory=dict)


def load_config(path: Path | None = None) -> ConfigBundle:
    config_path = (path or (ROOT / "config.json")).expanduser().resolve()
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    defaults_raw = raw.get("defaults") or {}
    defaults = Defaults(
        arch=str(defaults_raw.get("arch") or Defaults.arch),
        verify_sha256=bool(defaults_raw.get("verify_sha256", True)),
    )
    projects = {}
    for project, data in (raw.get("projects") or {}).items():
        projects[project] = ProjectConfig(
            project=project,
            source_package=str(data.get("source_package") or project),
            binary_packages=NameRules.from_json(data.get("binary_packages")),
            debug_packages=DebugRules.from_json(data.get("debug_packages")),
            elf=ElfRules.from_json(data.get("elf")),
        )
    return ConfigBundle(defaults=defaults, projects=projects)


def require_project(bundle: ConfigBundle, project: str) -> ProjectConfig:
    if project in bundle.projects:
        return bundle.projects[project]
    return ProjectConfig(
        project=project,
        source_package=project,
        binary_packages=NameRules(exact=(project,)),
        debug_packages=DebugRules(exact=(f"{project}-dbgsym", f"{project}-dbg")),
        elf=ElfRules(),
    )


def parse_csv_args(values: list[str] | None) -> list[str]:
    output = []
    for value in values or []:
        for item in str(value).split(","):
            item = item.strip()
            if item:
                output.append(item)
    return output
