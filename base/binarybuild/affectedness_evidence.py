"""Small, deterministic artifact facts for the affectedness reviewer.

The facts are intentionally non-decisive.  They give the reviewer a compact
starting point for checking the produced ELF, while source-level conclusions
remain subject to the target's actual platform and enabled feature set.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from binarybuild.compile_scripts import script_path_for_project, spec_path_for_project
from builder.config import BuildConfig


_ELF_MACHINES = {
    0x03: "i386",
    0x3E: "x86-64",
    0x28: "arm",
    0xB7: "aarch64",
    0x08: "mips",
    0x15: "ppc64",
}
_NEEDED_RE = re.compile(r"Shared library: \[([^\]]+)\]")
_MAX_OUTPUT_CHARS = 8_000


def target_arch(path: str | Path) -> str:
    """Return a compact ELF class/machine string, or an empty string."""
    try:
        with Path(path).open("rb") as handle:
            header = handle.read(20)
    except OSError:
        return ""
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return ""
    elf_class = "elf64" if header[4] == 2 else "elf32" if header[4] == 1 else "elf?"
    endian = "little" if header[5] != 2 else "big"
    machine = int.from_bytes(header[18:20], endian)
    return f"{elf_class}/{_ELF_MACHINES.get(machine, hex(machine))}"


def command_text(command: list[str]) -> str:
    """Run a read-only inspection command and retain a bounded diagnostic."""
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode:
        return ""
    return proc.stdout[:_MAX_OUTPUT_CHARS]


def dynamic_dependencies(path: str | Path, readelf: str = "readelf") -> list[str]:
    """Return DT_NEEDED entries for an ELF; static binaries simply return []."""
    text = command_text([readelf, "-dW", str(path)])
    return list(dict.fromkeys(match.group(1) for match in _NEEDED_RE.finditer(text)))


def artifact_build_record(candidate: dict[str, Any]) -> dict[str, Any]:
    raw = candidate.get("artifact_report_json") or ""
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def artifact_evidence(config: BuildConfig, candidate: dict[str, Any]) -> dict[str, Any]:
    """Create a compact, project-neutral review context for one target artifact."""
    target_path = Path(candidate.get("target_path") or candidate.get("path") or "")
    debug_path = Path(candidate.get("debug_path") or "")
    script = script_path_for_project(config.project)
    spec = spec_path_for_project(config.project)
    target_exists = target_path.is_file()
    debug_exists = debug_path.is_file()
    return {
        "target": {
            "path": str(target_path),
            "exists": target_exists,
            "architecture": target_arch(target_path) if target_exists else "",
            "file": command_text(["file", "-Lb", str(target_path)]) if target_exists else "",
            "dynamic_dependencies": dynamic_dependencies(target_path, config.toolchain.readelf) if target_exists else [],
        },
        "debug_companion": {
            "path": str(debug_path),
            "exists": debug_exists,
            "architecture": target_arch(debug_path) if debug_exists else "",
        },
        "build": {
            "architecture": config.architecture,
            "toolchain": config.toolchain.command_details(),
            "compiler": candidate.get("compiler", ""),
            "opt": candidate.get("opt", ""),
            "profile": candidate.get("build_profile", ""),
            "artifact_record": artifact_build_record(candidate),
        },
        "compile_adapter": {
            "script": str(script),
            "script_exists": script.is_file(),
            "spec": str(spec),
            "spec_exists": spec.is_file(),
        },
    }
