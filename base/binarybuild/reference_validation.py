from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from builder.architecture import matches_elf_architecture


@dataclass(frozen=True)
class ReferencePairValidation:
    valid: bool
    missing_vuln: tuple[str, ...] = ()
    missing_patch: tuple[str, ...] = ()
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "missing_vuln": list(self.missing_vuln),
            "missing_patch": list(self.missing_patch),
            "reason": self.reason,
        }


def partition_reference_functions(
    functions: Iterable[str],
    function_details: Iterable[Any],
) -> tuple[list[str], list[str]]:
    change_types: dict[str, set[str]] = {}
    for detail in function_details:
        function = detail["function"]
        change_type = (detail["change_type"] or "").strip().lower()
        change_types.setdefault(function, set()).add(change_type)

    patch_functions: list[str] = []
    vuln_functions: list[str] = []
    removed_types = {"deleted", "removed"}
    for function in functions:
        types = change_types.get(function, set())
        if types and types <= {"added"}:
            patch_functions.append(function)
        elif types and types <= removed_types:
            vuln_functions.append(function)
        else:
            patch_functions.append(function)
            vuln_functions.append(function)
    return vuln_functions, patch_functions


def symbol_names(path: Path, nm: str) -> set[str]:
    names: set[str] = set()
    for command in ([nm, "-A", str(path)], [nm, "-D", "-A", str(path)]):
        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except OSError:
            continue
        if proc.returncode:
            continue
        for line in proc.stdout.splitlines():
            parts = line.rsplit(None, 1)
            if len(parts) != 2:
                continue
            name = parts[1].split("@@", 1)[0].split("@", 1)[0]
            if name:
                names.add(name)
                names.add(name.lstrip("_"))
    return names


def validate_reference_pair(
    vuln_path: Path,
    patch_path: Path,
    *,
    vuln_functions: Iterable[str],
    patch_functions: Iterable[str],
    architecture: str,
    nm: str,
) -> ReferencePairValidation:
    if not vuln_path.exists() or not patch_path.exists():
        return ReferencePairValidation(valid=False, reason="reference file missing")
    if not matches_elf_architecture(vuln_path, architecture) or not matches_elf_architecture(
        patch_path, architecture
    ):
        return ReferencePairValidation(valid=False, reason="reference ELF architecture mismatch")

    required_vuln = list(dict.fromkeys(vuln_functions))
    required_patch = list(dict.fromkeys(patch_functions))
    if not required_vuln and not required_patch:
        return ReferencePairValidation(valid=True)

    vuln_symbols = symbol_names(vuln_path, nm)
    patch_symbols = symbol_names(patch_path, nm)
    missing_vuln = tuple(
        function
        for function in required_vuln
        if function not in vuln_symbols and function.lstrip("_") not in vuln_symbols
    )
    missing_patch = tuple(
        function
        for function in required_patch
        if function not in patch_symbols and function.lstrip("_") not in patch_symbols
    )
    return ReferencePairValidation(
        valid=not missing_vuln and not missing_patch,
        missing_vuln=missing_vuln,
        missing_patch=missing_patch,
        reason="required source functions are missing" if missing_vuln or missing_patch else "",
    )
