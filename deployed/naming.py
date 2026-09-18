"""Stable target-artifact names for Ubuntu deployed datasets."""

from __future__ import annotations

from pathlib import Path

from .system_utils import safe_token


DEPLOYED_SUFFIX = "-deployed"


def deployed_target_binary_name(project: str, source_version: str, binary_name: str | Path) -> str:
    """Return the physical target filename for one deployed ELF."""

    binary = Path(str(binary_name)).name
    return safe_token(f"{project}-{source_version}-{binary}{DEPLOYED_SUFFIX}", "binary")


def deployed_export_name(value: str | Path) -> str:
    """Return the base-compatible logical name stored in testset exports."""

    return Path(str(value)).name.removesuffix(DEPLOYED_SUFFIX)
