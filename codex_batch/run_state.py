from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .io import load_json


def select_cves(testset: dict[str, list[str]], cves: list[str] | None, limit: int | None) -> list[str]:
    selected = sorted(testset)
    if cves:
        wanted = set(cves)
        selected = [cve for cve in selected if cve in wanted]
    if limit is not None:
        selected = selected[:limit]
    return selected


def load_existing_results(output: Path, resume: bool) -> dict[str, Any]:
    if not resume or not output.exists():
        return {}
    existing = load_json(output)
    if not isinstance(existing, dict):
        raise ValueError("--output exists but is not a JSON object")
    return existing


def result_has_status_for_binaries(result: Any, binaries: list[str], status: str) -> bool:
    if not isinstance(result, dict):
        return False
    for binary in binaries:
        row = result.get(binary)
        if isinstance(row, dict) and row.get("status") == status:
            return True
    return False


def result_has_all_binaries(result: Any, binaries: list[str]) -> bool:
    return isinstance(result, dict) and all(binary in result for binary in binaries)


def should_skip(args: Any, merged: dict[str, Any], cve: str, binaries: list[str]) -> bool:
    """Whether a task is already covered by --output and can be skipped.

    Pure read over ``merged``; call it before submitting tasks so the resume
    decision is made while no worker is mutating ``merged``.
    """
    if not getattr(args, "resume", False):
        return False
    if not result_has_all_binaries(merged.get(cve), binaries):
        return False
    if getattr(args, "retry_errors", False) and result_has_status_for_binaries(
        merged[cve], binaries, "error"
    ):
        return False
    return True


def safe_run_id(cve: str, binary: str | None = None) -> str:
    raw = cve if binary is None else f"{cve}__{binary}"
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", raw)
