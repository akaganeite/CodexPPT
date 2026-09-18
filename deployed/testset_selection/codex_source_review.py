"""Codex-backed source classification for viable balanced candidate pools."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

from ..candidate_discovery.metadata import CveMetadata
from ..io_utils import read_json, write_json
from ..system_utils import safe_token


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "source_review_result.schema.json"


def review_source_candidates(
    metadata: CveMetadata,
    candidates: list[dict[str, Any]],
    *,
    output: Path,
    series: str,
    refresh: bool,
    timeout: int,
    log: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    tasks = [candidate_task(item) for item in candidates]
    review_dir, prompt_path, result_path, events_path = review_cache_paths(
        metadata,
        tasks,
        output=output,
        series=series,
    )
    if not refresh:
        cached = load_cached_source_review(
            metadata,
            candidates,
            output=output,
            series=series,
        )
        if cached is not None:
            return cached

    prompt = render_prompt(metadata, tasks)
    review_dir.mkdir(parents=True, exist_ok=True)
    prompt_path.write_text(prompt, encoding="utf-8")
    command = codex_command(prompt, result_path, candidates, metadata)
    if log:
        log(f"codex-source-review start cve={metadata.cve_id} series={series} candidates={len(tasks)}")
    started = time.monotonic()
    returncode = -1
    error = ""
    try:
        with events_path.open("w", encoding="utf-8", errors="replace") as events:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                stdout=events,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                timeout=max(1, timeout),
            )
        returncode = completed.returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        error = str(exc)

    try:
        result = read_json(result_path) if result_path.is_file() else {}
    except (OSError, ValueError):
        result = {}
    if not isinstance(result, dict):
        result = {}
    if returncode != 0 or result.get("status") not in {"ok", "partial"}:
        result = {
            "status": "failed",
            "items": [],
            "notes": error or f"codex exec returned {returncode}",
        }
    result["codex_returncode"] = returncode
    result["codex_seconds"] = round(time.monotonic() - started, 3)
    result["codex_events_path"] = str(events_path)
    write_json(result_path, result)
    if log:
        log(
            f"codex-source-review done cve={metadata.cve_id} series={series} "
            f"status={result['status']} seconds={result['codex_seconds']}"
        )
    return result


def load_cached_source_review(
    metadata: CveMetadata,
    candidates: list[dict[str, Any]],
    *,
    output: Path,
    series: str,
) -> dict[str, Any] | None:
    tasks = [candidate_task(item) for item in candidates]
    review_dir, prompt_path, result_path, _ = review_cache_paths(
        metadata,
        tasks,
        output=output,
        series=series,
    )
    cached = load_cached_result(result_path)
    if cached is not None:
        return cached

    expected_prompt = normalized_cache_prompt(render_prompt(metadata, tasks))
    for legacy_prompt_path in sorted(review_dir.glob("*.prompt.md")):
        try:
            legacy_prompt = legacy_prompt_path.read_text(encoding="utf-8")
        except OSError:
            continue
        if normalized_cache_prompt(legacy_prompt) != expected_prompt:
            continue
        legacy_result_path = legacy_prompt_path.with_name(
            legacy_prompt_path.name.removesuffix(".prompt.md") + ".result.json"
        )
        cached = load_cached_result(legacy_result_path)
        if cached is None:
            continue
        migrated = {**cached, "cache_migrated_from": str(legacy_result_path)}
        review_dir.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(render_prompt(metadata, tasks), encoding="utf-8")
        write_json(result_path, migrated)
        return migrated
    return None


def review_cache_paths(
    metadata: CveMetadata,
    tasks: list[dict[str, Any]],
    *,
    output: Path,
    series: str,
) -> tuple[Path, Path, Path, Path]:
    signature = hashlib.sha256(
        json.dumps(
            {
                "cve_id": metadata.cve_id,
                "functions": metadata.functions,
                "summary": metadata.summary,
                "diff_evidence": metadata.diff_evidence,
                "tasks": tasks,
                "review_version": "codex-source-review-v3",
            },
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
    ).hexdigest()[:20]
    review_dir = output / "state" / "codex_source_review" / safe_token(metadata.cve_id) / safe_token(series)
    return (
        review_dir,
        review_dir / f"{signature}.prompt.md",
        review_dir / f"{signature}.result.json",
        review_dir / f"{signature}.events.jsonl",
    )


def load_cached_result(result_path: Path) -> dict[str, Any] | None:
    if not result_path.is_file():
        return None
    try:
        cached = read_json(result_path)
    except (OSError, ValueError):
        return None
    return cached if isinstance(cached, dict) and cached.get("status") in {"ok", "partial"} else None


def normalized_cache_prompt(prompt: str) -> str:
    return re.sub(
        r'("source_root"\s*:\s*)"[^"]*"',
        r'\1"<source-root>"',
        prompt,
    )


def candidate_task(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidate_id": candidate["candidate_id"],
        "source_version": candidate["source_version"],
        "series": candidate["series"],
        "pocket": candidate["pocket"],
        "temporal_bucket": candidate["side"],
        "source_root": str(candidate["source_materialization"]["extracted_path"]),
    }


def render_prompt(metadata: CveMetadata, tasks: list[dict[str, Any]]) -> str:
    return f"""You are auditing Ubuntu source package versions for CVE affectedness.

Inspect the local source trees and the supplied fix evidence. Classify each candidate independently; temporal_bucket is only a version-ordering hint and is not ground truth.

Rules:
1. patch: the CVE fix or a semantically equivalent fix is present in the relevant function/code path.
2. vuln: the vulnerable logic is present and the fix is absent.
3. inconclusive: relevant code is absent, moved beyond reliable identification, or evidence is insufficient.
4. functions_available is true only when the affected function or a clearly identified semantic successor exists in the candidate source.
5. function_mappings must contain one entry for every affected function. candidate_function must be the exact source-level function or method name usable for symbol/DWARF lookup in this candidate. Use relationship=exact when unchanged, semantic_equivalent when renamed or refactored, and unavailable with an empty candidate_function when no reliable implementation exists.
6. Cite concrete file/function/condition evidence. Do not modify any files.

CVE: {metadata.cve_id}
Summary: {metadata.summary}
Affected functions: {json.dumps(metadata.functions, ensure_ascii=False)}
Function metadata: {json.dumps((metadata.raw.get('function_code') or {{}}), ensure_ascii=False, default=str)}
Fix evidence: {json.dumps(metadata.diff_evidence, ensure_ascii=False, default=str)}
Candidates: {json.dumps(tasks, indent=2, ensure_ascii=False)}

Return one schema-conforming item for every candidate_id.
"""


def codex_command(
    prompt: str,
    result_path: Path,
    candidates: list[dict[str, Any]],
    metadata: CveMetadata,
) -> list[str]:
    command = [
        "codex",
        "--ask-for-approval",
        "never",
        "--sandbox",
        "read-only",
        "exec",
        "--skip-git-repo-check",
        "--ephemeral",
        "-C",
        str(ROOT),
        "--output-schema",
        str(SCHEMA_PATH),
        "-o",
        str(result_path),
        "--json",
    ]
    model = os.environ.get("DEPLOYED_CODEX_MODEL", "").strip()
    if model:
        command.extend(["--model", model])
    add_dirs = {
        Path(str(item["source_materialization"]["extracted_path"])).resolve()
        for item in candidates
        if item.get("source_materialization", {}).get("extracted_path")
    }
    for evidence in metadata.diff_evidence:
        if isinstance(evidence, dict) and evidence.get("file"):
            add_dirs.add(Path(str(evidence["file"])).expanduser().resolve().parent)
    for directory in sorted(add_dirs):
        command.extend(["--add-dir", str(directory)])
    command.append(prompt)
    return command
