from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Any

from .providers import resolve_profile, resolved_reasoning_effort


CODEX_CONFIG_PATH = Path.home() / ".codex" / "config.toml"


def create_batch_manifest(
    args: argparse.Namespace,
    paths: dict[str, Path | None],
    script_dir: Path,
    metadata: dict[str, Any],
    raw_tasks: list[tuple[str, list[str], str]],
    pending_tasks: list[tuple[str, list[str], str]],
    merged: dict[str, Any],
) -> dict[str, Any]:
    """Describe a Codex batch without persisting secrets or prompt contents."""
    driver = script_dir / "codex_patch_presence_batch.py"
    return {
        "argv": [str(driver), *sys.argv[1:]],
        "completed_cases": completed_task_count(merged, raw_tasks),
        "compiler": args.compiler,
        "debug_dir": str(args.debug_dir) if args.debug_dir is not None else None,
        "driver": str(driver),
        "eval_groundtruth_json": path_text(paths["groundtruth_json"]),
        "jobs": max(1, args.jobs),
        "metadata_json": path_text(paths["project_json"]),
        "metadata_mode": args.metadata,
        "model_config": describe_model_config(args),
        "opt": args.opt,
        "output_json": path_text(paths["output"]),
        "pid": os.getpid(),
        "project": infer_project_name(args, paths["project_json"], metadata),
        "prompt_template": str(args.prompt_template),
        "static_only": True,
        "sandbox": args.sandbox,
        "static_only_policy": str(script_dir / "prompts" / "static_only_policy.md"),
        "anonymous_targets": True,
        "run_dir": path_text(paths["raw_dir"]),
        "source_json": path_text(paths["testset_json"]),
        "source_kind": "testset",
        "started_at_epoch": time.time(),
        "status": "running",
        "target_dir": path_text(paths["target_dir"]),
        "tool_name": "codex",
        "total_cases": len(raw_tasks),
        "pending_cases": len(pending_tasks),
    }


def finalize_batch_manifest(
    manifest: dict[str, Any],
    merged: dict[str, Any],
    raw_tasks: list[tuple[str, list[str], str]],
    status: str,
    error: str | None = None,
) -> None:
    manifest["completed_cases"] = completed_task_count(merged, raw_tasks)
    manifest["finished_at_epoch"] = time.time()
    manifest["status"] = status
    if error:
        manifest["error"] = error


def completed_task_count(merged: dict[str, Any], raw_tasks: list[tuple[str, list[str], str]]) -> int:
    count = 0
    for cve, binaries, _run_id in raw_tasks:
        result = merged.get(cve)
        if isinstance(result, dict) and all(binary in result for binary in binaries):
            count += 1
    return count


def infer_project_name(args: argparse.Namespace, project_json: Path | None, metadata: dict[str, Any]) -> str:
    if args.project:
        return args.project
    for entry in metadata.values():
        if isinstance(entry, dict) and isinstance(entry.get("project"), str) and entry["project"]:
            return entry["project"]
    if project_json is None:
        return "unknown"
    stem = project_json.stem
    for suffix in ("_behavior", "_metadata", "_project_source_analysis"):
        if stem.endswith(suffix):
            return stem[: -len(suffix)]
    return stem


def describe_model_config(args: argparse.Namespace) -> dict[str, Any]:
    profile = resolve_profile(args)
    reasoning_effort = resolved_reasoning_effort(args, profile)
    if profile.uses_current_codex_provider:
        codex_config = read_codex_config()
        profile_model = profile.model
        return {
            "profile": profile.name,
            "provider": codex_config.get("model_provider"),
            "model": profile_model or codex_config.get("model"),
            "model_source": "model_config.json" if profile_model else str(CODEX_CONFIG_PATH),
            "reasoning_effort": reasoning_effort or codex_config.get("model_reasoning_effort"),
            "source": str(CODEX_CONFIG_PATH),
            "wire_api": codex_config.get("wire_api"),
            "base_url": codex_config.get("base_url"),
        }
    return {
        "profile": profile.name,
        "provider": profile.provider,
        "model": profile.model,
        "reasoning_effort": reasoning_effort,
        "source": "model_config.json",
        "wire_api": profile.wire_api,
        "base_url": profile.base_url,
    }


def read_codex_config() -> dict[str, str | None]:
    if not CODEX_CONFIG_PATH.is_file():
        return {}
    raw = load_toml(CODEX_CONFIG_PATH)
    provider_name = string_value(raw.get("model_provider"))
    provider_config = raw.get("model_providers", {})
    if not isinstance(provider_config, dict) or not provider_name:
        provider_config = {}
    selected = provider_config.get(provider_name, {})
    if not isinstance(selected, dict):
        selected = {}
    return {
        "model_provider": provider_name,
        "model": string_value(raw.get("model")),
        "model_reasoning_effort": string_value(raw.get("model_reasoning_effort")),
        "base_url": string_value(selected.get("base_url")),
        "wire_api": string_value(selected.get("wire_api")),
    }


def load_toml(path: Path) -> dict[str, Any]:
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            return parse_basic_toml(path)
    with path.open("rb") as handle:
        loaded = tomllib.load(handle)
    return loaded if isinstance(loaded, dict) else {}


def parse_basic_toml(path: Path) -> dict[str, Any]:
    """Fallback for machines lacking tomllib/tomli; handles current simple keys."""
    result: dict[str, Any] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("[") or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if value.startswith('"') and value.endswith('"'):
            result[key] = value[1:-1]
    return result


def string_value(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def path_text(path: Path | None) -> str | None:
    return str(path) if path is not None else None
