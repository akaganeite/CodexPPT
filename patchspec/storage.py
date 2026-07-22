"""Atomic PatchSpec persistence, cache resolution, and dry-run semantics."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Callable

from .core import (
    PatchSpecValidationError,
    assert_valid_patch_spec,
    build_deterministic_skeleton,
    patch_spec_cache_key,
    patch_spec_digest,
    prepare_metadata,
)
from .generator import PatchSpecModelConfig, PatchSpecResult, generate_patch_spec


def patch_spec_cache_path(cache_dir: str | Path, cve_id: str, cache_key: str) -> Path:
    """Return ``<cache>/<CVE>/<key>.json`` without allowing path traversal."""
    safe_cve = re.sub(r"[^A-Za-z0-9_.-]+", "_", cve_id).strip("._")
    if not safe_cve:
        raise ValueError("cve_id cannot produce an empty cache directory name")
    if not re.fullmatch(r"[0-9a-f]{64}", cache_key):
        raise ValueError("cache_key must be a lowercase SHA-256")
    return Path(cache_dir).expanduser() / safe_cve / f"{cache_key}.json"


def write_patch_spec(path: str | Path, spec: dict[str, Any]) -> Path:
    """Validate structurally and atomically write a PatchSpec JSON artifact."""
    assert_valid_patch_spec(spec)
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(spec, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return destination


def load_patch_spec(
    path: str | Path,
    metadata: dict[str, Any] | None = None,
    cve_id: str | None = None,
) -> PatchSpecResult:
    source = Path(path).expanduser()
    try:
        spec = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PatchSpecValidationError([f"cannot load PatchSpec {source}: {exc}"]) from exc
    assert_valid_patch_spec(spec, metadata, cve_id)
    generation = spec["generation"]
    return PatchSpecResult(
        spec=spec,
        digest=patch_spec_digest(spec),
        generation_mode="cache_hit",
        usage={},
        cache_key=generation["cache_key"],
        cache_hit=True,
        path=str(source),
    )


def _expected_cache_key(
    metadata: dict[str, Any], config: PatchSpecModelConfig | None
) -> str:
    if config is None:
        return patch_spec_cache_key(
            metadata,
            model="unconfigured",
            reasoning_effort="unconfigured",
            reasoning=None,
        )
    return patch_spec_cache_key(
        metadata,
        model=config.model,
        reasoning_effort=config.reasoning_effort,
        reasoning=config.reasoning,
    )


def ensure_patch_spec(
    metadata: dict[str, Any],
    *,
    cve_id: str | None = None,
    config: PatchSpecModelConfig | None = None,
    cache_dir: str | Path | None = None,
    output_path: str | Path | None = None,
    dry_run: bool = False,
    client: Callable[..., dict[str, Any]] | None = None,
) -> PatchSpecResult:
    """Resolve a valid current-key spec, generating and persisting only on a miss."""
    prepared = prepare_metadata(metadata, cve_id)
    cache_key = _expected_cache_key(prepared, config)
    candidates: list[Path] = []
    if output_path is not None:
        candidates.append(Path(output_path).expanduser())
    cache_path: Path | None = None
    if cache_dir is not None:
        cache_path = patch_spec_cache_path(cache_dir, prepared["cve_id"], cache_key)
        if cache_path not in candidates:
            candidates.append(cache_path)

    invalid_errors: list[str] = []
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            result = load_patch_spec(candidate, prepared)
            if result.cache_key != cache_key:
                continue
            if output_path is not None and candidate != Path(output_path).expanduser() and not dry_run:
                written = write_patch_spec(output_path, result.spec)
                return PatchSpecResult(
                    spec=result.spec,
                    digest=result.digest,
                    generation_mode="cache_hit",
                    usage={},
                    cache_key=result.cache_key,
                    cache_hit=True,
                    path=str(written),
                )
            return result
        except PatchSpecValidationError as exc:
            invalid_errors.extend(exc.errors)

    if dry_run:
        if invalid_errors:
            raise PatchSpecValidationError(["invalid_cache: " + "; ".join(invalid_errors)])
        spec = build_deterministic_skeleton(
            prepared,
            model=config.model if config else "unconfigured",
            reasoning_effort=config.reasoning_effort if config else "unconfigured",
            reasoning=config.reasoning if config else None,
            mode="deterministic_skeleton",
            cache_key=cache_key,
        )
        return PatchSpecResult(
            spec=spec,
            digest=patch_spec_digest(spec),
            generation_mode="dry_run_skeleton",
            usage={},
            cache_key=cache_key,
            cache_hit=False,
            path=None,
        )

    if config is None:
        raise ValueError("PatchSpec model config is required on a cache miss")
    kwargs: dict[str, Any] = {}
    if client is not None:
        kwargs["client"] = client
    generated = generate_patch_spec(prepared, config=config, **kwargs)
    persisted_path: Path | None = None
    if cache_path is not None:
        persisted_path = write_patch_spec(cache_path, generated.spec)
    if output_path is not None:
        persisted_path = write_patch_spec(output_path, generated.spec)
    return PatchSpecResult(
        spec=generated.spec,
        digest=generated.digest,
        generation_mode=generated.generation_mode,
        usage=generated.usage,
        cache_key=generated.cache_key,
        cache_hit=False,
        path=str(persisted_path) if persisted_path is not None else None,
    )
