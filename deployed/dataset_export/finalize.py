"""Finalize a deployed run into a compact, base-shaped dataset root."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from ..candidate_discovery.metadata import resolve_metadata_path
from ..io_utils import read_json, write_json
from ..naming import deployed_export_name, deployed_target_binary_name
from ..testset_selection.ubuntu_publication_artifacts import normalize_arch, source_workspace_base


TRACE_EXPORTS = (
    "artifacts.json",
    "build_report.json",
    "dwarf_candidates.json",
    "excluded_cves.json",
    "function_missing.json",
    "groundtruth_1v1.json",
    "testset_1v1.json",
    "testset_detailed.json",
)


def deployed_variant(arch: str) -> str:
    return f"ubuntu-{normalize_arch(arch)}"


def final_testset_path(output: Path, arch: str) -> Path:
    return output / "exports" / f"testset.{deployed_variant(arch)}.json"


def final_groundtruth_path(output: Path, arch: str) -> Path:
    return output / "exports" / f"groundtruth.{deployed_variant(arch)}.json"


def rebase_finalized_output(output: Path) -> dict[str, str]:
    """Rewrite retained absolute paths after a finalized dataset is moved."""

    root = output.expanduser().resolve()
    manifest_path = root / "deployed" / "manifest.json"
    if not manifest_path.is_file():
        return {}
    try:
        manifest = read_json(manifest_path)
    except (OSError, ValueError):
        return {}
    if not isinstance(manifest, dict) or manifest.get("schema") != "ubuntu-deployed-final-layout-v1":
        return {}

    testset_text = str(manifest.get("testset") or "")
    testset = Path(testset_text).expanduser() if testset_text else Path()
    if not testset.name or testset.parent.name != "exports":
        return {}
    previous_root = testset.parent.parent
    if previous_root == root:
        return {}
    if not (root / "exports" / testset.name).is_file():
        return {}

    replacements = {str(previous_root): str(root)}
    rewrite_json_paths(root, replacements)
    write_json(manifest_path, replace_paths(manifest, replacements))
    return replacements


def finalize_run_output(
    output: Path,
    *,
    project: str,
    arch: str,
    metadata: Path,
) -> dict[str, Any]:
    """Move a verified run's public files to the base-shaped final layout.

    The function accepts both the current legacy ``<output>/dataset`` layout and
    the in-progress layout used by new ``run`` invocations. It intentionally
    does not delete work caches; callers must do that only after validation.
    """

    root = output.expanduser().resolve()
    legacy = root / "dataset"
    path_replacements = {
        str(legacy.resolve()): str(root),
        str((root / "input").resolve()): str((root / "deployed" / "input").resolve()),
        str((root / "selection").resolve()): str((root / "deployed" / "selection").resolve()),
        str((root / "state").resolve()): str((root / "deployed" / "state").resolve()),
    }
    adopt_legacy_dataset(root)
    exports = root / "exports"
    auxiliary = root / "deployed"
    trace = auxiliary / "trace"
    audit = auxiliary / "audit"
    variant = deployed_variant(arch)
    testset_path = exports / f"testset.{variant}.json"
    groundtruth_path = exports / f"groundtruth.{variant}.json"

    move_export(exports / "testset.json", testset_path)
    move_export(exports / "groundtruth.json", groundtruth_path)
    for name in TRACE_EXPORTS:
        move_path(exports / name, trace / name, replace=True)
    move_path(exports / "package_rankings", trace / "package_rankings", replace=True)
    move_project_trace_exports(exports, trace, project)

    move_path(root / "state", auxiliary / "state", replace=True)
    move_path(root / "build.log", auxiliary / "logs" / "build.log", replace=True)
    move_path(root / "input", auxiliary / "input")
    move_path(root / "selection", auxiliary / "selection")
    move_path(root / "validation.json", audit / "legacy_validation.json", replace=True)
    copy_base_exports(root, project=project, metadata=metadata)
    rewrite_json_paths(root, path_replacements)
    normalize_exported_binary_names(root, project)

    manifest = {
        "schema": "ubuntu-deployed-final-layout-v1",
        "project": project,
        "variant": variant,
        "testset": str(testset_path),
        "groundtruth": str(groundtruth_path),
        "metadata": str(exports / f"{project}_metadata.json"),
        "reference": str(exports / f"{project}_reference.json"),
        "trace": str(trace),
        "audit": str(audit),
        "cache_paths": [
            str(auxiliary / "selection" / "sources"),
            str(root / "artifacts"),
            str(root / "downloads"),
        ],
    }
    write_json(auxiliary / "manifest.json", manifest)
    return manifest


def cleanup_work_caches(output: Path) -> list[str]:
    root = output.expanduser().resolve()
    source_cache = root / "deployed" / "selection" / "sources"
    local_workspaces = local_source_workspaces(source_cache)
    targets = (
        source_cache,
        root / "artifacts",
        root / "downloads",
    )
    removed = []
    for path in targets:
        if path.exists():
            shutil.rmtree(path)
            removed.append(str(path))
    for path in local_workspaces:
        if path.exists():
            shutil.rmtree(path)
            removed.append(str(path))
        prune_empty_parents(path.parent, stop=source_workspace_base())
    return removed


def local_source_workspaces(source_cache: Path) -> list[Path]:
    if not source_cache.is_dir():
        return []
    base = source_workspace_base()
    paths = []
    for report_path in source_cache.rglob("source_materialization.json"):
        try:
            report = read_json(report_path)
        except (OSError, ValueError):
            continue
        if report.get("extraction_storage") != "local_symlink_workspace":
            continue
        extracted_path = Path(str(report.get("extracted_path") or "")).expanduser().resolve()
        workspace = extracted_path.parent
        if workspace != base and workspace.is_relative_to(base):
            paths.append(workspace)
    return sorted(set(paths))


def prune_empty_parents(path: Path, *, stop: Path) -> None:
    stop = stop.resolve()
    current = path.resolve()
    while current != stop and current.is_relative_to(stop):
        try:
            current.rmdir()
        except OSError:
            break
        current = current.parent


def adopt_legacy_dataset(root: Path) -> None:
    legacy = root / "dataset"
    if not legacy.is_dir():
        return
    for name in ("artifacts", "binaries", "downloads", "exports", "state", "build.log"):
        move_path(legacy / name, root / name)
    try:
        legacy.rmdir()
    except OSError:
        pass


def move_project_trace_exports(exports: Path, trace: Path, project: str) -> None:
    for suffix in (
        "_ubuntu_trace.json",
        "_ubuntu_trace.csv",
        "_deb_ddeb_links.json",
        "_deb_ddeb_links.csv",
    ):
        move_path(exports / f"{project}{suffix}", trace / f"{project}{suffix}", replace=True)


def copy_base_exports(root: Path, *, project: str, metadata: Path) -> None:
    source_metadata = resolve_metadata_path(metadata, project)
    base_root = source_metadata.parent.parent if source_metadata.parent.name in {"export", "exports"} else source_metadata.parent
    source_reference = next(
        (
            candidate
            for candidate in (
                base_root / "exports" / f"{project}_reference.json",
                base_root / "export" / f"{project}_reference.json",
            )
            if candidate.is_file()
        ),
        None,
    )
    destination = root / "exports"
    copy_export(source_metadata, destination / f"{project}_metadata.json")
    if source_reference:
        copy_export(source_reference, destination / f"{project}_reference.json")


def copy_export(source: Path, destination: Path) -> None:
    if destination.exists() and source.resolve() == destination.resolve():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def move_export(source: Path, destination: Path) -> None:
    if source.exists():
        move_path(source, destination, replace=True)
    elif not destination.exists():
        raise FileNotFoundError(f"required final export is missing: {source}")


def move_path(source: Path, destination: Path, *, replace: bool = False) -> None:
    if not source.exists():
        return
    if source.resolve() == destination.resolve():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if replace and source.is_file() and destination.is_file():
            destination.unlink()
        elif source.is_dir() and destination.is_dir():
            for child in source.iterdir():
                move_path(child, destination / child.name, replace=replace)
            source.rmdir()
            return
        else:
            raise FileExistsError(f"cannot move {source} to existing {destination}")
    shutil.move(str(source), str(destination))


def rewrite_json_paths(root: Path, replacements: dict[str, str]) -> None:
    retained_roots = (
        root / "exports",
        root / "deployed" / "input",
        root / "deployed" / "selection" / "exports",
        root / "deployed" / "state",
        root / "deployed" / "trace",
    )
    for directory in retained_roots:
        if not directory.is_dir():
            continue
        for path in directory.rglob("*.json"):
            try:
                payload = read_json(path)
            except (OSError, ValueError):
                continue
            rewritten = replace_paths(payload, replacements)
            if rewritten != payload:
                write_json(path, rewritten)


def normalize_exported_binary_names(root: Path, project: str) -> None:
    """Migrate old verbose artifact names and align JSON logical names.

    A pre-final-layout run used Ubuntu series, package, and installation path in
    its public filename.  The final layout follows the base convention: the
    physical file has a build-variant suffix and JSON keeps the suffix-free
    logical name.
    """

    artifact_path = existing_json_path(root / "deployed" / "trace" / "artifacts.json", root / "exports" / "artifacts.json")
    if artifact_path is None:
        return
    try:
        artifacts = read_json(artifact_path)
    except (OSError, ValueError):
        return
    if not isinstance(artifacts, list):
        return

    path_replacements: dict[str, str] = {}
    name_replacements: dict[str, str] = {}
    target_claims: dict[str, list[tuple[str, str]]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        source = Path(str(artifact.get("stripped_path") or ""))
        runtime_elf = str(artifact.get("runtime_elf") or "")
        source_version = str(artifact.get("source_version") or "")
        if not source.name or not runtime_elf or not source_version:
            continue
        target = source.with_name(deployed_target_binary_name(project, source_version, runtime_elf))
        debug_source = Path(str(artifact.get("debug_path") or ""))
        debug_target = debug_source.with_name(f"{target.name}.debug") if debug_source.name else Path()
        build_id = str(artifact.get("build_id") or "")
        target_claims.setdefault(str(target), []).append((str(source), build_id))
        if debug_source.name:
            target_claims.setdefault(str(debug_target), []).append((str(debug_source), build_id))
        path_replacements[str(source)] = str(target)
        if debug_source.name:
            path_replacements[str(debug_source)] = str(debug_target)
        name_replacements[source.name] = deployed_export_name(target.name)

    validate_target_claims(target_claims)
    rename_files(path_replacements)
    rewrite_json_paths(root, path_replacements)
    rewrite_json_names(root, name_replacements)


def existing_json_path(*candidates: Path) -> Path | None:
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def validate_target_claims(claims: dict[str, list[tuple[str, str]]]) -> None:
    for target, rows in claims.items():
        sources = {source for source, _ in rows}
        build_ids = {build_id for _, build_id in rows if build_id}
        if len(sources) > 1 and (not build_ids or len(build_ids) > 1):
            raise ValueError(f"multiple incompatible deployed artifacts map to {target}")


def rename_files(replacements: dict[str, str]) -> None:
    for source_text, target_text in sorted(replacements.items()):
        source = Path(source_text)
        target = Path(target_text)
        if source == target or not source.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            source.unlink()
        else:
            source.rename(target)


def rewrite_json_names(root: Path, replacements: dict[str, str]) -> None:
    if not replacements:
        return
    for path in retained_json_paths(root):
        try:
            payload = read_json(path)
        except (OSError, ValueError):
            continue
        rewritten = replace_exact_strings(payload, replacements)
        if rewritten != payload:
            write_json(path, rewritten)


def retained_json_paths(root: Path):
    retained_roots = (
        root / "exports",
        root / "deployed" / "input",
        root / "deployed" / "selection" / "exports",
        root / "deployed" / "state",
        root / "deployed" / "trace",
    )
    for directory in retained_roots:
        if directory.is_dir():
            yield from directory.rglob("*.json")


def replace_exact_strings(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, dict):
        return {key: replace_exact_strings(item, replacements) for key, item in value.items()}
    if isinstance(value, list):
        return [replace_exact_strings(item, replacements) for item in value]
    if isinstance(value, str):
        return replacements.get(value, value)
    return value


def replace_paths(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, dict):
        return {key: replace_paths(item, replacements) for key, item in value.items()}
    if isinstance(value, list):
        return [replace_paths(item, replacements) for item in value]
    if not isinstance(value, str):
        return value
    for source, destination in replacements.items():
        if value == source or value.startswith(f"{source}/"):
            return f"{destination}{value[len(source):]}"
    return value
