from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..candidate_discovery.metadata import CveMetadata
from ..config import ProjectConfig
from ..models import ArtifactResult, PackagePair
from ..naming import deployed_target_binary_name
from ..system_utils import canonical_download_direct, download_file, safe_token
from .elf_utils import (
    elf_matches_architecture,
    find_debug_file,
    is_elf,
    locate_runtime_elves,
    read_build_id,
    unstrip_elf,
    validate_functions,
)


def process_artifacts(
    *,
    project: ProjectConfig,
    pairs: list[PackagePair],
    metadata_by_cve: dict[str, CveMetadata],
    output: Path,
    verify_sha256: bool,
    resume: bool,
    skip_download: bool,
    log=None,
) -> list[ArtifactResult]:
    results: list[ArtifactResult] = []
    paired = [pair for pair in pairs if pair.status == "paired"]
    grouped: dict[tuple[str, str, str, str], list[PackagePair]] = defaultdict(list)
    for pair in paired:
        grouped[pair.artifact_key].append(pair)
    cache: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    total_groups = len(grouped)
    for index, (key, group) in enumerate(grouped.items(), start=1):
        artifact_report = materialize_pair(
            project=project,
            pair=group[0],
            output=output,
            verify_sha256=verify_sha256,
            resume=resume,
            skip_download=skip_download,
        )
        if log:
            log(
                "artifact "
                f"{index}/{total_groups} status={artifact_report.get('status', 'unknown')} "
                f"runtime={group[0].runtime_package} debug={group[0].debug_package} "
                f"version={group[0].source_version}"
            )
        cache[key] = artifact_report
        validation_cache = validate_group_candidates(artifact_report, group, metadata_by_cve)
        for pair in group:
            functions = pair.requested_functions or (
                metadata_by_cve.get(pair.cve_id).functions if metadata_by_cve.get(pair.cve_id) else []
            )
            result = result_for_cve(pair, functions, artifact_report, validation_cache)
            results.append(result)
    for pair in pairs:
        if pair.status == "paired":
            continue
        results.append(
            ArtifactResult(
                cve_id=pair.cve_id,
                label=pair.label,
                source_version=pair.source_version,
                runtime_package=pair.runtime_package,
                runtime_version=pair.runtime_version,
                debug_package=pair.debug_package,
                debug_version=pair.debug_version,
                status=pair.status,
                reason=pair.reason,
                functions=pair.requested_functions or (
                    metadata_by_cve.get(pair.cve_id).functions if metadata_by_cve.get(pair.cve_id) else []
                ),
                report=pair.to_json(),
            )
        )
    return results


def materialize_pair(
    *,
    project: ProjectConfig,
    pair: PackagePair,
    output: Path,
    verify_sha256: bool,
    resume: bool,
    skip_download: bool,
    download_timeout: int = 300,
) -> dict[str, Any]:
    artifact_dir = output / "artifacts" / artifact_dir_name(pair)
    report_path = artifact_dir / "artifact_report.json"
    if resume and report_path.exists():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            selected = report.get("selected_runtime") or {}
            stripped_path = str(selected.get("stripped_path") or "")
            exported_debug_path = str(selected.get("exported_debug_path") or "")
            if (
                report.get("status") == "ok"
                and Path(report.get("unstripped_path", "")).exists()
                and stripped_path
                and Path(stripped_path).exists()
                and exported_debug_path
                and Path(exported_debug_path).exists()
                and report_matches_pair_architecture(report, pair.architecture)
            ):
                return report
        except Exception:
            pass
    if skip_download:
        report = {
            "status": "skipped",
            "reason": "skip-download requested; package URLs were paired but artifacts were not extracted",
            "pair": pair.to_json(),
        }
        write_report(report_path, report)
        return report
    downloads_dir = output / "downloads"
    runtime_deb = downloads_dir / safe_token(pair.runtime_filename.split("/")[-1] or f"{pair.runtime_package}.deb")
    debug_deb = downloads_dir / safe_token(pair.debug_filename.split("/")[-1] or f"{pair.debug_package}.deb")
    download_started = time.monotonic()
    ok, message = download_package_file(
        package_download_urls(pair, debug=False),
        runtime_deb,
        sha256=pair.runtime_sha256,
        verify_sha256=verify_sha256,
        timeout=download_timeout,
    )
    if not ok:
        report = {"status": "url_unreachable", "reason": f"runtime download failed: {message}", "pair": pair.to_json()}
        write_report(report_path, report)
        return report
    remaining_download_time = max(5, int(download_timeout - (time.monotonic() - download_started)))
    ok, message = download_package_file(
        package_download_urls(pair, debug=True),
        debug_deb,
        sha256=pair.debug_sha256,
        verify_sha256=verify_sha256,
        timeout=remaining_download_time,
    )
    if not ok:
        report = {"status": "url_unreachable", "reason": f"debug download failed: {message}", "pair": pair.to_json()}
        write_report(report_path, report)
        return report
    extract_root = extract_root_for_output(output) / artifact_dir_name(pair)
    runtime_root = extract_root / "runtime"
    debug_root = extract_root / "debug"
    if not resume or not runtime_root.exists():
        runtime_root.mkdir(parents=True, exist_ok=True)
        ok, message = extract_deb(runtime_deb, runtime_root)
        if not ok:
            report = {"status": "extract_failed", "reason": f"runtime extract failed: {message}", "pair": pair.to_json()}
            write_report(report_path, report)
            return report
    if not resume or not debug_root.exists():
        debug_root.mkdir(parents=True, exist_ok=True)
        ok, message = extract_deb(debug_deb, debug_root)
        if not ok:
            report = {"status": "extract_failed", "reason": f"debug extract failed: {message}", "pair": pair.to_json()}
            write_report(report_path, report)
            return report
    runtime_elves = locate_runtime_elves(runtime_root, project.elf)
    if not runtime_elves:
        report = {"status": "elf_missing", "reason": "no runtime ELF matched project ELF selection rules", "pair": pair.to_json()}
        write_report(report_path, report)
        return report
    architecture_rejections = []
    if pair.architecture:
        matching_elves = []
        for runtime_elf in runtime_elves:
            matches, machine = elf_matches_architecture(runtime_elf, pair.architecture)
            if matches:
                matching_elves.append(runtime_elf)
            else:
                architecture_rejections.append(
                    {"path": str(runtime_elf), "machine": machine, "expected_architecture": pair.architecture}
                )
        runtime_elves = matching_elves
        if not runtime_elves:
            report = {
                "status": "wrong_architecture",
                "reason": f"no runtime ELF matched requested package architecture {pair.architecture}",
                "pair": pair.to_json(),
                "architecture_rejections": architecture_rejections,
            }
            write_report(report_path, report)
            return report
    candidates: list[dict[str, Any]] = []
    unstripped_dir = artifact_dir / "unstripped"
    stripped_dir = output / "binaries" / "target" / f"{project.project}_stripped"
    exported_debug_dir = output / "binaries" / "target" / f"{project.project}_debug"
    for runtime_elf in runtime_elves:
        relative_runtime = runtime_elf.relative_to(runtime_root).as_posix()
        build_id = read_build_id(runtime_elf)
        debug_file = find_debug_file(debug_root, build_id, relative_runtime)
        debug_machine = ""
        if debug_file and pair.architecture:
            debug_matches, debug_machine = elf_matches_architecture(debug_file, pair.architecture)
            if not debug_matches:
                debug_file = None
        candidate = {
            "runtime_elf": str(runtime_elf),
            "relative_runtime_elf": relative_runtime,
            "build_id": build_id,
            "machine": elf_matches_architecture(runtime_elf, pair.architecture)[1] if pair.architecture else "",
            "debug_machine": debug_machine,
            "debug_file": str(debug_file) if debug_file else "",
            "unstripped_path": "",
            "stripped_path": "",
            "exported_debug_path": "",
            "unstrip_message": "",
            "export_message": "",
        }
        if debug_file:
            binary_name = safe_token(
                f"{project.project}-{pair.source_version}-{pair.runtime_package}-{relative_runtime}",
                "unstripped",
            )
            unstripped_path = unstripped_dir / binary_name
            ok, message = unstrip_elf(runtime_elf, debug_file, unstripped_path)
            candidate["unstrip_message"] = message
            if ok:
                final_name = deployed_target_binary_name(project.project, pair.source_version, runtime_elf.name)
                stripped_path = stripped_dir / final_name
                exported_debug_path = exported_debug_dir / f"{final_name}.debug"
                export_ok, export_message = copy_exported_pair(
                    runtime_elf,
                    stripped_path,
                    debug_file,
                    exported_debug_path,
                    build_id,
                )
                candidate["export_message"] = export_message
                if export_ok:
                    candidate["unstripped_path"] = str(unstripped_path)
                    candidate["stripped_path"] = str(stripped_path.resolve())
                    candidate["exported_debug_path"] = str(exported_debug_path.resolve())
        candidates.append(candidate)
    debug_matched = [item for item in candidates if item["debug_file"]]
    if not debug_matched:
        report = {
            "status": "build_id_mismatch",
            "reason": "no debug file matched any runtime ELF Build-ID",
            "pair": pair.to_json(),
            "runtime_elf_candidates": candidates,
        }
        write_report(report_path, report)
        return report
    unstripped_candidates = [item for item in debug_matched if item["unstripped_path"]]
    if not unstripped_candidates:
        export_collisions = [item for item in debug_matched if item["export_message"]]
        report = {
            "status": "export_name_collision" if export_collisions else "unstrip_failed",
            "reason": (
                "all unstripped runtime ELFs collided with an existing deployed target name"
                if export_collisions
                else "no debug-matched runtime ELF could be unstripped"
            ),
            "pair": pair.to_json(),
            "runtime_elf_candidates": candidates,
        }
        write_report(report_path, report)
        return report
    selected = unstripped_candidates[0]
    report = {
        "status": "ok",
        "reason": "runtime/debug package extracted and Build-ID matched",
        "pair": pair.to_json(),
        "runtime_deb": str(runtime_deb),
        "debug_deb": str(debug_deb),
        "runtime_root": str(runtime_root),
        "debug_root": str(debug_root),
        "runtime_elf_candidates": candidates,
        "architecture_rejections": architecture_rejections,
        "unstripped_candidates": unstripped_candidates,
        "selected_runtime": selected,
        "build_id": selected["build_id"],
        "runtime_elf": selected["runtime_elf"],
        "debug_file": selected["debug_file"],
        "unstripped_path": selected["unstripped_path"],
        "stripped_path": selected["stripped_path"],
        "exported_debug_path": selected["exported_debug_path"],
    }
    write_report(report_path, report)
    return report


def result_for_cve(
    pair: PackagePair,
    functions: list[str],
    artifact_report: dict[str, Any],
    validation_cache: dict[str, tuple[dict[str, Any], dict[str, Any]]] | None = None,
    validation_functions: list[str] | None = None,
) -> ArtifactResult:
    selected, validation = select_candidate_for_functions(
        artifact_report,
        functions,
        validation_cache,
        validation_functions=validation_functions,
    )
    restore_candidate_exports(selected)
    base = ArtifactResult(
        cve_id=pair.cve_id,
        label=pair.label,
        source_version=pair.source_version,
        runtime_package=pair.runtime_package,
        runtime_version=pair.runtime_version,
        debug_package=pair.debug_package,
        debug_version=pair.debug_version,
        status=str(artifact_report.get("status") or "failed"),
        reason=str(artifact_report.get("reason") or ""),
        build_id=str(selected.get("build_id") or artifact_report.get("build_id") or ""),
        runtime_elf=str(selected.get("runtime_elf") or artifact_report.get("runtime_elf") or ""),
        debug_file=str(selected.get("debug_file") or artifact_report.get("debug_file") or ""),
        unstripped_path=str(selected.get("unstripped_path") or artifact_report.get("unstripped_path") or ""),
        stripped_path=str(selected.get("stripped_path") or artifact_report.get("stripped_path") or ""),
        debug_path=str(selected.get("exported_debug_path") or artifact_report.get("exported_debug_path") or ""),
        functions=list(functions),
        report=artifact_report,
    )
    if artifact_report.get("status") != "ok":
        return base
    base.report = {**artifact_report, "selected_for_functions": selected, "function_validation": validation}
    base.found_functions = list(validation.get("found") or [])
    base.missing_functions = list(validation.get("missing") or [])
    base.no_disassembly = list(validation.get("no_disassembly") or [])
    if validation.get("ok"):
        base.status = "ok"
        base.reason = "unstripped ELF contains all requested functions and objdump disassembled them"
    elif validation.get("available"):
        availability = str(validation.get("availability") or "dwarf_available")
        base.status = availability if availability in {"inline_only", "dwarf_range_present", "dwarf_available"} else "dwarf_available"
        base.reason = "unstripped ELF has requested functions only through DWARF evidence, not complete independent nm symbols"
    else:
        base.status = "function_missing"
        if validation.get("dwarf_abstract_only"):
            base.reason = "unstripped ELF has only abstract DWARF declarations for some requested functions and no concrete code range"
        else:
            base.reason = "unstripped ELF did not expose all requested functions through nm symbols or DWARF code ranges"
    return base


def restore_candidate_exports(candidate: dict[str, Any]) -> None:
    for source_key, destination_key in (
        ("runtime_elf", "stripped_path"),
        ("debug_file", "exported_debug_path"),
    ):
        source = Path(str(candidate.get(source_key) or ""))
        destination = Path(str(candidate.get(destination_key) or ""))
        if not source.is_file() or not destination.name or destination.is_file():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def copy_exported_elf(source: Path, destination: Path, build_id: str) -> None:
    """Copy a public artifact without allowing name collisions to overwrite it."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file():
        existing_build_id = read_build_id(destination)
        if existing_build_id == build_id:
            return
        raise ValueError(
            f"deployed target name collision: {destination} already has Build-ID {existing_build_id or 'missing'}, "
            f"expected {build_id or 'missing'} from {source}"
        )
    shutil.copy2(source, destination)


def copy_exported_pair(
    runtime_source: Path,
    runtime_destination: Path,
    debug_source: Path,
    debug_destination: Path,
    build_id: str,
) -> tuple[bool, str]:
    for source, destination in (
        (runtime_source, runtime_destination),
        (debug_source, debug_destination),
    ):
        if not destination.is_file():
            continue
        existing_build_id = read_build_id(destination)
        if existing_build_id != build_id:
            return False, (
                f"deployed target name collision: {destination} already has Build-ID "
                f"{existing_build_id or 'missing'}, expected {build_id or 'missing'} from {source}"
            )
    try:
        copy_exported_elf(runtime_source, runtime_destination, build_id)
        copy_exported_elf(debug_source, debug_destination, build_id)
    except ValueError as exc:
        return False, str(exc)
    return True, "exported runtime/debug pair"


def validate_group_candidates(
    artifact_report: dict[str, Any],
    group: list[PackagePair],
    metadata_by_cve: dict[str, CveMetadata],
) -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    if artifact_report.get("status") != "ok":
        return {}
    functions = sorted(
        {
            function
            for pair in group
            for function in (metadata_by_cve.get(pair.cve_id).functions if metadata_by_cve.get(pair.cve_id) else [])
        }
    )
    if not functions:
        return {}
    out: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for candidate in unstripped_candidates_from_report(artifact_report):
        path = Path(str(candidate.get("unstripped_path") or ""))
        if not path.exists():
            continue
        out[str(candidate.get("unstripped_path") or "")] = (candidate, validate_functions(path, functions))
    return out


def select_candidate_for_functions(
    artifact_report: dict[str, Any],
    functions: list[str],
    validation_cache: dict[str, tuple[dict[str, Any], dict[str, Any]]] | None = None,
    *,
    validation_functions: list[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    function_list = list(dict.fromkeys(functions))
    validation_scope = list(dict.fromkeys([*(validation_functions or []), *function_list]))
    candidates = [
        item
        for item in unstripped_candidates_from_report(artifact_report)
        if isinstance(item, dict) and item.get("unstripped_path")
    ]
    best_candidate = candidates[0] if candidates else {}
    best_validation: dict[str, Any] = {
        "ok": False,
        "available": False,
        "availability": "missing",
        "found": [],
        "missing": list(function_list),
        "no_disassembly": [],
        "symbol_names": {},
        "function_status": {},
    }
    best_score = (-1, -1, -len(functions), -len(functions))
    for candidate in candidates:
        path = Path(str(candidate.get("unstripped_path") or ""))
        if not path.exists():
            continue
        cache_key = str(candidate.get("unstripped_path") or "")
        if validation_cache is not None and cache_key in validation_cache:
            validation = slice_validation(validation_cache[cache_key][1], function_list)
        else:
            full_validation = validate_functions(path, validation_scope)
            if validation_cache is not None:
                validation_cache[cache_key] = (candidate, full_validation)
            validation = slice_validation(full_validation, function_list)
        score = (
            1 if validation.get("ok") else 0,
            1 if validation.get("available") else 0,
            len(validation.get("found") or []),
            -len(validation.get("missing") or []) - len(validation.get("no_disassembly") or []),
        )
        if score > best_score:
            best_candidate = candidate
            best_validation = validation
            best_score = score
        if validation.get("ok"):
            break
    return best_candidate, best_validation


def unstripped_candidates_from_report(artifact_report: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = [
        item
        for item in artifact_report.get("unstripped_candidates", [])
        if isinstance(item, dict) and item.get("unstripped_path")
    ]
    if not candidates and artifact_report.get("unstripped_path"):
        candidates = [
            {
                "runtime_elf": artifact_report.get("runtime_elf", ""),
                "relative_runtime_elf": Path(str(artifact_report.get("runtime_elf", ""))).name,
                "build_id": artifact_report.get("build_id", ""),
                "debug_file": artifact_report.get("debug_file", ""),
                "unstripped_path": artifact_report.get("unstripped_path", ""),
            }
        ]
    return candidates


def slice_validation(validation: dict[str, Any], functions: list[str]) -> dict[str, Any]:
    wanted = set(functions)
    function_status = {
        function: status
        for function, status in dict(validation.get("function_status") or {}).items()
        if function in wanted
    }

    def filtered_list(key: str) -> list[str]:
        return [item for item in list(validation.get(key) or []) if item in wanted]

    symbol_found = filtered_list("symbol_found")
    found = filtered_list("found")
    missing = filtered_list("missing")
    no_disassembly = filtered_list("no_disassembly")
    return {
        "ok": bool(functions) and len(symbol_found) == len(functions) and not no_disassembly,
        "available": bool(functions) and not missing and set(found) == wanted,
        "availability": summarize_validation_availability(function_status),
        "found": found,
        "symbol_found": symbol_found,
        "dwarf_found": filtered_list("dwarf_found"),
        "inline_only": filtered_list("inline_only"),
        "dwarf_range_present": filtered_list("dwarf_range_present"),
        "dwarf_abstract_only": filtered_list("dwarf_abstract_only"),
        "missing": missing,
        "no_disassembly": no_disassembly,
        "symbol_names": {key: value for key, value in dict(validation.get("symbol_names") or {}).items() if key in wanted},
        "function_status": function_status,
    }


def summarize_validation_availability(function_status: dict[str, Any]) -> str:
    statuses = {str(item.get("status") or "") for item in function_status.values() if isinstance(item, dict)}
    if not statuses:
        return "no_functions"
    if statuses == {"symbol_present"}:
        return "symbol_present"
    available = {"symbol_present", "dwarf_range_present", "inline_only"}
    if statuses.issubset(available):
        if statuses.issubset({"symbol_present", "inline_only"}) and "inline_only" in statuses:
            return "inline_only"
        if statuses.issubset({"symbol_present", "dwarf_range_present"}) and "dwarf_range_present" in statuses:
            return "dwarf_range_present"
        return "dwarf_available"
    if "dwarf_abstract_only" in statuses:
        return "dwarf_abstract_only"
    return "missing"


def artifact_dir_name(pair: PackagePair) -> str:
    architecture = pair.architecture.strip()
    architecture_part = f"-{architecture}" if architecture else ""
    return safe_token(
        f"{pair.series}-{pair.pocket}-{pair.source_version}{architecture_part}-"
        f"{pair.runtime_package}-{pair.runtime_version}",
        "artifact",
    )


def extract_root_for_output(output: Path) -> Path:
    configured = os.environ.get("DEPLOYED_EXTRACT_ROOT", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    token = safe_token(str(output.resolve()), "output")
    return Path.home() / ".cache" / "agentic_dataset_deployed_extract" / token


def package_download_urls(pair: PackagePair, *, debug: bool) -> list[str]:
    filename = (pair.debug_filename if debug else pair.runtime_filename).split("/")[-1]
    original_url = pair.debug_url if debug else pair.runtime_url
    component = pair.component.strip().lower()
    source_package = pair.source_package.strip().lower()
    if not filename or component not in {"main", "universe", "restricted", "multiverse"} or not source_package:
        return [original_url] if original_url else []
    prefix = source_package[:4] if source_package.startswith("lib") and len(source_package) >= 4 else source_package[:1]
    pool_path = f"pool/{component}/{prefix}/{source_package}/{filename}"
    if debug and filename.endswith(".ddeb"):
        mirrors = [f"https://ddebs.ubuntu.com/{pool_path}"]
    else:
        mirrors = [
            f"https://archive.ubuntu.com/ubuntu/{pool_path}",
            f"https://security.ubuntu.com/ubuntu/{pool_path}",
        ]
    snapshot_id = ubuntu_snapshot_id(pair.publication_date)
    snapshots = (
        [f"https://snapshot.ubuntu.com/ubuntu/{snapshot_id}/{pool_path}"]
        if snapshot_id and filename.endswith((".deb", ".ddeb"))
        else []
    )
    return list(dict.fromkeys([*mirrors, *snapshots, original_url]))


def ubuntu_snapshot_id(publication_date: str) -> str:
    value = publication_date.strip()
    if not value:
        return ""
    try:
        published = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if published.tzinfo is None:
        published = published.replace(tzinfo=timezone.utc)
    # Source publications can precede their binary publications by a few
    # hours. The following UTC day is a stable point where the pool object is
    # present while still preceding ordinary supersession windows.
    snapshot = published.astimezone(timezone.utc) + timedelta(days=1)
    return snapshot.strftime("%Y%m%dT%H%M%SZ")


def report_matches_pair_architecture(report: dict[str, Any], architecture: str) -> bool:
    if not architecture:
        return True
    selected = report.get("selected_runtime") or {}
    runtime_path = Path(str(selected.get("runtime_elf") or report.get("runtime_elf") or ""))
    debug_path = Path(str(selected.get("debug_file") or report.get("debug_file") or ""))
    if not runtime_path.is_file() or not debug_path.is_file():
        return False
    runtime_ok, _ = elf_matches_architecture(runtime_path, architecture)
    debug_ok, _ = elf_matches_architecture(debug_path, architecture)
    return runtime_ok and debug_ok


def download_package_file(
    urls: list[str],
    destination: Path,
    *,
    sha256: str,
    verify_sha256: bool,
    timeout: int,
) -> tuple[bool, str]:
    errors: list[str] = []
    available_urls = [url for url in urls if url]
    for index, url in enumerate(available_urls):
        is_original_url = index == len(available_urls) - 1
        is_snapshot_url = urllib.parse.urlsplit(url).hostname == "snapshot.ubuntu.com"
        ok, message = download_file(
            url,
            destination,
            sha256=sha256,
            verify_sha256=verify_sha256,
            timeout=timeout if is_original_url or is_snapshot_url else min(timeout, 20),
            attempts=2 if is_original_url or is_snapshot_url else 1,
            validator=validate_deb_archive,
            bypass_proxy=canonical_download_direct(url),
        )
        if ok:
            return True, message
        errors.append(f"{url}: {message}")
    return False, "; ".join(errors) or "no package download URL"


def validate_deb_archive(path: Path) -> tuple[bool, str]:
    try:
        stat = path.stat()
    except OSError as exc:
        return False, str(exc)
    return _validate_deb_archive_cached(str(path.resolve()), stat.st_size, stat.st_mtime_ns)


@lru_cache(maxsize=512)
def _validate_deb_archive_cached(path: str, size: int, mtime_ns: int) -> tuple[bool, str]:
    del size, mtime_ns
    try:
        proc = subprocess.run(
            ["dpkg-deb", "--fsys-tarfile", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Debian archive validation failed: {exc}"
    if proc.returncode:
        return False, (proc.stderr or "invalid Debian package archive").strip()
    return True, "valid Debian package archive"


def extract_deb(path: Path, dest: Path) -> tuple[bool, str]:
    if any(dest.iterdir()):
        return True, "reused existing extraction"
    proc = subprocess.run(["dpkg-deb", "-x", str(path), str(dest)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if proc.returncode:
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True, exist_ok=True)
        return False, (proc.stderr or proc.stdout).strip()
    return True, "extracted"


def write_report(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
