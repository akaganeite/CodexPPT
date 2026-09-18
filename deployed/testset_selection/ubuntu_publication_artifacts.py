from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..candidate_discovery.launchpad import launchpad_get
from ..candidate_discovery.source_history import SourcePublication
from ..io_utils import write_json
from ..system_utils import canonical_download_direct, download_file, run_command, safe_token


AUXILIARY_PACKAGE_RE = re.compile(r"(?:-dev|-doc|-docs|-common|-examples?|-tests?|-udeb)$")
ARTIFACT_CACHE_LOCK = threading.RLock()


def normalize_arch(value: str) -> str:
    normalized = value.strip().lower()
    return {
        "x86": "amd64",
        "x86_64": "amd64",
        "x64": "amd64",
        "x86-64": "amd64",
        "x86_32": "i386",
        "x86-32": "i386",
    }.get(normalized, normalized or "amd64")


def publication_binary_availability(
    publication: SourcePublication,
    *,
    arch: str,
    cache_dir: Path,
    refresh: bool,
) -> dict[str, Any]:
    with ARTIFACT_CACHE_LOCK:
        return _publication_binary_availability(
            publication,
            arch=arch,
            cache_dir=cache_dir,
            refresh=refresh,
        )


def _publication_binary_availability(
    publication: SourcePublication,
    *,
    arch: str,
    cache_dir: Path,
    refresh: bool,
) -> dict[str, Any]:
    effective_arch = normalize_arch(arch)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / f"{publication_id(publication)}-{effective_arch}.json"
    if cache_path.exists() and not refresh:
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        if cached.get("pairing_policy") == "runtime-debug-fallback-v2":
            return cached
        if "runtime_files" in cached and "debug_files" in cached:
            pairs = pair_runtime_debug_files(cached.get("runtime_files") or [], cached.get("debug_files") or [])
            cached.update(
                {
                    "pairing_policy": "runtime-debug-fallback-v2",
                    "ready": bool(pairs),
                    "runtime_debug_pairs": pairs,
                    "reason": "runtime/debug package pair available" if pairs else "no matching runtime/debug package pair",
                }
            )
            write_json(cache_path, cached)
            return cached
    raw_items = launchpad_get(publication.self_link, {"ws.op": "binaryFileUrls", "include_meta": "true"})
    files = []
    for raw_item in raw_items:
        item = raw_item if isinstance(raw_item, dict) else {"url": str(raw_item)}
        parsed = parse_binary_file(str(item.get("url") or ""))
        if not parsed or parsed["arch"] not in {effective_arch, "all"}:
            continue
        parsed.update({key: value for key, value in item.items() if key != "url"})
        files.append(parsed)
    runtime_files = [
        item
        for item in files
        if item["kind"] == "runtime" and not AUXILIARY_PACKAGE_RE.search(item["package"])
    ]
    debug_files = [item for item in files if item["kind"] == "debug"]
    pairs = pair_runtime_debug_files(runtime_files, debug_files)
    result = {
        "checked": True,
        "requested_arch": arch,
        "arch": effective_arch,
        "ready": bool(pairs),
        "runtime_files": runtime_files,
        "debug_files": debug_files,
        "runtime_debug_pairs": pairs,
        "pairing_policy": "runtime-debug-fallback-v2",
        "reason": "runtime/debug package pair available" if pairs else "no matching runtime/debug package pair",
    }
    write_json(cache_path, result)
    return result


def pair_runtime_debug_files(
    runtime_files: list[dict[str, Any]],
    debug_files: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    pairs = []
    for runtime in runtime_files:
        exact = [
            debug
            for debug in debug_files
            if re.sub(r"-(?:dbgsym|dbg)$", "", debug["package"]) == runtime["package"]
        ]
        if exact:
            pairs.extend({"runtime": runtime, "debug": debug, "match": "exact_package_name"} for debug in exact)
            continue
        # Older Ubuntu publications sometimes expose one source-wide -dbg
        # package instead of one dbgsym package per runtime binary. Keep a
        # small closed fallback set and let Build-ID matching decide.
        fallback = sorted(debug_files, key=lambda item: debug_fallback_key(runtime["package"], item["package"]))[:4]
        pairs.extend({"runtime": runtime, "debug": debug, "match": "source_debug_fallback"} for debug in fallback)
    return sorted(pairs, key=lambda item: (item["runtime"]["package"], item["debug"]["package"]))


def debug_fallback_key(runtime_package: str, debug_package: str) -> tuple[int, int, str]:
    debug_base = re.sub(r"-(?:dbgsym|dbg)$", "", debug_package)
    common_prefix = 0
    for index, (left, right) in enumerate(zip(runtime_package, debug_base)):
        if left != right:
            common_prefix = index
            break
    else:
        common_prefix = min(len(runtime_package), len(debug_base))
    source_wide = 0 if debug_base in runtime_package or runtime_package in debug_base else 1
    return source_wide, -common_prefix, debug_package


def parse_binary_file(url: str) -> dict[str, str] | None:
    filename = Path(urllib.parse.unquote(urllib.parse.urlsplit(url).path)).name
    suffix = ".ddeb" if filename.endswith(".ddeb") else ".deb" if filename.endswith(".deb") else ""
    if not suffix:
        return None
    fields = filename[: -len(suffix)].rsplit("_", 2)
    if len(fields) != 3:
        return None
    package, version, arch = fields
    kind = "debug" if suffix == ".ddeb" or package.endswith(("-dbgsym", "-dbg")) else "runtime"
    return {
        "package": package,
        "version": version,
        "arch": arch,
        "kind": kind,
        "filename": filename,
        "url": url,
    }


def materialize_source_publication(
    publication: SourcePublication,
    *,
    cache_dir: Path,
    refresh: bool,
    download_timeout: int = 90,
    total_timeout: int = 0,
) -> dict[str, Any]:
    with ARTIFACT_CACHE_LOCK:
        return _materialize_source_publication(
            publication,
            cache_dir=cache_dir,
            refresh=refresh,
            download_timeout=download_timeout,
            total_timeout=total_timeout,
        )


def _materialize_source_publication(
    publication: SourcePublication,
    *,
    cache_dir: Path,
    refresh: bool,
    download_timeout: int = 90,
    total_timeout: int = 0,
) -> dict[str, Any]:
    version_dir = cache_dir / safe_token(publication.source_package) / safe_token(publication.source_version)
    report_path = version_dir / "source_materialization.json"
    if report_path.exists() and not refresh:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        extracted_path = Path(str(report.get("extracted_path") or ""))
        if report.get("status") == "ok" and extracted_path.is_dir():
            return report
    version_dir.mkdir(parents=True, exist_ok=True)
    source_files_dir = version_dir / "source-files"
    source_files_dir.mkdir(parents=True, exist_ok=True)
    try:
        urls = launchpad_get(publication.self_link, {"ws.op": "sourceFileUrls"})
    except Exception as exc:
        report = source_failure(publication, f"sourceFileUrls failed: {exc}")
        write_json(report_path, report)
        return report
    started = time.monotonic()
    downloaded, errors = download_source_files(
        urls,
        publication=publication,
        source_files_dir=source_files_dir,
        cache_dir=cache_dir,
        source_package=publication.source_package,
        download_timeout=download_timeout,
        total_timeout=total_timeout,
        started=started,
        allow_cache=not refresh,
    )
    dsc_files = sorted(source_files_dir.glob("*.dsc"))
    if errors or len(dsc_files) != 1:
        report = {
            **source_failure(publication, "source package download incomplete or .dsc missing"),
            "downloaded": downloaded,
            "errors": errors,
        }
        write_json(report_path, report)
        return report
    extracted_path, use_local_workspace = source_extracted_path(publication, cache_dir)
    if extracted_path.exists():
        shutil.rmtree(extracted_path)
    extracted_path.parent.mkdir(parents=True, exist_ok=True)
    if not extracted_path.exists():
        proc = run_command(["dpkg-source", "-x", str(dsc_files[0]), str(extracted_path)], timeout=600)
        if proc.returncode != 0:
            shutil.rmtree(extracted_path, ignore_errors=True)
            repaired, repair_errors = download_source_files(
                urls,
                publication=publication,
                source_files_dir=source_files_dir,
                cache_dir=cache_dir,
                source_package=publication.source_package,
                download_timeout=download_timeout,
                total_timeout=total_timeout,
                started=started,
                allow_cache=False,
            )
            downloaded.extend(repaired)
            dsc_files = sorted(source_files_dir.glob("*.dsc"))
            if not repair_errors and len(dsc_files) == 1:
                proc = run_command(["dpkg-source", "-x", str(dsc_files[0]), str(extracted_path)], timeout=600)
            if repair_errors or len(dsc_files) != 1 or proc.returncode != 0:
                report = {
                    **source_failure(publication, "dpkg-source extraction failed after fresh download"),
                    "downloaded": downloaded,
                    "errors": repair_errors,
                    "stdout": proc.stdout[-4000:],
                    "stderr": proc.stderr[-4000:],
                }
                write_json(report_path, report)
                return report
    report = {
        "status": "ok",
        "source_package": publication.source_package,
        "source_version": publication.source_version,
        "series": publication.series,
        "source_publication": publication.to_json(),
        "source_urls": [str(url) for url in urls],
        "downloaded": downloaded,
        "extracted_path": str(extracted_path.resolve()),
        "extraction_storage": "local_symlink_workspace" if use_local_workspace else "output_cache",
    }
    write_json(report_path, report)
    return report


def download_source_files(
    urls: list[Any],
    *,
    publication: SourcePublication,
    source_files_dir: Path,
    cache_dir: Path,
    source_package: str,
    download_timeout: int,
    total_timeout: int,
    started: float,
    allow_cache: bool,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    downloaded: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []
    for raw_url in urls:
        url = str(raw_url)
        filename = Path(urllib.parse.unquote(urllib.parse.urlsplit(url).path)).name
        if not filename:
            continue
        remaining = int(total_timeout - (time.monotonic() - started)) if total_timeout > 0 else download_timeout
        if total_timeout > 0 and remaining <= 0:
            errors.append({"url": url, "error": "source publication download budget exhausted"})
            break
        destination = source_files_dir / filename
        reused_path = None
        if allow_cache and not destination.exists():
            reused_path = reuse_cached_source_file(cache_dir, source_package, filename, destination)
        if reused_path:
            ok, message = True, f"reused cached source file from {reused_path}"
            downloaded_url = url
        else:
            if not allow_cache:
                destination.unlink(missing_ok=True)
                destination.with_suffix(destination.suffix + ".tmp").unlink(missing_ok=True)
            ok = False
            message = "download failed"
            downloaded_url = url
            candidate_errors = []
            for candidate_url in source_download_urls(publication, url):
                remaining = int(total_timeout - (time.monotonic() - started)) if total_timeout > 0 else download_timeout
                if total_timeout > 0 and remaining <= 0:
                    candidate_errors.append("source publication download budget exhausted")
                    break
                hostname = (urllib.parse.urlsplit(candidate_url).hostname or "").lower()
                is_snapshot = hostname == "snapshot.ubuntu.com"
                is_original = candidate_url == url
                candidate_timeout = max(5, min(download_timeout, remaining))
                if not is_snapshot and not is_original:
                    candidate_timeout = min(candidate_timeout, 60)
                ok, message = download_file(
                    candidate_url,
                    destination,
                    verify_sha256=False,
                    timeout=candidate_timeout,
                    attempts=2 if is_snapshot or is_original else 1,
                    bypass_proxy=canonical_download_direct(candidate_url),
                )
                if ok:
                    downloaded_url = candidate_url
                    break
                candidate_errors.append(f"{candidate_url}: {message}")
            if not ok:
                message = "; ".join(candidate_errors) or message
        if ok:
            item = {"url": url, "path": str(destination), "message": message}
            if downloaded_url != url:
                item["download_url"] = downloaded_url
            downloaded.append(item)
        else:
            errors.append({"url": url, "error": message})
    return downloaded, errors


def source_download_urls(publication: SourcePublication, original_url: str) -> list[str]:
    """Return official Ubuntu mirrors for an exact Launchpad source filename."""

    filename = Path(urllib.parse.unquote(urllib.parse.urlsplit(original_url).path)).name
    component = publication.component.strip().lower()
    source_package = publication.source_package.strip().lower()
    if not filename or component not in {"main", "universe", "restricted", "multiverse"} or not source_package:
        return [original_url]
    prefix = source_package[:4] if source_package.startswith("lib") and len(source_package) >= 4 else source_package[:1]
    pool_path = f"pool/{component}/{prefix}/{source_package}/{filename}"
    snapshot_id = source_snapshot_id(publication.date_published or publication.date_created)
    candidates = [
        f"https://archive.ubuntu.com/ubuntu/{pool_path}",
        f"https://security.ubuntu.com/ubuntu/{pool_path}",
    ]
    if snapshot_id:
        candidates.append(f"https://snapshot.ubuntu.com/ubuntu/{snapshot_id}/{pool_path}")
    candidates.extend(
        [
            f"https://old-releases.ubuntu.com/ubuntu/{pool_path}",
            original_url,
        ]
    )
    return list(dict.fromkeys(candidates))


def source_snapshot_id(publication_date: str) -> str:
    value = publication_date.strip()
    if not value:
        return ""
    try:
        published = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if published.tzinfo is None:
        published = published.replace(tzinfo=timezone.utc)
    snapshot = published.astimezone(timezone.utc) + timedelta(days=1)
    return snapshot.strftime("%Y%m%dT%H%M%SZ")


def source_failure(publication: SourcePublication, reason: str) -> dict[str, Any]:
    return {
        "status": "failed",
        "reason": reason,
        "source_package": publication.source_package,
        "source_version": publication.source_version,
        "series": publication.series,
        "source_publication": publication.to_json(),
        "extracted_path": "",
    }


def source_workspace_base() -> Path:
    configured = os.environ.get("DEPLOYED_SOURCE_WORKDIR", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path(tempfile.gettempdir()) / "agentic-dataset-deployed-sources").resolve()


def local_source_workspace(cache_dir: Path) -> Path:
    scope = hashlib.sha256(str(cache_dir.expanduser().resolve()).encode("utf-8")).hexdigest()[:16]
    return source_workspace_base() / scope


def source_extracted_path(publication: SourcePublication, cache_dir: Path) -> tuple[Path, bool]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    use_local_workspace = not directory_supports_symlinks(cache_dir)
    version_dir = cache_dir / safe_token(publication.source_package) / safe_token(publication.source_version)
    extracted_path = (
        local_source_workspace(cache_dir)
        / safe_token(publication.source_package)
        / safe_token(publication.source_version)
        / "extracted"
        if use_local_workspace
        else version_dir / "extracted"
    )
    return extracted_path, use_local_workspace


def directory_supports_symlinks(directory: Path) -> bool:
    target = directory / ".deployed-symlink-target"
    link = directory / ".deployed-symlink-link"
    link.unlink(missing_ok=True)
    target.unlink(missing_ok=True)
    try:
        target.write_text("probe", encoding="utf-8")
        link.symlink_to(target.name)
        return link.is_symlink()
    except OSError:
        return False
    finally:
        link.unlink(missing_ok=True)
        target.unlink(missing_ok=True)


def reuse_cached_source_file(
    cache_dir: Path,
    source_package: str,
    filename: str,
    destination: Path,
) -> Path | None:
    package_dir = cache_dir / safe_token(source_package)
    if not package_dir.is_dir():
        return None
    for version_dir in sorted(package_dir.iterdir()):
        candidate = version_dir / "source-files" / filename
        if candidate == destination or not candidate.is_file() or candidate.stat().st_size == 0:
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.with_suffix(destination.suffix + ".tmp").unlink(missing_ok=True)
        try:
            os.link(candidate, destination)
        except OSError:
            shutil.copy2(candidate, destination)
        return candidate
    return None


def publication_id(publication: SourcePublication) -> str:
    tail = publication.self_link.rstrip("/").rsplit("/", 1)[-1]
    return safe_token(tail or f"{publication.source_package}-{publication.source_version}")
