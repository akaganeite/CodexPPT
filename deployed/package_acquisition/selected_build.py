"""Convert balanced source selections into ranked package downloads and artifacts."""

from __future__ import annotations

import json
import time
from itertools import combinations
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote, urlsplit

from .artifacts import materialize_pair, result_for_cve
from ..candidate_discovery.metadata import CveMetadata
from ..config import ProjectConfig
from ..models import ArtifactResult, LabeledSourceVersion, PackagePair
from ..testset_selection.balanced_policy import (
    balanced_pair_combination_key,
    balanced_pair_versions_unique,
)
from ..testset_selection.ubuntu_3v3 import selection_from_pairs
from .package_ranker import rank_selected_packages


FUNCTION_EVIDENCE_STATUSES = {"ok", "inline_only", "dwarf_range_present", "dwarf_available"}


def load_selection_results(path: Path) -> list[dict[str, Any]]:
    source = path.expanduser().resolve()
    raw = json.loads(source.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict) and raw.get("cve_id") and "selected" in raw:
        items = [raw]
    elif isinstance(raw, dict) and isinstance(raw.get("results"), list):
        items = raw["results"]
    else:
        raise ValueError("selection file must contain full balanced-selection result objects")
    selected = [item for item in items if isinstance(item, dict) and item.get("selected")]
    if not selected:
        raise ValueError("selection file does not contain any balanced CVE selection")
    for item in selected:
        pool = item.get("candidate_pool") or {}
        if pool and len(pool.get("pairs") or []) < 1:
            raise ValueError(f"{item.get('cve_id')}: candidate pool has no balanced pair")
        selection = item.get("selected") or {}
        count = balanced_selection_count(selection)
        if not 1 <= count <= 3:
            raise ValueError(f"{item.get('cve_id')}: selection must contain one to three balanced pairs")
    return selected


def labels_from_selections(
    selections: list[dict[str, Any]],
    metadata_by_cve: dict[str, CveMetadata],
) -> list[LabeledSourceVersion]:
    output = []
    for result in selections:
        cve_id = str(result.get("cve_id") or "")
        metadata = metadata_by_cve.get(cve_id)
        selected = result.get("selected") or {}
        for label, rows in (("vuln", selected.get("vulnerable") or []), ("patch", selected.get("patch") or [])):
            for row in rows:
                publication = row.get("source_publication") or {}
                output.append(
                    LabeledSourceVersion(
                        cve_id=cve_id,
                        source_package=str(result.get("source_package") or publication.get("source_package") or ""),
                        source_version=str(row.get("source_version") or ""),
                        ubuntu_version=str(row.get("source_version") or ""),
                        series=str(row.get("series") or selected.get("series") or ""),
                        pocket=str(row.get("pocket") or publication.get("pocket") or ""),
                        component=str(row.get("component") or publication.get("component") or ""),
                        label=label,
                        reason="resolved by adaptive balanced Tier1 package validation",
                        provenance="resolved_balanced",
                        source_url=str(publication.get("self_link") or ""),
                        metadata_functions=list(metadata.functions if metadata else []),
                    )
                )
    return output


def ensure_package_rankings(
    selections: list[dict[str, Any]],
    metadata_by_cve: dict[str, CveMetadata],
    project: ProjectConfig,
    *,
    output: Path,
    config_path: Path | None,
    base_binary_hints: dict[str, list[str]] | None = None,
    refresh: bool = False,
    log: Callable[[str], None] | None = None,
) -> dict[str, dict[str, Any]]:
    rankings = {}
    for result in selections:
        cve_id = str(result.get("cve_id") or "")
        metadata = metadata_by_cve.get(cve_id)
        if not metadata:
            continue
        existing = result.get("package_ranking")
        if isinstance(existing, dict) and existing.get("tasks") and not refresh:
            ranking = existing
        else:
            ranking = rank_selected_packages(
                result,
                metadata,
                project,
                output=output,
                config_path=config_path,
                base_binary_hints=(base_binary_hints or {}).get(cve_id, []),
                refresh=refresh,
                log=log,
            )
            result["package_ranking"] = ranking
        rankings[cve_id] = ranking
    return rankings


def planned_pairs_from_rankings(
    selections: list[dict[str, Any]],
    rankings: dict[str, dict[str, Any]],
) -> list[PackagePair]:
    output = []
    for result in selections:
        cve_id = str(result.get("cve_id") or "")
        ranking = rankings.get(cve_id) or {}
        families = {item.get("candidate_id"): item for item in ranking.get("candidate_families") or []}
        for task in ranking.get("tasks") or []:
            for ranked in task.get("ranking") or []:
                family = families.get(ranked.get("candidate_id"))
                if not family:
                    continue
                pairs = pairs_for_family(result, task, family)
                if len(pairs) == required_artifact_count(result.get("selected") or {}):
                    output.extend(pairs)
                    break
    return output


def materialize_ranked_selections(
    selections: list[dict[str, Any]],
    rankings: dict[str, dict[str, Any]],
    project: ProjectConfig,
    *,
    output: Path,
    verify_sha256: bool,
    resume: bool,
    max_family_attempts: int = 0,
    max_version_attempts: int = 4,
    max_per_label: int = 3,
    max_search_minutes: float = 30.0,
    log: Callable[[str], None] | None = None,
    materializer: Callable[..., dict[str, Any]] = materialize_pair,
) -> tuple[list[PackagePair], list[ArtifactResult], dict[str, Any]]:
    selected_pairs: list[PackagePair] = []
    artifacts: list[ArtifactResult] = []
    cve_reports = []
    resolved_selections = []
    report_cache: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    function_validation_cache: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    validation_functions = requested_function_universe(selections, rankings)
    for selection in selections:
        cve_id = str(selection.get("cve_id") or "")
        ranking = rankings.get(cve_id) or {}
        families = {item.get("candidate_id"): item for item in ranking.get("candidate_families") or []}
        tasks = ranking.get("tasks") or []
        version_options = version_attempts(
            selection,
            max_attempts=max_version_attempts,
            max_per_label=max_per_label,
        )
        cve_started = time.monotonic()
        cve_deadline = cve_started + max_search_minutes * 60 if max_search_minutes > 0 else 0.0
        version_reports = []
        accepted_selection = None
        accepted_pairs: list[PackagePair] = []
        accepted_artifacts: list[ArtifactResult] = []
        for version_index, selected in enumerate(version_options, start=1):
            elapsed_minutes = (time.monotonic() - cve_started) / 60.0
            if max_search_minutes > 0 and elapsed_minutes >= max_search_minutes:
                version_reports.append({"attempt": version_index, "status": "budget_exhausted", "tasks": []})
                break
            task_reports = []
            combo_pairs: list[PackagePair] = []
            combo_artifacts: list[ArtifactResult] = []
            combo_ok = bool(tasks)
            if log:
                log(
                    f"version-attempt cve={cve_id} attempt={version_index}/{len(version_options)} "
                    f"versions={','.join(selected_source_versions(selected))}"
                )
            for task in tasks:
                task_report, task_pairs, task_artifacts = materialize_task_for_selection(
                    selection,
                    selected,
                    task,
                    families,
                    project,
                    output=output,
                    verify_sha256=verify_sha256,
                    resume=resume,
                    max_family_attempts=max_family_attempts,
                    report_cache=report_cache,
                    function_validation_cache=function_validation_cache,
                    validation_functions=validation_functions,
                    materializer=materializer,
                    deadline=cve_deadline,
                )
                task_reports.append(task_report)
                if task_report["status"] != "selected":
                    combo_ok = False
                    break
                combo_pairs.extend(task_pairs)
                combo_artifacts.extend(task_artifacts)
            version_reports.append(
                {
                    "attempt": version_index,
                    "status": "selected" if combo_ok else "rejected",
                    "selection": selected,
                    "tasks": task_reports,
                }
            )
            if combo_ok:
                accepted_selection = selected
                accepted_pairs = merge_pairs(combo_pairs)
                accepted_artifacts = combo_artifacts
                break
        if accepted_selection:
            resolved = {**selection, "selected": accepted_selection, "status": "resolved_balanced"}
            resolved_selections.append(resolved)
            selected_pairs.extend(accepted_pairs)
            artifacts.extend(accepted_artifacts)
        cve_reports.append(
            {
                "cve_id": cve_id,
                "status": "selected" if accepted_selection else "unresolved",
                "version_attempts": version_reports,
                "elapsed_seconds": round(time.monotonic() - cve_started, 3),
            }
        )
        if log:
            log(
                f"package-search cve={cve_id} status={'selected' if accepted_selection else 'unresolved'} "
                f"version_attempts={len(version_reports)} elapsed={time.monotonic() - cve_started:.1f}s"
            )
    return selected_pairs, artifacts, {
        "schema": "ubuntu-adaptive-package-search-v2",
        "policy": {
            "max_version_attempts": max_version_attempts,
            "max_per_label": max_per_label,
            "max_family_attempts": max_family_attempts,
            "max_search_minutes_per_cve": max_search_minutes,
            "anchor_first": True,
            "balanced_fallback": "largest available set, descending to 1v1",
        },
        "cves": cve_reports,
        "resolved_selections": resolved_selections,
        "selected_cves": sum(1 for item in cve_reports if item["status"] == "selected"),
        "unresolved_cves": sum(1 for item in cve_reports if item["status"] != "selected"),
    }


def materialize_task_for_selection(
    selection_result: dict[str, Any],
    selected: dict[str, Any],
    task: dict[str, Any],
    families: dict[str, dict[str, Any]],
    project: ProjectConfig,
    *,
    output: Path,
    verify_sha256: bool,
    resume: bool,
    max_family_attempts: int,
    report_cache: dict[tuple[str, str, str, str], dict[str, Any]],
    function_validation_cache: dict[str, tuple[dict[str, Any], dict[str, Any]]],
    validation_functions: list[str],
    materializer: Callable[..., dict[str, Any]],
    deadline: float,
) -> tuple[dict[str, Any], list[PackagePair], list[ArtifactResult]]:
    attempts = []
    ranked_items = list(task.get("ranking") or [])
    if max_family_attempts > 0:
        ranked_items = ranked_items[:max_family_attempts]
    for ranked in ranked_items:
        if deadline and time.monotonic() >= deadline:
            attempts.append({"status": "budget_exhausted", "reason": "CVE search budget exhausted"})
            break
        family = families.get(ranked.get("candidate_id"))
        if not family:
            continue
        family_pairs = pairs_for_family(selection_result, task, family, selected=selected)
        expected_count = required_artifact_count(selected)
        attempt = {
            "candidate_id": family.get("candidate_id"),
            "runtime_package": family.get("runtime_package"),
            "debug_package": family.get("debug_package"),
            "status": "rejected",
            "reason": "",
            "anchors": [],
        }
        if len(family_pairs) != expected_count:
            attempt["reason"] = f"family covers {len(family_pairs)}/{expected_count} versions in this attempt"
            attempts.append(attempt)
            continue
        ordered_pairs = anchor_first(family_pairs)
        candidate_artifacts = []
        failed = False
        for index, pair in enumerate(ordered_pairs):
            if deadline and time.monotonic() >= deadline:
                failed = True
                attempt["reason"] = "CVE search budget exhausted"
                break
            artifact = materialize_one(
                project,
                pair,
                output=output,
                verify_sha256=verify_sha256,
                resume=resume,
                cache=report_cache,
                function_validation_cache=function_validation_cache,
                validation_functions=validation_functions,
                materializer=materializer,
                deadline=deadline,
            )
            candidate_artifacts.append(artifact)
            if index < 2:
                attempt["anchors"].append(compact_artifact(artifact))
            if artifact.status not in FUNCTION_EVIDENCE_STATUSES:
                failed = True
                attempt["reason"] = (
                    "anchor function/package validation failed" if index < 2 else "non-anchor function/package validation failed"
                )
                break
        if failed:
            attempts.append(attempt)
            continue
        attempt["status"] = "selected"
        attempt["reason"] = (
            f"all {expected_count} versions passed package, Build-ID, and function validation"
        )
        attempts.append(attempt)
        return (
            {
                "function": task.get("function") or "",
                "source_file": task.get("source_file") or "",
                "status": "selected",
                "selected_candidate_id": family.get("candidate_id") or "",
                "attempts": attempts,
            },
            family_pairs,
            candidate_artifacts,
        )
    return (
        {
            "function": task.get("function") or "",
            "source_file": task.get("source_file") or "",
            "status": "unresolved",
            "selected_candidate_id": "",
            "attempts": attempts,
        },
        [],
        [],
    )


def pairs_for_family(
    selection: dict[str, Any],
    task: dict[str, Any],
    family: dict[str, Any],
    *,
    selected: dict[str, Any] | None = None,
) -> list[PackagePair]:
    cve_id = str(selection.get("cve_id") or "")
    function = str(task.get("function") or "")
    task_id = str(task.get("task_hash") or f"{cve_id}:{function}")
    selected = selected or selection.get("selected") or {}
    wanted = {
        (label, str(item.get("series") or ""), str(item.get("source_version") or ""))
        for label, rows in (("vuln", selected.get("vulnerable") or []), ("patch", selected.get("patch") or []))
        for item in rows
    }
    output = []
    for item in family.get("versions") or []:
        key = (str(item.get("label") or ""), str(item.get("series") or ""), str(item.get("source_version") or ""))
        if key not in wanted:
            continue
        runtime = item.get("runtime") or {}
        debug = item.get("debug") or {}
        runtime_url = str(runtime.get("url") or "")
        debug_url = str(debug.get("url") or "")
        requested_function = candidate_function_name(item, function)
        provenance = ["selected_balanced", "deepseek_package_ranking", "build_id_validation"]
        if requested_function != function:
            provenance.append(f"function_mapping:{function}={requested_function}")
        output.append(
            PackagePair(
                cve_id=cve_id,
                label=str(item.get("label") or ""),
                source_package=str(selection.get("source_package") or ""),
                source_version=str(item.get("source_version") or ""),
                series=str(item.get("series") or ""),
                pocket=str(item.get("pocket") or ""),
                component=str(item.get("component") or ""),
                architecture=str(
                    runtime.get("arch")
                    or debug.get("arch")
                    or selection.get("arch")
                    or selection.get("requested_arch")
                    or ""
                ),
                publication_date=str(
                    (item.get("source_publication") or {}).get("date_published")
                    or (item.get("source_publication") or {}).get("date_created")
                    or ""
                ),
                runtime_package=str(runtime.get("package") or ""),
                runtime_version=str(runtime.get("version") or ""),
                runtime_url=runtime_url,
                runtime_sha256=str(runtime.get("sha256") or ""),
                runtime_filename=str(runtime.get("filename") or url_filename(runtime_url)),
                debug_package=str(debug.get("package") or ""),
                debug_version=str(debug.get("version") or ""),
                debug_url=debug_url,
                debug_sha256=str(debug.get("sha256") or ""),
                debug_filename=str(debug.get("filename") or url_filename(debug_url)),
                status="paired",
                reason="selected from LLM-ranked closed-world candidate families",
                provenance=provenance,
                requested_functions=[requested_function],
                ranking_task_id=task_id,
                candidate_id=str(family.get("candidate_id") or ""),
            )
        )
    return output


def candidate_function_name(version: dict[str, Any], canonical_function: str) -> str:
    validation = version.get("source_validation") or {}
    for mapping in validation.get("function_mappings") or []:
        if not isinstance(mapping, dict) or mapping.get("canonical_function") != canonical_function:
            continue
        candidate = str(mapping.get("candidate_function") or "").strip()
        if candidate and mapping.get("relationship") in {"exact", "semantic_equivalent"}:
            return candidate
    return canonical_function


def version_attempts(
    selection: dict[str, Any],
    *,
    max_attempts: int,
    max_per_label: int = 3,
) -> list[dict[str, Any]]:
    if not 1 <= max_per_label <= 3:
        raise ValueError("max_per_label must be between one and three")
    pool_pairs = list((selection.get("candidate_pool") or {}).get("pairs") or [])
    if not pool_pairs:
        selected = selection.get("selected") or {}
        pool_pairs = [
            {
                "series": vulnerable.get("series") or patched.get("series") or selected.get("series") or "",
                "ubuntu_release": selected.get("ubuntu_release") or "",
                "fixed_source_version": selected.get("fixed_source_version") or "",
                "series_rank": 0,
                "within_series_rank": index,
                "vulnerable": vulnerable,
                "patch": patched,
                "distance_mismatch_days": abs(
                    abs(float(vulnerable.get("days_from_fix") or 0)) - abs(float(patched.get("days_from_fix") or 0))
                ),
            }
            for index, (vulnerable, patched) in enumerate(
                zip(selected.get("vulnerable") or [], selected.get("patch") or [])
            )
        ]
    pool = selection.get("candidate_pool") or {}
    target_count = int(pool.get("target_count_per_label") or 0)
    if target_count < 1:
        target_count = min(3, balanced_selection_count(selection.get("selected") or {}), len(pool_pairs))
    target_count = min(max_per_label, target_count, len(pool_pairs))
    if target_count < 1:
        return []
    ranked_by_count = {
        count: sorted(
            (items for items in combinations(pool_pairs, count) if balanced_pair_versions_unique(items)),
            key=version_combination_key,
        )
        for count in range(target_count, 0, -1)
    }
    if max_attempts <= 0:
        ranked = [items for count in range(target_count, 0, -1) for items in ranked_by_count[count]]
        return [selection_from_pairs(list(items)) for items in ranked]

    selected_combinations = []
    queues = {count: list(items) for count, items in ranked_by_count.items()}
    lower_counts = [count for count in range(target_count - 1, 0, -1) if queues[count]]
    primary_slots = max(1, max_attempts - len(lower_counts))
    selected_combinations.extend(queues[target_count][:primary_slots])
    del queues[target_count][:primary_slots]
    for count in lower_counts:
        if len(selected_combinations) >= max_attempts:
            break
        selected_combinations.append(queues[count].pop(0))
    while len(selected_combinations) < max_attempts:
        next_items = next((queues[count] for count in range(target_count, 0, -1) if queues[count]), None)
        if not next_items:
            break
        selected_combinations.append(next_items.pop(0))
    return [selection_from_pairs(list(items)) for items in selected_combinations]


def balanced_selection_count(selected: dict[str, Any]) -> int:
    vulnerable_count = len(selected.get("vulnerable") or [])
    patch_count = len(selected.get("patch") or [])
    return vulnerable_count if vulnerable_count == patch_count else 0


def required_artifact_count(selected: dict[str, Any]) -> int:
    count = balanced_selection_count(selected)
    return count * 2 if 1 <= count <= 3 else 0


def version_combination_key(items: tuple[dict[str, Any], ...]) -> tuple[Any, ...]:
    return balanced_pair_combination_key(items)


def selected_source_versions(selected: dict[str, Any]) -> list[str]:
    return [
        str(item.get("source_version") or "")
        for item in [*(selected.get("vulnerable") or []), *(selected.get("patch") or [])]
    ]


def merge_pairs(pairs: list[PackagePair]) -> list[PackagePair]:
    merged: dict[tuple[str, str, str, str, str], PackagePair] = {}
    for pair in pairs:
        key = (pair.cve_id, pair.label, pair.source_version, pair.runtime_url, pair.debug_url)
        previous = merged.get(key)
        if previous is None:
            merged[key] = pair
            continue
        previous.requested_functions = list(dict.fromkeys([*previous.requested_functions, *pair.requested_functions]))
    return list(merged.values())


def anchor_first(pairs: list[PackagePair]) -> list[PackagePair]:
    vuln = next((item for item in pairs if item.label == "vuln"), None)
    patch = next((item for item in pairs if item.label == "patch"), None)
    anchors = [item for item in (vuln, patch) if item]
    anchor_versions = {item.source_version for item in anchors}
    return anchors + [item for item in pairs if item.source_version not in anchor_versions]


def materialize_one(
    project: ProjectConfig,
    pair: PackagePair,
    *,
    output: Path,
    verify_sha256: bool,
    resume: bool,
    cache: dict[tuple[str, str, str, str], dict[str, Any]],
    function_validation_cache: dict[str, tuple[dict[str, Any], dict[str, Any]]] | None = None,
    validation_functions: list[str] | None = None,
    materializer: Callable[..., dict[str, Any]],
    deadline: float = 0.0,
) -> ArtifactResult:
    report = cache.get(pair.artifact_key)
    if report is None:
        remaining_seconds = int(deadline - time.monotonic()) if deadline else 300
        download_timeout = max(5, min(300, remaining_seconds))
        report = materializer(
            project=project,
            pair=pair,
            output=output,
            verify_sha256=verify_sha256,
            resume=resume,
            skip_download=False,
            download_timeout=download_timeout,
        )
        if cacheable_materialization_report(report):
            cache[pair.artifact_key] = report
    return result_for_cve(
        pair,
        pair.requested_functions,
        report,
        function_validation_cache,
        validation_functions,
    )


def requested_function_universe(
    selections: list[dict[str, Any]],
    rankings: dict[str, dict[str, Any]],
) -> list[str]:
    """Collect every function name that this build may validate in an ELF."""

    functions: list[str] = []
    for selection in selections:
        cve_id = str(selection.get("cve_id") or "")
        ranking = rankings.get(cve_id) or {}
        families = ranking.get("candidate_families") or []
        for task in ranking.get("tasks") or []:
            canonical = str(task.get("function") or "")
            if not canonical:
                continue
            functions.append(canonical)
            for family in families:
                for version in family.get("versions") or []:
                    functions.append(candidate_function_name(version, canonical))
    return list(dict.fromkeys(function for function in functions if function))


def cacheable_materialization_report(report: dict[str, Any]) -> bool:
    return report.get("status") not in {"url_unreachable", "extract_failed", "skipped"}


def compact_artifact(artifact: ArtifactResult) -> dict[str, Any]:
    return {
        "source_version": artifact.source_version,
        "label": artifact.label,
        "status": artifact.status,
        "runtime_package": artifact.runtime_package,
        "debug_package": artifact.debug_package,
        "runtime_elf": artifact.runtime_elf,
        "found_functions": artifact.found_functions,
        "missing_functions": artifact.missing_functions,
        "reason": artifact.reason,
    }


def url_filename(url: str) -> str:
    return Path(unquote(urlsplit(url).path)).name
