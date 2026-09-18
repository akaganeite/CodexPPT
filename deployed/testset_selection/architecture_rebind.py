"""Rebind reviewed source selections to another Ubuntu binary architecture."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

from ..candidate_discovery.source_history import SourcePublication
from .balanced_policy import primary_balanced_pairs, rebuild_balanced_pairs
from .temporal_sampling import candidate_distance_key, reserve_candidate_count, reviewed_candidate_count
from .ubuntu_3v3 import selection_from_pairs
from .ubuntu_publication_artifacts import normalize_arch, publication_binary_availability


SOURCE_LABELS = {"vuln", "patch"}


def rebind_reviewed_selections(
    results: list[dict[str, Any]],
    *,
    arch: str,
    cache_dir: Path,
    max_per_label: int = 1,
    refresh: bool = False,
    log: Callable[[str], None] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return source-reviewed selections whose package evidence is for ``arch``.

    Source labels and semantic function mappings are retained. Architecture-
    dependent package availability, candidate pairs, package rankings, and the
    final balanced selection are rebuilt from scratch.
    """

    if not 1 <= max_per_label <= 3:
        raise ValueError("max_per_label must be between one and three")
    effective_arch = normalize_arch(arch)
    selected = []
    excluded = []
    for source in results:
        result = deepcopy(source)
        result.pop("package_ranking", None)
        result["requested_arch"] = arch
        result["arch"] = effective_arch
        if max_per_label == 1:
            rebound, attempted = rebind_first_available_pair(
                result,
                arch=effective_arch,
                cache_dir=cache_dir,
                refresh=refresh,
                log=log,
            )
            if rebound is not None:
                selected.append(rebound)
            else:
                result["selected"] = None
                result["status"] = "architecture_insufficient"
                result["architecture_rebind"] = {
                    "source_review_reused": True,
                    "arch": effective_arch,
                    "max_per_label": 1,
                    "attempted_candidate_count": attempted,
                }
                excluded.append(result)
            continue
        attempts = []
        for source_attempt in result.get("series_attempts") or []:
            attempt = deepcopy(source_attempt)
            rebound_candidates = []
            for source_candidate in attempt.get("candidate_matrix") or []:
                candidate = deepcopy(source_candidate)
                validation = candidate.get("source_validation") or {}
                label = str(validation.get("classified_label") or "")
                functions_available = bool(validation.get("functions_available"))
                candidate["temporal_side"] = str(
                    candidate.get("temporal_side") or candidate.get("side") or ""
                )
                if label in SOURCE_LABELS:
                    candidate["side"] = label
                availability = rebind_candidate_availability(
                    candidate,
                    arch=effective_arch,
                    cache_dir=cache_dir,
                    refresh=refresh,
                )
                candidate["binary_availability"] = availability
                candidate["precheck_ready"] = bool(availability.get("ready"))
                candidate["review_attempted"] = label in SOURCE_LABELS
                candidate["source_materialization"] = {
                    "status": "review_reused",
                    "extracted_path": "",
                }
                reasons = []
                if not candidate["precheck_ready"]:
                    reasons.append("runtime/debug deb pair unavailable for rebound architecture")
                if label not in SOURCE_LABELS:
                    reasons.append("source review did not assign a vuln/patch label")
                if not functions_available:
                    reasons.append("affected functions are unavailable according to source review")
                candidate["rejection_reasons"] = reasons
                candidate["eligible"] = not reasons
                rebound_candidates.append(candidate)
                if log:
                    log(
                        f"rebind cve={result.get('cve_id')} series={attempt.get('series')} "
                        f"version={candidate.get('source_version')} label={label or '-'} "
                        f"arch={effective_arch} ready={candidate['precheck_ready']}"
                    )
            attempt["candidate_matrix"] = rebound_candidates
            attempt["eligible_vulnerable"] = sorted(
                (
                    item
                    for item in rebound_candidates
                    if item.get("eligible") and item.get("side") == "vuln"
                ),
                key=candidate_distance_key,
            )
            attempt["eligible_patch"] = sorted(
                (
                    item
                    for item in rebound_candidates
                    if item.get("eligible") and item.get("side") == "patch"
                ),
                key=candidate_distance_key,
            )
            attempt["status"] = (
                "candidates_ready"
                if attempt["eligible_vulnerable"] and attempt["eligible_patch"]
                else "architecture_insufficient"
            )
            attempt["reason"] = (
                f"architecture rebind left {len(attempt['eligible_vulnerable'])} vuln and "
                f"{len(attempt['eligible_patch'])} patch candidates"
            )
            attempts.append(attempt)
        result["series_attempts"] = attempts
        balanced_pairs = rebuild_balanced_pairs(attempts)
        selected_pairs = primary_balanced_pairs(
            balanced_pairs,
            max_per_label=max_per_label,
        )
        result["selected"] = selection_from_pairs(selected_pairs) if selected_pairs else None
        pool = result.setdefault("candidate_pool", {})
        pool.update(
            {
                "minimum_count_per_label": 1,
                "maximum_count_per_label": max_per_label,
                "target_count_per_label": len(selected_pairs),
                "pair_count": len(balanced_pairs),
                "vulnerable": [item["vulnerable"] for item in balanced_pairs],
                "patch": [item["patch"] for item in balanced_pairs],
                "pairs": balanced_pairs,
                "reviewed_candidate_count": sum(reviewed_candidate_count(item) for item in attempts),
                "reserve_candidate_count": sum(reserve_candidate_count(item) for item in attempts),
            }
        )
        result["status"] = "candidate_pool_ready" if selected_pairs else "architecture_insufficient"
        result["architecture_rebind"] = {
            "source_review_reused": True,
            "arch": effective_arch,
            "max_per_label": max_per_label,
        }
        (selected if selected_pairs else excluded).append(result)
    return selected, excluded


def rebind_first_available_pair(
    result: dict[str, Any],
    *,
    arch: str,
    cache_dir: Path,
    refresh: bool,
    log: Callable[[str], None] | None,
) -> tuple[dict[str, Any] | None, int]:
    """Lazily try reviewed pair options until one architecture-ready 1v1 exists."""

    attempted: dict[tuple[str, str], dict[str, Any]] = {}
    for pair in prioritized_pairs(result):
        rows = []
        for role in ("vulnerable", "patch"):
            source_candidate = pair.get(role) or {}
            key = (
                str(source_candidate.get("series") or pair.get("series") or ""),
                str(source_candidate.get("source_version") or ""),
            )
            candidate = attempted.get(key)
            if candidate is None:
                candidate = rebound_candidate(
                    source_candidate,
                    arch=arch,
                    cache_dir=cache_dir,
                    refresh=refresh,
                )
                attempted[key] = candidate
                if log:
                    validation = candidate.get("source_validation") or {}
                    log(
                        f"rebind cve={result.get('cve_id')} series={key[0]} version={key[1]} "
                        f"label={validation.get('classified_label') or '-'} arch={arch} "
                        f"ready={candidate.get('precheck_ready')}"
                    )
            rows.append(candidate)
        eligible = [item for item in rows if item.get("eligible")]
        by_label = {str((item.get("source_validation") or {}).get("classified_label") or ""): item for item in eligible}
        if set(by_label) != SOURCE_LABELS:
            continue
        rebound_pair = {
            **{key: value for key, value in pair.items() if key not in {"vulnerable", "patch"}},
            "vulnerable": by_label["vuln"],
            "patch": by_label["patch"],
        }
        result["selected"] = selection_from_pairs([rebound_pair])
        result["series_attempts"] = [
            {
                "series": rebound_pair.get("series") or "",
                "ubuntu_release": rebound_pair.get("ubuntu_release") or "",
                "fixed_source_version": rebound_pair.get("fixed_source_version") or "",
                "status": "candidates_ready",
                "reason": "source-reviewed pair is available for rebound architecture",
                "candidate_matrix": rows,
                "eligible_vulnerable": [by_label["vuln"]],
                "eligible_patch": [by_label["patch"]],
            }
        ]
        result["candidate_pool"] = {
            "minimum_count_per_label": 1,
            "maximum_count_per_label": 1,
            "target_count_per_label": 1,
            "pair_count": 1,
            "vulnerable": [by_label["vuln"]],
            "patch": [by_label["patch"]],
            "pairs": [rebound_pair],
            "reviewed_candidate_count": 2,
            "reserve_candidate_count": 0,
        }
        result["status"] = "candidate_pool_ready"
        result["architecture_rebind"] = {
            "source_review_reused": True,
            "arch": arch,
            "max_per_label": 1,
            "attempted_candidate_count": len(attempted),
        }
        return result, len(attempted)
    return None, len(attempted)


def prioritized_pairs(result: dict[str, Any]) -> list[dict[str, Any]]:
    pool_pairs = list((result.get("candidate_pool") or {}).get("pairs") or [])
    by_signature = {
        pair_signature(item): item
        for item in pool_pairs
        if pair_signature(item)[0] and pair_signature(item)[1]
    }
    ordered = []
    selected = result.get("selected") or {}
    for vulnerable, patch in zip(selected.get("vulnerable") or [], selected.get("patch") or []):
        signature = (
            str(vulnerable.get("source_version") or ""),
            str(patch.get("source_version") or ""),
        )
        ordered.append(
            by_signature.get(signature)
            or {
                "series": vulnerable.get("series") or patch.get("series") or selected.get("series") or "",
                "ubuntu_release": selected.get("ubuntu_release") or "",
                "fixed_source_version": selected.get("fixed_source_version") or "",
                "series_rank": 0,
                "within_series_rank": len(ordered),
                "sampling_stratum": "near",
                "distance_mismatch_days": abs(
                    abs(float(vulnerable.get("days_from_fix") or 0.0))
                    - abs(float(patch.get("days_from_fix") or 0.0))
                ),
                "vulnerable": vulnerable,
                "patch": patch,
            }
        )
    seen = {pair_signature(item) for item in ordered}
    ordered.extend(item for item in pool_pairs if pair_signature(item) not in seen)
    return ordered


def pair_signature(pair: dict[str, Any]) -> tuple[str, str]:
    return (
        str((pair.get("vulnerable") or {}).get("source_version") or ""),
        str((pair.get("patch") or {}).get("source_version") or ""),
    )


def rebound_candidate(
    source_candidate: dict[str, Any],
    *,
    arch: str,
    cache_dir: Path,
    refresh: bool,
) -> dict[str, Any]:
    candidate = deepcopy(source_candidate)
    validation = candidate.get("source_validation") or {}
    label = str(validation.get("classified_label") or "")
    functions_available = bool(validation.get("functions_available"))
    candidate["temporal_side"] = str(candidate.get("temporal_side") or candidate.get("side") or "")
    if label in SOURCE_LABELS:
        candidate["side"] = label
    availability = rebind_candidate_availability(
        candidate,
        arch=arch,
        cache_dir=cache_dir,
        refresh=refresh,
    )
    candidate["binary_availability"] = availability
    candidate["precheck_ready"] = bool(availability.get("ready"))
    candidate["review_attempted"] = label in SOURCE_LABELS
    candidate["source_materialization"] = {"status": "review_reused", "extracted_path": ""}
    reasons = []
    if not candidate["precheck_ready"]:
        reasons.append("runtime/debug deb pair unavailable for rebound architecture")
    if label not in SOURCE_LABELS:
        reasons.append("source review did not assign a vuln/patch label")
    if not functions_available:
        reasons.append("affected functions are unavailable according to source review")
    candidate["rejection_reasons"] = reasons
    candidate["eligible"] = not reasons
    return candidate


def rebind_candidate_availability(
    candidate: dict[str, Any],
    *,
    arch: str,
    cache_dir: Path,
    refresh: bool,
) -> dict[str, Any]:
    publication_data = candidate.get("source_publication") or {}
    try:
        publication = SourcePublication(**publication_data)
    except TypeError as exc:
        return {
            "checked": False,
            "ready": False,
            "arch": arch,
            "reason": f"invalid source publication: {exc}",
        }
    try:
        return publication_binary_availability(
            publication,
            arch=arch,
            cache_dir=cache_dir,
            refresh=refresh,
        )
    except Exception as exc:
        return {
            "checked": False,
            "ready": False,
            "arch": arch,
            "reason": str(exc),
        }
