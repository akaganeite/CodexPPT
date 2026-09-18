from __future__ import annotations

from datetime import datetime, timezone
from functools import cmp_to_key
import time
import threading
from pathlib import Path
from typing import Any, Callable

from ..candidate_discovery.metadata import CveMetadata
from ..candidate_discovery.source_history import SourcePublication, load_source_history
from ..candidate_discovery.ubuntu_groundtruth import build_ubuntu_groundtruth
from ..candidate_discovery.ubuntu_source_groundtruth import publication_json, select_exact_publication
from ..versions import debian_compare
from .balanced_policy import (
    balanced_pair_combination_key,
    balanced_pair_versions_unique,
    extend_unique_balanced_pairs,
    pair_signatures,
    primary_balanced_pairs,
    rebuild_balanced_pairs,
)
from .codex_source_review import load_cached_source_review, review_source_candidates
from .temporal_sampling import (
    PRECHECK_RESERVE_MULTIPLIER,
    SAMPLING_STRATA,
    assign_sampling_metadata,
    candidate_distance_key,
    fallback_review_candidate_ids,
    initial_review_candidate_ids,
    reserve_candidate_count,
    reviewed_candidate_count,
    spread_temporal_candidates,
)
from .ubuntu_publication_artifacts import (
    materialize_source_publication,
    normalize_arch,
    publication_binary_availability,
    source_extracted_path,
)


SOURCE_HISTORY_LOCK = threading.Lock()
def select_3v3_for_cve(
    payload: dict[str, Any],
    metadata: CveMetadata,
    *,
    source_package: str,
    output: Path,
    arch: str = "x86",
    series_filter: list[str] | None = None,
    include_esm: bool = False,
    max_candidates_per_side: int = 8,
    max_per_label: int = 3,
    max_selection_minutes: float = 20.0,
    source_download_timeout: int = 90,
    source_review_timeout: int = 300,
    refresh: bool = False,
    log: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    if max_candidates_per_side < 1:
        raise ValueError("max_candidates_per_side must be positive")
    if not 1 <= max_per_label <= 3:
        raise ValueError("max_per_label must be between one and three")
    effective_arch = normalize_arch(arch)
    deadline = time.monotonic() + max_selection_minutes * 60 if max_selection_minutes > 0 else 0.0
    parsed = build_ubuntu_groundtruth(
        payload,
        series_filter=series_filter or (),
        include_esm=include_esm,
    )
    patch_rows = [
        row
        for row in parsed["security_patch_groundtruth"]
        if row["source_package"] == source_package
    ]
    series = sorted({row["ubuntu_series"] for row in patch_rows})
    history_cache = output / "state" / "source_history" / f"{safe_name(source_package)}.json"
    history_cache.parent.mkdir(parents=True, exist_ok=True)
    with SOURCE_HISTORY_LOCK:
        histories = load_source_history(
            source_package,
            series,
            cache_path=history_cache,
            refresh=refresh,
            log=log,
        )
    ordered_rows = sorted(patch_rows, key=release_sort_key, reverse=True)
    attempts = []
    for patch_row in ordered_rows:
        attempt = evaluate_series(
            patch_row,
            histories.get(patch_row["ubuntu_series"], []),
            metadata,
            payload=payload,
            output=output,
            arch=effective_arch,
            include_esm=include_esm,
            max_candidates_per_side=max_candidates_per_side,
            deadline=deadline,
            source_download_timeout=source_download_timeout,
            refresh=refresh,
            log=log,
        )
        attempts.append(attempt)
    temporal_pair_capacity = sum(
        int(attempt.get("temporal_pair_capacity") or 0) for attempt in attempts
    )
    review_pair_capacity_upper_bound = sum(
        int(attempt.get("review_pair_capacity_upper_bound") or 0) for attempt in attempts
    )

    balanced_pairs = []
    if review_pair_capacity_upper_bound >= 1:
        for index, attempt in enumerate(attempts):
            candidate_ids = initial_review_candidate_ids(attempt, max_candidates_per_side)
            if not candidate_ids:
                continue
            review_attempt_sources(
                attempt,
                metadata,
                candidate_ids=candidate_ids,
                output=output,
                deadline=deadline,
                source_download_timeout=source_download_timeout,
                source_review_timeout=source_review_timeout,
                refresh=refresh,
                log=log,
            )
            balanced_pairs = rebuild_balanced_pairs(attempts)
            if len(balanced_pairs) >= max_per_label:
                break
    else:
        for attempt in attempts:
            if attempt.get("status") == "prechecked":
                attempt["status"] = "structurally_insufficient"
                attempt["reason"] = (
                    f"binary-available source history provides only "
                    f"{attempt.get('review_pair_capacity_upper_bound', 0)} possible balanced pairs in this series"
                )
    selected_pairs = primary_balanced_pairs(balanced_pairs, max_per_label=max_per_label)
    selected_count = len(selected_pairs)
    selected = selection_from_pairs(selected_pairs) if selected_pairs else None
    reviewed_count = sum(reviewed_candidate_count(attempt) for attempt in attempts)
    reserve_count = sum(reserve_candidate_count(attempt) for attempt in attempts)
    candidate_pool = {
        "minimum_count_per_label": 1,
        "maximum_count_per_label": max_per_label,
        "target_count_per_label": selected_count,
        "temporal_pair_capacity": temporal_pair_capacity,
        "review_pair_capacity_upper_bound": review_pair_capacity_upper_bound,
        "pair_count": len(balanced_pairs),
        "vulnerable": [item["vulnerable"] for item in balanced_pairs],
        "patch": [item["patch"] for item in balanced_pairs],
        "pairs": balanced_pairs,
        "reviewed_candidate_count": reviewed_count,
        "reserve_candidate_count": reserve_count,
    }
    return {
        "schema": "ubuntu-balanced-candidate-pool-v3",
        "cve_id": metadata.cve_id,
        "source_package": source_package,
        "requested_arch": arch,
        "arch": effective_arch,
        "selection_policy": {
            "tier": "tier1_launchpad_source_package",
            "series_order": "latest_release_first_then_previous",
            "series_policy": "latest series first; supplement from previous series in label-balanced pairs",
            "vulnerable_count": f"1-{max_per_label}",
            "patch_count": f"1-{max_per_label}",
            "time_selection": "stratified near/mid/far candidate pool; up to three balanced pairs are resolved after deb/ddeb validation",
            "time_symmetry": "sample relative near/mid/far strata on each side and minimize actual vuln/patch day-distance mismatch",
            "max_candidates_per_side": max_candidates_per_side,
            "precheck_reserve_multiplier": PRECHECK_RESERVE_MULTIPLIER,
            "max_selection_minutes": max_selection_minutes,
            "source_download_timeout_seconds": source_download_timeout,
            "source_review_timeout_seconds": source_review_timeout,
            "source_review": "Codex exec assigns final labels after binary-availability precheck",
            "source_fallback": "unreviewed binary-ready candidates remain available for incremental Codex review",
            "excluded_pockets": ["Proposed", "Backports"],
        },
        "candidate_pool": candidate_pool,
        "selected": selected,
        "status": (
            "candidate_pool_ready"
            if selected
            else "insufficient_balanced_publications"
            if review_pair_capacity_upper_bound < 1
            else "insufficient_after_codex_review"
        ),
        "series_attempts": attempts,
    }


def evaluate_series(
    patch_row: dict[str, Any],
    history: list[SourcePublication],
    metadata: CveMetadata,
    *,
    payload: dict[str, Any],
    output: Path,
    arch: str,
    include_esm: bool,
    max_candidates_per_side: int,
    deadline: float,
    source_download_timeout: int,
    refresh: bool,
    log: Callable[[str], None] | None,
) -> dict[str, Any]:
    series = patch_row["ubuntu_series"]
    fixed_version = patch_row["fixed_source_version"]
    fixed_publication = select_exact_publication(history, fixed_version, patch_row["pocket"])
    publications = candidate_publications(history, include_esm=include_esm)
    fixed_date, fixed_anchor = resolve_fixed_anchor(
        payload,
        patch_row,
        publications,
        fixed_publication=fixed_publication,
    )
    attempt: dict[str, Any] = {
        "series": series,
        "ubuntu_release": patch_row["ubuntu_release"],
        "fixed_source_version": fixed_version,
        "fixed_source_publication": publication_json(fixed_publication),
        "fixed_time_anchor": fixed_anchor,
        "status": "insufficient",
        "reason": "",
        "candidate_matrix": [],
        "selection": None,
    }
    if not fixed_date:
        attempt["reason"] = "no usable fixed-version time anchor"
        return attempt
    raw_vuln = []
    raw_patch = []
    for publication in publications:
        published = publication_datetime(publication)
        if not published:
            continue
        comparison = debian_compare(publication.source_version, fixed_version)
        days = (published - fixed_date).total_seconds() / 86400.0
        if comparison < 0:
            raw_vuln.append((abs(days), publication, days))
        else:
            raw_patch.append((abs(days), publication, days))
    raw_vuln.sort(key=lambda item: (item[0], item[1].source_version))
    raw_patch.sort(key=lambda item: (item[0], item[1].source_version))
    if len(raw_vuln) + len(raw_patch) < 2:
        attempt["reason"] = f"source history has only {len(raw_vuln) + len(raw_patch)} usable candidate"
        return attempt

    precheck_limit = max_candidates_per_side * PRECHECK_RESERVE_MULTIPLIER
    for side, candidates in (("vuln", raw_vuln), ("patch", raw_patch)):
        for history_rank, history_quantile, publication, days in spread_temporal_candidates(
            candidates,
            limit=precheck_limit,
        ):
            if deadline and time.monotonic() >= deadline:
                attempt["reason"] = "selection time budget exhausted"
                attempt["status"] = "budget_exhausted"
                return attempt
            record = precheck_candidate(
                publication,
                side=side,
                days_from_fix=days,
                history_rank=history_rank,
                history_quantile=history_quantile,
                output=output,
                arch=arch,
                refresh=refresh,
            )
            attempt["candidate_matrix"].append(record)
            if log:
                log(
                    f"3v3-precheck cve={metadata.cve_id} series={series} side={side} "
                    f"version={publication.source_version} binary_ready={record['precheck_ready']}"
                )
    assign_sampling_metadata(attempt["candidate_matrix"])
    precheck_vuln = [
        item for item in attempt["candidate_matrix"] if item["side"] == "vuln" and item["precheck_ready"]
    ]
    precheck_patch = [
        item for item in attempt["candidate_matrix"] if item["side"] == "patch" and item["precheck_ready"]
    ]
    attempt["precheck_vulnerable"] = precheck_vuln
    attempt["precheck_patch"] = precheck_patch
    attempt["eligible_vulnerable"] = []
    attempt["eligible_patch"] = []
    attempt["temporal_pair_capacity"] = min(len(precheck_vuln), len(precheck_patch))
    attempt["review_pair_capacity_upper_bound"] = len(
        {item["source_version"] for item in (*precheck_vuln, *precheck_patch)}
    ) // 2
    attempt["initial_review_candidate_ids"] = sorted(
        initial_review_candidate_ids(attempt, max_candidates_per_side)
    )
    attempt["precheck_limit_per_side"] = precheck_limit
    attempt["status"] = "prechecked"
    attempt["reason"] = (
        f"binary availability left {len(precheck_vuln)} vuln and {len(precheck_patch)} patch candidates"
    )
    return attempt


def review_attempt_sources(
    attempt: dict[str, Any],
    metadata: CveMetadata,
    *,
    candidate_ids: set[str] | None = None,
    output: Path,
    deadline: float,
    source_download_timeout: int,
    refresh: bool,
    log: Callable[[str], None] | None,
    source_review_timeout: int = 300,
) -> None:
    if attempt.get("status") not in {"prechecked", "candidates_ready", "review_insufficient"}:
        return
    candidates = []
    for candidate in attempt.get("candidate_matrix") or []:
        if not candidate.get("precheck_ready") or (
            candidate_ids is not None and candidate["candidate_id"] not in candidate_ids
        ):
            continue
        candidate["review_attempted"] = True
        publication = SourcePublication(**candidate["source_publication"])
        extracted_path, _ = source_extracted_path(publication, output / "sources")
        candidate["source_materialization"] = {
            "status": "review_cache_probe",
            "extracted_path": str(extracted_path),
        }
        candidates.append(candidate)

    review = None
    cache_hit = False
    if candidates and not refresh:
        review = load_cached_source_review(
            metadata,
            candidates,
            output=output,
            series=str(attempt.get("series") or "series"),
        )
        cache_hit = review is not None
        if cache_hit:
            for candidate in candidates:
                candidate["source_materialization"]["status"] = "review_cache_reused"
            if log:
                log(
                    f"codex-source-review cache-hit cve={metadata.cve_id} "
                    f"series={attempt.get('series')} candidates={len(candidates)}"
                )

    reviewable = []
    for candidate in candidates if review is None else []:
        remaining_seconds = int(deadline - time.monotonic()) if deadline else source_download_timeout
        if deadline and remaining_seconds <= 0:
            candidate["rejection_reasons"].append("selection time budget exhausted")
            continue
        publication = SourcePublication(**candidate["source_publication"])
        materialization = materialize_source_publication(
            publication,
            cache_dir=output / "sources",
            refresh=refresh,
            download_timeout=max(5, min(source_download_timeout, remaining_seconds)),
            total_timeout=max(5, remaining_seconds),
        )
        candidate["source_materialization"] = materialization
        if materialization.get("status") != "ok":
            candidate["rejection_reasons"].append("source package materialization failed")
            continue
        reviewable.append(candidate)

    if review is None:
        review = {"status": "failed", "items": [], "notes": "no source candidates materialized"}
    if reviewable and review.get("status") == "failed":
        remaining_seconds = int(deadline - time.monotonic()) if deadline else source_review_timeout
        review_timeout = min(source_review_timeout, remaining_seconds) if deadline else source_review_timeout
        review = review_source_candidates(
            metadata,
            reviewable,
            output=output,
            series=str(attempt.get("series") or "series"),
            refresh=refresh,
            timeout=max(1, review_timeout),
            log=log,
        )
    review_summary = {
        "status": review.get("status"),
        "notes": review.get("notes", ""),
        "codex_seconds": review.get("codex_seconds", 0),
        "codex_events_path": review.get("codex_events_path", ""),
        "candidate_ids": [item["candidate_id"] for item in candidates],
        "cache_hit": cache_hit,
    }
    attempt["codex_source_review"] = review_summary
    attempt.setdefault("codex_source_review_rounds", []).append(review_summary)
    reviewed = {
        str(item.get("candidate_id") or ""): item
        for item in review.get("items") or []
        if isinstance(item, dict)
    }
    for candidate in candidates if cache_hit else reviewable:
        item = reviewed.get(candidate["candidate_id"])
        if item is None:
            candidate["source_validation"] = {
                "reviewer": "codex_exec",
                "classified_label": "inconclusive",
                "functions_available": False,
                "reason": "Codex review did not return this candidate",
                "evidence": [],
                "function_mappings": [],
            }
            candidate["rejection_reasons"].append("Codex source review missing or failed")
        else:
            classified_label = item.get("classified_label", "inconclusive")
            candidate["source_validation"] = {
                "reviewer": "codex_exec",
                "classified_label": classified_label,
                "functions_available": bool(item.get("functions_available")),
                "confidence": item.get("confidence", 0),
                "reason": item.get("reason", ""),
                "evidence": item.get("evidence") or [],
                "function_mappings": item.get("function_mappings") or [],
            }
            if not item.get("functions_available"):
                candidate["rejection_reasons"].append("affected functions are unavailable according to Codex review")
            if classified_label not in {"vuln", "patch"}:
                candidate["rejection_reasons"].append("Codex source review was inconclusive")
            else:
                candidate["temporal_side"] = candidate["side"]
                candidate["side"] = classified_label
        candidate["eligible"] = not candidate["rejection_reasons"]
        if log:
            log(
                f"3v3-review cve={metadata.cve_id} series={attempt['series']} "
                f"temporal_side={candidate.get('temporal_side', candidate['side'])} "
                f"classified={candidate['source_validation'].get('classified_label')} "
                f"version={candidate['source_version']} eligible={candidate['eligible']}"
            )

    eligible_vuln = sorted(
        (
            item
            for item in attempt.get("candidate_matrix") or []
            if item["side"] == "vuln" and item["eligible"]
        ),
        key=candidate_distance_key,
    )
    eligible_patch = sorted(
        (
            item
            for item in attempt.get("candidate_matrix") or []
            if item["side"] == "patch" and item["eligible"]
        ),
        key=candidate_distance_key,
    )
    attempt["eligible_vulnerable"] = eligible_vuln
    attempt["eligible_patch"] = eligible_patch
    attempt["status"] = "candidates_ready" if eligible_vuln and eligible_patch else "review_insufficient"
    attempt["reason"] = (
        f"Codex review left {len(eligible_vuln)} vuln and {len(eligible_patch)} patch candidates"
    )


def selection_from_pairs(pairs: list[dict[str, Any]]) -> dict[str, Any]:
    if not 1 <= len(pairs) <= 3:
        raise ValueError("a final selection requires one to three balanced pairs")
    if not balanced_pair_versions_unique(pairs):
        raise ValueError("a final selection requires distinct source versions on both labels")
    series = list(dict.fromkeys(str(item.get("series") or "") for item in pairs))
    vulnerable = [item["vulnerable"] for item in pairs]
    patched = [item["patch"] for item in pairs]
    return {
        "series": series[0] if len(series) == 1 else "+".join(series),
        "series_used": series,
        "ubuntu_release": pairs[0].get("ubuntu_release") or "",
        "fixed_source_version": pairs[0].get("fixed_source_version") or "",
        "count_per_label": len(pairs),
        "vulnerable": vulnerable,
        "patch": patched,
        "pairs": [
            {
                "series": item.get("series") or "",
                "vuln_source_version": item["vulnerable"]["source_version"],
                "vuln_days_from_fix": item["vulnerable"]["days_from_fix"],
                "patch_source_version": item["patch"]["source_version"],
                "patch_days_from_fix": item["patch"]["days_from_fix"],
                "distance_mismatch_days": item["distance_mismatch_days"],
                "sampling_stratum": item.get("sampling_stratum") or "mixed",
            }
            for item in pairs
        ],
        "selection_score": {
            "total_distance_days": round(
                sum(abs(item["days_from_fix"]) for item in [*vulnerable, *patched]),
                4,
            ),
            "symmetry_error_days": round(sum(item["distance_mismatch_days"] for item in pairs), 4),
            "series_count": len(series),
            "sampling_strata": [item.get("sampling_stratum") or "mixed" for item in pairs],
        },
    }


def expand_selection_result(
    result: dict[str, Any],
    metadata: CveMetadata,
    *,
    output: Path,
    preferred_strata: list[str] | tuple[str, ...] = SAMPLING_STRATA,
    per_stratum: int = 1,
    max_per_label: int = 3,
    max_selection_minutes: float = 20.0,
    source_download_timeout: int = 90,
    source_review_timeout: int = 300,
    refresh: bool = False,
    log: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    before_pairs = pair_signatures((result.get("candidate_pool") or {}).get("pairs") or [])
    reviewed_ids = []
    deadline = time.monotonic() + max_selection_minutes * 60 if max_selection_minutes > 0 else 0.0
    for attempt in result.get("series_attempts") or []:
        candidate_ids = fallback_review_candidate_ids(
            attempt,
            preferred_strata=preferred_strata,
            per_stratum=per_stratum,
        )
        if not candidate_ids:
            continue
        review_attempt_sources(
            attempt,
            metadata,
            candidate_ids=candidate_ids,
            output=output,
            deadline=deadline,
            source_download_timeout=source_download_timeout,
            source_review_timeout=source_review_timeout,
            refresh=refresh,
            log=log,
        )
        reviewed_ids.extend(sorted(candidate_ids))
        refreshed_pairs = rebuild_balanced_pairs(result.get("series_attempts") or [])
        if pair_signatures(refreshed_pairs) - before_pairs:
            break
    refresh_selection_result(result, max_per_label=max_per_label)
    after_pairs = pair_signatures((result.get("candidate_pool") or {}).get("pairs") or [])
    report = {
        "round": len(result.get("source_fallback_rounds") or []) + 1,
        "preferred_strata": list(preferred_strata),
        "reviewed_candidate_ids": reviewed_ids,
        "new_pair_count": len(after_pairs - before_pairs),
        "reserve_candidate_count": (result.get("candidate_pool") or {}).get("reserve_candidate_count", 0),
    }
    result.setdefault("source_fallback_rounds", []).append(report)
    return report


def refresh_selection_result(result: dict[str, Any], *, max_per_label: int = 3) -> None:
    attempts = result.get("series_attempts") or []
    balanced_pairs = rebuild_balanced_pairs(attempts)
    selected_pairs = primary_balanced_pairs(balanced_pairs, max_per_label=max_per_label)
    selected = selection_from_pairs(selected_pairs) if selected_pairs else None
    pool = result.setdefault("candidate_pool", {})
    pool.update(
        {
            "target_count_per_label": len(selected_pairs),
            "pair_count": len(balanced_pairs),
            "vulnerable": [item["vulnerable"] for item in balanced_pairs],
            "patch": [item["patch"] for item in balanced_pairs],
            "pairs": balanced_pairs,
            "reviewed_candidate_count": sum(reviewed_candidate_count(item) for item in attempts),
            "reserve_candidate_count": sum(reserve_candidate_count(item) for item in attempts),
        }
    )
    result["selected"] = selected
    result["status"] = "candidate_pool_ready" if selected else "insufficient_after_codex_review"


def precheck_candidate(
    publication: SourcePublication,
    *,
    side: str,
    days_from_fix: float,
    history_rank: int,
    history_quantile: float,
    output: Path,
    arch: str,
    refresh: bool,
) -> dict[str, Any]:
    rejection_reasons = []
    try:
        availability = publication_binary_availability(
            publication,
            arch=arch,
            cache_dir=output / "state" / "binary_availability",
            refresh=refresh,
        )
    except Exception as exc:
        availability = {"checked": False, "ready": False, "reason": str(exc), "arch": arch}
    if not availability.get("ready"):
        rejection_reasons.append("runtime/debug deb pair unavailable")
    return {
        "candidate_id": safe_name(f"{side}-{publication.series}-{publication.source_version}"),
        "side": side,
        "source_version": publication.source_version,
        "series": publication.series,
        "pocket": publication.pocket,
        "component": publication.component,
        "days_from_fix": round(days_from_fix, 4),
        "history_rank": history_rank,
        "history_quantile": round(history_quantile, 4),
        "sampling_position": 0.0,
        "sampling_stratum": "near",
        "source_publication": publication.to_json(),
        "binary_availability": availability,
        "source_materialization": {"status": "skipped", "extracted_path": ""},
        "source_validation": {
            "reviewer": "codex_exec",
            "classified_label": "not_reviewed",
            "functions_available": False,
        },
        "precheck_ready": not rejection_reasons,
        "review_attempted": False,
        "eligible": False,
        "rejection_reasons": rejection_reasons,
    }


def candidate_publications(
    history: list[SourcePublication],
    *,
    include_esm: bool,
) -> list[SourcePublication]:
    allowed_pockets = {"release", "updates", "security"}
    if include_esm:
        allowed_pockets.update({"esm-apps", "esm-infra"})
    by_version: dict[str, SourcePublication] = {}
    for item in history:
        if item.status == "Deleted" or item.pocket.strip().lower() not in allowed_pockets:
            continue
        previous = by_version.get(item.source_version)
        if previous is None or publication_datetime_key(item) < publication_datetime_key(previous):
            by_version[item.source_version] = item
    return list(by_version.values())


def resolve_fixed_anchor(
    payload: dict[str, Any],
    patch_row: dict[str, Any],
    publications: list[SourcePublication],
    *,
    fixed_publication: SourcePublication | None,
) -> tuple[datetime | None, dict[str, Any]]:
    if fixed_publication:
        published = publication_datetime(fixed_publication)
        if published:
            return published, {
                "source": "exact_fixed_publication",
                "datetime": published.isoformat(),
                "publication": publication_json(fixed_publication),
            }

    notice_ids = {str(item) for item in patch_row.get("notice_ids") or [] if item}
    notice_dates = []
    for notice in payload.get("notices") or []:
        notice_id = str(notice.get("id") or "")
        if notice_ids and notice_id not in notice_ids:
            continue
        if not notice_ids and not notice_matches_patch_row(notice, patch_row):
            continue
        published = parse_datetime(
            notice.get("published") or notice.get("date_published") or notice.get("date")
        )
        if published:
            notice_dates.append((published, notice_id))
    if notice_dates:
        published, notice_id = min(notice_dates)
        return published, {
            "source": "ubuntu_security_notice",
            "datetime": published.isoformat(),
            "notice_id": notice_id,
            "exact_fixed_publication_missing": fixed_publication is None,
        }

    ordered = sorted(
        (item for item in publications if publication_datetime(item)),
        key=cmp_to_key(lambda left, right: debian_compare(left.source_version, right.source_version)),
    )
    if not ordered:
        return None, {"source": "unavailable", "datetime": ""}
    fixed_version = str(patch_row.get("fixed_source_version") or "")
    later = [item for item in ordered if debian_compare(item.source_version, fixed_version) >= 0]
    nearest = later[0] if later else ordered[-1]
    published = publication_datetime(nearest)
    return published, {
        "source": "nearest_source_publication",
        "datetime": published.isoformat() if published else "",
        "publication": publication_json(nearest),
        "exact_fixed_publication_missing": fixed_publication is None,
        "approximate": True,
    }


def notice_matches_patch_row(notice: dict[str, Any], patch_row: dict[str, Any]) -> bool:
    series = str(patch_row.get("ubuntu_series") or "")
    source_package = str(patch_row.get("source_package") or "")
    fixed_version = str(patch_row.get("fixed_source_version") or "")
    for item in (notice.get("release_packages") or {}).get(series) or []:
        if not item.get("is_source"):
            continue
        if source_package and item.get("name") != source_package:
            continue
        if fixed_version and item.get("version") != fixed_version:
            continue
        return True
    return False


def publication_datetime(publication: SourcePublication) -> datetime | None:
    value = publication.date_published or publication.date_created
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def publication_datetime_key(publication: SourcePublication) -> tuple[int, datetime]:
    parsed = publication_datetime(publication)
    return (0, parsed) if parsed else (1, datetime.max.replace(tzinfo=timezone.utc))


def release_sort_key(row: dict[str, Any]) -> tuple[int, int]:
    release = str(row.get("ubuntu_release") or "0.0")
    try:
        major, minor = release.split(".", 1)
        return int(major), int(minor)
    except (TypeError, ValueError):
        return 0, 0


def safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in "_.-" else "-" for char in value) or "source"
