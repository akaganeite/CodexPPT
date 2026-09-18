"""Time-spread source candidate annotation and review-batch selection."""

from __future__ import annotations

from typing import Any

from ..candidate_discovery.source_history import SourcePublication


SAMPLING_STRATA = ("near", "mid", "far")
SAMPLING_TARGETS = {"near": 0.2, "mid": 0.5, "far": 0.8}
PRECHECK_RESERVE_MULTIPLIER = 3


def candidate_distance_key(item: dict[str, Any]) -> tuple[float, str]:
    return abs(float(item.get("days_from_fix") or 0.0)), str(item.get("source_version") or "")


def spread_temporal_candidates(
    candidates: list[tuple[float, SourcePublication, float]],
    *,
    limit: int,
) -> list[tuple[int, float, SourcePublication, float]]:
    if not candidates or limit < 1:
        return []
    count = len(candidates)
    if count <= limit:
        indices = list(range(count))
    elif limit == 1:
        indices = [0]
    else:
        indices = []
        for offset in range(limit):
            index = round(offset * (count - 1) / (limit - 1))
            if index not in indices:
                indices.append(index)
        indices.extend(index for index in range(count) if index not in indices)
        indices = indices[:limit]
    return [
        (
            index,
            index / (count - 1) if count > 1 else 0.0,
            candidates[index][1],
            candidates[index][2],
        )
        for index in indices
    ]


def assign_sampling_metadata(candidates: list[dict[str, Any]]) -> None:
    ready_by_side = {
        side: [
            item
            for item in candidates
            if item.get("precheck_ready") and temporal_side(item) == side
        ]
        for side in ("vuln", "patch")
    }
    maxima = {
        side: max((abs(float(item.get("days_from_fix") or 0.0)) for item in rows), default=0.0)
        for side, rows in ready_by_side.items()
    }
    positive_maxima = [value for value in maxima.values() if value > 0]
    common_horizon = min(positive_maxima) if len(positive_maxima) == 2 else max(positive_maxima, default=0.0)
    if common_horizon <= 0:
        common_horizon = max(
            (abs(float(item.get("days_from_fix") or 0.0)) for item in candidates),
            default=1.0,
        ) or 1.0
    annotated = set()
    for rows in ready_by_side.values():
        ordered = sorted(rows, key=candidate_distance_key)
        for rank, item in enumerate(ordered):
            position = rank / (len(ordered) - 1) if len(ordered) > 1 else 0.0
            item["sampling_position"] = round(position, 4)
            item["sampling_stratum"] = stratum_for_position(position)
            item["sampling_horizon_days"] = round(common_horizon, 4)
            item["sampling_side_rank"] = rank
            annotated.add(id(item))
    for item in candidates:
        if id(item) in annotated:
            continue
        position = float(item.get("history_quantile") or 0.0)
        item["sampling_position"] = round(position, 4)
        item["sampling_stratum"] = stratum_for_position(position)
        item["sampling_horizon_days"] = round(common_horizon, 4)


def stratum_for_position(position: float) -> str:
    return "near" if position < 1 / 3 else "mid" if position < 2 / 3 else "far"


def temporal_side(candidate: dict[str, Any]) -> str:
    return str(candidate.get("temporal_side") or candidate.get("side") or "")


def sampling_candidate_key(candidate: dict[str, Any]) -> tuple[float, float, int, str]:
    stratum = str(candidate.get("sampling_stratum") or "near")
    position = float(candidate.get("sampling_position") or 0.0)
    return (
        abs(position - SAMPLING_TARGETS.get(stratum, 0.0)),
        abs(float(candidate.get("days_from_fix") or 0.0)),
        int(candidate.get("history_rank") or 0),
        str(candidate.get("source_version") or ""),
    )


def candidate_pair_key(vulnerable: dict[str, Any], patched: dict[str, Any]) -> tuple[Any, ...]:
    return (
        abs(
            abs(float(vulnerable.get("days_from_fix") or 0.0))
            - abs(float(patched.get("days_from_fix") or 0.0))
        ),
        sampling_candidate_key(vulnerable),
        sampling_candidate_key(patched),
    )


def stratified_candidate_order(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups = {
        stratum: sorted(
            (item for item in candidates if item.get("sampling_stratum") == stratum),
            key=sampling_candidate_key,
        )
        for stratum in SAMPLING_STRATA
    }
    ordered = []
    while any(groups.values()):
        for stratum in SAMPLING_STRATA:
            if groups[stratum]:
                ordered.append(groups[stratum].pop(0))
    return ordered


def initial_review_candidate_ids(attempt: dict[str, Any], limit_per_side: int) -> set[str]:
    ready_by_side = {
        side: [
            item
            for item in attempt.get("candidate_matrix") or []
            if item.get("precheck_ready")
            and temporal_side(item) == side
            and not item.get("review_attempted")
        ]
        for side in ("vuln", "patch")
    }
    selected = set()
    counts = {"vuln": 0, "patch": 0}
    for stratum in SAMPLING_STRATA:
        if counts["vuln"] >= limit_per_side or counts["patch"] >= limit_per_side:
            break
        vulnerable = [item for item in ready_by_side["vuln"] if item.get("sampling_stratum") == stratum]
        patched = [item for item in ready_by_side["patch"] if item.get("sampling_stratum") == stratum]
        options = [
            (candidate_pair_key(vuln, patch), vuln, patch)
            for vuln in vulnerable
            for patch in patched
            if str(vuln.get("source_version") or "") != str(patch.get("source_version") or "")
        ]
        if not options:
            continue
        _, vuln, patch = min(options, key=lambda item: item[0])
        selected.update((vuln["candidate_id"], patch["candidate_id"]))
        counts["vuln"] += 1
        counts["patch"] += 1
    for side in ("vuln", "patch"):
        remaining = [item for item in ready_by_side[side] if item["candidate_id"] not in selected]
        needed = max(0, limit_per_side - counts[side])
        selected.update(item["candidate_id"] for item in stratified_candidate_order(remaining)[:needed])
    return selected


def reviewed_candidate_count(attempt: dict[str, Any]) -> int:
    return sum(bool(item.get("review_attempted")) for item in attempt.get("candidate_matrix") or [])


def reserve_candidate_count(attempt: dict[str, Any]) -> int:
    return sum(
        bool(item.get("precheck_ready")) and not item.get("review_attempted")
        for item in attempt.get("candidate_matrix") or []
    )


def fallback_review_candidate_ids(
    attempt: dict[str, Any],
    *,
    preferred_strata: list[str] | tuple[str, ...] = SAMPLING_STRATA,
    per_stratum: int = 1,
) -> set[str]:
    available = [
        item
        for item in attempt.get("candidate_matrix") or []
        if item.get("precheck_ready") and not item.get("review_attempted")
    ]
    preferred = list(dict.fromkeys(preferred_strata))
    remaining = [stratum for stratum in SAMPLING_STRATA if stratum not in preferred]
    for strata in (preferred, remaining):
        selected = set()
        for stratum in strata:
            by_side = {
                side: sorted(
                    (
                        item
                        for item in available
                        if temporal_side(item) == side and item.get("sampling_stratum") == stratum
                    ),
                    key=sampling_candidate_key,
                )
                for side in ("vuln", "patch")
            }
            if not by_side["vuln"] or not by_side["patch"]:
                continue
            for side in ("vuln", "patch"):
                selected.update(item["candidate_id"] for item in by_side[side][:per_stratum])
        if selected:
            return selected
    selected = set()
    by_side = {
        side: stratified_candidate_order([item for item in available if temporal_side(item) == side])
        for side in ("vuln", "patch")
    }
    if by_side["vuln"] and by_side["patch"]:
        selected.add(by_side["vuln"][0]["candidate_id"])
        selected.add(by_side["patch"][0]["candidate_id"])
        return selected
    unpaired = stratified_candidate_order(
        [item for item in available if item.get("sampling_stratum") in preferred or not preferred]
    ) or stratified_candidate_order(available)
    selected.update(item["candidate_id"] for item in unpaired[: max(2, per_stratum * 2)])
    return selected
