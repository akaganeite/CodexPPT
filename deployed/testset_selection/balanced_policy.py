"""Balanced source-version pairing and near/mid/far combination ranking."""

from __future__ import annotations

from collections import Counter
from itertools import combinations
from typing import Any

from .temporal_sampling import SAMPLING_STRATA, candidate_pair_key


def rebuild_balanced_pairs(attempts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    balanced_pairs: list[dict[str, Any]] = []
    for series_rank, attempt in enumerate(attempts):
        extend_unique_balanced_pairs(balanced_pairs, attempt, series_rank=series_rank)
    return balanced_pairs


def pair_signatures(pairs: list[dict[str, Any]]) -> set[tuple[str, str, str]]:
    return {
        (
            str(item.get("series") or ""),
            str(item["vulnerable"].get("source_version") or ""),
            str(item["patch"].get("source_version") or ""),
        )
        for item in pairs
    }


def primary_balanced_pairs(
    pairs: list[dict[str, Any]],
    *,
    max_per_label: int = 3,
) -> list[dict[str, Any]]:
    if not 1 <= max_per_label <= 3:
        raise ValueError("max_per_label must be between one and three")
    for count in range(min(max_per_label, len(pairs)), 0, -1):
        ranked = sorted(
            (items for items in combinations(pairs, count) if balanced_pair_versions_unique(items)),
            key=balanced_pair_combination_key,
        )
        if ranked:
            return order_combination_pairs(list(ranked[0]))
    return []


def balanced_pair_combination_key(
    items: tuple[dict[str, Any], ...] | list[dict[str, Any]],
) -> tuple[Any, ...]:
    desired = {1: ("near",), 2: ("near", "far"), 3: SAMPLING_STRATA}[len(items)]
    actual = Counter(str(item.get("sampling_stratum") or "mixed") for item in items)
    missing = sum(1 for stratum in desired if actual[stratum] < 1)
    duplicate_or_mixed = sum(
        max(0, count - 1) for stratum, count in actual.items() if stratum != "mixed"
    ) + actual["mixed"]
    return (
        missing,
        duplicate_or_mixed,
        max(int(item.get("series_rank") or 0) for item in items),
        sum(int(item.get("series_rank") or 0) for item in items),
        round(sum(float(item.get("distance_mismatch_days") or 0.0) for item in items), 4),
        round(
            sum(
                abs(float(item["vulnerable"].get("days_from_fix") or 0.0))
                + abs(float(item["patch"].get("days_from_fix") or 0.0))
                for item in items
            ),
            4,
        ),
        tuple(
            sorted(
                (
                    str(item["vulnerable"].get("source_version") or ""),
                    str(item["patch"].get("source_version") or ""),
                )
                for item in items
            )
        ),
    )


def order_combination_pairs(pairs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    desired = {1: ("near",), 2: ("near", "far"), 3: SAMPLING_STRATA}[len(pairs)]
    order = {stratum: index for index, stratum in enumerate(desired)}
    return sorted(
        pairs,
        key=lambda item: (
            order.get(str(item.get("sampling_stratum") or "mixed"), len(order)),
            int(item.get("series_rank") or 0),
            float(item.get("distance_mismatch_days") or 0.0),
        ),
    )


def extend_unique_balanced_pairs(
    balanced_pairs: list[dict[str, Any]],
    attempt: dict[str, Any],
    *,
    series_rank: int,
) -> None:
    vulnerable = list(attempt.get("eligible_vulnerable") or [])
    patched = list(attempt.get("eligible_patch") or [])
    local_pairs = []
    for stratum in SAMPLING_STRATA:
        pair_candidate_groups(
            local_pairs,
            [item for item in vulnerable if item.get("sampling_stratum") == stratum],
            [item for item in patched if item.get("sampling_stratum") == stratum],
            attempt=attempt,
            series_rank=series_rank,
            sampling_stratum=stratum,
        )
    paired_versions = {
        str(row.get("source_version") or "")
        for pair in local_pairs
        for row in (pair["vulnerable"], pair["patch"])
    }
    pair_candidate_groups(
        local_pairs,
        [item for item in vulnerable if str(item.get("source_version") or "") not in paired_versions],
        [item for item in patched if str(item.get("source_version") or "") not in paired_versions],
        attempt=attempt,
        series_rank=series_rank,
        sampling_stratum="mixed",
    )
    local_pairs.sort(key=single_pair_key)
    for within_series_rank, pair in enumerate(local_pairs):
        pair["within_series_rank"] = within_series_rank
        balanced_pairs.append(pair)


def pair_candidate_groups(
    output: list[dict[str, Any]],
    vulnerable: list[dict[str, Any]],
    patched: list[dict[str, Any]],
    *,
    attempt: dict[str, Any],
    series_rank: int,
    sampling_stratum: str,
) -> None:
    vulnerable = list(vulnerable)
    patched = list(patched)
    while vulnerable and patched:
        options = [
            (candidate_pair_key(vuln, patch), vuln, patch)
            for vuln in vulnerable
            for patch in patched
            if str(vuln.get("source_version") or "") != str(patch.get("source_version") or "")
        ]
        if not options:
            return
        _, vuln, patch = min(options, key=lambda item: item[0])
        output.append(
            {
                "series": attempt["series"],
                "ubuntu_release": attempt["ubuntu_release"],
                "fixed_source_version": attempt["fixed_source_version"],
                "series_rank": series_rank,
                "within_series_rank": 0,
                "sampling_stratum": sampling_stratum,
                "vulnerable": vuln,
                "patch": patch,
                "distance_mismatch_days": round(
                    abs(abs(float(vuln["days_from_fix"])) - abs(float(patch["days_from_fix"]))),
                    4,
                ),
            }
        )
        vulnerable.remove(vuln)
        patched.remove(patch)


def single_pair_key(pair: dict[str, Any]) -> tuple[Any, ...]:
    return (
        {"near": 0, "mid": 1, "far": 2, "mixed": 3}.get(
            str(pair.get("sampling_stratum") or "mixed"),
            3,
        ),
        float(pair.get("distance_mismatch_days") or 0.0),
        str(pair["vulnerable"].get("source_version") or ""),
        str(pair["patch"].get("source_version") or ""),
    )


def balanced_pair_versions_unique(pairs: list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> bool:
    vulnerable = [str(item["vulnerable"].get("source_version") or "") for item in pairs]
    patched = [str(item["patch"].get("source_version") or "") for item in pairs]
    return (
        all(vulnerable)
        and all(patched)
        and len(vulnerable) == len(set(vulnerable))
        and len(patched) == len(set(patched))
        and set(vulnerable).isdisjoint(patched)
    )
