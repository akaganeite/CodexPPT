from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .ubuntu_groundtruth import build_ubuntu_groundtruth
from .source_history import SourcePublication, load_source_history
from ..versions import debian_compare, debian_sort_key


def build_source_groundtruth_for_cve(
    payload: dict[str, Any],
    *,
    source_path: Path | None,
    state_dir: Path,
    series_filter: list[str] | None = None,
    include_esm: bool = False,
    max_vulnerable: int = 3,
    refresh: bool = False,
    log: Callable[[str], None] | None = None,
    source_history_loader: Callable[..., dict[str, list[SourcePublication]]] = load_source_history,
) -> dict[str, Any]:
    if max_vulnerable < 1:
        raise ValueError("max_vulnerable must be positive")
    parsed = build_ubuntu_groundtruth(
        payload,
        source_path=source_path,
        series_filter=series_filter or (),
        include_esm=include_esm,
    )
    patch_rows = parsed["security_patch_groundtruth"]
    grouped: dict[str, set[str]] = {}
    for row in patch_rows:
        grouped.setdefault(row["source_package"], set()).add(row["ubuntu_series"])

    histories: dict[tuple[str, str], list[SourcePublication]] = {}
    history_errors: list[dict[str, str]] = []
    state_dir.mkdir(parents=True, exist_ok=True)
    for source_package, series in sorted(grouped.items()):
        cache_path = state_dir / f"{safe_package_name(source_package)}.json"
        try:
            loaded = source_history_loader(
                source_package,
                sorted(series),
                cache_path=cache_path,
                refresh=refresh,
                log=log,
            )
            for item_series, items in loaded.items():
                histories[(source_package, item_series)] = items
        except Exception as exc:
            history_errors.append({"source_package": source_package, "error": str(exc)})

    output_rows = []
    for patch_row in patch_rows:
        key = (patch_row["source_package"], patch_row["ubuntu_series"])
        history = histories.get(key, [])
        fixed_version = patch_row["fixed_source_version"]
        patch_publication = select_exact_publication(history, fixed_version, patch_row["pocket"])
        vulnerable = (
            select_vulnerable_source_publications(history, fixed_version, max_count=max_vulnerable)
            if patch_publication
            else []
        )
        output_rows.append(
            {
                **patch_row,
                "patch_source_publication": publication_json(patch_publication),
                "patch_publication_found": patch_publication is not None,
                "source_groundtruth_status": "verified" if patch_publication else "json_only",
                "vulnerable_candidates": [publication_json(item) for item in vulnerable],
                "vulnerable_candidate_count": len(vulnerable),
                "source_history_count": len(history),
                "source_history_loaded": key in histories,
            }
        )
    output_rows.sort(key=lambda row: (row["cve_id"], row["source_package"], row["ubuntu_series"]))
    return {
        "schema": "ubuntu-source-groundtruth-v1",
        "cve_id": parsed["cve_id"],
        "source_json": parsed["source_json"],
        "ubuntu_security_url": parsed["ubuntu_security_url"],
        "series_filter": parsed["series_filter"],
        "include_esm": parsed["include_esm"],
        "max_vulnerable": max_vulnerable,
        "rows": output_rows,
        "history_errors": history_errors,
    }


def select_exact_publication(
    history: list[SourcePublication],
    version: str,
    preferred_pocket: str,
) -> SourcePublication | None:
    candidates = [item for item in history if item.source_version == version and item.status != "Deleted"]
    if not candidates:
        return None
    preferred = preferred_pocket.strip().lower()
    return sorted(
        candidates,
        key=lambda item: (
            0 if item.pocket.strip().lower() == preferred else 1,
            publication_status_rank(item.status),
            pocket_rank(item.pocket),
            item.date_published or item.date_created,
        ),
    )[0]


def select_vulnerable_source_publications(
    history: list[SourcePublication],
    fixed_version: str,
    *,
    max_count: int,
) -> list[SourcePublication]:
    candidates = [
        item
        for item in history
        if item.source_version
        and item.status != "Deleted"
        and item.pocket.strip().lower() != "proposed"
        and debian_compare(item.source_version, fixed_version) < 0
    ]
    by_version: dict[str, SourcePublication] = {}
    for item in candidates:
        previous = by_version.get(item.source_version)
        if previous is None or publication_preference(item) < publication_preference(previous):
            by_version[item.source_version] = item
    return sorted(by_version.values(), key=lambda item: debian_sort_key(item.source_version), reverse=True)[:max_count]


def publication_preference(item: SourcePublication) -> tuple[int, int, str]:
    return (
        pocket_rank(item.pocket),
        publication_status_rank(item.status),
        item.date_published or item.date_created,
    )


def pocket_rank(pocket: str) -> int:
    return {
        "security": 0,
        "updates": 1,
        "release": 2,
        "backports": 3,
        "proposed": 9,
    }.get(pocket.strip().lower(), 8)


def publication_status_rank(status: str) -> int:
    return {"Published": 0, "Superseded": 1, "Deleted": 9}.get(status, 8)


def publication_json(item: SourcePublication | None) -> dict[str, Any] | None:
    return item.to_json() if item else None


def safe_package_name(package: str) -> str:
    return "".join(char if char.isalnum() or char in "_.-" else "-" for char in package) or "source"
