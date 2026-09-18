"""Launchpad source-publication history with per-series persistent caching."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit

from ..io_utils import read_json, write_json
from .launchpad import ARCHIVE, launchpad_get, publication_preference
from ..versions import debian_sort_key


@dataclass(frozen=True)
class SourcePublication:
    source_package: str
    source_version: str
    series: str
    pocket: str
    component: str
    status: str
    self_link: str
    date_published: str
    date_created: str
    provenance: str = "launchpad_api_getPublishedSources"

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def load_source_history(
    source_package: str,
    series: list[str],
    *,
    cache_path: Path,
    refresh: bool,
    log=None,
) -> dict[str, list[SourcePublication]]:
    cached: dict[str, Any] = {}
    if cache_path.exists() and not refresh:
        try:
            cached = read_json(cache_path)
        except (OSError, ValueError):
            cached = {}
    changed = False
    output: dict[str, list[SourcePublication]] = {}
    for index, ubuntu_series in enumerate(series, start=1):
        # Cache each series independently so adding a new series does not refetch old history.
        raw_items = cached.get(ubuntu_series)
        if raw_items is None:
            raw_items = []
            for status in ("Published", "Superseded", "Deleted"):
                raw_items.extend(fetch_source_publications(source_package, ubuntu_series, status))
            cached[ubuntu_series] = raw_items
            changed = True
            write_json(cache_path, cached)
        output[ubuntu_series] = dedupe_source_publications(SourcePublication(**item) for item in raw_items)
        if log:
            log(f"source-history {index}/{len(series)} series={ubuntu_series} publications={len(output[ubuntu_series])}")
    if changed:
        write_json(cache_path, cached)
    return output


def fetch_source_publications(source_package: str, series: str, status: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    params = {
        "ws.op": "getPublishedSources",
        "source_name": source_package,
        "exact_match": "true",
        "status": status,
        "distro_series": f"/ubuntu/{series}",
        "ws.size": "100",
    }
    data = launchpad_get(ARCHIVE, params)
    while True:
        for item in data.get("entries") or []:
            if item.get("source_package_name") != source_package:
                continue
            if not str(item.get("distro_series_link") or "").endswith(f"/{series}"):
                continue
            entries.append(
                SourcePublication(
                    source_package=source_package,
                    source_version=str(item.get("source_package_version") or ""),
                    series=series,
                    pocket=str(item.get("pocket") or ""),
                    component=str(item.get("component_name") or ""),
                    status=str(item.get("status") or ""),
                    self_link=str(item.get("self_link") or ""),
                    date_published=str(item.get("date_published") or ""),
                    date_created=str(item.get("date_created") or ""),
                ).to_json()
            )
        next_url = data.get("next_collection_link")
        if not next_url:
            return entries
        data = launchpad_get(next_url.split("?", 1)[0], dict(parse_qsl(urlsplit(next_url).query, keep_blank_values=True)))


def dedupe_source_publications(items: Iterable[SourcePublication]) -> list[SourcePublication]:
    by_key: dict[tuple[str, str, str, str], SourcePublication] = {}
    for item in items:
        key = (item.source_version, item.series, item.pocket, item.component)
        previous = by_key.get(key)
        if previous is None or source_publication_preference(item) < source_publication_preference(previous):
            by_key[key] = item
    return sorted(by_key.values(), key=lambda item: debian_sort_key(item.source_version))


def source_publication_preference(item: SourcePublication) -> tuple[int, int, str]:
    return publication_preference(
        {
            "pocket": item.pocket,
            "status": item.status,
            "date_published": item.date_published,
            "date_created": item.date_created,
        }
    )
