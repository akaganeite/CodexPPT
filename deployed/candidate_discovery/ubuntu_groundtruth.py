from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable


SECURITY_CVE_URL = "https://ubuntu.com/security/cves/{cve_id}.json"
DEFAULT_RELEASE_CATALOG = {
    "lucid": "10.04",
    "maverick": "10.10",
    "natty": "11.04",
    "oneiric": "11.10",
    "precise": "12.04",
    "quantal": "12.10",
    "raring": "13.04",
    "saucy": "13.10",
    "trusty": "14.04",
    "utopic": "14.10",
    "vivid": "15.04",
    "wily": "15.10",
    "xenial": "16.04",
    "yakkety": "16.10",
    "zesty": "17.04",
    "artful": "17.10",
    "bionic": "18.04",
    "cosmic": "18.10",
    "disco": "19.04",
    "eoan": "19.10",
    "focal": "20.04",
    "groovy": "20.10",
    "hirsute": "21.04",
    "impish": "21.10",
    "jammy": "22.04",
    "kinetic": "22.10",
    "lunar": "23.04",
    "mantic": "23.10",
    "noble": "24.04",
    "oracular": "24.10",
    "plucky": "25.04",
    "questing": "25.10",
    "resolute": "26.04",
}
RELEASE_VERSION_RE = re.compile(r"^\S+$")


def build_ubuntu_groundtruth(
    payload: dict[str, Any],
    *,
    source_path: Path | None = None,
    source_url: str = "",
    series_filter: Iterable[str] | None = None,
    include_esm: bool = False,
    release_catalog: dict[str, str] | None = None,
) -> dict[str, Any]:
    catalog = dict(DEFAULT_RELEASE_CATALOG)
    catalog.update(release_catalog or {})
    requested_series = normalize_series_filter(series_filter or (), catalog)
    cve_id = detect_cve_id(payload, source_path)
    security_url = source_url or (SECURITY_CVE_URL.format(cve_id=cve_id) if cve_id else "")
    status_rows: list[dict[str, Any]] = []
    patch_rows: list[dict[str, Any]] = []
    for package_entry in payload.get("packages") or []:
        source_package = str(package_entry.get("name") or "")
        if not source_package:
            continue
        for raw_status in package_entry.get("statuses") or []:
            row = normalize_status_row(
                cve_id=cve_id,
                source_package=source_package,
                raw_status=raw_status,
                payload=payload,
                security_url=security_url,
                catalog=catalog,
                requested_series=requested_series,
                include_esm=include_esm,
            )
            if row is None:
                continue
            status_rows.append(row)
            if row["groundtruth_label"] == "patch":
                patch_rows.append(row)
    status_rows = dedupe_rows(status_rows)
    patch_rows = [row for row in dedupe_rows(patch_rows) if row["groundtruth_label"] == "patch"]
    status_rows.sort(key=status_sort_key)
    patch_rows.sort(key=status_sort_key)
    return {
        "schema": "ubuntu-release-groundtruth-v1",
        "cve_id": cve_id,
        "source_json": str(source_path) if source_path else "",
        "ubuntu_security_url": security_url,
        "release_catalog": catalog,
        "series_filter": sorted(requested_series),
        "include_esm": include_esm,
        "release_status": status_rows,
        "security_patch_groundtruth": patch_rows,
    }


def normalize_status_row(
    *,
    cve_id: str,
    source_package: str,
    raw_status: dict[str, Any],
    payload: dict[str, Any],
    security_url: str,
    catalog: dict[str, str],
    requested_series: set[str],
    include_esm: bool,
) -> dict[str, Any] | None:
    series = str(raw_status.get("release_codename") or "").strip().lower()
    if not series:
        return None
    release = catalog.get(series, "")
    if requested_series and series not in requested_series and release not in requested_series:
        return None
    status = normalize_status(raw_status.get("status"))
    pocket = normalize_pocket(raw_status.get("pocket"))
    description = str(raw_status.get("description") or "").strip()
    fixed_version = description if status == "released" and valid_version(description) else ""
    is_ubuntu_release = series not in {"upstream", "devel"}
    security_pocket = pocket == "security"
    esm_pocket = pocket.startswith("esm-")
    security_eligible = is_ubuntu_release and (security_pocket or (include_esm and esm_pocket))
    label, exclusion_reason = classify_groundtruth(
        status=status,
        fixed_version=fixed_version,
        is_ubuntu_release=is_ubuntu_release,
        security_eligible=security_eligible,
        pocket=pocket,
        include_esm=include_esm,
    )
    return {
        "cve_id": cve_id,
        "source_package": source_package,
        "ubuntu_series": series,
        "ubuntu_release": release,
        "is_ubuntu_release": is_ubuntu_release,
        "status": status,
        "description": description,
        "pocket": pocket,
        "component": str(raw_status.get("component") or ""),
        "fixed_source_version": fixed_version,
        "security_eligible": security_eligible,
        "groundtruth_label": label,
        "exclusion_reason": exclusion_reason,
        "notice_ids": notice_ids_for_status(payload, series, source_package, fixed_version),
        "evidence": {
            "source": "ubuntu_security_cve_json",
            "url": security_url,
        },
    }


def classify_groundtruth(
    *,
    status: str,
    fixed_version: str,
    is_ubuntu_release: bool,
    security_eligible: bool,
    pocket: str,
    include_esm: bool,
) -> tuple[str, str]:
    if not is_ubuntu_release:
        return "", "upstream_or_devel"
    if status == "released" and not fixed_version:
        return "", "released_without_valid_fixed_version"
    if status == "released" and not security_eligible:
        if pocket.startswith("esm-") and not include_esm:
            return "", "esm_disabled"
        return "", "non_security_pocket"
    if status == "released" and security_eligible:
        return "patch", ""
    if status == "not_affected":
        return "not_affected", ""
    if status in {"needed", "needs_triage", "pending"}:
        return "possibly_affected", status
    if status == "ignored":
        return "ignored", "ignored_by_ubuntu_security_status"
    if status in {"dne", "does_not_exist"}:
        return "not_present", "source_package_does_not_exist"
    return "unknown", f"unhandled_status:{status or 'empty'}"


def notice_ids_for_status(
    payload: dict[str, Any],
    series: str,
    source_package: str,
    fixed_version: str,
) -> list[str]:
    ids = []
    for notice in payload.get("notices") or []:
        release_packages = (notice.get("release_packages") or {}).get(series) or []
        if any(
            bool(item.get("is_source"))
            and item.get("name") == source_package
            and (not fixed_version or item.get("version") == fixed_version)
            for item in release_packages
        ):
            notice_id = str(notice.get("id") or "")
            if notice_id and notice_id not in ids:
                ids.append(notice_id)
    return sorted(ids)


def normalize_series_filter(values: Iterable[str], catalog: dict[str, str]) -> set[str]:
    reverse = {release: series for series, release in catalog.items()}
    result: set[str] = set()
    for value in values:
        for item in str(value).split(","):
            item = item.strip().lower()
            if not item:
                continue
            if re.fullmatch(r"\d{4}", item):
                item = f"{item[:2]}.{item[2:]}"
            result.add(reverse.get(item, item))
    return result


def normalize_status(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def normalize_pocket(value: Any) -> str:
    return str(value or "").strip().lower()


def valid_version(value: str) -> bool:
    return bool(value and value.lower() not in {"code not present", "not available", "unknown"} and RELEASE_VERSION_RE.match(value))


def detect_cve_id(payload: dict[str, Any], source_path: Path | None) -> str:
    for value in (payload.get("id"), payload.get("cve_id"), payload.get("CVE")):
        if value:
            return str(value).strip().upper()
    if source_path:
        match = re.search(r"CVE-\d{4}-\d{4,}", source_path.name, re.IGNORECASE)
        if match:
            return match.group(0).upper()
    return ""


def dedupe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for row in rows:
        key = (
            row["cve_id"],
            row["source_package"],
            row["ubuntu_series"],
            row["status"],
            row["fixed_source_version"],
            row["pocket"],
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output


def status_sort_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(row.get("cve_id") or ""),
        str(row.get("source_package") or ""),
        str(row.get("ubuntu_series") or ""),
        str(row.get("fixed_source_version") or row.get("status") or ""),
    )


def load_cve_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Ubuntu CVE JSON must contain an object: {path}")
    if not isinstance(payload.get("packages"), list):
        raise ValueError(f"Ubuntu CVE JSON has no packages list: {path}")
    return payload


def load_release_catalog(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"release catalog must be a JSON object: {path}")
    return {str(series).strip().lower(): str(release).strip() for series, release in payload.items()}
