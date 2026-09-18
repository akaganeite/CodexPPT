from __future__ import annotations

import json
from typing import Any

from builder.config import BuildConfig
from builder.db import ProjectDB


def load_raw_nvd(db: ProjectDB, cve_id: str) -> dict[str, Any]:
    row = db.conn.execute("SELECT raw_json FROM cves WHERE cve_id=?", (cve_id,)).fetchone()
    if not row or not row["raw_json"]:
        return {}
    try:
        raw = json.loads(row["raw_json"])
    except json.JSONDecodeError:
        return {}
    return raw.get("raw_nvd", raw) if isinstance(raw, dict) else {}


def cpe_parts(criteria: str) -> list[str]:
    return criteria.split(":")


def text_value(value: Any) -> str:
    return str(value).strip() if isinstance(value, (str, int, float)) else ""


def version_constraint(
    *,
    version: str = "",
    start_including: str = "",
    start_excluding: str = "",
    end_including: str = "",
    end_excluding: str = "",
) -> dict[str, Any] | None:
    version = text_value(version)
    start_including = text_value(start_including)
    start_excluding = text_value(start_excluding)
    end_including = text_value(end_including)
    end_excluding = text_value(end_excluding)
    bounds = {
        "start_including": start_including,
        "start_excluding": start_excluding,
        "end_including": end_including,
        "end_excluding": end_excluding,
    }
    if version not in ("", "*", "-") and not any(bounds.values()):
        return {"exact": version, **bounds, "all": False}
    if any(bounds.values()):
        if version not in ("", "*", "-") and not start_including and not start_excluding:
            bounds["start_including"] = version
        return {"exact": "", **bounds, "all": False}
    if version in ("*", "-"):
        return {"exact": "", **bounds, "all": True}
    return None


def product_matches(config: BuildConfig, criteria: str) -> bool:
    parts = cpe_parts(criteria)
    return (
        len(parts) >= 6
        and parts[0] == "cpe"
        and parts[1] == "2.3"
        and parts[2] == "a"
        and parts[3] == config.vendor
        and parts[4] == config.product_name
    )


def collect_cpe_matches(node: dict[str, Any]) -> list[dict[str, Any]]:
    matches = [item for item in node.get("cpeMatch", []) or [] if isinstance(item, dict)]
    for child in node.get("children", []) or []:
        if isinstance(child, dict):
            matches.extend(collect_cpe_matches(child))
    return matches


def vulnerable_cpe_matches(config: BuildConfig, db: ProjectDB, cve_id: str) -> list[dict[str, Any]]:
    matches = []
    for config_item in load_raw_nvd(db, cve_id).get("configurations", []) or []:
        if not isinstance(config_item, dict):
            continue
        for node in config_item.get("nodes", []) or []:
            if not isinstance(node, dict):
                continue
            for match in collect_cpe_matches(node):
                if match.get("vulnerable") and product_matches(config, match.get("criteria", "")):
                    matches.append(match)
    return matches


def affected_data_items(raw: dict[str, Any]) -> list[dict[str, Any]]:
    items = []
    for group in raw.get("affected", []) or []:
        if not isinstance(group, dict):
            continue
        nested = group.get("affectedData")
        if isinstance(nested, list):
            items.extend(item for item in nested if isinstance(item, dict))
        elif "product" in group and "versions" in group:
            items.append(group)
    return items


def affected_data_product_matches(config: BuildConfig, item: dict[str, Any]) -> bool:
    return text_value(item.get("product")).casefold() == config.product_name.casefold()


def affected_data_constraints(config: BuildConfig, db: ProjectDB, cve_id: str) -> list[dict[str, Any]] | None:
    constraints = []
    raw = load_raw_nvd(db, cve_id)
    for item in affected_data_items(raw):
        if not affected_data_product_matches(config, item):
            continue
        for version_item in item.get("versions", []) or []:
            if not isinstance(version_item, dict):
                continue
            if text_value(version_item.get("status")).casefold() != "affected":
                continue
            constraint = version_constraint(
                version=version_item.get("version", ""),
                end_including=version_item.get("lessThanOrEqual", ""),
                end_excluding=version_item.get("lessThan", ""),
            )
            if constraint and constraint not in constraints:
                constraints.append(constraint)
    return constraints or None


def affected_constraints(config: BuildConfig, db: ProjectDB, cve_id: str) -> list[dict[str, Any]] | None:
    # Product-specific affectedData is more precise than a CPE interval.
    precise = affected_data_constraints(config, db, cve_id)
    if precise is not None:
        return precise
    constraints = []
    for match in vulnerable_cpe_matches(config, db, cve_id):
        parts = cpe_parts(match.get("criteria", ""))
        constraint = version_constraint(
            version=parts[5] if len(parts) > 5 else "",
            start_including=match.get("versionStartIncluding", ""),
            start_excluding=match.get("versionStartExcluding", ""),
            end_including=match.get("versionEndIncluding", ""),
            end_excluding=match.get("versionEndExcluding", ""),
        )
        if constraint and constraint not in constraints:
            constraints.append(constraint)
    return constraints or None


def affected_ranges(config: BuildConfig, db: ProjectDB, cve_id: str) -> list[dict[str, str]]:
    precise = affected_data_constraints(config, db, cve_id)
    if precise is not None:
        return [
            {
                "source": "affectedData",
                "criteria": "affectedData",
                "version": constraint["exact"],
                "versionStartIncluding": constraint["start_including"],
                "versionStartExcluding": constraint["start_excluding"],
                "versionEndIncluding": constraint["end_including"],
                "versionEndExcluding": constraint["end_excluding"],
            }
            for constraint in precise
        ]
    ranges = []
    for match in vulnerable_cpe_matches(config, db, cve_id):
        criteria = match.get("criteria", "")
        parts = cpe_parts(criteria)
        ranges.append(
            {
                "criteria": criteria,
                "version": parts[5] if len(parts) > 5 else "",
                "versionStartIncluding": match.get("versionStartIncluding", ""),
                "versionStartExcluding": match.get("versionStartExcluding", ""),
                "versionEndIncluding": match.get("versionEndIncluding", ""),
                "versionEndExcluding": match.get("versionEndExcluding", ""),
            }
        )
    return ranges
