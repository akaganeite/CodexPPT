from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from typing import Any

from builder.config import BuildConfig
from builder.db import ProjectDB
from builder.logging import get_logger


def nvd_headers(config: BuildConfig) -> dict[str, str]:
    headers = {"User-Agent": "agentic-dataset-builder/0.1"}
    if config.nvd_api_key:
        headers["apiKey"] = config.nvd_api_key
    return headers


def parse_nvd_cves(data: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        raw_refs = cve.get("references", [])
        if isinstance(raw_refs, dict):
            raw_refs = raw_refs.get("referenceData", [])
        refs = [r.get("url", "") for r in raw_refs if isinstance(r, dict) and r.get("url")]
        cwes = []
        for weakness in cve.get("weaknesses", []) or []:
            for desc in weakness.get("description", []) or []:
                if desc.get("value"):
                    cwes.append(desc["value"])
        descriptions = cve.get("descriptions", []) or []
        summary = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
        out.append(
            {
                "id": cve_id,
                "summary": summary,
                "cwe": sorted(set(cwes)),
                "references": refs,
                "published": cve.get("published", ""),
                "last_modified": cve.get("lastModified", ""),
                "raw_nvd": cve,
            }
        )
    return out


def fetch_nvd_request(config: BuildConfig, params: dict[str, str]) -> dict[str, Any]:
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {k: v for k, v in params.items() if v}
    url = base + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=nvd_headers(config))
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_nvd_cves(config: BuildConfig) -> list[dict[str, Any]]:
    log = get_logger(config.output, "cve_metadata")
    params = {
        "virtualMatchString": f"cpe:2.3:a:{config.vendor}:{config.product_name}:*:*:*:*:*:*:*:*",
        "startIndex": "0",
        "resultsPerPage": "2000",
    }
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
    log.trace("fetching NVD CVEs", url=url)
    data = fetch_nvd_request(config, params)
    out = parse_nvd_cves(data)
    log.trace("fetched NVD CVEs", count=len(out))
    return out


def fetch_nvd_cve_id(config: BuildConfig, cve_id: str) -> dict[str, Any] | None:
    log = get_logger(config.output, "cve_metadata")
    log.trace("fetching NVD CVE by id", cve=cve_id)
    data = fetch_nvd_request(config, {"cveId": cve_id})
    items = parse_nvd_cves(data)
    return items[0] if items else None


def dedupe_cves(cves: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in cves:
        cve_id = item["id"]
        if cve_id in seen:
            continue
        seen.add(cve_id)
        out.append(item)
    return out


def select_cves(config: BuildConfig, cves: list[dict[str, Any]]) -> list[str]:
    if config.cves:
        available = {item["id"] for item in cves}
        return [cve_id for cve_id in config.cves if cve_id in available]
    sorted_items = sorted(cves, key=lambda x: (x.get("published", ""), x["id"]), reverse=True)
    return [item["id"] for item in sorted_items[: config.latest]]


def update_cve_metadata(config: BuildConfig, db: ProjectDB) -> list[str]:
    log = get_logger(config.output, "cve_metadata")
    cves = dedupe_cves(fetch_nvd_cves(config))
    if config.cves:
        seen = {item["id"] for item in cves}
        for cve_id in [item for item in config.cves if item not in seen]:
            try:
                item = fetch_nvd_cve_id(config, cve_id)
            except Exception as exc:
                log.warn("failed to fetch requested CVE by id", cve=cve_id, error=str(exc))
                continue
            if item:
                cves.append(item)
                seen.add(cve_id)
                log.trace("fetched requested CVE by id", cve=cve_id)
            else:
                log.warn("requested CVE not found in NVD", cve=cve_id)
            time.sleep(0.7 if not os.environ.get("NVD_NIST_API_KEY") else 0.1)
    cves = dedupe_cves(cves)
    selected = set(select_cves(config, cves))
    for item in cves:
        db.upsert_cve(item, selected=item["id"] in selected)
    missing_requested = [cve_id for cve_id in config.cves if cve_id not in selected]
    if missing_requested:
        log.warn("some requested CVEs were not selected because metadata was unavailable", missing=missing_requested)
    db.record_stage("cve_metadata", "ok", {"fetched": len(cves), "selected": len(selected), "missing_requested": missing_requested})
    log.trace("selected CVEs", selected=sorted(selected))
    # NVD rate limit hygiene for repeated local tests.
    time.sleep(0.7 if not os.environ.get("NVD_NIST_API_KEY") else 0.1)
    return sorted(selected, reverse=True)
