"""Official Ubuntu CVE tracker fallback for unavailable Security JSON."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any

from ..io_utils import write_json
from ..system_utils import download_file


TRACKER_URL = "https://git.launchpad.net/ubuntu-cve-tracker/plain/{bucket}/{cve_id}"
STATUS_RE = re.compile(
    r"^(?P<scope>[^:\s]+)_(?P<package>[a-z0-9][a-z0-9+.-]*):\s*"
    r"(?P<status>[A-Za-z-]+)(?:\s+\((?P<description>.*)\))?\s*$",
    re.IGNORECASE,
)


def fetch_tracker_cve(cve_id: str, destination: Path, *, timeout: int) -> tuple[bool, str]:
    tracker_path = destination.with_suffix(".tracker")
    errors = []
    for bucket in tracker_bucket_order(cve_id):
        url = TRACKER_URL.format(bucket=bucket, cve_id=cve_id)
        ok, message = download_file(
            url,
            tracker_path,
            verify_sha256=False,
            timeout=max(3, timeout),
            attempts=1,
            bypass_proxy=True,
        )
        if not ok:
            errors.append(f"{bucket}: {message}")
            continue
        try:
            payload = parse_tracker_cve(tracker_path.read_text(encoding="utf-8"), source_url=url, bucket=bucket)
        except (OSError, ValueError) as exc:
            errors.append(f"{bucket}: {exc}")
            tracker_path.unlink(missing_ok=True)
            continue
        if payload.get("id") != cve_id or not payload.get("packages"):
            errors.append(f"{bucket}: tracker entry has no matching package status")
            tracker_path.unlink(missing_ok=True)
            continue
        write_json(destination, payload)
        tracker_path.unlink(missing_ok=True)
        return True, f"ubuntu-cve-tracker {bucket} fallback"
    tracker_path.unlink(missing_ok=True)
    return False, "; ".join(errors) or "Ubuntu CVE tracker entry unavailable"


def tracker_bucket_order(cve_id: str) -> tuple[str, str]:
    match = re.match(r"CVE-(\d{4})-", cve_id, re.IGNORECASE)
    year = int(match.group(1)) if match else 0
    current_year = datetime.now(timezone.utc).year
    return ("active", "retired") if year >= current_year - 1 else ("retired", "active")


def parse_tracker_cve(text: str, *, source_url: str = "", bucket: str = "") -> dict[str, Any]:
    fields = parse_tracker_fields(text)
    cve_id = field_text(fields, "Candidate").upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        raise ValueError("tracker entry has no valid Candidate field")

    statuses: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for line in text.splitlines():
        match = STATUS_RE.match(line.strip())
        if not match:
            continue
        series, pocket = tracker_scope(match.group("scope"))
        statuses[match.group("package")].append(
            {
                "release_codename": series,
                "status": match.group("status"),
                "description": str(match.group("description") or "").strip(),
                "pocket": pocket,
                "component": None,
            }
        )
    packages = [
        {"name": package, "statuses": rows}
        for package, rows in sorted(statuses.items())
    ]
    notes = field_text(fields, "Notes")
    patches = {
        key.removeprefix("Patches_"): [item for item in values if item]
        for key, values in fields.items()
        if key.startswith("Patches_")
    }
    return {
        "schema": "ubuntu-cve-tracker-fallback-v1",
        "id": cve_id,
        "description": field_text(fields, "Description"),
        "ubuntu_description": field_text(fields, "Ubuntu-Description"),
        "notes": [{"author": "ubuntu-cve-tracker", "note": notes}] if notes else [],
        "references": fields.get("References", []),
        "priority": field_text(fields, "Priority"),
        "packages": packages,
        "patches": patches,
        "tracker_source": source_url,
        "tracker_bucket": bucket,
    }


def parse_tracker_fields(text: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = defaultdict(list)
    current = ""
    for raw_line in text.splitlines():
        if raw_line and not raw_line[0].isspace() and ":" in raw_line:
            current, value = raw_line.split(":", 1)
            fields[current].append(value.strip())
        elif current and raw_line[:1].isspace():
            value = raw_line.strip()
            if value:
                fields[current].append(value)
    return dict(fields)


def field_text(fields: dict[str, list[str]], key: str) -> str:
    return "\n".join(item for item in fields.get(key, []) if item).strip()


def tracker_scope(scope: str) -> tuple[str, str]:
    parts = [item for item in scope.lower().split("/") if item]
    if len(parts) == 1:
        return parts[0], "security"
    if parts[0].startswith("esm-"):
        return parts[-1], parts[0]
    if parts[-1] == "esm":
        return parts[0], "esm-infra"
    return parts[0], parts[-1]
