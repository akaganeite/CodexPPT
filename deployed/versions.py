from __future__ import annotations

import re
from functools import cmp_to_key
from typing import Any


try:
    import apt_pkg

    apt_pkg.init_system()

    def debian_compare(left: str, right: str) -> int:
        return apt_pkg.version_compare(str(left), str(right))

except Exception:  # pragma: no cover - fallback for non-Debian systems.
    try:
        from debian.debian_support import Version

        def debian_compare(left: str, right: str) -> int:
            lver = Version(str(left))
            rver = Version(str(right))
            return (lver > rver) - (lver < rver)

    except Exception:

        def debian_compare(left: str, right: str) -> int:
            return (str(left) > str(right)) - (str(left) < str(right))


def debian_sort_key(version: str) -> Any:
    return cmp_to_key(debian_compare)(str(version))


def upstream_version(version: str) -> str:
    value = str(version)
    if ":" in value:
        value = value.split(":", 1)[1]
    if "-" in value:
        value = value.rsplit("-", 1)[0]
    return value


def loose_version_candidates(raw: object) -> list[str]:
    values: list[str] = []
    if isinstance(raw, str):
        values.append(raw)
    elif isinstance(raw, (int, float)):
        values.append(str(raw))
    elif isinstance(raw, list):
        for item in raw:
            values.extend(loose_version_candidates(item))
    elif isinstance(raw, dict):
        for key in ("version", "fixed", "fixed_version", "introduced", "last_affected"):
            if key in raw:
                values.extend(loose_version_candidates(raw[key]))
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        value = value.strip()
        if not value or value.lower() in {"none", "unknown", "not fixed", "not-fixed"}:
            continue
        match = re.search(r"\d+(?:[._-]\d+)+(?:[A-Za-z0-9.+:~_-]*)?", value)
        normalized = match.group(0).replace("_", ".") if match else value
        if normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out
