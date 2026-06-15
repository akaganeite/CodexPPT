from __future__ import annotations

from typing import Any


def normalize_testset(raw: Any) -> dict[str, list[str]]:
    """Accept only dataset export list format.

    Supported item shapes:
      - {"CVE": "...", "functions": [...], "binaries": [...]}
      - {"CVE": "...", "functions": [...], "vuln": [...], "patch": [...],
         "not_affected": [...]}

    The legacy top-level object format, CVE -> [binaries], is intentionally
    rejected so every run uses the dataset export schema.
    """
    if not isinstance(raw, list):
        raise ValueError(
            "testset JSON must be a dataset export list, e.g. "
            "[{'CVE': 'CVE-...', 'functions': [...], 'binaries': [...]}]"
        )

    out: dict[str, list[str]] = {}
    bad: list[int] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            bad.append(index)
            continue
        cve = item.get("CVE")
        if not isinstance(cve, str) or not cve:
            bad.append(index)
            continue
        binaries = item.get("binaries")
        if binaries is None:
            binaries = []
            for key in ("vuln", "patch", "not_affected"):
                values = item.get(key, [])
                if not isinstance(values, list) or not all(isinstance(x, str) for x in values):
                    bad.append(index)
                    break
                binaries.extend(values)
            else:
                pass
        if not isinstance(binaries, list) or not all(isinstance(x, str) for x in binaries):
            bad.append(index)
            continue
        deduped = list(dict.fromkeys(binaries))
        if not deduped:
            bad.append(index)
            continue
        out[cve] = deduped
    if bad:
        sample = ", ".join(str(x) for x in bad[:5])
        raise ValueError(
            "testset JSON must be a dataset export list with CVE and either "
            f"binaries or vuln/patch/not_affected string lists. Bad item indexes: {sample}"
        )
    return out
