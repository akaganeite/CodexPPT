from __future__ import annotations

from typing import Any


def normalize_testset(raw: Any) -> dict[str, list[str]]:
    """Accept the original CVE -> [binaries] format.

    A ground-truth style CVE -> {vuln, patch} file is intentionally rejected:
    detection needs concrete binary names, not labels.
    """
    if not isinstance(raw, dict):
        raise ValueError("testset JSON must be an object: CVE -> list[binary]")

    out: dict[str, list[str]] = {}
    bad: list[str] = []
    for cve, value in raw.items():
        if isinstance(value, list) and all(isinstance(x, str) for x in value):
            out[str(cve)] = value
        else:
            bad.append(str(cve))
    if bad:
        sample = ", ".join(bad[:5])
        raise ValueError(
            "testset JSON must map each CVE to a list of binary names. "
            f"Non-list entries include: {sample}"
        )
    return out

