from __future__ import annotations

import re
from typing import Any


VERSION_RE = re.compile(r"^[A-Za-z0-9_+.-]+-([0-9]+(?:\.[0-9]+){1,3})-[A-Za-z0-9_+.-]+$")


def normalize_groundtruth(raw: Any) -> dict[str, dict[str, list[str]]]:
    """Accept only dataset export list groundtruth format."""
    if not isinstance(raw, list):
        raise ValueError(
            "groundtruth JSON must be a dataset export list, e.g. "
            "[{'CVE': 'CVE-...', 'vuln': [...], 'patch': [...], 'not_affected': [...]}]"
        )

    out: dict[str, dict[str, list[str]]] = {}
    bad: list[int] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            bad.append(index)
            continue
        cve = item.get("CVE")
        if not isinstance(cve, str) or not cve:
            bad.append(index)
            continue
        normalized: dict[str, list[str]] = {}
        for key in ("vuln", "patch", "not_affected"):
            values = item.get(key, [])
            if not isinstance(values, list) or not all(isinstance(x, str) for x in values):
                bad.append(index)
                break
            normalized[key] = list(dict.fromkeys(values))
        else:
            out[cve] = normalized
    if bad:
        sample = ", ".join(str(x) for x in bad[:5])
        raise ValueError(
            "groundtruth JSON must be a dataset export list with CVE and "
            f"vuln/patch/not_affected string lists. Bad item indexes: {sample}"
        )
    return out


def expected_status_for_binary(binary: str, gt: dict[str, Any]) -> str | None:
    """Return present/absent/not_affected, or None if missing.

    Groundtruth entries can be either full binary names, e.g.
    curl-7.58.0-2ubuntu3.24-curl, or legacy upstream versions such as 7.58.0.
    Full binary names are checked first so distribution package revisions can
    have different labels under the same upstream version.
    """
    patched = {str(x) for x in gt.get("patch", [])}
    vulnerable = {str(x) for x in gt.get("vuln", [])}
    not_affected = {str(x) for x in gt.get("not_affected", [])}

    if binary in patched:
        return "present"
    if binary in vulnerable:
        return "absent"
    if binary in not_affected:
        return "not_affected"

    match = VERSION_RE.match(binary)
    if not match:
        return None
    version = match.group(1)
    if version in patched:
        return "present"
    if version in vulnerable:
        return "absent"
    if version in not_affected:
        return "not_affected"
    return None


def evaluate_results(results: dict[str, Any], groundtruth: dict[str, Any]) -> dict[str, Any]:
    """Evaluate merged results against dataset export list groundtruth.

    not_found is excluded from TC. not_affected is reported separately and also
    excluded from patch-presence TC because it is an applicability decision
    rather than a present/absent prediction. inconclusive and error are counted
    in patch-presence TC, but not in the Accuracy denominator, matching the
    original binary table definition.
    """
    groundtruth_by_cve = normalize_groundtruth(groundtruth)
    counts = {
        "TP": 0,
        "TN": 0,
        "FP": 0,
        "FN": 0,
        "not_affected_TP": 0,
        "not_affected_FP": 0,
        "not_affected_FN": 0,
        "inconclusive": 0,
        "error": 0,
        "not_found": 0,
        "not_affected": 0,
        "version_not_in_groundtruth": 0,
        "missing_groundtruth_cve": 0,
    }
    mismatches: list[dict[str, str]] = []

    for cve, per_binary in results.items():
        gt = groundtruth_by_cve.get(cve)
        if not isinstance(gt, dict):
            counts["missing_groundtruth_cve"] += len(per_binary)
            continue

        for binary, row in per_binary.items():
            expected = expected_status_for_binary(binary, gt)
            if expected is None:
                counts["version_not_in_groundtruth"] += 1
                continue

            status = str(row.get("status", "error")) if isinstance(row, dict) else "error"
            if status == "not_found":
                counts["not_found"] += 1
                continue
            if status == "not_affected":
                counts["not_affected"] += 1
                if expected == "not_affected":
                    counts["not_affected_TP"] += 1
                elif expected in {"present", "absent"}:
                    counts["not_affected_FP"] += 1
                    mismatches.append(
                        {"cve": cve, "binary": binary, "expected": expected, "predicted": status}
                    )
                continue
            if status == "inconclusive":
                counts["inconclusive"] += 1
                if expected == "not_affected":
                    counts["not_affected_FN"] += 1
                continue
            if status == "error":
                counts["error"] += 1
                if expected == "not_affected":
                    counts["not_affected_FN"] += 1
                continue

            if expected == "not_affected":
                counts["not_affected_FN"] += 1
                mismatches.append({"cve": cve, "binary": binary, "expected": expected, "predicted": status})
            elif expected == "present" and status == "present":
                counts["TP"] += 1
            elif expected == "absent" and status == "absent":
                counts["TN"] += 1
            elif expected == "absent" and status == "present":
                counts["FP"] += 1
                mismatches.append({"cve": cve, "binary": binary, "expected": expected, "predicted": status})
            elif expected == "present" and status == "absent":
                counts["FN"] += 1
                mismatches.append({"cve": cve, "binary": binary, "expected": expected, "predicted": status})
            else:
                counts["error"] += 1

    tp = counts["TP"]
    tn = counts["TN"]
    fp = counts["FP"]
    fn = counts["FN"]
    undecided = counts["inconclusive"] + counts["error"]
    accuracy_den = tp + tn + fp + fn
    tc = accuracy_den + undecided
    not_affected_total = counts["not_affected_TP"] + counts["not_affected_FN"]
    not_affected_included_tc = tc + not_affected_total
    not_affected_included_correct = tp + tn + counts["not_affected_TP"]

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / accuracy_den if accuracy_den else 0.0
    dsr = (tp + tn) / tc if tc else 0.0
    not_affected_included_dsr = (
        not_affected_included_correct / not_affected_included_tc if not_affected_included_tc else 0.0
    )
    not_affected_accuracy = (
        counts["not_affected_TP"] / not_affected_total if not_affected_total else 0.0
    )

    return {
        "counts": {
            **counts,
            "TC": tc,
            "accuracy_denominator": accuracy_den,
            "not_affected_total": not_affected_total,
            "not_affected_included_TC": not_affected_included_tc,
            "not_affected_included_correct": not_affected_included_correct,
        },
        "metrics": {
            "P": precision,
            "R": recall,
            "F1": f1,
            "A": accuracy,
            "DSR": dsr,
            "not_affected_included_DSR": not_affected_included_dsr,
            "not_affected_accuracy": not_affected_accuracy,
        },
        "mismatches": mismatches,
    }
