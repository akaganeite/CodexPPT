from __future__ import annotations

import re
from typing import Any


VERSION_RE = re.compile(r"^binutils-([0-9]+(?:\.[0-9]+){1,2})-(?:objdump|readelf|nm)$")


def evaluate_results(results: dict[str, Any], groundtruth: dict[str, Any]) -> dict[str, Any]:
    """Evaluate merged results against CVE -> {vuln, patch} groundtruth.

    not_found is excluded from TC. inconclusive and error are counted in TC, but
    not in the Accuracy denominator, matching the table definition supplied by
    the user.
    """
    counts = {
        "TP": 0,
        "TN": 0,
        "FP": 0,
        "FN": 0,
        "inconclusive": 0,
        "error": 0,
        "not_found": 0,
        "version_not_in_groundtruth": 0,
        "missing_groundtruth_cve": 0,
    }
    mismatches: list[dict[str, str]] = []

    for cve, per_binary in results.items():
        gt = groundtruth.get(cve)
        if not isinstance(gt, dict):
            counts["missing_groundtruth_cve"] += len(per_binary)
            continue
        patched = {str(x) for x in gt.get("patch", [])}
        vulnerable = {str(x) for x in gt.get("vuln", [])}

        for binary, row in per_binary.items():
            match = VERSION_RE.match(binary)
            if not match:
                counts["version_not_in_groundtruth"] += 1
                continue
            version = match.group(1)
            if version in patched:
                expected = "present"
            elif version in vulnerable:
                expected = "absent"
            else:
                counts["version_not_in_groundtruth"] += 1
                continue

            status = str(row.get("status", "error")) if isinstance(row, dict) else "error"
            if status == "not_found":
                counts["not_found"] += 1
                continue
            if status == "inconclusive":
                counts["inconclusive"] += 1
                continue
            if status == "error":
                counts["error"] += 1
                continue

            if expected == "present" and status == "present":
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

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / accuracy_den if accuracy_den else 0.0
    dsr = (tp + tn) / tc if tc else 0.0

    return {
        "counts": {
            **counts,
            "TC": tc,
            "accuracy_denominator": accuracy_den,
        },
        "metrics": {
            "P": precision,
            "R": recall,
            "F1": f1,
            "A": accuracy,
            "DSR": dsr,
        },
        "mismatches": mismatches,
    }

