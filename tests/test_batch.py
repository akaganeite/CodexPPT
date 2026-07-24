"""Offline checks for direct batch selection, labels, and resume metadata.

    python3 -m claudeagent.tests.test_batch
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
from pathlib import Path

from claudeagent import batch


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _run() -> int:
    failures: list[str] = []

    def check(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        testset = root / "testset.json"
        groundtruth = root / "groundtruth.json"
        metadata = root / "metadata.json"
        _write(testset, [{"CVE": "CVE-A", "binaries": ["one", "missing"]}])
        _write(groundtruth, [{"CVE": "CVE-A", "vuln": ["one"], "patch": [], "not_affected": []}])
        _write(metadata, {"CVE-A": {"project": "demo", "description": "bounds check"}})

        cases = batch.load_cases(str(testset), str(groundtruth), "")
        check("testset controls selected cases", [case["binary_name"] for case in cases] == ["one", "missing"])
        check("groundtruth labels unknown separately", [case["expected"] for case in cases] == ["absent", "unknown"])
        metrics = batch.batch_metrics_pptagent([
            {"expected": "absent", "predicted": "absent", "usage_totals": {}, "timing": {}},
            {"expected": "unknown", "predicted": "present", "usage_totals": {}, "timing": {}},
        ])
        check("unknown case excluded from score", metrics["overall_metrics"]["overall_DSR"] == 1.0)

        args = batch.build_parser().parse_args([
            "--testset", str(testset),
            "--groundtruth", str(groundtruth),
            "--metadata-json", str(metadata),
            "--binaries-root", str(root / "binaries"),
            "--out-root", str(root / "out"),
            "--dry-run",
        ])
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = batch.run_batch(args)
        output = stdout.getvalue()
        check("dry run validates direct metadata mode", status == 0 and "metadata_hashes:" in output)
        check("dry run does not create output", not (root / "out").exists())

    if failures:
        print("BATCH TESTS FAILED:")
        for failure in failures:
            print("  -", failure)
        return 1
    print("BATCH TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(_run())
