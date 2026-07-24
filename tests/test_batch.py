"""Offline checks for direct batch selection, labels, and resume metadata.

    python3 -m claudeagent.tests.test_batch
"""

from __future__ import annotations

import contextlib
import io
import json
import os
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
        check("dry run reports verifier digest", "verify_agent: on" in output and "verify_config_digest:" in output)
        check("dry run does not create output", not (root / "out").exists())

        check("verify agent enabled by default", args.verify_agent == "on")
        check("verify verdict budget defaults to five", args.verify_verdict_calls == 5)
        check("case timeout accommodates verifier", args.case_timeout == 3600)

        command = batch._case_command(
            cases[0],
            args,
            root / "binary",
            root / "case",
        )
        check("case command forwards verifier mode", command[command.index("--verify-agent") + 1] == "on")
        check("case command forwards verifier budget", command[command.index("--verify-verdict-calls") + 1] == "5")

        explicit_args = batch.build_parser().parse_args([
            "--testset", str(testset),
            "--groundtruth", str(groundtruth),
            "--metadata-json", str(metadata),
            "--out-root", str(root / "out-explicit"),
            "--verify-model-profile", "deepseek",
        ])
        explicit_command = batch._case_command(
            cases[0], explicit_args, root / "binary", root / "case"
        )
        check(
            "case command forwards verifier profile",
            explicit_command[explicit_command.index("--verify-model-profile") + 1] == "deepseek",
        )

        # Main and verifier usage remain independently addressable in records
        # and aggregate batch metrics.
        record = batch._empty_record(cases[0], root / "binary", root / "case")
        batch._update_record_from_final(record, {
            "status": "absent",
            "confidence": 0.9,
            "ok": True,
            "evidence_ids": ["ev_0001"],
            "usage_metrics": {
                "model_turns": 2,
                "totals": {"input_tokens": 100, "output_tokens": 10, "total_tokens": 110},
            },
            "verification": {
                "mode": "on",
                "outcome": "confirmed",
                "config_digest": "a" * 64,
                "sessions": [{"claim_calls": 1, "verdict_calls": 2}],
            },
            "verification_usage_metrics": {
                "model_turns": 4,
                "totals": {"input_tokens": 40, "output_tokens": 5, "total_tokens": 45},
                "timing": {"wall_seconds": 3.5},
            },
        })
        separated = batch.batch_metrics_pptagent([record])
        check("main usage excludes verifier", separated["usage_totals"].get("prompt_tokens") == 100)
        check(
            "verifier usage separately aggregated",
            separated["verification_metrics"]["usage_totals"].get("prompt_tokens") == 40,
        )
        check("verifier outcome exposed", record["verification_outcome"] == "confirmed")
        check("verifier calls exposed", (
            record["verification_claim_calls"], record["verification_verdict_calls"]
        ) == (1, 2))

        # Resume rejects a valid artifact whenever verifier mode or digest no
        # longer matches the requested verification configuration.
        resume_args = batch.build_parser().parse_args([
            "--testset", str(testset),
            "--groundtruth", str(groundtruth),
            "--metadata-json", str(metadata),
            "--out-root", str(root / "resume"),
        ])
        existing = {
            "status": "absent",
            "metadata_sha256": "metadata-digest",
            "verification": {"mode": "on", "config_digest": "verify-digest"},
        }
        original_existing = batch._existing_case_artifact
        batch._existing_case_artifact = lambda _case_dir: existing
        try:
            selected = [cases[0]]
            to_run, to_reuse, counts = batch._select_resume_cases(
                selected,
                root / "resume",
                resume_args,
                {"CVE-A": "metadata-digest"},
                ("on", "verify-digest"),
            )
            check("matching verifier signature resumes", not to_run and len(to_reuse) == 1)
            check("matching verifier signature is fresh", counts["stale_verify_agent"] == 0)
            to_run, to_reuse, counts = batch._select_resume_cases(
                selected,
                root / "resume",
                resume_args,
                {"CVE-A": "metadata-digest"},
                ("on", "changed-digest"),
            )
            check("changed verifier digest reruns", len(to_run) == 1 and not to_reuse)
            check("changed verifier digest counted stale", counts["stale_verify_agent"] == 1)
            to_run, to_reuse, counts = batch._select_resume_cases(
                selected,
                root / "resume",
                resume_args,
                {"CVE-A": "metadata-digest"},
                ("off", ""),
            )
            check("changed verifier mode reruns", len(to_run) == 1 and not to_reuse)
            check("changed verifier mode counted stale", counts["stale_verify_agent"] == 1)
        finally:
            batch._existing_case_artifact = original_existing

        # Both provider keys are imported in one bootstrap pass for child
        # worker processes.
        key_names = ["CLAUDEAGENT_TEST_MAIN_KEY", "CLAUDEAGENT_TEST_VERIFY_KEY"]
        original_import = batch.import_env_from_interactive_shell
        imported_names: list[str] = []
        for name in key_names:
            os.environ.pop(name, None)
        def fake_import(names: list[str]) -> dict[str, str]:
            imported_names.extend(names)
            for name in names:
                os.environ[name] = "test-key"
            return {name: "test-key" for name in names}
        batch.import_env_from_interactive_shell = fake_import
        try:
            available = batch.bootstrap_api_keys(key_names)
            check("bootstrap imports both profile keys", imported_names == key_names)
            check("bootstrap returns both available keys", available == set(key_names))
        finally:
            batch.import_env_from_interactive_shell = original_import
            for name in key_names:
                os.environ.pop(name, None)

    if failures:
        print("BATCH TESTS FAILED:")
        for failure in failures:
            print("  -", failure)
        return 1
    print("BATCH TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(_run())
