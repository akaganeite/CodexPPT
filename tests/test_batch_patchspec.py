"""Offline tests for batch-level PatchSpec pre-generation and reuse.

Run from the package parent:
    python3 -m claudeagent.tests.test_batch_patchspec
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

from claudeagent import batch
from claudeagent.patchspec import PatchSpecModelConfig


METADATA = {
    "CVE-A": {
        "cve_id": "CVE-A",
        "project": "curl",
        "functions": ["alpha"],
        "patch_hunk": [{"old_lines": ["return old;"], "new_lines": ["return new;"]}],
    },
    "CVE-B": {
        "cve_id": "CVE-B",
        "project": "curl",
        "functions": ["beta"],
        "patch_hunk": [{"old_lines": ["use(x);"], "new_lines": ["if(x) use(x);"]}],
    },
}


CONFIG = PatchSpecModelConfig(
    api_key="",
    base_url="https://example.invalid/v1",
    model="gpt-5.5",
    reasoning_effort="medium",
    reasoning={"effort": "medium"},
    timeout=1,
    max_retries=1,
)


def _args(tmp: str) -> argparse.Namespace:
    return argparse.Namespace(
        binaries_root=tmp,
        variant="variant",
        compiler="gcc",
        opt="o0",
        out_root=str(Path(tmp) / "out"),
        metadata_json=str(Path(tmp) / "metadata.json"),
        max_turns=20,
        finalization_turns=3,
        api_timeout=240,
        api_max_retries=3,
        api_turn_retries=1,
        case_timeout=900,
        model="",
        base_url="",
        model_profile="",
        no_strict=False,
        resume="auto",
        retry_inconclusive=False,
    )


def _result(cve_id: str, path: Path | None = None, *, usage=None, mode="generated"):
    return SimpleNamespace(
        spec={"source": {"cve_id": cve_id}},
        digest=f"digest-{cve_id}",
        generation_mode=mode,
        usage=usage or {},
        cache_key=("a" if cve_id == "CVE-A" else "b") * 64,
        cache_hit=mode == "cache_hit",
        path=str(path) if path is not None else None,
    )


def _run() -> int:
    failures: list[str] = []

    def check(label: str, condition: bool) -> None:
        if not condition:
            failures.append(label)

    # One ensure call per distinct CVE, even when several cases share it.
    with tempfile.TemporaryDirectory() as tmp:
        calls: list[tuple[str, bool]] = []
        cache_dir = Path(tmp) / "cache"

        def ensure_stub(metadata, *, cve_id, config, cache_dir, dry_run):
            calls.append((cve_id, dry_run))
            return _result(cve_id)

        results, errors, _ = batch.prepare_patch_specs(
            METADATA,
            ["CVE-A", "CVE-A", "CVE-B"],
            config=CONFIG,
            cache_dir=cache_dir,
            dry_run=True,
            max_workers=2,
            ensure_fn=ensure_stub,
        )
        check("distinct CVE ensure count", sorted(calls) == [("CVE-A", True), ("CVE-B", True)])
        check("distinct CVE results", set(results) == {"CVE-A", "CVE-B"} and not errors)
        check("stub dry run no cache write", not cache_dir.exists())

    # The real dry-run path builds an in-memory skeleton without a key or write.
    with tempfile.TemporaryDirectory() as tmp:
        cache_dir = Path(tmp) / "cache"
        results, errors, _ = batch.prepare_patch_specs(
            METADATA,
            ["CVE-A"],
            config=CONFIG,
            cache_dir=cache_dir,
            dry_run=True,
            max_workers=1,
        )
        check("real dry run succeeds", not errors and results["CVE-A"].generation_mode == "dry_run_skeleton")
        check("real dry run no write", not cache_dir.exists() and results["CVE-A"].path is None)
        entry = batch.patchspec_manifest_entry(results["CVE-A"], cache_dir=cache_dir, cve_id="CVE-A")
        check("dry run reports candidate path", entry["path"].endswith(f"CVE-A/{results['CVE-A'].cache_key}.json"))

    # The public batch dry-run also remains side-effect free end to end.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        groundtruth = root / "groundtruth.json"
        metadata_path = root / "metadata.json"
        binaries = root / "binaries" / "variant"
        binaries.mkdir(parents=True)
        (binaries / "bin").write_bytes(b"ELF")
        groundtruth.write_text(
            json.dumps([{"CVE": "CVE-A", "vuln": ["bin"], "patch": [], "not_affected": []}]),
            encoding="utf-8",
        )
        metadata_path.write_text(json.dumps(METADATA), encoding="utf-8")
        output = root / "dry-output"
        args = batch.build_parser().parse_args([
            "--groundtruth", str(groundtruth),
            "--binaries-root", str(root / "binaries"),
            "--variant", "variant",
            "--metadata-json", str(metadata_path),
            "--out-root", str(output),
            "--dry-run",
        ])
        with contextlib.redirect_stdout(io.StringIO()):
            status = batch.run_batch(args)
        check("batch dry run succeeds", status == 0)
        check("batch dry run writes nothing", not output.exists())

    # Per-CVE failures are isolated instead of triggering duplicate case-local generation.
    def partly_failing(metadata, *, cve_id, config, cache_dir, dry_run):
        if cve_id == "CVE-B":
            raise RuntimeError("bad metadata")
        return _result(cve_id)

    results, errors, _ = batch.prepare_patch_specs(
        METADATA,
        ["CVE-A", "CVE-B"],
        config=CONFIG,
        cache_dir=Path("/unused"),
        dry_run=True,
        max_workers=2,
        ensure_fn=partly_failing,
    )
    check("failure isolated", set(results) == {"CVE-A"} and set(errors) == {"CVE-B"})

    # Generation usage is counted once from the distinct-CVE result map.
    usage = {
        "attempts": [{"input_tokens": 70, "output_tokens": 30, "total_tokens": 100}],
        "total": {
            "input_tokens": 70,
            "output_tokens": 30,
            "total_tokens": 100,
            "input_tokens_details": {"cached_tokens": 20},
            "output_tokens_details": {"reasoning_tokens": 12},
        },
    }
    metrics = batch.patchspec_batch_metrics(
        {"CVE-A": _result("CVE-A", usage=usage)}, {}, 1.25
    )
    check("usage counted once", metrics["usage_totals"].get("total_tokens") == 100)
    check("model turns from attempts", metrics["model_turns"] == 1)
    check(
        "nested reasoning usage retained",
        metrics["usage_totals"].get("completion_tokens_details.reasoning_tokens") == 12,
    )

    with tempfile.TemporaryDirectory() as tmp:
        args = _args(tmp)
        case = {"cve_id": "CVE-A", "binary_name": "bin", "expected": "present"}
        command = batch._case_command(
            case,
            args,
            Path(tmp) / "binary",
            Path(tmp) / "case",
            Path(tmp) / "shared-spec.json",
        )
        patch_index = command.index("--patchspec-json")
        metadata_index = command.index("--metadata-json")
        check("case gets explicit PatchSpec", command[patch_index + 1].endswith("shared-spec.json"))
        check("case retains host metadata", command[metadata_index + 1] == args.metadata_json)

        # A CVE-level hard failure produces error records without starting a child.
        binary = Path(tmp) / "variant" / "bin"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"ELF")
        failed = batch._record_patchspec_failure(case, args, "invalid spec")
        check("failure record", failed.get("predicted") == "error" and "invalid spec" in failed.get("error", ""))

    # A failed retry must not silently score a pre-existing final_result.json.
    with tempfile.TemporaryDirectory() as tmp:
        args = _args(tmp)
        case = {"cve_id": "CVE-A", "binary_name": "bin", "expected": "present"}
        binary = Path(tmp) / "variant" / "bin"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"ELF")
        case_dir = batch.safe_case_dir(Path(args.out_root), "CVE-A", "bin")
        case_dir.mkdir(parents=True)
        (case_dir / "final_result.json").write_text(
            json.dumps({"status": "present", "ok": True}), encoding="utf-8"
        )
        original_run = batch.subprocess.run
        batch.subprocess.run = lambda *unused_args, **unused_kwargs: SimpleNamespace(
            returncode=1, stderr="child failed before write"
        )
        try:
            stale = batch.run_one_case(case, args, Path(tmp) / "shared-spec.json")
        finally:
            batch.subprocess.run = original_run
        check(
            "stale final ignored",
            stale.get("predicted") == "error" and "stale artifact" in stale.get("error", ""),
        )

    # auto/error resume invalidates a completed result with the wrong cache key.
    with tempfile.TemporaryDirectory() as tmp:
        args = _args(tmp)
        out_root = Path(args.out_root)
        cases = [
            {"cve_id": "CVE-A", "binary_name": "matching", "expected": "present"},
            {"cve_id": "CVE-A", "binary_name": "stale", "expected": "present"},
        ]
        for binary_name, key in [("matching", "a" * 64), ("stale", "c" * 64)]:
            case_dir = batch.safe_case_dir(out_root, "CVE-A", binary_name)
            case_dir.mkdir(parents=True)
            (case_dir / "final_result.json").write_text(
                json.dumps({"status": "present", "patch_spec": {"cache_key": key}}),
                encoding="utf-8",
            )
        to_run, to_reuse, counts = batch._select_resume_cases(
            cases, out_root, args, patchspec_keys={"CVE-A": "a" * 64}
        )
        check("matching result reused", [item["binary_name"] for item in to_reuse] == ["matching"])
        check("stale result rerun", [item["binary_name"] for item in to_run] == ["stale"])
        check("stale counted", counts["stale_patchspec"] == 1)

    if failures:
        print("FAIL:", failures)
        return 1
    print("BATCH PATCHSPEC TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
