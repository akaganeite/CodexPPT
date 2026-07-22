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
from claudeagent.evidence_verifier import VERIFIER_PROMPT_VERSION
from claudeagent.finalize import build_final_artifact, preflight_missing_result
from claudeagent.patchspec import PatchSpecModelConfig
from claudeagent.runtime import initialize_agent_context


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
        evidence_verifier="llm",
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


def _valid_final(
    *,
    cache_key: str,
    verifier_mode: str = "llm",
    verifier_digest: str = "d" * 64,
) -> dict:
    support = {
        "support_id": "sup_0001",
        "behavior_id": "B001",
        "observed_side": "new",
        "summary": "The cited target code implements the required guarded behavior.",
        "evidence_ids": ["ev_0001"],
        "decisive_addresses": ["0x1010"],
    }
    claim = {
        "summary": "The sole required behavior is established as NEW.",
        "support_ids": ["sup_0001"],
        "unresolved_behavior_ids": [],
    }
    verdict = {
        "status": "present",
        "rule": "all_applicable_required_new",
        "behavior_claims": [{
            "behavior_id": "B001",
            "required": True,
            "resolved_side": "new",
            "resolution": "consistent",
            "support_ids": ["sup_0001"],
        }],
    }
    if verifier_mode == "llm":
        audit = {
            "mode": "llm",
            "outcome": "accepted",
            "prompt_version": VERIFIER_PROMPT_VERSION,
            "model": "gpt-5.5",
            "reasoning": {"effort": "medium"},
            "config_digest": verifier_digest,
            "repair_pending": False,
            "attempts": [{
                "attempt": 1,
                "outcome": "accept",
                "verification": {
                    "action": "accept",
                    "claim_relation": "supported",
                    "support_checks": [{
                        "support_id": "sup_0001",
                        "checked_evidence_ids": ["ev_0001"],
                        "relation": "direct",
                        "assessed_side": "new",
                        "reason": "The cited target predicate implements the NEW behavior.",
                    }],
                    "missing_behavior_ids": [],
                    "repair_instruction": "",
                },
            }],
        }
    else:
        audit = {
            "mode": "off",
            "outcome": "off",
            "prompt_version": VERIFIER_PROMPT_VERSION,
            "model": "",
            "reasoning": None,
            "config_digest": "",
            "repair_pending": False,
            "attempts": [],
        }
    return {
        "schema_version": "final_result.v3",
        "ok": True,
        "project": "curl",
        "cve_id": "CVE-A",
        "binary": "/anonymous/target_binary",
        "status": "present",
        "confidence": "high",
        "supports": [support],
        "claim": claim,
        "verdict": verdict,
        "evidence": [support["summary"]],
        "evidence_ids": ["ev_0001"],
        "reasoning": claim["summary"],
        "decisive_addresses": ["0x1010"],
        "inconclusive_reason": "none",
        "completed_at_epoch": 1.0,
        "observations": [],
        "evidence_ledger": [{
            "evidence_id": "ev_0001",
            "observation_id": "obs_0001",
            "kind": "disassembly_predicates",
            "claim": "The guarded target predicate is present.",
            "supporting_excerpt": ["0x1010: test eax,eax"],
            "location": {},
            "confidence": "supporting",
            "polarity": "positive",
        }],
        "harness_metrics": {},
        "patch_spec": {
            "digest": "spec-digest",
            "generation_mode": "generated",
            "resolution_mode": "provided",
            "cache_key": cache_key,
            "cache_hit": False,
            "behavior_contract": [{"behavior_id": "B001", "required": True}],
        },
        "evidence_verification": audit,
        "timing": {"wall_seconds": 1.0},
        "usage_metrics": {
            "provider": "openai-responses",
            "model_turns": 1,
            "totals": {},
            "by_turn": [],
            "evidence_verifier": {
                "provider": "openai-responses",
                "model": "gpt-5.5" if verifier_mode == "llm" else "",
                "model_turns": 1 if verifier_mode == "llm" else 0,
                "totals": {},
                "by_attempt": [],
            },
        },
    }


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
        verifier_index = command.index("--evidence-verifier")
        check("case gets explicit PatchSpec", command[patch_index + 1].endswith("shared-spec.json"))
        check("case retains host metadata", command[metadata_index + 1] == args.metadata_json)
        check("case gets verifier mode", command[verifier_index + 1] == "llm")

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
            {"cve_id": "CVE-A", "binary_name": "stale-verifier", "expected": "present"},
            {"cve_id": "CVE-A", "binary_name": "stale-digest", "expected": "present"},
            {"cve_id": "CVE-A", "binary_name": "invalid-verifier", "expected": "present"},
            {"cve_id": "CVE-A", "binary_name": "preflight-inconclusive", "expected": "present"},
        ]
        expected_verifier_digest = "d" * 64
        for binary_name, key, verifier_mode, verifier_digest in [
            ("matching", "a" * 64, "llm", expected_verifier_digest),
            ("stale", "c" * 64, "llm", expected_verifier_digest),
            ("stale-verifier", "a" * 64, "off", ""),
            ("stale-digest", "a" * 64, "llm", "e" * 64),
            ("invalid-verifier", "a" * 64, "llm", expected_verifier_digest),
        ]:
            case_dir = batch.safe_case_dir(out_root, "CVE-A", binary_name)
            case_dir.mkdir(parents=True)
            artifact = _valid_final(
                cache_key=key,
                verifier_mode=verifier_mode,
                verifier_digest=verifier_digest,
            )
            if binary_name == "invalid-verifier":
                artifact["ok"] = False
                artifact["evidence_verification"]["outcome"] = "not_run"
                artifact["evidence_verification"]["attempts"] = []
            (case_dir / "final_result.json").write_text(
                json.dumps(artifact),
                encoding="utf-8",
            )
        initialize_agent_context(
            {"cve_id": "CVE-A", "project": "curl"},
            "/anonymous/target_binary",
            patch_spec_info={
                "digest": "spec-digest",
                "generation_mode": "generated",
                "resolution_mode": "provided",
                "cache_key": "a" * 64,
                "cache_hit": False,
                "usage": {},
            },
            patch_spec={"behaviors": [{"behavior_id": "B001", "required": True}]},
            evidence_verifier_mode="llm",
        )
        preflight_artifact, preflight_errors = build_final_artifact(
            preflight_missing_result(
                {"cve_id": "CVE-A", "project": "curl"},
                "/anonymous/target_binary",
                {"ok": False, "error": "unsupported"},
            ),
            [],
            0.0,
        )
        check("preflight inconclusive fixture valid", not preflight_errors)
        preflight_dir = batch.safe_case_dir(out_root, "CVE-A", "preflight-inconclusive")
        preflight_dir.mkdir(parents=True)
        (preflight_dir / "final_result.json").write_text(
            json.dumps(preflight_artifact),
            encoding="utf-8",
        )
        to_run, to_reuse, counts = batch._select_resume_cases(
            cases,
            out_root,
            args,
            patchspec_keys={"CVE-A": "a" * 64},
            evidence_verifier_digest=expected_verifier_digest,
        )
        check(
            "matching and preflight results reused",
            [item["binary_name"] for item in to_reuse]
            == ["matching", "preflight-inconclusive"],
        )
        check(
            "stale result rerun",
            [item["binary_name"] for item in to_run]
            == ["stale", "stale-verifier", "stale-digest", "invalid-verifier"],
        )
        check("stale counted", counts["stale_patchspec"] == 1)
        check("stale verifier counted", counts["stale_evidence_verifier"] == 2)

    verifier_metrics = batch.evidence_verifier_batch_metrics([
        {
            "evidence_verifier_mode": "llm",
            "evidence_verifier_outcome": "accepted",
            "evidence_verifier_model_turns": 1,
            "evidence_verifier_usage_totals": {"prompt_tokens": 10, "completion_tokens": 2},
        },
        {
            "evidence_verifier_mode": "llm",
            "evidence_verifier_outcome": "accepted_after_repair",
            "evidence_verifier_model_turns": 2,
            "evidence_verifier_usage_totals": {"prompt_tokens": 12, "completion_tokens": 3},
        },
    ])
    check("verifier outcome counts", verifier_metrics["outcome_counts"] == {
        "accepted": 1,
        "accepted_after_repair": 1,
    })
    check("verifier usage separate aggregate", verifier_metrics["usage_totals"].get("prompt_tokens") == 22)
    check("verifier model turns aggregate", verifier_metrics["model_turns"] == 3)

    valid_artifact = _valid_final(cache_key="a" * 64)
    check("valid determinate artifact accepted", not batch._artifact_validation_errors(valid_artifact))
    invalid_artifact = _valid_final(cache_key="a" * 64)
    invalid_artifact["ok"] = False
    invalid_artifact["evidence_verification"]["outcome"] = "not_run"
    invalid_artifact["evidence_verification"]["attempts"] = []
    check(
        "unverified determinate artifact rejected",
        bool(batch._artifact_validation_errors(invalid_artifact)),
    )
    malformed_usage = _valid_final(cache_key="a" * 64)
    malformed_usage["usage_metrics"]["evidence_verifier"]["model_turns"] = "bad"
    malformed_fields = batch._evidence_verifier_fields(malformed_usage)
    malformed_metrics = batch.evidence_verifier_batch_metrics([{
        "evidence_verifier_mode": "llm",
        "evidence_verifier_outcome": "accepted",
        "evidence_verifier_model_turns": "bad",
        "evidence_verifier_usage_totals": {},
    }])
    check(
        "malformed verifier usage cannot crash batch",
        malformed_fields["evidence_verifier_model_turns"] == 0
        and malformed_metrics["model_turns"] == 0,
    )

    # Resume never reuses a pre-claim legacy artifact, even with a matching key.
    with tempfile.TemporaryDirectory() as tmp:
        args = _args(tmp)
        out_root = Path(args.out_root)
        case = {"cve_id": "CVE-A", "binary_name": "legacy", "expected": "present"}
        case_dir = batch.safe_case_dir(out_root, "CVE-A", "legacy")
        case_dir.mkdir(parents=True)
        (case_dir / "final_result.json").write_text(
            json.dumps({"status": "present", "patch_spec": {"cache_key": "a" * 64}}),
            encoding="utf-8",
        )
        to_run, to_reuse, unused_counts = batch._select_resume_cases(
            [case], out_root, args, patchspec_keys={"CVE-A": "a" * 64}
        )
        check("legacy artifact rerun", to_run == [case] and to_reuse == [])

    if failures:
        print("FAIL:", failures)
        return 1
    print("BATCH PATCHSPEC TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(_run())
