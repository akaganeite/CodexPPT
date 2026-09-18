from __future__ import annotations

import json
import unittest
from pathlib import Path

from builder import cli
from CVEhunt.nvd_constraints import affected_constraints, affected_ranges
from test_support import (
    DatabaseTestCase,
    PIPELINE_STAGES,
    add_artifact,
    add_testset,
    build_args,
    make_config,
    mock_pipeline_stages,
    write_elf,
)
from testset.export_stage import build_testset_pick, export_variant_testset_and_groundtruth
from testset.testset_stage import version_is_affected


class VariantResumeTest(DatabaseTestCase):
    def test_shared_nvd_constraints_feed_selection_and_review(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-0900"
        raw_nvd = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:demo:demo:*:*:*:*:*:*:*:*",
                                    "versionStartIncluding": "1.0",
                                    "versionEndExcluding": "2.0",
                                },
                                {"vulnerable": True, "criteria": "cpe:2.3:a:other:demo:9.0:*:*:*:*:*:*:*"},
                            ]
                        }
                    ]
                }
            ]
        }
        db.upsert_cve({"id": cve_id, "summary": "summary", "raw_nvd": raw_nvd}, selected=True)
        config = make_config(self.root, [cve_id])
        self.assertEqual(
            affected_constraints(config, db, cve_id),
            [
                {
                    "exact": "",
                    "start_including": "1.0",
                    "start_excluding": "",
                    "end_including": "",
                    "end_excluding": "2.0",
                    "all": False,
                }
            ],
        )
        self.assertEqual(affected_ranges(config, db, cve_id)[0]["versionEndExcluding"], "2.0")

    def test_precise_affected_data_overrides_broad_cpe_range(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2025-1373"
        raw_nvd = {
            "affected": [
                {
                    "affectedData": [
                        {
                            "product": "Demo",
                            "versions": [
                                {"version": "7.0", "status": "affected"},
                                {"version": "7.1", "status": "affected"},
                                {"version": "9.0", "status": "unaffected"},
                            ],
                        },
                        {"product": "other", "versions": [{"version": "1.0", "status": "affected"}]},
                    ]
                }
            ],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:demo:demo:*:*:*:*:*:*:*:*",
                                    "versionEndIncluding": "7.1",
                                }
                            ]
                        }
                    ]
                }
            ],
        }
        db.upsert_cve({"id": cve_id, "summary": "summary", "raw_nvd": raw_nvd}, selected=True)
        config = make_config(self.root, [cve_id])

        self.assertEqual(
            affected_constraints(config, db, cve_id),
            [
                {
                    "exact": "7.0",
                    "start_including": "",
                    "start_excluding": "",
                    "end_including": "",
                    "end_excluding": "",
                    "all": False,
                },
                {
                    "exact": "7.1",
                    "start_including": "",
                    "start_excluding": "",
                    "end_including": "",
                    "end_excluding": "",
                    "all": False,
                },
            ],
        )
        self.assertTrue(version_is_affected("7.1", affected_constraints(config, db, cve_id) or []))
        self.assertFalse(version_is_affected("5.1.6", affected_constraints(config, db, cve_id) or []))
        self.assertEqual(
            [item["version"] for item in affected_ranges(config, db, cve_id)],
            ["7.0", "7.1"],
        )
        self.assertEqual(affected_ranges(config, db, cve_id)[0]["source"], "affectedData")

    def test_cli_variant_only_skips_upstream_and_canonical_export(self) -> None:
        config = make_config(self.root, ["CVE-2024-0999"])
        db = self.open_db()
        cve_id = config.cves[0]
        db.upsert_cve({"id": cve_id, "summary": "summary"}, selected=True)
        db.upsert_fix_candidate(cve_id, {"commit": "fix", "parent": "parent", "selected": True})
        db.replace_source_functions(cve_id, "fix", [{"function": "f", "file": "a.c"}])
        add_testset(db, cve_id, "v1")
        vuln, fixed = self.root / "vuln", self.root / "fixed"
        write_elf(vuln)
        write_elf(fixed)
        db.upsert_reference(
            {"cve_id": cve_id, "compiler": "gcc", "opt": "-O0", "vuln_path": vuln, "patch_path": fixed, "status": "ok"}
        )
        self.close_db(db)

        with mock_pipeline_stages() as mocks:
            self.assertEqual(cli.handle_build(build_args(self.root, config.cves)), 0)
            mocks["run_target_build"].assert_called_once()
            mocks["export_variant_testset_and_groundtruth"].assert_called_once()
            skipped = set(PIPELINE_STAGES) - {"run_target_build", "run_debug_split", "export_variant_testset_and_groundtruth"}
            for name in skipped:
                mocks[name].assert_not_called()

    def test_cli_variant_only_runs_rca_when_related_allowlist_is_missing(self) -> None:
        config = make_config(self.root, ["CVE-2024-0998"])
        db = self.open_db()
        cve_id = config.cves[0]
        db.upsert_cve({"id": cve_id, "summary": "summary"}, selected=True)
        db.upsert_fix_candidate(cve_id, {"commit": "fix", "parent": "parent", "selected": True})
        db.replace_source_functions(cve_id, "fix", [{"function": "f", "file": "a.c"}])
        add_testset(db, cve_id, "v1")
        vuln, fixed = self.root / "vuln-rca", self.root / "fixed-rca"
        write_elf(vuln)
        write_elf(fixed)
        db.upsert_reference(
            {"cve_id": cve_id, "compiler": "gcc", "opt": "-O0", "vuln_path": vuln, "patch_path": fixed, "status": "ok"}
        )
        self.close_db(db)

        args = build_args(self.root, config.cves)
        args.metadata_mode = "source"
        with mock_pipeline_stages() as mocks:
            self.assertEqual(cli.handle_build(args), 0)
            mocks["run_rca_metadata"].assert_called_once()
            mocks["run_cve2diff"].assert_not_called()
            mocks["run_source_analysis"].assert_not_called()

    def test_cli_bootstrap_runs_upstream_and_full_scope_export(self) -> None:
        with mock_pipeline_stages() as mocks:
            self.assertEqual(cli.handle_build(build_args(self.root, ["CVE-2024-9999"])), 0)
            skipped = {"run_rca_metadata"}
            for name in set(PIPELINE_STAGES) - skipped:
                mocks[name].assert_called_once()
            self.assertEqual(mocks["export_outputs"].call_args.args[0].cves, [])
            mocks["run_rca_metadata"].assert_not_called()

    def test_cli_latest_resume_refreshes_metadata_and_bootstraps_only_new_cves(self) -> None:
        old_cve = "CVE-2024-1009"
        new_cve = "CVE-2026-0001"
        config = make_config(self.root, [old_cve])
        db = self.open_db()
        db.upsert_cve({"id": old_cve, "summary": "old"}, selected=True)
        db.upsert_fix_candidate(old_cve, {"commit": "fix", "parent": "parent", "selected": True})
        db.replace_source_functions(old_cve, "fix", [{"function": "f", "file": "a.c"}])
        add_testset(db, old_cve, "v1")
        vuln, fixed = self.root / "latest-vuln", self.root / "latest-fixed"
        write_elf(vuln)
        write_elf(fixed)
        db.upsert_reference(
            {
                "cve_id": old_cve,
                "compiler": "gcc",
                "opt": "-O0",
                "vuln_path": vuln,
                "patch_path": fixed,
                "status": "ok",
            }
        )
        self.assertTrue(cli.latest_resume_needs_work(config, db, old_cve))
        add_artifact(db, self.root, old_cve, "v1", "clang", "-O3")
        db.record_stage("target_build", "ok", {})
        db.record_stage("debug_split", "ok", {})
        self.assertFalse(cli.latest_resume_needs_work(config, db, old_cve))
        self.close_db(db)

        args = build_args(self.root, [])
        args.latest = 50
        with mock_pipeline_stages() as mocks:
            mocks["update_cve_metadata"].return_value = [old_cve, new_cve]
            self.assertEqual(cli.handle_build(args), 0)

            self.assertEqual(mocks["update_git_repo"].call_count, 1)
            mocks["update_cve_metadata"].assert_called_once()
            self.assertEqual(mocks["run_cve2diff"].call_args.args[0].cves, [new_cve])
            self.assertEqual(mocks["run_source_analysis"].call_args.args[0].cves, [new_cve])
            self.assertEqual(mocks["run_reference_build"].call_args.args[0].cves, [new_cve])
            self.assertEqual(mocks["run_target_build"].call_args.args[0].cves, [new_cve])
            self.assertEqual(mocks["export_outputs"].call_args.args[0].cves, [])

    def test_readiness_requires_gcc_o0_reference_files(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-1000"
        db.upsert_cve({"id": cve_id, "summary": "summary"}, selected=True)
        db.upsert_fix_candidate(cve_id, {"commit": "fix", "parent": "parent", "selected": True})
        db.replace_source_functions(cve_id, "fix", [{"function": "f", "file": "a.c"}])
        add_testset(db, cve_id, "v1")
        vuln, fixed = self.root / "reference-vuln", self.root / "reference-patch"
        write_elf(vuln)
        write_elf(fixed)
        db.upsert_reference(
            {"cve_id": cve_id, "compiler": "gcc", "opt": "-O0", "vuln_path": vuln, "patch_path": fixed, "status": "ok"}
        )
        self.assertEqual(db.classify_requested_cves([cve_id, "CVE-2024-NEW"]), ([cve_id], ["CVE-2024-NEW"]))
        fixed.unlink()
        self.assertEqual(db.classify_requested_cves([cve_id]), ([], [cve_id]))

    def test_review_is_reused_across_build_variants(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-1001"
        add_testset(db, cve_id, "v1")
        gcc_artifact = add_artifact(db, self.root, cve_id, "v1", "gcc", "-O2")
        add_artifact(db, self.root, cve_id, "v1", "clang", "-O3")
        gcc_config = make_config(self.root, [cve_id], "gcc", "-O2")
        clang_config = make_config(self.root, [cve_id], "clang", "-O3")
        candidate = db.selected_target_candidates(gcc_config)[0]
        db.upsert_not_affected_review(
            {**candidate, "status": "affected", "report": {"policy": "affectedness-audit-v1"}}
        )
        self.assertEqual(db.pending_not_affected_candidates(clang_config), [])
        self.assertEqual(
            db.conn.execute("SELECT reviewed_artifact_id FROM affectedness_reviews").fetchone()["reviewed_artifact_id"],
            gcc_artifact,
        )

    def test_variant_export_is_cumulative_and_requires_split_files(self) -> None:
        db = self.open_db()
        entries = (
            ("CVE-2024-1002", "v1", "vuln", True),
            ("CVE-2024-1003", "v2", "patch", True),
            ("CVE-2024-1004", "v3", "vuln", False),
            ("CVE-2024-1005", "v4", "not_affected", True),
        )
        for cve_id, tag, label, split in entries:
            add_testset(db, cve_id, tag, label)
            add_artifact(db, self.root, cve_id, tag, "clang", "-O3", split=split)
        export_variant_testset_and_groundtruth(make_config(self.root, ["CVE-2024-1003"]), db)
        testset = json.loads((self.root / "exports" / "testset.clang-O3.json").read_text())
        groundtruth = json.loads((self.root / "exports" / "groundtruth.clang-O3.json").read_text())
        pick = json.loads((self.root / "exports" / "testset.pick.clang-O3.json").read_text())
        expected = {"CVE-2024-1002", "CVE-2024-1003"}
        self.assertEqual({item["CVE"] for item in testset}, expected)
        self.assertEqual({item["CVE"] for item in groundtruth}, expected)
        self.assertEqual({item["CVE"] for item in pick}, expected)
        self.assertEqual(testset[0]["binaries"], ["demo-1-tool"])

    def test_testset_pick_ignores_gt_suspicious_entries(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2026-11822"
        db.upsert_cve({"id": cve_id, "summary": "summary"}, selected=True)
        for version in ("3.53.0", "3.53.1", "3.53.4"):
            db.upsert_release(
                {"tag": f"v{version}", "commit_sha": f"sha-{version}", "date": "", "version": version, "norm_tag": version}
            )
        db.replace_testset_entries(
            cve_id,
            [
                {"label": "vuln", "version": "3.53.0", "tag": "v3.53.0", "binary_name": "tool"},
                {"label": "patch", "version": "3.53.1", "tag": "v3.53.1", "binary_name": "tool"},
                {
                    "label": "patch",
                    "version": "3.53.4",
                    "tag": "v3.53.4",
                    "binary_name": "tool",
                    "status": "gt_suspicious",
                },
            ],
        )

        pick = build_testset_pick(
            make_config(self.root, [cve_id]),
            db,
            db.testset_entries(make_config(self.root, [cve_id])),
            lambda row: f"demo-{row['version']}-tool",
        )

        self.assertEqual(pick[cve_id]["binaries"], ["demo-3.53.0-tool", "demo-3.53.1-tool"])

    def test_variant_export_merges_review_labels_and_keeps_pick_covered(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-1006"
        db.upsert_cve({"id": cve_id, "summary": cve_id}, selected=True)
        entries = (
            ("v1", "vuln", "not_affected"),
            ("v2", "vuln", "backport_fix"),
            ("v3", "patch", "missing_fix"),
            ("v4", "patch", "patch_evolution"),
        )
        for tag, _, _ in entries:
            db.upsert_release({"tag": tag, "commit_sha": f"sha-{tag}", "date": "", "version": tag[1:], "norm_tag": tag[1:]})
        db.replace_testset_entries(
            cve_id,
            [{"label": label, "version": tag[1:], "tag": tag, "binary_name": "tool"} for tag, label, _ in entries],
        )
        config = make_config(self.root, [cve_id], "clang", "-O3")
        for tag, _, _ in entries:
            add_artifact(db, self.root, cve_id, tag, "clang", "-O3")
        candidates = {candidate["tag"]: candidate for candidate in db.selected_target_candidates(config)}
        for tag, _, status in entries:
            db.upsert_not_affected_review(
                {**candidates[tag], "status": status, "report": {"policy": "affectedness-audit-v1"}}
            )

        export_variant_testset_and_groundtruth(config, db)

        exports = self.root / "exports"
        primary = {item["CVE"]: item for item in json.loads((exports / "groundtruth.clang-O3.json").read_text())}
        tri_state = {item["CVE"]: item for item in json.loads((exports / "groundtruth_with_not_affected.clang-O3.json").read_text())}
        not_affected = {item["CVE"]: item for item in json.loads((exports / "not_affected.clang-O3.json").read_text())}
        pick = {item["CVE"]: item for item in json.loads((exports / "testset.pick.clang-O3.json").read_text())}

        self.assertEqual(tri_state[cve_id]["vuln"], ["demo-3-tool"])
        self.assertEqual(tri_state[cve_id]["patch"], ["demo-2-tool", "demo-4-tool"])
        self.assertEqual(tri_state[cve_id]["not_affected"], ["demo-1-tool"])
        self.assertEqual(primary, tri_state)
        self.assertEqual(not_affected[cve_id]["binaries"], ["demo-1-tool"])
        self.assertEqual(pick[cve_id]["binaries"], ["demo-1-tool", "demo-4-tool"])

    def test_replacing_unchanged_testset_entry_preserves_mapping_and_review(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-1007"
        add_testset(db, cve_id, "v1")
        config = make_config(self.root, [cve_id], "clang", "-O3")
        add_artifact(db, self.root, cve_id, "v1", "clang", "-O3")
        before = db.testset_entries(config)[0]
        candidate = db.selected_target_candidates(config)[0]
        db.upsert_not_affected_review(
            {**candidate, "status": "affected", "report": {"policy": "affectedness-audit-v1"}}
        )

        db.replace_testset_entries(
            cve_id,
            [{"label": "vuln", "version": "1", "tag": "v1", "binary_name": "tool", "reason": "reselected"}],
        )

        after = db.testset_entries(config)[0]
        self.assertEqual(after["id"], before["id"])
        self.assertIsNotNone(db.target_mapping_for_testset(after, config))
        self.assertIsNotNone(db.not_affected_review_for_candidate(candidate, policy="affectedness-audit-v1"))

    def test_variant_export_reattaches_exact_unmapped_artifact(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-1008"
        add_testset(db, cve_id, "v1")
        config = make_config(self.root, [cve_id], "clang", "-O3")
        artifact_id = add_artifact(db, self.root, cve_id, "v1", "clang", "-O3")
        db.conn.execute("DELETE FROM target_mappings WHERE artifact_id=?", (artifact_id,))
        db.conn.commit()

        export_variant_testset_and_groundtruth(config, db)

        row = db.testset_entries(config)[0]
        self.assertIsNotNone(db.target_mapping_for_testset(row, config))
        testset = json.loads((self.root / "exports" / "testset.clang-O3.json").read_text())
        self.assertEqual(testset[0]["binaries"], ["demo-1-tool"])

    def test_variant_export_recovers_split_files_without_artifact_row(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-1010"
        add_testset(db, cve_id, "v1")
        config = make_config(self.root, [cve_id], "gcc", "-O2")
        name = config.target_binary_name("1", "tool")
        stripped = config.target_stripped_dir / name
        debug = config.target_debug_dir / f"{name}.debug"
        write_elf(stripped)
        write_elf(debug)

        testset_count, groundtruth_count = export_variant_testset_and_groundtruth(config, db)

        self.assertEqual((testset_count, groundtruth_count), (1, 1))
        artifact = db.target_artifact_for_task("demo", "v1", "tool", "gcc", "-O2")
        self.assertIsNotNone(artifact)
        self.assertEqual(Path(artifact["path"]), stripped)
        self.assertEqual(Path(artifact["debug_path"]), debug)


if __name__ == "__main__":
    unittest.main()
