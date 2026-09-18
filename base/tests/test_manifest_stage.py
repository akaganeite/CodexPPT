from __future__ import annotations

import json
from unittest.mock import DEFAULT, Mock, patch

from builder import cli
from builder.config import BuildConfig
from test_support import DatabaseTestCase, add_artifact, make_config
from testset.manifest_stage import (
    align_locked_manifest_exports,
    apply_locked_manifest,
    apply_locked_manifest_reviews,
    load_project_manifest,
    validate_locked_manifest_exports,
)


class ManifestStageTest(DatabaseTestCase):
    def write_manifest(self) -> None:
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(
            json.dumps(
                {
                    "demo": {
                        "CVE-2024-1000": {
                            "vuln": ["demo-1.0-tool"],
                            "patch": ["demo-2.0-tool"],
                            "not_affected": ["demo-3.0-tool"],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

    def config(self) -> BuildConfig:
        config = make_config(self.root, ["CVE-2024-1000"], compiler="gcc", opt="-O2")
        config.testset_manifest = self.manifest
        return config

    def test_locked_manifest_replaces_testset_and_records_final_labels(self) -> None:
        self.write_manifest()
        db = self.open_db()
        cve_id = "CVE-2024-1000"
        db.upsert_cve({"id": cve_id, "summary": "summary"}, selected=True)
        for version in ("1.0", "2.0", "3.0"):
            db.upsert_release(
                {"tag": f"v{version}", "commit_sha": version, "date": "", "version": version, "norm_tag": version}
            )
        config = self.config()
        result = apply_locked_manifest(config, db)
        self.assertEqual(result["cves"], 1)
        rows = db.testset_entries(config)
        self.assertEqual([(row["label"], row["version"]) for row in rows], [("patch", "2.0"), ("vuln", "1.0"), ("vuln", "3.0")])

        for row in rows:
            add_artifact(db, self.root, cve_id, row["tag"], "gcc", "-O2")
        review_result = apply_locked_manifest_reviews(config, db)
        self.assertEqual(review_result["counts"], {"vuln": 1, "patch": 1, "not_affected": 1})
        statuses = {
            row["version"]: row["status"]
            for row in db.conn.execute(
                """
                SELECT t.version,r.status FROM affectedness_reviews r
                JOIN testset_entries t ON t.id=r.testset_entry_id
                """
            )
        }
        self.assertEqual(statuses, {"1.0": "affected", "2.0": "affected", "3.0": "not_affected"})

    def test_manifest_requires_project_entry(self) -> None:
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "no non-empty project entry"):
            load_project_manifest(self.manifest, "other")

    def test_locked_manifest_pipeline_builds_and_requires_references(self) -> None:
        self.write_manifest()
        config = self.config()
        db = Mock()
        db.selected_fixes_missing_reference.return_value = []
        log = Mock()
        stages = {
            "update_releases": DEFAULT,
            "apply_locked_manifest": DEFAULT,
            "run_reference_build": DEFAULT,
            "run_target_build": DEFAULT,
            "apply_locked_manifest_reviews": DEFAULT,
            "run_debug_split": DEFAULT,
            "export_variant_testset_and_groundtruth": DEFAULT,
            "export_outputs": DEFAULT,
            "align_locked_manifest_exports": DEFAULT,
            "validate_locked_manifest_exports": DEFAULT,
        }
        with patch.multiple(cli, **stages) as mocks:
            mocks["validate_locked_manifest_exports"].return_value = {"cves": 1, "testcases": 3}
            cli.run_locked_manifest_pipeline(config, db, log)
            mocks["run_reference_build"].assert_called_once_with(config, db)

        db.selected_fixes_missing_reference.return_value = ["CVE-2024-1000"]
        with patch.multiple(cli, **stages):
            with self.assertRaisesRegex(RuntimeError, "reference build is incomplete"):
                cli.run_locked_manifest_pipeline(config, db, log)

    def test_locked_exports_preserve_manifest_order(self) -> None:
        self.write_manifest()
        config = self.config()
        config.exports_dir.mkdir(parents=True)
        testset = [
            {
                "CVE": "CVE-2024-1000",
                "functions": ["demo"],
                "binaries": ["demo-3.0-tool", "demo-2.0-tool", "demo-1.0-tool"],
            }
        ]
        groundtruth = [
            {
                "CVE": "CVE-2024-1000",
                "functions": ["demo"],
                "vuln": ["demo-1.0-tool"],
                "patch": ["demo-2.0-tool"],
                "not_affected": ["demo-3.0-tool"],
            }
        ]
        for name in ("testset.json", "testset.gcc-O2.json"):
            (config.exports_dir / name).write_text(json.dumps(testset), encoding="utf-8")
        for name in ("groundtruth.json", "groundtruth.gcc-O2.json"):
            (config.exports_dir / name).write_text(json.dumps(groundtruth), encoding="utf-8")
        (config.exports_dir / "demo_metadata.json").write_text(
            json.dumps({"CVE-2024-9999": {}, "CVE-2024-1000": {"functions": ["demo"]}}),
            encoding="utf-8",
        )
        (config.exports_dir / "demo_reference.json").write_text(
            json.dumps([{"CVE": "CVE-2024-9999"}, {"CVE": "CVE-2024-1000"}]),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(RuntimeError, "testset mismatch"):
            validate_locked_manifest_exports(config)
        align_locked_manifest_exports(config)
        result = validate_locked_manifest_exports(config)

        self.assertEqual(result["testcases"], 3)
        aligned = json.loads((config.exports_dir / "testset.gcc-O2.json").read_text(encoding="utf-8"))
        self.assertEqual(
            aligned[0]["binaries"],
            ["demo-1.0-tool", "demo-2.0-tool", "demo-3.0-tool"],
        )
        metadata = json.loads((config.exports_dir / "demo_metadata.json").read_text(encoding="utf-8"))
        references = json.loads((config.exports_dir / "demo_reference.json").read_text(encoding="utf-8"))
        self.assertEqual(list(metadata), ["CVE-2024-1000"])
        self.assertEqual([item["CVE"] for item in references], ["CVE-2024-1000"])
