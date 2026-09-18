from __future__ import annotations

import json
import os
import sys
import unittest
from unittest import mock

from RCA import generate_behavior_analysis_deepseek as behavior_generator
from RCA.related_file_allowlist import ALLOWLIST_SCHEMA
from test_support import DatabaseTestCase, make_config


class RcaAllowlistResumeTest(DatabaseTestCase):
    def test_source_and_behavior_resume_require_current_allowlist(self) -> None:
        db = self.open_db()
        cve_id = "CVE-2024-3131"
        config = make_config(self.root, [cve_id])
        config.metadata_mode = "source"
        db.upsert_cve({"id": cve_id, "summary": "summary"}, selected=True)
        db.upsert_fix_candidate(cve_id, {"commit": "fix", "parent": "parent", "selected": True})
        config.rca_dir.mkdir(parents=True, exist_ok=True)
        config.rca_related_file_allowlist_json.parent.mkdir(parents=True, exist_ok=True)
        config.rca_source_min_json.write_text(json.dumps({cve_id: {"functions": []}}), encoding="utf-8")
        config.rca_related_file_allowlist_json.write_text(
            json.dumps(
                {
                    "schema": "related_file_allowlist.v1",
                    "project": config.project,
                    "cves": {cve_id: {}},
                }
            ),
            encoding="utf-8",
        )
        db.record_stage("RCA", "ok", {})
        db.upsert_many_rca_statuses(
            [
                {
                    "cve_id": cve_id,
                    "mode": "source",
                    "status": "ok",
                    "artifact_path": str(config.rca_source_min_json),
                    "detail": {},
                }
            ]
        )
        self.assertFalse(db.stage_satisfied("RCA", config))

        db.upsert_many_rca_statuses(
            [
                {
                    "cve_id": cve_id,
                    "mode": "source",
                    "status": "ok",
                    "artifact_path": str(config.rca_source_min_json),
                    "detail": {
                        "related_file_allowlist": str(config.rca_related_file_allowlist_json),
                        "related_file_allowlist_schema": "related_file_allowlist.v1",
                    },
                }
            ]
        )
        self.assertFalse(db.stage_satisfied("RCA", config))

        config.rca_related_file_allowlist_json.write_text(
            json.dumps(
                {
                    "schema": ALLOWLIST_SCHEMA,
                    "project": config.project,
                    "cves": {cve_id: {}},
                }
            ),
            encoding="utf-8",
        )
        db.upsert_many_rca_statuses(
            [
                {
                    "cve_id": cve_id,
                    "mode": "source",
                    "status": "ok",
                    "artifact_path": str(config.rca_source_min_json),
                    "detail": {
                        "related_file_allowlist": str(config.rca_related_file_allowlist_json),
                        "related_file_allowlist_schema": ALLOWLIST_SCHEMA,
                    },
                }
            ]
        )
        self.assertTrue(db.stage_satisfied("RCA", config))

        config.rca_source_min_json.write_text("{}", encoding="utf-8")
        self.assertFalse(db.stage_satisfied("RCA", config))
        config.rca_source_min_json.write_text(json.dumps({cve_id: {"functions": []}}), encoding="utf-8")
        self.assertTrue(db.stage_satisfied("RCA", config))

        config.metadata_mode = "behavior"
        config.rca_behavior_json.parent.mkdir(parents=True, exist_ok=True)
        config.rca_behavior_json.write_text(
            json.dumps(
                {
                    cve_id: {
                        "root_cause_analysis": {"summary": "root cause"},
                        "patch_intent_analysis": {"summary": "intent"},
                        "function_anchors": {},
                    }
                }
            ),
            encoding="utf-8",
        )
        db.upsert_many_rca_statuses(
            [
                {
                    "cve_id": cve_id,
                    "mode": "behavior",
                    "status": "ok",
                    "artifact_path": str(config.rca_behavior_json),
                    "detail": {"behavior": str(config.rca_behavior_json)},
                }
            ]
        )
        self.assertFalse(db.stage_satisfied("RCA", config))

        config.rca_behavior_json.write_text(
            json.dumps(
                {
                    cve_id: {
                        "root_cause_analysis": {"summary": "root cause"},
                        "patch_intent_analysis": {"summary": "intent"},
                        "function_anchors": {},
                        "patch_source": {"commit": "fix", "locations": []},
                    }
                }
            ),
            encoding="utf-8",
        )
        self.assertTrue(db.stage_satisfied("RCA", config))

    def test_behavior_resume_skips_an_existing_complete_item(self) -> None:
        cve_id = "CVE-2024-4243"
        source_path = self.root / "source.min.json"
        behavior_path = self.root / "behavior.json"
        source_path.write_text(
            json.dumps({cve_id: {"functions": ["patched_function"]}}),
            encoding="utf-8",
        )
        behavior_path.write_text(
            json.dumps(
                {
                    cve_id: {
                        "root_cause_analysis": {"summary": "existing"},
                        "patch_intent_analysis": {"summary": "existing"},
                        "function_anchors": {"patched_function": [{"anchor": "existing"}] * 5},
                    }
                }
            ),
            encoding="utf-8",
        )
        argv = [
            "generate_behavior_analysis_deepseek.py",
            "--input",
            str(source_path),
            "--output",
            str(behavior_path),
            "--resume",
        ]
        environment = {
            "DEEPSEEK_API_KEY": "test-key",
            "DEEPSEEK_BASE_URL": "https://example.invalid",
            "DEEPSEEK_MODEL": "test-model",
        }
        with mock.patch.object(sys, "argv", argv), mock.patch.dict(os.environ, environment), mock.patch.object(
            behavior_generator, "analyze_one"
        ) as analyze_one:
            self.assertEqual(behavior_generator.main(), 0)
        analyze_one.assert_not_called()


if __name__ == "__main__":
    unittest.main()
